//! Witness state persistence using Sea ORM.

use crate::error::{Error, Result};
use crate::witness::WitnessedState;
use sea_orm::{prelude::*, ActiveValue, DatabaseConnection, QuerySelect, TransactionTrait};
use sigstore_types::Sha256Hash;
use std::sync::Arc;

/// Store for witness state, tracking the last witnessed checkpoint per log.
#[derive(Clone)]
pub struct WitnessStateStore {
    conn: Arc<DatabaseConnection>,
}

impl WitnessStateStore {
    /// Create a new witness state store.
    pub fn new(conn: Arc<DatabaseConnection>) -> Self {
        Self { conn }
    }

    /// Get the witnessed state for a log origin.
    pub async fn get(&self, origin: &str) -> Result<Option<WitnessedState>> {
        let row = witness_state::Entity::find_by_id(origin.to_string())
            .one(&*self.conn)
            .await?;

        match row {
            Some(model) => {
                let root_hash = Sha256Hash::try_from_slice(&model.root_hash)
                    .map_err(|e| Error::Internal(format!("invalid root hash in db: {}", e)))?;
                Ok(Some(WitnessedState {
                    origin: model.origin,
                    size: model.size as u64,
                    root_hash,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get the witnessed state for a log, initializing if not present.
    ///
    /// New logs start with size=0 and an empty tree root hash.
    pub async fn get_or_init(&self, origin: &str) -> Result<WitnessedState> {
        if let Some(state) = self.get(origin).await? {
            return Ok(state);
        }

        // Initialize with empty tree state
        let empty_root = empty_root_hash();

        // Use a transaction to handle race conditions
        let txn = self.conn.begin().await?;

        // Check again inside transaction
        let existing = witness_state::Entity::find_by_id(origin.to_string())
            .one(&txn)
            .await?;

        if let Some(model) = existing {
            txn.rollback().await?;
            let root_hash = Sha256Hash::try_from_slice(&model.root_hash)
                .map_err(|e| Error::Internal(format!("invalid root hash in db: {}", e)))?;
            return Ok(WitnessedState {
                origin: model.origin,
                size: model.size as u64,
                root_hash,
            });
        }

        // Insert new state
        let model = witness_state::ActiveModel {
            origin: ActiveValue::Set(origin.to_string()),
            size: ActiveValue::Set(0),
            root_hash: ActiveValue::Set(empty_root.as_bytes().to_vec()),
            checkpoint: ActiveValue::Set(String::new()),
            updated_at: ActiveValue::Set(chrono::Utc::now().into()),
        };

        witness_state::Entity::insert(model).exec(&txn).await?;
        txn.commit().await?;

        Ok(WitnessedState {
            origin: origin.to_string(),
            size: 0,
            root_hash: empty_root,
        })
    }

    /// Update the witnessed state for a log, compare-and-swap style.
    ///
    /// This is called after successfully verifying a consistency proof. The
    /// verification happened against a state read earlier (`expected_size`,
    /// `expected_root`); this method re-checks under a row lock that the
    /// persisted state still matches. Without this check, two concurrent
    /// requests could each verify a proof against the same old state and the
    /// witness would end up cosigning two conflicting roots at the same size
    /// (a split view).
    ///
    /// Returns `UpdateOutcome::Conflict` if the persisted state no longer
    /// matches the expected state; the caller must re-read and re-verify.
    pub async fn update(
        &self,
        origin: &str,
        expected_size: u64,
        expected_root: &Sha256Hash,
        size: u64,
        root_hash: Sha256Hash,
        checkpoint: &str,
    ) -> Result<UpdateOutcome> {
        // Sizes are stored as i64; reject values that would wrap negative and
        // corrupt the monotonicity comparison.
        if size > i64::MAX as u64 || expected_size > i64::MAX as u64 {
            return Err(Error::InvalidEntry(format!(
                "tree size {} exceeds supported maximum",
                size
            )));
        }
        if size < expected_size {
            return Err(Error::InvalidEntry(format!(
                "size rollback not allowed: current size {} > new size {}",
                expected_size, size
            )));
        }

        let txn = self.conn.begin().await?;

        // Lock and get current state
        let current = witness_state::Entity::find_by_id(origin.to_string())
            .lock_exclusive()
            .one(&txn)
            .await?;

        match current {
            Some(model) => {
                // CAS check: the state must not have moved since the caller
                // verified the consistency proof.
                if model.size as u64 != expected_size
                    || model.root_hash != expected_root.as_bytes().to_vec()
                {
                    txn.rollback().await?;
                    return Ok(UpdateOutcome::Conflict {
                        current_size: model.size as u64,
                    });
                }
                // Update existing
                witness_state::Entity::update(witness_state::ActiveModel {
                    origin: ActiveValue::Unchanged(origin.to_string()),
                    size: ActiveValue::Set(size as i64),
                    root_hash: ActiveValue::Set(root_hash.as_bytes().to_vec()),
                    checkpoint: ActiveValue::Set(checkpoint.to_string()),
                    updated_at: ActiveValue::Set(chrono::Utc::now().into()),
                })
                .exec(&txn)
                .await?;
            }
            None => {
                // Callers always go through get_or_init first, so an absent
                // row means the expected state is the initial empty state.
                if expected_size != 0 {
                    txn.rollback().await?;
                    return Ok(UpdateOutcome::Conflict { current_size: 0 });
                }
                // Insert new
                witness_state::Entity::insert(witness_state::ActiveModel {
                    origin: ActiveValue::Set(origin.to_string()),
                    size: ActiveValue::Set(size as i64),
                    root_hash: ActiveValue::Set(root_hash.as_bytes().to_vec()),
                    checkpoint: ActiveValue::Set(checkpoint.to_string()),
                    updated_at: ActiveValue::Set(chrono::Utc::now().into()),
                })
                .exec(&txn)
                .await?;
            }
        }

        txn.commit().await?;
        Ok(UpdateOutcome::Updated)
    }

    /// List all witnessed logs.
    pub async fn list(&self) -> Result<Vec<WitnessedState>> {
        let rows = witness_state::Entity::find().all(&*self.conn).await?;

        rows.into_iter()
            .map(|model| {
                let root_hash = Sha256Hash::try_from_slice(&model.root_hash)
                    .map_err(|e| Error::Internal(format!("invalid root hash in db: {}", e)))?;
                Ok(WitnessedState {
                    origin: model.origin,
                    size: model.size as u64,
                    root_hash,
                })
            })
            .collect()
    }
}

/// Outcome of a compare-and-swap state update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The state was updated.
    Updated,
    /// The persisted state changed since the caller read it.
    Conflict {
        /// The size currently persisted for this log.
        current_size: u64,
    },
}

/// RFC 6962 empty tree root hash.
fn empty_root_hash() -> Sha256Hash {
    Sha256Hash::from_bytes([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ])
}

// ============================================================================
// SeaORM entity definitions
// ============================================================================

mod witness_state {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "witness_state")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub origin: String,
        pub size: i64,
        pub root_hash: Vec<u8>,
        pub checkpoint: String,
        pub updated_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
