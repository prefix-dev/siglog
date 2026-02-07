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

    /// Update the witnessed state for a log.
    ///
    /// This is called after successfully verifying a consistency proof.
    pub async fn update(
        &self,
        origin: &str,
        size: u64,
        root_hash: Sha256Hash,
        checkpoint: &str,
    ) -> Result<()> {
        let txn = self.conn.begin().await?;

        // Lock and get current state
        let current = witness_state::Entity::find_by_id(origin.to_string())
            .lock_exclusive()
            .one(&txn)
            .await?;

        match current {
            Some(model) => {
                // Prevent size rollback: new size must be >= current size
                if (size as i64) < model.size {
                    return Err(Error::InvalidEntry(format!(
                        "size rollback not allowed: current size {} > new size {}",
                        model.size, size
                    )));
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
        Ok(())
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
