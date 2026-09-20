//! Witness state persistence using Sea ORM.

use crate::error::{Error, Result};
use crate::witness::WitnessedState;
use sea_orm::{
    prelude::*,
    sea_query::{Expr, OnConflict},
    ActiveValue, ConnectionTrait, DatabaseConnection,
};
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

        // Insert new state
        let model = witness_state::ActiveModel {
            origin: ActiveValue::Set(origin.to_string()),
            size: ActiveValue::Set(0),
            root_hash: ActiveValue::Set(empty_root.as_bytes().to_vec()),
            checkpoint: ActiveValue::Set(String::new()),
            updated_at: ActiveValue::Set(chrono::Utc::now().into()),
        };

        // Let the database arbitrate concurrent first requests without a
        // read-to-write lock upgrade (SQLITE_BUSY) or duplicate-key error.
        witness_state::Entity::insert(model)
            .on_conflict(
                OnConflict::column(witness_state::Column::Origin)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&*self.conn)
            .await?;
        self.get(origin)
            .await?
            .ok_or_else(|| Error::Internal("witness state missing after initialization".into()))
    }

    /// Commit only if the state used to verify the proof is still current.
    pub async fn update(
        &self,
        expected: &WitnessedState,
        size: u64,
        root_hash: Sha256Hash,
        checkpoint: &str,
    ) -> Result<bool> {
        Self::update_in(&*self.conn, expected, size, root_hash, checkpoint).await
    }

    pub async fn update_in<C: ConnectionTrait>(
        conn: &C,
        expected: &WitnessedState,
        size: u64,
        root_hash: Sha256Hash,
        checkpoint: &str,
    ) -> Result<bool> {
        if size < expected.size || (size == expected.size && root_hash != expected.root_hash) {
            return Err(Error::InvalidEntry(
                "checkpoint rollback or conflicting root".into(),
            ));
        }
        let size = i64::try_from(size).map_err(|_| Error::InvalidEntry("tree too large".into()))?;
        let result = Self::matching(expected)
            .col_expr(witness_state::Column::Size, Expr::value(size))
            .col_expr(
                witness_state::Column::RootHash,
                Expr::value(root_hash.as_bytes().to_vec()),
            )
            .col_expr(
                witness_state::Column::Checkpoint,
                Expr::value(checkpoint.to_string()),
            )
            .col_expr(
                witness_state::Column::UpdatedAt,
                Expr::value(chrono::Utc::now().fixed_offset()),
            )
            .exec(conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    /// Acquire a database writer lock before reading monitor state (also on SQLite).
    pub async fn lock_in<C: ConnectionTrait>(conn: &C, expected: &WitnessedState) -> Result<bool> {
        let result = Self::matching(expected)
            .col_expr(
                witness_state::Column::Size,
                Expr::col(witness_state::Column::Size),
            )
            .exec(conn)
            .await?;
        Ok(result.rows_affected == 1)
    }

    fn matching(expected: &WitnessedState) -> sea_orm::UpdateMany<witness_state::Entity> {
        witness_state::Entity::update_many()
            .filter(witness_state::Column::Origin.eq(&expected.origin))
            .filter(witness_state::Column::Size.eq(expected.size as i64))
            .filter(witness_state::Column::RootHash.eq(expected.root_hash.as_bytes().to_vec()))
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
