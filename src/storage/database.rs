//! SeaORM-based database storage for sequencing state.
//!
//! Stores:
//! - Log state (next index, integrated size, root hash)
//! - Pending entries awaiting integration

use crate::error::{Error, Result};
use crate::migration::Migrator;
use crate::types::{Entry, EntryData, LogIndex, SequencedEntry, TreeSize};
use sea_orm::{
    prelude::*, ActiveValue, ConnectOptions, Database as SeaDatabase, DatabaseConnection,
    QueryOrder, QuerySelect, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use sigstore_types::Sha256Hash;
use std::sync::Arc;
use std::time::Duration;

/// Database connection wrapper.
#[derive(Clone)]
pub struct Database {
    conn: Arc<DatabaseConnection>,
}

impl Database {
    /// Connect to the database.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let mut opts = ConnectOptions::new(database_url);
        opts.max_connections(10)
            .min_connections(1)
            .connect_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .sqlx_logging(false);

        let conn = SeaDatabase::connect(opts).await?;

        // Enable WAL mode for SQLite to allow concurrent readers/writers
        if matches!(
            conn.get_database_backend(),
            sea_orm::DatabaseBackend::Sqlite
        ) {
            conn.execute_unprepared("PRAGMA journal_mode=WAL")
                .await
                .map_err(Error::Database)?;
            conn.execute_unprepared("PRAGMA busy_timeout=5000")
                .await
                .map_err(Error::Database)?;
        }

        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    /// Get the database connection.
    pub fn connection(&self) -> &DatabaseConnection {
        &self.conn
    }

    /// Run database migrations.
    pub async fn run_migrations(&self) -> Result<()> {
        Migrator::up(&*self.conn, None)
            .await
            .map_err(Error::Database)?;
        Ok(())
    }

    // ========================================================================
    // Log state operations
    // ========================================================================

    /// Get the current log state.
    pub async fn get_log_state(&self) -> Result<LogState> {
        let row = log_state::Entity::find_by_id(1)
            .one(&*self.conn)
            .await?
            .ok_or_else(|| Error::Internal("log state not found".into()))?;

        let root_hash = row
            .root_hash
            .and_then(|bytes| Sha256Hash::try_from_slice(&bytes).ok());

        Ok(LogState {
            next_index: LogIndex::new(row.next_index as u64),
            integrated_size: TreeSize::new(row.integrated_size as u64),
            root_hash,
        })
    }

    /// Atomically assign indices to a batch of entries.
    ///
    /// Returns the sequenced entries with their assigned indices.
    pub async fn sequence_entries(&self, entries: Vec<Entry>) -> Result<Vec<SequencedEntry>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let txn = self.conn.begin().await?;

        // Lock and get current state
        let state = log_state::Entity::find_by_id(1)
            .lock_exclusive()
            .one(&txn)
            .await?
            .ok_or_else(|| Error::Internal("log state not found".into()))?;

        let start_index = state.next_index as u64;
        let mut sequenced = Vec::with_capacity(entries.len());

        // Insert pending entries
        for (offset, entry) in entries.into_iter().enumerate() {
            let idx = start_index + offset as u64;

            let pending = pending_entries::ActiveModel {
                idx: ActiveValue::Set(idx as i64),
                data: ActiveValue::Set(entry.data().as_bytes().to_vec()),
                leaf_hash: ActiveValue::Set(entry.leaf_hash().as_bytes().to_vec()),
                created_at: ActiveValue::Set(chrono::Utc::now().into()),
            };

            pending_entries::Entity::insert(pending).exec(&txn).await?;

            sequenced.push(SequencedEntry::new(LogIndex::new(idx), entry));
        }

        // Update next_index
        let new_next_index = start_index + sequenced.len() as u64;
        log_state::Entity::update(log_state::ActiveModel {
            id: ActiveValue::Unchanged(1),
            next_index: ActiveValue::Set(new_next_index as i64),
            integrated_size: ActiveValue::Unchanged(state.integrated_size),
            root_hash: ActiveValue::Unchanged(state.root_hash),
        })
        .exec(&txn)
        .await?;

        txn.commit().await?;

        Ok(sequenced)
    }

    /// Get pending entries that need integration.
    ///
    /// Returns entries with indices in [from_index, from_index + limit).
    pub async fn get_pending_entries(
        &self,
        from_index: LogIndex,
        limit: usize,
    ) -> Result<Vec<PendingEntry>> {
        let rows = pending_entries::Entity::find()
            .filter(pending_entries::Column::Idx.gte(from_index.value() as i64))
            .order_by_asc(pending_entries::Column::Idx)
            .limit(limit as u64)
            .all(&*self.conn)
            .await?;

        rows.into_iter()
            .map(|row| {
                let leaf_hash = Sha256Hash::try_from_slice(&row.leaf_hash)
                    .map_err(|e| Error::Internal(format!("invalid leaf hash: {}", e)))?;

                Ok(PendingEntry {
                    index: LogIndex::new(row.idx as u64),
                    data: EntryData::new(row.data),
                    leaf_hash,
                })
            })
            .collect()
    }

    /// Mark entries as integrated up to the given size.
    ///
    /// Updates the integrated size and root hash, and deletes pending entries.
    pub async fn mark_integrated(&self, new_size: TreeSize, root_hash: Sha256Hash) -> Result<()> {
        let txn = self.conn.begin().await?;

        // Update log state
        log_state::Entity::update(log_state::ActiveModel {
            id: ActiveValue::Unchanged(1),
            next_index: ActiveValue::NotSet,
            integrated_size: ActiveValue::Set(new_size.value() as i64),
            root_hash: ActiveValue::Set(Some(root_hash.as_bytes().to_vec())),
        })
        .exec(&txn)
        .await?;

        // Delete integrated entries
        pending_entries::Entity::delete_many()
            .filter(pending_entries::Column::Idx.lt(new_size.value() as i64))
            .exec(&txn)
            .await?;

        txn.commit().await?;

        Ok(())
    }
}

/// Current log state.
#[derive(Debug, Clone)]
pub struct LogState {
    /// Next available index for sequencing.
    pub next_index: LogIndex,
    /// Size of the integrated tree.
    pub integrated_size: TreeSize,
    /// Root hash of the integrated tree (None if empty).
    pub root_hash: Option<Sha256Hash>,
}

impl LogState {
    /// Get the number of entries pending integration.
    pub fn pending_count(&self) -> u64 {
        self.next_index.value() - self.integrated_size.value()
    }
}

/// A pending entry awaiting integration.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    /// The assigned index.
    pub index: LogIndex,
    /// The entry data.
    pub data: EntryData,
    /// The precomputed leaf hash.
    pub leaf_hash: Sha256Hash,
}

// ============================================================================
// SeaORM entity definitions
// ============================================================================

mod log_state {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "log_state")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: i32,
        pub next_index: i64,
        pub integrated_size: i64,
        pub root_hash: Option<Vec<u8>>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod pending_entries {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "pending_entries")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub idx: i64,
        pub data: Vec<u8>,
        pub leaf_hash: Vec<u8>,
        pub created_at: DateTimeWithTimeZone,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
