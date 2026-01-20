//! Content index for tracking seen entries and detecting duplicates.
//!
//! The content index maintains mappings from content identifiers (like SHA256 hashes
//! or filenames) to the log indices where they first appeared. This enables
//! detecting duplicate or conflicting entries.

use crate::error::Result;
use sea_orm::{prelude::*, ActiveValue, DatabaseConnection, TransactionTrait};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// An index violation detected during validation.
#[derive(Debug, Clone)]
pub struct IndexViolation {
    /// The type of violation.
    pub kind: ViolationKind,
    /// The key that was violated (e.g., SHA256 hash or filename).
    pub key: String,
    /// The index where the key was first seen.
    pub first_index: u64,
    /// The current index where the duplicate was found.
    pub current_index: u64,
    /// Additional context (e.g., the conflicting hash for filename violations).
    pub context: Option<String>,
}

/// Types of index violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// Same key seen twice (e.g., duplicate SHA256).
    DuplicateKey,
    /// Same key with different associated value (e.g., filename with different SHA256).
    ConflictingValue,
}

/// In-memory content index with optional persistence.
///
/// Tracks mappings from keys to (first_index, optional_value) pairs.
/// Used for both SHA256 uniqueness (key only) and filename->hash mapping.
pub struct ContentIndex {
    /// In-memory index: key -> (first_index, optional_associated_value)
    index: RwLock<HashMap<String, (u64, Option<String>)>>,
    /// Pending entries not yet committed.
    pending: RwLock<Vec<PendingEntry>>,
    /// Name of this index (for logging).
    name: String,
}

#[derive(Debug, Clone)]
struct PendingEntry {
    key: String,
    index: u64,
    value: Option<String>,
}

impl ContentIndex {
    /// Create a new in-memory content index.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            pending: RwLock::new(Vec::new()),
            name: name.into(),
        }
    }

    /// Get the name of this index.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if a key exists and optionally validate its associated value.
    ///
    /// Returns `None` if the key doesn't exist or the value matches.
    /// Returns `Some(IndexViolation)` if there's a conflict.
    pub async fn check(
        &self,
        key: &str,
        current_index: u64,
        expected_value: Option<&str>,
    ) -> Option<IndexViolation> {
        // First check pending entries
        let pending = self.pending.read().await;
        for entry in pending.iter() {
            if entry.key == key {
                // Key exists in pending
                if let Some(expected) = expected_value {
                    if entry.value.as_deref() != Some(expected) {
                        return Some(IndexViolation {
                            kind: ViolationKind::ConflictingValue,
                            key: key.to_string(),
                            first_index: entry.index,
                            current_index,
                            context: entry.value.clone(),
                        });
                    }
                }
                // Same key, same value (or no value check) - duplicate
                return Some(IndexViolation {
                    kind: ViolationKind::DuplicateKey,
                    key: key.to_string(),
                    first_index: entry.index,
                    current_index,
                    context: None,
                });
            }
        }
        drop(pending);

        // Then check committed index
        let index = self.index.read().await;
        if let Some((first_index, stored_value)) = index.get(key) {
            if let Some(expected) = expected_value {
                if stored_value.as_deref() != Some(expected) {
                    return Some(IndexViolation {
                        kind: ViolationKind::ConflictingValue,
                        key: key.to_string(),
                        first_index: *first_index,
                        current_index,
                        context: stored_value.clone(),
                    });
                }
            }
            // Same key found
            return Some(IndexViolation {
                kind: ViolationKind::DuplicateKey,
                key: key.to_string(),
                first_index: *first_index,
                current_index,
                context: None,
            });
        }

        None
    }

    /// Check if a key exists (simple existence check).
    pub async fn contains(&self, key: &str) -> bool {
        // Check pending
        let pending = self.pending.read().await;
        if pending.iter().any(|e| e.key == key) {
            return true;
        }
        drop(pending);

        // Check committed
        let index = self.index.read().await;
        index.contains_key(key)
    }

    /// Stage an entry for later commit.
    ///
    /// This doesn't immediately add to the index, but records it as pending.
    /// Call `commit()` to finalize all pending entries.
    pub async fn stage(&self, key: String, index: u64, value: Option<String>) {
        let mut pending = self.pending.write().await;
        pending.push(PendingEntry { key, index, value });
    }

    /// Commit all pending entries to the main index.
    pub async fn commit(&self) {
        let mut pending = self.pending.write().await;
        let mut index = self.index.write().await;

        for entry in pending.drain(..) {
            index.insert(entry.key, (entry.index, entry.value));
        }
    }

    /// Rollback all pending entries (discard without committing).
    pub async fn rollback(&self) {
        let mut pending = self.pending.write().await;
        pending.clear();
    }

    /// Get the number of entries in the committed index.
    pub async fn len(&self) -> usize {
        let index = self.index.read().await;
        index.len()
    }

    /// Check if the committed index is empty.
    pub async fn is_empty(&self) -> bool {
        let index = self.index.read().await;
        index.is_empty()
    }

    /// Get the number of pending entries.
    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.read().await;
        pending.len()
    }

    /// Load entries from a pre-existing map (e.g., loaded from database).
    ///
    /// This replaces the current index contents.
    pub async fn load_from(&self, data: HashMap<String, (u64, Option<String>)>) {
        let mut index = self.index.write().await;
        *index = data;
    }

    /// Commit pending entries and return them for persistence.
    ///
    /// This commits the pending entries to the in-memory index and returns
    /// them as a vector of (key, first_index, value) tuples for saving to
    /// the database.
    pub async fn commit_and_drain(&self) -> Vec<(String, u64, Option<String>)> {
        let mut pending = self.pending.write().await;
        let mut index = self.index.write().await;

        let entries: Vec<_> = pending
            .drain(..)
            .map(|e| {
                let tuple = (e.key.clone(), e.index, e.value.clone());
                index.insert(e.key, (e.index, e.value));
                tuple
            })
            .collect();

        entries
    }
}

/// Persistent content index store using Sea ORM.
///
/// Stores content index entries in the database for persistence across restarts.
pub struct ContentIndexStore {
    conn: Arc<DatabaseConnection>,
}

impl ContentIndexStore {
    /// Create a new content index store.
    pub fn new(conn: Arc<DatabaseConnection>) -> Self {
        Self { conn }
    }

    /// Load all entries for a given index name and log origin.
    pub async fn load(
        &self,
        index_name: &str,
        origin: &str,
    ) -> Result<HashMap<String, (u64, Option<String>)>> {
        let rows = content_index::Entity::find()
            .filter(content_index::Column::IndexName.eq(index_name))
            .filter(content_index::Column::Origin.eq(origin))
            .all(&*self.conn)
            .await?;

        let mut map = HashMap::new();
        for row in rows {
            map.insert(row.key, (row.first_index as u64, row.value));
        }

        Ok(map)
    }

    /// Save entries to the database.
    pub async fn save(
        &self,
        index_name: &str,
        origin: &str,
        entries: &[(String, u64, Option<String>)],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let txn = self.conn.begin().await?;

        for (key, first_index, value) in entries {
            let model = content_index::ActiveModel {
                id: ActiveValue::NotSet,
                index_name: ActiveValue::Set(index_name.to_string()),
                origin: ActiveValue::Set(origin.to_string()),
                key: ActiveValue::Set(key.clone()),
                first_index: ActiveValue::Set(*first_index as i64),
                value: ActiveValue::Set(value.clone()),
            };

            content_index::Entity::insert(model)
                .on_conflict(
                    sea_orm::sea_query::OnConflict::columns([
                        content_index::Column::IndexName,
                        content_index::Column::Origin,
                        content_index::Column::Key,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .exec(&txn)
                .await?;
        }

        txn.commit().await?;
        Ok(())
    }
}

// ============================================================================
// SeaORM entity definitions
// ============================================================================

mod content_index {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "content_index")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub index_name: String,
        pub origin: String,
        pub key: String,
        pub first_index: i64,
        pub value: Option<String>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_content_index_basic() {
        let index = ContentIndex::new("test");

        // Initially empty
        assert!(index.is_empty().await);
        assert!(!index.contains("key1").await);

        // Stage an entry
        index.stage("key1".to_string(), 0, None).await;
        assert_eq!(index.pending_count().await, 1);

        // Pending entries should be visible in contains check
        assert!(index.contains("key1").await);

        // Check should find the pending entry
        let violation = index.check("key1", 1, None).await;
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().kind, ViolationKind::DuplicateKey);

        // Commit
        index.commit().await;
        assert_eq!(index.pending_count().await, 0);
        assert_eq!(index.len().await, 1);

        // Still findable after commit
        assert!(index.contains("key1").await);
    }

    #[tokio::test]
    async fn test_content_index_value_conflict() {
        let index = ContentIndex::new("test");

        // Stage entry with value
        index
            .stage("filename.tar.gz".to_string(), 0, Some("hash1".to_string()))
            .await;
        index.commit().await;

        // Same key, same value - should be DuplicateKey
        let violation = index.check("filename.tar.gz", 1, Some("hash1")).await;
        assert!(violation.is_some());
        assert_eq!(violation.unwrap().kind, ViolationKind::DuplicateKey);

        // Same key, different value - should be ConflictingValue
        let violation = index.check("filename.tar.gz", 2, Some("hash2")).await;
        assert!(violation.is_some());
        let v = violation.unwrap();
        assert_eq!(v.kind, ViolationKind::ConflictingValue);
        assert_eq!(v.context, Some("hash1".to_string()));
    }

    #[tokio::test]
    async fn test_content_index_rollback() {
        let index = ContentIndex::new("test");

        index.stage("key1".to_string(), 0, None).await;
        index.stage("key2".to_string(), 1, None).await;
        assert_eq!(index.pending_count().await, 2);

        index.rollback().await;
        assert_eq!(index.pending_count().await, 0);
        assert!(index.is_empty().await);
    }
}
