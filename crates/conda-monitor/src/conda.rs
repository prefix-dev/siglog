//! Conda package log monitor.
//!
//! Validates Conda package log entries by checking:
//! 1. SHA256 uniqueness - no two packages can have the same SHA256 hash
//! 2. Filename uniqueness - a filename cannot reappear with a different SHA256
//!
//! These rules ensure:
//! - No duplicate package content (SHA256 check)
//! - No package replacement attacks (filename check)
//!
//! Keys are stored as SHA256 hashes for space efficiency. Values (like the
//! SHA256 associated with a filename) are stored verbatim for conflict reporting.

use async_trait::async_trait;
use siglog::error::Result;
use siglog::monitor::{
    ContentIndex, ContentIndexStore, Monitor, ValidationError, ValidationResult, ViolationKind,
};
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Hash a key using SHA256 and return as hex string.
///
/// This is used to store keys in a space-efficient, fixed-size format.
fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// A monitor for Conda package transparency logs.
///
/// Validates that:
/// - Each SHA256 hash appears only once (no duplicate content)
/// - Each filename maps to only one SHA256 (no package replacement)
pub struct CondaMonitor {
    /// Index of SHA256 hashes to first-seen index.
    sha256_index: Arc<ContentIndex>,
    /// Index of filenames to (first-seen index, SHA256).
    filename_index: Arc<ContentIndex>,
}

impl CondaMonitor {
    /// Create a new Conda monitor.
    pub fn new() -> Self {
        Self {
            sha256_index: Arc::new(ContentIndex::new("conda_sha256")),
            filename_index: Arc::new(ContentIndex::new("conda_filename")),
        }
    }

    /// Create a Conda monitor with pre-populated indices.
    ///
    /// Use this when restoring from persistence.
    pub fn with_indices(
        sha256_index: Arc<ContentIndex>,
        filename_index: Arc<ContentIndex>,
    ) -> Self {
        Self {
            sha256_index,
            filename_index,
        }
    }

    /// Get the SHA256 index.
    pub fn sha256_index(&self) -> &ContentIndex {
        &self.sha256_index
    }

    /// Get the filename index.
    pub fn filename_index(&self) -> &ContentIndex {
        &self.filename_index
    }

    /// Parse a Conda entry and extract sha256 and filename.
    fn parse_entry(data: &[u8]) -> std::result::Result<CondaEntry, ValidationError> {
        serde_json::from_slice(data)
            .map_err(|e| ValidationError::ParseError(format!("invalid JSON: {}", e)))
    }
}

impl Default for CondaMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Monitor for CondaMonitor {
    async fn load_state(&self, conn: &DatabaseConnection, origin: &str) -> Result<()> {
        let store = ContentIndexStore::new(Arc::new(conn.clone()));

        // Load SHA256 index
        let sha256_data = store.load(self.sha256_index.name(), origin).await?;
        let sha256_count = sha256_data.len();
        self.sha256_index.load_from(sha256_data).await;

        // Load filename index
        let filename_data = store.load(self.filename_index.name(), origin).await?;
        let filename_count = filename_data.len();
        self.filename_index.load_from(filename_data).await;

        tracing::info!(
            "Loaded {} SHA256 entries and {} filename entries for {}",
            sha256_count,
            filename_count,
            origin
        );

        Ok(())
    }

    async fn validate_entry(&self, index: u64, data: &[u8]) -> Result<ValidationResult> {
        // Parse the entry
        let entry = match Self::parse_entry(data) {
            Ok(e) => e,
            Err(e) => return Ok(ValidationResult::Invalid(e)),
        };

        // Hash the keys for space-efficient storage
        let sha256_key = hash_key(&entry.sha256);
        let filename_key = hash_key(&entry.filename);

        // Check SHA256 uniqueness
        if let Some(violation) = self.sha256_index.check(&sha256_key, index, None).await {
            return Ok(ValidationResult::Invalid(
                ValidationError::DuplicateSha256 {
                    hash: entry.sha256.clone(),
                    first_index: violation.first_index,
                    current_index: index,
                },
            ));
        }

        // Check filename uniqueness (with SHA256 as the associated value - stored verbatim)
        if let Some(violation) = self
            .filename_index
            .check(&filename_key, index, Some(&entry.sha256))
            .await
        {
            match violation.kind {
                ViolationKind::DuplicateKey => {
                    // Same filename, same SHA256 - this is actually fine
                    // (shouldn't happen if SHA256 check passed, but handle it)
                    tracing::debug!(
                        "Filename {} seen again at index {} (first at {}), but SHA256 matches",
                        entry.filename,
                        index,
                        violation.first_index
                    );
                }
                ViolationKind::ConflictingValue => {
                    // Same filename, different SHA256 - this is bad!
                    return Ok(ValidationResult::Invalid(
                        ValidationError::DuplicateFilename {
                            filename: entry.filename.clone(),
                            first_hash: violation.context.unwrap_or_default(),
                            current_hash: entry.sha256.clone(),
                            first_index: violation.first_index,
                            current_index: index,
                        },
                    ));
                }
            }
        }

        // Stage the entries for later commit (keys are hashed, values are verbatim)
        self.sha256_index.stage(sha256_key, index, None).await;
        self.filename_index
            .stage(filename_key, index, Some(entry.sha256))
            .await;

        Ok(ValidationResult::Valid)
    }

    async fn commit_entries(
        &self,
        conn: &DatabaseConnection,
        origin: &str,
        _from_index: u64,
        _to_index: u64,
    ) -> Result<()> {
        let store = ContentIndexStore::new(Arc::new(conn.clone()));

        // Commit SHA256 index and persist to database
        let sha256_entries = self.sha256_index.commit_and_drain().await;
        if !sha256_entries.is_empty() {
            store
                .save(self.sha256_index.name(), origin, &sha256_entries)
                .await?;
            tracing::debug!("Persisted {} SHA256 entries", sha256_entries.len());
        }

        // Commit filename index and persist to database
        let filename_entries = self.filename_index.commit_and_drain().await;
        if !filename_entries.is_empty() {
            store
                .save(self.filename_index.name(), origin, &filename_entries)
                .await?;
            tracing::debug!("Persisted {} filename entries", filename_entries.len());
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "conda"
    }
}

/// Minimal Conda package entry for validation.
///
/// We only need sha256 and filename for validation purposes.
#[derive(Debug, Deserialize)]
struct CondaEntry {
    /// SHA256 hash of the package.
    sha256: String,
    /// Filename of the package (e.g., "numpy-1.24.0-py39_0.tar.bz2").
    #[serde(alias = "fn")]
    filename: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use siglog::migration::Migrator;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    fn make_conda_entry(filename: &str, sha256: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "filename": filename,
            "sha256": sha256,
            "name": "test-package",
            "version": "1.0.0",
            "build": "py39_0",
        }))
        .unwrap()
    }

    async fn setup_test_db() -> DatabaseConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn test_valid_entries() {
        let conn = setup_test_db().await;
        let monitor = CondaMonitor::new();

        // First entry is always valid
        let data1 = make_conda_entry("pkg1-1.0.0.tar.bz2", "aaaa");
        let result = monitor.validate_entry(0, &data1).await.unwrap();
        assert!(matches!(result, ValidationResult::Valid));

        // Commit
        monitor
            .commit_entries(&conn, "test.log", 0, 1)
            .await
            .unwrap();

        // Different package is valid
        let data2 = make_conda_entry("pkg2-2.0.0.tar.bz2", "bbbb");
        let result = monitor.validate_entry(1, &data2).await.unwrap();
        assert!(matches!(result, ValidationResult::Valid));
    }

    #[tokio::test]
    async fn test_duplicate_sha256() {
        let conn = setup_test_db().await;
        let monitor = CondaMonitor::new();

        // Add first entry
        let data1 = make_conda_entry("pkg1-1.0.0.tar.bz2", "same_hash");
        let result = monitor.validate_entry(0, &data1).await.unwrap();
        assert!(matches!(result, ValidationResult::Valid));
        monitor
            .commit_entries(&conn, "test.log", 0, 1)
            .await
            .unwrap();

        // Same SHA256 with different filename should fail
        let data2 = make_conda_entry("pkg2-1.0.0.tar.bz2", "same_hash");
        let result = monitor.validate_entry(1, &data2).await.unwrap();
        assert!(matches!(
            result,
            ValidationResult::Invalid(ValidationError::DuplicateSha256 { .. })
        ));
    }

    #[tokio::test]
    async fn test_filename_replacement() {
        let conn = setup_test_db().await;
        let monitor = CondaMonitor::new();

        // Add first entry
        let data1 = make_conda_entry("pkg-1.0.0.tar.bz2", "hash1");
        let result = monitor.validate_entry(0, &data1).await.unwrap();
        assert!(matches!(result, ValidationResult::Valid));
        monitor
            .commit_entries(&conn, "test.log", 0, 1)
            .await
            .unwrap();

        // Same filename with different SHA256 should fail
        let data2 = make_conda_entry("pkg-1.0.0.tar.bz2", "hash2");
        let result = monitor.validate_entry(1, &data2).await.unwrap();
        assert!(matches!(
            result,
            ValidationResult::Invalid(ValidationError::DuplicateFilename { .. })
        ));
    }

    #[tokio::test]
    async fn test_invalid_json() {
        let monitor = CondaMonitor::new();

        let result = monitor.validate_entry(0, b"not json").await.unwrap();
        assert!(matches!(
            result,
            ValidationResult::Invalid(ValidationError::ParseError(_))
        ));
    }

    #[tokio::test]
    async fn test_missing_fields() {
        let monitor = CondaMonitor::new();

        // Missing sha256
        let data = serde_json::to_vec(&serde_json::json!({
            "filename": "pkg.tar.bz2",
        }))
        .unwrap();
        let result = monitor.validate_entry(0, &data).await.unwrap();
        assert!(matches!(
            result,
            ValidationResult::Invalid(ValidationError::ParseError(_))
        ));
    }
}
