//! Monitor module for validating transparency log contents.
//!
//! A monitor is a specialized witness that not only co-signs checkpoints
//! but also validates the log contents according to domain-specific rules.
//!
//! This module provides:
//! - A [`Monitor`] trait for implementing custom validation logic
//! - A [`ContentIndex`] for tracking seen entries and detecting duplicates
//! - A [`MonitoringWitness`] that wraps a monitor to create a validating witness
//!
//! For Conda-specific monitoring, see the `conda-monitor` crate.

pub mod handlers;
mod index;

pub use index::{ContentIndex, ContentIndexStore, IndexViolation, ViolationKind};

use crate::checkpoint::{CheckpointSignature, CheckpointSigner, CosignedCheckpoint};
use crate::error::Result;
use crate::witness::{
    verify_consistency, AddCheckpointRequest, CheckpointVerifier, LogConfig, WitnessError,
    WitnessStateStore, WitnessedState,
};
use async_trait::async_trait;
use ed25519_dalek::Signer;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

/// Validation result from a monitor.
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// Entry is valid.
    Valid,
    /// Entry violates a validation rule.
    Invalid(ValidationError),
}

/// Validation errors that can occur during monitoring.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// Duplicate SHA256 hash detected.
    #[error(
        "duplicate SHA256: {hash} (first seen at index {first_index}, now at {current_index})"
    )]
    DuplicateSha256 {
        hash: String,
        first_index: u64,
        current_index: u64,
    },

    /// Duplicate filename with different hash detected.
    #[error("filename '{filename}' already exists with different hash (first: {first_hash}, now: {current_hash})")]
    DuplicateFilename {
        filename: String,
        first_hash: String,
        current_hash: String,
        first_index: u64,
        current_index: u64,
    },

    /// Failed to parse entry data.
    #[error("failed to parse entry: {0}")]
    ParseError(String),

    /// Other validation failure.
    #[error("{0}")]
    Other(String),
}

/// Trait for implementing custom log content validation.
///
/// Monitors extend the basic witness functionality by validating log contents
/// before co-signing checkpoints. If validation fails, the monitor refuses
/// to sign.
///
/// Monitors support database persistence for their state (e.g., tracking seen
/// entries). The `load_state` method is called at startup, and `commit_entries`
/// persists newly validated entries.
#[async_trait]
pub trait Monitor: Send + Sync {
    /// Load persisted state from the database.
    ///
    /// Called at startup to restore the monitor's state from the database.
    /// The `origin` identifies which log's state to load.
    async fn load_state(&self, conn: &DatabaseConnection, origin: &str) -> Result<()>;

    /// Validate a single log entry.
    ///
    /// Called for each new entry when processing a checkpoint request.
    /// Returns `ValidationResult::Valid` if the entry passes all checks,
    /// or `ValidationResult::Invalid` with details if it fails.
    async fn validate_entry(&self, index: u64, data: &[u8]) -> Result<ValidationResult>;

    /// Called after all entries in a batch have been validated successfully.
    ///
    /// This commits the validated entries to both in-memory state and the
    /// database for persistence. The `origin` identifies which log the
    /// entries belong to.
    async fn commit_entries(
        &self,
        conn: &DatabaseConnection,
        origin: &str,
        from_index: u64,
        to_index: u64,
    ) -> Result<()>;

    /// Roll back entries staged during a failed validation attempt.
    async fn rollback_entries(&self) -> Result<()> {
        Ok(())
    }

    /// Get the name of this monitor (for logging/identification).
    fn name(&self) -> &str;
}

/// A monitoring witness that validates log contents before co-signing.
pub struct MonitoringWitness<M: Monitor> {
    /// The underlying monitor implementation.
    monitor: Arc<M>,
    /// The witness signer.
    signer: Arc<CheckpointSigner>,
    /// Database connection for persistence.
    conn: Arc<DatabaseConnection>,
    /// State store for tracking witnessed checkpoints.
    state_store: WitnessStateStore,
    /// Known logs and their verification keys.
    logs: Vec<LogConfig>,
    /// HTTP client for fetching log entries.
    http_client: reqwest::Client,
}

impl<M: Monitor> MonitoringWitness<M> {
    /// Create a new monitoring witness.
    pub fn new(
        monitor: Arc<M>,
        signer: Arc<CheckpointSigner>,
        conn: Arc<DatabaseConnection>,
        logs: Vec<LogConfig>,
    ) -> Self {
        Self {
            monitor,
            signer,
            conn: conn.clone(),
            state_store: WitnessStateStore::new(conn),
            logs,
            http_client: reqwest::Client::new(),
        }
    }

    /// Load persisted state for all configured logs.
    ///
    /// Call this after creating the witness to restore state from the database.
    pub async fn load_state(&self) -> Result<()> {
        for log in &self.logs {
            tracing::info!("Loading monitor state for log: {}", log.origin);
            self.monitor.load_state(&self.conn, &log.origin).await?;
        }
        Ok(())
    }

    /// Get the witness name.
    pub fn name(&self) -> &str {
        self.signer.name().as_str()
    }

    /// Get the monitor name.
    pub fn monitor_name(&self) -> &str {
        self.monitor.name()
    }

    /// Process an add-checkpoint request with content validation.
    ///
    /// This extends the standard witness flow by:
    /// 1. Fetching new entries from the log
    /// 2. Validating each entry against the monitor's rules
    /// 3. Only signing if all entries pass validation
    pub async fn add_checkpoint(
        &self,
        request: AddCheckpointRequest,
    ) -> std::result::Result<CheckpointSignature, MonitorError> {
        // 1. Parse and verify the checkpoint
        let checkpoint = CosignedCheckpoint::from_text(&request.checkpoint).map_err(|e| {
            MonitorError::Witness(WitnessError::BadRequest(format!(
                "invalid checkpoint: {}",
                e
            )))
        })?;

        let origin = checkpoint.checkpoint.origin.as_str();

        // 2. Find the log configuration
        let log_config =
            self.logs
                .iter()
                .find(|l| l.origin == origin)
                .ok_or(MonitorError::Witness(WitnessError::UnknownLog(
                    origin.to_string(),
                )))?;

        // 3. Verify the log's signature
        let verifier = CheckpointVerifier::new(log_config.clone());
        verifier
            .verify(&checkpoint)
            .map_err(|e| MonitorError::Witness(WitnessError::InvalidSignature(e.to_string())))?;

        let new_size = checkpoint.checkpoint.size.value();
        let new_root = checkpoint.checkpoint.root_hash;

        // 4. Validate old_size constraints
        if request.old_size > new_size {
            return Err(MonitorError::Witness(WitnessError::BadRequest(format!(
                "old_size ({}) > checkpoint size ({})",
                request.old_size, new_size
            ))));
        }

        // 5. Get or initialize state
        let state = self.state_store.get_or_init(origin).await.map_err(|e| {
            MonitorError::Witness(WitnessError::Internal(format!(
                "failed to get state: {}",
                e
            )))
        })?;

        // 6. Check for conflicts
        if request.old_size != state.size {
            return Err(MonitorError::Witness(WitnessError::Conflict(state.size)));
        }

        // 7. Verify consistency proof
        if state.size > 0 {
            if new_size < state.size {
                return Err(MonitorError::Witness(WitnessError::BadRequest(format!(
                    "checkpoint size ({}) < witnessed size ({})",
                    new_size, state.size
                ))));
            }

            if new_size == state.size {
                if new_root != state.root_hash {
                    return Err(MonitorError::Witness(WitnessError::InvalidProof(
                        "same size but different roots - split view detected".to_string(),
                    )));
                }
            } else {
                verify_consistency(
                    state.size,
                    new_size,
                    &state.root_hash,
                    &new_root,
                    &request.proof,
                )
                .map_err(|e| MonitorError::Witness(WitnessError::InvalidProof(e.to_string())))?;
            }
        } else if !request.proof.is_empty() {
            return Err(MonitorError::Witness(WitnessError::InvalidProof(
                "non-empty proof for empty tree".to_string(),
            )));
        }

        // 8. MONITOR-SPECIFIC: Fetch and validate new entries
        if new_size > state.size {
            let log_url = log_config.url.as_ref().ok_or_else(|| {
                MonitorError::Witness(WitnessError::Internal("log URL not configured".to_string()))
            })?;

            if let Err(err) = self
                .validate_new_entries(log_url, state.size, new_size)
                .await
            {
                if let Err(rollback_err) = self.monitor.rollback_entries().await {
                    tracing::warn!(
                        "failed to roll back monitor entries after validation error: {}",
                        rollback_err
                    );
                }
                return Err(err);
            }
        }

        // 9. Create cosignature
        let body = checkpoint.checkpoint.to_body();
        let signature = self.signer.signing_key_ref().sign(body.as_bytes());
        let cosig = CheckpointSignature {
            name: self.signer.name().clone(),
            key_id: self.signer.key_id().clone(),
            signature,
        };

        // 10. Commit the validated entries to the monitor's index and database
        if new_size > state.size {
            self.monitor
                .commit_entries(&self.conn, origin, state.size, new_size)
                .await
                .map_err(|e| {
                    MonitorError::Witness(WitnessError::Internal(format!(
                        "failed to commit entries: {}",
                        e
                    )))
                })?;
        }

        // 11. Update witness state
        self.state_store
            .update(origin, new_size, new_root, &request.checkpoint)
            .await
            .map_err(|e| {
                MonitorError::Witness(WitnessError::Internal(format!(
                    "failed to update state: {}",
                    e
                )))
            })?;

        Ok(cosig)
    }

    /// Fetch and validate new entries from the log.
    async fn validate_new_entries(
        &self,
        log_url: &str,
        from_index: u64,
        to_index: u64,
    ) -> std::result::Result<(), MonitorError> {
        tracing::info!(
            "Validating entries {} to {} from {}",
            from_index,
            to_index,
            log_url
        );

        // Fetch entries in batches (256 entries per bundle)
        const BUNDLE_SIZE: u64 = 256;

        let mut current = from_index;
        while current < to_index {
            let bundle_index = current / BUNDLE_SIZE;
            let bundle_start = bundle_index * BUNDLE_SIZE;

            // Fetch the entry bundle (pass tree_size for partial tile computation)
            let entries = self
                .fetch_entry_bundle(log_url, bundle_index, to_index)
                .await?;

            // Validate entries within this bundle that are in our range
            for (offset, entry_data) in entries.iter().enumerate() {
                let entry_index = bundle_start + offset as u64;

                if entry_index < from_index {
                    continue;
                }
                if entry_index >= to_index {
                    break;
                }

                // Validate the entry
                match self.monitor.validate_entry(entry_index, entry_data).await {
                    Ok(ValidationResult::Valid) => {
                        tracing::debug!("Entry {} validated successfully", entry_index);
                    }
                    Ok(ValidationResult::Invalid(err)) => {
                        tracing::warn!("Entry {} validation failed: {}", entry_index, err);
                        return Err(MonitorError::Validation(err));
                    }
                    Err(e) => {
                        return Err(MonitorError::Witness(WitnessError::Internal(format!(
                            "validation error at index {}: {}",
                            entry_index, e
                        ))));
                    }
                }
            }

            current = (bundle_index + 1) * BUNDLE_SIZE;
        }

        Ok(())
    }

    /// Fetch an entry bundle from the log.
    async fn fetch_entry_bundle(
        &self,
        log_url: &str,
        bundle_index: u64,
        tree_size: u64,
    ) -> std::result::Result<Vec<Vec<u8>>, MonitorError> {
        // Build the tile path for entries (with partial size if needed)
        const BUNDLE_SIZE: u64 = 256;
        let bundle_start = bundle_index * BUNDLE_SIZE;
        let bundle_end = (bundle_index + 1) * BUNDLE_SIZE;

        // If tree_size is less than bundle_end, this is a partial tile
        let path = if tree_size < bundle_end {
            let partial = tree_size - bundle_start;
            format_entry_path_with_partial(bundle_index, partial)
        } else {
            format_entry_path(bundle_index)
        };

        let url = format!("{}/tile/entries/{}", log_url.trim_end_matches('/'), path);

        tracing::debug!("Fetching entry bundle from {}", url);

        let response = self.http_client.get(&url).send().await.map_err(|e| {
            MonitorError::Witness(WitnessError::Internal(format!(
                "failed to fetch entries: {}",
                e
            )))
        })?;

        if !response.status().is_success() {
            return Err(MonitorError::Witness(WitnessError::Internal(format!(
                "failed to fetch entries: HTTP {}",
                response.status()
            ))));
        }

        let data = response.bytes().await.map_err(|e| {
            MonitorError::Witness(WitnessError::Internal(format!(
                "failed to read entry bundle: {}",
                e
            )))
        })?;

        // Parse the entry bundle (entries are length-prefixed)
        parse_entry_bundle(&data).map_err(|e| {
            MonitorError::Witness(WitnessError::Internal(format!(
                "failed to parse entry bundle: {}",
                e
            )))
        })
    }

    /// Get the current witnessed state for a log.
    pub async fn get_state(&self, origin: &str) -> Result<Option<WitnessedState>> {
        self.state_store.get(origin).await
    }

    /// Validate that the monitor witness can read persisted witness state.
    pub async fn ready(&self) -> Result<()> {
        let _ = self.state_store.list().await?;
        Ok(())
    }
}

/// Format an entry bundle path following the tlog-tiles spec.
fn format_entry_path(index: u64) -> String {
    if index == 0 {
        return "000".to_string();
    }

    let mut parts = Vec::new();
    let mut n = index;

    while n > 0 {
        parts.push(format!("{:03}", n % 1000));
        n /= 1000;
    }

    parts.reverse();

    // Add 'x' prefix to all but the last part
    let mut result = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            result.push('/');
        }
        if i < parts.len() - 1 {
            result.push('x');
        }
        result.push_str(part);
    }

    result
}

/// Format an entry bundle path with partial size suffix.
fn format_entry_path_with_partial(index: u64, partial: u64) -> String {
    let base = format_entry_path(index);
    format!("{}.p/{}", base, partial)
}

/// Parse an entry bundle (length-prefixed entries).
fn parse_entry_bundle(data: &[u8]) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Read 2-byte big-endian length prefix
        if offset + 2 > data.len() {
            return Err("truncated length prefix".to_string());
        }
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        // Read entry data
        if offset + len > data.len() {
            return Err(format!("truncated entry: expected {} bytes", len));
        }
        entries.push(data[offset..offset + len].to_vec());
        offset += len;
    }

    Ok(entries)
}

/// Errors from monitor operations.
#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    /// Witness-level error (same as WitnessError).
    #[error("{0}")]
    Witness(#[from] WitnessError),

    /// Validation failed.
    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
}

impl MonitorError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            MonitorError::Witness(e) => e.status_code(),
            MonitorError::Validation(_) => 422, // Unprocessable Entity
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_entry_path() {
        assert_eq!(format_entry_path(0), "000");
        assert_eq!(format_entry_path(1), "001");
        assert_eq!(format_entry_path(123), "123");
        assert_eq!(format_entry_path(1000), "x001/000");
        assert_eq!(format_entry_path(1234), "x001/234");
        assert_eq!(format_entry_path(123456), "x123/456");
    }

    #[test]
    fn test_parse_entry_bundle() {
        // Empty bundle
        assert_eq!(parse_entry_bundle(&[]).unwrap(), Vec::<Vec<u8>>::new());

        // Single entry: length=3, data=[1,2,3]
        let bundle = vec![0x00, 0x03, 0x01, 0x02, 0x03];
        let entries = parse_entry_bundle(&bundle).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], vec![1, 2, 3]);

        // Two entries
        let bundle = vec![
            0x00, 0x02, 0xAA, 0xBB, // entry 1: length=2, data=[0xAA, 0xBB]
            0x00, 0x01, 0xCC, // entry 2: length=1, data=[0xCC]
        ];
        let entries = parse_entry_bundle(&bundle).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], vec![0xAA, 0xBB]);
        assert_eq!(entries[1], vec![0xCC]);
    }
}
