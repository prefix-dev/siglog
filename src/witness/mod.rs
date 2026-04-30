//! Witness module for co-signing transparency log checkpoints.
//!
//! A witness is a third-party service that verifies consistency proofs from
//! transparency logs and co-signs checkpoints to prevent split-view attacks.
//!
//! This module implements the C2SP tlog-witness specification:
//! <https://c2sp.org/tlog-witness>

pub mod handlers;
mod proof;
mod state;
mod verifier;

#[cfg(test)]
mod litewitness_test;

pub use proof::{verify_consistency, ConsistencyProof};
pub use state::WitnessStateStore;
pub use verifier::{CheckpointVerifier, LogConfig};

use crate::checkpoint::{CheckpointSignature, CheckpointSigner, CosignedCheckpoint};
use crate::error::{Error, Result};
use ed25519_dalek::Signer;
use sea_orm::DatabaseConnection;
use sigstore_types::Sha256Hash;
use std::sync::Arc;

/// A witness that co-signs checkpoints after verifying consistency.
pub struct Witness {
    /// The witness signer (for creating cosignatures).
    signer: Arc<CheckpointSigner>,
    /// State store for tracking witnessed checkpoints.
    state_store: WitnessStateStore,
    /// Known logs and their verification keys.
    logs: Vec<LogConfig>,
}

impl Witness {
    /// Create a new witness.
    pub fn new(
        signer: Arc<CheckpointSigner>,
        conn: Arc<DatabaseConnection>,
        logs: Vec<LogConfig>,
    ) -> Self {
        Self {
            signer,
            state_store: WitnessStateStore::new(conn),
            logs,
        }
    }

    /// Get the witness name.
    pub fn name(&self) -> &str {
        self.signer.name().as_str()
    }

    /// Process an add-checkpoint request.
    ///
    /// Returns the cosignature line on success, or an error with appropriate
    /// HTTP status code semantics:
    /// - `WitnessError::Conflict(size)`: 409 with the actual size
    /// - `WitnessError::UnknownLog`: 404
    /// - `WitnessError::InvalidSignature`: 403
    /// - `WitnessError::InvalidProof`: 422
    /// - `WitnessError::BadRequest`: 400
    pub async fn add_checkpoint(
        &self,
        request: AddCheckpointRequest,
    ) -> std::result::Result<CheckpointSignature, WitnessError> {
        // 1. Parse and verify the checkpoint
        let checkpoint = CosignedCheckpoint::from_text(&request.checkpoint)
            .map_err(|e| WitnessError::BadRequest(format!("invalid checkpoint: {}", e)))?;

        let origin = checkpoint.checkpoint.origin.as_str();

        // 2. Find the log configuration
        let log_config = self
            .logs
            .iter()
            .find(|l| l.origin == origin)
            .ok_or(WitnessError::UnknownLog(origin.to_string()))?;

        // 3. Verify the log's signature on the checkpoint
        let verifier = CheckpointVerifier::new(log_config.clone());
        verifier
            .verify(&checkpoint)
            .map_err(|e| WitnessError::InvalidSignature(e.to_string()))?;

        let new_size = checkpoint.checkpoint.size.value();
        let new_root = checkpoint.checkpoint.root_hash;

        // 4. Validate old_size constraints
        if request.old_size > new_size {
            return Err(WitnessError::BadRequest(format!(
                "old_size ({}) > checkpoint size ({})",
                request.old_size, new_size
            )));
        }

        // 5. Get or initialize state for this log
        let state = self
            .state_store
            .get_or_init(origin)
            .await
            .map_err(|e| WitnessError::Internal(format!("failed to get state: {}", e)))?;

        // 6. Check for conflicts
        if request.old_size != state.size {
            return Err(WitnessError::Conflict(state.size));
        }

        // 7. Verify consistency proof (if not bootstrapping from empty)
        if state.size > 0 {
            if new_size < state.size {
                return Err(WitnessError::BadRequest(format!(
                    "checkpoint size ({}) < witnessed size ({})",
                    new_size, state.size
                )));
            }

            if new_size == state.size {
                // Same size - roots must match
                if new_root != state.root_hash {
                    return Err(WitnessError::InvalidProof(
                        "same size but different roots - split view detected".to_string(),
                    ));
                }
            } else {
                // Verify the consistency proof
                verify_consistency(
                    state.size,
                    new_size,
                    &state.root_hash,
                    &new_root,
                    &request.proof,
                )
                .map_err(|e| WitnessError::InvalidProof(e.to_string()))?;
            }
        } else if !request.proof.is_empty() {
            // Bootstrapping from empty - proof should be empty
            return Err(WitnessError::InvalidProof(
                "non-empty proof for empty tree".to_string(),
            ));
        }

        // 8. Create cosignature
        let body = checkpoint.checkpoint.to_body();
        let signature = self.signer.signing_key_ref().sign(body.as_bytes());
        let cosig = CheckpointSignature {
            name: self.signer.name().clone(),
            key_id: self.signer.key_id().clone(),
            signature,
        };

        // 9. Update state
        self.state_store
            .update(origin, new_size, new_root, &request.checkpoint)
            .await
            .map_err(|e| WitnessError::Internal(format!("failed to update state: {}", e)))?;

        Ok(cosig)
    }

    /// Get the current witnessed state for a log.
    pub async fn get_state(&self, origin: &str) -> Result<Option<WitnessedState>> {
        self.state_store.get(origin).await
    }

    /// Validate that the witness can read its persisted state.
    pub async fn ready(&self) -> Result<()> {
        let _ = self.state_store.list().await?;
        Ok(())
    }
}

/// Request to add a checkpoint for witnessing.
#[derive(Debug, Clone)]
pub struct AddCheckpointRequest {
    /// The tree size the requester believes the witness last saw.
    pub old_size: u64,
    /// The consistency proof from old_size to the new checkpoint's size.
    pub proof: ConsistencyProof,
    /// The full checkpoint text (with log signature).
    pub checkpoint: String,
}

impl AddCheckpointRequest {
    /// Parse from the wire format.
    ///
    /// Format:
    /// ```text
    /// old <size>
    /// <base64-hash-1>
    /// <base64-hash-2>
    /// ...
    /// <empty line>
    /// <checkpoint text>
    /// ```
    pub fn from_ascii(body: &str) -> Result<Self> {
        let mut lines = body.lines();

        // Parse "old <size>" line
        let old_line = lines
            .next()
            .ok_or_else(|| Error::InvalidEntry("missing old size line".into()))?;

        let old_size = if let Some(rest) = old_line.strip_prefix("old ") {
            rest.trim()
                .parse::<u64>()
                .map_err(|e| Error::InvalidEntry(format!("invalid old size: {}", e)))?
        } else {
            return Err(Error::InvalidEntry(format!(
                "expected 'old <size>', got '{}'",
                old_line
            )));
        };

        // Parse proof hashes until empty line
        let mut proof_hashes = Vec::new();
        // Maximum proof hashes: 64 (covers tree height up to 2^64)
        const MAX_PROOF_HASHES: usize = 64;

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }

            // Check limit before adding
            if proof_hashes.len() >= MAX_PROOF_HASHES {
                return Err(Error::InvalidEntry(format!(
                    "too many proof hashes: limit is {}",
                    MAX_PROOF_HASHES
                )));
            }
            let hash_bytes = base64::engine::general_purpose::STANDARD
                .decode(line)
                .map_err(|e| Error::InvalidEntry(format!("invalid proof hash base64: {}", e)))?;
            if hash_bytes.len() != 32 {
                return Err(Error::InvalidEntry(format!(
                    "proof hash must be 32 bytes, got {}",
                    hash_bytes.len()
                )));
            }
            let hash = Sha256Hash::try_from_slice(&hash_bytes)
                .map_err(|e| Error::InvalidEntry(format!("invalid hash: {}", e)))?;
            proof_hashes.push(hash);
        }

        // Rest is checkpoint text
        let checkpoint: String = lines.collect::<Vec<_>>().join("\n");
        if checkpoint.is_empty() {
            return Err(Error::InvalidEntry("missing checkpoint".into()));
        }

        Ok(Self {
            old_size,
            proof: ConsistencyProof::new(proof_hashes),
            checkpoint,
        })
    }
}

/// State of a witnessed checkpoint.
#[derive(Debug, Clone)]
pub struct WitnessedState {
    /// The log origin.
    pub origin: String,
    /// The tree size.
    pub size: u64,
    /// The root hash.
    pub root_hash: Sha256Hash,
}

/// Errors from witness operations.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// 409 Conflict - old_size doesn't match witnessed size.
    #[error("conflict: witnessed size is {0}")]
    Conflict(u64),

    /// 404 Not Found - unknown log origin.
    #[error("unknown log: {0}")]
    UnknownLog(String),

    /// 403 Forbidden - checkpoint signature doesn't verify.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// 422 Unprocessable Entity - consistency proof doesn't verify.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// 400 Bad Request - malformed request.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// 500 Internal Server Error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl WitnessError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            WitnessError::Conflict(_) => 409,
            WitnessError::UnknownLog(_) => 404,
            WitnessError::InvalidSignature(_) => 403,
            WitnessError::InvalidProof(_) => 422,
            WitnessError::BadRequest(_) => 400,
            WitnessError::Internal(_) => 500,
        }
    }
}

use base64::Engine;
