//! Content-validating witnesses. Each request authenticates entries against a
//! signed checkpoint and commits content indices and witness state atomically.
pub mod handlers;
mod index;
pub use index::{ContentIndex, ContentIndexStore, IndexViolation, ViolationKind};

use crate::checkpoint::{CheckpointSignature, CheckpointSigner, CosignedCheckpoint};
use crate::client::LogClient;
use crate::error::Result;
use crate::witness::{
    verify_consistency, AddCheckpointRequest, CheckpointVerifier, LogConfig, WitnessError,
    WitnessStateStore, WitnessedState,
};
use async_trait::async_trait;
use ed25519_dalek::Signer;
use sea_orm::{ConnectionTrait, DatabaseConnection, TransactionTrait};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum ValidationResult {
    Valid,
    Invalid(ValidationError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "duplicate SHA256: {hash} (first seen at index {first_index}, now at {current_index})"
    )]
    DuplicateSha256 {
        hash: String,
        first_index: u64,
        current_index: u64,
    },
    #[error("filename '{filename}' already exists with different hash (first: {first_hash}, now: {current_hash})")]
    DuplicateFilename {
        filename: String,
        first_hash: String,
        current_hash: String,
        first_index: u64,
        current_index: u64,
    },
    #[error("failed to parse entry: {0}")]
    ParseError(String),
    #[error("{0}")]
    Other(String),
}

/// State is reloaded for the request's origin under a database writer lock.
/// Persistence must use the supplied connection, never a separate transaction.
#[async_trait]
pub trait Monitor: Send + Sync {
    async fn load_state<C: ConnectionTrait>(&self, conn: &C, origin: &str) -> Result<()>;
    async fn validate_entry(&self, index: u64, data: &[u8]) -> Result<ValidationResult>;
    async fn commit_entries<C: ConnectionTrait>(
        &self,
        conn: &C,
        origin: &str,
        from_index: u64,
        to_index: u64,
    ) -> Result<()>;
    async fn rollback_entries(&self) -> Result<()> {
        Ok(())
    }
    fn name(&self) -> &str;
}

pub struct MonitoringWitness<M: Monitor> {
    monitor: Arc<M>,
    signer: Arc<CheckpointSigner>,
    conn: Arc<DatabaseConnection>,
    state_store: WitnessStateStore,
    logs: Vec<LogConfig>,
    request_lock: tokio::sync::Mutex<()>,
}

impl<M: Monitor> MonitoringWitness<M> {
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
            request_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Content state is loaded per request, not shared between origins.
    pub async fn load_state(&self) -> Result<()> {
        self.ready().await
    }
    pub fn name(&self) -> &str {
        self.signer.name().as_str()
    }
    pub fn monitor_name(&self) -> &str {
        self.monitor.name()
    }

    pub async fn add_checkpoint(
        &self,
        request: AddCheckpointRequest,
    ) -> std::result::Result<CheckpointSignature, MonitorError> {
        // ponytail: one in-memory monitor; serialize requests and reload per origin.
        // Use separate per-origin monitor instances if throughput requires it.
        let _guard = self
            .request_lock
            .try_lock()
            .map_err(|_| MonitorError::Busy)?;
        let result = self.add_locked(request).await;
        if result.is_err() {
            self.monitor.rollback_entries().await.map_err(internal)?;
        }
        result
    }

    async fn add_locked(
        &self,
        request: AddCheckpointRequest,
    ) -> std::result::Result<CheckpointSignature, MonitorError> {
        let checkpoint = CosignedCheckpoint::from_text(&request.checkpoint)
            .map_err(|e| WitnessError::BadRequest(e.to_string()))?;
        let cp = &checkpoint.checkpoint;
        let origin = cp.origin.as_str();
        let log = self
            .logs
            .iter()
            .find(|l| l.origin == origin)
            .ok_or_else(|| WitnessError::UnknownLog(origin.to_string()))?;
        CheckpointVerifier::new(log.clone())
            .verify(&checkpoint)
            .map_err(|e| WitnessError::InvalidSignature(e.to_string()))?;
        let size = cp.size.value();
        if size > i64::MAX as u64 || request.old_size > size {
            return Err(WitnessError::BadRequest("invalid tree sizes".into()).into());
        }
        let state = self
            .state_store
            .get_or_init(origin)
            .await
            .map_err(internal)?;
        if request.old_size != state.size {
            return Err(WitnessError::Conflict(state.size).into());
        }
        verify_consistency(
            state.size,
            size,
            &state.root_hash,
            &cp.root_hash,
            &request.proof,
        )
        .map_err(|e| WitnessError::InvalidProof(e.to_string()))?;

        // Lock before loading content state, including across processes. The same
        // transaction commits both indices and checkpoint, or neither on failure.
        let txn = self.conn.begin().await.map_err(internal)?;
        if !WitnessStateStore::lock_in(&txn, &state)
            .await
            .map_err(internal)?
        {
            txn.rollback().await.map_err(internal)?;
            let current = self
                .state_store
                .get_or_init(origin)
                .await
                .map_err(internal)?;
            return Err(WitnessError::Conflict(current.size).into());
        }
        self.monitor.rollback_entries().await.map_err(internal)?;
        self.monitor
            .load_state(&txn, origin)
            .await
            .map_err(internal)?;
        if size > state.size {
            let url = log
                .url
                .as_ref()
                .ok_or_else(|| WitnessError::Internal("log URL not configured".into()))?;
            let client = LogClient::new(url).map_err(internal)?;
            for bundle_index in state.size / 256..size.div_ceil(256) {
                let bundle = client
                    .bundle(bundle_index, size)
                    .await
                    .map_err(invalid_content)?;
                for (offset, entry) in bundle.entries.iter().enumerate() {
                    let index = bundle_index * 256 + offset as u64;
                    if index < state.size {
                        continue;
                    }
                    client
                        .verify_entry(entry.as_bytes(), index, cp)
                        .await
                        .map_err(invalid_content)?;
                    match self
                        .monitor
                        .validate_entry(index, entry.as_bytes())
                        .await
                        .map_err(internal)?
                    {
                        ValidationResult::Valid => (),
                        ValidationResult::Invalid(err) => return Err(err.into()),
                    }
                }
            }
            self.monitor
                .commit_entries(&txn, origin, state.size, size)
                .await
                .map_err(internal)?;
        }
        if !WitnessStateStore::update_in(&txn, &state, size, cp.root_hash, &request.checkpoint)
            .await
            .map_err(internal)?
        {
            return Err(WitnessError::Conflict(state.size).into());
        }
        txn.commit().await.map_err(internal)?;
        let signature = self.signer.signing_key_ref().sign(cp.to_body().as_bytes());
        Ok(CheckpointSignature {
            name: self.signer.name().clone(),
            key_id: self.signer.key_id().clone(),
            signature,
        })
    }

    pub async fn get_state(&self, origin: &str) -> Result<Option<WitnessedState>> {
        self.state_store.get(origin).await
    }
    pub async fn ready(&self) -> Result<()> {
        self.state_store.list().await?;
        Ok(())
    }
}

fn internal(e: impl std::fmt::Display) -> MonitorError {
    WitnessError::Internal(e.to_string()).into()
}
fn invalid_content(e: impl std::fmt::Display) -> MonitorError {
    WitnessError::InvalidProof(e.to_string()).into()
}

#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    #[error("monitor busy; retry later")]
    Busy,
    #[error("{0}")]
    Witness(#[from] WitnessError),
    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
}
impl MonitorError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Busy => 503,
            Self::Witness(e) => e.status_code(),
            Self::Validation(_) => 422,
        }
    }
}
