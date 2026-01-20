//! Background workers for integration and checkpoint publishing.

use crate::checkpoint::signer::{Checkpoint, CheckpointSigner, CosignedCheckpoint, Origin};
use crate::error::Result;
use crate::merkle::integrate::integrate;
use crate::merkle::{generate_consistency_proof_simple, EntryBundle};
use crate::storage::opendal::CheckpointData;
use crate::storage::{Database, TileStorage};
use crate::types::{EntryData, LogIndex, PartialSize, TileIndex, TreeSize};
use crate::vindex::VerifiableIndex;
use base64::{engine::general_purpose::STANDARD, Engine};
use sigstore_types::Sha256Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Configuration for an external witness service.
#[derive(Debug, Clone)]
pub struct ExternalWitness {
    /// Name of the witness (for logging).
    pub name: String,
    /// URL of the witness service (e.g., "http://localhost:8081").
    pub url: String,
}

impl ExternalWitness {
    /// Create a new external witness configuration.
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
        }
    }
}

/// Tracks the state of external witnesses.
#[derive(Debug, Default)]
struct ExternalWitnessState {
    /// Last known size for each witness (by URL).
    sizes: std::collections::HashMap<String, u64>,
}

impl ExternalWitnessState {
    fn get_size(&self, url: &str) -> u64 {
        *self.sizes.get(url).unwrap_or(&0)
    }

    fn set_size(&mut self, url: &str, size: u64) {
        self.sizes.insert(url.to_string(), size);
    }
}

/// Tracks the last published checkpoint state to avoid redundant publishes.
#[derive(Debug, Default)]
struct LastPublished {
    size: u64,
    root_hash: Option<Sha256Hash>,
}

/// Configuration for background workers.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// How often to check for pending entries.
    pub integration_interval: Duration,
    /// Maximum entries to integrate per batch.
    pub integration_batch_size: usize,
    /// How often to publish checkpoints.
    pub checkpoint_interval: Duration,
    /// Log origin string.
    pub origin: String,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            integration_interval: Duration::from_millis(100),
            integration_batch_size: 1024,
            checkpoint_interval: Duration::from_secs(1),
            origin: "example.com/log".to_string(),
        }
    }
}

/// Run the integration worker.
///
/// This worker:
/// 1. Polls for pending entries
/// 2. Integrates them into the Merkle tree
/// 3. Writes tiles to storage
/// 4. Marks entries as integrated
/// 5. Optionally indexes entries in vindex
pub async fn run_integration_worker(
    db: Database,
    storage: TileStorage,
    config: WorkerConfig,
    vindex: Option<Arc<VerifiableIndex>>,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!(
        "Starting integration worker{}",
        if vindex.is_some() { " with vindex" } else { "" }
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Integration worker shutting down");
                    return;
                }
            }
            _ = tokio::time::sleep(config.integration_interval) => {
                if let Err(e) = run_integration_cycle(&db, &storage, &config, vindex.as_ref()).await {
                    tracing::error!("Integration error: {}", e);
                }
            }
        }
    }
}

async fn run_integration_cycle(
    db: &Database,
    storage: &TileStorage,
    config: &WorkerConfig,
    vindex: Option<&Arc<VerifiableIndex>>,
) -> Result<()> {
    // Get current state
    let state = db.get_log_state().await?;

    if state.pending_count() == 0 {
        return Ok(());
    }

    tracing::debug!(
        "Integrating entries from {} to {}",
        state.integrated_size.value(),
        state.next_index.value()
    );

    // Get pending entries
    let pending = db
        .get_pending_entries(
            LogIndex::new(state.integrated_size.value()),
            config.integration_batch_size,
        )
        .await?;

    if pending.is_empty() {
        return Ok(());
    }

    // Collect leaf hashes
    let leaf_hashes: Vec<_> = pending.iter().map(|e| e.leaf_hash).collect();

    // Integrate into the tree
    let result = integrate(storage, state.integrated_size, &leaf_hashes).await?;

    // Write tiles
    for (tile_id, tile) in &result.tiles {
        let partial = crate::api::paths::partial_tile_size(
            tile_id.level.value(),
            tile_id.index.value(),
            result.new_size.value(),
        );

        storage
            .write_tile(
                tile_id.level,
                tile_id.index,
                PartialSize::new(partial),
                tile,
            )
            .await?;
    }

    // Write entry bundles
    write_entry_bundles(storage, &pending, state.integrated_size, result.new_size).await?;

    // Index entries in vindex if enabled
    if let Some(vi) = vindex {
        for entry in &pending {
            if let Err(e) = vi.index_entry(entry.index, entry.data.as_bytes()) {
                tracing::warn!("Failed to index entry {}: {}", entry.index.value(), e);
            }
        }
        // Flush vindex WAL periodically (if using WAL)
        if let Err(e) = vi.flush() {
            tracing::warn!("Failed to flush vindex WAL: {}", e);
        }
        tracing::debug!(
            "Indexed {} entries in vindex, total keys: {}",
            pending.len(),
            vi.key_count()
        );
    }

    // Mark entries as integrated
    db.mark_integrated(result.new_size, result.root_hash)
        .await?;

    tracing::info!(
        "Integrated {} entries, new size: {}, root: {}",
        pending.len(),
        result.new_size.value(),
        result.root_hash.to_hex()
    );

    Ok(())
}

/// Write entry bundles for the integrated entries.
async fn write_entry_bundles(
    storage: &TileStorage,
    pending: &[crate::storage::database::PendingEntry],
    from_size: TreeSize,
    to_size: TreeSize,
) -> Result<()> {
    use crate::api::paths::ENTRY_BUNDLE_WIDTH;

    let from = from_size.value();
    let to = to_size.value();

    // Group entries by bundle index
    let mut bundles: std::collections::HashMap<u64, Vec<&EntryData>> =
        std::collections::HashMap::new();

    for entry in pending {
        let bundle_idx = entry.index.value() / ENTRY_BUNDLE_WIDTH;
        bundles.entry(bundle_idx).or_default().push(&entry.data);
    }

    // Write each bundle
    for (bundle_idx, entries) in bundles {
        let partial = crate::api::paths::partial_tile_size(0, bundle_idx, to);

        // Load existing bundle if partial
        let mut bundle = if partial > 0 {
            let existing_partial = crate::api::paths::partial_tile_size(0, bundle_idx, from);
            if existing_partial > 0 {
                storage
                    .read_entry_bundle(
                        TileIndex::new(bundle_idx),
                        PartialSize::new(existing_partial),
                    )
                    .await?
                    .unwrap_or_default()
            } else {
                EntryBundle::new()
            }
        } else {
            EntryBundle::new()
        };

        // Append entries
        for entry_data in entries {
            bundle.push(entry_data.clone());
        }

        // Write bundle
        storage
            .write_entry_bundle(
                TileIndex::new(bundle_idx),
                PartialSize::new(partial),
                &bundle,
            )
            .await?;
    }

    Ok(())
}

/// Run the checkpoint publisher worker.
///
/// This worker periodically signs and publishes the current log state.
/// If witnesses are provided, they will also cosign the checkpoint.
pub async fn run_checkpoint_worker(
    db: Database,
    storage: TileStorage,
    signer: Arc<CheckpointSigner>,
    witnesses: Vec<Arc<CheckpointSigner>>,
    external_witnesses: Vec<ExternalWitness>,
    config: WorkerConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!(
        "Starting checkpoint publisher with {} in-process witnesses and {} external witnesses",
        witnesses.len(),
        external_witnesses.len()
    );

    let origin = Origin::new(config.origin.clone());
    let client = reqwest::Client::new();
    let mut witness_state = ExternalWitnessState::default();
    let mut last_published = LastPublished::default();

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("Checkpoint publisher shutting down");
                    return;
                }
            }
            _ = tokio::time::sleep(config.checkpoint_interval) => {
                if let Err(e) = publish_checkpoint(&db, &storage, &signer, &witnesses, &external_witnesses, &client, &origin, &mut witness_state, &mut last_published).await {
                    tracing::error!("Checkpoint publish error: {}", e);
                }
            }
        }
    }
}

async fn publish_checkpoint(
    db: &Database,
    storage: &TileStorage,
    signer: &CheckpointSigner,
    witnesses: &[Arc<CheckpointSigner>],
    external_witnesses: &[ExternalWitness],
    client: &reqwest::Client,
    origin: &Origin,
    witness_state: &mut ExternalWitnessState,
    last_published: &mut LastPublished,
) -> Result<()> {
    let state = db.get_log_state().await?;

    // Only publish if we have a root hash
    let root_hash = match state.root_hash {
        Some(h) => h,
        None => {
            if state.integrated_size.value() == 0 {
                // Empty tree - use empty root
                sigstore_types::Sha256Hash::from_bytes([
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
                    0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
                    0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ])
            } else {
                return Ok(()); // No root hash yet
            }
        }
    };

    let new_size = state.integrated_size.value();

    // Skip publishing if nothing has changed
    if last_published.size == new_size && last_published.root_hash.as_ref() == Some(&root_hash) {
        tracing::trace!(
            "Skipping checkpoint publish: tree unchanged (size={}, root={})",
            new_size,
            root_hash.to_hex()
        );
        return Ok(());
    }

    let checkpoint = Checkpoint::new(origin.clone(), state.integrated_size, root_hash);

    // Create cosigned checkpoint with the log's signature
    let mut cosigned = CosignedCheckpoint::new(checkpoint, signer);

    // Add in-process witness signatures
    for witness in witnesses {
        cosigned.add_signature(witness);
    }

    // Call external witnesses and merge their signatures
    for ext_witness in external_witnesses {
        let old_size = witness_state.get_size(&ext_witness.url);

        // Generate consistency proof if witness has witnessed an older size
        let proof = if old_size != 0 && old_size != new_size {
            match generate_consistency_proof_simple(storage, old_size, new_size).await {
                Ok(p) => {
                    tracing::debug!(
                        "Generated consistency proof for {} (from {} to {}, {} hashes)",
                        ext_witness.name,
                        old_size,
                        new_size,
                        p.len()
                    );
                    p
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to generate consistency proof for {}: {}",
                        ext_witness.name,
                        e
                    );
                    continue;
                }
            }
        } else {
            Vec::new()
        };

        match call_external_witness(
            client,
            ext_witness,
            &cosigned,
            old_size,
            &proof,
            witness_state,
        )
        .await
        {
            Ok(signature_line) => {
                if let Err(e) = cosigned.add_signature_line(&signature_line) {
                    tracing::warn!(
                        "Failed to parse signature from external witness {}: {}",
                        ext_witness.name,
                        e
                    );
                } else {
                    witness_state.set_size(&ext_witness.url, new_size);
                    tracing::debug!("Got signature from external witness: {}", ext_witness.name);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to get signature from external witness {}: {}",
                    ext_witness.name,
                    e
                );
            }
        }
    }

    let text = cosigned.to_text();

    storage
        .write_checkpoint(&CheckpointData::from(text))
        .await?;

    // Update last published state
    last_published.size = new_size;
    last_published.root_hash = Some(root_hash);

    tracing::debug!(
        "Published checkpoint: size={}, root={}, signatures={}",
        new_size,
        root_hash.to_hex(),
        cosigned.signature_count()
    );

    Ok(())
}

/// Call an external witness service to get its signature line.
/// Returns the signature line (e.g., "— witness_name base64sig") on success.
async fn call_external_witness(
    client: &reqwest::Client,
    witness: &ExternalWitness,
    checkpoint: &CosignedCheckpoint,
    old_size: u64,
    proof: &[Sha256Hash],
    witness_state: &mut ExternalWitnessState,
) -> Result<String> {
    let url = format!("{}/add-checkpoint", witness.url.trim_end_matches('/'));

    // Format request: "old <size>\n<proof_hashes>\n\n<checkpoint_text>"
    // Proof hashes are base64-encoded, one per line
    let proof_lines: String = proof
        .iter()
        .map(|h| STANDARD.encode(h.as_bytes()))
        .collect::<Vec<_>>()
        .join("\n");

    let request_body = if proof_lines.is_empty() {
        format!("old {}\n\n{}", old_size, checkpoint.to_text())
    } else {
        format!(
            "old {}\n{}\n\n{}",
            old_size,
            proof_lines,
            checkpoint.to_text()
        )
    };

    let response = client
        .post(&url)
        .header("Content-Type", "text/plain")
        .body(request_body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| crate::error::Error::Config(format!("witness request failed: {}", e)))?;

    if response.status() == reqwest::StatusCode::CONFLICT {
        // Parse the conflict response to get the witness's current size
        // Per C2SP spec: response body is just the size followed by newline
        let body = response.text().await.unwrap_or_default();
        if let Ok(size) = body.trim().parse::<u64>() {
            witness_state.set_size(&witness.url, size);
            tracing::debug!(
                "External witness {} has already witnessed size {}",
                witness.name,
                size
            );
        }
        return Err(crate::error::Error::Config(format!(
            "witness conflict: current size is {}",
            body.trim()
        )));
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(crate::error::Error::Config(format!(
            "witness returned {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        )));
    }

    // Return the signature line
    response
        .text()
        .await
        .map_err(|e| crate::error::Error::Config(format!("failed to read witness response: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::signer::{Checkpoint, CheckpointSignature};
    use crate::types::TreeSize;
    use ed25519_dalek::Signer;
    use sigstore_types::Sha256Hash;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_signer(name: &str) -> CheckpointSigner {
        CheckpointSigner::generate(name)
    }

    fn empty_root_hash() -> Sha256Hash {
        Sha256Hash::from_bytes([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ])
    }

    /// Create a signature line in the note format for testing.
    fn make_signature_line(signer: &CheckpointSigner, body: &str) -> String {
        let signature = signer.signing_key_ref().sign(body.as_bytes());
        let sig = CheckpointSignature {
            name: signer.name().clone(),
            key_id: signer.key_id().clone(),
            signature,
        };
        sig.to_line()
    }

    #[tokio::test]
    async fn test_call_external_witness_success() {
        // Start a mock witness server
        let mock_server = MockServer::start().await;

        // Create a witness signer to generate a valid signature
        let witness_signer = test_signer("test-witness");
        let log_signer = test_signer("test.log");

        // Create a checkpoint
        let checkpoint = Checkpoint::new(
            Origin::new("test.log".to_string()),
            TreeSize::new(10),
            empty_root_hash(),
        );
        let cosigned = CosignedCheckpoint::new(checkpoint, &log_signer);

        // Generate the expected signature line
        let body = cosigned.checkpoint.to_body();
        let sig_line = make_signature_line(&witness_signer, &body);

        // Configure mock to return the signature line
        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&sig_line))
            .mount(&mock_server)
            .await;

        // Call the external witness
        let client = reqwest::Client::new();
        let ext_witness = ExternalWitness::new("test-witness", mock_server.uri());
        let mut witness_state = ExternalWitnessState::default();

        let result =
            call_external_witness(&client, &ext_witness, &cosigned, 0, &[], &mut witness_state)
                .await;

        assert!(result.is_ok(), "Expected success, got: {:?}", result);
        assert_eq!(result.unwrap(), sig_line);
    }

    #[tokio::test]
    async fn test_call_external_witness_conflict() {
        // Start a mock witness server
        let mock_server = MockServer::start().await;

        let log_signer = test_signer("test.log");

        // Create a checkpoint
        let checkpoint = Checkpoint::new(
            Origin::new("test.log".to_string()),
            TreeSize::new(10),
            empty_root_hash(),
        );
        let cosigned = CosignedCheckpoint::new(checkpoint, &log_signer);

        // Configure mock to return 409 Conflict
        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(
                ResponseTemplate::new(409)
                    .insert_header("Content-Type", "text/x.tlog.size")
                    .set_body_string("5\n"),
            )
            .mount(&mock_server)
            .await;

        // Call the external witness
        let client = reqwest::Client::new();
        let ext_witness = ExternalWitness::new("test-witness", mock_server.uri());
        let mut witness_state = ExternalWitnessState::default();

        let result =
            call_external_witness(&client, &ext_witness, &cosigned, 0, &[], &mut witness_state)
                .await;

        assert!(result.is_err());
        // Should have updated witness state with the conflict size
        assert_eq!(witness_state.get_size(&mock_server.uri()), 5);
    }

    #[tokio::test]
    async fn test_multiple_external_witnesses() {
        // Start two mock witness servers
        let mock_witness1 = MockServer::start().await;
        let mock_witness2 = MockServer::start().await;

        // Create signers
        let log_signer = test_signer("test.log");
        let witness1_signer = test_signer("witness1");
        let witness2_signer = test_signer("witness2");

        // Create a checkpoint
        let checkpoint = Checkpoint::new(
            Origin::new("test.log".to_string()),
            TreeSize::new(10),
            empty_root_hash(),
        );
        let mut cosigned = CosignedCheckpoint::new(checkpoint, &log_signer);

        // Generate signature lines for both witnesses
        let body = cosigned.checkpoint.to_body();
        let sig_line1 = make_signature_line(&witness1_signer, &body);
        let sig_line2 = make_signature_line(&witness2_signer, &body);

        // Configure mocks
        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&sig_line1))
            .mount(&mock_witness1)
            .await;

        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&sig_line2))
            .mount(&mock_witness2)
            .await;

        // Call both witnesses
        let client = reqwest::Client::new();
        let mut witness_state = ExternalWitnessState::default();

        let ext_witnesses = vec![
            ExternalWitness::new("witness1", mock_witness1.uri()),
            ExternalWitness::new("witness2", mock_witness2.uri()),
        ];

        // Simulate what publish_checkpoint does for external witnesses
        for ext_witness in &ext_witnesses {
            let old_size = witness_state.get_size(&ext_witness.url);

            match call_external_witness(
                &client,
                ext_witness,
                &cosigned,
                old_size,
                &[],
                &mut witness_state,
            )
            .await
            {
                Ok(signature_line) => {
                    cosigned
                        .add_signature_line(&signature_line)
                        .expect("Failed to add signature line");
                    witness_state.set_size(&ext_witness.url, 10);
                }
                Err(e) => panic!("Witness call failed: {}", e),
            }
        }

        // Verify we have 3 signatures: log + 2 witnesses
        assert_eq!(
            cosigned.signature_count(),
            3,
            "Expected 3 signatures (log + 2 witnesses)"
        );

        // Verify the checkpoint text contains all signatures
        let text = cosigned.to_text();
        assert!(text.contains("— test.log "), "Missing log signature");
        assert!(text.contains("— witness1 "), "Missing witness1 signature");
        assert!(text.contains("— witness2 "), "Missing witness2 signature");
    }

    #[tokio::test]
    async fn test_external_witness_partial_failure() {
        // Start two mock witness servers
        let mock_witness1 = MockServer::start().await;
        let mock_witness2 = MockServer::start().await;

        // Create signers
        let log_signer = test_signer("test.log");
        let witness1_signer = test_signer("witness1");

        // Create a checkpoint
        let checkpoint = Checkpoint::new(
            Origin::new("test.log".to_string()),
            TreeSize::new(10),
            empty_root_hash(),
        );
        let mut cosigned = CosignedCheckpoint::new(checkpoint, &log_signer);

        // Generate signature for witness1 only
        let body = cosigned.checkpoint.to_body();
        let sig_line1 = make_signature_line(&witness1_signer, &body);

        // Configure mock1 to succeed, mock2 to fail
        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&sig_line1))
            .mount(&mock_witness1)
            .await;

        Mock::given(method("POST"))
            .and(path("/add-checkpoint"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&mock_witness2)
            .await;

        // Call both witnesses
        let client = reqwest::Client::new();
        let mut witness_state = ExternalWitnessState::default();

        let ext_witnesses = vec![
            ExternalWitness::new("witness1", mock_witness1.uri()),
            ExternalWitness::new("witness2", mock_witness2.uri()),
        ];

        let mut success_count = 0;
        let mut failure_count = 0;

        for ext_witness in &ext_witnesses {
            let old_size = witness_state.get_size(&ext_witness.url);

            match call_external_witness(
                &client,
                ext_witness,
                &cosigned,
                old_size,
                &[],
                &mut witness_state,
            )
            .await
            {
                Ok(signature_line) => {
                    cosigned
                        .add_signature_line(&signature_line)
                        .expect("Failed to add signature line");
                    witness_state.set_size(&ext_witness.url, 10);
                    success_count += 1;
                }
                Err(_) => {
                    failure_count += 1;
                }
            }
        }

        // Verify partial success
        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 1);
        assert_eq!(
            cosigned.signature_count(),
            2,
            "Expected 2 signatures (log + 1 successful witness)"
        );
    }
}
