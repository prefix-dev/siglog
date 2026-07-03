//! Bulk import: build the Merkle tree, tiles, entry bundles, vindex, and
//! checkpoint for a large batch of entries in one pass.
//!
//! The incremental integration path rewrites each partial tile up to 256
//! times as the tree grows and acknowledges entries batch-by-batch — the
//! right behavior for a live log, but needlessly slow for a one-time
//! bootstrap. This module instead:
//!
//! 1. Streams entries in chunks aligned to the tile width, reusing the same
//!    [`integrate`] tree builder as the live path (so the resulting tree is
//!    byte-identical to what incremental integration would produce),
//! 2. Uploads the resulting tiles and entry bundles **concurrently**,
//! 3. Builds the vindex in the same pass and finishes with a snapshot,
//! 4. Sets the database log state once, at the very end, and signs a single
//!    checkpoint.
//!
//! Crash safety: object writes are idempotent, and the database state is
//! only written after every object upload succeeded — so an interrupted
//! import can simply be re-run. With [`ImportConfig::resume`] set, objects
//! that already exist are skipped (the re-run must use the same chunk size
//! so partial-tile paths line up).

use crate::checkpoint::signer::{Checkpoint, CheckpointSigner, CosignedCheckpoint, Origin};
use crate::error::{Error, Result};
use crate::merkle::integrate::integrate;
use crate::merkle::EntryBundle;
use crate::storage::opendal::CheckpointData;
use crate::storage::{Database, TileStorage};
use crate::types::{Entry, LogIndex, PartialSize, TileIndex, TreeSize};
use crate::vindex::VerifiableIndex;
use futures::stream::StreamExt;
use sigstore_types::Sha256Hash;
use std::sync::Arc;

/// Entries per bundle / hashes per tile.
const TILE_WIDTH: usize = 256;

/// Configuration for a bulk import.
#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// Log origin for the final checkpoint.
    pub origin: String,
    /// Entries per integration chunk. Must be a multiple of 256. Larger
    /// chunks mean fewer partial-tile rewrites at upper levels but more
    /// memory per chunk.
    pub chunk_size: usize,
    /// Maximum concurrent object uploads.
    pub upload_concurrency: usize,
    /// Skip uploading objects that already exist (resuming an interrupted
    /// import). The resumed run must use the same chunk size.
    pub resume: bool,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            origin: "example.com/log".to_string(),
            chunk_size: 65536,
            upload_concurrency: 32,
            resume: false,
        }
    }
}

/// Summary of a completed bulk import.
#[derive(Debug)]
pub struct ImportSummary {
    /// Total entries imported.
    pub entries: u64,
    /// Final tree size (== entries).
    pub tree_size: u64,
    /// Final root hash.
    pub root_hash: Sha256Hash,
    /// Objects uploaded (tiles + bundles).
    pub objects_written: u64,
    /// Objects skipped because they already existed (resume).
    pub objects_skipped: u64,
}

/// Run a bulk import from an entry iterator into an **empty** log.
///
/// `entries` yields the raw bytes of each log entry, already in their final
/// (normalized) form. The database log state must be empty; it is written
/// once, after all objects are durably uploaded.
pub async fn bulk_import<I>(
    db: &Database,
    storage: &TileStorage,
    signer: &CheckpointSigner,
    vindex: Option<&Arc<VerifiableIndex>>,
    config: &ImportConfig,
    entries: I,
) -> Result<ImportSummary>
where
    I: IntoIterator<Item = Result<Vec<u8>>>,
{
    if config.chunk_size == 0 || config.chunk_size % TILE_WIDTH != 0 {
        return Err(Error::Config(format!(
            "chunk_size must be a positive multiple of {}, got {}",
            TILE_WIDTH, config.chunk_size
        )));
    }
    let origin = Origin::new(config.origin.clone())?;

    // The import target must be an empty log: importing on top of existing
    // entries would require the incremental path, and overwriting an
    // existing tree would fork it.
    let state = db.get_log_state().await?;
    if state.next_index.value() != 0 || state.integrated_size.value() != 0 {
        return Err(Error::Config(format!(
            "bulk import requires an empty log; found next_index={}, integrated_size={}",
            state.next_index.value(),
            state.integrated_size.value()
        )));
    }

    let mut entries = entries.into_iter();
    let mut tree_size: u64 = 0;
    let mut root_hash = None;
    let mut written: u64 = 0;
    let mut skipped: u64 = 0;

    loop {
        // Collect the next chunk.
        let mut chunk_data: Vec<Vec<u8>> = Vec::with_capacity(config.chunk_size);
        for entry in entries.by_ref() {
            let data = entry?;
            if data.is_empty() {
                return Err(Error::InvalidEntry(format!(
                    "entry {} is empty",
                    tree_size + chunk_data.len() as u64
                )));
            }
            if data.len() > crate::api::handlers::MAX_ENTRY_SIZE {
                return Err(Error::InvalidEntry(format!(
                    "entry {} is {} bytes (max {})",
                    tree_size + chunk_data.len() as u64,
                    data.len(),
                    crate::api::handlers::MAX_ENTRY_SIZE
                )));
            }
            chunk_data.push(data);
            if chunk_data.len() == config.chunk_size {
                break;
            }
        }
        if chunk_data.is_empty() {
            break;
        }

        // Hash and index the chunk.
        let mut leaf_hashes = Vec::with_capacity(chunk_data.len());
        for (offset, data) in chunk_data.iter().enumerate() {
            let idx = tree_size + offset as u64;
            leaf_hashes.push(*Entry::new(data.clone()).leaf_hash());
            if let Some(vi) = vindex {
                vi.index_entry(LogIndex::new(idx), data)?;
            }
        }

        // Build this chunk of the tree with the same code path as live
        // integration (loads the compact range from already-written tiles).
        let result = integrate(storage, TreeSize::new(tree_size), &leaf_hashes).await?;
        let new_size = result.new_size.value();

        // Upload tiles concurrently (bounded by upload_concurrency).
        let tile_jobs: Vec<_> = result
            .tiles
            .iter()
            .map(|(tile_id, tile)| {
                let partial = crate::api::paths::partial_tile_size(
                    tile_id.level.value(),
                    tile_id.index.value(),
                    new_size,
                );
                let path = crate::api::paths::tile_path(
                    tile_id.level.value(),
                    tile_id.index.value(),
                    partial,
                );
                async move {
                    if config.resume && storage.exists(&path).await? {
                        return Ok::<bool, Error>(false);
                    }
                    storage
                        .write_tile(
                            tile_id.level,
                            tile_id.index,
                            PartialSize::new(partial),
                            tile,
                        )
                        .await?;
                    Ok(true)
                }
            })
            .collect();
        let mut stream = futures::stream::iter(tile_jobs)
            .buffer_unordered(config.upload_concurrency.max(1));
        while let Some(wrote) = stream.next().await {
            if wrote? {
                written += 1;
            } else {
                skipped += 1;
            }
        }
        drop(stream);

        // Upload entry bundles concurrently. Chunks are 256-aligned, so
        // every bundle here is full except possibly the final one.
        let first_bundle = tree_size / TILE_WIDTH as u64;
        let bundle_jobs: Vec<_> = chunk_data
            .chunks(TILE_WIDTH)
            .enumerate()
            .map(|(i, bundle_entries)| {
                let bundle_idx = first_bundle + i as u64;
                let partial = crate::api::paths::partial_tile_size(0, bundle_idx, new_size);
                let path = crate::api::paths::entries_path(bundle_idx, partial);
                let bundle = EntryBundle::with_entries(
                    bundle_entries
                        .iter()
                        .map(|d| crate::types::EntryData::new(d.clone()))
                        .collect(),
                );
                async move {
                    if config.resume && storage.exists(&path).await? {
                        return Ok::<bool, Error>(false);
                    }
                    storage
                        .write_entry_bundle(
                            TileIndex::new(bundle_idx),
                            PartialSize::new(partial),
                            &bundle,
                        )
                        .await?;
                    Ok(true)
                }
            })
            .collect();
        let mut stream = futures::stream::iter(bundle_jobs)
            .buffer_unordered(config.upload_concurrency.max(1));
        while let Some(wrote) = stream.next().await {
            if wrote? {
                written += 1;
            } else {
                skipped += 1;
            }
        }
        drop(stream);

        if let Some(vi) = vindex {
            vi.flush()?;
        }

        tree_size = new_size;
        root_hash = Some(result.root_hash);
        tracing::info!(
            "Imported {} entries (root {})",
            tree_size,
            result.root_hash.to_hex()
        );
    }

    let root_hash = root_hash.ok_or_else(|| Error::InvalidEntry("no entries to import".into()))?;

    // Persist the vindex snapshot before the DB state: the vindex must
    // never be behind the database.
    if let Some(vi) = vindex {
        vi.flush()?;
        vi.snapshot()?;
    }

    // Only now, with every object durably uploaded, commit the log state.
    db.initialize_imported_state(TreeSize::new(tree_size), root_hash)
        .await?;

    // Sign and publish the checkpoint. Witness cosignatures are collected
    // by the live server's checkpoint worker once it starts.
    let checkpoint = Checkpoint::new(origin, TreeSize::new(tree_size), root_hash);
    let cosigned = CosignedCheckpoint::new(checkpoint, signer);
    storage
        .write_checkpoint(&CheckpointData::from(cosigned.to_text()))
        .await?;

    Ok(ImportSummary {
        entries: tree_size,
        tree_size,
        root_hash,
        objects_written: written,
        objects_skipped: skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vindex::JsonKeysMapFn;
    use opendal::{services::Memory, Operator};

    fn mem_storage() -> TileStorage {
        TileStorage::new(Operator::new(Memory::default()).unwrap().finish())
    }

    async fn mem_db() -> Database {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.run_migrations().await.unwrap();
        db
    }

    fn test_entries(n: usize) -> Vec<Result<Vec<u8>>> {
        (0..n)
            .map(|i| Ok(format!(r#"{{"name":"pkg-{:05}","version":"1.0"}}"#, i).into_bytes()))
            .collect()
    }

    fn config(chunk_size: usize) -> ImportConfig {
        ImportConfig {
            origin: "import.test/log".to_string(),
            chunk_size,
            upload_concurrency: 8,
            resume: false,
        }
    }

    /// The bulk import must produce the exact same tree as one-shot
    /// integration of the same leaves — chunking must be invisible.
    #[tokio::test]
    async fn test_import_root_matches_single_integration() {
        let n = 700; // spans multiple bundles with a partial tail

        // Reference root: single integrate() call over all leaves.
        let reference = mem_storage();
        let leaves: Vec<_> = test_entries(n)
            .into_iter()
            .map(|e| *Entry::new(e.unwrap()).leaf_hash())
            .collect();
        let expected = integrate(&reference, TreeSize::new(0), &leaves)
            .await
            .unwrap();

        // Bulk import with small chunks.
        let storage = mem_storage();
        let db = mem_db().await;
        let signer = CheckpointSigner::generate("import.test/log");
        let summary = bulk_import(
            &db,
            &storage,
            &signer,
            None,
            &config(256),
            test_entries(n),
        )
        .await
        .unwrap();

        assert_eq!(summary.tree_size, n as u64);
        assert_eq!(summary.root_hash, expected.root_hash);

        // DB state committed.
        let state = db.get_log_state().await.unwrap();
        assert_eq!(state.integrated_size.value(), n as u64);
        assert_eq!(state.root_hash, Some(expected.root_hash));

        // Checkpoint written and parseable.
        let ckpt = storage.read_checkpoint().await.unwrap().unwrap();
        let cosigned = CosignedCheckpoint::from_text(ckpt.as_str().unwrap()).unwrap();
        assert_eq!(cosigned.checkpoint.size.value(), n as u64);
        assert_eq!(cosigned.checkpoint.root_hash, expected.root_hash);

        // All entry bundles present and correctly sized.
        for bundle_idx in 0..=(n as u64 - 1) / 256 {
            let partial = crate::api::paths::partial_tile_size(0, bundle_idx, n as u64);
            let bundle = storage
                .read_entry_bundle(TileIndex::new(bundle_idx), PartialSize::new(partial))
                .await
                .unwrap()
                .unwrap();
            let expected_len = if partial == 0 { 256 } else { partial as usize };
            assert_eq!(bundle.entries.len(), expected_len);
        }
    }

    /// Root must not depend on the chunk size.
    #[tokio::test]
    async fn test_import_chunk_size_invariance() {
        let n = 600;
        let mut roots = Vec::new();
        for chunk in [256usize, 512, 65536] {
            let storage = mem_storage();
            let db = mem_db().await;
            let signer = CheckpointSigner::generate("import.test/log");
            let summary = bulk_import(
                &db,
                &storage,
                &signer,
                None,
                &config(chunk),
                test_entries(n),
            )
            .await
            .unwrap();
            roots.push(summary.root_hash);
        }
        assert!(roots.windows(2).all(|w| w[0] == w[1]));
    }

    /// Importing into a non-empty log must be refused.
    #[tokio::test]
    async fn test_import_requires_empty_log() {
        let storage = mem_storage();
        let db = mem_db().await;
        let signer = CheckpointSigner::generate("import.test/log");

        bulk_import(&db, &storage, &signer, None, &config(256), test_entries(10))
            .await
            .unwrap();

        // Second import must fail: the log is no longer empty.
        let result = bulk_import(
            &db,
            &storage,
            &signer,
            None,
            &config(256),
            test_entries(10),
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty log"));
    }

    /// Resume: a re-run over already-written objects skips them and
    /// produces the same root.
    #[tokio::test]
    async fn test_import_resume_skips_existing() {
        let n = 300;
        let storage = mem_storage();
        let signer = CheckpointSigner::generate("import.test/log");

        // First (simulated interrupted) run: objects written, but pretend
        // the process died before the DB commit by using a throwaway DB.
        let db1 = mem_db().await;
        let first = bulk_import(&db1, &storage, &signer, None, &config(256), test_entries(n))
            .await
            .unwrap();
        assert!(first.objects_written > 0);
        assert_eq!(first.objects_skipped, 0);

        // Resume against the same storage with a fresh (still-empty) DB.
        let db2 = mem_db().await;
        let mut cfg = config(256);
        cfg.resume = true;
        let resumed = bulk_import(&db2, &storage, &signer, None, &cfg, test_entries(n))
            .await
            .unwrap();

        assert_eq!(resumed.root_hash, first.root_hash);
        assert_eq!(resumed.objects_written, 0, "everything already uploaded");
        assert_eq!(resumed.objects_skipped, first.objects_written);
        let state = db2.get_log_state().await.unwrap();
        assert_eq!(state.integrated_size.value(), n as u64);
    }

    /// Vindex built during import must serve correct lookups and survive a
    /// restart via its snapshot.
    #[tokio::test]
    async fn test_import_builds_vindex() {
        let n = 300;
        let temp_dir = tempfile::tempdir().unwrap();
        let wal_path = temp_dir.path().join("vindex.wal");

        let storage = mem_storage();
        let db = mem_db().await;
        let signer = CheckpointSigner::generate("import.test/log");
        let vi = Arc::new(
            VerifiableIndex::with_wal(Arc::new(JsonKeysMapFn::new("name")), &wal_path, 0).unwrap(),
        );

        bulk_import(
            &db,
            &storage,
            &signer,
            Some(&vi),
            &config(256),
            test_entries(n),
        )
        .await
        .unwrap();

        assert_eq!(vi.tree_size(), n as u64);
        let result = vi.lookup_string("pkg-00042");
        assert!(result.found);
        assert_eq!(result.indices[0].value(), 42);

        // Snapshot was written; a restart at the imported size must load it.
        let restored = VerifiableIndex::with_wal(
            Arc::new(JsonKeysMapFn::new("name")),
            &wal_path,
            n as u64,
        )
        .unwrap();
        assert_eq!(restored.root_hash(), vi.root_hash());
    }
}
