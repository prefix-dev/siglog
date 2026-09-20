//! Offline, Tessera-only bootstrap. The server must be stopped.
//!
//! Inputs are fingerprinted before writing and checked again before committing.
//! All objects are immutable/content-checked on resume. The database transaction
//! holds the writer lock until every upload succeeds. No checkpoint is published:
//! the normal server collects its configured witness quorum after startup.

use crate::api::{handlers::MAX_ENTRY_SIZE, paths};
use crate::error::{Error, Result};
use crate::merkle::{integrate::integrate, EntryBundle};
use crate::storage::{Database, TileStorage};
use crate::types::{EntryData, TreeSize};
use futures::{stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigstore_types::Sha256Hash;

const MANIFEST_PATH: &str = "import-manifest.json";

/// Fingerprint of ordered entries: SHA256 of each u64-BE length followed by bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSummary {
    pub entries: u64,
    pub sha256: String,
}

impl InputSummary {
    pub fn scan(entries: impl IntoIterator<Item = Result<Vec<u8>>>) -> Result<Self> {
        let mut digest = Sha256::new();
        let mut count = 0u64;
        for entry in entries {
            let data = entry?;
            fingerprint_entry(&mut digest, &data)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| Error::InvalidEntry("too many entries".into()))?;
        }
        if count == 0 || count > i64::MAX as u64 {
            return Err(Error::InvalidEntry(
                "input must contain 1..=i64::MAX entries".into(),
            ));
        }
        Ok(Self {
            entries: count,
            sha256: hex::encode(digest.finalize()),
        })
    }
}

fn fingerprint_entry(digest: &mut Sha256, data: &[u8]) -> Result<()> {
    if data.is_empty() || data.len() > MAX_ENTRY_SIZE {
        return Err(Error::InvalidEntry(format!(
            "entry size must be 1..={MAX_ENTRY_SIZE}, got {}",
            data.len()
        )));
    }
    digest.update((data.len() as u64).to_be_bytes());
    digest.update(data);
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ImportConfig {
    /// A positive multiple of 256, at most 65536. Memory is proportional to this.
    pub chunk_size: usize,
    pub upload_concurrency: usize,
    pub resume: bool,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            chunk_size: 4096,
            upload_concurrency: 16,
            resume: false,
        }
    }
}

#[derive(Debug)]
pub struct ImportSummary {
    pub tree_size: u64,
    pub root_hash: Sha256Hash,
    pub objects_written: u64,
    pub objects_verified: u64,
}

/// Import into an empty database and dedicated storage namespace. Re-running
/// after an interruption requires the same input fingerprint and chunk size.
/// A completed import is rejected, even with `resume`, rather than appended twice.
pub async fn bulk_import(
    db: &Database,
    storage: &TileStorage,
    input: &InputSummary,
    config: &ImportConfig,
    entries: impl IntoIterator<Item = Result<Vec<u8>>>,
) -> Result<ImportSummary> {
    if config.chunk_size == 0
        || config.chunk_size > 65536
        || !config.chunk_size.is_multiple_of(256)
        || config.upload_concurrency == 0
        || config.upload_concurrency > 256
    {
        return Err(Error::Config(
            "chunk size must be a multiple of 256 in 256..=65536; concurrency must be 1..=256"
                .into(),
        ));
    }
    if input.entries == 0 || input.entries > i64::MAX as u64 {
        return Err(Error::InvalidEntry("invalid input entry count".into()));
    }
    let txn = db.begin_import().await?;
    if storage.read_checkpoint().await?.is_some() {
        return Err(Error::Config(
            "storage has a published checkpoint; use a fresh log namespace".into(),
        ));
    }
    let manifest = serde_json::to_vec(&serde_json::json!({
        "version": 1, "mode": "tessera", "input": input, "chunk_size": config.chunk_size,
    }))
    .map_err(|e| Error::Config(e.to_string()))?;
    if config.resume && storage.read_raw(MANIFEST_PATH).await?.is_none() {
        return Err(Error::Config("no import manifest to resume".into()));
    }
    storage
        .write_import_object(MANIFEST_PATH, manifest, config.resume)
        .await?;

    let mut entries = entries.into_iter();
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut root = None;
    let mut written = 0;
    let mut verified = 0;
    loop {
        let chunk: Vec<_> = entries
            .by_ref()
            .take(config.chunk_size)
            .collect::<Result<_>>()?;
        if chunk.is_empty() {
            break;
        }
        if chunk.len() as u64 > input.entries - size {
            return Err(Error::InvalidEntry(
                "input changed after preflight (extra entries)".into(),
            ));
        }
        for data in &chunk {
            fingerprint_entry(&mut digest, data)?;
        }
        let leaves: Vec<_> = chunk
            .iter()
            .map(|data| sigstore_merkle::hash_leaf(data))
            .collect();
        let result = integrate(storage, TreeSize::new(size), &leaves).await?;
        let new_size = result.new_size.value();
        let mut objects = Vec::new();
        for (id, tile) in result.tiles {
            let partial = paths::partial_tile_size(id.level.value(), id.index.value(), new_size);
            objects.push((
                paths::tile_path(id.level.value(), id.index.value(), partial),
                tile.to_bytes(),
            ));
        }
        for (offset, data) in chunk.chunks(256).enumerate() {
            let index = size / 256 + offset as u64;
            let partial = paths::partial_tile_size(0, index, new_size);
            let bundle =
                EntryBundle::with_entries(data.iter().cloned().map(EntryData::new).collect());
            objects.push((paths::entries_path(index, partial), bundle.to_bytes()?));
        }
        let mut uploads = stream::iter(objects)
            .map(|(path, data)| async move {
                storage
                    .write_import_object(&path, data, config.resume)
                    .await
            })
            .buffer_unordered(config.upload_concurrency);
        while let Some(wrote) = uploads.try_next().await? {
            if wrote {
                written += 1;
            } else {
                verified += 1;
            }
        }
        size = new_size;
        root = Some(result.root_hash);
        tracing::info!(entries = size, total = input.entries, "Imported chunk");
    }
    if size != input.entries || hex::encode(digest.finalize()) != input.sha256 {
        return Err(Error::InvalidEntry(
            "input changed after preflight; database not committed".into(),
        ));
    }
    let root_hash = root.ok_or_else(|| Error::InvalidEntry("empty input".into()))?;
    storage.sync_import().await?;
    Database::finish_import(txn, TreeSize::new(size), root_hash).await?;
    Ok(ImportSummary {
        tree_size: size,
        root_hash,
        objects_written: written,
        objects_verified: verified,
    })
}
