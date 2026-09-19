//! Bounded HTTP reads and inclusion verification against a trusted checkpoint.
use crate::{
    api::paths,
    checkpoint::Checkpoint,
    error::{Error, Result},
    merkle::{
        proof::{generate_inclusion_proof, TileReader},
        EntryBundle, HashTile,
    },
    types::{PartialSize, TileIndex, TileLevel},
};
use std::{collections::HashMap, sync::Mutex, time::Duration};

/// Read an untrusted HTTP response without unbounded buffering.
pub async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::InvalidEntry(e.to_string()))?
    {
        if chunk.len() > limit.saturating_sub(data.len()) {
            return Err(Error::InvalidEntry(
                "HTTP response exceeds size limit".into(),
            ));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

pub struct LogClient {
    url: String,
    client: reqwest::Client,
    tiles: Mutex<HashMap<String, HashTile>>,
}

impl LogClient {
    pub fn new(url: &str) -> Result<Self> {
        Self::with_timeout(url, Duration::from_secs(30))
    }

    pub fn with_timeout(url: &str, timeout: Duration) -> Result<Self> {
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| Error::Config(e.to_string()))?,
            tiles: Mutex::new(HashMap::new()),
        })
    }

    pub async fn read(&self, path: &str, limit: usize) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(format!("{}/{}", self.url, path))
            .send()
            .await
            .map_err(|e| Error::InvalidEntry(e.to_string()))?;
        bounded_body(
            response
                .error_for_status()
                .map_err(|e| Error::InvalidEntry(e.to_string()))?,
            limit,
        )
        .await
    }

    /// Fetch a complete bundle at the checkpoint's fixed size.
    pub async fn bundle(&self, index: u64, tree_size: u64) -> Result<EntryBundle> {
        if tree_size > i64::MAX as u64 || index >= tree_size.div_ceil(256) {
            return Err(Error::InvalidEntry("bundle outside checkpoint".into()));
        }
        let count = (tree_size - index * 256).min(256) as usize;
        let path = paths::entries_path(index, (count % 256) as u8);
        let data = self.read(&path, count * (65535 + 2)).await?;
        let bundle = EntryBundle::from_bytes(&data)?;
        if bundle.len() != count {
            return Err(Error::InvalidEntry("incomplete entry bundle".into()));
        }
        Ok(bundle)
    }

    pub async fn verify_entry(
        &self,
        data: &[u8],
        index: u64,
        checkpoint: &Checkpoint,
    ) -> Result<()> {
        if checkpoint.size.value() > i64::MAX as u64 {
            return Err(Error::InvalidEntry("tree too large".into()));
        }
        let proof = generate_inclusion_proof(self, index, checkpoint.size.value()).await?;
        sigstore_merkle::verify_inclusion_proof(
            &sigstore_merkle::hash_leaf(data),
            index,
            checkpoint.size.value(),
            &proof,
            &checkpoint.root_hash,
        )
        .map_err(|e| Error::Merkle(e.to_string()))
    }
}

#[async_trait::async_trait]
impl TileReader for LogClient {
    async fn read_tile(
        &self,
        level: TileLevel,
        index: TileIndex,
        partial: PartialSize,
    ) -> Result<Option<HashTile>> {
        let path = paths::tile_path(level.value(), index.value(), partial.value());
        if let Some(tile) = self.tiles.lock().unwrap().get(&path) {
            return Ok(Some(tile.clone()));
        }
        let count = if partial.value() == 0 {
            256
        } else {
            partial.value() as usize
        };
        // Older siglog tiles append cached internal rows after the bottom row.
        // Bound the entire height-8 tile, but authenticate only bottom-row hashes.
        let data = self.read(&path, 511 * 32).await?;
        if data.len() < count * 32 || !data.len().is_multiple_of(32) {
            return Err(Error::InvalidEntry("incomplete hash tile".into()));
        }
        let tile = HashTile::from_bytes(&data[..count * 32])?;
        let mut cache = self.tiles.lock().unwrap();
        // ponytail: bounded per-request cache; use LRU only if eviction becomes costly.
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(path, tile.clone());
        Ok(Some(tile))
    }
}
