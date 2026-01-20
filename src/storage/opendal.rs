//! OpenDAL-based storage for static tiles and checkpoint.
//!
//! Stores:
//! - `checkpoint` - The signed checkpoint
//! - `tile/{level}/{index}` - Hash tiles
//! - `tile/entries/{index}` - Entry bundles

use crate::api::paths;
use crate::error::{Error, Result};
use crate::merkle::{EntryBundle, HashTile};
use crate::types::{PartialSize, TileIndex, TileLevel};
use opendal::{services::Fs, services::S3, Operator};
use std::sync::Arc;

/// Storage for tiles and checkpoints using OpenDAL.
#[derive(Clone)]
pub struct TileStorage {
    op: Arc<Operator>,
}

impl TileStorage {
    /// Create a new tile storage with S3-compatible backend.
    pub fn new_s3(
        endpoint: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) -> Result<Self> {
        let mut builder = S3::default()
            .endpoint(endpoint)
            .bucket(bucket)
            .access_key_id(access_key)
            .secret_access_key(secret_key)
            .region(region);

        // Disable virtual host style for compatibility with R2/MinIO
        builder = builder.disable_config_load();

        let op = Operator::new(builder)
            .map_err(|e| Error::Storage(e.into()))?
            .finish();

        Ok(Self { op: Arc::new(op) })
    }

    /// Create a new tile storage with filesystem backend.
    pub fn new_fs(root: &str) -> Result<Self> {
        let builder = Fs::default().root(root);

        let op = Operator::new(builder)
            .map_err(|e| Error::Storage(e.into()))?
            .finish();

        Ok(Self { op: Arc::new(op) })
    }

    /// Create a new tile storage with an existing operator (for testing).
    pub fn new(op: Operator) -> Self {
        Self { op: Arc::new(op) }
    }

    // ========================================================================
    // Checkpoint operations
    // ========================================================================

    /// Read the current checkpoint.
    pub async fn read_checkpoint(&self) -> Result<Option<CheckpointData>> {
        match self.op.read(paths::CHECKPOINT_PATH).await {
            Ok(data) => Ok(Some(CheckpointData::new(data.to_vec()))),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Storage(e)),
        }
    }

    /// Write a new checkpoint.
    pub async fn write_checkpoint(&self, data: &CheckpointData) -> Result<()> {
        self.op
            .write(paths::CHECKPOINT_PATH, data.as_bytes().to_vec())
            .await
            .map_err(Error::Storage)
    }

    // ========================================================================
    // Hash tile operations
    // ========================================================================

    /// Read a hash tile.
    pub async fn read_tile(
        &self,
        level: TileLevel,
        index: TileIndex,
        partial: PartialSize,
    ) -> Result<Option<HashTile>> {
        let path = paths::tile_path(level.value(), index.value(), partial.value());

        match self.op.read(&path).await {
            Ok(data) => {
                let bytes = data.to_vec();
                let tile = HashTile::from_bytes(&bytes)?;
                Ok(Some(tile))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Storage(e)),
        }
    }

    /// Write a hash tile.
    pub async fn write_tile(
        &self,
        level: TileLevel,
        index: TileIndex,
        partial: PartialSize,
        tile: &HashTile,
    ) -> Result<()> {
        let path = paths::tile_path(level.value(), index.value(), partial.value());
        let data = tile.to_bytes();

        self.op.write(&path, data).await.map_err(Error::Storage)
    }

    // ========================================================================
    // Entry bundle operations
    // ========================================================================

    /// Read an entry bundle.
    pub async fn read_entry_bundle(
        &self,
        index: TileIndex,
        partial: PartialSize,
    ) -> Result<Option<EntryBundle>> {
        let path = paths::entries_path(index.value(), partial.value());

        match self.op.read(&path).await {
            Ok(data) => {
                let bytes = data.to_vec();
                let bundle = EntryBundle::from_bytes(&bytes)?;
                Ok(Some(bundle))
            }
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Storage(e)),
        }
    }

    /// Write an entry bundle.
    pub async fn write_entry_bundle(
        &self,
        index: TileIndex,
        partial: PartialSize,
        bundle: &EntryBundle,
    ) -> Result<()> {
        let path = paths::entries_path(index.value(), partial.value());
        let data = bundle.to_bytes();

        self.op.write(&path, data).await.map_err(Error::Storage)
    }

    // ========================================================================
    // Raw bytes operations (for serving HTTP responses directly)
    // ========================================================================

    /// Read raw bytes from a path.
    pub async fn read_raw(&self, path: &str) -> Result<Option<Vec<u8>>> {
        match self.op.read(path).await {
            Ok(data) => Ok(Some(data.to_vec())),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Storage(e)),
        }
    }
}

/// Wrapper type for checkpoint data.
#[derive(Debug, Clone)]
pub struct CheckpointData(Vec<u8>);

impl CheckpointData {
    /// Create new checkpoint data.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the data as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the inner bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get as UTF-8 string (checkpoints are text).
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|e| Error::InvalidEntry(e.to_string()))
    }
}

impl From<Vec<u8>> for CheckpointData {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<String> for CheckpointData {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opendal::services::Memory;

    async fn create_test_storage() -> TileStorage {
        let builder = Memory::default();
        let op = Operator::new(builder).unwrap().finish();
        TileStorage::new(op)
    }

    #[tokio::test]
    async fn test_checkpoint_roundtrip() {
        let storage = create_test_storage().await;

        // Initially no checkpoint
        assert!(storage.read_checkpoint().await.unwrap().is_none());

        // Write checkpoint
        let data = CheckpointData::from("test checkpoint\n".to_string());
        storage.write_checkpoint(&data).await.unwrap();

        // Read it back
        let read = storage.read_checkpoint().await.unwrap().unwrap();
        assert_eq!(read.as_str().unwrap(), "test checkpoint\n");
    }

    #[tokio::test]
    async fn test_tile_roundtrip() {
        use sigstore_types::Sha256Hash;

        let storage = create_test_storage().await;
        let level = TileLevel::new(0);
        let index = TileIndex::new(0);
        let partial = PartialSize::full();

        // Initially no tile
        assert!(storage
            .read_tile(level, index, partial)
            .await
            .unwrap()
            .is_none());

        // Write tile
        let nodes = vec![
            Sha256Hash::from_bytes([1u8; 32]),
            Sha256Hash::from_bytes([2u8; 32]),
        ];
        let tile = HashTile::with_nodes(nodes.clone());
        storage
            .write_tile(level, index, partial, &tile)
            .await
            .unwrap();

        // Read it back
        let read = storage
            .read_tile(level, index, partial)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.nodes, nodes);
    }

    #[tokio::test]
    async fn test_entry_bundle_roundtrip() {
        use crate::types::EntryData;

        let storage = create_test_storage().await;
        let index = TileIndex::new(0);
        let partial = PartialSize::new(2);

        // Initially no bundle
        assert!(storage
            .read_entry_bundle(index, partial)
            .await
            .unwrap()
            .is_none());

        // Write bundle
        let entries = vec![EntryData::from("entry 1"), EntryData::from("entry 2")];
        let bundle = EntryBundle::with_entries(entries);
        storage
            .write_entry_bundle(index, partial, &bundle)
            .await
            .unwrap();

        // Read it back
        let read = storage
            .read_entry_bundle(index, partial)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.entries.len(), 2);
        assert_eq!(read.entries[0].as_bytes(), b"entry 1");
        assert_eq!(read.entries[1].as_bytes(), b"entry 2");
    }
}
