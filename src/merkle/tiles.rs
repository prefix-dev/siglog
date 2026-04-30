//! Tile data structures for tlog-tiles format.
//!
//! Hash tiles contain Merkle tree node hashes.
//! Entry bundles contain log entries.

use crate::error::{Error, Result};
use sigstore_types::Sha256Hash;

/// A hash tile containing Merkle tree node hashes.
///
/// Format: concatenated 32-byte SHA-256 hashes with no length prefix.
#[derive(Debug, Clone, Default)]
pub struct HashTile {
    /// The node hashes in this tile.
    pub nodes: Vec<Sha256Hash>,
}

impl HashTile {
    /// Create a new empty hash tile.
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Create a hash tile with the given nodes.
    pub fn with_nodes(nodes: Vec<Sha256Hash>) -> Self {
        Self { nodes }
    }

    /// Serialize the tile to bytes.
    ///
    /// Format: concatenated 32-byte hashes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.nodes.len() * 32);
        for node in &self.nodes {
            result.extend_from_slice(node.as_bytes());
        }
        result
    }

    /// Deserialize a tile from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if !data.len().is_multiple_of(32) {
            return Err(Error::InvalidEntry(format!(
                "hash tile length {} is not a multiple of 32",
                data.len()
            )));
        }

        let mut nodes = Vec::with_capacity(data.len() / 32);
        for chunk in data.chunks_exact(32) {
            let hash = Sha256Hash::try_from_slice(chunk)
                .map_err(|e| Error::InvalidEntry(format!("invalid hash: {}", e)))?;
            nodes.push(hash);
        }

        Ok(Self { nodes })
    }

    /// Get the number of nodes in this tile.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the tile is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// An entry bundle containing log entries.
///
/// Format: length-prefixed entries where each entry is:
/// - 2-byte big-endian length
/// - entry data bytes
#[derive(Debug, Clone, Default)]
pub struct EntryBundle {
    /// The entries in this bundle.
    pub entries: Vec<crate::types::EntryData>,
}

impl EntryBundle {
    /// Create a new empty entry bundle.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create an entry bundle with the given entries.
    pub fn with_entries(entries: Vec<crate::types::EntryData>) -> Self {
        Self { entries }
    }

    /// Serialize the bundle to bytes.
    ///
    /// Format: [2-byte BE length][data][2-byte BE length][data]...
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let total_size: usize = self.entries.iter().map(|e| 2 + e.len()).sum();
        let mut result = Vec::with_capacity(total_size);

        for entry in &self.entries {
            if entry.len() > u16::MAX as usize {
                return Err(Error::InvalidEntry(format!(
                    "entry bundle item too large: {} bytes (max {})",
                    entry.len(),
                    u16::MAX
                )));
            }
            let len = entry.len() as u16;
            result.extend_from_slice(&len.to_be_bytes());
            result.extend_from_slice(entry.as_bytes());
        }

        Ok(result)
    }

    /// Deserialize a bundle from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        use crate::types::EntryData;

        let mut entries = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            // Need at least 2 bytes for length
            if offset + 2 > data.len() {
                return Err(Error::InvalidEntry(format!(
                    "truncated entry bundle at offset {}",
                    offset
                )));
            }

            let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + len > data.len() {
                return Err(Error::InvalidEntry(format!(
                    "entry at offset {} claims {} bytes but only {} available",
                    offset - 2,
                    len,
                    data.len() - offset
                )));
            }

            entries.push(EntryData::new(data[offset..offset + len].to_vec()));
            offset += len;
        }

        Ok(Self { entries })
    }

    /// Get the number of entries in this bundle.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Append an entry to the bundle.
    pub fn push(&mut self, entry: crate::types::EntryData) {
        self.entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntryData;

    #[test]
    fn test_hash_tile_roundtrip() {
        let nodes = vec![
            Sha256Hash::from_bytes([1u8; 32]),
            Sha256Hash::from_bytes([2u8; 32]),
            Sha256Hash::from_bytes([3u8; 32]),
        ];
        let tile = HashTile::with_nodes(nodes.clone());

        let bytes = tile.to_bytes();
        assert_eq!(bytes.len(), 96);

        let parsed = HashTile::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.nodes, nodes);
    }

    #[test]
    fn test_hash_tile_empty() {
        let tile = HashTile::new();
        let bytes = tile.to_bytes();
        assert!(bytes.is_empty());

        let parsed = HashTile::from_bytes(&bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_hash_tile_invalid_length() {
        let data = vec![0u8; 33]; // Not a multiple of 32
        assert!(HashTile::from_bytes(&data).is_err());
    }

    #[test]
    fn test_entry_bundle_roundtrip() {
        let entries = vec![
            EntryData::from("hello"),
            EntryData::from("world"),
            EntryData::from("test entry with more data"),
        ];
        let bundle = EntryBundle::with_entries(entries);

        let bytes = bundle.to_bytes().unwrap();
        let parsed = EntryBundle::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].as_bytes(), b"hello");
        assert_eq!(parsed.entries[1].as_bytes(), b"world");
        assert_eq!(parsed.entries[2].as_bytes(), b"test entry with more data");
    }

    #[test]
    fn test_entry_bundle_empty() {
        let bundle = EntryBundle::new();
        let bytes = bundle.to_bytes().unwrap();
        assert!(bytes.is_empty());

        let parsed = EntryBundle::from_bytes(&bytes).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_entry_bundle_single_entry() {
        let entry = EntryData::from("single entry");
        let bundle = EntryBundle::with_entries(vec![entry]);

        let bytes = bundle.to_bytes().unwrap();
        // 2 bytes length + 12 bytes data
        assert_eq!(bytes.len(), 14);
        assert_eq!(&bytes[0..2], &[0, 12]); // Big-endian length

        let parsed = EntryBundle::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].as_bytes(), b"single entry");
    }

    #[test]
    fn test_entry_bundle_truncated() {
        // Just a length prefix with no data
        let data = vec![0, 10];
        assert!(EntryBundle::from_bytes(&data).is_err());

        // Partial length prefix
        let data = vec![0];
        assert!(EntryBundle::from_bytes(&data).is_err());
    }

    #[test]
    fn test_entry_bundle_rejects_oversized_entry() {
        let entry = EntryData::new(vec![0u8; u16::MAX as usize + 1]);
        let bundle = EntryBundle::with_entries(vec![entry]);

        assert!(bundle.to_bytes().is_err());
    }
}
