//! Verifiable Index (VIndex) - Maps keys to log entry indices with verifiable proofs.
//!
//! This module implements a verifiable index that:
//! 1. Extracts keys from log entries using a MapFn
//! 2. Maintains a key → [indices] mapping
//! 3. Persists mappings to a Write Ahead Log (WAL)
//! 4. Provides lookup with the log indices for any key
//! 5. Builds a Merkle prefix tree for verifiable inclusion proofs
//!
//! Architecture:
//! - InputLog: The transparency log entries are indexed
//! - MapFn: Extracts keys (SHA256 hashes) from entry data
//! - WAL: Persists (index, keys) pairs for crash recovery
//! - Index: In-memory map from key → list of log indices
//! - PrefixTree: Merkle tree for verifiable proofs

mod prefix_tree;
mod wal;

use crate::error::Result;
use crate::types::LogIndex;
pub use prefix_tree::{LookupProof, PrefixTree, ProofNode};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, RwLock};
pub use wal::{WalReader, WalWriter};

/// A 32-byte SHA256 hash used as a key in the index.
pub type IndexKey = [u8; 32];

/// MapFn extracts keys from log entry data.
///
/// Given the raw bytes of a log entry, returns zero or more keys
/// under which this entry should be indexed.
///
/// # Example
/// For a package registry, the MapFn might extract the package name
/// and return `SHA256(package_name)` as the key.
pub trait MapFn: Send + Sync {
    /// Extract keys from entry data.
    fn map(&self, data: &[u8]) -> Vec<IndexKey>;
}

/// A MapFn that extracts a single key by hashing the entire entry.
pub struct IdentityMapFn;

impl MapFn for IdentityMapFn {
    fn map(&self, data: &[u8]) -> Vec<IndexKey> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        vec![hasher.finalize().into()]
    }
}

/// A MapFn that extracts keys from JSON entries.
///
/// Expects entries to be JSON objects with a "keys" field containing
/// an array of strings. Each string is hashed to produce a key.
pub struct JsonKeysMapFn {
    /// The JSON field name containing the keys array.
    pub field: String,
}

impl JsonKeysMapFn {
    pub fn new(field: impl Into<String>) -> Self {
        Self {
            field: field.into(),
        }
    }
}

impl MapFn for JsonKeysMapFn {
    fn map(&self, data: &[u8]) -> Vec<IndexKey> {
        // Try to parse as JSON
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Vec::new();
        };

        // Get the keys field
        let Some(keys) = value.get(&self.field) else {
            return Vec::new();
        };

        // Extract string values and hash them
        match keys {
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| {
                    let mut hasher = Sha256::new();
                    hasher.update(s.as_bytes());
                    hasher.finalize().into()
                })
                .collect(),
            serde_json::Value::String(s) => {
                let mut hasher = Sha256::new();
                hasher.update(s.as_bytes());
                vec![hasher.finalize().into()]
            }
            _ => Vec::new(),
        }
    }
}

/// Lookup result containing the log indices for a key.
#[derive(Debug, Clone)]
pub struct LookupResult {
    /// The log indices where entries with this key are stored.
    pub indices: Vec<LogIndex>,
    /// The tree size at which this lookup is valid.
    pub tree_size: u64,
    /// Whether the key was found in the prefix tree.
    pub found: bool,
    /// The inclusion/exclusion proof from the prefix tree.
    pub proof: Vec<ProofNode>,
}

/// The verifiable index maintains a mapping from keys to log indices.
pub struct VerifiableIndex {
    /// The key → indices mapping.
    index: RwLock<HashMap<IndexKey, Vec<LogIndex>>>,
    /// WAL writer for persistence.
    wal_writer: Option<RwLock<WalWriter>>,
    /// The map function for extracting keys.
    map_fn: Arc<dyn MapFn>,
    /// Current tree size (number of entries indexed).
    tree_size: RwLock<u64>,
    /// The Merkle prefix tree for verifiable proofs.
    prefix_tree: RwLock<PrefixTree>,
}

impl VerifiableIndex {
    /// Create a new in-memory verifiable index without persistence.
    pub fn new(map_fn: Arc<dyn MapFn>) -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            wal_writer: None,
            map_fn,
            tree_size: RwLock::new(0),
            prefix_tree: RwLock::new(PrefixTree::new()),
        }
    }

    /// Create a new verifiable index with WAL persistence.
    ///
    /// If the WAL file exists, it will be replayed to rebuild the index.
    pub fn with_wal(map_fn: Arc<dyn MapFn>, wal_path: impl AsRef<Path>) -> Result<Self> {
        let wal_path = wal_path.as_ref();

        // Create or open WAL
        let mut tree_size = 0u64;
        let mut index: HashMap<IndexKey, Vec<LogIndex>> = HashMap::new();
        let mut prefix_tree = PrefixTree::new();

        // Replay existing WAL if it exists
        if wal_path.exists() {
            let mut reader = WalReader::open(wal_path)?;
            while let Some((idx, keys)) = reader.next()? {
                for key in keys {
                    index.entry(key).or_default().push(idx);
                }
                tree_size = tree_size.max(idx.value() + 1);
            }

            // Rebuild prefix tree from index
            for (key, indices) in &index {
                let value_hash = compute_value_hash(indices);
                prefix_tree.insert(key, value_hash);
            }
        }

        let wal_writer = WalWriter::open(wal_path)?;

        Ok(Self {
            index: RwLock::new(index),
            wal_writer: Some(RwLock::new(wal_writer)),
            map_fn,
            tree_size: RwLock::new(tree_size),
            prefix_tree: RwLock::new(prefix_tree),
        })
    }

    /// Index a new entry at the given log index.
    ///
    /// Extracts keys from the entry data and adds them to the index.
    pub fn index_entry(&self, idx: LogIndex, data: &[u8]) -> Result<()> {
        let keys = self.map_fn.map(data);

        if keys.is_empty() {
            // Still need to update tree size even if no keys
            let mut tree_size = self.tree_size.write().unwrap();
            *tree_size = (*tree_size).max(idx.value() + 1);
            return Ok(());
        }

        // Write to WAL first (if enabled)
        if let Some(wal) = &self.wal_writer {
            let mut wal = wal.write().unwrap();
            wal.append(idx, &keys)?;
        }

        // Update in-memory index and prefix tree
        {
            let mut index = self.index.write().unwrap();
            let mut prefix_tree = self.prefix_tree.write().unwrap();

            for key in &keys {
                let indices = index.entry(*key).or_default();
                indices.push(idx);

                // Update the prefix tree with the new value hash
                let value_hash = compute_value_hash(indices);
                prefix_tree.insert(key, value_hash);
            }
        }

        // Update tree size
        {
            let mut tree_size = self.tree_size.write().unwrap();
            *tree_size = (*tree_size).max(idx.value() + 1);
        }

        Ok(())
    }

    /// Look up a key and return all log indices containing entries with that key.
    pub fn lookup(&self, key: &IndexKey) -> LookupResult {
        let index = self.index.read().unwrap();
        let prefix_tree = self.prefix_tree.read().unwrap();
        let tree_size = *self.tree_size.read().unwrap();

        let indices = index.get(key).cloned().unwrap_or_default();
        let lookup_proof = prefix_tree.lookup(key);

        LookupResult {
            indices,
            tree_size,
            found: lookup_proof.found,
            proof: lookup_proof.proof,
        }
    }

    /// Look up by a string key (hashes the string to get the index key).
    pub fn lookup_string(&self, key: &str) -> LookupResult {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash: IndexKey = hasher.finalize().into();
        self.lookup(&hash)
    }

    /// Get the current tree size (number of entries indexed).
    pub fn tree_size(&self) -> u64 {
        *self.tree_size.read().unwrap()
    }

    /// Get the number of unique keys in the index.
    pub fn key_count(&self) -> usize {
        self.index.read().unwrap().len()
    }

    /// Flush the WAL to disk.
    pub fn flush(&self) -> Result<()> {
        if let Some(wal) = &self.wal_writer {
            wal.write().unwrap().flush()?;
        }
        Ok(())
    }

    /// Get the root hash of the prefix tree.
    ///
    /// This hash commits to the entire index state and can be used
    /// to verify proofs.
    pub fn root_hash(&self) -> IndexKey {
        self.prefix_tree.read().unwrap().root_hash()
    }
}

/// Compute the value hash for a list of indices.
///
/// The value hash is SHA256 of all indices concatenated as big-endian u64s.
/// This matches the Go implementation.
fn compute_value_hash(indices: &[LogIndex]) -> IndexKey {
    let mut hasher = Sha256::new();
    for idx in indices {
        hasher.write_all(&idx.value().to_be_bytes()).unwrap();
    }
    hasher.finalize().into()
}

/// Hash a string to produce an index key.
pub fn hash_key(s: &str) -> IndexKey {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_map_fn() {
        let map_fn = IdentityMapFn;
        let keys = map_fn.map(b"hello world");
        assert_eq!(keys.len(), 1);

        // Same input should produce same key
        let keys2 = map_fn.map(b"hello world");
        assert_eq!(keys, keys2);

        // Different input should produce different key
        let keys3 = map_fn.map(b"goodbye world");
        assert_ne!(keys, keys3);
    }

    #[test]
    fn test_json_keys_map_fn() {
        let map_fn = JsonKeysMapFn::new("packages");

        // Test with array of strings
        let data = br#"{"packages": ["foo", "bar", "baz"]}"#;
        let keys = map_fn.map(data);
        assert_eq!(keys.len(), 3);

        // Test with single string
        let data = br#"{"packages": "foo"}"#;
        let keys = map_fn.map(data);
        assert_eq!(keys.len(), 1);

        // Test with missing field
        let data = br#"{"other": "value"}"#;
        let keys = map_fn.map(data);
        assert_eq!(keys.len(), 0);

        // Test with invalid JSON
        let data = b"not json";
        let keys = map_fn.map(data);
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_verifiable_index_in_memory() {
        let map_fn = Arc::new(JsonKeysMapFn::new("name"));
        let index = VerifiableIndex::new(map_fn);

        // Index some entries
        index
            .index_entry(LogIndex::new(0), br#"{"name": "foo"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(1), br#"{"name": "bar"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(2), br#"{"name": "foo"}"#)
            .unwrap();

        // Lookup foo - should have 2 entries with proof
        let result = index.lookup_string("foo");
        assert_eq!(result.indices.len(), 2);
        assert_eq!(result.indices[0].value(), 0);
        assert_eq!(result.indices[1].value(), 2);
        assert!(result.found);
        // Proof should include bar's subtree
        assert!(!result.proof.is_empty());

        // Lookup bar - should have 1 entry with proof
        let result = index.lookup_string("bar");
        assert_eq!(result.indices.len(), 1);
        assert_eq!(result.indices[0].value(), 1);
        assert!(result.found);
        // Proof should include foo's subtree
        assert!(!result.proof.is_empty());

        // Lookup unknown - should have 0 entries with exclusion proof
        let result = index.lookup_string("unknown");
        assert_eq!(result.indices.len(), 0);
        assert!(!result.found);

        assert_eq!(index.tree_size(), 3);
        assert_eq!(index.key_count(), 2);

        // Root hash should be non-zero
        let root_hash = index.root_hash();
        assert_ne!(root_hash, [0u8; 32]);
    }

    #[test]
    fn test_verifiable_index_root_changes() {
        let map_fn = Arc::new(JsonKeysMapFn::new("name"));
        let index = VerifiableIndex::new(map_fn);

        // Empty index should have zero root
        assert_eq!(index.root_hash(), [0u8; 32]);

        // Add first entry
        index
            .index_entry(LogIndex::new(0), br#"{"name": "foo"}"#)
            .unwrap();
        let root1 = index.root_hash();
        assert_ne!(root1, [0u8; 32]);

        // Add second entry - root should change
        index
            .index_entry(LogIndex::new(1), br#"{"name": "bar"}"#)
            .unwrap();
        let root2 = index.root_hash();
        assert_ne!(root2, root1);

        // Add duplicate key - root should change (value hash changes)
        index
            .index_entry(LogIndex::new(2), br#"{"name": "foo"}"#)
            .unwrap();
        let root3 = index.root_hash();
        assert_ne!(root3, root2);
    }

    #[test]
    fn test_hash_key() {
        let key1 = hash_key("foo");
        let key2 = hash_key("foo");
        let key3 = hash_key("bar");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.len(), 32);
    }
}
