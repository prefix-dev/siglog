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

use crate::error::{Error, Result};
use crate::types::LogIndex;
pub use prefix_tree::{LookupProof, PrefixTree, ProofNode};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, RwLock};
pub use wal::{
    validate_and_truncate_wal, BatchedBinaryWalWriter, BatchedWalWriter, BinaryWalWriter,
    WalReader, WalWriter,
};

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

/// WAL writer variant (batched or unbatched).
enum WalWriterVariant {
    Unbatched(WalWriter),
    Batched(BatchedWalWriter),
}

impl WalWriterVariant {
    fn append(&mut self, idx: LogIndex, keys: &[IndexKey]) -> Result<()> {
        match self {
            WalWriterVariant::Unbatched(w) => w.append(idx, keys),
            WalWriterVariant::Batched(w) => w.append(idx, keys.to_vec()),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match self {
            WalWriterVariant::Unbatched(w) => w.flush(),
            WalWriterVariant::Batched(w) => w.flush(),
        }
    }
}

/// The verifiable index maintains a mapping from keys to log indices.
pub struct VerifiableIndex {
    /// The key → indices mapping.
    index: RwLock<HashMap<IndexKey, Vec<LogIndex>>>,
    /// WAL writer for persistence.
    wal_writer: Option<RwLock<WalWriterVariant>>,
    /// The map function for extracting keys.
    map_fn: Arc<dyn MapFn>,
    /// Current tree size (number of entries indexed).
    tree_size: RwLock<u64>,
    /// The Merkle prefix tree for verifiable proofs.
    prefix_tree: RwLock<PrefixTree>,
    /// Maximum number of unique keys allowed.
    max_keys: usize,
    /// Maximum number of indices per key.
    max_indices_per_key: usize,
}

impl VerifiableIndex {
    /// Default maximum number of unique keys (10M keys ≈ 2.5 GB).
    const DEFAULT_MAX_KEYS: usize = 10_000_000;

    /// Default maximum number of indices per key (1000 indices per key).
    const DEFAULT_MAX_INDICES_PER_KEY: usize = 1000;

    /// Read max_keys from environment or use default.
    fn get_max_keys() -> usize {
        std::env::var("VINDEX_MAX_KEYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_MAX_KEYS)
    }

    /// Read max_indices_per_key from environment or use default.
    fn get_max_indices_per_key() -> usize {
        std::env::var("VINDEX_MAX_INDICES_PER_KEY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Self::DEFAULT_MAX_INDICES_PER_KEY)
    }

    /// Create a new in-memory verifiable index without persistence.
    pub fn new(map_fn: Arc<dyn MapFn>) -> Self {
        Self::new_with_limits(map_fn, None, None)
    }

    /// Create a new in-memory verifiable index with custom limits.
    pub fn new_with_limits(
        map_fn: Arc<dyn MapFn>,
        max_keys: Option<usize>,
        max_indices_per_key: Option<usize>,
    ) -> Self {
        let max_keys = max_keys.unwrap_or_else(Self::get_max_keys);
        let max_indices_per_key = max_indices_per_key.unwrap_or_else(Self::get_max_indices_per_key);

        tracing::info!(
            "VerifiableIndex limits: max_keys={}, max_indices_per_key={}",
            max_keys,
            max_indices_per_key
        );

        Self {
            index: RwLock::new(HashMap::new()),
            wal_writer: None,
            map_fn,
            tree_size: RwLock::new(0),
            prefix_tree: RwLock::new(PrefixTree::new()),
            max_keys,
            max_indices_per_key,
        }
    }

    /// Create a new verifiable index with WAL persistence.
    ///
    /// If the WAL file exists, it will be validated against the expected tree size
    /// and truncated if necessary (to handle crash recovery), then replayed to
    /// rebuild the index.
    ///
    /// # Arguments
    /// * `map_fn` - The function to extract keys from entry data
    /// * `wal_path` - Path to the WAL file
    /// * `expected_tree_size` - The integrated tree size from the database; used to
    ///   truncate the WAL if it ran ahead before a crash
    pub fn with_wal(
        map_fn: Arc<dyn MapFn>,
        wal_path: impl AsRef<Path>,
        expected_tree_size: u64,
    ) -> Result<Self> {
        Self::with_wal_and_batch_size(map_fn, wal_path, expected_tree_size, 1)
    }

    /// Create a new verifiable index with batched WAL persistence.
    ///
    /// This variant uses batched writes to reduce fsync overhead.
    /// For high throughput workloads, use batch_size=100 or higher.
    ///
    /// # Arguments
    /// * `map_fn` - The function to extract keys from entry data
    /// * `wal_path` - Path to the WAL file
    /// * `expected_tree_size` - The integrated tree size from the database
    /// * `batch_size` - Number of entries to buffer before fsyncing (1 = no batching)
    pub fn with_wal_and_batch_size(
        map_fn: Arc<dyn MapFn>,
        wal_path: impl AsRef<Path>,
        expected_tree_size: u64,
        batch_size: usize,
    ) -> Result<Self> {
        let wal_path = wal_path.as_ref();

        // Validate and truncate WAL to match expected tree size
        // This is critical for crash recovery: if the WAL was flushed but the database
        // wasn't updated before a crash, we truncate the WAL to avoid duplicates
        let actual_wal_size = validate_and_truncate_wal(wal_path, expected_tree_size)?;
        tracing::info!(
            "WAL validated: expected_tree_size={}, actual_wal_size={}",
            expected_tree_size,
            actual_wal_size
        );

        // Create or open WAL
        let mut tree_size = 0u64;
        let mut index: HashMap<IndexKey, Vec<LogIndex>> = HashMap::new();
        let mut prefix_tree = PrefixTree::new();

        // Track seen (idx, key) pairs to prevent duplicates (defense in depth)
        let mut seen: HashSet<(u64, IndexKey)> = HashSet::new();

        // Replay existing WAL if it exists
        if wal_path.exists() {
            let mut reader = WalReader::open(wal_path)?;
            while let Some((idx, keys)) = reader.next_entry()? {
                for key in keys {
                    // Deduplicate: only add if we haven't seen this (idx, key) pair
                    if seen.insert((idx.value(), key)) {
                        index.entry(key).or_default().push(idx);
                    }
                }
                tree_size = tree_size.max(idx.value() + 1);
            }

            // Rebuild prefix tree from index
            for (key, indices) in &index {
                let value_hash = compute_value_hash(indices);
                prefix_tree.insert(key, value_hash);
            }

            tracing::info!(
                "WAL replayed: {} unique keys, tree_size={}",
                index.len(),
                tree_size
            );
        }

        // Create writer (batched or unbatched based on batch_size)
        let wal_writer = if batch_size > 1 {
            tracing::info!("Using batched WAL writer with batch_size={}", batch_size);
            WalWriterVariant::Batched(BatchedWalWriter::open(wal_path, batch_size)?)
        } else {
            WalWriterVariant::Unbatched(WalWriter::open(wal_path)?)
        };

        let max_keys = Self::get_max_keys();
        let max_indices_per_key = Self::get_max_indices_per_key();

        tracing::info!(
            "VerifiableIndex limits: max_keys={}, max_indices_per_key={}",
            max_keys,
            max_indices_per_key
        );

        Ok(Self {
            index: RwLock::new(index),
            wal_writer: Some(RwLock::new(wal_writer)),
            map_fn,
            tree_size: RwLock::new(tree_size),
            prefix_tree: RwLock::new(prefix_tree),
            max_keys,
            max_indices_per_key,
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

        // Check memory limits before modifying state
        {
            let index = self.index.read().unwrap();
            let current_key_count = index.len();

            // Count how many new keys would be added
            let new_keys_count = keys.iter().filter(|k| !index.contains_key(*k)).count();

            // Check total key limit
            if current_key_count + new_keys_count > self.max_keys {
                let msg = format!(
                    "maximum keys exceeded: current={}, new={}, max={}",
                    current_key_count, new_keys_count, self.max_keys
                );
                tracing::warn!("Index capacity limit: {}", msg);
                return Err(Error::IndexFull(msg));
            }

            // Check per-key limit
            for key in &keys {
                if let Some(indices) = index.get(key) {
                    if indices.len() >= self.max_indices_per_key {
                        let msg = format!(
                            "maximum indices per key exceeded: key has {} indices, max={}",
                            indices.len(),
                            self.max_indices_per_key
                        );
                        tracing::warn!("Index capacity limit: {}", msg);
                        return Err(Error::IndexFull(msg));
                    }
                }
            }

            // Log warning when approaching limits (at 90%)
            let key_usage_pct = (current_key_count as f64 / self.max_keys as f64) * 100.0;
            if key_usage_pct >= 90.0 {
                tracing::warn!(
                    "Index approaching capacity: {:.1}% of max keys ({}/{})",
                    key_usage_pct,
                    current_key_count,
                    self.max_keys
                );
            }
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

    /// Get the maximum number of keys allowed.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    /// Get the maximum number of indices per key allowed.
    pub fn max_indices_per_key(&self) -> usize {
        self.max_indices_per_key
    }

    /// Get memory usage statistics.
    pub fn memory_stats(&self) -> MemoryStats {
        let index = self.index.read().unwrap();
        let key_count = index.len();
        let total_indices: usize = index.values().map(|v| v.len()).sum();
        let max_indices_for_key = index.values().map(|v| v.len()).max().unwrap_or(0);

        MemoryStats {
            key_count,
            max_keys: self.max_keys,
            total_indices,
            max_indices_for_key,
            max_indices_per_key: self.max_indices_per_key,
            key_usage_pct: (key_count as f64 / self.max_keys as f64) * 100.0,
        }
    }
}

/// Memory usage statistics for the verifiable index.
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Current number of unique keys.
    pub key_count: usize,
    /// Maximum number of keys allowed.
    pub max_keys: usize,
    /// Total number of indices across all keys.
    pub total_indices: usize,
    /// Maximum number of indices for any single key.
    pub max_indices_for_key: usize,
    /// Maximum number of indices per key allowed.
    pub max_indices_per_key: usize,
    /// Key usage as a percentage.
    pub key_usage_pct: f64,
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

    #[test]
    fn test_memory_stats() {
        // Ensure defaults are used
        std::env::remove_var("VINDEX_MAX_KEYS");
        std::env::remove_var("VINDEX_MAX_INDICES_PER_KEY");

        let map_fn = Arc::new(JsonKeysMapFn::new("name"));
        let index = VerifiableIndex::new(map_fn);

        // Initial stats
        let stats = index.memory_stats();
        assert_eq!(stats.key_count, 0);
        assert_eq!(stats.total_indices, 0);
        assert_eq!(stats.max_indices_for_key, 0);

        // Add some entries
        index
            .index_entry(LogIndex::new(0), br#"{"name": "foo"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(1), br#"{"name": "bar"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(2), br#"{"name": "foo"}"#)
            .unwrap();

        let stats = index.memory_stats();
        assert_eq!(stats.key_count, 2); // foo, bar
        assert_eq!(stats.total_indices, 3); // 2 for foo, 1 for bar
        assert_eq!(stats.max_indices_for_key, 2); // foo has 2 indices
        assert!(stats.key_usage_pct < 1.0); // Very low usage
    }

    #[test]
    fn test_max_keys_limit() {
        let map_fn = Arc::new(JsonKeysMapFn::new("name"));
        let index = VerifiableIndex::new_with_limits(map_fn, Some(2), Some(1000));

        assert_eq!(index.max_keys(), 2);

        // Add two keys - should succeed
        index
            .index_entry(LogIndex::new(0), br#"{"name": "foo"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(1), br#"{"name": "bar"}"#)
            .unwrap();

        // Try to add a third key - should fail
        let result = index.index_entry(LogIndex::new(2), br#"{"name": "baz"}"#);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::IndexFull(_)));

        // Adding duplicate key should still work
        let result = index.index_entry(LogIndex::new(3), br#"{"name": "foo"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_indices_per_key_limit() {
        let map_fn = Arc::new(JsonKeysMapFn::new("name"));
        let index = VerifiableIndex::new_with_limits(map_fn, Some(1000), Some(2));

        assert_eq!(index.max_indices_per_key(), 2);

        // Add two indices for same key - should succeed
        index
            .index_entry(LogIndex::new(0), br#"{"name": "foo"}"#)
            .unwrap();
        index
            .index_entry(LogIndex::new(1), br#"{"name": "foo"}"#)
            .unwrap();

        // Try to add a third index for same key - should fail
        let result = index.index_entry(LogIndex::new(2), br#"{"name": "foo"}"#);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::IndexFull(_)));

        // Adding a different key should still work
        let result = index.index_entry(LogIndex::new(3), br#"{"name": "bar"}"#);
        assert!(result.is_ok());
    }
}
