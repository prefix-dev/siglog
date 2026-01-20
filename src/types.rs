//! Core domain types for the Tessera transparency log.

use sigstore_merkle::hash_leaf;
use sigstore_types::Sha256Hash;
use std::fmt;

/// A log entry containing arbitrary data to be added to the transparency log.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The raw entry data.
    data: EntryData,
    /// The Merkle leaf hash of this entry (computed lazily or eagerly).
    leaf_hash: Sha256Hash,
}

impl Entry {
    /// Create a new entry from raw data.
    ///
    /// Computes the leaf hash immediately.
    pub fn new(data: impl Into<EntryData>) -> Self {
        let data = data.into();
        let leaf_hash = hash_leaf(data.as_bytes());
        Self { data, leaf_hash }
    }

    /// Get the entry data.
    pub fn data(&self) -> &EntryData {
        &self.data
    }

    /// Get the Merkle leaf hash.
    pub fn leaf_hash(&self) -> &Sha256Hash {
        &self.leaf_hash
    }

    /// Consume the entry and return its data.
    pub fn into_data(self) -> EntryData {
        self.data
    }
}

/// Wrapper type for entry data bytes.
#[derive(Clone)]
pub struct EntryData(Vec<u8>);

impl EntryData {
    /// Create new entry data from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the length of the data.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the data is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume and return the inner bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for EntryData {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for EntryData {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl From<&str> for EntryData {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

impl From<String> for EntryData {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

impl AsRef<[u8]> for EntryData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EntryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() <= 64 {
            write!(f, "EntryData({} bytes)", self.0.len())
        } else {
            write!(f, "EntryData({} bytes, truncated)", self.0.len())
        }
    }
}

/// A sequenced entry that has been assigned an index in the log.
#[derive(Debug, Clone)]
pub struct SequencedEntry {
    /// The assigned log index.
    index: LogIndex,
    /// The entry itself.
    entry: Entry,
}

impl SequencedEntry {
    /// Create a new sequenced entry.
    pub fn new(index: LogIndex, entry: Entry) -> Self {
        Self { index, entry }
    }

    /// Get the log index.
    pub fn index(&self) -> LogIndex {
        self.index
    }

    /// Get the entry.
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// Get the leaf hash.
    pub fn leaf_hash(&self) -> &Sha256Hash {
        self.entry.leaf_hash()
    }

    /// Consume and return the inner entry.
    pub fn into_entry(self) -> Entry {
        self.entry
    }
}

/// A log index (position of an entry in the log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogIndex(u64);

impl LogIndex {
    /// Create a new log index.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// Get the index value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Get the bundle index this entry belongs to.
    pub fn bundle_index(&self) -> u64 {
        self.0 / 256
    }

    /// Get the offset within the bundle.
    pub fn bundle_offset(&self) -> u8 {
        (self.0 % 256) as u8
    }
}

impl From<u64> for LogIndex {
    fn from(index: u64) -> Self {
        Self::new(index)
    }
}

impl From<LogIndex> for u64 {
    fn from(index: LogIndex) -> Self {
        index.0
    }
}

impl fmt::Display for LogIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tree size (number of entries in the log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TreeSize(u64);

impl TreeSize {
    /// Create a new tree size.
    pub fn new(size: u64) -> Self {
        Self(size)
    }

    /// Get the size value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for TreeSize {
    fn from(size: u64) -> Self {
        Self::new(size)
    }
}

impl From<TreeSize> for u64 {
    fn from(size: TreeSize) -> Self {
        size.0
    }
}

impl fmt::Display for TreeSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tile level in the Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileLevel(u64);

impl TileLevel {
    /// Create a new tile level.
    ///
    /// # Panics
    /// Panics if level > 63.
    pub fn new(level: u64) -> Self {
        assert!(level <= 63, "tile level must be 0-63");
        Self(level)
    }

    /// Get the level value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for TileLevel {
    fn from(level: u64) -> Self {
        Self::new(level)
    }
}

impl fmt::Display for TileLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tile index within a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileIndex(u64);

impl TileIndex {
    /// Create a new tile index.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// Get the index value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for TileIndex {
    fn from(index: u64) -> Self {
        Self::new(index)
    }
}

impl fmt::Display for TileIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tile ID combining level and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileId {
    pub level: TileLevel,
    pub index: TileIndex,
}

impl TileId {
    /// Create a new tile ID.
    pub fn new(level: impl Into<TileLevel>, index: impl Into<TileIndex>) -> Self {
        Self {
            level: level.into(),
            index: index.into(),
        }
    }
}

/// Partial tile size (0 means full tile, 1-255 means partial).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PartialSize(u8);

impl PartialSize {
    /// Create a new partial size.
    pub fn new(size: u8) -> Self {
        Self(size)
    }

    /// Full tile (no partial suffix needed).
    pub fn full() -> Self {
        Self(0)
    }

    /// Get the size value.
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Check if this represents a full tile.
    pub fn is_full(&self) -> bool {
        self.0 == 0
    }
}

impl From<u8> for PartialSize {
    fn from(size: u8) -> Self {
        Self::new(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = Entry::new("hello world");
        assert!(!entry.data().is_empty());
        // Leaf hash should be non-zero
        assert_ne!(entry.leaf_hash().as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_log_index() {
        let idx = LogIndex::new(512);
        assert_eq!(idx.value(), 512);
        assert_eq!(idx.bundle_index(), 2);
        assert_eq!(idx.bundle_offset(), 0);

        let idx = LogIndex::new(257);
        assert_eq!(idx.bundle_index(), 1);
        assert_eq!(idx.bundle_offset(), 1);
    }

    #[test]
    fn test_tree_size() {
        let size = TreeSize::new(0);
        assert!(size.is_empty());

        let size = TreeSize::new(100);
        assert!(!size.is_empty());
        assert_eq!(size.value(), 100);
    }
}
