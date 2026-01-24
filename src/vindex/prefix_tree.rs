//! Merkle Prefix Tree (Radix Tree) for verifiable key lookups.
//!
//! This implements a binary prefix tree where:
//! - Keys are 256-bit SHA256 hashes
//! - Each node stores a prefix (bitstring) and either children or a value
//! - The tree is Merkleized: each node's hash commits to its subtree
//! - Proofs consist of sibling nodes along the path to a key
//!
//! The tree supports:
//! - Insert: Add or update a key-value pair
//! - Lookup: Find a key and generate inclusion/exclusion proof
//! - Root: Get the root hash committing to the entire tree state

use sha2::{Digest, Sha256};

/// A 256-bit key or hash.
pub type Hash256 = [u8; 32];

/// A proof node containing the label (path) and hash of a sibling.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofNode {
    /// Number of bits in the label.
    pub label_bit_len: u32,
    /// The label bytes (path in the tree).
    pub label_path: Vec<u8>,
    /// The hash at this node.
    pub hash: Hash256,
}

/// Result of a lookup operation.
#[derive(Debug, Clone)]
pub struct LookupProof {
    /// Whether the key was found in the tree.
    pub found: bool,
    /// The proof path (sibling nodes from root to key).
    pub proof: Vec<ProofNode>,
}

/// A label representing a bit path in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Label {
    /// The bytes containing the bits.
    bytes: Vec<u8>,
    /// Number of valid bits (0 to bytes.len() * 8).
    bit_len: u32,
}

impl Label {
    /// Create an empty label.
    pub fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            bit_len: 0,
        }
    }

    /// Create a label from a full 256-bit key.
    pub fn from_key(key: &Hash256) -> Self {
        Self {
            bytes: key.to_vec(),
            bit_len: 256,
        }
    }

    /// Get the bit length.
    pub fn bit_len(&self) -> u32 {
        self.bit_len
    }

    /// Get the underlying bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get a specific bit (0 or 1). Panics if out of range.
    pub fn bit(&self, idx: u32) -> u8 {
        assert!(idx < self.bit_len);
        let byte_idx = (idx / 8) as usize;
        let bit_idx = 7 - (idx % 8); // MSB first
        (self.bytes[byte_idx] >> bit_idx) & 1
    }

    /// Get the prefix of a given length.
    pub fn prefix(&self, len: u32) -> Self {
        if len >= self.bit_len {
            return self.clone();
        }

        if len == 0 {
            return Self::empty();
        }

        let full_bytes = (len / 8) as usize;
        let remaining_bits = len % 8;

        let mut bytes = self.bytes[..full_bytes].to_vec();
        if remaining_bits > 0 && full_bytes < self.bytes.len() {
            // Mask off the unused bits in the last byte
            let mask = 0xFFu8 << (8 - remaining_bits);
            bytes.push(self.bytes[full_bytes] & mask);
        }

        Self {
            bytes,
            bit_len: len,
        }
    }

    /// Get the suffix starting at a given bit position.
    #[allow(dead_code)]
    pub fn suffix(&self, start: u32) -> Self {
        if start >= self.bit_len {
            return Self::empty();
        }

        let new_len = self.bit_len - start;
        let mut result = Label::empty();

        for i in 0..new_len {
            result = result.append_bit(self.bit(start + i));
        }

        result
    }

    /// Append a single bit (0 or 1).
    pub fn append_bit(&self, bit: u8) -> Self {
        let new_bit_len = self.bit_len + 1;
        let byte_idx = (self.bit_len / 8) as usize;
        let bit_idx = 7 - (self.bit_len % 8);

        let mut bytes = self.bytes.clone();
        if byte_idx >= bytes.len() {
            bytes.push(0);
        }
        if bit == 1 {
            bytes[byte_idx] |= 1 << bit_idx;
        }

        Self {
            bytes,
            bit_len: new_bit_len,
        }
    }

    /// Check if this label is a prefix of another.
    pub fn is_prefix_of(&self, other: &Label) -> bool {
        if self.bit_len > other.bit_len {
            return false;
        }
        if self.bit_len == 0 {
            return true;
        }

        // Compare full bytes
        let full_bytes = (self.bit_len / 8) as usize;
        if self.bytes[..full_bytes] != other.bytes[..full_bytes] {
            return false;
        }

        // Compare remaining bits
        let remaining_bits = self.bit_len % 8;
        if remaining_bits > 0 {
            let mask = 0xFFu8 << (8 - remaining_bits);
            let self_last = self.bytes.get(full_bytes).copied().unwrap_or(0) & mask;
            let other_last = other.bytes.get(full_bytes).copied().unwrap_or(0) & mask;
            if self_last != other_last {
                return false;
            }
        }

        true
    }

    /// Find the common prefix length with another label.
    pub fn common_prefix_len(&self, other: &Label) -> u32 {
        let max_len = self.bit_len.min(other.bit_len);
        if max_len == 0 {
            return 0;
        }

        // Compare full bytes first (much faster than bit-by-bit)
        let full_bytes = (max_len / 8) as usize;
        for i in 0..full_bytes {
            if self.bytes[i] != other.bytes[i] {
                // Found differing byte - find the exact bit
                let diff = self.bytes[i] ^ other.bytes[i];
                let leading_zeros = diff.leading_zeros();
                return (i as u32) * 8 + leading_zeros;
            }
        }

        // Check remaining bits in the partial byte
        let remaining_bits = max_len % 8;
        if remaining_bits > 0 && full_bytes < self.bytes.len() && full_bytes < other.bytes.len() {
            let mask = 0xFFu8 << (8 - remaining_bits);
            let self_byte = self.bytes[full_bytes] & mask;
            let other_byte = other.bytes[full_bytes] & mask;
            if self_byte != other_byte {
                let diff = self_byte ^ other_byte;
                let leading_zeros = diff.leading_zeros();
                return (full_bytes as u32) * 8 + leading_zeros;
            }
        }

        max_len
    }
}

/// A node in the prefix tree.
#[derive(Debug, Clone, Default)]
enum Node {
    /// An empty node (placeholder).
    #[default]
    Empty,
    /// A leaf node with a key and value hash.
    Leaf { key: Label, value_hash: Hash256 },
    /// An internal node with two children.
    Internal {
        /// The prefix for this subtree.
        prefix: Label,
        /// Left child (bit 0).
        left: Box<Node>,
        /// Right child (bit 1).
        right: Box<Node>,
        /// Cached hash of this node.
        hash: Hash256,
    },
}

impl Node {
    /// Compute the hash of this node.
    fn hash(&self) -> Hash256 {
        match self {
            Node::Empty => [0u8; 32],
            Node::Leaf { key, value_hash } => {
                // Hash: H(0x00 || key_bits || value_hash)
                let mut hasher = Sha256::new();
                hasher.update([0x00]); // Leaf domain separator
                hasher.update(&key.bytes);
                hasher.update(value_hash);
                hasher.finalize().into()
            }
            Node::Internal { hash, .. } => *hash,
        }
    }

    /// Check if node is empty.
    fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }
}

/// A Merkle prefix tree.
pub struct PrefixTree {
    root: Node,
}

impl Default for PrefixTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixTree {
    /// Create an empty prefix tree.
    pub fn new() -> Self {
        Self { root: Node::Empty }
    }

    /// Get the root hash of the tree.
    pub fn root_hash(&self) -> Hash256 {
        self.root.hash()
    }

    /// Insert a key-value pair into the tree.
    pub fn insert(&mut self, key: &Hash256, value_hash: Hash256) {
        let key_label = Label::from_key(key);
        self.root = Self::insert_rec(std::mem::take(&mut self.root), &key_label, value_hash);
    }

    fn insert_rec(node: Node, key: &Label, value_hash: Hash256) -> Node {
        match node {
            Node::Empty => {
                // Create a new leaf
                Node::Leaf {
                    key: key.clone(),
                    value_hash,
                }
            }
            Node::Leaf {
                key: existing_key,
                value_hash: existing_value,
            } => {
                if *key == existing_key {
                    // Update existing key
                    Node::Leaf {
                        key: key.clone(),
                        value_hash,
                    }
                } else {
                    // Split into internal node
                    let common_len = key.common_prefix_len(&existing_key);
                    let prefix = key.prefix(common_len);

                    let key_bit = key.bit(common_len);
                    let _existing_bit = existing_key.bit(common_len);

                    let new_leaf = Node::Leaf {
                        key: key.clone(),
                        value_hash,
                    };
                    let existing_leaf = Node::Leaf {
                        key: existing_key,
                        value_hash: existing_value,
                    };

                    let (left, right) = if key_bit == 0 {
                        (Box::new(new_leaf), Box::new(existing_leaf))
                    } else {
                        (Box::new(existing_leaf), Box::new(new_leaf))
                    };

                    let hash = Self::compute_internal_hash(&prefix, &left, &right);

                    Node::Internal {
                        prefix,
                        left,
                        right,
                        hash,
                    }
                }
            }
            Node::Internal {
                prefix,
                left,
                right,
                ..
            } => {
                let common_len = key.common_prefix_len(&prefix);

                if common_len < prefix.bit_len() {
                    // Key diverges before end of prefix - need to split this node
                    let new_prefix = prefix.prefix(common_len);
                    let key_bit = key.bit(common_len);

                    let new_leaf = Node::Leaf {
                        key: key.clone(),
                        value_hash,
                    };

                    // The old internal node becomes a child
                    let old_internal_hash = Self::compute_internal_hash(&prefix, &left, &right);
                    let old_internal = Node::Internal {
                        prefix: prefix.clone(),
                        left,
                        right,
                        hash: old_internal_hash,
                    };

                    let (new_left, new_right) = if key_bit == 0 {
                        (Box::new(new_leaf), Box::new(old_internal))
                    } else {
                        (Box::new(old_internal), Box::new(new_leaf))
                    };

                    let hash = Self::compute_internal_hash(&new_prefix, &new_left, &new_right);

                    Node::Internal {
                        prefix: new_prefix,
                        left: new_left,
                        right: new_right,
                        hash,
                    }
                } else {
                    // Key matches prefix - recurse into appropriate child
                    let next_bit = key.bit(prefix.bit_len());

                    let (new_left, new_right) = if next_bit == 0 {
                        let new_left = Self::insert_rec(*left, key, value_hash);
                        (Box::new(new_left), right)
                    } else {
                        let new_right = Self::insert_rec(*right, key, value_hash);
                        (left, Box::new(new_right))
                    };

                    let hash = Self::compute_internal_hash(&prefix, &new_left, &new_right);

                    Node::Internal {
                        prefix,
                        left: new_left,
                        right: new_right,
                        hash,
                    }
                }
            }
        }
    }

    fn compute_internal_hash(prefix: &Label, left: &Node, right: &Node) -> Hash256 {
        // Hash: H(0x01 || prefix_len || prefix_bytes || left_hash || right_hash)
        let mut hasher = Sha256::new();
        hasher.update([0x01]); // Internal node domain separator
        hasher.update(prefix.bit_len().to_be_bytes());
        hasher.update(&prefix.bytes);
        hasher.update(left.hash());
        hasher.update(right.hash());
        hasher.finalize().into()
    }

    /// Lookup a key and return an inclusion/exclusion proof.
    pub fn lookup(&self, key: &Hash256) -> LookupProof {
        let key_label = Label::from_key(key);
        let mut proof = Vec::new();
        let found = Self::lookup_rec(&self.root, &key_label, &mut proof);
        LookupProof { found, proof }
    }

    fn lookup_rec(node: &Node, key: &Label, proof: &mut Vec<ProofNode>) -> bool {
        match node {
            Node::Empty => false,
            Node::Leaf {
                key: leaf_key,
                value_hash: _,
            } => *key == *leaf_key,
            Node::Internal {
                prefix,
                left,
                right,
                ..
            } => {
                // Check if key matches the prefix
                if !prefix.is_prefix_of(key) {
                    // Key doesn't match this subtree
                    return false;
                }

                let next_bit = key.bit(prefix.bit_len());

                if next_bit == 0 {
                    // Going left, add right sibling to proof
                    if !right.is_empty() {
                        let right_label = prefix.append_bit(1);
                        proof.push(ProofNode {
                            label_bit_len: right_label.bit_len(),
                            label_path: right_label.bytes().to_vec(),
                            hash: right.hash(),
                        });
                    }
                    Self::lookup_rec(left, key, proof)
                } else {
                    // Going right, add left sibling to proof
                    if !left.is_empty() {
                        let left_label = prefix.append_bit(0);
                        proof.push(ProofNode {
                            label_bit_len: left_label.bit_len(),
                            label_path: left_label.bytes().to_vec(),
                            hash: left.hash(),
                        });
                    }
                    Self::lookup_rec(right, key, proof)
                }
            }
        }
    }

    /// Get the number of keys in the tree.
    pub fn len(&self) -> usize {
        Self::count_keys(&self.root)
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        matches!(self.root, Node::Empty)
    }

    fn count_keys(node: &Node) -> usize {
        match node {
            Node::Empty => 0,
            Node::Leaf { .. } => 1,
            Node::Internal { left, right, .. } => Self::count_keys(left) + Self::count_keys(right),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(n: u8) -> Hash256 {
        let mut key = [0u8; 32];
        key[0] = n;
        key
    }

    #[test]
    fn test_label_basics() {
        let label = Label::empty();
        assert_eq!(label.bit_len(), 0);

        let key = test_key(0b10110000);
        let label = Label::from_key(&key);
        assert_eq!(label.bit_len(), 256);
        assert_eq!(label.bit(0), 1);
        assert_eq!(label.bit(1), 0);
        assert_eq!(label.bit(2), 1);
        assert_eq!(label.bit(3), 1);
    }

    #[test]
    fn test_label_prefix() {
        let key = test_key(0b11001010);
        let label = Label::from_key(&key);

        let prefix = label.prefix(4);
        assert_eq!(prefix.bit_len(), 4);
        assert_eq!(prefix.bit(0), 1);
        assert_eq!(prefix.bit(1), 1);
        assert_eq!(prefix.bit(2), 0);
        assert_eq!(prefix.bit(3), 0);
    }

    #[test]
    fn test_label_is_prefix_of() {
        let key1 = test_key(0b11001010);
        let label1 = Label::from_key(&key1);

        let prefix = label1.prefix(4);
        assert!(prefix.is_prefix_of(&label1));
        assert!(!label1.is_prefix_of(&prefix));

        let empty = Label::empty();
        assert!(empty.is_prefix_of(&label1));
        assert!(empty.is_prefix_of(&prefix));
    }

    #[test]
    fn test_empty_tree() {
        let tree = PrefixTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert_eq!(tree.root_hash(), [0u8; 32]);
    }

    #[test]
    fn test_single_insert() {
        let mut tree = PrefixTree::new();
        let key = test_key(42);
        let value = [1u8; 32];

        tree.insert(&key, value);

        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);
        assert_ne!(tree.root_hash(), [0u8; 32]);

        let result = tree.lookup(&key);
        assert!(result.found);
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = PrefixTree::new();

        for i in 0..10u8 {
            let key = test_key(i);
            let value = [i; 32];
            tree.insert(&key, value);
        }

        assert_eq!(tree.len(), 10);

        // All keys should be found
        for i in 0..10u8 {
            let key = test_key(i);
            let result = tree.lookup(&key);
            assert!(result.found, "Key {} not found", i);
        }

        // Non-existent key should not be found
        let result = tree.lookup(&test_key(255));
        assert!(!result.found);
    }

    #[test]
    fn test_update_existing_key() {
        let mut tree = PrefixTree::new();
        let key = test_key(42);

        tree.insert(&key, [1u8; 32]);
        let hash1 = tree.root_hash();

        tree.insert(&key, [2u8; 32]);
        let hash2 = tree.root_hash();

        assert_ne!(hash1, hash2);
        assert_eq!(tree.len(), 1); // Still only one key
    }

    #[test]
    fn test_lookup_proof_structure() {
        let mut tree = PrefixTree::new();

        // Insert keys that will create a specific tree structure
        let key1 = test_key(0b00000000); // Starts with 0
        let key2 = test_key(0b10000000); // Starts with 1

        tree.insert(&key1, [1u8; 32]);
        tree.insert(&key2, [2u8; 32]);

        // Lookup key1 should have key2's subtree in proof
        let result1 = tree.lookup(&key1);
        assert!(result1.found);
        assert!(!result1.proof.is_empty());

        // Lookup key2 should have key1's subtree in proof
        let result2 = tree.lookup(&key2);
        assert!(result2.found);
        assert!(!result2.proof.is_empty());
    }

    #[test]
    fn test_deterministic_root() {
        // Same insertions in same order should produce same root
        let mut tree1 = PrefixTree::new();
        let mut tree2 = PrefixTree::new();

        for i in 0..5u8 {
            let key = test_key(i);
            let value = [i; 32];
            tree1.insert(&key, value);
            tree2.insert(&key, value);
        }

        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }

    #[test]
    fn test_insert_performance() {
        use sha2::{Digest, Sha256};
        use std::time::Instant;

        let mut tree = PrefixTree::new();
        let count = 1000;

        // Generate realistic SHA256 hash keys
        let keys: Vec<Hash256> = (0..count)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(format!("package-{}", i).as_bytes());
                hasher.finalize().into()
            })
            .collect();

        let start = Instant::now();
        for (i, key) in keys.iter().enumerate() {
            let value = [i as u8; 32];
            tree.insert(key, value);
        }
        let elapsed = start.elapsed();

        println!(
            "Inserted {} keys in {:?} ({:.2} µs/key)",
            count,
            elapsed,
            elapsed.as_micros() as f64 / count as f64
        );

        // In release mode: ~6µs/key, in debug: ~100µs/key
        // Allow up to 200ms for debug builds
        assert!(
            elapsed.as_millis() < 200,
            "Insert performance too slow: {:?}",
            elapsed
        );

        assert_eq!(tree.len(), count);
    }
}
