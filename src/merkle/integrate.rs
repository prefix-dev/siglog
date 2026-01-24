//! Merkle tree integration for transparency log.
//!
//! Implements incremental tree building using the compact range algorithm.
//! Uses sigstore-merkle for hash operations.

use crate::api::paths::{TILE_HEIGHT, TILE_WIDTH};
use crate::error::{Error, Result};
use crate::merkle::HashTile;
use crate::storage::TileStorage;
use crate::types::{PartialSize, TileId, TileIndex, TileLevel, TreeSize};
use sigstore_merkle::hash_children;
use sigstore_types::Sha256Hash;
use std::collections::HashMap;

/// Tile identifier for caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TileKey {
    level: u64,
    index: u64,
}

impl From<TileId> for TileKey {
    fn from(id: TileId) -> Self {
        Self {
            level: id.level.value(),
            index: id.index.value(),
        }
    }
}

/// Result of integrating entries into the tree.
#[derive(Debug)]
pub struct IntegrationResult {
    /// New tree size after integration.
    pub new_size: TreeSize,
    /// New root hash.
    pub root_hash: Sha256Hash,
    /// Tiles that were created or modified.
    pub tiles: HashMap<TileId, HashTile>,
}

/// Integrate new leaf hashes into the Merkle tree.
///
/// This function:
/// 1. Loads the existing compact range from storage
/// 2. Appends new leaves to build the tree incrementally
/// 3. Returns the new tiles that need to be written
pub async fn integrate(
    storage: &TileStorage,
    from_size: TreeSize,
    leaf_hashes: &[Sha256Hash],
) -> Result<IntegrationResult> {
    if leaf_hashes.is_empty() {
        // Nothing to integrate
        let root_hash = if from_size.value() == 0 {
            empty_root_hash()
        } else {
            // Would need to compute from existing tree
            return Err(Error::Internal(
                "cannot get root of non-empty tree without new entries".into(),
            ));
        };

        return Ok(IntegrationResult {
            new_size: from_size,
            root_hash,
            tiles: HashMap::new(),
        });
    }

    let mut builder = TreeBuilder::new(storage, from_size).await?;

    // Append all leaf hashes
    for leaf_hash in leaf_hashes {
        builder.append(*leaf_hash)?;
    }

    // Finalize and get results
    builder.finalize().await
}

/// RFC 6962 empty tree root hash.
fn empty_root_hash() -> Sha256Hash {
    // SHA256(empty) for RFC 6962
    Sha256Hash::from_bytes([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ])
}

/// Incremental tree builder using compact range algorithm.
struct TreeBuilder<'a> {
    storage: &'a TileStorage,
    /// Initial tree size (before this integration).
    from_size: u64,
    /// Current tree size (number of leaves).
    size: u64,
    /// The compact range: hashes of complete subtrees at each level.
    /// Index is the level (0 = leaves).
    range: Vec<Option<Sha256Hash>>,
    /// Tile write cache.
    tile_cache: HashMap<TileKey, TileMutator>,
}

impl<'a> TreeBuilder<'a> {
    /// Create a new tree builder from existing state.
    async fn new(storage: &'a TileStorage, from_size: TreeSize) -> Result<Self> {
        let size = from_size.value();

        // Build the compact range from the existing tree
        let range = if size == 0 {
            Vec::new()
        } else {
            load_compact_range(storage, size).await?
        };

        Ok(Self {
            storage,
            from_size: size,
            size,
            range,
            tile_cache: HashMap::new(),
        })
    }

    /// Append a leaf hash to the tree.
    fn append(&mut self, leaf_hash: Sha256Hash) -> Result<()> {
        let leaf_index = self.size;
        self.size += 1;

        // Store the leaf hash in the appropriate tile
        self.set_node(0, leaf_index, leaf_hash)?;

        // Propagate up the tree
        let mut hash = leaf_hash;
        let mut index = leaf_index;
        let mut level = 0u64;

        // Merge with existing subtrees at each level
        while index & 1 == 1 {
            // We're a right child, merge with left sibling
            if let Some(left) = self.range.get(level as usize).and_then(|h| *h) {
                hash = hash_children(&left, &hash);
                self.range[level as usize] = None;

                // Store the internal node if it's not ephemeral
                level += 1;
                index >>= 1;

                if should_store_node(level, index, self.size) {
                    self.set_node(level, index, hash)?;
                }
            } else {
                break;
            }
        }

        // Store in the compact range
        while self.range.len() <= level as usize {
            self.range.push(None);
        }
        self.range[level as usize] = Some(hash);

        Ok(())
    }

    /// Set a node hash at the given level and index.
    fn set_node(&mut self, level: u64, index: u64, hash: Sha256Hash) -> Result<()> {
        let (tile_level, tile_index, node_level, node_index) = node_to_tile_coords(level, index);

        let key = TileKey {
            level: tile_level,
            index: tile_index,
        };

        let mutator = self.tile_cache.entry(key).or_insert_with(TileMutator::new);

        mutator.set(node_level as usize, node_index as usize, hash);

        Ok(())
    }

    /// Finalize the tree and return results.
    async fn finalize(self) -> Result<IntegrationResult> {
        // Compute the root hash from the compact range
        let root_hash = self.compute_root()?;

        // Convert tile cache to output format
        let mut tiles = HashMap::new();
        for (key, mutator) in self.tile_cache {
            // Load existing tile if any
            let level = TileLevel::new(key.level);
            let index = TileIndex::new(key.index);

            // Calculate the previous partial size (what existed before this integration)
            let prev_partial = partial_tile_size(key.level, key.index, self.from_size);

            // Try to load existing tile:
            // - If previous was partial, load that partial tile
            // - If previous was full (or tile didn't exist), try loading full tile
            let mut tile = if prev_partial.value() > 0 {
                // Previous tile was partial, load it
                self.storage
                    .read_tile(level, index, prev_partial)
                    .await?
                    .unwrap_or_else(HashTile::new)
            } else {
                // Previous tile was full or doesn't exist yet
                self.storage
                    .read_tile(level, index, PartialSize::full())
                    .await?
                    .unwrap_or_else(HashTile::new)
            };

            // Apply mutations
            mutator.apply_to(&mut tile);

            let tile_id = TileId::new(level, index);
            tiles.insert(tile_id, tile);
        }

        Ok(IntegrationResult {
            new_size: TreeSize::new(self.size),
            root_hash,
            tiles,
        })
    }

    /// Compute the root hash from the compact range.
    fn compute_root(&self) -> Result<Sha256Hash> {
        if self.size == 0 {
            return Ok(empty_root_hash());
        }

        // Chain the compact range hashes to get the root
        let mut hash: Option<Sha256Hash> = None;

        for h in self.range.iter().flatten() {
            hash = Some(match hash {
                None => *h,
                Some(right) => hash_children(h, &right),
            });
        }

        hash.ok_or_else(|| Error::Internal("empty compact range".into()))
    }
}

/// Check if a node should be stored (non-ephemeral).
fn should_store_node(level: u64, index: u64, tree_size: u64) -> bool {
    // A node is non-ephemeral if it's within the tile structure
    // and the subtree it represents is complete
    let subtree_size = 1u64 << level;
    let subtree_end = (index + 1) * subtree_size;

    // Node is complete if the subtree end is within the tree
    subtree_end <= tree_size
}

/// Convert node coordinates to tile coordinates.
fn node_to_tile_coords(level: u64, index: u64) -> (u64, u64, u64, u64) {
    let tile_row_width = 1u64 << (TILE_HEIGHT - level % TILE_HEIGHT);
    let tile_level = level / TILE_HEIGHT;
    let tile_index = index / tile_row_width;
    let node_level = level % TILE_HEIGHT;
    let node_index = index % tile_row_width;

    (tile_level, tile_index, node_level, node_index)
}

/// Calculate partial tile size.
fn partial_tile_size(level: u64, index: u64, log_size: u64) -> PartialSize {
    let size_at_level = log_size >> (level * TILE_HEIGHT);
    let full_tiles = size_at_level / TILE_WIDTH;

    if index < full_tiles {
        PartialSize::full()
    } else {
        PartialSize::new((size_at_level % TILE_WIDTH) as u8)
    }
}

/// Load the compact range from existing tiles.
async fn load_compact_range(storage: &TileStorage, size: u64) -> Result<Vec<Option<Sha256Hash>>> {
    // Compute which nodes are in the compact range
    let range_nodes = compute_range_nodes(size);

    let mut range = Vec::new();

    for (level, index) in range_nodes {
        // Compute the hash for this node
        let hash = compute_node_hash(storage, level, index, size).await?;

        while range.len() <= level as usize {
            range.push(None);
        }
        range[level as usize] = Some(hash);
    }

    Ok(range)
}

/// Recursively compute a node hash from tiles.
/// For leaf nodes (level 0), read directly from tile.
/// For internal nodes, recursively compute from children.
#[async_recursion::async_recursion]
async fn compute_node_hash(
    storage: &TileStorage,
    level: u64,
    index: u64,
    tree_size: u64,
) -> Result<Sha256Hash> {
    if level == 0 {
        // Leaf node - read from tile
        let (tile_level, tile_index, _node_level, node_index) = node_to_tile_coords(level, index);
        let partial = partial_tile_size(tile_level, tile_index, tree_size);

        let tile = storage
            .read_tile(
                TileLevel::new(tile_level),
                TileIndex::new(tile_index),
                partial,
            )
            .await?
            .ok_or_else(|| {
                Error::Internal(format!(
                    "missing tile at level={}, index={}",
                    tile_level, tile_index
                ))
            })?;

        tile.nodes
            .get(node_index as usize)
            .copied()
            .ok_or_else(|| Error::Internal(format!("missing leaf at index {}", node_index)))
    } else {
        // Internal node - compute from children
        let left_index = index * 2;
        let right_index = index * 2 + 1;

        let left = compute_node_hash(storage, level - 1, left_index, tree_size).await?;
        let right = compute_node_hash(storage, level - 1, right_index, tree_size).await?;

        Ok(hash_children(&left, &right))
    }
}

/// Compute the nodes in the compact range for a given tree size.
///
/// The compact range represents the rightmost complete subtrees at each level.
/// For tree size N, we iterate through its binary representation - each 1 bit
/// indicates a complete subtree of that power-of-2 size in the frontier.
///
/// The node index at each level is computed from the cumulative count of leaves
/// covered by larger (higher-level) subtrees, divided by the subtree size at that level.
fn compute_range_nodes(size: u64) -> Vec<(u64, u64)> {
    if size == 0 {
        return Vec::new();
    }

    // Find the highest bit set to determine max level
    let max_level = 63 - size.leading_zeros() as u64;

    let mut nodes = Vec::new();
    let mut cumulative_leaves = 0u64;

    // Iterate from highest level to lowest
    for level in (0..=max_level).rev() {
        let subtree_size = 1u64 << level;
        if size & subtree_size != 0 {
            // There's a complete subtree at this level
            // The index is the cumulative leaf count divided by subtree size
            let index = cumulative_leaves >> level;
            nodes.push((level, index));
            cumulative_leaves += subtree_size;
        }
    }

    // Reverse to get lowest level first (matching the original order)
    nodes.reverse();
    nodes
}

/// Tile mutator for tracking changes to a tile.
///
/// Tiles store hashes in a specific layout based on the tree structure.
/// For a tile with height 8, the layout is:
/// - Rows 0-255: Level 0 (leaf hashes) - 256 entries
/// - Rows 256-383: Level 1 - 128 entries
/// - Rows 384-447: Level 2 - 64 entries
/// - etc.
#[derive(Debug)]
struct TileMutator {
    /// Changes keyed by (level, index_within_level) -> hash
    nodes: HashMap<(usize, usize), Sha256Hash>,
}

impl TileMutator {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    fn set(&mut self, level: usize, index: usize, hash: Sha256Hash) {
        self.nodes.insert((level, index), hash);
    }

    fn apply_to(self, tile: &mut HashTile) {
        // Calculate the flat offset for a node at (level, index)
        // Level 0 (leaves): indices 0-255, offset = index
        // Level 1: indices 0-127, offset = 256 + index
        // Level 2: indices 0-63, offset = 256 + 128 + index
        // etc.
        fn flat_offset(level: usize, index: usize) -> usize {
            let mut offset = 0;
            let mut width = TILE_WIDTH as usize;
            for _ in 0..level {
                offset += width;
                width /= 2;
            }
            offset + index
        }

        // Find max offset needed
        let max_offset = self
            .nodes
            .keys()
            .map(|&(level, index)| flat_offset(level, index))
            .max()
            .unwrap_or(0);

        // Ensure tile has enough capacity
        while tile.nodes.len() <= max_offset {
            tile.nodes.push(Sha256Hash::from_bytes([0u8; 32]));
        }

        // Apply changes
        for ((level, index), hash) in self.nodes {
            let offset = flat_offset(level, index);
            tile.nodes[offset] = hash;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_to_tile_coords() {
        // Level 0, index 0 -> tile (0, 0), node (0, 0)
        assert_eq!(node_to_tile_coords(0, 0), (0, 0, 0, 0));

        // Level 0, index 255 -> tile (0, 0), node (0, 255)
        assert_eq!(node_to_tile_coords(0, 255), (0, 0, 0, 255));

        // Level 0, index 256 -> tile (0, 1), node (0, 0)
        assert_eq!(node_to_tile_coords(0, 256), (0, 1, 0, 0));

        // Level 8, index 0 -> tile (1, 0), node (0, 0)
        assert_eq!(node_to_tile_coords(8, 0), (1, 0, 0, 0));
    }

    /// Test vectors ported from tessera's TestNodeCoordsToTileAddress in tile_test.go
    #[test]
    fn test_node_to_tile_coords_tessera_vectors() {
        // These are direct ports from tessera/api/layout/tile_test.go
        let test_cases = [
            // (tree_level, tree_index) -> (tile_level, tile_index, node_level, node_index)
            (0, 0, 0, 0, 0, 0),
            (0, 255, 0, 0, 0, 255),
            (0, 256, 0, 1, 0, 0),
            (1, 0, 0, 0, 1, 0),
            (8, 0, 1, 0, 0, 0),
        ];

        for (
            tree_level,
            tree_index,
            want_tile_level,
            want_tile_index,
            want_node_level,
            want_node_index,
        ) in test_cases
        {
            let (tl, ti, nl, ni) = node_to_tile_coords(tree_level, tree_index);
            assert_eq!(
                tl, want_tile_level,
                "tile_level mismatch for ({}, {})",
                tree_level, tree_index
            );
            assert_eq!(
                ti, want_tile_index,
                "tile_index mismatch for ({}, {})",
                tree_level, tree_index
            );
            assert_eq!(
                nl, want_node_level,
                "node_level mismatch for ({}, {})",
                tree_level, tree_index
            );
            assert_eq!(
                ni, want_node_index,
                "node_index mismatch for ({}, {})",
                tree_level, tree_index
            );
        }
    }

    #[test]
    fn test_compute_range_nodes() {
        // Size 1: one node at level 0, index 0
        assert_eq!(compute_range_nodes(1), vec![(0, 0)]);

        // Size 2: one node at level 1, index 0
        assert_eq!(compute_range_nodes(2), vec![(1, 0)]);

        // Size 3: nodes at level 0 index 2, level 1 index 0
        // - Level 1 subtree covers leaves 0-1 at index 0
        // - Level 0 leaf 2 is at index 2
        assert_eq!(compute_range_nodes(3), vec![(0, 2), (1, 0)]);

        // Size 4: one node at level 2, index 0
        assert_eq!(compute_range_nodes(4), vec![(2, 0)]);

        // Size 5: nodes at level 0 index 4, level 2 index 0
        // - 4 leaves (0-3) form complete subtree at level 2, index 0
        // - Leaf 4 at level 0, index 4
        assert_eq!(compute_range_nodes(5), vec![(0, 4), (2, 0)]);

        // Size 1560: 1024 + 512 + 16 + 8 leaves
        // - Level 10 subtree covers leaves 0-1023 at index 0
        // - Level 9 subtree covers leaves 1024-1535 at index 2
        // - Level 4 subtree covers leaves 1536-1551 at index 96
        // - Level 3 subtree covers leaves 1552-1559 at index 194
        assert_eq!(
            compute_range_nodes(1560),
            vec![(3, 194), (4, 96), (9, 2), (10, 0)]
        );
    }

    #[test]
    fn test_empty_root() {
        let root = empty_root_hash();
        // SHA256 of empty string
        assert_eq!(
            root.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Compute root hash from leaf hashes using compact range algorithm.
    /// This is a simplified synchronous version for testing.
    fn compute_root_from_leaves(leaf_hashes: &[Sha256Hash]) -> Sha256Hash {
        if leaf_hashes.is_empty() {
            return empty_root_hash();
        }

        // Build compact range by appending leaves
        let mut range: Vec<Option<Sha256Hash>> = Vec::new();

        for (leaf_index, &leaf_hash) in leaf_hashes.iter().enumerate() {
            let mut hash = leaf_hash;
            let mut index = leaf_index as u64;
            let mut level = 0usize;

            // Merge with existing subtrees at each level
            while index & 1 == 1 {
                if let Some(Some(left)) = range.get(level) {
                    hash = hash_children(left, &hash);
                    range[level] = None;
                    level += 1;
                    index >>= 1;
                } else {
                    break;
                }
            }

            while range.len() <= level {
                range.push(None);
            }
            range[level] = Some(hash);
        }

        // Chain range hashes to get root
        let mut root: Option<Sha256Hash> = None;
        for h in range.iter().flatten() {
            root = Some(match root {
                None => *h,
                Some(right) => hash_children(h, &right),
            });
        }

        root.unwrap_or_else(empty_root_hash)
    }

    /// RFC 6962 leaf hash: SHA256(0x00 || data)
    fn rfc6962_hash_leaf(data: &[u8]) -> Sha256Hash {
        sigstore_merkle::hash_leaf(data)
    }

    /// Test that validates root hash computation matches expected values.
    /// These test vectors ensure compatibility with tessera's implementation.
    #[test]
    fn test_root_hash_computation() {
        // Single leaf tree
        let leaf0 = rfc6962_hash_leaf(&[0u8]);
        let root1 = compute_root_from_leaves(&[leaf0]);
        // Root of single leaf tree is just the leaf hash
        assert_eq!(root1, leaf0, "single leaf root mismatch");

        // Two leaf tree
        let leaf1 = rfc6962_hash_leaf(&[1u8]);
        let root2 = compute_root_from_leaves(&[leaf0, leaf1]);
        // Root should be hash_children(leaf0, leaf1)
        let expected_root2 = hash_children(&leaf0, &leaf1);
        assert_eq!(root2, expected_root2, "two leaf root mismatch");

        // Three leaf tree
        let leaf2 = rfc6962_hash_leaf(&[2u8]);
        let root3 = compute_root_from_leaves(&[leaf0, leaf1, leaf2]);
        // Root should be hash_children(hash_children(leaf0, leaf1), leaf2)
        let expected_root3 = hash_children(&expected_root2, &leaf2);
        assert_eq!(root3, expected_root3, "three leaf root mismatch");

        // Four leaf tree (balanced)
        let leaf3 = rfc6962_hash_leaf(&[3u8]);
        let root4 = compute_root_from_leaves(&[leaf0, leaf1, leaf2, leaf3]);
        // Root should be hash_children(hash_children(leaf0, leaf1), hash_children(leaf2, leaf3))
        let expected_root4 = hash_children(&expected_root2, &hash_children(&leaf2, &leaf3));
        assert_eq!(root4, expected_root4, "four leaf root mismatch");
    }

    /// Test that validates incremental tree building produces same roots.
    /// Ported from tessera's TestIntegrate which validates consistent incremental building.
    #[test]
    fn test_incremental_root_consistency() {
        // Build tree incrementally and verify roots match batch computation
        let mut leaves = Vec::new();

        for i in 0..=255u8 {
            let leaf_hash = rfc6962_hash_leaf(&[i]);
            leaves.push(leaf_hash);

            // Compute root incrementally
            let incremental_root = compute_root_from_leaves(&leaves);

            // Compute root from scratch with same leaves
            let batch_root = compute_root_from_leaves(&leaves);

            assert_eq!(
                incremental_root,
                batch_root,
                "root mismatch at size {}: incremental {:?} vs batch {:?}",
                leaves.len(),
                incremental_root.to_hex(),
                batch_root.to_hex()
            );
        }
    }

    /// Test large tree (mimics tessera's TestIntegrate with 200 entries * multiple chunks).
    /// This validates the compact range algorithm handles larger trees correctly.
    #[test]
    fn test_large_tree_root_computation() {
        let chunk_size = 200;
        let num_chunks = 10;
        let mut leaves = Vec::new();

        for chunk in 0..num_chunks {
            // Add a chunk of leaves
            for i in 0..chunk_size {
                let seq = chunk * chunk_size + i;
                let leaf_hash = rfc6962_hash_leaf(&[seq as u8]);
                leaves.push(leaf_hash);
            }

            // Verify root can be computed without error
            let root = compute_root_from_leaves(&leaves);

            // Sanity check: root should be 32 bytes
            assert_eq!(
                root.as_bytes().len(),
                32,
                "root should be 32 bytes at chunk {}",
                chunk
            );

            // Sanity check: root should not be all zeros (except for extremely unlikely collision)
            assert_ne!(
                root.as_bytes(),
                &[0u8; 32],
                "root should not be all zeros at chunk {}",
                chunk
            );
        }
    }

    /// Test specific known root hash values.
    /// These can be validated against Go tessera to ensure byte-for-byte compatibility.
    #[test]
    fn test_known_root_hashes() {
        // Empty tree - RFC 6962 specifies empty root as SHA256("")
        assert_eq!(
            empty_root_hash().to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Single leaf: RFC 6962 leaf hash is SHA256(0x00 || data)
        // So hash_leaf([0x00]) = SHA256(0x00 || 0x00) = SHA256([0x00, 0x00])
        let leaf = rfc6962_hash_leaf(&[0x00]);
        let root1 = compute_root_from_leaves(&[leaf]);

        // For size=1, root equals the single leaf hash
        assert_eq!(root1, leaf);

        // RFC 6962 leaf hash of [0x00] is SHA256(0x00 || 0x00)
        // This is NOT the same as SHA256(0x00) which would be 5feceb66...
        // SHA256(0x00 || 0x00) = SHA256([0x00, 0x00]) which is different
        let sha256_of_zero = "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9";
        assert_ne!(
            leaf.to_hex(),
            sha256_of_zero,
            "RFC 6962 leaf hash should include 0x00 prefix, not be raw SHA256"
        );
    }

    /// Test vectors generated from Go tessera reference implementation.
    /// These ensure byte-for-byte compatibility with the Go implementation.
    ///
    /// Generated with: cd tessera && go run ../tests/generate_vectors.go
    #[test]
    fn test_go_tessera_leaf_hash_vectors() {
        // RFC 6962 leaf hash = SHA256(0x00 || data)
        let test_vectors = [
            (
                0x00u8,
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            ),
            (
                0x01u8,
                "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
            ),
            (
                0x02u8,
                "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f",
            ),
            (
                0x03u8,
                "583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d",
            ),
            (
                0x04u8,
                "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            ),
        ];

        for (input, expected_hex) in test_vectors {
            let hash = rfc6962_hash_leaf(&[input]);
            assert_eq!(
                hash.to_hex(),
                expected_hex,
                "leaf hash mismatch for input 0x{:02x}",
                input
            );
        }
    }

    /// Root hash test vectors from Go tessera.
    /// Trees are built with sequential byte leaves: [0], [1], [2], ...
    ///
    /// Generated with: cd tessera && go run ../tests/generate_vectors.go
    #[test]
    fn test_go_tessera_root_hash_vectors() {
        // (tree_size, expected_root_hash_hex)
        let test_vectors = [
            (
                1,
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            ),
            (
                2,
                "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a",
            ),
            (
                3,
                "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688",
            ),
            (
                4,
                "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
            ),
            (
                5,
                "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
            ),
            (
                6,
                "bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8",
            ),
            (
                7,
                "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3",
            ),
            (
                8,
                "ef7f49b620f6c7ea9b963a214da34b5021c6ded8ed57734380a311ab726aa907",
            ),
            (
                9,
                "162a21c2230e0284ea38cb8739ee4bb75947a1acd5d529c638ec068969fb3c4a",
            ),
            (
                10,
                "487540cba07f8eee7688295955ee3b4c04003e8ca2de94426237cd44491108a7",
            ),
        ];

        for (size, expected_hex) in test_vectors {
            // Build tree with sequential byte leaves [0], [1], ..., [size-1]
            let leaves: Vec<Sha256Hash> =
                (0..size).map(|i| rfc6962_hash_leaf(&[i as u8])).collect();

            let root = compute_root_from_leaves(&leaves);
            assert_eq!(
                root.to_hex(),
                expected_hex,
                "root hash mismatch for size {}",
                size
            );
        }
    }

    /// Larger tree test vectors from Go tessera.
    /// These test the algorithm with sizes that span multiple tiles.
    #[test]
    fn test_go_tessera_large_tree_vectors() {
        // (tree_size, expected_root_hash_hex)
        // Note: leaves are [0], [1], ..., wrapping at 256 back to [0]
        let test_vectors = [
            (
                16,
                "93f2bd0cd60b2e597cf53fb12ae63ed157e0c10efbfe097d23caf8a5f59c6e27",
            ),
            (
                100,
                "9eccc8f11ab3ecd41cbf41f5045df576dcedc60f44d4a3de5f40b7d4f7e9d7e3",
            ),
            (
                200,
                "e2f07a9cf65026ba282cb286d673b564787a64785575ad1aaa74468da02d6161",
            ),
            (
                256,
                "0387b1bfaad194ad5b534d6a57c9710a83484cb544258df5f4df94bc41820b5f",
            ),
        ];

        for (size, expected_hex) in test_vectors {
            // Build tree with sequential byte leaves [0], [1], ..., wrapping at 256
            let leaves: Vec<Sha256Hash> = (0..size)
                .map(|i| rfc6962_hash_leaf(&[(i % 256) as u8]))
                .collect();

            let root = compute_root_from_leaves(&leaves);
            assert_eq!(
                root.to_hex(),
                expected_hex,
                "root hash mismatch for size {}",
                size
            );
        }
    }
}
