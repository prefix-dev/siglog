//! Merkle proof generation for transparency logs.
//!
//! This module provides consistency proof generation using tile-based storage.
//! For small trees where higher-level tiles don't exist, internal hashes are
//! computed dynamically from level 0 (leaf) hashes.

use crate::error::{Error, Result};
use crate::storage::TileStorage;
use crate::types::{PartialSize, TileIndex, TileLevel};
use sigstore_merkle::hash_children;
use sigstore_types::Sha256Hash;

/// Hash tile source, shared by local proof generation and remote verification.
#[async_trait::async_trait]
pub trait TileReader: Send + Sync {
    async fn read_tile(
        &self,
        level: TileLevel,
        index: TileIndex,
        partial: PartialSize,
    ) -> Result<Option<crate::merkle::HashTile>>;
}

#[async_trait::async_trait]
impl TileReader for TileStorage {
    async fn read_tile(
        &self,
        level: TileLevel,
        index: TileIndex,
        partial: PartialSize,
    ) -> Result<Option<crate::merkle::HashTile>> {
        TileStorage::read_tile(self, level, index, partial).await
    }
}

/// Tile width (256 hashes per tile per level).
const TILE_WIDTH: u64 = 256;

/// Generate a consistency proof from old_size to new_size.
///
/// The proof demonstrates that the tree at old_size is a prefix of the tree
/// at new_size, as per RFC 9162 §2.1.4.2.
///
/// This function handles small trees where higher-level tiles don't exist
/// by computing internal hashes from level 0 tiles.
pub async fn generate_consistency_proof_simple(
    storage: &dyn TileReader,
    old_size: u64,
    new_size: u64,
) -> Result<Vec<Sha256Hash>> {
    if old_size == 0 || old_size == new_size {
        return Ok(vec![]);
    }

    if old_size > new_size {
        return Err(Error::InvalidEntry(format!(
            "old_size ({}) > new_size ({})",
            old_size, new_size
        )));
    }

    // Use proof generation matching the verification algorithm
    proof_nodes(storage, old_size, new_size, true).await
}

/// Generate proof nodes for consistency proof.
/// This implements the algorithm to match the verification in witness/proof.rs.
#[async_recursion::async_recursion]
async fn proof_nodes(
    storage: &dyn TileReader,
    old_size: u64,
    new_size: u64,
    start_from_old_root: bool,
) -> Result<Vec<Sha256Hash>> {
    let mut proof = Vec::new();

    // Handle the case where old_size is at a complete subtree boundary
    if old_size.is_power_of_two() {
        // For power-of-2 old_size, the old_root is provided separately to verification,
        // so the proof contains only the siblings needed to reach the new root.
        let level = old_size.trailing_zeros() as u64;
        proof.extend(path_siblings(storage, old_size, new_size, level).await?);
    } else {
        // Non-power-of-2: use the standard subproof algorithm
        subproof(
            storage,
            old_size,
            new_size,
            0,
            new_size,
            start_from_old_root,
            &mut proof,
        )
        .await?;
    }

    Ok(proof)
}

/// Get sibling hashes along the path from old_size subtree to new root.
async fn path_siblings(
    storage: &dyn TileReader,
    _old_size: u64,
    new_size: u64,
    start_level: u64,
) -> Result<Vec<Sha256Hash>> {
    let mut siblings = Vec::new();
    let mut level = start_level;
    // For power-of-2 old_size, the old tree is the leftmost subtree at its level
    let mut path_idx = 0u64;

    while (1u64 << level) < new_size {
        let subtree_size = 1u64 << level;
        let sibling_idx = path_idx ^ 1; // XOR to get sibling index
        let sibling_start = sibling_idx * subtree_size;

        // Only add sibling if it exists in the tree
        if sibling_start < new_size {
            let sibling_end = (sibling_start + subtree_size).min(new_size);
            let sibling_hash =
                compute_subtree_hash(storage, sibling_start, sibling_end, new_size).await?;
            siblings.push(sibling_hash);
        }

        level += 1;
        path_idx >>= 1;
    }

    Ok(siblings)
}

/// Recursive subproof algorithm per RFC 9162.
#[async_recursion::async_recursion]
async fn subproof(
    storage: &dyn TileReader,
    m: u64,
    n: u64,
    base: u64,
    tree_size: u64,
    complete: bool,
    proof: &mut Vec<Sha256Hash>,
) -> Result<Sha256Hash> {
    if m == n {
        let hash = compute_subtree_hash(storage, base, base + m, tree_size).await?;
        if !complete {
            proof.push(hash);
        }
        return Ok(hash);
    }

    let k = largest_power_of_2_less_than(n);

    if m <= k {
        let left_hash = subproof(storage, m, k, base, tree_size, complete, proof).await?;
        let right_hash = compute_subtree_hash(storage, base + k, base + n, tree_size).await?;
        proof.push(right_hash);
        Ok(hash_children(&left_hash, &right_hash))
    } else {
        let left_hash = compute_subtree_hash(storage, base, base + k, tree_size).await?;
        let right_hash = subproof(storage, m - k, n - k, base + k, tree_size, false, proof).await?;
        proof.push(left_hash);
        Ok(hash_children(&left_hash, &right_hash))
    }
}

/// Compute the hash of a subtree from start to end.
#[async_recursion::async_recursion]
pub async fn compute_subtree_hash(
    storage: &dyn TileReader,
    start: u64,
    end: u64,
    tree_size: u64,
) -> Result<Sha256Hash> {
    let count = end - start;

    if count == 0 {
        return Err(Error::InvalidEntry("empty subtree".into()));
    }

    if count == 1 {
        return read_leaf_hash(storage, start, tree_size).await;
    }

    if count.is_power_of_two() && start.is_multiple_of(count) {
        let level = count.trailing_zeros() as u8;
        return try_read_tile_hash(storage, level, start >> level, tree_size).await;
    }

    let k = largest_power_of_2_less_than(count);
    let left = compute_subtree_hash(storage, start, start + k, tree_size).await?;
    let right = compute_subtree_hash(storage, start + k, end, tree_size).await?;
    Ok(hash_children(&left, &right))
}

/// Read a leaf hash from level 0 tiles.
async fn read_leaf_hash(
    storage: &dyn TileReader,
    index: u64,
    tree_size: u64,
) -> Result<Sha256Hash> {
    let tile_index = index / TILE_WIDTH;
    let offset = (index % TILE_WIDTH) as usize;

    let tile_start = tile_index * TILE_WIDTH;
    let partial = if tile_start + TILE_WIDTH > tree_size {
        (tree_size - tile_start).min(255) as u8
    } else {
        0
    };

    let tile = storage
        .read_tile(
            TileLevel::new(0),
            TileIndex::new(tile_index),
            PartialSize::new(partial),
        )
        .await?
        .ok_or_else(|| {
            Error::NotFound(format!("leaf tile 0/{} (partial={})", tile_index, partial))
        })?;

    if offset >= tile.nodes.len() {
        return Err(Error::NotFound(format!(
            "leaf {} not in tile 0/{} (tile has {} nodes)",
            index,
            tile_index,
            tile.nodes.len()
        )));
    }

    Ok(tile.nodes[offset])
}

/// Try to read a hash from a tile at the specified level.
async fn try_read_tile_hash(
    storage: &dyn TileReader,
    level: u8,
    index: u64,
    tree_size: u64,
) -> Result<Sha256Hash> {
    // A tile spans eight tree levels; only its bottom row is stored.
    let tile_level = u64::from(level) / 8;
    let width = 1usize << (level % 8);
    let bottom_index = index << (level % 8);
    let tile_index = bottom_index / TILE_WIDTH;
    let offset = (bottom_index % TILE_WIDTH) as usize;
    let partial = crate::api::paths::partial_tile_size(tile_level, tile_index, tree_size);

    let tile = storage
        .read_tile(
            TileLevel::new(tile_level),
            TileIndex::new(tile_index),
            PartialSize::new(partial),
        )
        .await?
        .ok_or_else(|| {
            Error::NotFound(format!(
                "tile {}/{} (partial={})",
                level, tile_index, partial
            ))
        })?;

    let mut nodes = tile
        .nodes
        .get(offset..offset + width)
        .ok_or_else(|| Error::NotFound("subtree missing from tile".into()))?
        .to_vec();
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|p| hash_children(&p[0], &p[1]))
            .collect();
    }
    Ok(nodes[0])
}

/// RFC 6962 inclusion path, ordered from leaf to root, at one fixed tree size.
pub async fn generate_inclusion_proof(
    storage: &dyn TileReader,
    index: u64,
    tree_size: u64,
) -> Result<Vec<Sha256Hash>> {
    if index >= tree_size {
        return Err(Error::InvalidEntry("index outside tree".into()));
    }
    let (mut start, mut end) = (0, tree_size);
    let mut siblings = Vec::new();
    while end - start > 1 {
        let split = start + largest_power_of_2_less_than(end - start);
        if index < split {
            siblings.push((split, end));
            end = split;
        } else {
            siblings.push((start, split));
            start = split;
        }
    }
    let mut proof = Vec::with_capacity(siblings.len());
    for (start, end) in siblings.into_iter().rev() {
        proof.push(compute_subtree_hash(storage, start, end, tree_size).await?);
    }
    Ok(proof)
}

/// Get the largest power of 2 that is strictly less than n.
fn largest_power_of_2_less_than(n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    1 << (63 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_largest_power_of_2() {
        assert_eq!(largest_power_of_2_less_than(0), 0);
        assert_eq!(largest_power_of_2_less_than(1), 0);
        assert_eq!(largest_power_of_2_less_than(2), 1);
        assert_eq!(largest_power_of_2_less_than(3), 2);
        assert_eq!(largest_power_of_2_less_than(4), 2);
        assert_eq!(largest_power_of_2_less_than(5), 4);
        assert_eq!(largest_power_of_2_less_than(8), 4);
        assert_eq!(largest_power_of_2_less_than(9), 8);
        assert_eq!(largest_power_of_2_less_than(16), 8);
        assert_eq!(largest_power_of_2_less_than(17), 16);
    }
}
