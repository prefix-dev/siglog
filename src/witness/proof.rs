//! Consistency proof verification for Merkle trees.
//!
//! Implements RFC 9162 §2.1.4.2 consistency proof verification.

use sigstore_merkle::hash_children;
use sigstore_types::Sha256Hash;
use thiserror::Error;

/// A consistency proof between two tree sizes.
#[derive(Debug, Clone, Default)]
pub struct ConsistencyProof {
    /// The proof hashes.
    hashes: Vec<Sha256Hash>,
}

impl ConsistencyProof {
    /// Create a new consistency proof from hashes.
    pub fn new(hashes: Vec<Sha256Hash>) -> Self {
        Self { hashes }
    }

    /// Get the proof hashes.
    pub fn hashes(&self) -> &[Sha256Hash] {
        &self.hashes
    }

    /// Check if the proof is empty.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Get the number of hashes in the proof.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }
}

/// Errors from consistency proof verification.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("old size ({old}) > new size ({new})")]
    InvalidSizes { old: u64, new: u64 },

    #[error("proof length mismatch: expected {expected}, got {actual}")]
    WrongLength { expected: usize, actual: usize },

    #[error("old root mismatch")]
    OldRootMismatch,

    #[error("new root mismatch")]
    NewRootMismatch,

    #[error("non-empty proof for trees of equal size")]
    NonEmptyProofForEqualSize,

    #[error("non-empty proof for empty old tree")]
    NonEmptyProofForEmptyOld,

    #[error("invalid root for empty tree")]
    InvalidEmptyRoot,
}

/// Verify a consistency proof between two tree sizes.
///
/// This implements RFC 9162 §2.1.4.2 (which is the same as RFC 6962 §2.1.4).
///
/// The proof demonstrates that the tree at `old_size` is a prefix of the tree
/// at `new_size` - i.e., the first `old_size` leaves are identical.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Sha256Hash,
    new_root: &Sha256Hash,
    proof: &ConsistencyProof,
) -> Result<(), ProofError> {
    // Handle edge cases
    if old_size > new_size {
        return Err(ProofError::InvalidSizes {
            old: old_size,
            new: new_size,
        });
    }

    if old_size == new_size {
        if !proof.is_empty() {
            return Err(ProofError::NonEmptyProofForEqualSize);
        }
        if old_root != new_root {
            return Err(ProofError::OldRootMismatch);
        }
        return Ok(());
    }

    if old_size == 0 {
        if !proof.is_empty() {
            return Err(ProofError::NonEmptyProofForEmptyOld);
        }
        // Verify old_root is the empty tree hash
        if old_root != &empty_root_hash() {
            return Err(ProofError::InvalidEmptyRoot);
        }
        return Ok(());
    }

    // Calculate expected proof length
    let expected_len = proof_length(old_size, new_size);
    if proof.len() != expected_len {
        return Err(ProofError::WrongLength {
            expected: expected_len,
            actual: proof.len(),
        });
    }

    // Run the verification algorithm
    verify_consistency_inner(old_size, new_size, old_root, new_root, proof.hashes())
}

/// Inner verification logic implementing RFC 9162 algorithm.
///
/// This uses a recursive approach that mirrors SUBPROOF generation.
fn verify_consistency_inner(
    old_size: u64,
    new_size: u64,
    old_root: &Sha256Hash,
    new_root: &Sha256Hash,
    proof: &[Sha256Hash],
) -> Result<(), ProofError> {
    if old_size == new_size {
        if proof.is_empty() && old_root == new_root {
            return Ok(());
        }
        return Err(ProofError::OldRootMismatch);
    }

    // For power-of-2 old_size, use simpler path-based verification
    if old_size.is_power_of_two() {
        return verify_power_of_2(old_size, new_size, old_root, new_root, proof);
    }

    // For non-power-of-2 old_size, use recursive verification matching SUBPROOF
    let mut idx = 0;
    let (computed_old, computed_new) = verify_subproof(old_size, new_size, proof, &mut idx, true)?;

    if idx != proof.len() {
        return Err(ProofError::WrongLength {
            expected: idx,
            actual: proof.len(),
        });
    }

    if &computed_old != old_root {
        return Err(ProofError::OldRootMismatch);
    }
    if &computed_new != new_root {
        return Err(ProofError::NewRootMismatch);
    }

    Ok(())
}

/// Verify consistency proof for power-of-2 old_size.
fn verify_power_of_2(
    old_size: u64,
    new_size: u64,
    old_root: &Sha256Hash,
    new_root: &Sha256Hash,
    proof: &[Sha256Hash],
) -> Result<(), ProofError> {
    // For power-of-2 old_size, walk from old_root to new_root via siblings
    let mut sr = *old_root;
    let _old_level = old_size.trailing_zeros();

    // Walk up the tree, combining with siblings
    let mut size = old_size;
    let mut proof_idx = 0;

    while size < new_size {
        if proof_idx >= proof.len() {
            return Err(ProofError::WrongLength {
                expected: proof_idx + 1,
                actual: proof.len(),
            });
        }

        let sibling = &proof[proof_idx];
        proof_idx += 1;

        // Sibling is always on the right (we start from leftmost subtree)
        sr = hash_children(&sr, sibling);
        size *= 2;

        // If new_size < size, we've overshot - need to adjust
        // This happens for non-power-of-2 new_size
        if size > new_size {
            break;
        }
    }

    // Handle any remaining proof elements for non-power-of-2 new_size
    // The tree structure for non-power-of-2 needs special handling
    while proof_idx < proof.len() {
        let sibling = &proof[proof_idx];
        proof_idx += 1;
        sr = hash_children(&sr, sibling);
    }

    if &sr != new_root {
        return Err(ProofError::NewRootMismatch);
    }

    Ok(())
}

/// Recursive verification matching SUBPROOF generation.
/// Returns (old_tree_hash, new_tree_hash).
///
/// The proof elements are consumed in the same order as generated:
/// - For m <= k: recurse first (inner elements), then right hash
/// - For m > k: recurse first (inner elements), then left hash
fn verify_subproof(
    m: u64,
    n: u64,
    proof: &[Sha256Hash],
    idx: &mut usize,
    complete: bool,
) -> Result<(Sha256Hash, Sha256Hash), ProofError> {
    if m == n {
        if complete {
            // complete=true means we don't have proof element for this
            // We can't compute the hash without more context
            // This case shouldn't happen in practice for verification
            return Err(ProofError::WrongLength {
                expected: *idx + 1,
                actual: proof.len(),
            });
        }
        // Get the subtree hash from proof
        if *idx >= proof.len() {
            return Err(ProofError::WrongLength {
                expected: *idx + 1,
                actual: proof.len(),
            });
        }
        let hash = proof[*idx];
        *idx += 1;
        return Ok((hash, hash));
    }

    let k = largest_power_of_2_less_than(n);

    if m <= k {
        // Recurse into left subtree FIRST (matching generation order)
        let (left_old, left_new) = verify_subproof(m, k, proof, idx, complete)?;

        // THEN get right subtree hash from proof
        if *idx >= proof.len() {
            return Err(ProofError::WrongLength {
                expected: *idx + 1,
                actual: proof.len(),
            });
        }
        let right = proof[*idx];
        *idx += 1;

        let new_hash = hash_children(&left_new, &right);
        Ok((left_old, new_hash))
    } else {
        // Recurse into right subtree FIRST (matching generation order)
        let (right_old, right_new) = verify_subproof(m - k, n - k, proof, idx, false)?;

        // THEN get left subtree hash from proof
        if *idx >= proof.len() {
            return Err(ProofError::WrongLength {
                expected: *idx + 1,
                actual: proof.len(),
            });
        }
        let left = proof[*idx];
        *idx += 1;

        let old_hash = hash_children(&left, &right_old);
        let new_hash = hash_children(&left, &right_new);
        Ok((old_hash, new_hash))
    }
}

/// Calculate the expected proof length for a consistency proof.
///
/// For power-of-2 old_size: proof_length = tree_height(new_size) - log2(old_size)
/// For non-power-of-2: we use the RFC SUBPROOF recursion pattern
fn proof_length(old_size: u64, new_size: u64) -> usize {
    if old_size == 0 || old_size == new_size {
        return 0;
    }

    if old_size.is_power_of_two() {
        // For power-of-2 old_size, count siblings from old_size level to new root
        let old_level = old_size.trailing_zeros() as usize;
        let tree_height = if new_size.is_power_of_two() {
            new_size.trailing_zeros() as usize
        } else {
            (64 - (new_size - 1).leading_zeros()) as usize
        };
        return tree_height - old_level;
    }

    // For non-power-of-2 old_size, use RFC SUBPROOF counting
    subproof_length(old_size, new_size, true)
}

/// Count proof elements for RFC SUBPROOF algorithm.
fn subproof_length(m: u64, n: u64, complete: bool) -> usize {
    if m == n {
        return if complete { 0 } else { 1 };
    }

    let k = largest_power_of_2_less_than(n);

    if m <= k {
        // SUBPROOF(m, D[0:k], complete) + 1 for right hash
        subproof_length(m, k, complete) + 1
    } else {
        // 1 for left hash + SUBPROOF(m-k, D[k:n], false)
        1 + subproof_length(m - k, n - k, false)
    }
}

/// Largest power of 2 less than n.
fn largest_power_of_2_less_than(n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    1 << (63 - (n - 1).leading_zeros())
}

/// RFC 6962 empty tree root hash.
fn empty_root_hash() -> Sha256Hash {
    Sha256Hash::from_bytes([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_merkle::hash_leaf;

    /// Build a complete tree and return the root hash.
    #[allow(dead_code)]
    fn build_tree(leaves: &[Sha256Hash]) -> Sha256Hash {
        if leaves.is_empty() {
            return empty_root_hash();
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        // Build compact range
        let mut range: Vec<Option<Sha256Hash>> = Vec::new();

        for (i, &leaf) in leaves.iter().enumerate() {
            let mut hash = leaf;
            let mut idx = i as u64;
            let mut level = 0usize;

            while idx & 1 == 1 {
                if let Some(Some(left)) = range.get(level) {
                    hash = hash_children(left, &hash);
                    range[level] = None;
                    level += 1;
                    idx >>= 1;
                } else {
                    break;
                }
            }

            while range.len() <= level {
                range.push(None);
            }
            range[level] = Some(hash);
        }

        // Compute root from range
        let mut root: Option<Sha256Hash> = None;
        for hash in range.iter().flatten() {
            root = Some(match root {
                None => *hash,
                Some(r) => hash_children(hash, &r),
            });
        }
        root.unwrap_or_else(empty_root_hash)
    }

    #[test]
    fn test_empty_to_empty() {
        let empty = empty_root_hash();
        let proof = ConsistencyProof::new(vec![]);
        assert!(verify_consistency(0, 0, &empty, &empty, &proof).is_ok());
    }

    #[test]
    fn test_same_size() {
        let leaf = hash_leaf(&[1u8]);
        let proof = ConsistencyProof::new(vec![]);
        assert!(verify_consistency(1, 1, &leaf, &leaf, &proof).is_ok());
    }

    #[test]
    fn test_same_size_different_roots() {
        let leaf1 = hash_leaf(&[1u8]);
        let leaf2 = hash_leaf(&[2u8]);
        let proof = ConsistencyProof::new(vec![]);
        assert!(matches!(
            verify_consistency(1, 1, &leaf1, &leaf2, &proof),
            Err(ProofError::OldRootMismatch)
        ));
    }

    #[test]
    fn test_old_greater_than_new() {
        let leaf = hash_leaf(&[1u8]);
        let proof = ConsistencyProof::new(vec![]);
        assert!(matches!(
            verify_consistency(2, 1, &leaf, &leaf, &proof),
            Err(ProofError::InvalidSizes { .. })
        ));
    }

    #[test]
    fn test_proof_length() {
        // Basic edge cases
        assert_eq!(proof_length(0, 0), 0);
        assert_eq!(proof_length(0, 1), 0);
        assert_eq!(proof_length(1, 1), 0);
        assert_eq!(proof_length(2, 2), 0);

        // Power-of-2 old sizes need fewer proof elements
        assert_eq!(proof_length(1, 2), 1);
        assert_eq!(proof_length(2, 4), 1);
        assert_eq!(proof_length(4, 8), 1);

        // Non-power-of-2 old sizes need the extra element for the subtree
        // The actual length depends on the bit structure
        assert!(proof_length(3, 4) > 0);
        assert!(proof_length(1, 4) > 0);
    }
}
