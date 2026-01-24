//! Tests using litewitness test vectors from torchwood.
//!
//! These test vectors come from:
//! https://github.com/FiloSottile/litetlog/blob/main/cmd/litewitness/testdata/litewitness.txt

use super::proof::{verify_consistency, ConsistencyProof};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sigstore_merkle::hash_children;
use sigstore_types::Sha256Hash;

/// Leaf hashes from the litewitness test vectors.
/// These are simple hashes: {0x2a, index, 0, 0, ...}
fn litewitness_leaf_hash(index: u8) -> Sha256Hash {
    let mut hash = [0u8; 32];
    hash[0] = 0x2a; // 42 in decimal
    hash[1] = index;
    Sha256Hash::from_bytes(hash)
}

/// Compute the Merkle root for the litewitness test tree at a given size.
fn compute_litewitness_root(size: usize) -> Sha256Hash {
    if size == 0 {
        return empty_root_hash();
    }

    let leaves: Vec<Sha256Hash> = (0..size).map(|i| litewitness_leaf_hash(i as u8)).collect();

    compute_root(&leaves)
}

/// Compute root from leaves using compact range algorithm.
fn compute_root(leaves: &[Sha256Hash]) -> Sha256Hash {
    if leaves.is_empty() {
        return empty_root_hash();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

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

    let mut root: Option<Sha256Hash> = None;
    for hash in range.iter().flatten() {
        root = Some(match root {
            None => *hash,
            Some(r) => hash_children(hash, &r),
        });
    }
    root.unwrap_or_else(empty_root_hash)
}

fn empty_root_hash() -> Sha256Hash {
    Sha256Hash::from_bytes([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ])
}

fn decode_hash(base64_str: &str) -> Sha256Hash {
    let bytes = BASE64.decode(base64_str).expect("invalid base64");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Sha256Hash::from_bytes(arr)
}

#[test]
fn test_litewitness_tree_roots() {
    // Verify we compute the same roots as the test vectors

    // Size 1: root = leaf[0] = 0x2a00...
    let root1 = compute_litewitness_root(1);
    let expected1 = decode_hash("KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    assert_eq!(root1, expected1, "Root at size 1 mismatch");

    // Size 3
    let root3 = compute_litewitness_root(3);
    let expected3 = decode_hash("RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=");
    assert_eq!(root3, expected3, "Root at size 3 mismatch");

    // Size 5
    let root5 = compute_litewitness_root(5);
    let expected5 = decode_hash("QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=");
    assert_eq!(root5, expected5, "Root at size 5 mismatch");
}

#[test]
fn test_litewitness_consistency_1_to_3() {
    // Proof from size 1 to size 3
    // proof = [leaf[1], leaf[2]]
    let old_size = 1u64;
    let new_size = 3u64;
    let old_root = compute_litewitness_root(1);
    let new_root = compute_litewitness_root(3);

    let proof_hashes = vec![
        decode_hash("KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), // leaf[1]
        decode_hash("KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), // leaf[2]
    ];

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(
        result.is_ok(),
        "Consistency proof 1->3 failed: {:?}",
        result
    );
}

#[test]
fn test_litewitness_consistency_1_to_5() {
    // Proof from size 1 to size 5
    let old_size = 1u64;
    let new_size = 5u64;
    let old_root = compute_litewitness_root(1);
    let new_root = compute_litewitness_root(5);

    let proof_hashes = vec![
        decode_hash("KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        decode_hash("+fUDV+k970B4I3uKrqJM4aP1lloPZP8mvr2Z4wRw2LI="),
        decode_hash("KgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    ];

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(
        result.is_ok(),
        "Consistency proof 1->5 failed: {:?}",
        result
    );
}

#[test]
fn test_litewitness_consistency_3_to_5() {
    // Proof from size 3 to size 5
    let old_size = 3u64;
    let new_size = 5u64;
    let old_root = compute_litewitness_root(3);
    let new_root = compute_litewitness_root(5);

    let proof_hashes = vec![
        decode_hash("KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        decode_hash("KgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        decode_hash("wgiIFdZfYNv6WU1OllBKsWnLYIS/DBMqt8Uh/S4OukE="),
        decode_hash("KgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
    ];

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(
        result.is_ok(),
        "Consistency proof 3->5 failed: {:?}",
        result
    );
}

#[test]
fn test_litewitness_consistency_0_to_1() {
    // Proof from empty tree (size 0) to size 1
    // Empty proof is valid when old_size is 0
    let old_size = 0u64;
    let new_size = 1u64;
    let old_root = empty_root_hash();
    let new_root = compute_litewitness_root(1);

    let proof = ConsistencyProof::new(vec![]);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(
        result.is_ok(),
        "Consistency proof 0->1 failed: {:?}",
        result
    );
}

#[test]
fn test_litewitness_bad_proof_hash() {
    // Same as 1->3 but with corrupted proof hash
    let old_size = 1u64;
    let new_size = 3u64;
    let old_root = compute_litewitness_root(1);
    let new_root = compute_litewitness_root(3);

    // Second hash has wrong last byte (0x10 instead of 0x00)
    let proof_hashes = vec![
        decode_hash("KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        decode_hash("KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA="), // corrupted
    ];

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(result.is_err(), "Corrupted proof should fail verification");
}

#[test]
fn test_litewitness_missing_proof() {
    // 1->3 with empty proof should fail
    let old_size = 1u64;
    let new_size = 3u64;
    let old_root = compute_litewitness_root(1);
    let new_root = compute_litewitness_root(3);

    let proof = ConsistencyProof::new(vec![]);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(result.is_err(), "Missing proof should fail verification");
}

#[test]
fn test_litewitness_same_size() {
    // Proof from size 3 to size 3 (empty proof, roots must match)
    let size = 3u64;
    let root = compute_litewitness_root(3);

    let proof = ConsistencyProof::new(vec![]);
    let result = verify_consistency(size, size, &root, &root, &proof);

    assert!(result.is_ok(), "Same size proof failed: {:?}", result);
}

#[test]
fn test_litewitness_same_size_different_roots() {
    // Same size but different roots should fail
    let size = 3u64;
    let root1 = compute_litewitness_root(3);
    let root2 = compute_litewitness_root(5);

    let proof = ConsistencyProof::new(vec![]);
    let result = verify_consistency(size, size, &root1, &root2, &proof);

    assert!(
        result.is_err(),
        "Same size with different roots should fail"
    );
}
