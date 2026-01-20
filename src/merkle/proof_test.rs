//! Integration tests for consistency proof generation and verification.

use crate::merkle::tiles::HashTile;
use crate::storage::TileStorage;
use crate::types::{PartialSize, TileIndex, TileLevel};
use crate::witness::{verify_consistency, ConsistencyProof};
use sigstore_merkle::{hash_children, hash_leaf};
use sigstore_types::Sha256Hash;

/// Build a tree and return all leaf hashes and roots at each size.
fn build_test_tree(num_leaves: usize) -> (Vec<Sha256Hash>, Vec<Sha256Hash>) {
    let leaves: Vec<Sha256Hash> = (0..num_leaves).map(|i| hash_leaf(&[i as u8])).collect();

    let mut roots = Vec::new();
    for size in 1..=num_leaves {
        let root = compute_root(&leaves[..size]);
        roots.push(root);
    }

    (leaves, roots)
}

/// Compute the Merkle root for a set of leaves.
fn compute_root(leaves: &[Sha256Hash]) -> Sha256Hash {
    if leaves.is_empty() {
        return empty_root_hash();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Build using compact range algorithm
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
    for h in &range {
        if let Some(hash) = h {
            root = Some(match root {
                None => *hash,
                Some(r) => hash_children(hash, &r),
            });
        }
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

/// Create in-memory storage with leaf hashes.
async fn create_test_storage(leaves: &[Sha256Hash]) -> TileStorage {
    use opendal::services::Memory;
    use opendal::Operator;

    let op = Operator::new(Memory::default()).unwrap().finish();
    let storage = TileStorage::new(op);

    // Write all leaves to level 0 tile
    let tile = HashTile::with_nodes(leaves.to_vec());
    let partial = leaves.len().min(255) as u8;
    storage
        .write_tile(
            TileLevel::new(0),
            TileIndex::new(0),
            PartialSize::new(partial),
            &tile,
        )
        .await
        .unwrap();

    storage
}

/// Test that proof_length matches what we generate.
#[test]
fn test_expected_proof_lengths() {
    use crate::witness::ConsistencyProof;

    // Calculate expected proof length using the same algorithm as the verifier
    fn proof_length(old_size: u64, new_size: u64) -> usize {
        if old_size == 0 || old_size == new_size {
            return 0;
        }

        let mut fn_val = old_size - 1;
        let mut sn = new_size - 1;

        while fn_val & 1 == 1 {
            fn_val >>= 1;
            sn >>= 1;
        }

        let mut len = 0;
        while fn_val > 0 || sn > 0 {
            if fn_val & 1 == 1 || sn & 1 == 1 {
                len += 1;
            }
            fn_val >>= 1;
            sn >>= 1;
        }

        if !old_size.is_power_of_two() {
            len += 1;
        }

        len
    }

    // Print expected lengths for debugging
    for old in 1..=10u64 {
        for new in old..=10u64 {
            let expected = proof_length(old, new);
            println!("proof_length({}, {}) = {}", old, new, expected);
        }
    }
}

#[tokio::test]
async fn test_proof_generation_1_to_2() {
    let (leaves, roots) = build_test_tree(2);
    let storage = create_test_storage(&leaves).await;

    let old_size = 1;
    let new_size = 2;
    let old_root = roots[old_size as usize - 1];
    let new_root = roots[new_size as usize - 1];

    let proof_hashes = super::generate_consistency_proof_simple(&storage, old_size, new_size)
        .await
        .expect("proof generation failed");

    println!("Proof 1->2: {} hashes", proof_hashes.len());
    for (i, h) in proof_hashes.iter().enumerate() {
        println!("  proof[{}] = {:?}", i, hex::encode(h.as_bytes()));
    }

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    if let Err(e) = &result {
        println!("Verification failed: {}", e);
        println!("old_root = {:?}", hex::encode(old_root.as_bytes()));
        println!("new_root = {:?}", hex::encode(new_root.as_bytes()));
    }

    assert!(result.is_ok(), "Verification failed: {:?}", result);
}

#[tokio::test]
async fn test_proof_generation_1_to_3() {
    let (leaves, roots) = build_test_tree(3);
    let storage = create_test_storage(&leaves).await;

    let old_size = 1;
    let new_size = 3;
    let old_root = roots[old_size as usize - 1];
    let new_root = roots[new_size as usize - 1];

    let proof_hashes = super::generate_consistency_proof_simple(&storage, old_size, new_size)
        .await
        .expect("proof generation failed");

    println!("Proof 1->3: {} hashes", proof_hashes.len());
    for (i, h) in proof_hashes.iter().enumerate() {
        println!("  proof[{}] = {:?}", i, hex::encode(h.as_bytes()));
    }

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    if let Err(e) = &result {
        println!("Verification failed: {}", e);
    }

    assert!(result.is_ok(), "Verification failed for 1->3: {:?}", result);
}

#[tokio::test]
async fn test_proof_generation_2_to_3() {
    let (leaves, roots) = build_test_tree(3);
    let storage = create_test_storage(&leaves).await;

    let old_size = 2;
    let new_size = 3;
    let old_root = roots[old_size as usize - 1];
    let new_root = roots[new_size as usize - 1];

    let proof_hashes = super::generate_consistency_proof_simple(&storage, old_size, new_size)
        .await
        .expect("proof generation failed");

    println!("Proof 2->3: {} hashes", proof_hashes.len());

    let proof = ConsistencyProof::new(proof_hashes);
    let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

    assert!(result.is_ok(), "Verification failed for 2->3: {:?}", result);
}

#[tokio::test]
async fn test_proof_generation_all_combinations() {
    let max_size = 10;
    let (leaves, roots) = build_test_tree(max_size);

    let mut failures = Vec::new();

    for new_size in 1..=max_size as u64 {
        // Create storage with exactly new_size leaves (simulating the current state of the log)
        let storage = create_test_storage(&leaves[..new_size as usize]).await;

        for old_size in 1..=new_size {
            let old_root = roots[old_size as usize - 1];
            let new_root = roots[new_size as usize - 1];

            let proof_hashes = match super::generate_consistency_proof_simple(
                &storage, old_size, new_size,
            )
            .await
            {
                Ok(hashes) => hashes,
                Err(e) => {
                    failures.push((
                        old_size,
                        new_size,
                        0,
                        Some(format!("generation error: {}", e)),
                    ));
                    continue;
                }
            };

            let proof = ConsistencyProof::new(proof_hashes.clone());
            let result = verify_consistency(old_size, new_size, &old_root, &new_root, &proof);

            if result.is_err() {
                failures.push((
                    old_size,
                    new_size,
                    proof_hashes.len(),
                    Some(format!("{:?}", result.err())),
                ));
            }
        }
    }

    if !failures.is_empty() {
        println!("Failed cases:");
        for (old, new, len, err) in &failures {
            println!(
                "  {}->{}: generated {} hashes, error: {:?}",
                old, new, len, err
            );
        }
        panic!("{} verification(s) failed", failures.len());
    }
}
