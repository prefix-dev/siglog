#!/usr/bin/env python3
"""
Generate conformance test cases for witness implementations.

This script creates a comprehensive set of test cases covering:
- Happy path scenarios
- Error conditions
- Edge cases
- Consistency proof validation

Uses the same Merkle tree conventions as litewitness:
- Leaf hashes: raw 32-byte values (e.g., [42, N, 0, 0, ..., 0])
- Interior hashes: SHA256(0x01 + left + right)
"""

import json
import base64
import hashlib
from pathlib import Path
from typing import List, Optional


class MerkleTree:
    """
    RFC 9162 Merkle tree implementation.

    Uses the same conventions as sigsum/litewitness:
    - Leaf hashes are raw 32-byte values added directly
    - Interior nodes: SHA256(0x01 + left + right)
    """

    def __init__(self):
        self.leaves: List[bytes] = []

    def add_leaf_hash(self, leaf_hash: bytes) -> None:
        """Add a pre-computed leaf hash to the tree."""
        assert len(leaf_hash) == 32, f"Leaf hash must be 32 bytes, got {len(leaf_hash)}"
        self.leaves.append(leaf_hash)

    def size(self) -> int:
        """Return the number of leaves in the tree."""
        return len(self.leaves)

    def get_root_hash(self) -> bytes:
        """Compute the root hash of the tree."""
        if not self.leaves:
            # Empty tree root per RFC 6962
            return hashlib.sha256(b"").digest()
        return self._compute_subtree_hash(0, len(self.leaves))

    def _compute_subtree_hash(self, start: int, end: int) -> bytes:
        """Compute hash of subtree from start to end (exclusive)."""
        count = end - start
        if count == 0:
            raise ValueError("Empty subtree")
        if count == 1:
            return self.leaves[start]

        # Split at largest power of 2 less than count
        k = largest_power_of_2_less_than(count)
        left = self._compute_subtree_hash(start, start + k)
        right = self._compute_subtree_hash(start + k, end)
        return hash_children(left, right)

    def prove_consistency(self, old_size: int) -> List[bytes]:
        """
        Generate consistency proof from old_size to current size.

        Follows RFC 9162 Section 2.1.4.2 SUBPROOF algorithm.
        """
        new_size = len(self.leaves)

        if old_size == 0 or old_size == new_size:
            return []

        if old_size > new_size:
            raise ValueError(f"old_size ({old_size}) > new_size ({new_size})")

        if is_power_of_two(old_size):
            # For power-of-2 old_size, use simpler path-based proof
            return self._path_siblings(old_size, new_size)
        else:
            # For non-power-of-2, use full SUBPROOF algorithm
            proof = []
            self._subproof(old_size, new_size, 0, True, proof)
            return proof

    def _path_siblings(self, old_size: int, new_size: int) -> List[bytes]:
        """
        Generate proof for power-of-2 old_size.

        The proof consists of siblings along the path from the old tree
        (which is a complete subtree) to the new root.
        """
        siblings = []
        level = old_size.bit_length() - 1  # log2(old_size) for power of 2
        path_idx = 0  # Index within current level

        # Walk up from the old tree's root to the new tree's root
        subtree_size = old_size
        while subtree_size < new_size:
            sibling_idx = path_idx ^ 1  # XOR to get sibling
            sibling_start = sibling_idx * subtree_size

            if sibling_start < new_size:
                sibling_end = min(sibling_start + subtree_size, new_size)
                sibling_hash = self._compute_subtree_hash(sibling_start, sibling_end)
                siblings.append(sibling_hash)

            subtree_size *= 2
            path_idx >>= 1

        return siblings

    def _subproof(self, m: int, n: int, base: int, complete: bool,
                  proof: List[bytes]) -> bytes:
        """
        RFC 9162 SUBPROOF algorithm.

        Returns the hash of the subtree and adds necessary hashes to proof.
        """
        if m == n:
            subtree_hash = self._compute_subtree_hash(base, base + m)
            if not complete:
                proof.append(subtree_hash)
            return subtree_hash

        k = largest_power_of_2_less_than(n)

        if m <= k:
            # Old tree is entirely in left subtree
            left_hash = self._subproof(m, k, base, complete, proof)
            right_hash = self._compute_subtree_hash(base + k, base + n)
            proof.append(right_hash)
            return hash_children(left_hash, right_hash)
        else:
            # Old tree spans both subtrees
            left_hash = self._compute_subtree_hash(base, base + k)
            right_hash = self._subproof(m - k, n - k, base + k, False, proof)
            proof.append(left_hash)
            return hash_children(left_hash, right_hash)


def hash_children(left: bytes, right: bytes) -> bytes:
    """Compute interior node hash: SHA256(0x01 + left + right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_power_of_2_less_than(n: int) -> int:
    """Return the largest power of 2 that is strictly less than n."""
    if n <= 1:
        return 0
    # Use (n-1).bit_length() to get floor(log2(n-1)) + 1
    # Then shift by one less to get largest power of 2 < n
    return 1 << ((n - 1).bit_length() - 1)


def is_power_of_two(n: int) -> bool:
    """Check if n is a power of 2."""
    return n > 0 and (n & (n - 1)) == 0


def make_leaf_hash(index: int) -> bytes:
    """
    Create a leaf hash for testing.

    Uses the same convention as litewitness tests:
    [42, index, 0, 0, ..., 0] (32 bytes)
    """
    data = bytearray(32)
    data[0] = 42
    data[1] = index & 0xFF  # Only use lowest byte for simplicity
    return bytes(data)


def to_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("ascii")


def build_tree(size: int) -> MerkleTree:
    """Build a MerkleTree with the given number of leaves."""
    tree = MerkleTree()
    for i in range(size):
        tree.add_leaf_hash(make_leaf_hash(i))
    return tree


def compute_root_hash(size: int) -> str:
    """Compute the root hash for a tree of given size."""
    if size == 0:
        # Empty tree root per RFC 6962
        return to_base64(hashlib.sha256(b"").digest())
    tree = build_tree(size)
    return to_base64(tree.get_root_hash())


def compute_consistency_proof(old_size: int, new_size: int) -> List[str]:
    """
    Compute consistency proof from old_size to new_size.

    Returns list of base64-encoded 32-byte hashes.
    """
    if old_size == 0 or old_size == new_size:
        return []

    if old_size > new_size:
        raise ValueError(f"old_size ({old_size}) > new_size ({new_size})")

    tree = build_tree(new_size)
    proof = tree.prove_consistency(old_size)
    return [to_base64(h) for h in proof]


def generate_test_cases() -> List[dict]:
    """Generate all test cases."""
    cases = []

    # ========== HAPPY PATH CASES ==========

    cases.append({
        "name": "bootstrap_size_1",
        "description": "Bootstrap witness with first checkpoint at size 1",
        "should_fail": False,
        "old_size": 0,
        "new_size": 1,
        "proof": [],
        "root_hash": compute_root_hash(1),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_1_to_2",
        "description": "Growth from size 1 to 2 (power of 2 boundary)",
        "should_fail": False,
        "old_size": 1,
        "new_size": 2,
        "proof": compute_consistency_proof(1, 2),
        "root_hash": compute_root_hash(2),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_1_to_3",
        "description": "Valid checkpoint update from size 1 to 3",
        "should_fail": False,
        "old_size": 1,
        "new_size": 3,
        "proof": compute_consistency_proof(1, 3),
        "root_hash": compute_root_hash(3),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_2_to_3",
        "description": "Growth from power-of-2 to non-power-of-2",
        "should_fail": False,
        "old_size": 2,
        "new_size": 3,
        "proof": compute_consistency_proof(2, 3),
        "root_hash": compute_root_hash(3),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_3_to_5",
        "description": "Valid checkpoint update from size 3 to 5",
        "should_fail": False,
        "old_size": 3,
        "new_size": 5,
        "proof": compute_consistency_proof(3, 5),
        "root_hash": compute_root_hash(5),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_1_to_5",
        "description": "Growth spanning multiple levels (1 to 5)",
        "should_fail": False,
        "old_size": 1,
        "new_size": 5,
        "proof": compute_consistency_proof(1, 5),
        "root_hash": compute_root_hash(5),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_4_to_8",
        "description": "Growth between powers of 2",
        "should_fail": False,
        "old_size": 4,
        "new_size": 8,
        "proof": compute_consistency_proof(4, 8),
        "root_hash": compute_root_hash(8),
        "expected_status": 200,
    })

    cases.append({
        "name": "growth_7_to_15",
        "description": "Growth from non-power-of-2 to non-power-of-2",
        "should_fail": False,
        "old_size": 7,
        "new_size": 15,
        "proof": compute_consistency_proof(7, 15),
        "root_hash": compute_root_hash(15),
        "expected_status": 200,
    })

    cases.append({
        "name": "same_size_same_root",
        "description": "Resubmit same checkpoint (idempotent)",
        "should_fail": False,
        "old_size": 5,
        "new_size": 5,
        "proof": [],
        "root_hash": compute_root_hash(5),
        "expected_status": 200,
    })

    # ========== SIGNATURE ERROR CASES (403 Forbidden) ==========

    cases.append({
        "name": "invalid_signature_fail",
        "description": "Checkpoint with invalid signature should fail",
        "should_fail": True,
        "old_size": 0,
        "new_size": 1,
        "proof": [],
        "root_hash": compute_root_hash(1),
        "expected_status": 403,
        "checkpoint_valid": False,
    })

    # ========== CONSISTENCY PROOF ERROR CASES (422 Unprocessable Entity) ==========

    cases.append({
        "name": "missing_proof_fail",
        "description": "Missing consistency proof when required",
        "should_fail": True,
        "old_size": 1,
        "new_size": 5,
        "proof": [],  # Should have proof
        "root_hash": compute_root_hash(5),
        "expected_status": 422,
    })

    # Generate a valid-looking but wrong proof (correct length, wrong hashes)
    wrong_proof = [to_base64(hashlib.sha256(f"wrong_{i}".encode()).digest())
                   for i in range(len(compute_consistency_proof(1, 3)))]
    cases.append({
        "name": "wrong_proof_hashes_fail",
        "description": "Consistency proof with wrong hash values",
        "should_fail": True,
        "old_size": 1,
        "new_size": 3,
        "proof": wrong_proof,
        "root_hash": compute_root_hash(3),
        "expected_status": 422,
    })

    cases.append({
        "name": "wrong_proof_length_fail",
        "description": "Consistency proof with wrong number of hashes",
        "should_fail": True,
        "old_size": 1,
        "new_size": 3,
        "proof": [to_base64(make_leaf_hash(0))],  # Wrong number of proof nodes
        "root_hash": compute_root_hash(3),
        "expected_status": 422,
    })

    # Note: rust-tessera accepts non-empty proofs for same size (ignores them)
    # This is lenient behavior, not a strict requirement
    # cases.append({
    #     "name": "proof_for_same_size_fail",
    #     "description": "Non-empty proof when old_size == new_size",
    #     "should_fail": True,
    #     "old_size": 3,
    #     "new_size": 3,
    #     "proof": [to_base64(make_leaf_hash(0))],  # Should be empty
    #     "root_hash": compute_root_hash(3),
    #     "expected_status": 422,
    # })

    # Note: Both rust-tessera and litewitness accept non-empty proofs for bootstrap
    # This is lenient behavior - they just ignore the extra proof hashes
    # cases.append({
    #     "name": "proof_for_bootstrap_fail",
    #     "description": "Non-empty proof when bootstrapping (old_size=0)",
    #     "should_fail": True,
    #     "old_size": 0,
    #     "new_size": 1,
    #     "proof": [to_base64(make_leaf_hash(0))],  # Should be empty
    #     "root_hash": compute_root_hash(1),
    #     "expected_status": 422,
    # })

    # ========== SIZE VALIDATION CASES (422 or 400) ==========

    cases.append({
        "name": "old_size_greater_than_new_fail",
        "description": "old_size > new_size is invalid",
        "should_fail": True,
        "old_size": 10,
        "new_size": 5,
        "proof": [],
        "root_hash": compute_root_hash(5),
        "expected_status": 400,  # rust-tessera returns 400 for this
    })

    cases.append({
        "name": "same_size_different_root_fail",
        "description": "Same size but different root indicates split-view attack",
        "should_fail": True,
        "old_size": 3,
        "new_size": 3,
        "proof": [],
        "root_hash": to_base64(hashlib.sha256(b"wrong_root").digest()),
        "expected_status": 422,
    })

    # ========== EDGE CASES ==========

    cases.append({
        "name": "power_of_2_boundaries",
        "description": "Growth across power-of-2 boundaries",
        "should_fail": False,
        "old_size": 15,
        "new_size": 17,
        "proof": compute_consistency_proof(15, 17),
        "root_hash": compute_root_hash(17),
        "expected_status": 200,
    })

    cases.append({
        "name": "single_entry_growth",
        "description": "Minimal growth (add one entry)",
        "should_fail": False,
        "old_size": 10,
        "new_size": 11,
        "proof": compute_consistency_proof(10, 11),
        "root_hash": compute_root_hash(11),
        "expected_status": 200,
    })

    # ========== MALFORMED REQUEST CASES (400 Bad Request) ==========

    cases.append({
        "name": "invalid_base64_proof_fail",
        "description": "Proof with invalid base64 encoding",
        "should_fail": True,
        "old_size": 1,
        "new_size": 3,
        "proof": ["not!!!valid!!!base64"],
        "root_hash": compute_root_hash(3),
        "expected_status": 400,
    })

    cases.append({
        "name": "empty_checkpoint_fail",
        "description": "Empty checkpoint text",
        "should_fail": True,
        "old_size": 0,
        "new_size": 0,
        "proof": [],
        "root_hash": "",
        # Note: rust-tessera returns 400, litewitness returns 500
        # Both indicate failure, so we don't specify expected_status
    })

    return cases


def main():
    """Generate all test cases and write to JSON files."""
    output_dir = Path(__file__).parent / "test" / "cases"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating test cases in {output_dir}...")

    # Print some debug info about computed values
    print("\nDebug - Tree structure verification:")
    for size in [1, 2, 3, 5]:
        root = compute_root_hash(size)
        print(f"  Size {size}: root = {root}")

    print("\nDebug - Consistency proof verification:")
    for (old, new) in [(1, 2), (1, 3), (1, 5), (3, 5)]:
        proof = compute_consistency_proof(old, new)
        print(f"  {old}->{new}: proof = {proof}")

    cases = generate_test_cases()

    # Remove old test cases first
    for old_file in output_dir.glob("*.json"):
        old_file.unlink()

    for case in cases:
        filename = f"{case['name']}.json"
        filepath = output_dir / filename

        with open(filepath, "w") as f:
            json.dump(case, f, indent=2)

        status = "FAIL" if case["should_fail"] else "PASS"
        print(f"  [{status}] {filename}: {case['description']}")

    print(f"\nGenerated {len(cases)} test cases.")
    print(f"Success cases: {sum(1 for c in cases if not c['should_fail'])}")
    print(f"Failure cases: {sum(1 for c in cases if c['should_fail'])}")


if __name__ == "__main__":
    main()
