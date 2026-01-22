"""
RFC 9162 Merkle tree implementation for witness conformance tests.

Uses the same conventions as sigsum/litewitness:
- Leaf hashes: raw 32-byte values (e.g., [42, N, 0, 0, ..., 0])
- Interior hashes: SHA256(0x01 + left + right)
"""

import base64
import hashlib
from typing import List


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
    """Compute the root hash for a tree of given size (base64 encoded)."""
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
