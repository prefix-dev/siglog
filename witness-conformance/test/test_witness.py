"""
Main conformance tests for witness implementations.

This test suite validates that a witness implementation conforms to
the C2SP tlog-witness specification.
"""

import base64
import pytest
from .client import WitnessClient, WitnessError
from .merkle import compute_root_hash, compute_consistency_proof


def make_fake_signature(key_id: bytes = b"\x00\x00\x00\x00") -> str:
    """
    Create a fake signature that is properly formatted but cryptographically invalid.

    Returns a base64-encoded string of 68 bytes (4 byte key_id + 64 byte signature).
    """
    # 4 bytes key_id + 64 bytes fake Ed25519 signature = 68 bytes total
    fake_sig = key_id + (b"\x00" * 64)
    return base64.b64encode(fake_sig).decode("ascii")


def bootstrap_witness(witness_client: WitnessClient, log_signer, target_size: int) -> None:
    """
    Bootstrap the witness from size 0 to target_size.

    This function sequentially submits checkpoints to bring the witness
    to the desired state. Each step uses valid proofs computed from
    the Merkle tree.

    Args:
        witness_client: The witness client to bootstrap
        log_signer: The log signer for generating signed checkpoints
        target_size: The target tree size (witness will be at this size after bootstrapping)
    """
    if target_size <= 0:
        return

    # Bootstrap step by step: 0->1, 1->2, ..., (target_size-1)->target_size
    for size in range(1, target_size + 1):
        old_size = size - 1
        new_size = size
        root_hash = compute_root_hash(new_size)
        proof = compute_consistency_proof(old_size, new_size)

        checkpoint = log_signer.sign_checkpoint(new_size, root_hash)
        response = witness_client.add_checkpoint(old_size, proof, checkpoint)

        if response["status_code"] != 200:
            raise WitnessError(
                f"Bootstrap failed at size {size}: status={response['status_code']}, "
                f"body={response['body']}"
            )


def test_witness_conformance(witness_client: WitnessClient, log_signer, test_case: dict):
    """
    Run a single conformance test case.

    Each test case is loaded from a JSON file in test/cases and contains:
    - name: Test case name
    - description: What the test validates
    - should_fail: Whether the operation should fail
    - old_size: Previous tree size
    - new_size: New tree size
    - proof: Consistency proof hashes
    - root_hash: New root hash
    - expected_status: Expected HTTP status code
    - checkpoint_valid: Whether checkpoint signature should be valid (optional)
    """
    name = test_case.get("name", "unknown")
    description = test_case.get("description", "")
    should_fail = test_case.get("should_fail", False)
    old_size = test_case["old_size"]
    new_size = test_case.get("new_size", old_size)
    proof = test_case.get("proof", [])
    root_hash = test_case.get("root_hash", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    expected_status = test_case.get("expected_status")
    checkpoint_valid = test_case.get("checkpoint_valid", True)

    # Bootstrap the witness to old_size (skip for bootstrap tests where old_size=0)
    if old_size > 0:
        bootstrap_witness(witness_client, log_signer, old_size)

    # Generate checkpoint
    if checkpoint_valid:
        checkpoint = log_signer.sign_checkpoint(new_size, root_hash)
    else:
        # Generate an invalid checkpoint (valid format but wrong signature)
        # Must include blank line between body and signature
        checkpoint = f"{log_signer.origin}\n{new_size}\n{root_hash}\n\n"
        checkpoint += f"— {log_signer.name} {make_fake_signature()}\n"

    # Submit checkpoint to witness
    response = witness_client.add_checkpoint(old_size, proof, checkpoint)

    # Validate response
    status_code = response["status_code"]
    body = response["body"]

    if should_fail:
        # Should get an error status code
        assert status_code >= 400, (
            f"Test '{name}' expected failure but got status {status_code}. "
            f"Description: {description}"
        )

        if expected_status is not None:
            assert status_code == expected_status, (
                f"Test '{name}' expected status {expected_status} but got {status_code}. "
                f"Response body: {body}"
            )
    else:
        # Should succeed
        assert status_code == 200, (
            f"Test '{name}' expected success but got status {status_code}. "
            f"Response body: {body}. Description: {description}"
        )

        # Response should be a signature line
        assert body.startswith("—"), (
            f"Test '{name}' expected signature line but got: {body}"
        )


def test_health_check(witness_client: WitnessClient):
    """Test that the health check endpoint works."""
    assert witness_client.health_check(), "Health check failed"


def test_sequential_checkpoints(witness_client: WitnessClient, log_signer):
    """
    Test a sequence of checkpoint submissions.

    This validates that the witness correctly maintains state across
    multiple checkpoint submissions.
    """
    # Checkpoint 1: Bootstrap at size 1
    root1 = compute_root_hash(1)
    checkpoint1 = log_signer.sign_checkpoint(1, root1)
    response1 = witness_client.add_checkpoint(0, [], checkpoint1)
    assert response1["status_code"] == 200, f"Bootstrap failed: {response1['body']}"

    # Checkpoint 2: Grow to size 3
    root3 = compute_root_hash(3)
    proof_1_to_3 = compute_consistency_proof(1, 3)
    checkpoint2 = log_signer.sign_checkpoint(3, root3)
    response2 = witness_client.add_checkpoint(1, proof_1_to_3, checkpoint2)
    assert response2["status_code"] == 200, f"Second checkpoint failed: {response2['body']}"

    # Checkpoint 3: Grow to size 5
    root5 = compute_root_hash(5)
    proof_3_to_5 = compute_consistency_proof(3, 5)
    checkpoint3 = log_signer.sign_checkpoint(5, root5)
    response3 = witness_client.add_checkpoint(3, proof_3_to_5, checkpoint3)
    assert response3["status_code"] == 200, f"Third checkpoint failed: {response3['body']}"


def test_conflict_detection(witness_client: WitnessClient, log_signer):
    """
    Test that the witness detects conflicts (old_size mismatch).

    When old_size doesn't match the witnessed size, the witness should
    return 409 Conflict with the actual witnessed size.
    """
    # Bootstrap at size 1
    root1 = compute_root_hash(1)
    checkpoint1 = log_signer.sign_checkpoint(1, root1)
    response1 = witness_client.add_checkpoint(0, [], checkpoint1)
    assert response1["status_code"] == 200

    # Try to submit with wrong old_size (0 instead of 1)
    # old_size must be <= new_size, so use 0 as the wrong old_size
    root5 = compute_root_hash(5)
    checkpoint2 = log_signer.sign_checkpoint(5, root5)
    response2 = witness_client.add_checkpoint(0, [], checkpoint2)

    # Should get 409 Conflict
    assert response2["status_code"] == 409, (
        f"Expected 409 Conflict but got {response2['status_code']}: {response2['body']}"
    )

    # Response should indicate the actual witnessed size
    # Content-Type should be text/x.tlog.size
    content_type = response2["headers"].get("Content-Type", response2["headers"].get("content-type", ""))
    assert "text/x.tlog.size" in content_type, (
        f"Expected Content-Type text/x.tlog.size but got {content_type}"
    )

    # Body should contain the actual size (1)
    assert "1" in response2["body"], (
        f"Expected body to contain actual size '1' but got: {response2['body']}"
    )


def test_invalid_signature(witness_client: WitnessClient, log_signer):
    """
    Test that the witness rejects checkpoints with invalid signatures.

    Should return 403 Forbidden.
    """
    # Create checkpoint with invalid signature (valid format but wrong signature)
    root1 = compute_root_hash(1)
    checkpoint = f"{log_signer.origin}\n1\n{root1}\n\n"
    checkpoint += f"— {log_signer.name} {make_fake_signature()}\n"

    response = witness_client.add_checkpoint(0, [], checkpoint)

    # Should get 403 Forbidden
    assert response["status_code"] == 403, (
        f"Expected 403 Forbidden but got {response['status_code']}: {response['body']}"
    )


def test_unknown_log(witness_client: WitnessClient, log_signer):
    """
    Test that the witness rejects checkpoints from unknown logs.

    Should return 403 Forbidden or 404 Not Found (implementation-dependent).
    """
    root1 = compute_root_hash(1)
    # Create checkpoint for a different log origin with valid signature format
    checkpoint = f"unknown.example.com/log\n1\n{root1}\n\n"
    checkpoint += f"— unknown.example.com/log {make_fake_signature()}\n"

    response = witness_client.add_checkpoint(0, [], checkpoint)

    # Should get 403 or 404 (rust-tessera returns 404, litewitness returns 403)
    assert response["status_code"] in (403, 404), (
        f"Expected 403 or 404 but got {response['status_code']}: {response['body']}"
    )


def test_malformed_request(witness_client: WitnessClient):
    """
    Test that the witness rejects malformed requests.

    Should return 400 Bad Request.
    """
    import requests

    # Submit completely invalid data
    try:
        response = requests.post(
            f"{witness_client.base_url}/add-checkpoint",
            data="invalid garbage data\nno proper format",
            headers={"Content-Type": "text/plain"},
            timeout=5.0,
        )

        # Should get 400 Bad Request
        assert response.status_code == 400, (
            f"Expected 400 Bad Request but got {response.status_code}: {response.text}"
        )
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Request failed: {e}")


def test_idempotent_checkpoint(witness_client: WitnessClient, log_signer):
    """
    Test that resubmitting the same checkpoint is idempotent.

    Submitting the same checkpoint twice with the same old_size and new_size
    should succeed both times.
    """
    # Bootstrap at size 1
    root1 = compute_root_hash(1)
    checkpoint1 = log_signer.sign_checkpoint(1, root1)
    response1 = witness_client.add_checkpoint(0, [], checkpoint1)
    assert response1["status_code"] == 200, f"First submission failed: {response1['body']}"

    # Submit same checkpoint again (old_size=1, new_size=1, same root)
    checkpoint2 = log_signer.sign_checkpoint(1, root1)
    response2 = witness_client.add_checkpoint(1, [], checkpoint2)
    assert response2["status_code"] == 200, f"Idempotent submission failed: {response2['body']}"


def test_proof_verification(witness_client: WitnessClient, log_signer):
    """
    Test that the witness correctly verifies consistency proofs.

    Submit checkpoints with valid proofs and verify they are accepted.
    """
    # Bootstrap at size 1
    root1 = compute_root_hash(1)
    checkpoint1 = log_signer.sign_checkpoint(1, root1)
    response1 = witness_client.add_checkpoint(0, [], checkpoint1)
    assert response1["status_code"] == 200

    # Grow to size 3 with valid proof
    root3 = compute_root_hash(3)
    proof_1_to_3 = compute_consistency_proof(1, 3)
    checkpoint2 = log_signer.sign_checkpoint(3, root3)
    response2 = witness_client.add_checkpoint(1, proof_1_to_3, checkpoint2)
    assert response2["status_code"] == 200, (
        f"Valid proof rejected: {response2['body']}"
    )


def test_invalid_proof_rejected(witness_client: WitnessClient, log_signer):
    """
    Test that the witness rejects invalid consistency proofs.

    Submit a checkpoint with a wrong proof and verify it is rejected.
    """
    # Bootstrap at size 1
    root1 = compute_root_hash(1)
    checkpoint1 = log_signer.sign_checkpoint(1, root1)
    response1 = witness_client.add_checkpoint(0, [], checkpoint1)
    assert response1["status_code"] == 200

    # Try to grow to size 3 with wrong proof (valid base64, wrong values)
    root3 = compute_root_hash(3)
    # Use valid 32-byte base64 hashes that will fail proof verification
    wrong_proof = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                   "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]
    checkpoint2 = log_signer.sign_checkpoint(3, root3)
    response2 = witness_client.add_checkpoint(1, wrong_proof, checkpoint2)

    # Should be rejected with 422 (proof verification failure)
    assert response2["status_code"] == 422, (
        f"Expected 422 for invalid proof but got {response2['status_code']}: {response2['body']}"
    )
