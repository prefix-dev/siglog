"""
Pytest configuration and fixtures for witness conformance tests.
"""

import json
import pytest
import tempfile
from pathlib import Path
from typing import Iterator

from .client import WitnessClient


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--entrypoint",
        action="store",
        required=True,
        help="Path to the witness binary to test",
    )
    parser.addoption(
        "--port",
        action="store",
        type=int,
        default=2026,
        help="Port for the witness server (default: 2026)",
    )
    parser.addoption(
        "--private-key",
        action="store",
        help="Witness private key in Note format (optional, will generate if not provided)",
    )
    parser.addoption(
        "--log-config",
        action="store",
        help="Log configuration in format 'origin=vkey' (optional)",
    )


def pytest_generate_tests(metafunc):
    """
    Dynamically generate test cases from JSON files.

    This hook discovers all JSON files in the test/cases directory and
    parametrizes tests that use the 'test_case' fixture.
    """
    if "test_case" in metafunc.fixturenames:
        cases_dir = Path(__file__).parent / "cases"
        test_cases = []
        test_ids = []

        # Discover all JSON files
        for json_file in sorted(cases_dir.glob("*.json")):
            try:
                with open(json_file, "r") as f:
                    case_data = json.load(f)
                    test_cases.append(case_data)
                    test_ids.append(json_file.stem)
            except Exception as e:
                pytest.fail(f"Failed to load test case {json_file}: {e}")

        if not test_cases:
            pytest.skip("No test cases found in test/cases directory")

        metafunc.parametrize("test_case", test_cases, ids=test_ids)


@pytest.fixture(scope="session")
def entrypoint(request) -> str:
    """Get the witness binary path from command line."""
    return request.config.getoption("--entrypoint")


@pytest.fixture(scope="session")
def port(request) -> int:
    """Get the witness port from command line."""
    return request.config.getoption("--port")


@pytest.fixture(scope="session")
def private_key(request) -> str:
    """Get or generate a witness private key."""
    key = request.config.getoption("--private-key")
    if key:
        return key

    # Generate a test key using cryptography library
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import base64
    import hashlib

    private_key_obj = ed25519.Ed25519PrivateKey.generate()
    seed = private_key_obj.private_bytes_raw()
    pubkey = private_key_obj.public_key().public_bytes_raw()

    # Build Note format key
    # Format: PRIVATE+KEY+{name}+{hash}+{base64(0x01 + seed)}
    name = "witness-conformance-test"

    # Compute hash (first 4 bytes of SHA256(name + "\n" + alg + pubkey))
    alg_and_pubkey = b"\x01" + pubkey
    hash_input = name.encode() + b"\n" + alg_and_pubkey
    hash_bytes = hashlib.sha256(hash_input).digest()[:4]
    hash_hex = hash_bytes.hex()

    alg_and_seed = b"\x01" + seed
    encoded = base64.b64encode(alg_and_seed).decode("ascii")

    return f"PRIVATE+KEY+{name}+{hash_hex}+{encoded}"


@pytest.fixture(scope="session")
def log_key_pair(request):
    """Generate or get a log key pair and configuration."""
    config = request.config.getoption("--log-config")
    if config:
        # If user provided config, we can't get the private key
        # so we'll generate a new one (this won't match, but it's best effort)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        origin = config.split("=")[0]
        log_key = ed25519.Ed25519PrivateKey.generate()
        return log_key, config, origin

    # Generate a test log config with private key
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import base64
    import hashlib
    import os

    # Generate log key
    log_key = ed25519.Ed25519PrivateKey.generate()
    log_pubkey = log_key.public_key().public_bytes_raw()

    # Build verification key
    # Format: {name}+{hash}+{base64(0x01 + pubkey)}
    origin = "example.com/conformance-log"
    alg_and_pubkey = b"\x01" + log_pubkey

    # Compute hash (first 4 bytes of SHA256(name + "\n" + alg + pubkey))
    hash_input = origin.encode() + b"\n" + alg_and_pubkey
    hash_bytes = hashlib.sha256(hash_input).digest()[:4]
    hash_hex = hash_bytes.hex()

    encoded = base64.b64encode(alg_and_pubkey).decode("ascii")
    vkey = f"{origin}+{hash_hex}+{encoded}"

    config = f"{origin}={vkey}"

    # Export public key hex for litewitness (so wrapper can register the log)
    pubkey_hex = log_pubkey.hex()
    log_info_file = Path(__file__).parent.parent / ".test_log_info"
    with open(log_info_file, "w") as f:
        f.write(f"{origin}\n{pubkey_hex}\n")

    return log_key, config, origin


@pytest.fixture(scope="session")
def log_config(log_key_pair) -> str:
    """Get the log configuration string."""
    _, config, _ = log_key_pair
    return config


@pytest.fixture
def temp_database() -> Iterator[str]:
    """Create a temporary SQLite database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    db_url = f"sqlite://{db_path}"
    yield db_url

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def witness_client(entrypoint: str, port: int, private_key: str,
                   log_config: str, temp_database: str) -> Iterator[WitnessClient]:
    """
    Create and start a witness client for testing.

    This fixture provides a fresh witness instance for each test.
    """
    client = WitnessClient(
        entrypoint=entrypoint,
        port=port,
        database_url=temp_database,
        private_key=private_key,
        log_config=log_config,
    )

    client.start()
    yield client
    client.stop()


@pytest.fixture
def log_signer(log_key_pair):
    """
    Create a log signer for generating test checkpoints.

    Uses the log private key from log_key_pair fixture.
    """
    import base64

    # Get the log key and origin from log_key_pair
    private_key, config, origin = log_key_pair
    public_key = private_key.public_key()

    class LogSigner:
        def __init__(self, origin, private_key, public_key):
            self.origin = origin
            self.private_key = private_key
            self.public_key = public_key
            self.name = origin

            # Compute key ID
            import hashlib
            alg_and_pubkey = b"\x01" + public_key.public_bytes_raw()
            hash_input = origin.encode() + b"\n" + alg_and_pubkey
            self.key_id = hashlib.sha256(hash_input).digest()[:4]

        def sign_checkpoint(self, tree_size: int, root_hash: str) -> str:
            """Generate a signed checkpoint."""
            # Build checkpoint body
            body = f"{self.origin}\n{tree_size}\n{root_hash}\n"

            # Sign the body
            signature = self.private_key.sign(body.encode())

            # Build signature line
            # Format: — {name} {base64(key_id + signature)}
            sig_data = self.key_id + signature
            sig_encoded = base64.b64encode(sig_data).decode("ascii")
            sig_line = f"— {self.name} {sig_encoded}\n"

            return body + "\n" + sig_line

    return LogSigner(origin, private_key, public_key)
