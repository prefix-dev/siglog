"""
Witness client wrapper for conformance testing.

This module provides a wrapper around witness binaries for testing purposes.
"""

import subprocess
import time
import signal
import requests
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class WitnessError(Exception):
    """Base exception for witness client errors."""

    def __init__(self, message: str, returncode: Optional[int] = None,
                 stdout: Optional[str] = None, stderr: Optional[str] = None):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class WitnessClient:
    """
    Client for interacting with a witness server.

    This client manages the lifecycle of a witness process and provides
    methods for testing the witness API endpoints.
    """

    def __init__(self, entrypoint: str, port: int = 2026,
                 database_url: Optional[str] = None,
                 private_key: Optional[str] = None,
                 log_config: Optional[str] = None):
        """
        Initialize the witness client.

        Args:
            entrypoint: Path to the witness binary
            port: Port to run the witness on (default: 2026)
            database_url: Database URL for witness state (default: in-memory SQLite)
            private_key: Witness private key in Note format
            log_config: Log configuration in format "origin=vkey"
        """
        self.entrypoint = Path(entrypoint)
        self.port = port
        self.database_url = database_url or "sqlite::memory:"
        self.private_key = private_key
        self.log_config = log_config
        self.base_url = f"http://localhost:{port}"
        self.process: Optional[subprocess.Popen] = None

        if not self.entrypoint.exists():
            raise WitnessError(f"Witness binary not found: {entrypoint}")

    def start(self, timeout: float = 5.0) -> None:
        """
        Start the witness server process.

        Args:
            timeout: Maximum time to wait for server to be ready (seconds)

        Raises:
            WitnessError: If the server fails to start within timeout
        """
        if self.process is not None:
            raise WitnessError("Witness is already running")

        # Build command line arguments
        cmd = [
            str(self.entrypoint),
            "--database-url", self.database_url,
            "--listen", f"0.0.0.0:{self.port}",
        ]

        if self.private_key:
            cmd.extend(["--private-key", self.private_key])

        if self.log_config:
            cmd.extend(["--log", self.log_config])

        # Start the process
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as e:
            raise WitnessError(f"Failed to start witness: {e}")

        # Wait for server to be ready
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.health_check():
                return

            # Check if process has died
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise WitnessError(
                    "Witness process died during startup",
                    returncode=self.process.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )

            time.sleep(0.1)

        # Timeout reached
        self.stop()
        raise WitnessError(f"Witness server did not become ready within {timeout}s")

    def stop(self) -> None:
        """Stop the witness server process."""
        if self.process is None:
            return

        # Try graceful shutdown first
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            # Force kill if graceful shutdown fails
            self.process.kill()
            self.process.wait()

        self.process = None

    def add_checkpoint(self, old_size: int, proof: list[str], checkpoint: str) -> dict:
        """
        Submit a checkpoint to the witness.

        Args:
            old_size: The tree size the witness last saw
            proof: List of base64-encoded consistency proof hashes
            checkpoint: The full checkpoint text (with log signature)

        Returns:
            dict with 'status_code', 'body', and 'headers'

        Raises:
            WitnessError: If the witness is not running
        """
        if self.process is None:
            raise WitnessError("Witness is not running")

        # Build request body in wire format
        lines = [f"old {old_size}"]
        lines.extend(proof)
        lines.append("")  # Empty line separator
        lines.append(checkpoint)
        body = "\n".join(lines)

        # Make the request
        try:
            response = requests.post(
                f"{self.base_url}/add-checkpoint",
                data=body,
                headers={"Content-Type": "text/plain"},
                timeout=5.0,
            )

            return {
                "status_code": response.status_code,
                "body": response.text,
                "headers": dict(response.headers),
            }
        except requests.exceptions.RequestException as e:
            raise WitnessError(f"Request failed: {e}")

    def health_check(self) -> bool:
        """
        Check if the witness server is healthy.

        Returns:
            True if server responds with 200 OK
        """
        if self.process is None:
            return False

        # Try /health first (rust-tessera witness)
        try:
            response = requests.get(f"{self.base_url}/health", timeout=1.0)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass

        # Fallback to root path (litewitness)
        try:
            response = requests.get(f"{self.base_url}/", timeout=1.0)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    @contextmanager
    def raises(self, expected_status: Optional[int] = None):
        """
        Context manager for testing expected failures.

        Usage:
            with client.raises(403):
                client.add_checkpoint(...)

        Args:
            expected_status: Expected HTTP status code for failure
        """
        try:
            yield
            # If we get here, the operation succeeded when it shouldn't have
            raise AssertionError("Expected operation to fail, but it succeeded")
        except WitnessError:
            # This is expected - re-raise for the test to handle
            raise

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False
