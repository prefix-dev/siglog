# Witness Conformance Test Suite

A comprehensive conformance test suite for transparency log witness implementations, inspired by [sigstore-conformance](https://github.com/sigstore/sigstore-conformance).

This test suite validates that witness implementations conform to the [C2SP tlog-witness specification](https://c2sp.org/tlog-witness).

## Features

- **JSON-based test cases**: Easy to read, write, and extend
- **Comprehensive coverage**: 20+ test cases covering happy paths, error conditions, and edge cases
- **Automatic test discovery**: Add new test cases by simply dropping JSON files
- **Flexible witness invocation**: Works with any witness binary that follows the standard protocol
- **uv-enabled**: Modern Python packaging with uv support

## Test Coverage

The test suite includes:

### Happy Path Tests (10 cases)
- Bootstrap scenarios (size 0→1)
- Sequential growth (1→3→5)
- Power-of-2 tree sizes
- Large tree sizes
- Idempotent operations

### Error Condition Tests (10 cases)
- Invalid checkpoint signatures (403 Forbidden)
- Missing or corrupted consistency proofs (422 Unprocessable Entity)
- Wrong proof lengths
- Invalid size relationships (old > new)
- Split-view detection (same size, different root)
- Malformed requests (400 Bad Request)

## Installation

### Using uv (recommended)

```bash
cd witness-conformance
uv venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows
uv pip install -e .
```

### Using pip

```bash
cd witness-conformance
pip install -e .
```

## Usage

### Basic Usage

Run the conformance tests against your witness binary:

```bash
pytest --entrypoint=/path/to/your/witness
```

### With Custom Configuration

```bash
pytest \
  --entrypoint=/path/to/your/witness \
  --port=2026 \
  --private-key="PRIVATE+KEY+witness+deadbeef+..." \
  --log-config="example.com/log=example.com/log+hash+key"
```

### Run Specific Tests

```bash
# Run only happy path tests (tests that should pass)
pytest -k "not _fail"

# Run only error condition tests
pytest -k "_fail"

# Run a specific test case
pytest test/test_witness.py::test_witness_conformance[bootstrap_size_1]
```

### Generate JSON Report

```bash
pytest --json-report --json-report-file=conformance-report.json
```

### Verbose Output

```bash
pytest -v --tb=short
```

## Test Case Format

Test cases are JSON files in `test/cases/` with the following structure:

```json
{
  "name": "bootstrap_size_1",
  "description": "Bootstrap witness with first checkpoint at size 1",
  "should_fail": false,
  "old_size": 0,
  "new_size": 1,
  "proof": [],
  "root_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "expected_status": 200,
  "checkpoint_valid": true
}
```

### Fields

- `name`: Unique identifier for the test case
- `description`: Human-readable description of what the test validates
- `should_fail`: Whether the operation should fail (true/false)
- `old_size`: Previous tree size the witness saw
- `new_size`: New tree size in the checkpoint
- `proof`: Array of base64-encoded consistency proof hashes
- `root_hash`: Base64-encoded root hash for the new tree size
- `expected_status`: Expected HTTP status code (200, 403, 404, 422, etc.)
- `checkpoint_valid`: Whether the checkpoint signature should be valid (optional, default: true)

### Naming Convention

Test files ending with `_fail.json` indicate expected failure cases. All other tests are expected to succeed.

## Adding New Test Cases

1. Create a new JSON file in `test/cases/`:

```bash
cat > test/cases/my_new_test.json << 'EOF'
{
  "name": "my_new_test",
  "description": "Description of what this tests",
  "should_fail": false,
  "old_size": 1,
  "new_size": 3,
  "proof": ["hash1", "hash2"],
  "root_hash": "base64_root_hash",
  "expected_status": 200
}
EOF
```

2. Run pytest - the new test will be automatically discovered

### Regenerating Test Cases

To regenerate all test cases (useful after modifying the generator):

```bash
python3 generate_cases.py
```

## Witness Protocol

The conformance suite expects witnesses to:

1. Accept command-line arguments:
   - `--database-url`: Database connection string
   - `--listen`: Listen address (e.g., `0.0.0.0:2026`)
   - `--private-key`: Witness private key in Note format
   - `--log`: Log configuration in format `origin=vkey`

2. Expose HTTP endpoints:
   - `POST /add-checkpoint`: Submit checkpoint for witnessing
   - `GET /health`: Health check

3. Use wire format for `/add-checkpoint`:
   ```
   old <size>
   <base64-hash-1>
   <base64-hash-2>
   ...
   <empty line>
   <checkpoint text>
   ```

4. Return appropriate HTTP status codes:
   - `200 OK`: Successful witnessing (returns signature line)
   - `400 Bad Request`: Malformed request
   - `403 Forbidden`: Invalid checkpoint signature
   - `404 Not Found`: Unknown log origin
   - `409 Conflict`: old_size mismatch (returns witnessed size)
   - `422 Unprocessable Entity`: Invalid consistency proof

## Example: Testing rust-tessera Witness

```bash
# Build the witness binary
cd ../
cargo build --release --bin witness

# Run conformance tests
cd witness-conformance
pytest --entrypoint=../target/release/witness -v
```

## Architecture

```
witness-conformance/
├── pyproject.toml          # Project configuration
├── generate_cases.py       # Test case generator
├── test/
│   ├── conftest.py         # Pytest configuration & fixtures
│   ├── client.py           # WitnessClient wrapper
│   ├── test_witness.py     # Main conformance tests
│   └── cases/              # JSON test cases (auto-discovered)
│       ├── bootstrap_size_1.json
│       ├── growth_1_to_3.json
│       ├── invalid_signature_fail.json
│       └── ...
└── README.md
```

## Development

### Running Tests Locally

```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Run with coverage
pytest --cov=test --cov-report=html

# Run with verbose output
pytest -vv
```

### Adding Test Fixtures

Edit `test/conftest.py` to add new fixtures that can be used across all tests.

### Customizing the Test Runner

The test suite uses pytest's powerful plugin system. You can:
- Add custom markers in `pyproject.toml`
- Add hooks in `conftest.py`
- Use pytest plugins for additional features

## Contributing

To add new test cases:

1. Either manually create JSON files in `test/cases/`
2. Or modify `generate_cases.py` and regenerate all cases

Test cases should be:
- **Focused**: Test one specific behavior
- **Documented**: Clear description field
- **Deterministic**: Same input always produces same result
- **Independent**: Can run in any order

## License

This conformance suite is part of the rust-tessera project.

## References

- [C2SP tlog-witness specification](https://c2sp.org/tlog-witness)
- [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
