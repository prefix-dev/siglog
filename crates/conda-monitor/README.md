# conda-monitor

A monitoring witness for Conda package transparency logs.

This crate provides Conda-specific functionality for the [rust-tessera](../../README.md) transparency log:

- **CondaMonitor**: Validates Conda package log entries for SHA256 and filename uniqueness
- **RepodataEntry**: Normalizes repodata entries for consistent hashing
- **FilenameMapFn**: Maps entries to index keys by filename

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
conda-monitor = { path = "crates/conda-monitor" }
```

## Usage

### Running the Monitor

```bash
# Build
cargo build --release -p conda-monitor

# Run
./target/release/conda-monitor \
    --database-url sqlite:./conda_monitor.db \
    --private-key "PRIVATE+KEY+monitor.example.com+xxxx+base64..." \
    --log "conda.example.com=conda.example.com+yyyy+base64key=http://log.example.com" \
    --listen 0.0.0.0:2027
```

### Ingesting Repodata

```bash
./target/release/conda-log-ingest \
    --url https://conda.anaconda.org/conda-forge/linux-64/repodata.json \
    --log-url http://localhost:8080 \
    --subdir linux-64
```

### Verifying Entries

```bash
./target/release/conda-log-verify \
    --log-url http://localhost:8080 \
    --subdir linux-64 \
    --filename numpy-1.26.0-py311h123_0.conda \
    --repodata-url https://conda.anaconda.org/conda-forge/linux-64/repodata.json
```

## Validation Rules

The Conda monitor enforces two key rules:

1. **SHA256 Uniqueness**: No two packages can have the same SHA256 hash (prevents duplicate content)
2. **Filename Uniqueness**: A filename cannot reappear with a different SHA256 (prevents package replacement attacks)

## API

### Monitor Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/add-checkpoint` | POST | Submit a checkpoint for validation and co-signing |
| `/health` | GET | Health check |
| `/stats` | GET | Monitor statistics (entry counts, etc.) |

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:./conda_monitor.db` |
| `WITNESS_PRIVATE_KEY` | Ed25519 signing key (note format) | Required |
| `MONITOR_LOGS` | Logs to monitor (format: `origin=vkey=url`) | Required |
| `LISTEN_ADDR` | Server listen address | `0.0.0.0:2027` |

## License

BSD-3-Clause. See [LICENSE](../../LICENSE) for details.
