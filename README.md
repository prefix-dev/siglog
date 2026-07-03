![Siglog Banner](https://github.com/user-attachments/assets/dea9a3a6-94fd-45ee-a123-ccc126e88163)

# siglog

A Rust implementation of a [Tessera](https://github.com/transparency-dev/tessera)-compatible transparency log server for package distribution systems.

This implementation follows the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) specification and provides an append-only Merkle tree with cryptographic guarantees that all users see the same data.

## Features

- **Transparency Log Server**: Accepts entries, builds a Merkle tree, and publishes signed checkpoints
- **Witness Server**: Independent co-signing of checkpoints following the [tlog-witness](https://c2sp.org/tlog-witness) specification
- **Verifiable Index**: Optional key-value index with cryptographic proofs for efficient lookups
- **Multiple Storage Backends**: S3-compatible storage (Tigris, MinIO) or local filesystem
- **Multiple Database Backends**: SQLite (with LiteFS for distribution) or PostgreSQL

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
  ┌────┼────┐
  │    │    │
  ▼    ▼    ▼
┌──────────┐ ┌─────────┐
│Log Server│ │ Witness │
│   8080   │ │  8081   │
└────┬─────┘ └────┬────┘
     │            │
     └────────────┘
            │
            ▼
    ┌──────────────────┐
    │  SQLite (LiteFS) │
    │  or PostgreSQL   │
    └────────┬─────────┘
             │
             ▼
    ┌──────────────────┐
    │ S3 / Filesystem  │
    │  (Tile Storage)  │
    └──────────────────┘
```

## Building

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- SQLite 3.x or PostgreSQL 14+
- (Optional) S3-compatible storage for production

### Build

```bash
# Build all binaries in release mode
cargo build --release

# Binaries will be in ./target/release/
# - siglog           (log server)
# - witness          (witness server)
```

## Configuration

### Environment Variables

#### Log Server (`siglog`)

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | Server listen address | `0.0.0.0:8080` |
| `DATABASE_URL` | Database connection string | `sqlite:./siglog.db?mode=rwc` |
| `LOG_ORIGIN` | Log origin identifier | Required |
| `LOG_PRIVATE_KEY` | Ed25519 signing key (note format) | Required |
| `STORAGE_BACKEND` | Storage type: `s3` or `fs` | `fs` |
| `FS_ROOT` | Filesystem storage path (`STORAGE_PATH` is also accepted for compatibility) | `./tiles` |
| `S3_BUCKET` | S3 bucket name | - |
| `S3_ACCESS_KEY` | S3 access key | - |
| `S3_SECRET_KEY` | S3 secret key | - |
| `S3_ENDPOINT` | S3 endpoint URL | - |
| `S3_REGION` | S3 region | `auto` |
| `API_KEY` | Bearer token required for `/add` writes | Required unless `ALLOW_PUBLIC_WRITES=true` |
| `ALLOW_PUBLIC_WRITES` | Allow unauthenticated `/add` writes for local development | `false` |
| `EXTERNAL_WITNESSES` | External witnesses to collect cosignatures from, comma-separated. Format: `name=url=vkey` — the note-format verification key is required and cosignatures are verified against it before a checkpoint is published | - |
| `WITNESS_QUORUM` | Minimum number of external witness cosignatures required to publish a checkpoint | All configured witnesses |
| `WITNESS_KEYS` | In-process witness private keys for local development (comma-separated) | - |
| `VINDEX_SNAPSHOT_INTERVAL` | Entries between vindex snapshots. Each snapshot persists the full index and truncates the WAL, bounding WAL growth and startup replay time (0 disables) | `100000` |
| `RATE_LIMIT_PER_SECOND` | Requests per second allowed per client IP | `100` |
| `RATE_LIMIT_BURST_SIZE` | Burst capacity per client IP | `200` |
| `CHECKPOINT_INTERVAL` | Checkpoint frequency (seconds) | `1` |
| `BATCH_MAX_SIZE` | Max entries per batch | `256` |
| `BATCH_MAX_AGE_MS` | Max batch age (ms) | `1000` |
| `VINDEX_ENABLED` | Enable verifiable index | `false` |
| `VINDEX_KEY_FIELD` | JSON field for key extraction | `name` |
| `VINDEX_WAL_PATH` | WAL path for persistent vindex state (snapshot is stored alongside as `<path>.snapshot`). If the on-disk state is missing, corrupted, or behind the database, the vindex is automatically rebuilt from the log's entry bundles | Recommended when enabling vindex |

#### Witness Server (`witness`)

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | Server listen address | `0.0.0.0:8081` |
| `DATABASE_URL` | Database connection string | `sqlite:./witness.db` |
| `WITNESS_PRIVATE_KEY` | Ed25519 signing key (note format) | Required |
| `WITNESS_LOGS` | Logs to witness (format: `origin=vkey`) | Required |

### Key Format

Keys use the [note signature format](https://pkg.go.dev/golang.org/x/mod/sumdb/note):

```
# Private key format:
PRIVATE+KEY+<name>+<key_id>+<base64_seed>

# Public key (verification key) format:
<name>+<key_id>+<base64_pubkey>

# Example:
PRIVATE+KEY+example.com/log+a1b2c3d4+SGVsbG8gV29ybGQh...
example.com/log+a1b2c3d4+SGVsbG8gV29ybGQh...
```

Generate a new keypair:

```python
#!/usr/bin/env python3
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

name = "example.com/log"
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

seed = private_key.private_bytes_raw()
pub_bytes = public_key.public_bytes_raw()

# Key ID is first 4 bytes of SHA256(name || 0x0a || 0x01 || pubkey)
h = hashlib.sha256(name.encode() + b"\n\x01" + pub_bytes).digest()
key_id = base64.b64encode(h[:4]).decode().rstrip("=")

private_note = f"PRIVATE+KEY+{name}+{key_id}+{base64.b64encode(b'\\x01' + seed).decode()}"
public_note = f"{name}+{key_id}+{base64.b64encode(b'\\x01' + pub_bytes).decode()}"

print(f"Private: {private_note}")
print(f"Public:  {public_note}")
```

## Running Locally

### Using Docker Compose

The easiest way to run locally is with Docker Compose:

```bash
# Create a .env file with LOG_PRIVATE_KEY, LOG_PUBLIC_KEY,
# WITNESS_PRIVATE_KEY, and MONITOR_PRIVATE_KEY.

# Build and start services
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml up
```

This starts:
- Log server on `http://localhost:8080`
- Witness server on `http://localhost:8081`

### Running Manually

```bash
# Start the log server
export LOG_ORIGIN="my-transparency-log"
export LOG_PRIVATE_KEY="PRIVATE+KEY+my-transparency-log+xxxx+..."
export DATABASE_URL="sqlite:./siglog.db"
export STORAGE_BACKEND="fs"
export FS_ROOT="./tiles"
export API_KEY="local-dev-token"

./target/release/siglog

# In another terminal, start the witness
export WITNESS_PRIVATE_KEY="PRIVATE+KEY+witness.example.com+xxxx+..."
export WITNESS_LOGS="my-transparency-log=my-transparency-log+xxxx+..."
export DATABASE_URL="sqlite:./witness.db"

./target/release/witness
```

## Running a Witness

A witness independently verifies and co-signs transparency log checkpoints. Running a witness helps ensure the log operator cannot present different views to different users.

### Standalone Witness

```bash
./target/release/witness \
    --database-url sqlite:./witness.db \
    --private-key "PRIVATE+KEY+witness.example.com+xxxx+base64..." \
    --log "log.example.com=log.example.com+yyyy+base64pubkey..." \
    --listen 0.0.0.0:8081
```

### Witness API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/add-checkpoint` | POST | Submit a checkpoint for co-signing |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |

#### POST /add-checkpoint

Request body (text/plain, per [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness)):
```text
old <size>
<base64 consistency proof hash>
...

<checkpoint text with log signature>
```

Response (on success): the witness's [cosignature/v1](https://c2sp.org/tlog-cosignature)
line — a timestamped Ed25519 signature whose key ID is computed with the
cosignature/v1 algorithm byte (0x04).

## API Reference

### Log Server Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/add` | POST | Add a new entry to the log |
| `/checkpoint` | GET | Get the latest signed checkpoint |
| `/tile/{level}/{index}` | GET | Get a Merkle tree tile |
| `/tile/entries/{index}` | GET | Get an entry bundle |
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |

### Add Entry

```bash
curl -X POST http://localhost:8080/add \
  -H "Authorization: Bearer local-dev-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-package", "version": "1.0.0", "sha256": "abc123..."}'
```

### Get Checkpoint

```bash
curl http://localhost:8080/checkpoint
```

Response:
```
my-transparency-log
42
Ynl0ZXMgb2YgdGhlIHJvb3QgaGFzaA==

— my-transparency-log Ab1CdEf...
```

### Get Merkle Tile

```bash
# Get tile at level 0, index 0
curl http://localhost:8080/tile/0/000
```

### Get Entries

```bash
# Get entry bundle at index 0 (entries 0-255)
curl http://localhost:8080/tile/entries/000
```

## Bulk import (backfill)

Bootstrapping a log with existing data should not go through `POST /add` —
the incremental path acknowledges entries batch-by-batch and rewrites each
partial tile up to 256 times. `siglog-import` builds the tree in one pass
with concurrent uploads and produces a byte-identical tree to what
incremental integration would create (~5,000 entries/s locally vs ~36/s
over HTTP).

```bash
# 1. Convert conda repodata to normalized JSONL (one file per subdir)
conda-log-ingest --file linux-64/repodata.json --subdir linux-64 \
    --jsonl-out linux-64.jsonl

# 2. Import into an EMPTY log (server must not be running)
siglog-import \
    --origin conda.prefix.dev \
    --database-url sqlite:/data/siglog.db?mode=rwc \
    --storage-backend s3 \
    --jsonl noarch.jsonl --jsonl linux-64.jsonl \
    --epoch-note "conda-forge bootstrap $(date -u +%F), repodata sha256 ..." \
    --vindex-wal-path /data/vindex.wal

# 3. Start the server; it continues incrementally from the imported state.
```

The import writes the database state only after every tile and bundle is
durably uploaded, so an interrupted run can be retried; `--resume` skips
objects that already exist (use the same `--chunk-size` and input). On
Fly.io, run it as a one-off machine holding the data volume:

```bash
fly machine destroy <server-machine> --force     # volume must be free
fly machine run <image> --volume siglog_data:/data --entrypoint sleep -- infinity
fly ssh sftp shell   # upload the .jsonl files to /data/
fly ssh console -C "siglog-import --origin ... --jsonl /data/noarch.jsonl ..."
fly machine destroy <import-machine> --force
fly deploy           # recreate the server on the imported state
```

## Deployment

### Fly.io

Quick start:
```bash
# Create app and storage
fly apps create my-siglog
fly storage create
fly consul attach
fly volumes create litefs --size 1

# Set secrets
fly secrets set LOG_PRIVATE_KEY="PRIVATE+KEY+..."
fly secrets set API_KEY="..."
fly secrets set S3_ACCESS_KEY="..." S3_SECRET_KEY="..." S3_BUCKET="..."

# Deploy
fly deploy
```

### Docker

Pre-built images are available from GitHub Container Registry:

```bash
# Log server (replace OWNER/REPO with your GitHub repository)
docker pull ghcr.io/OWNER/REPO-server:latest

# Witness
docker pull ghcr.io/OWNER/REPO-witness:latest
```

Run the log server:

```bash
docker run -d \
  -p 8080:8080 \
  -v siglog-data:/data \
  -e LOG_ORIGIN="my-transparency-log" \
  -e LOG_PRIVATE_KEY="PRIVATE+KEY+..." \
  -e API_KEY="..." \
  ghcr.io/OWNER/REPO-server:latest
```

Run the witness:

```bash
docker run -d \
  -p 8081:8081 \
  -v witness-data:/data \
  -e WITNESS_PRIVATE_KEY="PRIVATE+KEY+..." \
  -e WITNESS_LOGS="my-transparency-log=my-transparency-log+xxxx+..." \
  ghcr.io/OWNER/REPO-witness:latest
```

To build images locally:

```bash
docker build -f docker/Dockerfile.server -t siglog-server .
docker build -f docker/Dockerfile.witness -t siglog-witness .
```

### Kubernetes

Example deployment manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: transparency-log
spec:
  replicas: 1
  selector:
    matchLabels:
      app: transparency-log
  template:
    metadata:
      labels:
        app: transparency-log
    spec:
      containers:
      - name: log
        image: your-registry/siglog:latest
        ports:
        - containerPort: 8080
        env:
        - name: LOG_ORIGIN
          value: "your-log.example.com"
        - name: LOG_PRIVATE_KEY
          valueFrom:
            secretKeyRef:
              name: siglog-secrets
              key: log-private-key
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: siglog-secrets
              key: api-key
        - name: DATABASE_URL
          value: "postgres://user:pass@postgres:5432/siglog"
        - name: STORAGE_BACKEND
          value: "s3"
        envFrom:
        - secretRef:
            name: s3-credentials
```

## Verification

Clients can verify entries against the transparency log:

1. Fetch the latest checkpoint
2. Verify the checkpoint signature
3. Verify any witness cosignatures
4. For a specific entry, fetch the inclusion proof
5. Verify the proof against the checkpoint root hash

## License

BSD-3-Clause. See [LICENSE](LICENSE) for details.
