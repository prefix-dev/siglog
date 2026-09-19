![Siglog Banner](https://github.com/user-attachments/assets/dea9a3a6-94fd-45ee-a123-ccc126e88163)

# siglog

A Rust transparency log server for package distribution systems, with [Tessera](https://github.com/transparency-dev/tessera) and [Rekor v2](https://github.com/sigstore/rekor-tiles) HTTP API modes.

This implementation follows the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) specification and provides signed checkpoints and append-only Merkle proofs. Detecting split views requires independent witnesses and client verification.

## Features

- **Transparency Log Server**: Accepts entries, builds a Merkle tree, and publishes signed checkpoints
- **Witness Server**: Independent co-signing of checkpoints following the [tlog-witness](https://c2sp.org/tlog-witness) specification
- **Verifiable Index**: Optional key-value lookup hints; its root is not authenticated by the log checkpoint
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

- Rust 1.95+ (install via [rustup](https://rustup.rs/))
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
| `LOG_MODE` | API mode: `tessera` or `rekor` (`--mode`) | `tessera` |
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
| `API_KEY` | Bearer token required for write requests in either mode | Required unless `ALLOW_PUBLIC_WRITES=true` |
| `ALLOW_PUBLIC_WRITES` | Allow unauthenticated writes for local development | `false` |
| `EXTERNAL_WITNESSES` | Comma-separated `name=url` witness endpoints | - |
| `EXTERNAL_WITNESS_KEYS` | Comma-separated pinned public note keys (Ed25519 or cosignature/v1), one per external witness name | Required with external witnesses |
| `WITNESS_QUORUM` | Minimum distinct external witness signatures required to publish | All configured witnesses |
| `CHECKPOINT_INTERVAL` | Checkpoint frequency (seconds) | `1` |
| `BATCH_MAX_SIZE` | Max entries per batch | `256` |
| `BATCH_MAX_AGE_MS` | Max batch age (ms) | `1000` |
| `VINDEX_ENABLED` | Enable verifiable index | `false` |
| `VINDEX_KEY_FIELD` | JSON field for key extraction | `name` |
| `VINDEX_WAL_PATH` | WAL path for persistent vindex recovery | Required when enabling vindex on a non-empty log |
| `VINDEX_SNAPSHOT_INTERVAL` | Entries between vindex snapshots/WAL compaction (`0` disables) | `100000` |

Witnesses and monitors emit timestamped C2SP `cosignature/v1` signatures.
The publisher verifies signatures against pinned keys before counting the quorum;
legacy plain Ed25519 witness signatures remain accepted. Log signatures remain
plain Ed25519. External witnesses must have distinct names and public keys.

The vindex reads legacy v2 WALs and writes CRC32-protected v3 records. Snapshots
bound WAL growth and replay time, not the in-memory index size. Missing, corrupt,
or incomplete index state is rebuilt from entry bundles; incomplete bundles fail
startup. Back up the database and tile storage together.

The server supervises its background workers, expires idle rate-limit buckets,
and times out HTTP requests after 30 seconds. Server, witness, and monitor handle
SIGTERM as well as Ctrl+C. Client IPs still come from the connection, not untrusted
forwarding headers.

The [witness conformance suite](witness-conformance/README.md) runs in CI, alongside
Rust security tests and the Go Rekor interoperability checks.

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
key_id = h[:4].hex()

private_note = f"PRIVATE+KEY+{name}+{key_id}+{base64.b64encode(bytes([1]) + seed).decode()}"
public_note = f"{name}+{key_id}+{base64.b64encode(bytes([1]) + pub_bytes).decode()}"

print(f"Private: {private_note}")
print(f"Public:  {public_note}")
```

## Running Locally

### Using Docker Compose

The easiest way to run locally is with Docker Compose:

```bash
# Create a .env file with LOG_PRIVATE_KEY, LOG_PUBLIC_KEY,
# WITNESS_PRIVATE_KEY, WITNESS_PUBLIC_KEY, MONITOR_PRIVATE_KEY,
# and MONITOR_PUBLIC_KEY (public keys named witness and monitor).

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

### Security and upgrade notes

- External witnesses require pinned public note keys; names and URLs alone are no longer sufficient. Every configured witness signature is verified before publication.
- Monitoring witnesses authenticate every new entry against the signed checkpoint. Concurrent monitor requests receive HTTP 503 with `Retry-After`; state is reloaded for the selected origin, and content indices and checkpoints commit in one database transaction. This prioritizes correctness over monitor throughput.
- `conda-log-verify` requires `--log-origin` and `--log-key` from a trusted source. It verifies checkpoint signatures and entry inclusion, and exits nonzero on failure. It does not establish checkpoint freshness, witness quorum, or lookup completeness.
- Vindex failures stop integration rather than silently omitting entries. WAL gaps fail startup; rebuild an inconsistent index from authenticated entries. WAL recovery discards all entries when the database is empty.
- Docker processes run as UID/GID `10001:10001`. Existing data volumes must be writable by that identity before upgrading. Filesystem object replacement is atomic.
- CI audits dependencies. The only advisory exception is the unused `rsa` dependency in SQLx's optional MySQL lockfile graph; CI also checks that it is absent from the enabled runtime graph.

## Bulk import

For offline bootstrap of a fresh Tessera log from conda-forge repodata, see the
[bulk import guide](docs/bulk-import.md). `conda-log-ingest --jsonl-out` exports
normalized snapshots; `siglog-import --jsonl ...` builds the tree with concurrent
uploads and content-checked resume. It refuses Rekor and nonempty logs and leaves
checkpoint publication to the normal witness-aware server.

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

Request body:
```json
{
  "checkpoint": "log.example.com\n123\nROOTHASH...\n\n- log.example.com SIGNATURE...",
  "proof": ["HASH1...", "HASH2..."],
  "old_size": 100
}
```

Response (on success): The witness's cosignature line.

## API Reference

### Choosing an API mode

```bash
# Existing raw-entry API (default)
./target/release/siglog --mode tessera

# Rekor v2 HTTP/JSON API; use a NEW database and tile storage directory
./target/release/siglog --mode rekor \
  --database-url 'sqlite:./rekor.db?mode=rwc' --fs-root ./rekor-tiles
```

Both commands also require the signing key, origin, and write-authentication configuration described above.
The selected mode is persisted in the database; startup rejects a different mode.
Existing non-empty, unmarked databases are treated as Tessera logs. Use separate
storage, databases, and log identities for separate logs—do not mix their writers.

Rekor mode exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/log/entries` | POST | Verify and integrate a hashedrekord v0.0.2 entry |
| `/api/v2/checkpoint` | GET | Latest signed checkpoint |
| `/api/v2/tile/{level}/{index}` | GET | Hash tile, including partial tiles |
| `/api/v2/tile/entries/{index}` | GET | Entry bundle, including partial bundles |
| `/health`, `/ready` | GET | Health and readiness |

`/add` is **not exposed** in Rekor mode. Existing explorer/package-monitor clients
that use the unprefixed API should continue using Tessera mode. Generic tile readers
can use `/api/v2/` as their read base URL in Rekor mode.

The submission schema follows [Rekor v2](https://github.com/sigstore/rekor-tiles/blob/v2.3.0/api/proto/rekor/v2/entry.proto):

```json
{
  "hashedRekordRequestV002": {
    "digest": "BASE64_ARTIFACT_SHA256",
    "signature": {
      "content": "BASE64_DER_ECDSA_SIGNATURE",
      "verifier": {
        "publicKey": {"rawBytes": "BASE64_DER_SPKI_PUBLIC_KEY"},
        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
      }
    }
  }
}
```

Use `Content-Type: application/json` and `Authorization: Bearer <API_KEY>`.
Exactly one `publicKey` or `x509Certificate` (DER, base64-encoded `rawBytes`) is required.
Supported signature algorithms are Ed25519ph/SHA-512 (`PKIX_ED25519_PH`, empty
context), ECDSA P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 and RSA PKCS#1 v1.5
SHA-256 with 2048/3072/4096-bit keys. Ed25519ph takes the artifact's SHA-512 digest;
pure Ed25519 signatures over that digest are not interchangeable.
Artifact signatures and key/algorithm agreement are verified before sequencing.
Certificate trust/identity policy remains the client's responsibility, as in Rekor.
RSA-PSS, deprecated DSSE submissions, and gRPC transport are not implemented.

A successful write returns HTTP **201** and a Sigstore `TransparencyLogEntry`:
canonicalized body, log ID, kind/version, and inclusion proof against a **published,
signed checkpoint**. Protobuf JSON integer fields are strings and byte fields are
base64. No v1 signed-entry timestamp/inclusion promise is issued.
The log ID is the full SHA-256 note-key hash, matching rekor-tiles v2.3.0.

Requests wait up to 30 seconds for sequencing, integration, and checkpoint publication
(including configured witnesses). A 504 does **not** undo a queued entry.
Exact canonical entries are deduplicated permanently and atomically in the database,
including concurrent retries, pending entries, and retries after restarts. A duplicate
returns HTTP **409**, gRPC JSON code **6**, and an `x-log-index` header with the original
index. This is not an inclusion promise: that entry may still await integration.
Different signatures or verification material produce different entries even for the
same artifact. Tessera mode still appends every submission.
Request bodies and canonical entries are each limited to 65,535 bytes.

### Tessera Log Server Endpoints

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

### Rekor interoperability checks

```bash
cargo test --workspace
cargo build --bin siglog
(cd rekor-conformance && go test -v)
```

The Go test requires Go 1.25.8+ (or automatic Go toolchain downloads). It launches an
isolated local server and uses the upstream rekor-tiles v2.3.0 writer and verifier
to check all supported signing algorithms, public keys and certificates, canonical
entry reconstruction, Ed25519ph signatures, duplicate responses, and inclusion proofs
across a full tile boundary. CI also checks concurrent deduplication and rollback on
SQLite and PostgreSQL; locally, set `SIGLOG_TEST_POSTGRES_URL` to a dedicated empty
PostgreSQL database to run that check.

## License

BSD-3-Clause. See [LICENSE](LICENSE) for details.
