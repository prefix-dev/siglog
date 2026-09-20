# Offline conda-forge bootstrap

`siglog-import` builds tiles and entry bundles directly, avoiding per-entry HTTP
requests and database pending rows. It accepts **Tessera only**; it refuses a
Rekor database, a nonempty database, or storage containing a published checkpoint.
Use a separate database and storage namespace from any existing log.

**Stop every server, worker and other writer using this database/storage before
importing, and leave them stopped until it succeeds.** The importer holds a
single database writer transaction throughout uploads. That serializes importers
using the same database, but cannot protect a storage bucket shared by different
databases. Never share namespaces. Configure PostgreSQL transaction timeouts to
allow the full import duration.

## 1. Freeze and normalize a snapshot

Build the tools:

```sh
cargo build --release --bin siglog --bin siglog-import
cargo build --release -p conda-monitor --bin conda-log-ingest --bin conda-log-verify
mkdir -p snapshots jsonl
```

Start small (use a separate throwaway database/storage for each experiment):

```sh
curl --fail --location --retry 3 \
  https://conda.anaconda.org/conda-forge/noarch/repodata.json \
  -o snapshots/noarch.json
./target/release/conda-log-ingest --file snapshots/noarch.json \
  --subdir noarch --limit 1000 --jsonl-out jsonl/noarch-sample.jsonl
```

For all subdirs advertised by the channel, use this **instead of** the sample
export, in a fresh `jsonl` directory. Full repodata can require substantial disk
and RAM. The exporter holds one parsed subdir in memory, not the entire channel.

```bash
set -euo pipefail
curl --fail --location --retry 3 \
  https://conda.anaconda.org/conda-forge/channeldata.json \
  -o snapshots/channeldata.json
python3 - <<'PY' > snapshots/subdirs.txt
import json, re
with open('snapshots/channeldata.json') as f:
    subdirs = sorted(set(json.load(f)['subdirs']))
assert subdirs and all(re.fullmatch(r'[a-z0-9_-]+', s) for s in subdirs)
print('\n'.join(subdirs))
PY
while IFS= read -r subdir; do
  curl --fail --location --retry 3 \
    "https://conda.anaconda.org/conda-forge/$subdir/repodata.json" \
    -o "snapshots/$subdir.json"
  ./target/release/conda-log-ingest --file "snapshots/$subdir.json" \
    --subdir "$subdir" --jsonl-out "jsonl/$subdir.jsonl"
done < snapshots/subdirs.txt
sha256sum snapshots/*.json jsonl/*.jsonl > snapshots/SHA256SUMS
```

Both `packages` and `packages.conda` are included, in filename order. The exporter
uses the same normalization as HTTP ingestion. Missing required fields (including
SHA256) are errors, not silently skipped packages. Resolve these errors explicitly;
do not describe an incomplete export as the full channel. Output files are
atomically published without overwriting existing exports.

Keep these frozen inputs. This is a snapshot of currently advertised packages,
**not a complete history** of removed packages or past repodata changes. Fetches
across subdirs are not an atomic channel-wide snapshot. A witness attests to log
consistency, not provenance or authenticity of the downloaded metadata.

## 2. Import into a fresh offline log

```bash
export DATABASE_URL='sqlite:./conda-log.db?mode=rwc'
export STORAGE_BACKEND=fs
export FS_ROOT="$PWD/conda-tiles"
# Alternatively set STORAGE_BACKEND=s3 and S3_ENDPOINT, S3_BUCKET,
# S3_ACCESS_KEY, S3_SECRET_KEY, S3_REGION (default: auto).

inputs=()
for file in jsonl/*.jsonl; do inputs+=(--jsonl "$file"); done
./target/release/siglog-import "${inputs[@]}"
```

File order determines entry indices. The importer reads each JSONL input twice:
first to validate bounded JSON-object lines and fingerprint the entire ordered
entry stream, then to build the tree. It rechecks the fingerprint before committing
so edits during import fail. `import-manifest.json` in tile storage binds the
fingerprint, count, chunk size and Tessera mode. It is operational metadata, not
an entry in the signed tree; retain the original input manifest separately.

Defaults: 4096 entries per chunk, 16 concurrent object uploads. Tune with
`--chunk-size` (multiple of 256, maximum 65536) and `--upload-concurrency` (1–256).
Memory scales with chunk size and entry size; the importer does not retain all
entries or build a full in-memory vindex. No signing key is needed for import.

On interruption, the database transaction rolls back but uploaded objects remain.
Keep the server stopped and repeat the **same command** with `--resume`. Every
existing object is compared byte-for-byte; mismatches are errors, never overwritten.
Use the same ordered inputs and chunk size. Resume rehashes the input and rereads
existing objects, saving uploads rather than all computation. A manifest is
required for resume. For filesystem storage on Unix, directory entries are synced
before committing, in addition to OpenDAL's file-content syncs.

A completed import cannot be run again, even with `--resume`. If a process exits
just after the database commit, a retry reports the nonempty log instead of
appending twice; start the server and verify its checkpoint against the input.
Back up the database and storage together; do not discard the database while
reusing its tile directory/bucket.

## 3. Start normally and verify

Set `LOG_ORIGIN`, `LOG_PRIVATE_KEY`, `API_KEY`, and any external witness settings
as described in the main README. Then:

```sh
export LOG_MODE=tessera
# Optional: rebuild vindex from the imported entry bundles on first startup.
export VINDEX_ENABLED=true
export VINDEX_KEY_FIELD=filename
export VINDEX_WAL_PATH="$PWD/conda-vindex.wal"
./target/release/siglog
```

Choose vindex limits appropriate to the dataset (`VINDEX_MAX_KEYS` and
`VINDEX_MAX_INDICES_PER_KEY`). The index remains memory-resident and its default
capacity may be too small for all conda-forge artifacts. The filename index is
required by `conda-log-verify` for candidate discovery. You can leave vindex
disabled to test large log ingestion first. The existing server recovery path
builds and snapshots it on startup; the importer never deletes an existing index.

The importer deliberately **does not publish a checkpoint**. The normal server
signs the imported root and obtains the configured witness quorum. Compare that
checkpoint's tree size and root with the importer's final output. Witnessing a
very large bootstrap through a content-validating monitor may need separate
performance tuning; a consistency-only witness does not download all entries.

For a package, use the verifier with trusted origin/key and the frozen repodata:

```sh
./target/release/conda-log-verify --help
# Supply --log-url, --log-origin, --log-key, --subdir, --filename,
# and --repodata-file pointing at the corresponding frozen snapshot.
```

Use `conda-log-ingest --api-key ...` to exercise later HTTP submissions. Tessera
appends each submission; it does not deduplicate repeated metadata. Do not submit
the entire frozen snapshot again unless you want duplicate entries.

## Automated checks

```sh
cargo test --test import_test
cargo test --bin siglog-import
cargo test -p conda-monitor --test import_export_test
```

Tests compare the imported root with an independent recursive RFC6962 tree,
verify inclusion proofs across bundle boundaries, rebuild/reload vindex, reopen
the SQLite database, and append through the normal worker before verifying a
signed checkpoint. They also exercise interrupted imports, changed input,
corrupted objects, Rekor/published-log refusal, and resume with pre-existing
future full tiles. Iterator-error injection tests the rollback path; it is not
a substitute for power-loss testing on your actual filesystem/object store.
