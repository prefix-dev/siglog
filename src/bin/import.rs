//! Bulk importer for bootstrapping a siglog transparency log.
//!
//! Reads pre-normalized entries as JSONL (one JSON object per line) and
//! builds the full tree — tiles, entry bundles, vindex, database state, and
//! a signed checkpoint — in one pass with concurrent uploads. Orders of
//! magnitude faster than submitting entries through `POST /add`.
//!
//! Producing the JSONL for a conda channel:
//!   conda-log-ingest --file linux-64/repodata.json --subdir linux-64 \
//!       --jsonl-out linux-64.jsonl
//!
//! Running the import (against the same DATABASE_URL / storage the server
//! will use — the server must NOT be running):
//!   siglog-import --origin conda.prefix.dev \
//!       --jsonl noarch.jsonl --jsonl linux-64.jsonl \
//!       --epoch-note "conda-forge bootstrap 2026-07-03" \
//!       --vindex-wal-path /data/vindex.wal

use clap::Parser;
use siglog::checkpoint::CheckpointSigner;
use siglog::import::{bulk_import, ImportConfig};
use siglog::storage::{Database, TileStorage};
use siglog::vindex;
use std::io::BufRead;
use std::sync::Arc;

/// Bulk importer for bootstrapping a siglog transparency log.
#[derive(Parser, Debug)]
#[command(name = "siglog-import")]
#[command(about = "Bulk-import pre-normalized entries into an empty transparency log")]
struct Args {
    /// Database URL (PostgreSQL: postgres://... or SQLite: sqlite:./path.db)
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Storage backend: "s3" or "fs"
    #[arg(long, env = "STORAGE_BACKEND", default_value = "fs")]
    storage_backend: String,

    /// Filesystem storage root directory (when storage_backend=fs)
    #[arg(long, env = "FS_ROOT")]
    fs_root: Option<String>,

    /// S3 endpoint URL (when storage_backend=s3)
    #[arg(long, env = "S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3 bucket name (when storage_backend=s3)
    #[arg(long, env = "S3_BUCKET")]
    s3_bucket: Option<String>,

    /// S3 access key (when storage_backend=s3)
    #[arg(long, env = "S3_ACCESS_KEY")]
    s3_access_key: Option<String>,

    /// S3 secret key (when storage_backend=s3)
    #[arg(long, env = "S3_SECRET_KEY")]
    s3_secret_key: Option<String>,

    /// S3 region (when storage_backend=s3)
    #[arg(long, env = "S3_REGION", default_value = "auto")]
    s3_region: String,

    /// Log origin string (e.g., "conda.prefix.dev")
    #[arg(long, env = "LOG_ORIGIN")]
    origin: String,

    /// Ed25519 private key in note format
    #[arg(long, env = "LOG_PRIVATE_KEY")]
    private_key: String,

    /// JSONL input file(s), one pre-normalized entry per line. Repeatable;
    /// files are imported in the order given. Use "-" for stdin.
    #[arg(long = "jsonl", required = true)]
    jsonl: Vec<String>,

    /// Optional epoch marker logged as entry 0, recording what this
    /// bootstrap represents (e.g. the repodata snapshot date/hashes).
    #[arg(long)]
    epoch_note: Option<String>,

    /// Entries per integration chunk (must be a multiple of 256).
    #[arg(long, default_value = "65536")]
    chunk_size: usize,

    /// Maximum concurrent object uploads.
    #[arg(long, default_value = "32")]
    upload_concurrency: usize,

    /// Resume an interrupted import: skip objects that already exist.
    /// Must use the same chunk size and input as the interrupted run.
    #[arg(long)]
    resume: bool,

    /// Build the vindex during import and write its WAL + snapshot here.
    #[arg(long, env = "VINDEX_WAL_PATH")]
    vindex_wal_path: Option<String>,

    /// JSON field name to extract vindex keys from.
    #[arg(long, env = "VINDEX_KEY_FIELD", default_value = "name")]
    vindex_key_field: String,
}

/// Iterator over entries from the input files (epoch marker first).
fn entry_iter(
    args: &Args,
) -> anyhow::Result<impl Iterator<Item = siglog::error::Result<Vec<u8>>>> {
    let epoch: Vec<siglog::error::Result<Vec<u8>>> = match &args.epoch_note {
        Some(note) => {
            let marker = serde_json::json!({
                "type": "epoch",
                "note": note,
                "timestamp": chrono::Utc::now().timestamp(),
            });
            vec![Ok(serde_json::to_vec(&marker).expect("epoch marker serializes"))]
        }
        None => Vec::new(),
    };

    let mut readers: Vec<Box<dyn BufRead>> = Vec::new();
    for path in &args.jsonl {
        if path == "-" {
            readers.push(Box::new(std::io::BufReader::new(std::io::stdin())));
        } else {
            let file = std::fs::File::open(path)
                .map_err(|e| anyhow::anyhow!("cannot open {}: {}", path, e))?;
            readers.push(Box::new(std::io::BufReader::new(file)));
        }
    }

    Ok(epoch.into_iter().chain(
        readers
            .into_iter()
            .flat_map(|r| r.lines())
            .filter(|line| !matches!(line, Ok(l) if l.trim().is_empty()))
            .map(|line| {
                line.map(|l| l.into_bytes())
                    .map_err(|e| siglog::error::Error::Io(e))
            }),
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("siglog=info".parse()?),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Bulk import starting for origin '{}'", args.origin);

    // Database + storage (same configuration the server will run with)
    let db = Database::connect(&args.database_url).await?;
    db.run_migrations().await?;

    let storage = match args.storage_backend.as_str() {
        "fs" => {
            let root = args
                .fs_root
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--fs-root is required for fs storage"))?;
            TileStorage::new_fs(&root)?
        }
        "s3" => {
            let get = |v: &Option<String>, name: &str| {
                v.clone()
                    .ok_or_else(|| anyhow::anyhow!("--{} is required for s3 storage", name))
            };
            TileStorage::new_s3(
                &get(&args.s3_endpoint, "s3-endpoint")?,
                &get(&args.s3_bucket, "s3-bucket")?,
                &get(&args.s3_access_key, "s3-access-key")?,
                &get(&args.s3_secret_key, "s3-secret-key")?,
                &args.s3_region,
            )?
        }
        other => anyhow::bail!("Unknown storage backend: {}. Use 'fs' or 's3'.", other),
    };

    let signer = CheckpointSigner::from_note_key(&args.private_key)?;

    // Vindex: the import always builds it from scratch, so clear any
    // leftover state first (a resumed import re-indexes from the input).
    let vindex = match &args.vindex_wal_path {
        Some(wal_path) => {
            let snapshot = vindex::snapshot_path(std::path::Path::new(wal_path));
            let _ = std::fs::remove_file(&snapshot);
            let _ = std::fs::remove_file(wal_path);
            let map_fn = Arc::new(vindex::JsonKeysMapFn::new(&args.vindex_key_field));
            Some(Arc::new(vindex::VerifiableIndex::with_wal_and_batch_size(
                map_fn, wal_path, 0, 1024,
            )?))
        }
        None => None,
    };

    let config = ImportConfig {
        origin: args.origin.clone(),
        chunk_size: args.chunk_size,
        upload_concurrency: args.upload_concurrency,
        resume: args.resume,
    };

    let start = std::time::Instant::now();
    let summary = bulk_import(
        &db,
        &storage,
        &signer,
        vindex.as_ref(),
        &config,
        entry_iter(&args)?,
    )
    .await?;
    let elapsed = start.elapsed();

    tracing::info!(
        "Import complete: {} entries in {:.1}s ({:.0} entries/s)",
        summary.entries,
        elapsed.as_secs_f64(),
        summary.entries as f64 / elapsed.as_secs_f64().max(0.001),
    );
    tracing::info!(
        "  tree_size={} root={} objects_written={} objects_skipped={}",
        summary.tree_size,
        summary.root_hash.to_hex(),
        summary.objects_written,
        summary.objects_skipped,
    );
    if let Some(vi) = &vindex {
        tracing::info!(
            "  vindex: {} keys, root={}",
            vi.key_count(),
            hex::encode(vi.root_hash())
        );
    }
    tracing::info!("The log server can now be started against this state.");

    Ok(())
}
