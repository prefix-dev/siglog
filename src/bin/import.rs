//! Offline Tessera bootstrap from deterministic JSONL files.
use clap::Parser;
use siglog::api::handlers::MAX_ENTRY_SIZE;
use siglog::error::{Error, Result};
use siglog::import::{bulk_import, ImportConfig, InputSummary};
use siglog::storage::{Database, TileStorage};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "siglog-import",
    about = "Offline bulk bootstrap for an empty Tessera log (stop the server first)"
)]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "STORAGE_BACKEND", default_value = "fs")]
    storage_backend: String,
    #[arg(long, env = "FS_ROOT")]
    fs_root: Option<String>,
    #[arg(long, env = "S3_ENDPOINT")]
    s3_endpoint: Option<String>,
    #[arg(long, env = "S3_BUCKET")]
    s3_bucket: Option<String>,
    #[arg(long, env = "S3_ACCESS_KEY")]
    s3_access_key: Option<String>,
    #[arg(long, env = "S3_SECRET_KEY")]
    s3_secret_key: Option<String>,
    #[arg(long, env = "S3_REGION", default_value = "auto")]
    s3_region: String,
    /// Frozen JSONL files in log order. Repeat for each subdir; stdin is not supported.
    #[arg(long = "jsonl", required = true)]
    jsonl: Vec<PathBuf>,
    /// Entries per chunk (multiple of 256, at most 65536).
    #[arg(long, default_value = "4096")]
    chunk_size: usize,
    #[arg(long, default_value = "16")]
    upload_concurrency: usize,
    /// Resume an interrupted import, verifying existing object contents.
    #[arg(long)]
    resume: bool,
}

/// Bound each line before parsing: malformed inputs cannot allocate unlimited RAM.
fn jsonl(reader: impl BufRead) -> impl Iterator<Item = Result<Vec<u8>>> {
    let mut reader = reader;
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let mut line = Vec::new();
        match reader
            .by_ref()
            .take((MAX_ENTRY_SIZE + 2) as u64)
            .read_until(b'\n', &mut line)
        {
            Ok(0) => {
                done = true;
                return None;
            }
            Err(e) => {
                done = true;
                return Some(Err(e.into()));
            }
            Ok(_) => (),
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let valid = !line.is_empty()
            && line.len() <= MAX_ENTRY_SIZE
            && serde_json::from_slice::<serde_json::Value>(&line).is_ok_and(|v| v.is_object());
        if !valid {
            done = true;
            return Some(Err(Error::InvalidEntry(format!(
                "JSONL requires one nonempty JSON object per line, at most {MAX_ENTRY_SIZE} bytes"
            ))));
        }
        Some(Ok(line))
    })
}

fn entries(paths: &[PathBuf]) -> Result<impl Iterator<Item = Result<Vec<u8>>>> {
    let readers = paths
        .iter()
        .map(|path| File::open(path).map(BufReader::new))
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok(readers.into_iter().flat_map(jsonl))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("siglog=info".parse()?),
        )
        .init();
    let args = Args::parse();
    // Two passes bind resume to the full input, including portions not yet uploaded.
    // The importer rechecks this fingerprint before committing if files change.
    let input = InputSummary::scan(entries(&args.jsonl)?)?;
    tracing::info!(entries = input.entries, sha256 = %input.sha256, "Input preflight complete");
    let db = Database::connect(&args.database_url).await?;
    db.run_migrations().await?;
    let required = |value: &Option<String>, name: &str| -> anyhow::Result<String> {
        value
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing --{name}"))
    };
    let storage = match args.storage_backend.as_str() {
        "fs" => TileStorage::new_fs(&required(&args.fs_root, "fs-root")?)?,
        "s3" => TileStorage::new_s3(
            &required(&args.s3_endpoint, "s3-endpoint")?,
            &required(&args.s3_bucket, "s3-bucket")?,
            &required(&args.s3_access_key, "s3-access-key")?,
            &required(&args.s3_secret_key, "s3-secret-key")?,
            &args.s3_region,
        )?,
        other => anyhow::bail!("unsupported storage backend: {other}"),
    };
    let summary = bulk_import(
        &db,
        &storage,
        &input,
        &ImportConfig {
            chunk_size: args.chunk_size,
            upload_concurrency: args.upload_concurrency,
            resume: args.resume,
        },
        entries(&args.jsonl)?,
    )
    .await?;
    println!(
        "Imported {} entries; root={} ({} objects uploaded, {} verified)",
        summary.tree_size,
        summary.root_hash.to_base64(),
        summary.objects_written,
        summary.objects_verified
    );
    println!("Start siglog --mode tessera with this database/storage to publish the witnessed checkpoint. Vindex rebuilds from entry bundles when enabled.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_jsonl_and_fingerprint() {
        let lf = b"{\"a\":1}\n{\"b\":2}\n";
        let crlf = b"{\"a\":1}\r\n{\"b\":2}";
        assert_eq!(
            InputSummary::scan(jsonl(&lf[..])).unwrap(),
            InputSummary::scan(jsonl(&crlf[..])).unwrap()
        );
        for input in [
            b"\n".to_vec(),
            b"[]\n".to_vec(),
            b"invalid\n".to_vec(),
            vec![b'x'; MAX_ENTRY_SIZE + 100],
        ] {
            assert!(InputSummary::scan(jsonl(input.as_slice())).is_err());
        }
        let max = format!("{{\"x\":\"{}\"}}\r\n", "x".repeat(MAX_ENTRY_SIZE - 8));
        assert_eq!(
            jsonl(max.as_bytes()).next().unwrap().unwrap().len(),
            MAX_ENTRY_SIZE
        );
    }
}
