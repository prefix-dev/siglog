//! Conda repodata ingestion tool.
//!
//! Downloads repodata.json from a conda channel and ingests all entries
//! into a tessera transparency log.
//!
//! Usage:
//!   conda-log-ingest --url https://conda.anaconda.org/robostack-humble/linux-64/repodata.json \
//!                    --log-url http://localhost:2025 \
//!                    --subdir linux-64

use clap::Parser;
use conda_monitor::RepodataEntry;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Conda repodata ingestion tool for tessera transparency logs.
#[derive(Parser, Debug)]
#[command(name = "conda-log-ingest")]
#[command(about = "Ingest conda repodata into a tessera transparency log")]
struct Args {
    /// URL to repodata.json (or path to local file with file:// prefix)
    #[arg(long)]
    url: Option<String>,

    /// Path to local repodata.json file
    #[arg(long, conflicts_with = "url")]
    file: Option<String>,

    /// Export normalized JSONL instead of HTTP submission. Requires a frozen local file.
    #[arg(long, requires = "file", conflicts_with = "dry_run")]
    jsonl_out: Option<PathBuf>,

    /// Bearer token for authenticated HTTP submission.
    #[arg(long, env = "API_KEY")]
    api_key: Option<String>,

    /// Tessera log server URL
    #[arg(long, default_value = "http://localhost:2025")]
    log_url: String,

    /// Subdirectory (platform) for these packages (e.g., linux-64, osx-arm64)
    #[arg(long)]
    subdir: String,

    /// Dry run - don't actually submit entries
    #[arg(long)]
    dry_run: bool,

    /// Number of entries to process (for testing)
    #[arg(long)]
    limit: Option<usize>,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()?;

    // Load repodata
    println!("Loading repodata...");
    let repodata: Value = if let Some(file_path) = &args.file {
        // Parse one subdir in RAM; use a streaming JSON visitor if this exceeds available memory.
        serde_json::from_reader(BufReader::new(std::fs::File::open(file_path)?))?
    } else if let Some(url) = &args.url {
        println!("Fetching from: {}", url);
        let resp = client.get(url).send()?;
        if !resp.status().is_success() {
            anyhow::bail!("Failed to fetch repodata: {}", resp.status());
        }
        resp.json()?
    } else {
        anyhow::bail!("Either --url or --file must be specified");
    };

    if args.jsonl_out.is_some() {
        anyhow::ensure!(repodata.is_object(), "repodata must be an object");
        for field in ["packages", "packages.conda"] {
            anyhow::ensure!(
                repodata.get(field).is_none_or(Value::is_object),
                "repodata {field} must be an object"
            );
        }
        if let Some(subdir) = repodata.pointer("/info/subdir").and_then(Value::as_str) {
            anyhow::ensure!(
                subdir == args.subdir,
                "repodata subdir {subdir} does not match --subdir {}",
                args.subdir
            );
        }
    }

    // Extract both package formats.
    let packages_conda = repodata
        .get("packages.conda")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().collect::<Vec<_>>())
        .unwrap_or_default();

    let packages = repodata
        .get("packages")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().collect::<Vec<_>>())
        .unwrap_or_default();

    // Include both formats, in deterministic filename order.
    let mut all_packages: Vec<_> = packages_conda.into_iter().chain(packages).collect();
    all_packages.sort_by(|a, b| a.0.cmp(b.0));

    let total = if let Some(limit) = args.limit {
        limit.min(all_packages.len())
    } else {
        all_packages.len()
    };

    println!(
        "Found {} packages in repodata (processing {})",
        all_packages.len(),
        total
    );

    if let Some(path) = &args.jsonl_out {
        export_jsonl(&all_packages[..total], &args.subdir, path)?;
        println!("Exported {total} entries to {}", path.display());
        return Ok(());
    }

    // Setup progress bar
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut success_count = 0;
    let mut skip_count = 0;
    let mut error_count = 0;
    let mut indices: HashMap<String, u64> = HashMap::new();

    for (filename, entry) in all_packages.into_iter().take(total) {
        pb.set_message(filename.to_string());

        // Normalize entry using the library
        let Some(normalized) = RepodataEntry::from_repodata(filename, &args.subdir, entry, None)
        else {
            skip_count += 1;
            pb.inc(1);
            continue;
        };

        let json_bytes = normalized.to_normalized_json();

        if args.dry_run {
            // Just print first few for verification
            if success_count < 3 {
                println!(
                    "\n[DRY RUN] Would submit: {}",
                    String::from_utf8_lossy(&json_bytes)
                );
            }
            success_count += 1;
            pb.inc(1);
            continue;
        }

        // Submit to log
        let add_url = format!("{}/add", args.log_url.trim_end_matches('/'));
        let mut request = client.post(&add_url).body(json_bytes);
        if let Some(key) = &args.api_key {
            request = request.bearer_auth(key);
        }
        match request.send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text() {
                        if let Ok(idx) = text.trim().parse::<u64>() {
                            indices.insert(filename.to_string(), idx);
                        }
                    }
                    success_count += 1;
                } else {
                    error_count += 1;
                    if error_count <= 5 {
                        eprintln!("\nError submitting {}: {}", filename, resp.status());
                    }
                }
            }
            Err(e) => {
                error_count += 1;
                if error_count <= 5 {
                    eprintln!("\nError submitting {}: {}", filename, e);
                }
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Done!");

    println!("\n=== Ingestion Summary ===");
    println!("Subdir: {}", args.subdir);
    println!("Submitted: {}", success_count);
    println!("Skipped: {}", skip_count);
    println!("Errors: {}", error_count);

    if !indices.is_empty() {
        println!("\nSample indices:");
        for (filename, idx) in indices.iter().take(5) {
            println!("  {} -> index {}", filename, idx);
        }
    }

    // Print verification example
    if success_count > 0 && !args.dry_run {
        println!("\n=== Verification ===");
        println!("Wait a few seconds for entries to be integrated, then verify with:");
        println!(
            "  conda-log-verify --log-url {} --log-origin <trusted-origin> --log-key <trusted-note-key> --subdir {} --filename <package>.conda",
            args.log_url, args.subdir
        );
    }

    anyhow::ensure!(error_count == 0, "{error_count} submissions failed");
    Ok(())
}

/// Publish the export atomically; missing fields never silently drop packages.
fn export_jsonl(packages: &[(&String, &Value)], subdir: &str, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!packages.is_empty(), "no packages to export");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = BufWriter::new(tmp.as_file_mut());
        for (filename, entry) in packages {
            let normalized = RepodataEntry::from_repodata(filename, subdir, entry, None)
                .ok_or_else(|| anyhow::anyhow!("cannot normalize {filename}: missing/invalid required fields (including sha256)"))?;
            anyhow::ensure!(
                hex::decode(&normalized.sha256).is_ok_and(|hash| hash.len() == 32),
                "invalid sha256 for {filename}"
            );
            let data = normalized.to_normalized_json();
            anyhow::ensure!(
                data.len() <= siglog::api::handlers::MAX_ENTRY_SIZE,
                "entry too large: {filename}"
            );
            writer.write_all(&data)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)?;
    Ok(())
}
