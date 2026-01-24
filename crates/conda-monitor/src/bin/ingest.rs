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
    #[arg(long)]
    file: Option<String>,

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
        let content = std::fs::read_to_string(file_path)?;
        serde_json::from_str(&content)?
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

    // Extract packages - prefer .conda over .tar.bz2 since .conda has sha256
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

    // Process .conda packages first (they have sha256), then .tar.bz2
    let all_packages: Vec<_> = packages_conda.into_iter().chain(packages).collect();

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
        let Some(normalized) =
            RepodataEntry::from_repodata(filename, &args.subdir, entry, None)
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
        match client.post(&add_url).body(json_bytes.clone()).send() {
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
            "  conda-log-verify --log-url {} --subdir {} --filename <package>.conda",
            args.log_url, args.subdir
        );
    }

    Ok(())
}
