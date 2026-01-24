//! Conda repodata verification tool.
//!
//! Verifies that a repodata entry exists in the transparency log.
//!
//! Usage:
//!   conda-log-verify --log-url http://localhost:2025 \
//!                    --subdir linux-64 \
//!                    --filename numpy-1.26.0-py311h123_0.conda \
//!                    --repodata-url https://conda.anaconda.org/robostack-humble/linux-64/repodata.json

use clap::Parser;
use conda_monitor::RepodataEntry;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Conda repodata verification tool for tessera transparency logs.
#[derive(Parser, Debug)]
#[command(name = "conda-log-verify")]
#[command(about = "Verify conda repodata entries in a tessera transparency log")]
struct Args {
    /// Tessera log server URL
    #[arg(long, default_value = "http://localhost:2025")]
    log_url: String,

    /// Subdirectory (platform) for this package
    #[arg(long)]
    subdir: String,

    /// Filename to verify
    #[arg(long)]
    filename: String,

    /// URL to repodata.json for fetching the entry
    #[arg(long)]
    repodata_url: Option<String>,

    /// Path to local repodata.json
    #[arg(long)]
    repodata_file: Option<String>,

    /// Show verbose output
    #[arg(long, short)]
    verbose: bool,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,
}

/// VIndex lookup response
#[derive(Debug, Deserialize)]
struct LookupResponse {
    indices: Vec<u64>,
    tree_size: u64,
    found: bool,
    proof: Vec<ProofNode>,
    root_hash: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ProofNode {
    label_bit_len: u32,
    label_path: String,
    hash: String,
}

/// Compute RFC 6962 leaf hash
fn compute_leaf_hash(entry_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // Leaf prefix
    hasher.update(entry_bytes);
    hasher.finalize().into()
}

/// Decode entry bundle and extract entry at offset
fn decode_entry_bundle(bundle: &[u8], offset: usize) -> Option<Vec<u8>> {
    let mut pos = 0;
    let mut entry_idx = 0;

    while pos + 2 <= bundle.len() {
        let len = u16::from_be_bytes([bundle[pos], bundle[pos + 1]]) as usize;
        pos += 2;

        if pos + len > bundle.len() {
            return None;
        }

        if entry_idx == offset {
            return Some(bundle[pos..pos + len].to_vec());
        }

        pos += len;
        entry_idx += 1;
    }

    None
}

/// Format a number in N-format (groups of 3 digits with x prefix)
fn format_n(n: u64) -> String {
    if n < 1000 {
        format!("{:03}", n)
    } else {
        let suffix = format!("{:03}", n % 1000);
        let prefix = format_n(n / 1000);
        format!("x{}/{}", prefix, suffix)
    }
}

/// Get the entry bundle path for a given log index and tree size
fn get_entry_bundle_path(log_index: u64, tree_size: u64) -> String {
    let tile_index = log_index / 256;
    let tile_start = tile_index * 256;
    let entries_in_tile = if tile_start + 256 <= tree_size {
        256 // Full tile
    } else {
        tree_size - tile_start // Partial tile
    };

    let base = format_n(tile_index);
    if entries_in_tile < 256 {
        format!("{}.p/{}", base, entries_in_tile)
    } else {
        base
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()?;

    println!("=== Conda Transparency Log Verification ===\n");
    println!("Log URL: {}", args.log_url);
    println!("Filename: {}", args.filename);
    println!("Subdir: {}", args.subdir);

    // Step 1: Compute index key
    let mut key_hasher = Sha256::new();
    key_hasher.update(args.filename.as_bytes());
    let index_key: [u8; 32] = key_hasher.finalize().into();
    let index_key_hex = hex::encode(index_key);

    if args.verbose {
        println!("\nIndex key (SHA256 of filename): {}", index_key_hex);
    }

    // Step 2: Query vindex
    println!("\n[1/4] Querying verifiable index...");
    let lookup_url = format!(
        "{}/vindex/lookup/{}",
        args.log_url.trim_end_matches('/'),
        index_key_hex
    );

    let lookup_resp: LookupResponse = client.get(&lookup_url).send()?.json()?;

    if !lookup_resp.found {
        println!("\n[X] VERIFICATION FAILED: Filename not found in log");
        println!("   The package '{}' has not been logged.", args.filename);
        return Ok(());
    }

    println!(
        "   Found {} log entries for this filename",
        lookup_resp.indices.len()
    );
    println!("   Log indices: {:?}", lookup_resp.indices);
    println!("   Tree size: {}", lookup_resp.tree_size);

    if args.verbose {
        println!("   Index root hash: {}", lookup_resp.root_hash);
        println!("   Proof nodes: {}", lookup_resp.proof.len());
    }

    // Step 3: Load repodata entry if provided
    let expected_hash: Option<[u8; 32]> = if args.repodata_url.is_some()
        || args.repodata_file.is_some()
    {
        println!("\n[2/4] Loading repodata entry...");

        let repodata: Value = if let Some(path) = &args.repodata_file {
            let content = std::fs::read_to_string(path)?;
            serde_json::from_str(&content)?
        } else if let Some(url) = &args.repodata_url {
            println!("   Fetching from: {}", url);
            client.get(url).send()?.json()?
        } else {
            unreachable!()
        };

        // Find entry in packages or packages.conda
        let entry = repodata
            .get("packages")
            .and_then(|p| p.get(&args.filename))
            .or_else(|| {
                repodata
                    .get("packages.conda")
                    .and_then(|p| p.get(&args.filename))
            });

        if let Some(entry) = entry {
            let normalized =
                RepodataEntry::from_repodata(&args.filename, &args.subdir, entry, None)
                    .ok_or_else(|| anyhow::anyhow!("Failed to normalize repodata entry"))?;

            let json_bytes = normalized.to_normalized_json();

            if args.verbose {
                println!(
                    "   Normalized JSON: {}",
                    String::from_utf8_lossy(&json_bytes)
                );
            }

            let leaf_hash = compute_leaf_hash(&json_bytes);
            println!("   Leaf hash: {}", hex::encode(leaf_hash));

            Some(leaf_hash)
        } else {
            println!("   [!] Entry not found in repodata");
            None
        }
    } else {
        println!("\n[2/4] Skipping repodata verification (no --repodata-url or --repodata-file)");
        None
    };

    // Step 4: Fetch entries from log and verify
    println!("\n[3/4] Fetching log entries...");

    let mut found_match = false;
    let mut verified_entries = Vec::new();

    for &log_index in &lookup_resp.indices {
        let offset = (log_index % 256) as usize;
        let path = get_entry_bundle_path(log_index, lookup_resp.tree_size);

        let entries_url = format!(
            "{}/tile/entries/{}",
            args.log_url.trim_end_matches('/'),
            path
        );

        if args.verbose {
            println!(
                "   Fetching bundle at index {} (path: {}, offset {})",
                log_index, path, offset
            );
        }

        let bundle_resp = client.get(&entries_url).send()?;
        if !bundle_resp.status().is_success() {
            println!(
                "   [!] Failed to fetch entry bundle: {}",
                bundle_resp.status()
            );
            continue;
        }

        let bundle = bundle_resp.bytes()?;

        if let Some(entry_bytes) = decode_entry_bundle(&bundle, offset) {
            let entry_leaf_hash = compute_leaf_hash(&entry_bytes);

            // Parse the entry to show info
            if let Ok(entry_json) = serde_json::from_slice::<Value>(&entry_bytes) {
                let name = entry_json
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let version = entry_json
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");

                verified_entries.push((
                    log_index,
                    name.to_string(),
                    version.to_string(),
                    entry_leaf_hash,
                ));

                if args.verbose {
                    println!(
                        "   Entry {}: {} {} (hash: {})",
                        log_index,
                        name,
                        version,
                        hex::encode(entry_leaf_hash)
                    );
                }
            }

            // Check if this matches our expected hash
            if let Some(expected) = expected_hash {
                if entry_leaf_hash == expected {
                    found_match = true;
                    println!("   [OK] Found matching entry at index {}", log_index);
                }
            }
        } else {
            println!("   [!] Could not decode entry at offset {}", offset);
        }
    }

    // Step 5: Fetch and display checkpoint
    println!("\n[4/4] Fetching checkpoint...");
    let checkpoint_url = format!("{}/checkpoint", args.log_url.trim_end_matches('/'));
    let checkpoint = client.get(&checkpoint_url).send()?.text()?;

    let lines: Vec<&str> = checkpoint.lines().collect();
    if lines.len() >= 3 {
        println!("   Origin: {}", lines[0]);
        println!("   Tree size: {}", lines[1]);
        println!("   Root hash: {}", lines[2]);

        // Count signatures
        let sig_count = lines.iter().filter(|l| l.starts_with("— ")).count();
        println!("   Signatures: {}", sig_count);

        if args.verbose {
            for line in lines.iter().filter(|l| l.starts_with("— ")) {
                println!("     {}", line);
            }
        }
    }

    // Final summary
    println!("\n=== Verification Summary ===");
    println!("Filename: {}", args.filename);
    println!("Log entries found: {}", lookup_resp.indices.len());

    if !verified_entries.is_empty() {
        println!("\nLogged versions:");
        for (idx, name, version, hash) in &verified_entries {
            println!(
                "  [{}] {}-{} ({})",
                idx,
                name,
                version,
                &hex::encode(hash)[..16]
            );
        }
    }

    if expected_hash.is_some() {
        if found_match {
            println!("\n[OK] VERIFICATION PASSED");
            println!("   The repodata entry matches an entry in the transparency log.");
            println!("   This confirms the mirror is serving the officially logged metadata.");
        } else {
            println!("\n[X] VERIFICATION FAILED");
            println!("   The repodata entry does not match any logged entry.");
            println!("   This could indicate:");
            println!("   - The repodata has been modified (possibly a patch not yet logged)");
            println!("   - The mirror is serving tampered data");
            println!("   - The entry was logged with different normalization");
        }
    } else {
        println!("\n[OK] Entry exists in log (full verification requires --repodata-url or --repodata-file)");
    }

    Ok(())
}
