//! Verify repodata inclusion against a pinned log key and origin.
use clap::Parser;
use conda_monitor::RepodataEntry;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use siglog::{
    checkpoint::CosignedCheckpoint,
    client::LogClient,
    witness::{CheckpointVerifier, LogConfig},
};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "conda-log-verify",
    about = "Verify conda metadata inclusion against a trusted log checkpoint"
)]
struct Args {
    #[arg(long, default_value = "http://localhost:2025")]
    log_url: String,
    /// Trusted checkpoint origin (not obtained from the server).
    #[arg(long)]
    log_origin: String,
    /// Trusted note verification key: name+hash+base64(algorithm+public-key).
    #[arg(long)]
    log_key: String,
    #[arg(long)]
    subdir: String,
    #[arg(long)]
    filename: String,
    #[arg(long, conflicts_with = "repodata_file")]
    repodata_url: Option<String>,
    #[arg(long)]
    repodata_file: Option<String>,
    #[arg(long, short)]
    verbose: bool,
    #[arg(long, default_value = "30")]
    timeout: u64,
    /// Maximum bytes accepted from a remote repodata endpoint.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_repodata_bytes: usize,
}

#[derive(Deserialize)]
struct LookupResponse {
    indices: Vec<u64>,
    found: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    verify(Args::parse()).await
}

async fn verify(args: Args) -> anyhow::Result<()> {
    let log = LogClient::with_timeout(&args.log_url, Duration::from_secs(args.timeout))?;
    let config = LogConfig::new(args.log_origin, &args.log_key)?;
    let text = log.read("checkpoint", 1024 * 1024).await?;
    let signed = CosignedCheckpoint::from_text(std::str::from_utf8(&text)?)?;
    CheckpointVerifier::new(config).verify(&signed)?;
    let cp = &signed.checkpoint;
    anyhow::ensure!(cp.size.value() <= i64::MAX as u64, "tree too large");

    // An unsigned lookup is only a discovery hint, not evidence of presence,
    // absence, or completeness. All successful claims require inclusion proofs.
    let key = hex::encode(Sha256::digest(args.filename.as_bytes()));
    let lookup: LookupResponse = serde_json::from_slice(
        &log.read(&format!("vindex/lookup/{key}"), 1024 * 1024)
            .await?,
    )?;
    anyhow::ensure!(
        lookup.found && !lookup.indices.is_empty(),
        "VERIFICATION FAILED: no candidates returned (not proof of absence)"
    );
    anyhow::ensure!(lookup.indices.len() <= 1000, "too many lookup candidates");

    let repodata: Option<Value> = if let Some(path) = args.repodata_file {
        Some(serde_json::from_reader(std::fs::File::open(path)?)?)
    } else if let Some(url) = args.repodata_url {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .build()?;
        Some(serde_json::from_slice(
            &siglog::client::bounded_body(
                client.get(url).send().await?.error_for_status()?,
                args.max_repodata_bytes,
            )
            .await?,
        )?)
    } else {
        None
    };
    let expected = repodata
        .as_ref()
        .map(|repodata| -> anyhow::Result<Vec<u8>> {
            let entry = repodata
                .get("packages")
                .and_then(|p| p.get(&args.filename))
                .or_else(|| {
                    repodata
                        .get("packages.conda")
                        .and_then(|p| p.get(&args.filename))
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("VERIFICATION FAILED: entry missing from repodata")
                })?;
            Ok(
                RepodataEntry::from_repodata(&args.filename, &args.subdir, entry, None)
                    .ok_or_else(|| anyhow::anyhow!("invalid repodata entry"))?
                    .to_normalized_json(),
            )
        })
        .transpose()?;

    let mut matched = false;
    for index in lookup.indices {
        anyhow::ensure!(
            index < cp.size.value(),
            "lookup index outside signed checkpoint; retry if the index is ahead of publication"
        );
        let bundle = log.bundle(index / 256, cp.size.value()).await?;
        let entry = bundle.entries[(index % 256) as usize].as_bytes();
        log.verify_entry(entry, index, cp).await?;
        let value: Value = serde_json::from_slice(entry)?;
        if value.get("filename").and_then(Value::as_str) != Some(&args.filename)
            || value.get("subdir").and_then(Value::as_str) != Some(&args.subdir)
        {
            continue;
        }
        if expected
            .as_ref()
            .is_none_or(|expected| expected.as_slice() == entry)
        {
            matched = true;
            if args.verbose {
                println!(
                    "Authenticated inclusion at index {index}, tree size {}",
                    cp.size.value()
                );
            }
        }
    }
    anyhow::ensure!(
        matched,
        "VERIFICATION FAILED: no authenticated matching entry"
    );
    if expected.is_some() {
        println!("VERIFICATION PASSED: metadata matches an authenticated log entry");
    } else {
        println!("Authenticated entry inclusion; metadata comparison not requested");
    }
    Ok(())
}
