//! Siglog - A minimal Tessera-compatible transparency log server.

use clap::Parser;
use siglog::api::handlers::{self, AppState};
use siglog::api::{self, rate_limit, Mode};
use siglog::checkpoint::CheckpointSigner;
use siglog::sequencer::{Sequencer, SequencerConfig};
use siglog::storage::{Database, TileStorage};
use siglog::vindex;
use siglog::worker::{self, WorkerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

/// Siglog - A minimal Tessera-compatible transparency log server.
#[derive(Parser, Debug)]
#[command(name = "siglog")]
#[command(about = "A minimal Tessera-compatible transparency log server")]
struct Args {
    /// API mode. Use separate databases and tile storage for different modes.
    #[arg(long, env = "LOG_MODE", value_enum, default_value = "tessera")]
    mode: Mode,

    /// Database URL (PostgreSQL: postgres://... or SQLite: sqlite:./path.db)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "sqlite:./siglog.db?mode=rwc"
    )]
    database_url: String,

    /// Storage backend: "s3" or "fs"
    #[arg(long, env = "STORAGE_BACKEND", default_value = "fs")]
    storage_backend: String,

    /// Filesystem storage root directory (when storage_backend=fs)
    #[arg(long, env = "FS_ROOT")]
    fs_root: Option<String>,

    /// S3/R2 endpoint URL (when storage_backend=s3)
    #[arg(long, env = "S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3/R2 bucket name (when storage_backend=s3)
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

    /// Log origin string (e.g., "example.com/log")
    #[arg(long, env = "LOG_ORIGIN")]
    origin: String,

    /// Ed25519 private key in note format (PRIVATE+KEY+name+base64)
    #[arg(long, env = "LOG_PRIVATE_KEY")]
    private_key: String,

    /// Server listen address
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8080")]
    listen: String,

    /// Checkpoint publish interval in seconds
    #[arg(long, env = "CHECKPOINT_INTERVAL", default_value = "1")]
    checkpoint_interval: u64,

    /// Max batch size for sequencing
    #[arg(long, env = "BATCH_MAX_SIZE", default_value = "256")]
    batch_max_size: usize,

    /// Max batch age in milliseconds
    #[arg(long, env = "BATCH_MAX_AGE_MS", default_value = "1000")]
    batch_max_age_ms: u64,

    /// Witness private keys in note format (comma-separated for multiple witnesses).
    /// Format: PRIVATE+KEY+name+base64,PRIVATE+KEY+name2+base64
    /// These are "fake" witnesses that run in-process for testing.
    #[arg(long, env = "WITNESS_KEYS")]
    witness_keys: Option<String>,

    /// External witness URLs (comma-separated).
    /// Format: name=url,name2=url2
    /// Example: --external-witnesses "witness1=http://localhost:8081,monitor=http://localhost:8082"
    #[arg(long, env = "EXTERNAL_WITNESSES")]
    external_witnesses: Option<String>,

    /// Pinned public note keys for external witnesses (comma-separated).
    #[arg(long, env = "EXTERNAL_WITNESS_KEYS")]
    external_witness_keys: Option<String>,

    /// Minimum external witness signatures required (default: all).
    #[arg(long, env = "WITNESS_QUORUM")]
    witness_quorum: Option<usize>,

    /// API key for authenticating write requests (optional).
    /// When set, write endpoints require an Authorization: Bearer <key> header.
    #[arg(long, env = "API_KEY")]
    api_key: Option<String>,

    /// Allow unauthenticated writes.
    ///
    /// This is intended for local development and test deployments.
    #[arg(long, env = "ALLOW_PUBLIC_WRITES")]
    allow_public_writes: bool,

    /// Enable verifiable index (vindex) for key lookups.
    #[arg(long, env = "VINDEX_ENABLED")]
    vindex_enabled: bool,

    /// JSON field name to extract keys from for vindex.
    /// Entries should be JSON objects with this field containing a string or array of strings.
    #[arg(long, env = "VINDEX_KEY_FIELD", default_value = "name")]
    vindex_key_field: String,

    /// Path to vindex WAL file for persistence (optional).
    #[arg(long, env = "VINDEX_WAL_PATH")]
    vindex_wal_path: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("siglog=info".parse()?)
                .add_directive("tower_http=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Starting Siglog");
    siglog::checkpoint::Origin::new(args.origin.clone())?;
    tracing::info!("Origin: {}", args.origin);
    tracing::info!("Listen: {}", args.listen);

    if args.api_key.is_none() && !args.allow_public_writes {
        anyhow::bail!(
            "API_KEY is required for writes. Set --allow-public-writes for local development."
        );
    }

    // Initialize database
    tracing::info!("Connecting to database...");
    let db = Database::connect(&args.database_url).await?;
    db.run_migrations().await?;
    db.ensure_mode(args.mode).await?;
    tracing::info!(mode = args.mode.as_str(), "API mode selected");
    tracing::info!("Database connected and migrations complete");

    // Initialize storage based on backend selection
    let storage = match args.storage_backend.as_str() {
        "fs" => {
            let root = args
                .fs_root
                .clone()
                .or_else(|| std::env::var("STORAGE_PATH").ok())
                .or_else(|| Some("./tiles".to_string()))
                .as_ref()
                .expect("filesystem storage root default missing")
                .to_string();
            tracing::info!("Initializing filesystem storage at {}...", root);
            TileStorage::new_fs(&root)?
        }
        "s3" => {
            let endpoint = args.s3_endpoint.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--s3-endpoint is required when storage_backend=s3")
            })?;
            let bucket = args.s3_bucket.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--s3-bucket is required when storage_backend=s3")
            })?;
            let access_key = args.s3_access_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--s3-access-key is required when storage_backend=s3")
            })?;
            let secret_key = args.s3_secret_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--s3-secret-key is required when storage_backend=s3")
            })?;
            tracing::info!("Initializing S3 storage at {}...", endpoint);
            TileStorage::new_s3(endpoint, bucket, access_key, secret_key, &args.s3_region)?
        }
        other => {
            anyhow::bail!("Unknown storage backend: {}. Use 'fs' or 's3'.", other);
        }
    };
    tracing::info!("Storage initialized");

    // Initialize signer
    let signer = Arc::new(CheckpointSigner::from_note_key(&args.private_key)?);
    tracing::info!("Checkpoint signer initialized: {}", signer.name());

    // Initialize in-process witnesses (for testing/development)
    let witnesses: Vec<Arc<CheckpointSigner>> = if let Some(witness_keys) = &args.witness_keys {
        witness_keys
            .split(',')
            .filter(|k| !k.trim().is_empty())
            .map(|key| {
                let signer =
                    CheckpointSigner::from_note_key(key.trim()).expect("invalid witness key");
                tracing::info!("In-process witness initialized: {}", signer.name());
                Arc::new(signer)
            })
            .collect()
    } else {
        Vec::new()
    };
    tracing::info!("{} in-process witnesses configured", witnesses.len());

    // Parse external witness URLs
    let external_witnesses: Vec<worker::ExternalWitness> =
        if let Some(ext_witnesses) = &args.external_witnesses {
            ext_witnesses
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '=').collect();
                    anyhow::ensure!(
                        parts.len() == 2,
                        "invalid external witness format: expected name=url"
                    );
                    let key = args
                        .external_witness_keys
                        .as_deref()
                        .unwrap_or("")
                        .split(',')
                        .map(str::trim)
                        .find(|key| key.split('+').next() == Some(parts[0]))
                        .ok_or_else(|| {
                            anyhow::anyhow!("missing pinned public key for witness {}", parts[0])
                        })?;
                    let witness = worker::ExternalWitness::new(key, parts[1])?;
                    tracing::info!(
                        "External witness configured: {} -> {}",
                        witness.name,
                        witness.url
                    );
                    Ok(witness)
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
    tracing::info!("{} external witnesses configured", external_witnesses.len());

    anyhow::ensure!(
        args.witness_quorum.unwrap_or(external_witnesses.len()) <= external_witnesses.len(),
        "WITNESS_QUORUM exceeds configured external witnesses"
    );
    let mut witness_names = std::collections::HashSet::new();
    let mut witness_keys = std::collections::HashSet::new();
    for witness in &external_witnesses {
        anyhow::ensure!(
            witness_names.insert(&witness.name) && witness_keys.insert(witness.public_key()),
            "external witnesses must have distinct names and public keys"
        );
    }

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Initialize sequencer
    let sequencer_config = SequencerConfig {
        batch_max_size: args.batch_max_size,
        batch_max_age: Duration::from_millis(args.batch_max_age_ms),
        ..Default::default()
    };
    let (sequencer, sequencer_task) = Sequencer::new(db.clone(), sequencer_config);

    // Spawn sequencer
    let sequencer_handle = tokio::spawn(sequencer_task);

    // Configure workers
    let worker_config = WorkerConfig {
        integration_interval: Duration::from_millis(100),
        integration_batch_size: 1024,
        checkpoint_interval: Duration::from_secs(args.checkpoint_interval),
        origin: args.origin.clone(),
        witness_quorum: args.witness_quorum,
    };

    // Initialize vindex if enabled (before spawning workers)
    let vindex = if args.vindex_enabled {
        tracing::info!(
            "Initializing vindex with key field: {}",
            args.vindex_key_field
        );
        let map_fn = Arc::new(vindex::JsonKeysMapFn::new(&args.vindex_key_field));

        let log_state = db.get_log_state().await?;
        let expected_tree_size = log_state.integrated_size.value();

        let vi = if let Some(wal_path) = &args.vindex_wal_path {
            // Validate the WAL against the database state after a crash.
            tracing::info!(
                "Vindex WAL path: {}, expected tree size from DB: {}",
                wal_path,
                expected_tree_size
            );
            match vindex::VerifiableIndex::with_wal(map_fn.clone(), wal_path, expected_tree_size) {
                Ok(vi) => vi,
                Err(e) => {
                    tracing::warn!("Vindex recovery failed ({e}); rebuilding from entry bundles");
                    vindex::VerifiableIndex::rebuild_from_storage(
                        map_fn,
                        wal_path,
                        expected_tree_size,
                        &storage,
                    )
                    .await?
                }
            }
        } else {
            if expected_tree_size > 0 {
                anyhow::bail!(
                    "VINDEX_WAL_PATH is required when enabling vindex for an existing log \
                     (integrated_size={})",
                    expected_tree_size
                );
            }
            vindex::VerifiableIndex::new(map_fn)
        };
        tracing::info!(
            "Vindex initialized with {} keys from {} entries",
            vi.key_count(),
            vi.tree_size()
        );
        Some(Arc::new(vi))
    } else {
        None
    };

    // Spawn integration worker (with optional vindex)
    let integration_handle = tokio::spawn(worker::run_integration_worker(
        db.clone(),
        storage.clone(),
        worker_config.clone(),
        vindex.clone(),
        shutdown_rx.clone(),
    ));

    // Spawn checkpoint worker
    let checkpoint_handle = tokio::spawn(worker::run_checkpoint_worker(
        db.clone(),
        storage.clone(),
        signer.clone(),
        witnesses,
        external_witnesses,
        worker_config,
        shutdown_rx.clone(),
    ));

    // Build application state
    let mut state = AppState::new(storage, sequencer, db.clone());
    if let Some(api_key) = args.api_key {
        tracing::info!("API key authentication enabled for write endpoints");
        state = state.with_api_key(api_key);
    } else {
        tracing::warn!("Public unauthenticated writes are enabled for write endpoints");
    }
    if let Some(ref vi) = vindex {
        state = state.with_vindex(vi.clone());
    }
    let state = Arc::new(state);

    // Configure rate limiting
    let rate_limit_config = Arc::new(
        GovernorConfigBuilder::default()
            .period(Duration::from_secs(1) / rate_limit::RATE_LIMIT_PER_SECOND as u32)
            .burst_size(rate_limit::RATE_LIMIT_BURST_SIZE)
            .finish()
            .expect("failed to create rate limit config"),
    );
    let limiter = rate_limit_config.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });
    let governor_layer =
        GovernorLayer::new(rate_limit_config).error_handler(rate_limit::rate_limit_error_handler);
    tracing::info!(
        "Rate limiting enabled: {} req/s per IP, burst {}",
        rate_limit::RATE_LIMIT_PER_SECOND,
        rate_limit::RATE_LIMIT_BURST_SIZE
    );

    // Build router
    let mut app = api::router(args.mode, signer);

    // Add vindex routes if enabled
    if vindex.is_some() {
        app = app
            .route(
                "/vindex/lookup/{hash}",
                axum::routing::get(handlers::vindex_lookup),
            )
            .route(
                "/vindex/lookup/key/{key}",
                axum::routing::get(handlers::vindex_lookup_key),
            )
            .route("/vindex/stats", axum::routing::get(handlers::vindex_stats));
        tracing::info!("Vindex API enabled at /vindex/lookup/*");
    }

    let app = app
        .with_state(state)
        .layer(governor_layer)
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                )
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        );

    // Start server
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("Server listening on {}", args.listen);
    let read_prefix = if args.mode == Mode::Rekor {
        "api/v2/"
    } else {
        ""
    };
    tracing::info!(
        "Environment variables for accessing this log:\n\
         export WRITE_URL=http://{}/\n\
         export READ_URL=http://{}/{}",
        args.listen,
        args.listen,
        read_prefix
    );

    // Handle shutdown
    let shutdown_signal = async move {
        siglog::shutdown::shutdown_signal().await;
        tracing::info!("Shutdown signal received");
        let _ = shutdown_tx.send(true);
    };

    let mut supervisor_shutdown = shutdown_rx;
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = supervisor_shutdown.changed() => (),
            r = sequencer_handle => { tracing::error!("sequencer exited: {r:?}"); std::process::exit(1); },
            r = integration_handle => { tracing::error!("integration worker exited: {r:?}"); std::process::exit(1); },
            r = checkpoint_handle => { tracing::error!("checkpoint worker exited: {r:?}"); std::process::exit(1); },
        }
    });

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await?;

    tracing::info!("Server stopped");
    Ok(())
}
