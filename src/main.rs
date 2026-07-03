//! Siglog - A minimal Tessera-compatible transparency log server.

use axum::extract::DefaultBodyLimit;
use clap::Parser;
use siglog::api::handlers::{self, AppState};
use siglog::api::rate_limit;
use siglog::checkpoint::signer::Origin;
use siglog::checkpoint::CheckpointSigner;
use siglog::sequencer::{Sequencer, SequencerConfig};
use siglog::storage::{Database, TileStorage};
use siglog::vindex;
use siglog::worker::{self, WorkerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};

/// Siglog - A minimal Tessera-compatible transparency log server.
#[derive(Parser, Debug)]
#[command(name = "siglog")]
#[command(about = "A minimal Tessera-compatible transparency log server")]
struct Args {
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

    /// External witnesses (comma-separated).
    /// Format: name=url=vkey where vkey is the witness's note-format
    /// verification key (name+hash+base64). Cosignatures are verified
    /// against this pinned key before counting toward the quorum.
    /// Example: --external-witnesses "w1=http://localhost:8081=w1+deadbeef+AQ..."
    #[arg(long, env = "EXTERNAL_WITNESSES")]
    external_witnesses: Option<String>,

    /// Minimum number of external witness cosignatures required to publish
    /// a checkpoint. Defaults to all configured external witnesses.
    #[arg(long, env = "WITNESS_QUORUM")]
    witness_quorum: Option<usize>,

    /// API key for authenticating write requests (optional).
    /// When set, the /add endpoint requires an Authorization: Bearer <key> header.
    #[arg(long, env = "API_KEY")]
    api_key: Option<String>,

    /// Allow unauthenticated writes to /add.
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
    tracing::info!("Origin: {}", args.origin);
    tracing::info!("Listen: {}", args.listen);

    if args.api_key.is_none() && !args.allow_public_writes {
        anyhow::bail!(
            "API_KEY is required for /add writes. Set --allow-public-writes for local development."
        );
    }

    // Validate the origin up front so a bad value fails startup instead of
    // killing the checkpoint worker after the server is already accepting
    // writes.
    Origin::new(args.origin.clone())
        .map_err(|e| anyhow::anyhow!("invalid LOG_ORIGIN '{}': {}", args.origin, e))?;

    // Initialize database
    tracing::info!("Connecting to database...");
    let db = Database::connect(&args.database_url).await?;
    db.run_migrations().await?;
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
    let mut witnesses: Vec<Arc<CheckpointSigner>> = Vec::new();
    if let Some(witness_keys) = &args.witness_keys {
        for key in witness_keys.split(',').filter(|k| !k.trim().is_empty()) {
            let signer = CheckpointSigner::from_note_key(key.trim())
                .map_err(|e| anyhow::anyhow!("invalid in-process witness key: {}", e))?;
            tracing::info!("In-process witness initialized: {}", signer.name());
            witnesses.push(Arc::new(signer));
        }
    }
    tracing::info!("{} in-process witnesses configured", witnesses.len());

    // Parse external witnesses (name=url=vkey)
    let mut external_witnesses: Vec<worker::ExternalWitness> = Vec::new();
    if let Some(ext_witnesses) = &args.external_witnesses {
        for s in ext_witnesses.split(',').filter(|s| !s.trim().is_empty()) {
            let parts: Vec<&str> = s.trim().splitn(3, '=').collect();
            if parts.len() != 3 {
                anyhow::bail!(
                    "invalid external witness format: expected 'name=url=vkey', got '{}'. \
                     The verification key is required so cosignatures can be verified.",
                    s
                );
            }
            let witness = worker::ExternalWitness::new(parts[0], parts[1], parts[2])
                .map_err(|e| anyhow::anyhow!("invalid external witness '{}': {}", parts[0], e))?;
            tracing::info!(
                "External witness configured: {} -> {}",
                witness.name,
                witness.url
            );
            external_witnesses.push(witness);
        }
    }
    tracing::info!("{} external witnesses configured", external_witnesses.len());

    if let Some(q) = args.witness_quorum {
        if q > external_witnesses.len() {
            anyhow::bail!(
                "WITNESS_QUORUM ({}) exceeds the number of configured external witnesses ({})",
                q,
                external_witnesses.len()
            );
        }
        tracing::info!(
            "Checkpoint publication quorum: {}/{} external witnesses",
            q,
            external_witnesses.len()
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

    // Spawn sequencer (supervised below: if it dies, the process exits so
    // the orchestrator can restart it, instead of silently acking writes
    // that never get sequenced).
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
            // Validate the snapshot + WAL against the database state after a
            // crash. If the on-disk state is unusable (missing, corrupted, or
            // behind the database), rebuild it from the log's entry bundles —
            // the log itself is the source of truth for the index.
            tracing::info!(
                "Vindex WAL path: {}, expected tree size from DB: {}",
                wal_path,
                expected_tree_size
            );
            match vindex::VerifiableIndex::with_wal(map_fn.clone(), wal_path, expected_tree_size) {
                Ok(vi) => vi,
                Err(e) => {
                    tracing::warn!("Vindex state unusable ({}); rebuilding from log storage", e);
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
        tracing::info!("API key authentication enabled for /add endpoint");
        state = state.with_api_key(api_key);
    } else {
        tracing::warn!("Public unauthenticated writes are enabled for /add endpoint");
    }
    if let Some(ref vi) = vindex {
        state = state.with_vindex(vi.clone());
    }
    let state = Arc::new(state);

    // Configure rate limiting. SmartIpKeyExtractor prefers standard proxy
    // headers (x-forwarded-for, x-real-ip, forwarded) and falls back to the
    // peer address, so per-client limits survive a reverse proxy.
    let rate_limit_rps = rate_limit::rate_limit_per_second();
    let rate_limit_burst = rate_limit::rate_limit_burst_size();
    let rate_limit_config = Arc::new(
        GovernorConfigBuilder::default()
            // per_second(n) would mean "one request per n seconds"!
            .per_nanosecond(rate_limit::replenish_interval_ns())
            .burst_size(rate_limit_burst)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("failed to create rate limit config"),
    );

    // tower_governor keeps one bucket per client key; without periodic
    // cleanup that map grows forever.
    let governor_limiter = rate_limit_config.limiter().clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            governor_limiter.retain_recent();
        }
    });

    let governor_layer =
        GovernorLayer::new(rate_limit_config).error_handler(rate_limit::rate_limit_error_handler);
    tracing::info!(
        "Rate limiting enabled: {} req/s per IP, burst {}",
        rate_limit_rps,
        rate_limit_burst
    );

    // Build router
    let mut app = axum::Router::new()
        .route("/add", axum::routing::post(handlers::add_entry))
        .route("/checkpoint", axum::routing::get(handlers::get_checkpoint))
        .route(
            "/tile/{level}/{*path}",
            axum::routing::get(handlers::get_tile),
        )
        .route(
            "/tile/entries/{*path}",
            axum::routing::get(handlers::get_entries),
        )
        .route("/health", axum::routing::get(handlers::health))
        .route("/ready", axum::routing::get(handlers::ready));

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
        .layer(DefaultBodyLimit::max(handlers::MAX_ENTRY_SIZE))
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
    tracing::info!(
        "Environment variables for accessing this log:\n\
         export WRITE_URL=http://{}/\n\
         export READ_URL=http://{}/",
        args.listen,
        args.listen
    );

    // Handle shutdown (SIGINT and SIGTERM)
    let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag = shutting_down.clone();
    let shutdown_signal = async move {
        siglog::shutdown::shutdown_signal().await;
        shutdown_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = shutdown_tx.send(true);
    };

    // Supervise the background pipeline: if any worker dies (panic or
    // unexpected return) outside of shutdown, exit so the orchestrator
    // restarts the process, instead of accepting writes that are never
    // integrated or published.
    let supervisor_flag = shutting_down.clone();
    tokio::spawn(async move {
        let reason = tokio::select! {
            r = sequencer_handle => format!("sequencer task exited: {:?}", r),
            r = integration_handle => format!("integration worker exited: {:?}", r),
            r = checkpoint_handle => format!("checkpoint worker exited: {:?}", r),
        };
        if !supervisor_flag.load(std::sync::atomic::Ordering::SeqCst) {
            tracing::error!(
                "{}; exiting so the orchestrator can restart the process",
                reason
            );
            std::process::exit(1);
        }
    });

    // ConnectInfo is required by the rate limiter's key extractor as the
    // fallback when no proxy headers are present; without it every request
    // fails with "unable to extract rate limit key".
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal)
    .await?;

    tracing::info!("Server stopped");
    Ok(())
}
