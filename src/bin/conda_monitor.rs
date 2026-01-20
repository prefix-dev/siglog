//! Conda Monitor - A monitoring witness for Conda package transparency logs.
//!
//! This binary validates Conda package logs by checking:
//! - SHA256 uniqueness (no duplicate package content)
//! - Filename uniqueness (no package replacement attacks)
//!
//! It implements the C2SP tlog-witness specification with additional validation.

use clap::Parser;
use rust_tessera::monitor::{handlers, CondaMonitor, MonitoringWitness};
use rust_tessera::witness::LogConfig;
use sea_orm::{ConnectOptions, ConnectionTrait, Database as SeaDatabase, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use std::sync::Arc;
use std::time::Duration;

/// Conda Monitor - A monitoring witness for Conda package transparency logs.
#[derive(Parser, Debug)]
#[command(name = "conda-monitor")]
#[command(about = "A monitoring witness for Conda package transparency logs")]
struct Args {
    /// Database URL (PostgreSQL: postgres://... or SQLite: sqlite:./path.db)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "sqlite:./conda_monitor.db"
    )]
    database_url: String,

    /// Witness private key in note format (PRIVATE+KEY+name+hash+base64)
    #[arg(long, env = "WITNESS_PRIVATE_KEY")]
    private_key: String,

    /// Log configurations to monitor.
    /// Format: origin=vkey=url (can be repeated).
    /// Example: --log "conda.example.com=conda.example.com+deadbeef+base64key=https://conda.example.com"
    #[arg(long = "log", env = "MONITOR_LOGS", value_parser = parse_log_config)]
    logs: Vec<LogConfig>,

    /// Server listen address
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:2027")]
    listen: String,
}

/// Parse a log configuration from "origin=vkey=url" format.
fn parse_log_config(s: &str) -> Result<LogConfig, String> {
    let parts: Vec<&str> = s.splitn(3, '=').collect();
    if parts.len() != 3 {
        return Err(format!(
            "invalid log config format: expected 'origin=vkey=url', got '{}'",
            s
        ));
    }
    LogConfig::with_url(parts[0].to_string(), parts[1], parts[2].to_string())
        .map_err(|e| format!("invalid log config: {}", e))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("conda_monitor=info".parse()?)
                .add_directive("rust_tessera=info".parse()?)
                .add_directive("tower_http=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Starting Conda Monitor");

    // Validate we have at least one log to monitor
    if args.logs.is_empty() {
        anyhow::bail!("At least one log must be configured with --log");
    }

    for log in &args.logs {
        tracing::info!(
            "Configured to monitor log: {} (url: {:?})",
            log.origin,
            log.url
        );
    }

    // Initialize database
    tracing::info!("Connecting to database: {}", args.database_url);
    let conn = connect_database(&args.database_url).await?;
    let conn = Arc::new(conn);
    tracing::info!("Database connected and migrations complete");

    // Initialize signer
    let signer = Arc::new(
        rust_tessera::checkpoint::CheckpointSigner::from_note_key(&args.private_key)
            .map_err(|e| anyhow::anyhow!("invalid private key: {}", e))?,
    );
    tracing::info!("Witness signer initialized: {}", signer.name());

    // Create the Conda monitor
    let monitor = Arc::new(CondaMonitor::new());
    tracing::info!("Conda monitor initialized");

    // Create monitoring witness
    let witness = Arc::new(MonitoringWitness::new(
        monitor.clone(),
        signer,
        conn,
        args.logs,
    ));

    // Load persisted state for all configured logs
    witness.load_state().await?;
    tracing::info!(
        "Monitoring witness ready: {} (monitor: {})",
        witness.name(),
        witness.monitor_name()
    );

    // Build router
    let app = axum::Router::new()
        .route(
            "/add-checkpoint",
            axum::routing::post(handlers::add_checkpoint::<CondaMonitor>),
        )
        .route("/health", axum::routing::get(handlers::health))
        .route(
            "/stats",
            axum::routing::get(handlers::stats::<CondaMonitor>),
        )
        .with_state(witness)
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
    tracing::info!("Conda monitor listening on {}", args.listen);

    // Handle shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        tracing::info!("Shutdown signal received");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    tracing::info!("Conda monitor stopped");
    Ok(())
}

/// Connect to the database and run migrations.
async fn connect_database(database_url: &str) -> anyhow::Result<DatabaseConnection> {
    let mut opts = ConnectOptions::new(database_url);
    opts.max_connections(10)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .sqlx_logging(false);

    let conn = SeaDatabase::connect(opts).await?;

    // Enable WAL mode for SQLite
    if matches!(
        conn.get_database_backend(),
        sea_orm::DatabaseBackend::Sqlite
    ) {
        conn.execute_unprepared("PRAGMA journal_mode=WAL").await?;
        conn.execute_unprepared("PRAGMA busy_timeout=5000").await?;
    }

    // Run migrations
    rust_tessera::migration::Migrator::up(&conn, None).await?;

    Ok(conn)
}
