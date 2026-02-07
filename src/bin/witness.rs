//! Siglog Witness - A witness server for transparency logs.
//!
//! This binary implements the C2SP tlog-witness specification:
//! <https://c2sp.org/tlog-witness>

use axum::extract::DefaultBodyLimit;
use clap::Parser;
use sea_orm::{ConnectOptions, ConnectionTrait, Database as SeaDatabase, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use siglog::witness::{handlers, LogConfig, Witness};
use std::sync::Arc;
use std::time::Duration;

/// Maximum allowed size for witness request bodies (1MB).
/// This prevents DoS attacks from extremely large checkpoint submissions.
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Siglog Witness - A witness server for transparency logs.
#[derive(Parser, Debug)]
#[command(name = "witness")]
#[command(about = "A witness server for transparency logs")]
struct Args {
    /// Database URL (PostgreSQL: postgres://... or SQLite: sqlite:./path.db)
    #[arg(long, env = "DATABASE_URL", default_value = "sqlite:./witness.db")]
    database_url: String,

    /// Witness private key in note format (PRIVATE+KEY+name+hash+base64)
    #[arg(long, env = "WITNESS_PRIVATE_KEY")]
    private_key: String,

    /// Log configurations to witness.
    /// Format: origin=vkey (can be repeated).
    /// Example: --log "example.com/log=example.com/log+deadbeef+base64key"
    #[arg(long = "log", env = "WITNESS_LOGS", value_parser = parse_log_config)]
    logs: Vec<LogConfig>,

    /// Server listen address
    #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:2026")]
    listen: String,
}

/// Parse a log configuration from "origin=vkey" format.
fn parse_log_config(s: &str) -> Result<LogConfig, String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid log config format: expected 'origin=vkey', got '{}'",
            s
        ));
    }
    LogConfig::new(parts[0].to_string(), parts[1]).map_err(|e| format!("invalid log config: {}", e))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("witness=info".parse()?)
                .add_directive("tower_http=debug".parse()?),
        )
        .init();

    let args = Args::parse();

    tracing::info!("Starting Siglog Witness");

    // Validate we have at least one log to witness
    if args.logs.is_empty() {
        anyhow::bail!("At least one log must be configured with --log");
    }

    for log in &args.logs {
        tracing::info!("Configured to witness log: {}", log.origin);
    }

    // Initialize database
    tracing::info!("Connecting to database: {}", args.database_url);
    let conn = connect_database(&args.database_url).await?;
    let conn = Arc::new(conn);
    tracing::info!("Database connected and migrations complete");

    // Initialize signer
    let signer = Arc::new(
        siglog::checkpoint::CheckpointSigner::from_note_key(&args.private_key)
            .map_err(|e| anyhow::anyhow!("invalid private key: {}", e))?,
    );
    tracing::info!("Witness signer initialized: {}", signer.name());

    // Create witness
    let witness = Arc::new(Witness::new(signer, conn, args.logs));
    tracing::info!("Witness name: {}", witness.name());

    // Build router with body size limit
    let app = axum::Router::new()
        .route(
            "/add-checkpoint",
            axum::routing::post(handlers::add_checkpoint),
        )
        .route("/health", axum::routing::get(handlers::health))
        .with_state(witness)
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(
                    tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO),
                )
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        );

    tracing::info!(
        "Request body size limit: {} bytes ({} MB)",
        MAX_BODY_SIZE,
        MAX_BODY_SIZE / 1024 / 1024
    );

    // Start server
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!("Witness server listening on {}", args.listen);

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

    tracing::info!("Witness server stopped");
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
    siglog::migration::Migrator::up(&conn, None).await?;

    Ok(conn)
}
