//! HTTP API module for the Tessera transparency log.

pub mod handlers;
pub mod paths;
pub mod rate_limit;
pub mod rekor;

use crate::checkpoint::CheckpointSigner;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Extension, Router,
};
use handlers::AppState;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    Tessera,
    Rekor,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tessera => "tessera",
            Self::Rekor => "rekor",
        }
    }
}

/// Mutually exclusive write APIs; health endpoints are shared.
pub fn router(mode: Mode, signer: Arc<CheckpointSigner>) -> Router<Arc<AppState>> {
    let reads = Router::new()
        .route("/checkpoint", get(handlers::get_checkpoint))
        .route("/tile/{level}/{*path}", get(handlers::get_tile))
        .route("/tile/entries/{*path}", get(handlers::get_entries));
    let api = match mode {
        Mode::Tessera => reads.route("/add", post(handlers::add_entry)),
        Mode::Rekor => Router::new().nest(
            "/api/v2",
            reads
                .route("/log/entries", post(rekor::create_entry))
                .layer(Extension(signer)),
        ),
    };
    api.route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .layer(DefaultBodyLimit::max(handlers::MAX_ENTRY_SIZE))
}
