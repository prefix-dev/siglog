//! Error types for the Tessera transparency log server.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// Result type alias using our error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the Tessera server.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("Storage error: {0}")]
    Storage(#[from] opendal::Error),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid entry: {0}")]
    InvalidEntry(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Merkle error: {0}")]
    Merkle(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Error::InvalidPath(_) | Error::InvalidEntry(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Error::Database(_) | Error::Storage(_) | Error::Io(_) => {
                tracing::error!("Internal error: {}", self);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            _ => {
                tracing::error!("Error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };

        (status, message).into_response()
    }
}
