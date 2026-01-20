//! HTTP handlers for the monitor server.

use super::{Monitor, MonitorError, MonitoringWitness, ValidationError};
use crate::witness::AddCheckpointRequest;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

/// Content type for tlog size responses (on 409 Conflict).
const CONTENT_TYPE_TLOG_SIZE: &str = "text/x.tlog.size";

/// POST /add-checkpoint - Submit a checkpoint for monitoring and witnessing.
///
/// This endpoint validates all new log entries against the monitor's rules
/// before co-signing the checkpoint.
pub async fn add_checkpoint<M: Monitor + 'static>(
    State(witness): State<Arc<MonitoringWitness<M>>>,
    body: Bytes,
) -> Response {
    // Parse body as UTF-8
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid UTF-8: {}", e)).into_response();
        }
    };

    // Parse the request
    let request = match AddCheckpointRequest::from_ascii(body_str) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("parse error: {}", e)).into_response();
        }
    };

    // Process the request
    match witness.add_checkpoint(request).await {
        Ok(cosig) => {
            // Return the cosignature line
            let sig_line = cosig.to_line();
            (StatusCode::OK, sig_line).into_response()
        }
        Err(e) => monitor_error_to_response(e),
    }
}

/// Convert a MonitorError to an HTTP response.
fn monitor_error_to_response(err: MonitorError) -> Response {
    match err {
        MonitorError::Witness(witness_err) => {
            use crate::witness::WitnessError;

            match witness_err {
                WitnessError::Conflict(size) => (
                    StatusCode::CONFLICT,
                    [(header::CONTENT_TYPE, CONTENT_TYPE_TLOG_SIZE)],
                    format!("{}\n", size),
                )
                    .into_response(),
                WitnessError::UnknownLog(origin) => {
                    (StatusCode::NOT_FOUND, format!("unknown log: {}", origin)).into_response()
                }
                WitnessError::InvalidSignature(msg) => {
                    (StatusCode::FORBIDDEN, format!("invalid signature: {}", msg)).into_response()
                }
                WitnessError::InvalidProof(msg) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("invalid proof: {}", msg),
                )
                    .into_response(),
                WitnessError::BadRequest(msg) => {
                    (StatusCode::BAD_REQUEST, format!("bad request: {}", msg)).into_response()
                }
                WitnessError::Internal(msg) => {
                    tracing::error!("Internal witness error: {}", msg);
                    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
                }
            }
        }
        MonitorError::Validation(validation_err) => {
            // Return validation errors as 422 with detailed JSON
            let response = ValidationErrorResponse::from(validation_err);
            (StatusCode::UNPROCESSABLE_ENTITY, Json(response)).into_response()
        }
    }
}

/// JSON response for validation errors.
#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse {
    /// Error type.
    pub error: String,
    /// Error message.
    pub message: String,
    /// Additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ValidationErrorDetails>,
}

/// Details about a validation error.
#[derive(Debug, Serialize)]
pub struct ValidationErrorDetails {
    /// The key that caused the violation (hash or filename).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Index where the key was first seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_index: Option<u64>,
    /// Current index where the duplicate was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_index: Option<u64>,
    /// The first hash (for filename conflicts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_hash: Option<String>,
    /// The current hash (for filename conflicts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_hash: Option<String>,
}

impl From<ValidationError> for ValidationErrorResponse {
    fn from(err: ValidationError) -> Self {
        match err {
            ValidationError::DuplicateSha256 {
                hash,
                first_index,
                current_index,
            } => Self {
                error: "duplicate_sha256".to_string(),
                message: format!("SHA256 {} already exists at index {}", hash, first_index),
                details: Some(ValidationErrorDetails {
                    key: Some(hash),
                    first_index: Some(first_index),
                    current_index: Some(current_index),
                    first_hash: None,
                    current_hash: None,
                }),
            },
            ValidationError::DuplicateFilename {
                filename,
                first_hash,
                current_hash,
                first_index,
                current_index,
            } => Self {
                error: "duplicate_filename".to_string(),
                message: format!("Filename {} already exists with different hash", filename),
                details: Some(ValidationErrorDetails {
                    key: Some(filename),
                    first_index: Some(first_index),
                    current_index: Some(current_index),
                    first_hash: Some(first_hash),
                    current_hash: Some(current_hash),
                }),
            },
            ValidationError::ParseError(msg) => Self {
                error: "parse_error".to_string(),
                message: msg,
                details: None,
            },
            ValidationError::Other(msg) => Self {
                error: "validation_error".to_string(),
                message: msg,
                details: None,
            },
        }
    }
}

/// GET /health - Health check.
pub async fn health() -> &'static str {
    "ok"
}

/// GET /stats - Get monitor statistics.
#[derive(Debug, Serialize)]
pub struct MonitorStatsResponse {
    /// Monitor name.
    pub monitor: String,
    /// Witness name.
    pub witness: String,
    /// Number of tracked SHA256 hashes.
    pub sha256_count: usize,
    /// Number of tracked filenames.
    pub filename_count: usize,
}

pub async fn stats<M: Monitor + 'static>(
    State(witness): State<Arc<MonitoringWitness<M>>>,
) -> Response {
    // For CondaMonitor, we can get stats from the indices
    // For generic monitors, we just return the names
    let response = MonitorStatsResponse {
        monitor: witness.monitor_name().to_string(),
        witness: witness.name().to_string(),
        sha256_count: 0, // Would need to expose from monitor
        filename_count: 0,
    };

    (StatusCode::OK, Json(response)).into_response()
}
