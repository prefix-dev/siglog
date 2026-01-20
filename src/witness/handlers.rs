//! HTTP handlers for the witness server.

use crate::witness::{AddCheckpointRequest, Witness, WitnessError};
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Content type for tlog size responses (on 409 Conflict).
const CONTENT_TYPE_TLOG_SIZE: &str = "text/x.tlog.size";

/// POST /add-checkpoint - Submit a checkpoint for witnessing.
///
/// Request body format:
/// ```text
/// old <size>
/// <base64-proof-hash-1>
/// <base64-proof-hash-2>
/// ...
/// <empty line>
/// <checkpoint text>
/// ```
///
/// Response on success (200 OK):
/// ```text
/// — <witness_name> <base64(key_id + signature)>
/// ```
///
/// Response on conflict (409 Conflict):
/// ```text
/// <witnessed_size>
/// ```
/// with Content-Type: text/x.tlog.size
pub async fn add_checkpoint(State(witness): State<Arc<Witness>>, body: Bytes) -> Response {
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
        Err(e) => witness_error_to_response(e),
    }
}

/// Convert a WitnessError to an HTTP response.
fn witness_error_to_response(err: WitnessError) -> Response {
    match err {
        WitnessError::Conflict(size) => {
            // 409 Conflict with the actual size
            (
                StatusCode::CONFLICT,
                [(header::CONTENT_TYPE, CONTENT_TYPE_TLOG_SIZE)],
                format!("{}\n", size),
            )
                .into_response()
        }
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

/// GET /checkpoint/{origin} - Get the latest witnessed checkpoint for a log.
pub async fn get_witnessed_checkpoint(
    State(witness): State<Arc<Witness>>,
    axum::extract::Path(origin): axum::extract::Path<String>,
) -> Response {
    match witness.get_state(&origin).await {
        Ok(Some(_state)) => {
            // TODO: Return the full checkpoint from state
            (StatusCode::OK, "checkpoint found").into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no witnessed checkpoint").into_response(),
        Err(e) => {
            tracing::error!("Error getting state: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /health - Health check.
pub async fn health() -> &'static str {
    "ok"
}
