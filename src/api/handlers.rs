//! HTTP handlers for the Tessera API.

use crate::api::paths;
use crate::error::{Error, Result};
use crate::sequencer::Sequencer;
use crate::storage::{Database, TileStorage};
use crate::types::Entry;
use crate::vindex::VerifiableIndex;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

/// Maximum entry size in bytes.
///
/// Entry bundles use a 2-byte length prefix, so accepting larger entries would
/// make the public tile data impossible to parse correctly.
pub const MAX_ENTRY_SIZE: usize = u16::MAX as usize;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub storage: TileStorage,
    pub sequencer: Sequencer,
    /// Optional verifiable index for key lookups.
    pub vindex: Option<Arc<VerifiableIndex>>,
    /// Optional API key for authenticating write requests.
    pub api_key: Option<String>,
}

impl AppState {
    pub fn new(storage: TileStorage, sequencer: Sequencer, db: Database) -> Self {
        Self {
            db,
            storage,
            sequencer,
            vindex: None,
            api_key: None,
        }
    }

    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    pub fn with_vindex(mut self, vindex: Arc<VerifiableIndex>) -> Self {
        self.vindex = Some(vindex);
        self
    }
}

/// POST /add - Add an entry to the log.
///
/// Request body: raw entry data bytes
/// Response: ASCII decimal representation of assigned index
pub async fn add_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    // Check API key if configured
    if let Some(ref expected_key) = state.api_key {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match provided {
            Some(token) if constant_time_eq(token.as_bytes(), expected_key.as_bytes()) => {}
            _ => return Err(Error::Unauthorized),
        }
    }

    if body.is_empty() {
        return Err(Error::InvalidEntry("empty entry".into()));
    }

    // Validate entry size to prevent DoS attacks
    if body.len() > MAX_ENTRY_SIZE {
        return Err(Error::InvalidEntry(format!(
            "entry too large: {} bytes (max {} bytes)",
            body.len(),
            MAX_ENTRY_SIZE
        )));
    }

    // Create entry and add to sequencer
    let entry = Entry::new(body.to_vec());
    let index = state.sequencer.add(entry).await?;

    // Return index as decimal string
    let response = (StatusCode::OK, index.to_string());
    Ok(response.into_response())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (&left, &right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// GET /checkpoint - Get the current checkpoint.
///
/// Response: Signed checkpoint text with Cache-Control: no-cache
pub async fn get_checkpoint(State(state): State<Arc<AppState>>) -> Result<Response> {
    match state.storage.read_checkpoint().await? {
        Some(data) => {
            let response = (
                StatusCode::OK,
                [(header::CACHE_CONTROL, "no-cache")],
                data.into_bytes(),
            );
            Ok(response.into_response())
        }
        None => Err(Error::NotFound("checkpoint not found".into())),
    }
}

/// GET /tile/{level}/*path - Get a hash tile.
///
/// Path format: /tile/{level}/{index}[.p/{partial}]
/// Response: Raw tile bytes with Cache-Control: immutable
pub async fn get_tile(
    State(state): State<Arc<AppState>>,
    Path((level, tile_path)): Path<(String, String)>,
) -> Result<Response> {
    // Parse the level and index from path
    let (level, index, partial) = paths::parse_tile_path(&level, &tile_path)?;

    // Read from storage
    let path = paths::tile_path(level, index, partial);
    match state.storage.read_raw(&path).await? {
        Some(data) => {
            let response = (
                StatusCode::OK,
                [
                    (header::CACHE_CONTROL, "max-age=31536000, immutable"),
                    (header::CONTENT_TYPE, "application/octet-stream"),
                ],
                data,
            );
            Ok(response.into_response())
        }
        None => Err(Error::NotFound(format!("tile not found: {}", path))),
    }
}

/// GET /tile/entries/*path - Get an entry bundle.
///
/// Path format: /tile/entries/{index}[.p/{partial}]
/// Response: Raw bundle bytes
pub async fn get_entries(
    State(state): State<Arc<AppState>>,
    Path(entries_path): Path<String>,
) -> Result<Response> {
    // Parse the index from path
    let (index, partial) = paths::parse_tile_index(&entries_path)?;

    // Read from storage
    let path = paths::entries_path(index, partial);
    match state.storage.read_raw(&path).await? {
        Some(data) => {
            let response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                data,
            );
            Ok(response.into_response())
        }
        None => Err(Error::NotFound(format!("entries not found: {}", path))),
    }
}

/// Health check endpoint.
pub async fn health() -> &'static str {
    "ok"
}

/// Readiness check endpoint.
///
/// This validates access to the database and tile storage.
pub async fn ready(State(state): State<Arc<AppState>>) -> Result<Response> {
    let log_state = state.db.get_log_state().await?;
    let _ = state.storage.read_checkpoint().await?;

    #[derive(Serialize)]
    struct ReadyResponse {
        status: &'static str,
        next_index: u64,
        integrated_size: u64,
        pending_count: u64,
    }

    let response = ReadyResponse {
        status: "ready",
        next_index: log_state.next_index.value(),
        integrated_size: log_state.integrated_size.value(),
        pending_count: log_state.pending_count(),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// A proof node from the prefix tree.
#[derive(Debug, Serialize)]
pub struct VindexProofNode {
    /// Number of bits in the label.
    pub label_bit_len: u32,
    /// The label bytes (path in the tree), hex-encoded.
    pub label_path: String,
    /// The hash at this node, hex-encoded.
    pub hash: String,
}

/// Response from a vindex lookup.
#[derive(Debug, Serialize)]
pub struct VindexLookupResponse {
    /// The log indices where entries with this key are stored.
    pub indices: Vec<u64>,
    /// The tree size at which this lookup is valid.
    pub tree_size: u64,
    /// Whether the key was found in the index.
    pub found: bool,
    /// The inclusion/exclusion proof from the prefix tree.
    pub proof: Vec<VindexProofNode>,
    /// The root hash of the prefix tree (commits to the entire index state).
    pub root_hash: String,
}

/// GET /vindex/lookup/{hash} - Look up entries by key hash.
///
/// Path: hex-encoded SHA256 hash (64 characters)
/// Response: JSON with log indices
pub async fn vindex_lookup(
    State(state): State<Arc<AppState>>,
    Path(hash_str): Path<String>,
) -> Result<Response> {
    let vindex = state
        .vindex
        .as_ref()
        .ok_or_else(|| Error::Internal("vindex not enabled".into()))?;

    // Parse hex hash
    let hash_bytes = hex::decode(&hash_str)
        .map_err(|e| Error::InvalidEntry(format!("invalid hex hash: {}", e)))?;

    if hash_bytes.len() != 32 {
        return Err(Error::InvalidEntry(format!(
            "hash must be 32 bytes, got {}",
            hash_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes);

    let result = vindex.lookup(&key);
    let root_hash = vindex.root_hash();

    let response = VindexLookupResponse {
        indices: result.indices.iter().map(|i| i.value()).collect(),
        tree_size: result.tree_size,
        found: result.found,
        proof: result
            .proof
            .into_iter()
            .map(|n| VindexProofNode {
                label_bit_len: n.label_bit_len,
                label_path: hex::encode(&n.label_path),
                hash: hex::encode(n.hash),
            })
            .collect(),
        root_hash: hex::encode(root_hash),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /vindex/lookup/key/{key} - Look up entries by string key.
///
/// The key string is hashed with SHA256 before lookup.
/// Response: JSON with log indices
pub async fn vindex_lookup_key(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Response> {
    let vindex = state
        .vindex
        .as_ref()
        .ok_or_else(|| Error::Internal("vindex not enabled".into()))?;

    let result = vindex.lookup_string(&key);
    let root_hash = vindex.root_hash();

    let response = VindexLookupResponse {
        indices: result.indices.iter().map(|i| i.value()).collect(),
        tree_size: result.tree_size,
        found: result.found,
        proof: result
            .proof
            .into_iter()
            .map(|n| VindexProofNode {
                label_bit_len: n.label_bit_len,
                label_path: hex::encode(&n.label_path),
                hash: hex::encode(n.hash),
            })
            .collect(),
        root_hash: hex::encode(root_hash),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

/// GET /vindex/stats - Get vindex statistics.
#[derive(Debug, Serialize)]
pub struct VindexStatsResponse {
    pub tree_size: u64,
    pub key_count: usize,
    /// The root hash of the prefix tree (commits to the entire index state).
    pub root_hash: String,
}

pub async fn vindex_stats(State(state): State<Arc<AppState>>) -> Result<Response> {
    let vindex = state
        .vindex
        .as_ref()
        .ok_or_else(|| Error::Internal("vindex not enabled".into()))?;

    let response = VindexStatsResponse {
        tree_size: vindex.tree_size(),
        key_count: vindex.key_count(),
        root_hash: hex::encode(vindex.root_hash()),
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
