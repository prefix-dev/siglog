//! Conda repodata transparency log support.
//!
//! This module provides:
//! - Normalization of repodata entries for consistent hashing
//! - MapFn implementation for indexing by filename
//! - Verification utilities

mod mapfn;
mod normalize;

pub use mapfn::FilenameMapFn;
pub use normalize::{normalize_repodata_entry, RepodataEntry};
