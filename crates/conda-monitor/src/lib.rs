//! Conda Monitor - A monitoring witness for Conda package transparency logs.
//!
//! This crate provides Conda-specific functionality for the rust-tessera transparency log:
//!
//! - [`CondaMonitor`]: Validates Conda package log entries
//! - [`normalize_repodata_entry`]: Normalizes repodata entries for consistent hashing
//! - [`FilenameMapFn`]: Maps entries to index keys by filename

mod conda;
mod mapfn;
mod normalize;

pub use conda::CondaMonitor;
pub use mapfn::FilenameMapFn;
pub use normalize::{normalize_repodata_entry, RepodataEntry};

// Re-export commonly used types from rust-tessera
pub use rust_tessera::monitor::{
    ContentIndex, ContentIndexStore, Monitor, MonitorError, MonitoringWitness, ValidationError,
    ValidationResult,
};
pub use rust_tessera::witness::LogConfig;
