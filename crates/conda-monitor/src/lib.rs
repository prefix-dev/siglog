//! Conda Monitor - A monitoring witness for Conda package transparency logs.
//!
//! This crate provides Conda-specific functionality for the siglog transparency log:
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

// Re-export commonly used types from siglog
pub use siglog::monitor::{
    ContentIndex, ContentIndexStore, Monitor, MonitorError, MonitoringWitness, ValidationError,
    ValidationResult,
};
pub use siglog::witness::LogConfig;
