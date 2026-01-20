//! Storage layer for the Tessera transparency log.
//!
//! This module provides:
//! - OpenDAL-based storage for static tiles and checkpoint
//! - SeaORM-based database storage for sequencing state

pub mod database;
pub mod opendal;

pub use database::Database;
pub use opendal::TileStorage;
