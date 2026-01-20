//! Checkpoint module for transparency log.

pub mod signer;

pub use signer::{
    Checkpoint, CheckpointSignature, CheckpointSigner, CosignedCheckpoint, KeyId, Origin,
    SignerName,
};
