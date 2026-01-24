//! Checkpoint signature verification.

use crate::checkpoint::{CosignedCheckpoint, KeyId};
use crate::error::{Error, Result};
use base64::Engine;
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Ed25519 algorithm identifier for note format.
const ALG_ED25519: u8 = 0x01;

/// Configuration for a known log.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// The log origin string.
    pub origin: String,
    /// The log's verification key (note format: name+hash+base64).
    pub vkey: String,
    /// The log's HTTP URL (for fetching entries).
    pub url: Option<String>,
    /// The parsed verifying key.
    verifying_key: VerifyingKey,
    /// The expected key ID.
    key_id: KeyId,
    /// The key name (from vkey).
    key_name: String,
}

impl LogConfig {
    /// Create a new log configuration from a verification key string.
    ///
    /// Format: `name+hash_hex+base64(alg + pubkey)`
    /// Example: `example.com/log+deadbeef+AQIDBAUGBwg...`
    pub fn new(origin: String, vkey: &str) -> Result<Self> {
        let (key_name, key_id, verifying_key) = parse_vkey(vkey)?;

        Ok(Self {
            origin,
            vkey: vkey.to_string(),
            url: None,
            verifying_key,
            key_id,
            key_name,
        })
    }

    /// Create a new log configuration with a URL for fetching entries.
    pub fn with_url(origin: String, vkey: &str, url: String) -> Result<Self> {
        let mut config = Self::new(origin, vkey)?;
        config.url = Some(url);
        Ok(config)
    }

    /// Get the log's public key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the key name.
    pub fn key_name(&self) -> &str {
        &self.key_name
    }
}

/// Verifier for checkpoint signatures.
pub struct CheckpointVerifier {
    config: LogConfig,
}

impl CheckpointVerifier {
    /// Create a new checkpoint verifier.
    pub fn new(config: LogConfig) -> Self {
        Self { config }
    }

    /// Verify a checkpoint's signature.
    ///
    /// Checks that:
    /// 1. The checkpoint origin matches the expected origin
    /// 2. At least one signature is from the configured log key
    /// 3. That signature is valid
    pub fn verify(&self, checkpoint: &CosignedCheckpoint) -> Result<()> {
        // Check origin matches
        if checkpoint.checkpoint.origin.as_str() != self.config.origin {
            return Err(Error::Config(format!(
                "origin mismatch: expected '{}', got '{}'",
                self.config.origin,
                checkpoint.checkpoint.origin.as_str()
            )));
        }

        // Find a signature from the log
        let log_sig = checkpoint
            .signatures
            .iter()
            .find(|s| s.key_id == self.config.key_id || s.name.as_str() == self.config.key_name);

        let log_sig = log_sig.ok_or_else(|| {
            Error::Config(format!(
                "no signature from log '{}' found",
                self.config.key_name
            ))
        })?;

        // Verify the signature
        let body = checkpoint.checkpoint.to_body();
        self.config
            .verifying_key
            .verify(body.as_bytes(), &log_sig.signature)
            .map_err(|e| Error::Signing(format!("signature verification failed: {}", e)))?;

        Ok(())
    }
}

/// Parse a verification key string.
///
/// Format: `name+hash_hex+base64(alg + pubkey)`
fn parse_vkey(vkey: &str) -> Result<(String, KeyId, VerifyingKey)> {
    let parts: Vec<&str> = vkey.trim().splitn(3, '+').collect();
    if parts.len() != 3 {
        return Err(Error::Config(format!(
            "invalid vkey format: expected 'name+hash+base64', got '{}'",
            vkey
        )));
    }

    let name = parts[0].to_string();
    let hash_hex = parts[1];
    let key_base64 = parts[2];

    // Parse expected hash
    if hash_hex.len() != 8 {
        return Err(Error::Config(format!(
            "invalid hash length: expected 8 hex chars, got {}",
            hash_hex.len()
        )));
    }
    let expected_hash =
        u32::from_str_radix(hash_hex, 16).map_err(|_| Error::Config("invalid hash hex".into()))?;

    // Decode key data
    let key_data = base64::engine::general_purpose::STANDARD
        .decode(key_base64)
        .map_err(|e| Error::Config(format!("invalid key base64: {}", e)))?;

    // Check format: 1-byte alg + 32-byte pubkey = 33 bytes
    if key_data.len() != 33 {
        return Err(Error::Config(format!(
            "invalid key length: expected 33, got {}",
            key_data.len()
        )));
    }

    // Check algorithm byte
    if key_data[0] != ALG_ED25519 {
        return Err(Error::Config(format!(
            "unsupported algorithm: expected {}, got {}",
            ALG_ED25519, key_data[0]
        )));
    }

    // Parse public key
    let pubkey_bytes: [u8; 32] = key_data[1..33]
        .try_into()
        .map_err(|_| Error::Config("invalid pubkey length".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| Error::Config(format!("invalid public key: {}", e)))?;

    // Compute and verify key ID
    let key_id = compute_key_id(&name, &verifying_key);
    if key_id.as_u32() != expected_hash {
        return Err(Error::Config(format!(
            "key hash mismatch: expected {:08x}, computed {:08x}",
            expected_hash,
            key_id.as_u32()
        )));
    }

    Ok((name, key_id, verifying_key))
}

/// Compute the key ID for a verifying key per Go's note format.
fn compute_key_id(name: &str, key: &VerifyingKey) -> KeyId {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update([ALG_ED25519]);
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();

    KeyId::new([hash[0], hash[1], hash[2], hash[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointSigner;

    #[test]
    fn test_parse_vkey_roundtrip() {
        // Generate a signer and export as note key
        let signer = CheckpointSigner::generate("test.example.com");
        let note_key = signer.to_note_key();

        // Extract vkey from private key format
        // PRIVATE+KEY+name+hash+base64(alg+seed) -> name+hash+base64(alg+pubkey)
        let parts: Vec<&str> = note_key.splitn(5, '+').collect();
        assert_eq!(parts.len(), 5);

        let name = parts[2];
        let hash = parts[3];

        // Build vkey with public key
        let pubkey = signer.public_key();
        let mut key_data = Vec::with_capacity(33);
        key_data.push(ALG_ED25519);
        key_data.extend_from_slice(pubkey.as_bytes());
        let vkey = format!(
            "{}+{}+{}",
            name,
            hash,
            base64::engine::general_purpose::STANDARD.encode(&key_data)
        );

        // Parse and verify
        let (parsed_name, parsed_id, parsed_key) = parse_vkey(&vkey).unwrap();
        assert_eq!(parsed_name, name);
        assert_eq!(parsed_id.as_u32(), signer.key_id().as_u32());
        assert_eq!(parsed_key.as_bytes(), pubkey.as_bytes());
    }
}
