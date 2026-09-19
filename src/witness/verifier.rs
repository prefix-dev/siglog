//! Checkpoint signature verification.

use crate::checkpoint::{CheckpointSignature, CosignedCheckpoint, KeyId};
use crate::error::{Error, Result};
use base64::Engine;
use ed25519_dalek::VerifyingKey;

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
        let config = Self::new_witness(vkey)?;
        let (_, alg, _, _) = parse_vkey(vkey)?;
        if alg != ALG_ED25519 {
            return Err(Error::Config("log keys must use plain Ed25519".into()));
        }
        Ok(Self { origin, ..config })
    }

    /// Pinned witness key; accepts plain note and cosignature/v1 keys.
    pub fn new_witness(vkey: &str) -> Result<Self> {
        let (key_name, _, key_id, verifying_key) = parse_vkey(vkey)?;
        Ok(Self {
            origin: String::new(),
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

    pub fn verify_signature(&self, signature: &CheckpointSignature, body: &[u8]) -> Result<()> {
        if signature.timestamp.is_some()
            || signature.key_id != self.key_id
            || signature.name.as_str() != self.key_name
        {
            return Err(Error::Signing("signature key identity mismatch".into()));
        }
        self.verifying_key
            .verify_strict(body, &signature.signature)
            .map_err(|e| Error::Signing(e.to_string()))
    }

    /// Verify a witness signature without allowing timestamped signatures as log signatures.
    pub fn verify_cosignature(&self, signature: &CheckpointSignature, body: &[u8]) -> Result<()> {
        use crate::checkpoint::signer::{compute_key_id_with_alg, cosignature_v1_message};
        let alg = if signature.timestamp.is_some() {
            0x04
        } else {
            0x01
        };
        let key_id = compute_key_id_with_alg(&self.key_name, &self.verifying_key, alg);
        if signature.key_id != key_id || signature.name.as_str() != self.key_name {
            return Err(Error::Signing("signature key identity mismatch".into()));
        }
        let message = match signature.timestamp {
            Some(ts) => cosignature_v1_message(
                ts,
                std::str::from_utf8(body).map_err(|e| Error::Signing(e.to_string()))?,
            )
            .into_bytes(),
            None => body.to_vec(),
        };
        self.verifying_key
            .verify_strict(&message, &signature.signature)
            .map_err(|e| Error::Signing(e.to_string()))
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
        let log_sig = checkpoint.signatures.iter().find(|s| {
            self.config
                .verify_signature(s, checkpoint.checkpoint.to_body().as_bytes())
                .is_ok()
        });

        let log_sig = log_sig.ok_or_else(|| {
            Error::Config(format!(
                "no signature from log '{}' found",
                self.config.key_name
            ))
        })?;

        // Verify the signature
        let body = checkpoint.checkpoint.to_body();
        self.config.verify_signature(log_sig, body.as_bytes())?;

        Ok(())
    }
}

/// Parse a verification key string.
///
/// Format: `name+hash_hex+base64(alg + pubkey)`
fn parse_vkey(vkey: &str) -> Result<(String, u8, KeyId, VerifyingKey)> {
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
    if key_data[0] != ALG_ED25519 && key_data[0] != 0x04 {
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

    if verifying_key.is_weak() {
        return Err(Error::Config("weak verification key".into()));
    }

    // Compute and verify key ID
    let key_id =
        crate::checkpoint::signer::compute_key_id_with_alg(&name, &verifying_key, key_data[0]);
    if key_id.as_u32() != expected_hash {
        return Err(Error::Config(format!(
            "key hash mismatch: expected {:08x}, computed {:08x}",
            expected_hash,
            key_id.as_u32()
        )));
    }

    Ok((name, key_data[0], key_id, verifying_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointSigner;

    #[test]
    fn cosignatures_are_verified_but_never_accepted_as_log_signatures() {
        use crate::checkpoint::{Checkpoint, Origin};
        use crate::types::TreeSize;
        use sigstore_types::Sha256Hash;
        let signer = CheckpointSigner::generate("witness");
        let cp = Checkpoint::new(
            Origin::new("log".into()).unwrap(),
            TreeSize::new(1),
            Sha256Hash::from_bytes([1; 32]),
        );
        let sig = signer.cosign_v1(&cp, 1234);
        let body = cp.to_body();
        let mut key_data = vec![0x04];
        key_data.extend_from_slice(signer.public_key().as_bytes());
        let vkey = format!(
            "witness+{:08x}+{}",
            signer.cosignature_v1_key_id().as_u32(),
            base64::engine::general_purpose::STANDARD.encode(key_data)
        );
        assert!(LogConfig::new("log".into(), &vkey).is_err());
        for key in [vkey, signer.verification_key()] {
            let config = LogConfig::new_witness(&key).unwrap();
            config.verify_cosignature(&sig, body.as_bytes()).unwrap();
            assert!(config.verify_signature(&sig, body.as_bytes()).is_err());
            let mut altered = sig.clone();
            altered.timestamp = Some(1235);
            assert!(config
                .verify_cosignature(&altered, body.as_bytes())
                .is_err());
            assert!(config
                .verify_cosignature(&sig, b"different body\n")
                .is_err());
        }
    }

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
        let (parsed_name, _, parsed_id, parsed_key) = parse_vkey(&vkey).unwrap();
        assert_eq!(parsed_name, name);
        assert_eq!(parsed_id.as_u32(), signer.key_id().as_u32());
        assert_eq!(parsed_key.as_bytes(), pubkey.as_bytes());
    }
}
