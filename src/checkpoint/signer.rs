//! Checkpoint signing using Ed25519 note format.
//!
//! Implements the signed note format used by Go's x/mod/sumdb/note:
//! - Checkpoint body: origin, size, root hash (base64)
//! - Signature line: `— {name} {base64(key_id + signature)}`
//!
//! See: <https://pkg.go.dev/golang.org/x/mod/sumdb/note>

use crate::error::{Error, Result};
use crate::types::TreeSize;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use sigstore_types::Sha256Hash;
use std::fmt;

/// An Ed25519 checkpoint signer.
#[derive(Clone)]
pub struct CheckpointSigner {
    /// The signer name (appears in checkpoint).
    name: SignerName,
    /// The signing key.
    signing_key: SigningKey,
    /// The 4-byte key ID (first 4 bytes of SHA-256 of public key).
    key_id: KeyId,
}

/// Ed25519 algorithm identifier for note format.
const ALG_ED25519: u8 = 0x01;

/// Ed25519 cosignature/v1 algorithm identifier (c2sp.org/tlog-cosignature).
pub const ALG_COSIGNATURE_V1: u8 = 0x04;

/// Build the message signed by an Ed25519 cosignature/v1 cosigner.
///
/// Per c2sp.org/tlog-cosignature: a `cosignature/v1` header line, a
/// `time <posix seconds>` line, then the whole note body of the checkpoint
/// (including its final newline).
pub fn cosignature_v1_message(timestamp: u64, body: &str) -> String {
    format!("cosignature/v1\ntime {}\n{}", timestamp, body)
}

impl CheckpointSigner {
    /// Create a new checkpoint signer from a note-format private key.
    ///
    /// Go note format: `PRIVATE+KEY+{name}+{hash_hex}+{base64(alg + seed)}`
    /// where hash_hex is 8 hex chars representing first 4 bytes of
    /// SHA256(name + "\n" + alg + public_key)
    pub fn from_note_key(key_str: &str) -> Result<Self> {
        // Format: PRIVATE+KEY+name+hash_hex+base64
        let parts: Vec<&str> = key_str.trim().splitn(5, '+').collect();
        if parts.len() != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
            return Err(Error::Config("invalid note private key format".into()));
        }

        let name = SignerName::new(parts[2].to_string());
        let expected_hash_hex = parts[3];

        // Parse the expected hash
        if expected_hash_hex.len() != 8 {
            return Err(Error::Config(format!(
                "invalid hash length: expected 8 hex chars, got {}",
                expected_hash_hex.len()
            )));
        }
        let expected_hash = u32::from_str_radix(expected_hash_hex, 16)
            .map_err(|_| Error::Config("invalid hash hex".into()))?;

        let key_data = STANDARD
            .decode(parts[4])
            .map_err(|e| Error::Config(format!("invalid key base64: {}", e)))?;

        // Go Ed25519 note format: 1-byte alg + 32-byte seed = 33 bytes
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

        let seed: [u8; 32] = key_data[1..33]
            .try_into()
            .map_err(|_| Error::Config("invalid seed length".into()))?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        // Compute key ID per Go's note format: SHA256(name + "\n" + alg + pubkey)[:4]
        let key_id = compute_key_id(&name.0, &verifying_key);

        // Verify the hash matches
        if key_id.as_u32() != expected_hash {
            return Err(Error::Config(format!(
                "key hash mismatch: expected {:08x}, got {:08x}",
                expected_hash,
                key_id.as_u32()
            )));
        }

        Ok(Self {
            name,
            signing_key,
            key_id,
        })
    }

    /// Create a new checkpoint signer from raw Ed25519 seed.
    pub fn from_seed(name: impl Into<String>, seed: &[u8; 32]) -> Self {
        let name = SignerName::new(name.into());
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let key_id = compute_key_id(&name.0, &verifying_key);

        Self {
            name,
            signing_key,
            key_id,
        }
    }

    /// Generate a new random signer (for testing).
    pub fn generate(name: impl Into<String>) -> Self {
        let name = SignerName::new(name.into());
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let key_id = compute_key_id(&name.0, &verifying_key);

        Self {
            name,
            signing_key,
            key_id,
        }
    }

    /// Get the signer name.
    pub fn name(&self) -> &SignerName {
        &self.name
    }

    /// Get the public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the key ID.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// Get a reference to the signing key.
    pub fn signing_key_ref(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Export as note-format private key string (Go compatible).
    /// Format: PRIVATE+KEY+name+hash_hex+base64(alg + seed)
    pub fn to_note_key(&self) -> String {
        let mut key_data = Vec::with_capacity(33);
        key_data.push(ALG_ED25519);
        key_data.extend_from_slice(self.signing_key.as_bytes());

        format!(
            "PRIVATE+KEY+{}+{:08x}+{}",
            self.name.as_str(),
            self.key_id.as_u32(),
            STANDARD.encode(&key_data)
        )
    }

    /// Sign a checkpoint.
    pub fn sign(&self, checkpoint: &Checkpoint) -> SignedCheckpoint {
        let body = checkpoint.to_body();
        let signature = self.signing_key.sign(body.as_bytes());

        SignedCheckpoint {
            checkpoint: checkpoint.clone(),
            signer_name: self.name.clone(),
            key_id: self.key_id.clone(),
            signature,
        }
    }

    /// The key ID this signer uses for cosignature/v1 cosignatures.
    ///
    /// Computed with the cosignature/v1 algorithm byte (0x04), so it differs
    /// from the plain note-signature key ID.
    pub fn cosignature_v1_key_id(&self) -> KeyId {
        compute_key_id_with_alg(
            self.name.as_str(),
            &self.signing_key.verifying_key(),
            ALG_COSIGNATURE_V1,
        )
    }

    /// Produce a C2SP cosignature/v1 cosignature over a checkpoint.
    ///
    /// `timestamp` is the POSIX time (seconds) at which the cosignature is
    /// generated; it is bound into the signed message and encoded in the
    /// signature blob.
    pub fn cosign_v1(&self, checkpoint: &Checkpoint, timestamp: u64) -> CheckpointSignature {
        let message = cosignature_v1_message(timestamp, &checkpoint.to_body());
        let signature = self.signing_key.sign(message.as_bytes());

        CheckpointSignature {
            name: self.name.clone(),
            key_id: self.cosignature_v1_key_id(),
            signature,
            timestamp: Some(timestamp),
        }
    }
}

/// Compute the key ID for a verifying key per Go's note format.
/// Hash = SHA256(name + "\n" + alg_byte + public_key)[:4]
fn compute_key_id(name: &str, key: &VerifyingKey) -> KeyId {
    compute_key_id_with_alg(name, key, ALG_ED25519)
}

/// Compute a key ID with an explicit algorithm byte.
/// Hash = SHA256(name + "\n" + alg_byte + public_key)[:4]
pub fn compute_key_id_with_alg(name: &str, key: &VerifyingKey, alg: u8) -> KeyId {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update([alg]);
    hasher.update(key.as_bytes());
    let hash = hasher.finalize();

    KeyId::new([hash[0], hash[1], hash[2], hash[3]])
}

/// Signer name wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerName(String);

impl SignerName {
    pub fn new(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key ID (first 4 bytes of key hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId([u8; 4]);

impl KeyId {
    pub fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Get as big-endian u32 (for comparison with Go's hash format).
    pub fn as_u32(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

/// An unsigned checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Log origin string.
    pub origin: Origin,
    /// Tree size.
    pub size: TreeSize,
    /// Root hash.
    pub root_hash: Sha256Hash,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(origin: Origin, size: TreeSize, root_hash: Sha256Hash) -> Self {
        Self {
            origin,
            size,
            root_hash,
        }
    }

    /// Format the checkpoint body (for signing).
    pub fn to_body(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin.as_str(),
            self.size.value(),
            self.root_hash.to_base64()
        )
    }
}

/// Log origin string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin(String);

impl Origin {
    /// Create a new origin string with validation.
    ///
    /// Returns an error if the origin:
    /// - Is empty
    /// - Contains newline or carriage return characters (breaks checkpoint format)
    pub fn new(origin: String) -> Result<Self> {
        if origin.is_empty() {
            return Err(Error::Config("origin cannot be empty".into()));
        }
        if origin.contains('\n') || origin.contains('\r') {
            return Err(Error::Config(
                "origin cannot contain newline or carriage return characters".into(),
            ));
        }
        Ok(Self(origin))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Origin {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<&str> for Origin {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Self::new(s.to_string())
    }
}

/// A single signature on a checkpoint.
#[derive(Debug, Clone)]
pub struct CheckpointSignature {
    /// The signer name.
    pub name: SignerName,
    /// The key ID.
    pub key_id: KeyId,
    /// The signature.
    pub signature: Signature,
    /// The POSIX timestamp for cosignature/v1 signatures.
    ///
    /// `None` for plain note signatures (e.g. the log's own signature);
    /// `Some` for C2SP cosignature/v1 witness cosignatures, where the
    /// timestamp is bound into the signed message.
    pub timestamp: Option<u64>,
}

impl CheckpointSignature {
    /// Format as a signature line.
    ///
    /// Plain signatures encode `key_id(4) || sig(64)`; cosignature/v1
    /// signatures encode `key_id(4) || timestamp(8, BE) || sig(64)` per
    /// c2sp.org/tlog-cosignature.
    pub fn to_line(&self) -> String {
        let mut sig_data = Vec::with_capacity(4 + 8 + 64);
        sig_data.extend_from_slice(self.key_id.as_bytes());
        if let Some(ts) = self.timestamp {
            sig_data.extend_from_slice(&ts.to_be_bytes());
        }
        sig_data.extend_from_slice(&self.signature.to_bytes());

        format!("— {} {}", self.name.as_str(), STANDARD.encode(&sig_data))
    }

    /// Parse a signature line.
    ///
    /// Accepts both plain note signatures (68-byte blob) and cosignature/v1
    /// signatures (76-byte blob with an embedded big-endian timestamp).
    pub fn from_line(line: &str) -> Result<Self> {
        let line = line.trim();
        if !line.starts_with("— ") {
            return Err(Error::Config("signature line must start with '— '".into()));
        }

        let rest = &line[4..]; // Skip "— " (em dash + space, 4 bytes in UTF-8)
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(Error::Config("invalid signature line format".into()));
        }

        let name = SignerName::new(parts[0].to_string());
        let sig_data = STANDARD
            .decode(parts[1])
            .map_err(|e| Error::Config(format!("invalid signature base64: {}", e)))?;

        let (timestamp, sig_bytes): (Option<u64>, &[u8]) = match sig_data.len() {
            68 => (None, &sig_data[4..]),
            76 => {
                let ts_bytes: [u8; 8] = sig_data[4..12]
                    .try_into()
                    .map_err(|_| Error::Config("invalid timestamp bytes".into()))?;
                (Some(u64::from_be_bytes(ts_bytes)), &sig_data[12..])
            }
            n => {
                return Err(Error::Config(format!(
                    "invalid signature length: expected 68 (plain) or 76 (cosignature/v1), got {}",
                    n
                )));
            }
        };

        let key_id = KeyId::new([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]);
        let signature = Signature::from_bytes(
            sig_bytes
                .try_into()
                .map_err(|_| Error::Config("invalid signature bytes".into()))?,
        );

        Ok(Self {
            name,
            key_id,
            signature,
            timestamp,
        })
    }
}

/// A signed checkpoint (single signer).
#[derive(Debug)]
pub struct SignedCheckpoint {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// The signer name.
    pub signer_name: SignerName,
    /// The key ID.
    pub key_id: KeyId,
    /// The signature.
    pub signature: Signature,
}

impl SignedCheckpoint {
    /// Format as the full checkpoint text.
    pub fn to_text(&self) -> String {
        let body = self.checkpoint.to_body();

        // Signature line: — {name} {base64(key_id + signature)}
        let mut sig_data = Vec::with_capacity(4 + 64);
        sig_data.extend_from_slice(self.key_id.as_bytes());
        sig_data.extend_from_slice(&self.signature.to_bytes());

        format!(
            "{}\n— {} {}\n",
            body.trim_end(),
            self.signer_name.as_str(),
            STANDARD.encode(&sig_data)
        )
    }

    /// Convert to a cosigned checkpoint (with just this signature).
    pub fn into_cosigned(self) -> CosignedCheckpoint {
        CosignedCheckpoint {
            checkpoint: self.checkpoint,
            signatures: vec![CheckpointSignature {
                name: self.signer_name,
                key_id: self.key_id,
                signature: self.signature,
                timestamp: None,
            }],
        }
    }
}

/// A checkpoint with multiple signatures (from log + witnesses).
#[derive(Debug, Clone)]
pub struct CosignedCheckpoint {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// All signatures (log + witnesses).
    pub signatures: Vec<CheckpointSignature>,
}

impl CosignedCheckpoint {
    /// Create a new cosigned checkpoint with an initial signature.
    pub fn new(checkpoint: Checkpoint, signer: &CheckpointSigner) -> Self {
        let body = checkpoint.to_body();
        let signature = signer.signing_key.sign(body.as_bytes());

        Self {
            checkpoint,
            signatures: vec![CheckpointSignature {
                name: signer.name.clone(),
                key_id: signer.key_id.clone(),
                signature,
                timestamp: None,
            }],
        }
    }

    /// Add a plain note cosignature from a witness (non-spec, legacy).
    pub fn add_signature(&mut self, signer: &CheckpointSigner) {
        let body = self.checkpoint.to_body();
        let signature = signer.signing_key.sign(body.as_bytes());

        self.signatures.push(CheckpointSignature {
            name: signer.name.clone(),
            key_id: signer.key_id.clone(),
            signature,
            timestamp: None,
        });
    }

    /// Add a C2SP cosignature/v1 cosignature from a witness signer.
    pub fn add_cosignature_v1(&mut self, signer: &CheckpointSigner, timestamp: u64) {
        let cosig = signer.cosign_v1(&self.checkpoint, timestamp);
        self.signatures.push(cosig);
    }

    /// Parse a cosigned checkpoint from text.
    pub fn from_text(text: &str) -> Result<Self> {
        let text = text.trim();

        // Find the blank line separating body from signatures
        let parts: Vec<&str> = text.splitn(2, "\n\n").collect();
        if parts.len() != 2 {
            return Err(Error::Config(
                "checkpoint must have body and signatures separated by blank line".into(),
            ));
        }

        let body = parts[0];
        let sig_section = parts[1];

        // Parse body
        let body_lines: Vec<&str> = body.lines().collect();
        if body_lines.len() < 3 {
            return Err(Error::Config(
                "checkpoint body must have at least 3 lines".into(),
            ));
        }

        let origin = Origin::new(body_lines[0].to_string())?;
        let size = body_lines[1]
            .parse::<u64>()
            .map_err(|e| Error::Config(format!("invalid tree size: {}", e)))?;
        let root_hash_bytes = STANDARD
            .decode(body_lines[2])
            .map_err(|e| Error::Config(format!("invalid root hash base64: {}", e)))?;

        if root_hash_bytes.len() != 32 {
            return Err(Error::Config(format!(
                "invalid root hash length: expected 32, got {}",
                root_hash_bytes.len()
            )));
        }

        let root_hash = Sha256Hash::from_bytes(
            root_hash_bytes
                .try_into()
                .map_err(|_| Error::Config("invalid root hash".into()))?,
        );

        let checkpoint = Checkpoint {
            origin,
            size: TreeSize::new(size),
            root_hash,
        };

        // Parse signatures
        let mut signatures = Vec::new();
        for line in sig_section.lines() {
            if line.starts_with("— ") {
                signatures.push(CheckpointSignature::from_line(line)?);
            }
        }

        if signatures.is_empty() {
            return Err(Error::Config(
                "checkpoint must have at least one signature".into(),
            ));
        }

        Ok(Self {
            checkpoint,
            signatures,
        })
    }

    /// Format as the full checkpoint text with all signatures.
    pub fn to_text(&self) -> String {
        let body = self.checkpoint.to_body();

        let mut text = body.trim_end().to_string();
        text.push_str("\n\n");

        for sig in &self.signatures {
            text.push_str(&sig.to_line());
            text.push('\n');
        }

        text
    }

    /// Get number of signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if a specific signer has signed.
    pub fn has_signature_from(&self, name: &SignerName) -> bool {
        self.signatures.iter().any(|s| &s.name == name)
    }

    /// Merge signatures from another cosigned checkpoint.
    /// Only adds signatures that are not already present.
    pub fn merge_signatures(&mut self, other: &CosignedCheckpoint) {
        for sig in &other.signatures {
            if !self.has_signature_from(&sig.name) {
                self.signatures.push(sig.clone());
            }
        }
    }

    /// Add a signature from a signature line (as returned by witness).
    /// Returns Ok(()) if added, or Err if already present or invalid.
    pub fn add_signature_line(&mut self, line: &str) -> Result<()> {
        let sig = CheckpointSignature::from_line(line)?;
        if !self.has_signature_from(&sig.name) {
            self.signatures.push(sig);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let signer = CheckpointSigner::generate("test.example.com");

        let checkpoint = Checkpoint::new(
            Origin::new("test.example.com".to_string()).unwrap(),
            TreeSize::new(42),
            Sha256Hash::from_bytes([0u8; 32]),
        );

        let signed = signer.sign(&checkpoint);
        let text = signed.to_text();

        // Verify format
        assert!(text.contains("test.example.com"));
        assert!(text.contains("42"));
        assert!(text.contains("—")); // Em dash
    }

    #[test]
    fn test_note_key_roundtrip() {
        let signer = CheckpointSigner::generate("test.example.com");
        let key_str = signer.to_note_key();

        let restored = CheckpointSigner::from_note_key(&key_str).unwrap();

        assert_eq!(signer.name().as_str(), restored.name().as_str());
        assert_eq!(signer.key_id().as_bytes(), restored.key_id().as_bytes());
        assert_eq!(
            signer.public_key().as_bytes(),
            restored.public_key().as_bytes()
        );
    }

    #[test]
    fn test_checkpoint_body_format() {
        let hash = Sha256Hash::from_bytes([0u8; 32]);
        let checkpoint = Checkpoint::new(
            Origin::new("example.com/log".to_string()).unwrap(),
            TreeSize::new(100),
            hash,
        );

        let body = checkpoint.to_body();
        let lines: Vec<&str> = body.lines().collect();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "example.com/log");
        assert_eq!(lines[1], "100");
        // Base64 of 32 zero bytes
        assert_eq!(lines[2], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }

    #[test]
    fn test_merge_signatures() {
        let log_signer = CheckpointSigner::generate("log.example.com");
        let witness1 = CheckpointSigner::generate("witness1.example.com");
        let witness2 = CheckpointSigner::generate("witness2.example.com");

        let checkpoint = Checkpoint::new(
            Origin::new("log.example.com".to_string()).unwrap(),
            TreeSize::new(42),
            Sha256Hash::from_bytes([0u8; 32]),
        );

        // Create checkpoint signed by log
        let mut cosigned1 = CosignedCheckpoint::new(checkpoint.clone(), &log_signer);
        assert_eq!(cosigned1.signature_count(), 1);
        assert!(cosigned1.has_signature_from(log_signer.name()));

        // Create checkpoint signed by witness1
        let mut cosigned2 = CosignedCheckpoint::new(checkpoint.clone(), &witness1);
        cosigned2.add_signature(&witness2);
        assert_eq!(cosigned2.signature_count(), 2);

        // Merge witness signatures into log checkpoint
        cosigned1.merge_signatures(&cosigned2);
        assert_eq!(cosigned1.signature_count(), 3);
        assert!(cosigned1.has_signature_from(log_signer.name()));
        assert!(cosigned1.has_signature_from(witness1.name()));
        assert!(cosigned1.has_signature_from(witness2.name()));

        // Merging again should not duplicate
        cosigned1.merge_signatures(&cosigned2);
        assert_eq!(cosigned1.signature_count(), 3);
    }

    #[test]
    fn test_parse_spec_example_cosignature_line() {
        // Example cosignature line from c2sp.org/tlog-cosignature. The blob
        // is keyid(4) || timestamp(8, BE) || sig(64); the spec's message
        // example uses "time 1679315147".
        let line = "— witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==";
        let sig = CheckpointSignature::from_line(line).unwrap();
        assert_eq!(sig.name.as_str(), "witness.example.com/w1");
        assert_eq!(sig.timestamp, Some(1679315147));
        assert_eq!(sig.key_id.as_bytes(), &[0x8d, 0x66, 0xcf, 0x3f]);
        // Round-trip back to the identical line.
        assert_eq!(sig.to_line(), line);
    }

    #[test]
    fn test_cosignature_v1_message_format() {
        // Exact message layout from the spec.
        let body = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
        let msg = cosignature_v1_message(1679315147, body);
        assert_eq!(
            msg,
            "cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
        );
    }

    #[test]
    fn test_cosign_v1_roundtrip_verifies() {
        use ed25519_dalek::Verifier;

        let signer = CheckpointSigner::generate("witness.example.com");
        let checkpoint = Checkpoint::new(
            Origin::new("example.com/log".to_string()).unwrap(),
            TreeSize::new(42),
            Sha256Hash::from_bytes([7u8; 32]),
        );

        let cosig = signer.cosign_v1(&checkpoint, 1679315147);
        assert_eq!(cosig.timestamp, Some(1679315147));
        assert_eq!(cosig.key_id, signer.cosignature_v1_key_id());
        // The v1 key ID must differ from the plain note key ID.
        assert_ne!(&cosig.key_id, signer.key_id());

        let parsed = CheckpointSignature::from_line(&cosig.to_line()).unwrap();
        let msg = cosignature_v1_message(1679315147, &checkpoint.to_body());
        signer
            .public_key()
            .verify(msg.as_bytes(), &parsed.signature)
            .expect("cosignature/v1 must verify over the timestamped message");
    }

    #[test]
    fn test_origin_validation() {
        // Valid origins
        assert!(Origin::new("example.com/log".to_string()).is_ok());
        assert!(Origin::new("my-log".to_string()).is_ok());
        assert!(Origin::new("a".to_string()).is_ok());

        // Invalid: empty
        assert!(Origin::new("".to_string()).is_err());

        // Invalid: contains newline
        assert!(Origin::new("log\nwith\nnewlines".to_string()).is_err());
        assert!(Origin::new("log\rwith\rcarriage".to_string()).is_err());
        assert!(Origin::new("log\r\nmixed".to_string()).is_err());
    }
}
