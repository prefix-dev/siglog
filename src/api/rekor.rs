//! Rekor v2 HTTP/JSON submission API (hashedrekord 0.0.2).

use super::handlers::{authorize_write, AppState, MAX_ENTRY_SIZE};
use crate::checkpoint::signer::{CheckpointSigner, CosignedCheckpoint};
use crate::error::{Error, Result};
use crate::merkle::proof::generate_inclusion_proof;
use crate::types::Entry;
use aws_lc_rs::{digest, signature};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{
    alphabet,
    engine::{general_purpose::STANDARD, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoOwned, Certificate};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateEntryRequest {
    #[serde(alias = "hashed_rekord_request_v002")]
    hashed_rekord_request_v002: HashedRekord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashedRekord {
    digest: String,
    signature: Signature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    content: String,
    verifier: Verifier,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Verifier {
    #[serde(alias = "public_key")]
    public_key: Option<EncodedKey>,
    #[serde(alias = "x509_certificate")]
    x509_certificate: Option<EncodedKey>,
    #[serde(alias = "key_details")]
    key_details: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncodedKey {
    #[serde(alias = "raw_bytes")]
    raw_bytes: String,
}

fn invalid(message: impl ToString) -> Error {
    Error::InvalidEntry(message.to_string())
}

// ProtoJSON accepts standard/URL-safe base64 with or without padding.
fn decode(value: &str) -> Result<Vec<u8>> {
    let config =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    GeneralPurpose::new(&alphabet::STANDARD, config)
        .decode(value)
        .or_else(|_| GeneralPurpose::new(&alphabet::URL_SAFE, config).decode(value))
        .map_err(|_| invalid("invalid base64"))
}

fn canonical_entry(body: &[u8]) -> Result<Vec<u8>> {
    let request: CreateEntryRequest = serde_json::from_slice(body).map_err(invalid)?;
    let hr = request.hashed_rekord_request_v002;
    let sig = decode(&hr.signature.content)?;
    let hash = decode(&hr.digest)?;
    let verifier = hr.signature.verifier;
    let (spki, material) = match (verifier.public_key, verifier.x509_certificate) {
        (Some(key), None) => {
            let der = decode(&key.raw_bytes)?;
            let spki = SubjectPublicKeyInfoOwned::from_der(&der).map_err(invalid)?;
            (
                spki,
                json!({"publicKey": {"rawBytes": STANDARD.encode(der)}}),
            )
        }
        (None, Some(cert)) => {
            let der = decode(&cert.raw_bytes)?;
            let cert = Certificate::from_der(&der).map_err(invalid)?;
            (
                cert.tbs_certificate.subject_public_key_info,
                json!({"x509Certificate": {"rawBytes": STANDARD.encode(der)}}),
            )
        }
        _ => {
            return Err(invalid(
                "exactly one publicKey or x509Certificate is required",
            ))
        }
    };
    let details = match &verifier.key_details {
        Value::String(s) => s.as_str(),
        Value::Number(n) => match n.as_u64() {
            Some(5) => "PKIX_ECDSA_P256_SHA_256",
            Some(8) => "PKIX_ED25519_PH",
            Some(12) => "PKIX_ECDSA_P384_SHA_384",
            Some(13) => "PKIX_ECDSA_P521_SHA_512",
            Some(9) => "PKIX_RSA_PKCS1V15_2048_SHA256",
            Some(10) => "PKIX_RSA_PKCS1V15_3072_SHA256",
            Some(11) => "PKIX_RSA_PKCS1V15_4096_SHA256",
            _ => return Err(invalid("unsupported keyDetails")),
        },
        _ => return Err(invalid("invalid keyDetails")),
    };
    let (algorithm, hash_algorithm, hash_name, curve, rsa_bits): (
        &dyn signature::VerificationAlgorithm,
        &digest::Algorithm,
        &str,
        Option<&str>,
        u32,
    ) = match details {
        "PKIX_ED25519_PH" => (
            &signature::ED25519, // Only the dalek prehashed verifier below is used for this variant.
            &digest::SHA512,
            "SHA2_512",
            None,
            0,
        ),
        "PKIX_ECDSA_P256_SHA_256" => (
            &signature::ECDSA_P256_SHA256_ASN1,
            &digest::SHA256,
            "SHA2_256",
            Some("1.2.840.10045.3.1.7"),
            0,
        ),
        "PKIX_ECDSA_P384_SHA_384" => (
            &signature::ECDSA_P384_SHA384_ASN1,
            &digest::SHA384,
            "SHA2_384",
            Some("1.3.132.0.34"),
            0,
        ),
        "PKIX_ECDSA_P521_SHA_512" => (
            &signature::ECDSA_P521_SHA512_ASN1,
            &digest::SHA512,
            "SHA2_512",
            Some("1.3.132.0.35"),
            0,
        ),
        "PKIX_RSA_PKCS1V15_2048_SHA256" => (
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &digest::SHA256,
            "SHA2_256",
            None,
            2048,
        ),
        "PKIX_RSA_PKCS1V15_3072_SHA256" => (
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &digest::SHA256,
            "SHA2_256",
            None,
            3072,
        ),
        "PKIX_RSA_PKCS1V15_4096_SHA256" => (
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &digest::SHA256,
            "SHA2_256",
            None,
            4096,
        ),
        _ => return Err(invalid(
            "unsupported keyDetails; use Ed25519ph, ECDSA P-256/P-384/P-521 or RSA PKCS#1 SHA-256",
        )),
    };
    let raw_key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| invalid("unaligned public key"))?;
    if details == "PKIX_ED25519_PH" {
        // RFC 8410: Ed25519 SPKI parameters MUST be absent, not NULL.
        if spki.algorithm.oid.to_string() != "1.3.101.112" || spki.algorithm.parameters.is_some() {
            return Err(invalid("public key algorithm does not match keyDetails"));
        }
    } else if let Some(curve) = curve {
        let params = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<x509_cert::der::asn1::ObjectIdentifier>().ok());
        if spki.algorithm.oid.to_string() != "1.2.840.10045.2.1"
            || params.map(|p| p.to_string()).as_deref() != Some(curve)
        {
            return Err(invalid("public key algorithm does not match keyDetails"));
        }
    } else if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1"
        || spki
            .algorithm
            .parameters
            .as_ref()
            .is_some_and(|p| !p.is_null())
        || signature::RsaParameters::public_modulus_len(raw_key)
            .map_err(|_| invalid("invalid RSA key"))?
            != rsa_bits
    {
        return Err(invalid(
            "RSA key size or algorithm does not match keyDetails",
        ));
    }
    let imported = digest::Digest::import_less_safe(&hash, hash_algorithm)
        .map_err(|_| invalid("digest length does not match keyDetails"))?;
    if details == "PKIX_ED25519_PH" {
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            raw_key
                .try_into()
                .map_err(|_| invalid("Ed25519 key must be 32 bytes"))?,
        )
        .map_err(invalid)?;
        let signature = ed25519_dalek::Signature::from_slice(&sig).map_err(invalid)?;
        // Import the supplied SHA-512 digest; do NOT hash it a second time.
        let prehash = Sha512Prehash(imported.as_ref().try_into().map_err(invalid)?);
        key.verify_prehashed_strict(prehash, None, &signature)
            .map_err(|_| invalid("invalid artifact signature"))?;
    } else {
        signature::UnparsedPublicKey::new(algorithm, raw_key)
            .verify_digest(&imported, &sig)
            .map_err(|_| invalid("invalid artifact signature"))?;
    }

    let mut material = material;
    material["keyDetails"] = json!(details);
    // All keys and values in this schema are ASCII strings, objects, or base64.
    // Sorted serde_json maps therefore give the same bytes as RFC 8785 JCS;
    // no user-supplied numbers or arbitrary JSON are passed through.
    let entry = json!({
        "apiVersion": "0.0.2", "kind": "hashedrekord",
        "spec": {"hashedRekordV002": {
            "data": {"algorithm": hash_name, "digest": STANDARD.encode(hash)},
            "signature": {"content": STANDARD.encode(sig), "verifier": material}
        }}
    });
    let bytes = serde_json::to_vec(&entry).map_err(|e| Error::Internal(e.to_string()))?;
    if bytes.len() > MAX_ENTRY_SIZE {
        return Err(invalid("canonical entry exceeds 65535 bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use sha2::Sha512;

    #[test]
    fn ed25519ph_rfc8032_and_domain_separation() {
        // RFC 8032 section 7.3, message "abc".
        let seed = hex::decode("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
            .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(seed.as_slice().try_into().unwrap());
        let mut der = hex::decode("302a300506032b6570032100").unwrap();
        der.extend_from_slice(key.verifying_key().as_bytes());
        let digest = Sha512::digest(b"abc");
        let expected = hex::decode(concat!(
            "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41",
            "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"
        ))
        .unwrap();
        let request = json!({"hashedRekordRequestV002": {
            "digest": STANDARD.encode(digest),
            "signature": {"content": STANDARD.encode(&expected), "verifier": {
                "publicKey": {"rawBytes": STANDARD.encode(&der)}, "keyDetails": "PKIX_ED25519_PH"
            }}
        }});
        let canonical = canonical_entry(request.to_string().as_bytes()).unwrap();
        let entry: Value = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(
            entry["spec"]["hashedRekordV002"]["data"]["algorithm"],
            "SHA2_512"
        );
        let mut numeric = request.clone();
        numeric["hashedRekordRequestV002"]["signature"]["verifier"]["keyDetails"] = json!(8);
        assert_eq!(
            canonical_entry(numeric.to_string().as_bytes()).unwrap(),
            canonical
        );

        for signature in [
            key.sign(&digest).to_bytes(), // Pure Ed25519 over the digest is NOT Ed25519ph.
            key.sign_prehashed(Sha512::new_with_prefix(digest), None)
                .unwrap()
                .to_bytes(),
            key.sign_prehashed(Sha512::new_with_prefix(b"abc"), Some(b"context"))
                .unwrap()
                .to_bytes(),
            [0u8; 64],
        ] {
            let mut bad = request.clone();
            bad["hashedRekordRequestV002"]["signature"]["content"] =
                json!(STANDARD.encode(signature));
            assert!(canonical_entry(bad.to_string().as_bytes()).is_err());
        }
        for size in [0, 32, 63, 65] {
            let mut bad = request.clone();
            bad["hashedRekordRequestV002"]["digest"] = json!(STANDARD.encode(vec![0; size]));
            assert!(canonical_entry(bad.to_string().as_bytes()).is_err());
        }
        let mut bad = request.clone();
        let mut null_params = hex::decode("302c300706032b65700500032100").unwrap();
        null_params.extend_from_slice(key.verifying_key().as_bytes());
        bad["hashedRekordRequestV002"]["signature"]["verifier"]["publicKey"]["rawBytes"] =
            json!(STANDARD.encode(null_params));
        assert!(canonical_entry(bad.to_string().as_bytes()).is_err());
    }
}

// dalek's prehashed API takes a Digest rather than digest bytes. This private
// adapter is finalized exactly once by verify_prehashed_strict; it cannot hash data.
#[derive(Clone)]
struct Sha512Prehash([u8; 64]);

impl Default for Sha512Prehash {
    fn default() -> Self {
        Self([0; 64])
    }
}
impl sha2::digest::OutputSizeUser for Sha512Prehash {
    type OutputSize = sha2::digest::consts::U64;
}
impl sha2::digest::HashMarker for Sha512Prehash {}
impl sha2::digest::Update for Sha512Prehash {
    fn update(&mut self, _data: &[u8]) {
        unreachable!("a precomputed digest cannot be updated");
    }
}
impl sha2::digest::FixedOutput for Sha512Prehash {
    fn finalize_into(self, out: &mut sha2::digest::Output<Self>) {
        out.copy_from_slice(&self.0);
    }
}

pub async fn create_entry(
    State(state): State<Arc<AppState>>,
    Extension(signer): Extension<Arc<CheckpointSigner>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        submit(&state, &signer, &headers, &body),
    )
    .await;
    match result {
        Ok(Ok(entry)) => (StatusCode::CREATED, Json(entry)).into_response(),
        Ok(Err(Error::Unauthorized)) => rekor_error(StatusCode::UNAUTHORIZED, 16, "Unauthorized"),
        Ok(Err(Error::Duplicate(index))) => {
            let mut response = rekor_error(StatusCode::CONFLICT, 6, "Entry already exists");
            response.headers_mut().insert(
                "x-log-index",
                index.to_string().parse().expect("decimal index"),
            );
            response
        }
        Ok(Err(Error::InvalidEntry(message))) => rekor_error(StatusCode::BAD_REQUEST, 3, &message),
        Ok(Err(error)) => {
            tracing::error!(%error, "Rekor submission failed");
            rekor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                13,
                "Internal server error",
            )
        }
        Err(_) => rekor_error(
            StatusCode::GATEWAY_TIMEOUT,
            4,
            "Timed out waiting for inclusion; entry may still be integrated",
        ),
    }
}

fn rekor_error(status: StatusCode, code: u8, message: &str) -> Response {
    (
        status,
        Json(json!({"code": code, "message": message, "details": []})),
    )
        .into_response()
}

async fn submit(
    state: &AppState,
    signer: &CheckpointSigner,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value> {
    authorize_write(state, headers)?;
    let canonical = canonical_entry(body)?;
    let entry = Entry::new(canonical.clone());
    let leaf = *entry.leaf_hash();
    let index = state.sequencer.add(entry).await?.value();
    loop {
        if let Some(data) = state.storage.read_checkpoint().await? {
            let envelope = data.as_str()?;
            let signed = CosignedCheckpoint::from_text(envelope)?;
            let cp = &signed.checkpoint;
            if cp.size.value() > index {
                // Never combine the latest DB root with an older published checkpoint.
                let body = cp.to_body();
                let valid = signed.signatures.iter().any(|sig| {
                    sig.name == *signer.name()
                        && sig.key_id == *signer.key_id()
                        && signer
                            .public_key()
                            .verify_strict(body.as_bytes(), &sig.signature)
                            .is_ok()
                });
                if !valid {
                    return Err(Error::Internal(
                        "invalid published checkpoint signature".into(),
                    ));
                }
                let hashes =
                    generate_inclusion_proof(&state.storage, index, cp.size.value()).await?;
                sigstore_merkle::verify_inclusion_proof(
                    &leaf,
                    index,
                    cp.size.value(),
                    &hashes,
                    &cp.root_hash,
                )
                .map_err(|e| Error::Merkle(e.to_string()))?;
                // Full (untruncated) C2SP note key ID, as used by rekor-tiles v2.
                let mut id = Sha256::new();
                id.update(signer.name().as_str());
                id.update(b"\n\x01");
                id.update(signer.public_key().as_bytes());
                return Ok(json!({
                    "logIndex": index.to_string(),
                    "logId": {"keyId": STANDARD.encode(id.finalize())},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                    "canonicalizedBody": STANDARD.encode(&canonical),
                    "inclusionProof": {
                        "logIndex": index.to_string(), "treeSize": cp.size.value().to_string(),
                        "rootHash": STANDARD.encode(cp.root_hash.as_bytes()),
                        "hashes": hashes.iter().map(|h| STANDARD.encode(h.as_bytes())).collect::<Vec<_>>(),
                        "checkpoint": {"envelope": envelope}
                    }
                }));
            }
        }
        // Poll published checkpoints; use worker notifications if write volume warrants it.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
