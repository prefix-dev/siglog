use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siglog::{
    api::{self, handlers::AppState, Mode},
    checkpoint::{signer::CosignedCheckpoint, CheckpointSigner},
    sequencer::{Sequencer, SequencerConfig},
    storage::{Database, TileStorage},
    worker::{self, WorkerConfig},
};
use sigstore_crypto::signing::KeyPair;
use sigstore_types::Sha256Hash;
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

fn signed_request() -> Value {
    let key = KeyPair::generate_ecdsa_p256().unwrap();
    let artifact = b"artifact";
    json!({"hashedRekordRequestV002": {
        "digest": STANDARD.encode(Sha256::digest(artifact)),
        "signature": {
            "content": STANDARD.encode(key.sign(artifact).unwrap().as_bytes()),
            "verifier": {
                "publicKey": {"rawBytes": STANDARD.encode(key.public_key_der().unwrap().as_bytes())},
                "keyDetails": "PKIX_ECDSA_P256_SHA_256"
            }
        }
    }})
}

fn post(value: &Value, auth: bool) -> Request<Body> {
    let mut req = Request::post("/api/v2/log/entries").header("Content-Type", "application/json");
    if auth {
        req = req.header("Authorization", "Bearer secret");
    }
    req.body(Body::from(value.to_string())).unwrap()
}

#[tokio::test]
async fn rekor_submission_and_mode_isolation() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    db.ensure_mode(Mode::Rekor).await.unwrap();
    db.ensure_mode(Mode::Rekor).await.unwrap();
    assert!(db.ensure_mode(Mode::Tessera).await.is_err());
    let storage =
        TileStorage::new(opendal::Operator::new(opendal::services::Memory::default()).unwrap());
    let signer = Arc::new(CheckpointSigner::generate("test.log"));
    let (sequencer, task) = Sequencer::new(
        db.clone(),
        SequencerConfig {
            batch_max_age: Duration::from_millis(1),
            ..Default::default()
        },
    );
    let task = tokio::spawn(task);
    let state = Arc::new(
        AppState::new(storage.clone(), sequencer, db.clone()).with_api_key("secret".into()),
    );
    let app = api::router(Mode::Rekor, signer.clone()).with_state(state.clone());
    for path in ["/add", "/checkpoint", "/tile/0/000"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let valid = signed_request();
    assert_eq!(
        app.clone()
            .oneshot(post(&valid, false))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut invalids = vec![json!({}), json!({"dsseRequestV002": {}})];
    for (path, replacement) in [
        (
            "/hashedRekordRequestV002/digest",
            json!(STANDARD.encode([0u8; 32])),
        ),
        (
            "/hashedRekordRequestV002/digest",
            json!(STANDARD.encode([0u8; 31])),
        ),
        ("/hashedRekordRequestV002/digest", json!("!invalid-base64")),
        ("/hashedRekordRequestV002/signature/content", json!("")),
        (
            "/hashedRekordRequestV002/signature/verifier/keyDetails",
            json!("PKIX_ECDSA_P384_SHA_384"),
        ),
        (
            "/hashedRekordRequestV002/signature/verifier/publicKey/rawBytes",
            json!("AAAA"),
        ),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(path).unwrap() = replacement;
        invalids.push(bad);
    }
    let mut bad = valid.clone();
    bad["hashedRekordRequestV002"]["signature"]["verifier"]["x509Certificate"] =
        json!({"rawBytes": "AAAA"});
    invalids.push(bad);
    let mut bad = valid.clone();
    bad["hashedRekordRequestV002"]["signature"]["verifier"]["keyDetails"] = json!("PKIX_ED25519");
    invalids.push(bad);
    for bad in invalids {
        let response = app.clone().oneshot(post(&bad, true)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(error["code"], 3);
    }
    let oversized = Request::post("/api/v2/log/entries")
        .header("Authorization", "Bearer secret")
        .body(Body::from(vec![b' '; 65536]))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(oversized).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 0);
    let request = tokio::spawn(app.clone().oneshot(post(&valid, true)));
    // Sequencing alone must not yield a successful Rekor response.
    tokio::time::timeout(Duration::from_secs(5), async {
        while db.get_log_state().await.unwrap().next_index.value() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(!request.is_finished());
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 1);
    // Retrying while the first request awaits integration must not append again.
    let duplicate = app.clone().oneshot(post(&valid, true)).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(duplicate.headers()["x-log-index"], "0");

    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let config = WorkerConfig {
        integration_interval: Duration::from_millis(5),
        checkpoint_interval: Duration::from_millis(5),
        origin: "test.log".into(),
        ..Default::default()
    };
    let integration = tokio::spawn(worker::run_integration_worker(
        db.clone(),
        storage.clone(),
        config.clone(),
        None,
        rx.clone(),
    ));
    let checkpoints = tokio::spawn(worker::run_checkpoint_worker(
        db.clone(),
        storage.clone(),
        signer.clone(),
        vec![],
        vec![],
        config,
        rx,
    ));
    let response = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let entry: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(entry["logIndex"], "0");
    assert_eq!(
        entry["kindVersion"],
        json!({"kind": "hashedrekord", "version": "0.0.2"})
    );
    assert!(entry.get("inclusionPromise").is_none());
    let canonical = STANDARD
        .decode(entry["canonicalizedBody"].as_str().unwrap())
        .unwrap();
    let body: Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(
        body["spec"]["hashedRekordV002"]["data"]["algorithm"],
        "SHA2_256"
    );
    let proof = &entry["inclusionProof"];
    let checkpoint =
        CosignedCheckpoint::from_text(proof["checkpoint"]["envelope"].as_str().unwrap()).unwrap();
    signer
        .public_key()
        .verify_strict(
            checkpoint.checkpoint.to_body().as_bytes(),
            &checkpoint.signatures[0].signature,
        )
        .unwrap();
    let hashes: Vec<_> = proof["hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            Sha256Hash::try_from_slice(&STANDARD.decode(h.as_str().unwrap()).unwrap()).unwrap()
        })
        .collect();
    sigstore_merkle::verify_inclusion_proof(
        &sigstore_merkle::hash_leaf(&canonical),
        0,
        checkpoint.checkpoint.size.value(),
        &hashes,
        &checkpoint.checkpoint.root_hash,
    )
    .unwrap();
    let bundle = app
        .clone()
        .oneshot(
            Request::get("/api/v2/tile/entries/000.p/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::OK);
    let bundle = siglog::merkle::EntryBundle::from_bytes(
        &to_bytes(bundle.into_body(), 65536).await.unwrap(),
    )
    .unwrap();
    assert_eq!(bundle.entries[0].as_bytes(), canonical);
    for path in ["/api/v2/checkpoint", "/api/v2/tile/0/000.p/1"] {
        assert_eq!(
            app.clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    // ProtoJSON aliases and alternate byte encodings normalize to identical leaves.
    let mut alternate = valid.clone();
    for path in [
        "/hashedRekordRequestV002/digest",
        "/hashedRekordRequestV002/signature/content",
        "/hashedRekordRequestV002/signature/verifier/publicKey/rawBytes",
    ] {
        let value = alternate.pointer_mut(path).unwrap();
        let bytes = STANDARD.decode(value.as_str().unwrap()).unwrap();
        *value = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    }
    alternate["hashedRekordRequestV002"]["signature"]["verifier"]["keyDetails"] = json!(5);
    let alternate: Value = serde_json::from_str(
        &alternate
            .to_string()
            .replace("hashedRekordRequestV002", "hashed_rekord_request_v002")
            .replace("publicKey", "public_key")
            .replace("rawBytes", "raw_bytes")
            .replace("keyDetails", "key_details"),
    )
    .unwrap();
    let response = app.oneshot(post(&alternate, true)).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()["x-log-index"], "0");
    let error: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(error["code"], 6);
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 1);

    let tessera = api::router(Mode::Tessera, signer).with_state(state);
    assert_eq!(
        tessera
            .clone()
            .oneshot(post(&valid, true))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let response = tessera
        .oneshot(
            Request::post("/add")
                .header("Authorization", "Bearer secret")
                .body(Body::from("raw bytes"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 100).await.unwrap().as_ref(),
        b"1"
    );
    shutdown.send(true).unwrap();
    integration.await.unwrap();
    checkpoints.await.unwrap();
    task.abort();
}

#[tokio::test]
async fn existing_unmarked_logs_are_tessera() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    db.sequence_entries(vec![siglog::types::Entry::new("legacy")])
        .await
        .unwrap();
    assert!(db.ensure_mode(Mode::Rekor).await.is_err());
    db.ensure_mode(Mode::Tessera).await.unwrap();
}

#[tokio::test]
async fn inclusion_paths_across_tile_boundaries() {
    use siglog::{
        merkle::{integrate::integrate, proof::generate_inclusion_proof},
        types::TreeSize,
    };
    let storage =
        TileStorage::new(opendal::Operator::new(opendal::services::Memory::default()).unwrap());
    let leaves: Vec<_> = (0u64..1025)
        .map(|i| sigstore_merkle::hash_leaf(&i.to_be_bytes()))
        .collect();
    let mut from = 0;
    for size in [1, 2, 3, 7, 128, 255, 256, 257, 511, 512, 1025] {
        let result = integrate(
            &storage,
            TreeSize::new(from),
            &leaves[from as usize..size as usize],
        )
        .await
        .unwrap();
        for (id, tile) in &result.tiles {
            let partial = api::paths::partial_tile_size(id.level.value(), id.index.value(), size);
            storage
                .write_tile(id.level, id.index, partial.into(), tile)
                .await
                .unwrap();
        }
        for index in [0, size / 2, size - 1] {
            let proof = generate_inclusion_proof(&storage, index, size)
                .await
                .unwrap();
            sigstore_merkle::verify_inclusion_proof(
                &leaves[index as usize],
                index,
                size,
                &proof,
                &result.root_hash,
            )
            .unwrap();
        }
        assert!(generate_inclusion_proof(&storage, size, size)
            .await
            .is_err());
        from = size;
    }
}
