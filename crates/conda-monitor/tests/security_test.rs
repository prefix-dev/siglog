use conda_monitor::CondaMonitor;
use siglog::{
    checkpoint::{Checkpoint, CheckpointSigner, CosignedCheckpoint, Origin},
    monitor::MonitoringWitness,
    storage::{Database, TileStorage},
    types::Entry,
    witness::{AddCheckpointRequest, ConsistencyProof, LogConfig},
};
use std::sync::Arc;
use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

async fn checkpoint(
    server: &MockServer,
    signer: &CheckpointSigner,
    entries: &[&str],
) -> CosignedCheckpoint {
    let dir = tempfile::tempdir().unwrap();
    let storage = TileStorage::new_fs(dir.path().to_str().unwrap()).unwrap();
    let hashes = entries
        .iter()
        .map(|e| *Entry::new(*e).leaf_hash())
        .collect::<Vec<_>>();
    let integrated = siglog::merkle::integrate::integrate(&storage, 0.into(), &hashes)
        .await
        .unwrap();
    let mut bundle = Vec::new();
    for entry in entries {
        bundle.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        bundle.extend_from_slice(entry.as_bytes());
    }
    Mock::given(path(format!("/tile/entries/000.p/{}", entries.len())))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle))
        .mount(server)
        .await;
    Mock::given(path(format!("/tile/0/000.p/{}", entries.len())))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(
                hashes
                    .iter()
                    .flat_map(|h| h.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            ),
        )
        .mount(server)
        .await;
    CosignedCheckpoint::new(
        Checkpoint::new(
            Origin::new(signer.name().to_string()).unwrap(),
            integrated.new_size,
            integrated.root_hash,
        ),
        signer,
    )
}
fn request(cp: &CosignedCheckpoint, old: u64, proof: ConsistencyProof) -> AddCheckpointRequest {
    AddCheckpointRequest {
        checkpoint: cp.to_text(),
        old_size: old,
        proof,
    }
}

#[tokio::test]
async fn monitor_isolates_origins_and_preserves_policy_after_restart() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    let signer_a = CheckpointSigner::generate("A");
    let signer_b = CheckpointSigner::generate("B");
    let configs = vec![
        LogConfig::with_url("A".into(), &signer_a.verification_key(), a.uri()).unwrap(),
        LogConfig::with_url("B".into(), &signer_b.verification_key(), b.uri()).unwrap(),
    ];
    let make = || {
        MonitoringWitness::new(
            Arc::new(CondaMonitor::new()),
            Arc::new(CheckpointSigner::generate("monitor")),
            Arc::new(db.connection().clone()),
            configs.clone(),
        )
    };
    let monitor = make();
    monitor.load_state().await.unwrap();
    let original = r#"{"filename":"pkg.conda","sha256":"original"}"#;
    let replacement = r#"{"filename":"pkg.conda","sha256":"replacement"}"#;
    let cp_a = checkpoint(&a, &signer_a, &[original]).await;
    monitor
        .add_checkpoint(request(&cp_a, 0, ConsistencyProof::default()))
        .await
        .unwrap();
    let cp_b = checkpoint(&b, &signer_b, &[replacement]).await;
    monitor
        .add_checkpoint(request(&cp_b, 0, ConsistencyProof::default()))
        .await
        .unwrap();
    let attack = checkpoint(&a, &signer_a, &[original, replacement]).await;
    let req = request(
        &attack,
        1,
        ConsistencyProof::new(vec![*Entry::new(replacement).leaf_hash()]),
    );
    assert!(monitor.add_checkpoint(req.clone()).await.is_err());
    drop(monitor);
    let restarted = make();
    restarted.load_state().await.unwrap();
    assert!(restarted.add_checkpoint(req).await.is_err());
    assert_eq!(restarted.get_state("A").await.unwrap().unwrap().size, 1);
    // A failed validation must not advance the checkpoint or poison later requests.
    restarted
        .add_checkpoint(request(&cp_a, 1, ConsistencyProof::default()))
        .await
        .unwrap();
}

#[tokio::test]
async fn cli_requires_authentic_inclusion_and_fails_with_nonzero_exit() {
    let server = MockServer::start().await;
    let signer = CheckpointSigner::generate("log");
    let entry = r#"{"filename":"pkg.conda","subdir":"linux-64","sha256":"original"}"#;
    let cp = checkpoint(&server, &signer, &[entry]).await;
    Mock::given(path(
        "/vindex/lookup/".to_string() + &hex::encode(sha2::Sha256::digest(b"pkg.conda")),
    ))
    .respond_with(
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"found":true,"indices":[0]})),
    )
    .mount(&server)
    .await;
    let repodata = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(repodata.path(), r#"{"packages":{"pkg.conda":{"name":"pkg","version":"1","build":"0","build_number":0,"size":1,"sha256":"different"}}}"#).unwrap();
    let wrong_key =
        CosignedCheckpoint::new(cp.checkpoint.clone(), &CheckpointSigner::generate("log"));
    for (text, success, compare) in [
        (
            "forged-log\n1\nnot-a-root\n\n— nobody not-a-signature\n".to_string(),
            false,
            false,
        ),
        (wrong_key.to_text(), false, false),
        (cp.to_text(), true, false),
        (cp.to_text(), false, true),
    ] {
        let mock = Mock::given(path("/checkpoint"))
            .respond_with(ResponseTemplate::new(200).set_body_string(text))
            .mount_as_scoped(&server)
            .await;
        let mut args = vec![
            "--log-url".to_string(),
            server.uri(),
            "--log-origin".into(),
            "log".into(),
            "--log-key".into(),
            signer.verification_key(),
            "--subdir".into(),
            "linux-64".into(),
            "--filename".into(),
            "pkg.conda".into(),
        ];
        if compare {
            args.extend([
                "--repodata-file".into(),
                repodata.path().to_str().unwrap().to_string(),
            ]);
        }
        let result = tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_conda-log-verify"))
                .args(args)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            result.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        drop(mock);
    }
    // A genuine signature over different content is not enough for inclusion.
    let wrong_cp = CosignedCheckpoint::new(
        Checkpoint::new(
            Origin::new("log".into()).unwrap(),
            1.into(),
            *Entry::new("different").leaf_hash(),
        ),
        &signer,
    );
    let _mock = Mock::given(path("/checkpoint"))
        .respond_with(ResponseTemplate::new(200).set_body_string(wrong_cp.to_text()))
        .mount_as_scoped(&server)
        .await;
    let args = vec![
        "--log-url".to_string(),
        server.uri(),
        "--log-origin".into(),
        "log".into(),
        "--log-key".into(),
        signer.verification_key(),
        "--subdir".into(),
        "linux-64".into(),
        "--filename".into(),
        "pkg.conda".into(),
    ];
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_conda-log-verify"))
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(!result.status.success());
}
use sha2::Digest;

#[tokio::test]
async fn monitor_rolls_back_content_when_checkpoint_commit_fails() {
    use sea_orm::ConnectionTrait;
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    let server = MockServer::start().await;
    let signer = CheckpointSigner::generate("log");
    let cp = checkpoint(
        &server,
        &signer,
        &[r#"{"filename":"pkg","sha256":"original"}"#],
    )
    .await;
    let monitor = MonitoringWitness::new(
        Arc::new(CondaMonitor::new()),
        Arc::new(CheckpointSigner::generate("monitor")),
        Arc::new(db.connection().clone()),
        vec![LogConfig::with_url("log".into(), &signer.verification_key(), server.uri()).unwrap()],
    );
    db.connection().execute_unprepared("CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON witness_state WHEN NEW.size > 0 BEGIN SELECT RAISE(FAIL, 'injected failure'); END").await.unwrap();
    let req = request(&cp, 0, ConsistencyProof::default());
    assert!(monitor.add_checkpoint(req.clone()).await.is_err());
    assert_eq!(monitor.get_state("log").await.unwrap().unwrap().size, 0);
    let rows = db
        .connection()
        .query_all_raw(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT * FROM content_index",
        ))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "content must roll back with the failed checkpoint"
    );
    db.connection()
        .execute_unprepared("DROP TRIGGER reject_checkpoint")
        .await
        .unwrap();
    monitor.add_checkpoint(req).await.unwrap();
}
