// Regressions for the reproduced security review findings.
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use siglog::client::LogClient;
use siglog::{
    checkpoint::{Checkpoint, CheckpointSigner, CosignedCheckpoint, Origin},
    monitor::{Monitor, MonitoringWitness, ValidationError, ValidationResult},
    storage::{Database, TileStorage},
    types::{LogIndex, TreeSize},
    vindex::{JsonKeysMapFn, VerifiableIndex, WalWriter},
    witness::{AddCheckpointRequest, ConsistencyProof, LogConfig, Witness, WitnessStateStore},
    worker::{self, ExternalWitness, WorkerConfig},
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

fn config(s: &CheckpointSigner) -> LogConfig {
    let mut key = vec![1];
    key.extend_from_slice(s.public_key().as_bytes());
    LogConfig::new(
        "log".into(),
        &format!("log+{:08x}+{}", s.key_id().as_u32(), STANDARD.encode(key)),
    )
    .unwrap()
}
async fn database() -> Database {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    db
}
fn request(s: &CheckpointSigner, leaf: &[u8]) -> AddCheckpointRequest {
    AddCheckpointRequest {
        old_size: 0,
        proof: ConsistencyProof::default(),
        checkpoint: CosignedCheckpoint::new(
            Checkpoint::new(
                Origin::new("log".into()).unwrap(),
                TreeSize::new(1),
                sigstore_merkle::hash_leaf(leaf),
            ),
            s,
        )
        .to_text(),
    }
}

#[tokio::test]
async fn witness_rejects_conflicting_roots_under_concurrent_requests() {
    check_witness_race(database().await).await;
}

#[tokio::test]
async fn postgres_witness_rejects_conflicting_roots() {
    let Ok(url) = std::env::var("SIGLOG_TEST_POSTGRES_URL") else {
        return;
    };
    let db = Database::connect(&url).await.unwrap();
    db.run_migrations().await.unwrap();
    check_witness_race(db).await;
}

async fn check_witness_race(db: Database) {
    let conn = Arc::new(db.connection().clone());
    WitnessStateStore::new(conn.clone())
        .get_or_init("log")
        .await
        .unwrap();
    let log = CheckpointSigner::generate("log");
    let witness = Arc::new(Witness::new(
        Arc::new(CheckpointSigner::generate("witness")),
        conn,
        vec![config(&log)],
    ));
    let requests = (0u8..24).map(|i| request(&log, &[i])).collect::<Vec<_>>();
    let outcomes = futures::future::join_all(requests.into_iter().map(|r| {
        let w = witness.clone();
        async move { w.add_checkpoint(r).await }
    }))
    .await;
    let successes = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "a witness must never sign competing roots: {outcomes:?}"
    );
}

struct OnlyAllowed(AtomicUsize);
#[async_trait]
impl Monitor for OnlyAllowed {
    async fn load_state<C: sea_orm::ConnectionTrait>(
        &self,
        _: &C,
        _: &str,
    ) -> siglog::error::Result<()> {
        Ok(())
    }
    async fn validate_entry(&self, _: u64, data: &[u8]) -> siglog::error::Result<ValidationResult> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(if data == b"allowed" {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid(ValidationError::Other("blocked".into()))
        })
    }
    async fn commit_entries<C: sea_orm::ConnectionTrait>(
        &self,
        _: &C,
        _: &str,
        _: u64,
        _: u64,
    ) -> siglog::error::Result<()> {
        Ok(())
    }
    fn name(&self) -> &str {
        "only-allowed"
    }
}
#[tokio::test]
async fn monitor_rejects_unvalidated_root_and_empty_bundle() {
    for bundle in [b"\0\x07allowed".to_vec(), vec![]] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bundle.clone()))
            .mount(&server)
            .await;
        let db = database().await;
        let log = CheckpointSigner::generate("log");
        let mut conf = config(&log);
        conf.url = Some(server.uri());
        let monitor = Arc::new(OnlyAllowed(AtomicUsize::new(0)));
        let witness = MonitoringWitness::new(
            monitor.clone(),
            Arc::new(CheckpointSigner::generate("monitor")),
            Arc::new(db.connection().clone()),
            vec![conf],
        );
        let result = witness.add_checkpoint(request(&log, b"blocked")).await;
        assert!(result.is_err(), "{result:?}");
        assert_eq!(monitor.0.load(Ordering::SeqCst), 0);
        assert_eq!(witness.get_state("log").await.unwrap().unwrap().size, 0);
    }
}
#[tokio::test]
async fn monitor_rejects_concurrent_work_instead_of_queuing_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"\0\x07allowed".to_vec()))
        .mount(&server)
        .await;
    let db = database().await;
    let log = CheckpointSigner::generate("log");
    let mut conf = config(&log);
    conf.url = Some(server.uri());
    let witness = MonitoringWitness::new(
        Arc::new(OnlyAllowed(AtomicUsize::new(0))),
        Arc::new(CheckpointSigner::generate("monitor")),
        Arc::new(db.connection().clone()),
        vec![conf],
    );
    let (first, second) = tokio::join!(
        witness.add_checkpoint(request(&log, b"allowed")),
        witness.add_checkpoint(request(&log, b"allowed"))
    );
    assert!(first.is_ok());
    assert!(matches!(second, Err(siglog::monitor::MonitorError::Busy)));
}

#[tokio::test]
async fn publisher_rejects_forged_witness_signature() {
    let server = MockServer::start().await;
    let witness_signer = CheckpointSigner::generate("witness");
    let mut forged_bytes = witness_signer.key_id().as_bytes().to_vec();
    forged_bytes.extend_from_slice(&[0u8; 64]);
    let forged = format!("— witness {}", STANDARD.encode(forged_bytes));
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(forged.clone()))
        .mount(&server)
        .await;
    let db = database().await;
    let storage =
        TileStorage::new(opendal::Operator::new(opendal::services::Memory::default()).unwrap());
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(worker::run_checkpoint_worker(
        db,
        storage.clone(),
        Arc::new(CheckpointSigner::generate("log")),
        vec![],
        vec![ExternalWitness::new(&witness_signer.verification_key(), server.uri()).unwrap()],
        WorkerConfig {
            origin: "log".into(),
            checkpoint_interval: Duration::from_millis(1),
            ..Default::default()
        },
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.received_requests().await.unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    task.await.unwrap();
    assert!(!server.received_requests().await.unwrap().is_empty());
    assert!(storage.read_checkpoint().await.unwrap().is_none());
}
#[tokio::test]
async fn stale_checkpoint_snapshot_cannot_commit() {
    let db = database().await;
    let store = WitnessStateStore::new(Arc::new(db.connection().clone()));
    let initial = store.get_or_init("log").await.unwrap();
    assert!(store
        .update(&initial, 1, sigstore_merkle::hash_leaf(b"a"), "a")
        .await
        .unwrap());
    assert!(!store
        .update(&initial, 1, sigstore_merkle::hash_leaf(b"b"), "b")
        .await
        .unwrap());
    assert!(!store
        .update(&initial, 2, sigstore_merkle::hash_leaf(b"c"), "c")
        .await
        .unwrap());
}

#[test]
fn wal_truncates_uncommitted_entries_when_database_empty() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let mut wal = WalWriter::open(temp.path()).unwrap();
    wal.append(LogIndex::new(0), &[[5u8; 32]]).unwrap();
    wal.flush().unwrap();
    drop(wal);
    let index =
        VerifiableIndex::with_wal(Arc::new(JsonKeysMapFn::new("keys")), temp.path(), 0).unwrap();
    assert_eq!(index.tree_size(), 0);
    assert!(!index.lookup(&[5u8; 32]).found);
}
#[tokio::test]
async fn s3_storage_keeps_signed_read_write_support() {
    use wiremock::matchers::{header_exists, path};
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/bucket/checkpoint"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).insert_header("ETag", "\"test\""))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/bucket/checkpoint"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_string("checkpoint"))
        .expect(1)
        .mount(&server)
        .await;
    let storage =
        TileStorage::new_s3(&server.uri(), "bucket", "access", "secret", "us-east-1").unwrap();
    storage
        .write_checkpoint(&siglog::storage::opendal::CheckpointData::from(
            "checkpoint".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(
        storage
            .read_checkpoint()
            .await
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "checkpoint"
    );
}

#[tokio::test]
async fn remote_inclusion_crosses_tile_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let storage = TileStorage::new_fs(dir.path().to_str().unwrap()).unwrap();
    let hashes = (0..600)
        .map(|i| sigstore_merkle::hash_leaf(i.to_string().as_bytes()))
        .collect::<Vec<_>>();
    let result = siglog::merkle::integrate::integrate(&storage, 0.into(), &hashes)
        .await
        .unwrap();
    for (id, tile) in result.tiles {
        let partial =
            siglog::api::paths::partial_tile_size(id.level.value(), id.index.value(), 600);
        storage
            .write_tile(
                id.level,
                id.index,
                siglog::types::PartialSize::new(partial),
                &tile,
            )
            .await
            .unwrap();
    }
    let cp = Checkpoint::new(
        Origin::new("log".into()).unwrap(),
        600.into(),
        result.root_hash,
    );
    let server = MockServer::start().await;
    let root = dir.path().to_path_buf();
    Mock::given(method("GET"))
        .respond_with(move |req: &wiremock::Request| {
            let bytes = std::fs::read(root.join(req.url.path().trim_start_matches('/'))).unwrap();
            ResponseTemplate::new(200).set_body_bytes(bytes)
        })
        .mount(&server)
        .await;
    let client = LogClient::new(&server.uri()).unwrap();
    for i in [0, 1, 255, 256, 511, 599] {
        client
            .verify_entry(i.to_string().as_bytes(), i, &cp)
            .await
            .unwrap();
        assert!(client.verify_entry(b"forged", i, &cp).await.is_err());
    }
    assert!(client.verify_entry(b"outside", 600, &cp).await.is_err());
}

#[test]
fn vindex_recovery_rejects_missing_entries() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let index =
        VerifiableIndex::with_wal(Arc::new(JsonKeysMapFn::new("keys")), temp.path(), 0).unwrap();
    let too_many =
        serde_json::json!({"keys": (0..256).map(|i| format!("key-{i}")).collect::<Vec<_>>()});
    assert!(index
        .index_entry(0.into(), too_many.to_string().as_bytes())
        .is_err());
    assert!(index
        .index_entry(1.into(), br#"{"keys":["last"]}"#)
        .is_err());
    drop(index);
    let mut wal = WalWriter::open(temp.path()).unwrap();
    wal.append(LogIndex::new(1), &[[7u8; 32]]).unwrap();
    wal.flush().unwrap();
    drop(wal);
    assert!(
        VerifiableIndex::with_wal(Arc::new(JsonKeysMapFn::new("keys")), temp.path(), 2).is_err()
    );
}
