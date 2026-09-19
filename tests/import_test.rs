use siglog::{
    api::{self, Mode},
    checkpoint::CheckpointSigner,
    error::{Error, Result},
    import::{bulk_import, ImportConfig, InputSummary},
    merkle::{proof::generate_inclusion_proof, EntryBundle},
    storage::{Database, TileStorage},
    types::{Entry, EntryData, PartialSize, TileIndex},
    vindex::{JsonKeysMapFn, VerifiableIndex},
    worker::{self, WorkerConfig},
};
use sigstore_types::Sha256Hash;
use std::{sync::Arc, time::Duration};

async fn database() -> Database {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    db
}
fn storage() -> TileStorage {
    TileStorage::new(opendal::Operator::new(opendal::services::Memory::default()).unwrap())
}
fn data(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!(r#"{{"name":"pkg-{i}"}}"#).into_bytes())
        .collect()
}
fn entries(data: &[Vec<u8>]) -> impl Iterator<Item = Result<Vec<u8>>> + '_ {
    data.iter().cloned().map(Ok)
}
fn input(data: &[Vec<u8>]) -> InputSummary {
    InputSummary::scan(entries(data)).unwrap()
}
fn config(resume: bool) -> ImportConfig {
    ImportConfig {
        chunk_size: 256,
        resume,
        ..Default::default()
    }
}
// Independent recursive RFC6962 tree construction, not the production integrator.
fn root(data: &[Vec<u8>]) -> Sha256Hash {
    if data.len() == 1 {
        return sigstore_merkle::hash_leaf(&data[0]);
    }
    let split = data.len().next_power_of_two() / 2;
    sigstore_merkle::hash_children(&root(&data[..split]), &root(&data[split..]))
}

#[tokio::test]
async fn bootstrap_restart_proofs_vindex_and_normal_append() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("log.db").display());
    let db = Database::connect(&url).await.unwrap();
    db.run_migrations().await.unwrap();
    let storage = TileStorage::new_fs(dir.path().join("tiles").to_str().unwrap()).unwrap();
    let mut data = data(700);
    let imported = bulk_import(&db, &storage, &input(&data), &config(false), entries(&data))
        .await
        .unwrap();
    assert_eq!(imported.root_hash, root(&data));
    assert!(
        storage.read_checkpoint().await.unwrap().is_none(),
        "import must not bypass witness policy"
    );
    assert!(db.ensure_mode(Mode::Rekor).await.is_err());
    drop(db);
    let db = Database::connect(&url).await.unwrap();
    assert_eq!(
        db.get_log_state().await.unwrap().integrated_size.value(),
        700
    );
    let wal = dir.path().join("index.wal");
    let index = Arc::new(
        VerifiableIndex::rebuild_from_storage(
            Arc::new(JsonKeysMapFn::new("name")),
            &wal,
            700,
            &storage,
        )
        .await
        .unwrap(),
    );
    assert_eq!(index.lookup_string("pkg-699").indices[0].value(), 699);
    let reloaded =
        VerifiableIndex::with_wal(Arc::new(JsonKeysMapFn::new("name")), &wal, 700).unwrap();
    assert_eq!(reloaded.root_hash(), index.root_hash());
    drop(reloaded);

    let appended = br#"{"name":"after-import"}"#.to_vec();
    let assigned = db
        .sequence_entries(vec![Entry::new(appended.clone())])
        .await
        .unwrap();
    assert_eq!(assigned[0].as_ref().unwrap().index().value(), 700);
    data.push(appended);
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let cfg = WorkerConfig {
        origin: "import.test".into(),
        integration_interval: Duration::from_millis(5),
        checkpoint_interval: Duration::from_millis(5),
        ..Default::default()
    };
    let integration = tokio::spawn(worker::run_integration_worker(
        db.clone(),
        storage.clone(),
        cfg.clone(),
        Some(index.clone()),
        rx.clone(),
    ));
    let signer = Arc::new(CheckpointSigner::generate("import.test"));
    let publisher = tokio::spawn(worker::run_checkpoint_worker(
        db.clone(),
        storage.clone(),
        signer.clone(),
        vec![],
        vec![],
        cfg,
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(cp) = storage.read_checkpoint().await.unwrap() {
                let cp = siglog::checkpoint::CosignedCheckpoint::from_text(cp.as_str().unwrap())
                    .unwrap();
                if cp.checkpoint.size.value() == 701 {
                    assert_eq!(cp.checkpoint.root_hash, root(&data));
                    signer
                        .public_key()
                        .verify_strict(
                            cp.checkpoint.to_body().as_bytes(),
                            &cp.signatures[0].signature,
                        )
                        .unwrap();
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    shutdown.send(true).unwrap();
    integration.await.unwrap();
    publisher.await.unwrap();
    for i in [0, 255, 256, 699, 700] {
        let proof = generate_inclusion_proof(&storage, i, 701).await.unwrap();
        sigstore_merkle::verify_inclusion_proof(
            &sigstore_merkle::hash_leaf(&data[i as usize]),
            i,
            701,
            &proof,
            &root(&data),
        )
        .unwrap();
    }
    assert_eq!(index.lookup_string("after-import").indices[0].value(), 700);
    let bundle = storage
        .read_entry_bundle(TileIndex::new(2), PartialSize::new(189))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bundle.entries.last().unwrap().as_bytes(), &data[700]);
    assert!(
        bulk_import(&db, &storage, &input(&data), &config(true), entries(&data))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn interrupted_import_resumes_only_identical_inputs_and_objects() {
    let db = database().await;
    let storage = storage();
    let mut data = data(700);
    let original = input(&data);
    let interrupted = entries(&data[..512]).chain(std::iter::once(Err(Error::Internal(
        "simulated interruption".into(),
    ))));
    assert!(
        bulk_import(&db, &storage, &original, &config(false), interrupted)
            .await
            .is_err()
    );
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 0);
    assert!(storage.read_checkpoint().await.unwrap().is_none());
    assert!(
        bulk_import(&db, &storage, &original, &config(false), entries(&data))
            .await
            .is_err()
    );
    // Even an edit in a not-yet-uploaded suffix is rejected by the manifest.
    data[699] = b"changed".to_vec();
    assert!(
        bulk_import(&db, &storage, &input(&data), &config(true), entries(&data))
            .await
            .is_err()
    );
    data = self::data(700);
    let summary = bulk_import(&db, &storage, &original, &config(true), entries(&data))
        .await
        .unwrap();
    assert!(summary.objects_verified > 0 && summary.objects_written > 0);
    assert_eq!(summary.root_hash, root(&data));
}

#[tokio::test]
async fn corruption_and_mutation_fail_without_committing() {
    let db = database().await;
    let storage = storage();
    let mut data = data(300);
    let original = input(&data);
    let interrupted =
        entries(&data[..256]).chain(std::iter::once(Err(Error::Internal("stop".into()))));
    assert!(
        bulk_import(&db, &storage, &original, &config(false), interrupted)
            .await
            .is_err()
    );
    storage
        .write_entry_bundle(
            TileIndex::new(0),
            PartialSize::full(),
            &EntryBundle::with_entries(vec![EntryData::from("corrupt")]),
        )
        .await
        .unwrap();
    assert!(
        bulk_import(&db, &storage, &original, &config(true), entries(&data))
            .await
            .is_err()
    );
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 0);
    let db = database().await;
    let storage = self::storage();
    data[299] = b"changed since preflight".to_vec();
    assert!(
        bulk_import(&db, &storage, &original, &config(false), entries(&data))
            .await
            .is_err()
    );
    assert_eq!(db.get_log_state().await.unwrap().integrated_size.value(), 0);
}

#[tokio::test]
async fn rekor_and_published_storage_are_untouched() {
    let db = database().await;
    let storage = storage();
    let data = data(1);
    db.ensure_mode(Mode::Rekor).await.unwrap();
    assert!(
        bulk_import(&db, &storage, &input(&data), &config(false), entries(&data))
            .await
            .is_err()
    );
    assert!(storage
        .read_raw("import-manifest.json")
        .await
        .unwrap()
        .is_none());
    let db = database().await;
    storage
        .write_checkpoint(&"existing checkpoint".to_string().into())
        .await
        .unwrap();
    assert!(
        bulk_import(&db, &storage, &input(&data), &config(false), entries(&data))
            .await
            .is_err()
    );
    assert_eq!(
        storage
            .read_checkpoint()
            .await
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "existing checkpoint"
    );
}

#[tokio::test]
async fn resume_ignores_future_full_tiles_when_rebuilding_earlier_chunks() {
    let db = database().await;
    let storage = storage();
    let data = data(65537);
    let input = input(&data);
    let mut cfg = ImportConfig::default();
    let interrupted = entries(&data[..65536]).chain(std::iter::once(Err(Error::Internal(
        "stop before final entry".into(),
    ))));
    assert!(bulk_import(&db, &storage, &input, &cfg, interrupted)
        .await
        .is_err());
    let partial_path = api::paths::tile_path(1, 0, 16);
    let partial_before = storage.read_raw(&partial_path).await.unwrap().unwrap();
    cfg.resume = true;
    let summary = bulk_import(&db, &storage, &input, &cfg, entries(&data))
        .await
        .unwrap();
    assert_eq!(summary.root_hash, root(&data));
    assert_eq!(
        storage.read_raw(&partial_path).await.unwrap().unwrap(),
        partial_before
    );
}
