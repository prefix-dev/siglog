use sea_orm::{ConnectionTrait, Statement};
use siglog::{
    api::Mode,
    error::Error,
    storage::Database,
    types::{Entry, TreeSize},
};

async fn check_duplicates(url: &str) {
    let db = Database::connect(url).await.unwrap();
    db.run_migrations().await.unwrap();
    assert_eq!(
        db.get_log_state().await.unwrap().next_index.value(),
        0,
        "use an empty test database"
    );
    db.ensure_mode(Mode::Rekor).await.unwrap();
    let other = Database::connect(url).await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..16 {
        let db = if i % 2 == 0 {
            db.clone()
        } else {
            other.clone()
        };
        tasks.push(tokio::spawn(async move {
            db.sequence_entries(vec![Entry::new("a"), Entry::new("a"), Entry::new("b")])
                .await
                .unwrap()
        }));
    }
    let mut inserted = 0;
    let mut duplicates = 0;
    for task in tasks {
        for (offset, result) in task.await.unwrap().into_iter().enumerate() {
            let expected = if offset == 2 { 1 } else { 0 };
            match result {
                Ok(entry) => {
                    assert_eq!(entry.index().value(), expected);
                    inserted += 1;
                }
                Err(Error::Duplicate(index)) => {
                    assert_eq!(index, expected);
                    duplicates += 1;
                }
                Err(error) => panic!("{error}"),
            }
        }
    }
    assert_eq!((inserted, duplicates), (2, 46));
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 2);
    let root = sigstore_merkle::hash_children(
        &sigstore_merkle::hash_leaf(b"a"),
        &sigstore_merkle::hash_leaf(b"b"),
    );
    db.mark_integrated_if_current(TreeSize::new(0), TreeSize::new(2), root)
        .await
        .unwrap();
    assert!(db
        .get_pending_entries(0.into(), 10)
        .await
        .unwrap()
        .is_empty());
    drop(other);
    drop(db);

    // Integration cleanup and a connection restart must not forget old hashes.
    let db = Database::connect(url).await.unwrap();
    db.ensure_mode(Mode::Rekor).await.unwrap();
    let result = db
        .sequence_entries(vec![Entry::new("b"), Entry::new("c")])
        .await
        .unwrap();
    assert!(matches!(result[0], Err(Error::Duplicate(1))));
    assert_eq!(result[1].as_ref().unwrap().index().value(), 2);
    assert_eq!(db.get_log_state().await.unwrap().next_index.value(), 3);

    // Rollback must undo the hash reservation along with the failed append.
    db.connection()
        .execute_unprepared("UPDATE log_state SET next_index = 9223372036854775807 WHERE id = 1")
        .await
        .unwrap();
    assert!(matches!(
        db.sequence_entries(vec![Entry::new("failed")]).await,
        Err(Error::IndexFull(_))
    ));
    let row = db
        .connection()
        .query_one_raw(Statement::from_string(
            db.connection().get_database_backend(),
            "SELECT COUNT(*) AS count FROM rekor_entries",
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i64>("", "count").unwrap(), 3);
    db.connection()
        .execute_unprepared("UPDATE log_state SET next_index = 3 WHERE id = 1")
        .await
        .unwrap();
    let result = db
        .sequence_entries(vec![Entry::new("failed")])
        .await
        .unwrap();
    assert_eq!(result[0].as_ref().unwrap().index().value(), 3);
}

#[tokio::test]
async fn sqlite_duplicates_are_atomic_and_persistent() {
    let dir = tempfile::tempdir().unwrap();
    check_duplicates(&format!(
        "sqlite:{}?mode=rwc",
        dir.path().join("log.db").display()
    ))
    .await;
}

#[tokio::test]
async fn postgres_duplicates_are_atomic_and_persistent() {
    // CI supplies a dedicated, empty PostgreSQL database.
    if let Ok(url) = std::env::var("SIGLOG_TEST_POSTGRES_URL") {
        check_duplicates(&url).await;
    }
}

#[tokio::test]
async fn tessera_still_appends_identical_entries() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    db.run_migrations().await.unwrap();
    db.ensure_mode(Mode::Tessera).await.unwrap();
    for expected in 0..3 {
        let result = db.sequence_entries(vec![Entry::new("same")]).await.unwrap();
        assert_eq!(result[0].as_ref().unwrap().index().value(), expected);
    }
}
