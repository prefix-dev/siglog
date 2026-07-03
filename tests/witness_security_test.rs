//! Tests for witness security improvements.

use siglog::witness::AddCheckpointRequest;

/// Maximum body size limit (matches witness.rs constant).
const MAX_BODY_SIZE: usize = 1024 * 1024;

#[test]
fn test_max_body_size_constant() {
    // Verify the constant is set to 1MB
    assert_eq!(MAX_BODY_SIZE, 1024 * 1024, "MAX_BODY_SIZE should be 1MB");
}

#[test]
fn test_proof_hash_count_limit() {
    // Test that parsing fails when proof has too many hashes (> 64)
    let mut body = "old 0\n".to_string();

    // Add 65 proof hashes (exceeds the limit of 64)
    for _ in 0..65 {
        // Valid base64 encoded 32-byte hash
        body.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    }
    body.push('\n'); // Empty line
    body.push_str("test-log\n1\nABCD\n");

    let result = AddCheckpointRequest::from_ascii(&body);
    assert!(result.is_err(), "Should reject > 64 proof hashes");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too many proof hashes") || err_msg.contains("limit is 64"),
        "Error should mention proof hash limit: {}",
        err_msg
    );
}

#[test]
fn test_proof_hash_count_at_limit() {
    // Test that exactly 64 proof hashes is accepted
    let mut body = "old 0\n".to_string();

    // Add exactly 64 proof hashes (at the limit)
    for _ in 0..64 {
        body.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    }
    body.push('\n');
    body.push_str("test-log\n1\nABCD\n");

    let result = AddCheckpointRequest::from_ascii(&body);
    assert!(result.is_ok(), "Should accept exactly 64 proof hashes");

    let request = result.unwrap();
    assert_eq!(request.proof.len(), 64);
}

#[test]
fn test_proof_hash_count_below_limit() {
    // Test that < 64 proof hashes works fine
    let mut body = "old 0\n".to_string();

    // Add 10 proof hashes
    for _ in 0..10 {
        body.push_str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    }
    body.push('\n');
    body.push_str("test-log\n1\nABCD\n");

    let result = AddCheckpointRequest::from_ascii(&body);
    assert!(result.is_ok(), "Should accept < 64 proof hashes");

    let request = result.unwrap();
    assert_eq!(request.proof.len(), 10);
}

#[cfg(test)]
mod state_tests {
    use sea_orm::{Database, DatabaseConnection};
    use siglog::witness::{UpdateOutcome, WitnessStateStore};
    use sigstore_types::Sha256Hash;
    use std::sync::Arc;

    async fn setup_test_db() -> DatabaseConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();

        // Run migrations
        use sea_orm_migration::MigratorTrait;
        siglog::migration::Migrator::up(&conn, None).await.unwrap();

        conn
    }

    fn empty_root() -> Sha256Hash {
        Sha256Hash::from_bytes([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ])
    }

    #[tokio::test]
    async fn test_size_rollback_prevention() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let hash1 = Sha256Hash::from_bytes([1u8; 32]);
        let hash2 = Sha256Hash::from_bytes([2u8; 32]);

        // Initialize with size 100
        let init = store.get_or_init(origin).await.unwrap();
        let outcome = store
            .update(origin, init.size, &init.root_hash, 100, hash1, "checkpoint1")
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated);

        // Try to rollback to size 50 (should fail)
        let result = store
            .update(origin, 100, &hash1, 50, hash2, "checkpoint2")
            .await;
        assert!(result.is_err(), "Should prevent size rollback");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("rollback") || err_msg.contains("current size 100 > new size 50"),
            "Error should mention rollback prevention: {}",
            err_msg
        );

        // Verify the state hasn't changed
        let state = store.get(origin).await.unwrap().unwrap();
        assert_eq!(state.size, 100, "Size should remain at 100");
        assert_eq!(state.root_hash, hash1, "Hash should remain unchanged");
    }

    #[tokio::test]
    async fn test_size_increase_allowed() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let hash1 = Sha256Hash::from_bytes([1u8; 32]);
        let hash2 = Sha256Hash::from_bytes([2u8; 32]);

        // Initialize with size 100
        let init = store.get_or_init(origin).await.unwrap();
        store
            .update(origin, init.size, &init.root_hash, 100, hash1, "checkpoint1")
            .await
            .unwrap();

        // Increase to size 200 (should succeed)
        let outcome = store
            .update(origin, 100, &hash1, 200, hash2, "checkpoint2")
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated, "Should allow size increase");

        // Verify the state has changed
        let state = store.get(origin).await.unwrap().unwrap();
        assert_eq!(state.size, 200, "Size should be updated to 200");
        assert_eq!(state.root_hash, hash2, "Hash should be updated");
    }

    #[tokio::test]
    async fn test_same_size_allowed() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let hash1 = Sha256Hash::from_bytes([1u8; 32]);

        // Initialize with size 100
        let init = store.get_or_init(origin).await.unwrap();
        store
            .update(origin, init.size, &init.root_hash, 100, hash1, "checkpoint1")
            .await
            .unwrap();

        // Update with same size and same root (idempotent republish)
        let outcome = store
            .update(origin, 100, &hash1, 100, hash1, "checkpoint1")
            .await
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Updated, "Should allow same size update");
    }

    #[tokio::test]
    async fn test_cas_conflict_on_stale_expected_state() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let hash1 = Sha256Hash::from_bytes([1u8; 32]);
        let hash2 = Sha256Hash::from_bytes([2u8; 32]);
        let hash3 = Sha256Hash::from_bytes([3u8; 32]);

        // Two "concurrent" requests both read the initial state.
        let init = store.get_or_init(origin).await.unwrap();

        // Request A wins the race.
        let outcome_a = store
            .update(origin, init.size, &init.root_hash, 10, hash1, "cp-a")
            .await
            .unwrap();
        assert_eq!(outcome_a, UpdateOutcome::Updated);

        // Request B tries to persist a *different* root at the same size,
        // using the stale expected state. Must be rejected, otherwise the
        // witness cosigns two conflicting roots (split view).
        let outcome_b = store
            .update(origin, init.size, &init.root_hash, 10, hash2, "cp-b")
            .await
            .unwrap();
        assert_eq!(
            outcome_b,
            UpdateOutcome::Conflict { current_size: 10 },
            "Stale CAS must conflict, not overwrite"
        );

        // Same-size different-root with a *matching* expected size but stale
        // root must also conflict.
        let outcome_c = store
            .update(origin, 10, &hash2, 10, hash3, "cp-c")
            .await
            .unwrap();
        assert_eq!(outcome_c, UpdateOutcome::Conflict { current_size: 10 });

        let state = store.get(origin).await.unwrap().unwrap();
        assert_eq!(state.root_hash, hash1, "Winner's root must be preserved");
    }

    #[tokio::test]
    async fn test_oversized_tree_size_rejected() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let init = store.get_or_init(origin).await.unwrap();

        // Sizes above i64::MAX would wrap negative in the database column and
        // defeat rollback protection.
        let result = store
            .update(
                origin,
                init.size,
                &init.root_hash,
                u64::MAX,
                empty_root(),
                "cp",
            )
            .await;
        assert!(result.is_err(), "Sizes above i64::MAX must be rejected");
    }
}
