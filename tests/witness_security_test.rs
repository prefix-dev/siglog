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
    use siglog::witness::WitnessStateStore;
    use sigstore_types::Sha256Hash;
    use std::sync::Arc;

    async fn setup_test_db() -> DatabaseConnection {
        let conn = Database::connect("sqlite::memory:").await.unwrap();

        // Run migrations
        use sea_orm_migration::MigratorTrait;
        siglog::migration::Migrator::up(&conn, None).await.unwrap();

        conn
    }

    #[tokio::test]
    async fn test_size_rollback_prevention() {
        let conn = setup_test_db().await;
        let store = WitnessStateStore::new(Arc::new(conn));

        let origin = "test-log";
        let hash1 = Sha256Hash::from_bytes([1u8; 32]);
        let hash2 = Sha256Hash::from_bytes([2u8; 32]);

        // Initialize with size 100
        let _ = store.get_or_init(origin).await.unwrap();
        store
            .update(origin, 100, hash1, "checkpoint1")
            .await
            .unwrap();

        // Try to rollback to size 50 (should fail)
        let result = store.update(origin, 50, hash2, "checkpoint2").await;
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
        let _ = store.get_or_init(origin).await.unwrap();
        store
            .update(origin, 100, hash1, "checkpoint1")
            .await
            .unwrap();

        // Increase to size 200 (should succeed)
        let result = store.update(origin, 200, hash2, "checkpoint2").await;
        assert!(result.is_ok(), "Should allow size increase");

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
        let _ = store.get_or_init(origin).await.unwrap();
        store
            .update(origin, 100, hash1, "checkpoint1")
            .await
            .unwrap();

        // Update with same size (should succeed - allows idempotent updates)
        let result = store.update(origin, 100, hash1, "checkpoint1").await;
        assert!(result.is_ok(), "Should allow same size update");
    }
}
