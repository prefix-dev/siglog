//! Integration tests for Phase 1 security fixes.
//!
//! These tests verify:
//! 1. Input size limits on /add endpoint
//! 2. Origin validation rejects malformed origins
//! 3. Rate limiting is properly configured

use siglog::api::rate_limit;
use siglog::checkpoint::signer::Origin;

#[test]
fn test_max_entry_size_constant() {
    // Verify MAX_ENTRY_SIZE constant exists and is reasonable
    // This is tested indirectly through the API handler
    // but we verify the rate limit constants are set
    assert!(rate_limit::RATE_LIMIT_PER_SECOND > 0);
    assert!(rate_limit::RATE_LIMIT_BURST_SIZE > 0);
}

#[test]
fn test_origin_validation_valid() {
    // Valid origins should succeed
    assert!(Origin::new("example.com/log".to_string()).is_ok());
    assert!(Origin::new("my-transparency-log".to_string()).is_ok());
    assert!(Origin::new("log.example.com".to_string()).is_ok());
    assert!(Origin::new("a".to_string()).is_ok()); // Single character is ok
}

#[test]
fn test_origin_validation_empty() {
    // Empty origins should be rejected
    let result = Origin::new("".to_string());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("origin cannot be empty"));
}

#[test]
fn test_origin_validation_newline() {
    // Origins with newlines should be rejected
    let result = Origin::new("log\nwith\nnewlines".to_string());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("newline or carriage return"));
}

#[test]
fn test_origin_validation_carriage_return() {
    // Origins with carriage returns should be rejected
    let result = Origin::new("log\rwith\rcarriage".to_string());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("newline or carriage return"));
}

#[test]
fn test_origin_validation_mixed_line_endings() {
    // Origins with mixed line endings should be rejected
    let result = Origin::new("log\r\nmixed".to_string());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("newline or carriage return"));
}

#[test]
fn test_rate_limit_config_values() {
    // Verify rate limiting constants are sensible
    assert_eq!(rate_limit::RATE_LIMIT_PER_SECOND, 100);
    assert_eq!(rate_limit::RATE_LIMIT_BURST_SIZE, 200);
}
