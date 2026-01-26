//! MapFn implementation for conda repodata entries.
//!
//! Extracts the filename from each entry for indexing in the verifiable index.

use siglog::vindex::{IndexKey, MapFn};
use sha2::{Digest, Sha256};

/// A MapFn that extracts the filename from conda repodata entries.
///
/// Expects entries to be JSON objects with a "filename" field.
/// The filename is hashed to produce the index key.
pub struct FilenameMapFn;

impl MapFn for FilenameMapFn {
    fn map(&self, data: &[u8]) -> Vec<IndexKey> {
        // Try to parse as JSON
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return Vec::new();
        };

        // Get the filename field
        let Some(filename) = value.get("filename").and_then(|v| v.as_str()) else {
            return Vec::new();
        };

        // Hash the filename
        let mut hasher = Sha256::new();
        hasher.update(filename.as_bytes());
        vec![hasher.finalize().into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filename_extraction() {
        let mapfn = FilenameMapFn;

        let entry = r#"{"filename": "numpy-1.26.0-py311h123_0.conda", "name": "numpy"}"#;
        let keys = mapfn.map(entry.as_bytes());

        assert_eq!(keys.len(), 1);

        // Verify the key is SHA256 of filename
        let mut expected = Sha256::new();
        expected.update(b"numpy-1.26.0-py311h123_0.conda");
        let expected_hash: [u8; 32] = expected.finalize().into();

        assert_eq!(keys[0], expected_hash);
    }

    #[test]
    fn test_missing_filename() {
        let mapfn = FilenameMapFn;

        let entry = r#"{"name": "numpy"}"#;
        let keys = mapfn.map(entry.as_bytes());

        assert!(keys.is_empty());
    }

    #[test]
    fn test_invalid_json() {
        let mapfn = FilenameMapFn;

        let keys = mapfn.map(b"not json");
        assert!(keys.is_empty());
    }
}
