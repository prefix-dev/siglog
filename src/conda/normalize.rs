//! Repodata entry normalization for consistent hashing.
//!
//! This module implements the normalization rules from the CEP:
//! 1. Keys sorted lexicographically
//! 2. Compact JSON (no whitespace)
//! 3. Empty arrays/objects omitted
//! 4. Null values omitted

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A normalized repodata entry for the transparency log.
///
/// Fields are ordered alphabetically for consistent serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepodataEntry {
    /// SHA256 hash of the Sigstore attestation bundle (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_sha256: Option<String>,

    /// Build string
    pub build: String,

    /// Build number
    pub build_number: u64,

    /// Constraint specifications (if non-empty)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constrains: Option<Vec<String>>,

    /// Dependency specifications (if non-empty)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends: Option<Vec<String>>,

    /// Artifact filename
    pub filename: String,

    /// License identifier (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    /// License family (if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_family: Option<String>,

    /// MD5 hash of artifact (for backwards compatibility)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,

    /// Package name
    pub name: String,

    /// SHA256 hash of artifact
    pub sha256: String,

    /// Size in bytes
    pub size: u64,

    /// Platform subdirectory (linux-64, osx-arm64, noarch, etc.)
    pub subdir: String,

    /// Publication timestamp (milliseconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,

    /// Package version
    pub version: String,
}

impl RepodataEntry {
    /// Create a new entry from raw repodata JSON and additional context.
    pub fn from_repodata(
        filename: &str,
        subdir: &str,
        entry: &Value,
        attestation_sha256: Option<String>,
    ) -> Option<Self> {
        let obj = entry.as_object()?;

        // Extract required fields
        let name = obj.get("name")?.as_str()?.to_string();
        let version = obj.get("version")?.as_str()?.to_string();
        let build = obj.get("build")?.as_str()?.to_string();
        let build_number = obj.get("build_number")?.as_u64()?;
        let sha256 = obj.get("sha256")?.as_str()?.to_string();
        let size = obj.get("size")?.as_u64()?;

        // Extract optional fields
        let md5 = obj.get("md5").and_then(|v| v.as_str()).map(String::from);
        let timestamp = obj.get("timestamp").and_then(|v| v.as_u64());
        let license = obj
            .get("license")
            .and_then(|v| v.as_str())
            .map(String::from);
        let license_family = obj
            .get("license_family")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Extract depends (skip if empty)
        let depends = obj.get("depends").and_then(|v| {
            let arr: Vec<String> = v
                .as_array()?
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        });

        // Extract constrains (skip if empty)
        let constrains = obj.get("constrains").and_then(|v| {
            let arr: Vec<String> = v
                .as_array()?
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        });

        Some(Self {
            attestation_sha256,
            build,
            build_number,
            constrains,
            depends,
            filename: filename.to_string(),
            license,
            license_family,
            md5,
            name,
            sha256,
            size,
            subdir: subdir.to_string(),
            timestamp,
            version,
        })
    }

    /// Serialize to normalized JSON bytes.
    ///
    /// Uses a BTreeMap to ensure keys are sorted alphabetically.
    pub fn to_normalized_json(&self) -> Vec<u8> {
        // Serialize to Value first, then to BTreeMap for sorted keys
        let value = serde_json::to_value(self).expect("serialization should not fail");
        let map: BTreeMap<String, Value> =
            serde_json::from_value(value).expect("should be an object");

        // Serialize compactly with sorted keys
        serde_json::to_vec(&map).expect("serialization should not fail")
    }
}

/// Normalize a repodata entry from raw JSON.
///
/// Returns the normalized JSON bytes suitable for hashing.
pub fn normalize_repodata_entry(
    filename: &str,
    subdir: &str,
    entry: &Value,
    attestation_sha256: Option<String>,
) -> Option<Vec<u8>> {
    let entry = RepodataEntry::from_repodata(filename, subdir, entry, attestation_sha256)?;
    Some(entry.to_normalized_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_normalization() {
        let entry = json!({
            "name": "numpy",
            "version": "1.26.0",
            "build": "py311h1234567_0",
            "build_number": 0,
            "sha256": "abc123def456",
            "md5": "fedcba987654",
            "size": 7654321,
            "depends": ["python >=3.11", "libblas >=3.9"],
            "constrains": [],
            "timestamp": 1699900000000_u64,
            "license": "BSD-3-Clause"
        });

        let normalized = normalize_repodata_entry(
            "numpy-1.26.0-py311h1234567_0.conda",
            "linux-64",
            &entry,
            None,
        )
        .unwrap();

        let json_str = String::from_utf8(normalized).unwrap();
        println!("Normalized: {}", json_str);

        // Verify it's valid JSON
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());

        // Verify required fields
        assert_eq!(parsed["name"], "numpy");
        assert_eq!(parsed["subdir"], "linux-64");
        assert_eq!(parsed["filename"], "numpy-1.26.0-py311h1234567_0.conda");

        // Verify empty constrains is omitted
        assert!(parsed.get("constrains").is_none());
    }

    #[test]
    fn test_keys_sorted() {
        let entry = json!({
            "name": "zlib",
            "version": "1.0.0",
            "build": "h0",
            "build_number": 0,
            "sha256": "aaa",
            "size": 100
        });

        let normalized =
            normalize_repodata_entry("zlib-1.0.0-h0.conda", "noarch", &entry, None).unwrap();
        let json_str = String::from_utf8(normalized).unwrap();

        // Keys should be in alphabetical order
        // build < build_number < filename < name < sha256 < size < subdir < version
        let keys: Vec<&str> = json_str
            .trim_matches(|c| c == '{' || c == '}')
            .split(',')
            .filter_map(|pair| pair.split(':').next())
            .map(|k| k.trim_matches('"'))
            .collect();

        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys);
    }
}
