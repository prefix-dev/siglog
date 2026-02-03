//! Write Ahead Log (WAL) for verifiable index persistence.
//!
//! The WAL stores (index, keys) pairs in a simple text format:
//! ```text
//! <index> <hex_key1> <hex_key2> ...
//! ```
//!
//! Each line represents one log entry and the keys it maps to.
//! Empty lines (entries with no keys) are skipped.
//!
//! On startup, the WAL is validated and truncated to match the expected
//! tree size from the database. This prevents duplicate entries after a crash.

use crate::error::{Error, Result};
use crate::types::LogIndex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;

use super::IndexKey;

/// WAL writer for appending new entries.
pub struct WalWriter {
    writer: BufWriter<File>,
}

impl WalWriter {
    /// Open or create a WAL file for writing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL: {}", e)))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    /// Append an entry to the WAL.
    ///
    /// Format: `<index> <hex_key1> <hex_key2> ...\n`
    pub fn append(&mut self, idx: LogIndex, keys: &[IndexKey]) -> Result<()> {
        if keys.is_empty() {
            // We still write a line for entries with no keys as a sentinel
            // This allows us to track that we've processed this index
            writeln!(self.writer, "{}", idx.value())
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;
        } else {
            write!(self.writer, "{}", idx.value())
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

            for key in keys {
                write!(self.writer, " {}", hex::encode(key))
                    .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;
            }

            writeln!(self.writer)
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;
        }

        Ok(())
    }

    /// Flush the WAL to disk with fsync for durability.
    pub fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|e| Error::Internal(format!("failed to flush WAL: {}", e)))?;

        // fsync to ensure data is persisted to disk (not just OS buffer)
        self.writer
            .get_ref()
            .sync_data()
            .map_err(|e| Error::Internal(format!("failed to sync WAL to disk: {}", e)))?;

        Ok(())
    }
}

/// WAL reader for replaying entries.
pub struct WalReader {
    reader: BufReader<File>,
    line_buf: String,
}

impl WalReader {
    /// Open a WAL file for reading.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL for reading: {}", e)))?;

        Ok(Self {
            reader: BufReader::new(file),
            line_buf: String::new(),
        })
    }

    /// Read the next entry from the WAL.
    ///
    /// Returns `Ok(None)` when EOF is reached.
    pub fn next_entry(&mut self) -> Result<Option<(LogIndex, Vec<IndexKey>)>> {
        self.line_buf.clear();

        let bytes_read = self
            .reader
            .read_line(&mut self.line_buf)
            .map_err(|e| Error::Internal(format!("failed to read from WAL: {}", e)))?;

        if bytes_read == 0 {
            return Ok(None);
        }

        parse_wal_line(&self.line_buf).map(Some)
    }
}

/// Validate and truncate the WAL file to match the expected tree size.
///
/// This function reads the WAL backwards to find the last complete entry,
/// and truncates any entries with index >= expected_tree_size.
/// This is critical for crash recovery: if the WAL was flushed but the database
/// wasn't updated before a crash, we need to truncate the WAL to match the
/// database state to avoid duplicate entries.
///
/// Returns the actual tree size found in the WAL (may be less than expected if WAL is behind).
pub fn validate_and_truncate_wal(path: impl AsRef<Path>, expected_tree_size: u64) -> Result<u64> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(0);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::Internal(format!("failed to open WAL for validation: {}", e)))?;

    let file_size = file
        .metadata()
        .map_err(|e| Error::Internal(format!("failed to get WAL metadata: {}", e)))?
        .len();

    if file_size == 0 {
        return Ok(0);
    }

    // Read the entire file to find all entries and their positions
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| Error::Internal(format!("failed to read WAL: {}", e)))?;

    // Find all line boundaries and parse entries
    let mut last_valid_pos: u64 = 0;
    let mut max_valid_idx: Option<u64> = None;
    let mut current_pos: u64 = 0;

    for line in content.lines() {
        let line_len = line.len() as u64 + 1; // +1 for newline

        if line.trim().is_empty() {
            current_pos += line_len;
            continue;
        }

        match parse_wal_line(line) {
            Ok((idx, _)) => {
                let idx_val = idx.value();
                if expected_tree_size == 0 || idx_val < expected_tree_size {
                    // This entry is within bounds
                    last_valid_pos = current_pos + line_len;
                    max_valid_idx = Some(match max_valid_idx {
                        Some(prev) => prev.max(idx_val),
                        None => idx_val,
                    });
                } else {
                    // Entry is beyond expected tree size - stop here
                    tracing::warn!(
                        "WAL entry {} >= expected tree size {}, truncating",
                        idx_val,
                        expected_tree_size
                    );
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to parse WAL line, truncating at position {}: {}",
                    current_pos,
                    e
                );
                break;
            }
        }

        current_pos += line_len;
    }

    // Truncate file if needed
    if last_valid_pos < file_size {
        tracing::info!(
            "Truncating WAL from {} to {} bytes (removing {} bytes)",
            file_size,
            last_valid_pos,
            file_size - last_valid_pos
        );
        file.set_len(last_valid_pos)
            .map_err(|e| Error::Internal(format!("failed to truncate WAL: {}", e)))?;
        file.sync_all()
            .map_err(|e| Error::Internal(format!("failed to sync truncated WAL: {}", e)))?;
    }

    // Return the tree size based on max index found + 1 (since indices are 0-based)
    Ok(max_valid_idx.map(|idx| idx + 1).unwrap_or(0))
}

/// Parse a single WAL line.
fn parse_wal_line(line: &str) -> Result<(LogIndex, Vec<IndexKey>)> {
    let line = line.trim();
    if line.is_empty() {
        return Err(Error::Internal("empty WAL line".into()));
    }

    let mut parts = line.split_whitespace();

    // First part is the index
    let idx_str = parts
        .next()
        .ok_or_else(|| Error::Internal("missing index in WAL line".into()))?;

    let idx: u64 = idx_str
        .parse()
        .map_err(|e| Error::Internal(format!("invalid index in WAL: {}", e)))?;

    // Remaining parts are hex-encoded keys
    let mut keys = Vec::new();
    for hex_key in parts {
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| Error::Internal(format!("invalid hex key in WAL: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(Error::Internal(format!(
                "invalid key length in WAL: expected 32, got {}",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        keys.push(key);
    }

    Ok((LogIndex::new(idx), keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_wal_write_read() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write some entries
        {
            let mut writer = WalWriter::open(path).unwrap();

            let key1 = [1u8; 32];
            let key2 = [2u8; 32];

            writer.append(LogIndex::new(0), &[key1]).unwrap();
            writer.append(LogIndex::new(1), &[key1, key2]).unwrap();
            writer.append(LogIndex::new(2), &[]).unwrap(); // No keys
            writer.flush().unwrap();
        }

        // Read them back
        {
            let mut reader = WalReader::open(path).unwrap();

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 0);
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], [1u8; 32]);

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 1);
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0], [1u8; 32]);
            assert_eq!(keys[1], [2u8; 32]);

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 2);
            assert_eq!(keys.len(), 0);

            assert!(reader.next_entry().unwrap().is_none());
        }
    }

    #[test]
    fn test_parse_wal_line() {
        // Line with keys
        let line = "42 0101010101010101010101010101010101010101010101010101010101010101 0202020202020202020202020202020202020202020202020202020202020202";
        let (idx, keys) = parse_wal_line(line).unwrap();
        assert_eq!(idx.value(), 42);
        assert_eq!(keys.len(), 2);

        // Line without keys
        let line = "123";
        let (idx, keys) = parse_wal_line(line).unwrap();
        assert_eq!(idx.value(), 123);
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_validate_and_truncate_wal_no_truncation_needed() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write entries 0-4
        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..5 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // Validate with expected size 5 - no truncation needed
        let actual_size = validate_and_truncate_wal(path, 5).unwrap();
        assert_eq!(actual_size, 5);

        // Verify all entries still present
        let mut reader = WalReader::open(path).unwrap();
        for i in 0..5 {
            let (idx, _) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), i);
        }
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_validate_and_truncate_wal_truncates_excess() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write entries 0-9
        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..10 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // Validate with expected size 5 - should truncate entries 5-9
        let actual_size = validate_and_truncate_wal(path, 5).unwrap();
        assert_eq!(actual_size, 5);

        // Verify only entries 0-4 remain
        let mut reader = WalReader::open(path).unwrap();
        for i in 0..5 {
            let (idx, _) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), i);
        }
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_validate_and_truncate_wal_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Create empty file
        File::create(path).unwrap();

        let actual_size = validate_and_truncate_wal(path, 5).unwrap();
        assert_eq!(actual_size, 0);
    }

    #[test]
    fn test_validate_and_truncate_wal_nonexistent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("nonexistent.wal");

        let actual_size = validate_and_truncate_wal(&path, 5).unwrap();
        assert_eq!(actual_size, 0);
    }

    #[test]
    fn test_validate_and_truncate_wal_wal_behind_expected() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write only entries 0-2 (WAL is behind expected)
        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..3 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // Validate with expected size 10 - WAL is behind, no truncation
        let actual_size = validate_and_truncate_wal(path, 10).unwrap();
        assert_eq!(actual_size, 3);
    }
}
