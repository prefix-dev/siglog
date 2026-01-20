//! Write Ahead Log (WAL) for verifiable index persistence.
//!
//! The WAL stores (index, keys) pairs in a simple text format:
//! ```text
//! <index> <hex_key1> <hex_key2> ...
//! ```
//!
//! Each line represents one log entry and the keys it maps to.
//! Empty lines (entries with no keys) are skipped.

use crate::error::{Error, Result};
use crate::types::LogIndex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
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

    /// Flush the WAL to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|e| Error::Internal(format!("failed to flush WAL: {}", e)))?;
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
    pub fn next(&mut self) -> Result<Option<(LogIndex, Vec<IndexKey>)>> {
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

            let (idx, keys) = reader.next().unwrap().unwrap();
            assert_eq!(idx.value(), 0);
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], [1u8; 32]);

            let (idx, keys) = reader.next().unwrap().unwrap();
            assert_eq!(idx.value(), 1);
            assert_eq!(keys.len(), 2);
            assert_eq!(keys[0], [1u8; 32]);
            assert_eq!(keys[1], [2u8; 32]);

            let (idx, keys) = reader.next().unwrap().unwrap();
            assert_eq!(idx.value(), 2);
            assert_eq!(keys.len(), 0);

            assert!(reader.next().unwrap().is_none());
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
}
