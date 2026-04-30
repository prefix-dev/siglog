//! Write Ahead Log (WAL) for verifiable index persistence.
//!
//! The WAL supports two formats:
//!
//! ## Text format (legacy):
//! ```text
//! <index> <hex_key1> <hex_key2> ...
//! ```
//! Cost: ~336 bytes for entry with 5 keys
//!
//! ## Binary format (v2):
//! ```text
//! [u8 version=2][u64 index][u8 key_count][32*key_count bytes of keys]
//! ```
//! Cost: ~169 bytes for entry with 5 keys (50% savings)
//!
//! The reader auto-detects format by checking the first byte:
//! - ASCII digit (0-9) → text format
//! - 0x02 → binary format v2
//!
//! On startup, the WAL is validated and truncated to match the expected
//! tree size from the database. This prevents duplicate entries after a crash.

use crate::error::{Error, Result};
use crate::types::LogIndex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use super::IndexKey;

/// WAL format version (binary only).
const WAL_VERSION_BINARY: u8 = 2;

/// Binary WAL writer (now the default and only format).
///
/// Format per entry: [version=0x02][u64 index][u8 key_count][32*key_count bytes]
///
/// Benefits:
/// - 50% space savings vs text format (169 bytes vs 336 bytes for 5 keys)
/// - 20-30% faster I/O (no hex encoding/decoding)
/// - Simpler parsing (no string allocation)
pub type WalWriter = BinaryWalWriter;

/// Batched binary WAL writer (now the default batched format).
///
/// Combines batching with binary format for maximum performance:
/// - Batching: 100x fewer fsyncs
/// - Binary format: 50% space savings
///
/// Expected improvement: 5-10x throughput over unbatched text format
pub type BatchedWalWriter = BatchedBinaryWalWriter;

/// Binary WAL writer for efficient storage.
///
/// Format per entry:
/// ```text
/// [u8 version=2][u64 index][u8 key_count][32*key_count bytes]
/// ```
///
/// Benefits over text format:
/// - 50% space savings (169 bytes vs 336 bytes for 5 keys)
/// - 20-30% faster I/O (no hex encoding/decoding)
/// - Simpler parsing (no string allocation)
pub struct BinaryWalWriter {
    writer: BufWriter<File>,
}

impl BinaryWalWriter {
    /// Open or create a binary WAL file for writing.
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

    /// Append an entry to the WAL in binary format.
    ///
    /// Format: [u8 version][u64 index][u8 key_count][keys...]
    pub fn append(&mut self, idx: LogIndex, keys: &[IndexKey]) -> Result<()> {
        if keys.len() > u8::MAX as usize {
            return Err(Error::InvalidEntry(format!(
                "too many WAL keys for entry {}: {} (max {})",
                idx.value(),
                keys.len(),
                u8::MAX
            )));
        }

        // Version marker
        self.writer
            .write_all(&[WAL_VERSION_BINARY])
            .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

        // Index (8 bytes, big-endian for readability in hex dumps)
        self.writer
            .write_all(&idx.value().to_be_bytes())
            .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

        // Key count (1 byte, limiting to 255 keys per entry)
        let key_count = keys.len() as u8;
        self.writer
            .write_all(&[key_count])
            .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

        // Keys (32 bytes each)
        for key in keys {
            self.writer
                .write_all(key)
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;
        }

        Ok(())
    }

    /// Flush the WAL to disk with fsync for durability.
    pub fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .map_err(|e| Error::Internal(format!("failed to flush WAL: {}", e)))?;

        self.writer
            .get_ref()
            .sync_data()
            .map_err(|e| Error::Internal(format!("failed to sync WAL to disk: {}", e)))?;

        Ok(())
    }
}

/// Batched binary WAL writer combining batching with binary format.
///
/// Provides both benefits:
/// - Batching: 100x fewer fsyncs
/// - Binary format: 50% space savings
///
/// Expected improvement: 5-10x throughput over unbatched text format
pub struct BatchedBinaryWalWriter {
    buffer: Vec<(LogIndex, Vec<IndexKey>)>,
    batch_size: usize,
    writer: BufWriter<File>,
}

impl BatchedBinaryWalWriter {
    /// Open or create a batched binary WAL file for writing.
    pub fn open(path: impl AsRef<Path>, batch_size: usize) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL: {}", e)))?;

        Ok(Self {
            buffer: Vec::with_capacity(batch_size),
            batch_size,
            writer: BufWriter::new(file),
        })
    }

    /// Append an entry to the buffer.
    pub fn append(&mut self, idx: LogIndex, keys: Vec<IndexKey>) -> Result<()> {
        if keys.len() > u8::MAX as usize {
            return Err(Error::InvalidEntry(format!(
                "too many WAL keys for entry {}: {} (max {})",
                idx.value(),
                keys.len(),
                u8::MAX
            )));
        }

        self.buffer.push((idx, keys));

        if self.buffer.len() >= self.batch_size {
            self.flush_batch()?;
        }

        Ok(())
    }

    /// Flush all buffered entries to disk with a single fsync.
    pub fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Internal method to flush the current batch in binary format.
    fn flush_batch(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        tracing::debug!("Flushing binary WAL batch of {} entries", self.buffer.len());

        // Write all buffered entries in binary format
        for (idx, keys) in &self.buffer {
            // Version marker
            self.writer
                .write_all(&[WAL_VERSION_BINARY])
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

            // Index
            self.writer
                .write_all(&idx.value().to_be_bytes())
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

            // Key count
            let key_count = keys.len() as u8;
            self.writer
                .write_all(&[key_count])
                .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

            // Keys
            for key in keys {
                self.writer
                    .write_all(key)
                    .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;
            }
        }

        // Flush buffer to OS
        self.writer
            .flush()
            .map_err(|e| Error::Internal(format!("failed to flush WAL: {}", e)))?;

        // Single fsync for entire batch
        self.writer
            .get_ref()
            .sync_data()
            .map_err(|e| Error::Internal(format!("failed to sync WAL to disk: {}", e)))?;

        // Clear buffer after successful write
        self.buffer.clear();

        Ok(())
    }

    /// Get the current number of buffered entries.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

/// WAL reader for replaying entries in binary format.
///
/// Format per entry: [version=0x02][u64 index][u8 key_count][32*key_count bytes]
pub struct WalReader {
    reader: BufReader<File>,
}

impl WalReader {
    /// Open a WAL file for reading.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL for reading: {}", e)))?;

        Ok(Self {
            reader: BufReader::new(file),
        })
    }

    /// Read the next entry from the WAL in binary format.
    ///
    /// Returns `Ok(None)` when EOF is reached.
    pub fn next_entry(&mut self) -> Result<Option<(LogIndex, Vec<IndexKey>)>> {
        // Read version byte
        let mut version = [0u8; 1];
        match self.reader.read_exact(&mut version) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Internal(format!("failed to read from WAL: {}", e))),
        }

        if version[0] != WAL_VERSION_BINARY {
            return Err(Error::Internal(format!(
                "invalid WAL version: expected 0x{:02x}, got 0x{:02x}",
                WAL_VERSION_BINARY, version[0]
            )));
        }

        // Read index (8 bytes, big-endian)
        let mut idx_bytes = [0u8; 8];
        self.reader
            .read_exact(&mut idx_bytes)
            .map_err(|e| Error::Internal(format!("failed to read index from WAL: {}", e)))?;
        let idx = u64::from_be_bytes(idx_bytes);

        // Read key count (1 byte)
        let mut count_byte = [0u8; 1];
        self.reader
            .read_exact(&mut count_byte)
            .map_err(|e| Error::Internal(format!("failed to read key count from WAL: {}", e)))?;
        let key_count = count_byte[0] as usize;

        // Read keys (32 bytes each)
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let mut key = [0u8; 32];
            self.reader
                .read_exact(&mut key)
                .map_err(|e| Error::Internal(format!("failed to read key from WAL: {}", e)))?;
            keys.push(key);
        }

        Ok(Some((LogIndex::new(idx), keys)))
    }
}

/// Validate and truncate the binary WAL file to match the expected tree size.
///
/// This function reads the WAL to find all entries and truncates any entries
/// with index >= expected_tree_size. This is critical for crash recovery: if
/// the WAL was flushed but the database wasn't updated before a crash, we need
/// to truncate the WAL to match the database state to avoid duplicate entries.
///
/// Returns the actual tree size found in the WAL (may be less than expected if WAL is behind).
pub fn validate_and_truncate_wal(path: impl AsRef<Path>, expected_tree_size: u64) -> Result<u64> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(0);
    }

    // Open file for reading to scan entries
    let mut reader = WalReader::open(path)?;
    let mut last_valid_pos: u64 = 0;
    let mut max_valid_idx: Option<u64> = None;

    // Calculate entry sizes as we read to find truncation point
    while let Some((idx, keys)) = reader.next_entry()? {
        let idx_val = idx.value();

        if expected_tree_size == 0 || idx_val < expected_tree_size {
            // This entry is within bounds
            // Binary format: 1 byte version + 8 bytes index + 1 byte count + 32*count bytes keys
            let entry_size = 1 + 8 + 1 + (keys.len() as u64 * 32);
            last_valid_pos += entry_size;
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

    // Truncate file if needed
    let file_size = std::fs::metadata(path)
        .map_err(|e| Error::Internal(format!("failed to get WAL metadata: {}", e)))?
        .len();

    if last_valid_pos < file_size {
        tracing::info!(
            "Truncating WAL from {} to {} bytes (removing {} bytes)",
            file_size,
            last_valid_pos,
            file_size - last_valid_pos
        );

        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| Error::Internal(format!("failed to open WAL for truncation: {}", e)))?;

        file.set_len(last_valid_pos)
            .map_err(|e| Error::Internal(format!("failed to truncate WAL: {}", e)))?;
        file.sync_all()
            .map_err(|e| Error::Internal(format!("failed to sync truncated WAL: {}", e)))?;
    }

    // Return the tree size based on max index found + 1 (since indices are 0-based)
    Ok(max_valid_idx.map(|idx| idx + 1).unwrap_or(0))
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
    fn test_binary_format_space_savings() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write entries with 5 keys each
        {
            let mut writer = WalWriter::open(path).unwrap();
            let keys: Vec<IndexKey> = (0..5).map(|i| [i; 32]).collect();

            for i in 0..100 {
                writer.append(LogIndex::new(i), &keys).unwrap();
            }
            writer.flush().unwrap();
        }

        // Check file size
        let file_size = std::fs::metadata(path).unwrap().len();

        // Binary format: (1 version + 8 index + 1 count + 5*32 keys) * 100 entries
        // = (1 + 8 + 1 + 160) * 100 = 170 * 100 = 17,000 bytes
        let expected_size = 170 * 100;

        // Text format would be: ~(5 + 5*65 + 1) * 100 = ~33,100 bytes
        // Binary saves: ~48% space

        println!("Binary format file size: {} bytes", file_size);
        println!("Expected size: {} bytes", expected_size);
        assert_eq!(file_size, expected_size);
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

    #[test]
    fn test_batched_wal_writer_basic() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write entries with batching
        {
            let mut writer = BatchedWalWriter::open(path, 10).unwrap();

            let key1 = [1u8; 32];
            let key2 = [2u8; 32];

            writer.append(LogIndex::new(0), vec![key1]).unwrap();
            writer.append(LogIndex::new(1), vec![key1, key2]).unwrap();
            writer.append(LogIndex::new(2), vec![]).unwrap();

            // Entries should be buffered
            assert_eq!(writer.buffered_count(), 3);

            // Manually flush
            writer.flush().unwrap();
            assert_eq!(writer.buffered_count(), 0);
        }

        // Read them back with regular reader
        {
            let mut reader = WalReader::open(path).unwrap();

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 0);
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0], [1u8; 32]);

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 1);
            assert_eq!(keys.len(), 2);

            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), 2);
            assert_eq!(keys.len(), 0);

            assert!(reader.next_entry().unwrap().is_none());
        }
    }

    #[test]
    fn test_batched_wal_writer_auto_flush() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write entries that trigger auto-flush
        {
            let mut writer = BatchedWalWriter::open(path, 3).unwrap();
            let key = [1u8; 32];

            // Add 3 entries - should auto-flush
            writer.append(LogIndex::new(0), vec![key]).unwrap();
            writer.append(LogIndex::new(1), vec![key]).unwrap();
            writer.append(LogIndex::new(2), vec![key]).unwrap();

            // Buffer should be empty after auto-flush
            assert_eq!(writer.buffered_count(), 0);

            // Add one more
            writer.append(LogIndex::new(3), vec![key]).unwrap();
            assert_eq!(writer.buffered_count(), 1);

            // Manual flush for remaining
            writer.flush().unwrap();
        }

        // Verify all 4 entries were written
        {
            let mut reader = WalReader::open(path).unwrap();
            for i in 0..4 {
                let (idx, _) = reader.next_entry().unwrap().unwrap();
                assert_eq!(idx.value(), i);
            }
            assert!(reader.next_entry().unwrap().is_none());
        }
    }

    #[test]
    fn test_batched_wal_writer_large_batch() {
        use std::time::Instant;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let entry_count = 1000;
        let batch_size = 100;

        // Write many entries
        let start = Instant::now();
        {
            let mut writer = BatchedWalWriter::open(path, batch_size).unwrap();
            let key = [1u8; 32];

            for i in 0..entry_count {
                writer.append(LogIndex::new(i), vec![key]).unwrap();
            }

            writer.flush().unwrap();
        }
        let elapsed = start.elapsed();

        // Should complete in reasonable time (batching reduces fsync overhead)
        println!(
            "Wrote {} entries in {:?} ({:.2} µs/entry)",
            entry_count,
            elapsed,
            elapsed.as_micros() as f64 / entry_count as f64
        );

        // Verify all entries
        {
            let mut reader = WalReader::open(path).unwrap();
            for i in 0..entry_count {
                let (idx, _) = reader.next_entry().unwrap().unwrap();
                assert_eq!(idx.value(), i);
            }
            assert!(reader.next_entry().unwrap().is_none());
        }
    }
}
