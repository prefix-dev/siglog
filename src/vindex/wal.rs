//! Write Ahead Log (WAL) for verifiable index persistence.
//!
//! ## Binary format v3 (current, checksummed):
//! ```text
//! [u8 version=3][u64 index][u8 key_count][32*key_count bytes of keys][u32 crc32 LE]
//! ```
//! The CRC32 covers everything from the version byte through the last key
//! byte, so bit rot and torn writes are detected instead of being replayed
//! as wrong keys.
//!
//! ## Binary format v2 (legacy, read-only):
//! ```text
//! [u8 version=2][u64 index][u8 key_count][32*key_count bytes of keys]
//! ```
//!
//! On startup, the WAL is validated and truncated:
//! - Entries with `index >= expected_tree_size` (from the database) are
//!   truncated — the WAL ran ahead of the database before a crash.
//! - A torn or corrupted tail (crash mid-write, bit rot) is truncated at the
//!   last fully-valid entry instead of failing startup.

use crate::error::{Error, Result};
use crate::types::LogIndex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use super::IndexKey;

/// Legacy binary WAL format version (no checksum, read-only support).
const WAL_VERSION_BINARY: u8 = 2;

/// Checksummed binary WAL format version (current write format).
const WAL_VERSION_CRC: u8 = 3;

/// Serialize a single WAL entry in v3 (checksummed) format.
fn encode_entry(buf: &mut Vec<u8>, idx: LogIndex, keys: &[IndexKey]) {
    let start = buf.len();
    buf.push(WAL_VERSION_CRC);
    buf.extend_from_slice(&idx.value().to_be_bytes());
    buf.push(keys.len() as u8);
    for key in keys {
        buf.extend_from_slice(key);
    }
    let crc = crc32fast::hash(&buf[start..]);
    buf.extend_from_slice(&crc.to_le_bytes());
}

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

/// Binary WAL writer for efficient storage (v3 checksummed format).
///
/// Each entry is serialized to a buffer and written with a single
/// `write_all` call, so a failed in-process write cannot leave a partial
/// entry interleaved with later entries.
pub struct BinaryWalWriter {
    file: File,
}

impl BinaryWalWriter {
    /// Open or create a binary WAL file for writing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL: {}", e)))?;

        Ok(Self { file })
    }

    /// Append an entry to the WAL in binary format.
    pub fn append(&mut self, idx: LogIndex, keys: &[IndexKey]) -> Result<()> {
        if keys.len() > u8::MAX as usize {
            return Err(Error::InvalidEntry(format!(
                "too many WAL keys for entry {}: {} (max {})",
                idx.value(),
                keys.len(),
                u8::MAX
            )));
        }

        let mut buf = Vec::with_capacity(14 + keys.len() * 32);
        encode_entry(&mut buf, idx, keys);
        self.file
            .write_all(&buf)
            .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

        Ok(())
    }

    /// Flush the WAL to disk with fsync for durability.
    pub fn flush(&mut self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|e| Error::Internal(format!("failed to sync WAL to disk: {}", e)))?;

        Ok(())
    }

    /// Truncate the WAL to zero length (after a snapshot has been written).
    pub fn truncate(&mut self) -> Result<()> {
        self.file
            .set_len(0)
            .map_err(|e| Error::Internal(format!("failed to truncate WAL: {}", e)))?;
        self.file
            .sync_all()
            .map_err(|e| Error::Internal(format!("failed to sync truncated WAL: {}", e)))?;
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
    file: File,
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
            file,
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
    ///
    /// The whole batch is serialized and written with a single `write_all`
    /// and a single fsync. On error the buffer is retained, so a retry
    /// rewrites the full batch; duplicated entries are harmless because
    /// replay deduplicates (idx, key) pairs, and torn fragments are removed
    /// by CRC-validated truncation on startup.
    fn flush_batch(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        tracing::debug!("Flushing binary WAL batch of {} entries", self.buffer.len());

        let mut buf = Vec::with_capacity(self.buffer.iter().map(|(_, k)| 14 + k.len() * 32).sum());
        for (idx, keys) in &self.buffer {
            encode_entry(&mut buf, *idx, keys);
        }

        self.file
            .write_all(&buf)
            .map_err(|e| Error::Internal(format!("failed to write to WAL: {}", e)))?;

        // Single fsync for entire batch
        self.file
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

    /// Truncate the WAL to zero length (after a snapshot has been written).
    ///
    /// The in-memory buffer must be empty (call [`flush`](Self::flush) first).
    pub fn truncate(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            return Err(Error::Internal(
                "cannot truncate WAL with buffered entries; flush first".into(),
            ));
        }
        self.file
            .set_len(0)
            .map_err(|e| Error::Internal(format!("failed to truncate WAL: {}", e)))?;
        self.file
            .sync_all()
            .map_err(|e| Error::Internal(format!("failed to sync truncated WAL: {}", e)))?;
        Ok(())
    }
}

/// WAL reader for replaying entries in binary format (v2 legacy and v3
/// checksummed).
pub struct WalReader {
    reader: BufReader<File>,
    /// Byte offset just past the last successfully-parsed entry.
    valid_pos: u64,
}

impl WalReader {
    /// Open a WAL file for reading.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())
            .map_err(|e| Error::Internal(format!("failed to open WAL for reading: {}", e)))?;

        Ok(Self {
            reader: BufReader::new(file),
            valid_pos: 0,
        })
    }

    /// Byte offset just past the last entry successfully returned by
    /// [`next_entry`](Self::next_entry). Used for truncating a corrupted tail.
    pub fn valid_pos(&self) -> u64 {
        self.valid_pos
    }

    /// Read the next entry from the WAL.
    ///
    /// Returns `Ok(None)` on clean EOF. A torn tail or corrupted entry
    /// (bad version byte, short read, checksum mismatch) returns an error;
    /// callers recovering from a crash should truncate at [`valid_pos`](Self::valid_pos).
    pub fn next_entry(&mut self) -> Result<Option<(LogIndex, Vec<IndexKey>)>> {
        // Read version byte
        let mut version = [0u8; 1];
        match self.reader.read_exact(&mut version) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Internal(format!("failed to read from WAL: {}", e))),
        }

        if version[0] != WAL_VERSION_BINARY && version[0] != WAL_VERSION_CRC {
            return Err(Error::Internal(format!(
                "invalid WAL version: expected 0x{:02x} or 0x{:02x}, got 0x{:02x}",
                WAL_VERSION_BINARY, WAL_VERSION_CRC, version[0]
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

        let mut entry_size = 1 + 8 + 1 + key_count as u64 * 32;

        // v3: verify the trailing CRC32 over version..keys.
        if version[0] == WAL_VERSION_CRC {
            let mut crc_bytes = [0u8; 4];
            self.reader
                .read_exact(&mut crc_bytes)
                .map_err(|e| Error::Internal(format!("failed to read checksum from WAL: {}", e)))?;
            let stored_crc = u32::from_le_bytes(crc_bytes);

            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&version);
            hasher.update(&idx_bytes);
            hasher.update(&count_byte);
            for key in &keys {
                hasher.update(key);
            }
            if hasher.finalize() != stored_crc {
                return Err(Error::Internal(format!(
                    "WAL checksum mismatch for entry {}",
                    idx
                )));
            }
            entry_size += 4;
        }

        self.valid_pos += entry_size;
        Ok(Some((LogIndex::new(idx), keys)))
    }
}

/// Validate and truncate the binary WAL file to match the expected tree size.
///
/// Two kinds of tail are removed:
/// - Entries with `index >= expected_tree_size`: the WAL was flushed but the
///   database wasn't updated before a crash, so the WAL ran ahead. (The
///   worker always writes the WAL before marking entries integrated, so the
///   WAL can only ever be ahead of — never behind — the database.)
/// - A torn or corrupted tail (crash mid-write, checksum mismatch): the scan
///   stops at the last fully-valid entry and everything after is truncated.
///
/// Returns the actual tree size found in the WAL (may be less than expected
/// if the WAL is behind; callers treat that as fatal).
pub fn validate_and_truncate_wal(path: impl AsRef<Path>, expected_tree_size: u64) -> Result<u64> {
    let path = path.as_ref();

    if !path.exists() {
        return Ok(0);
    }

    // Open file for reading to scan entries
    let mut reader = WalReader::open(path)?;
    let mut last_valid_pos: u64 = 0;
    let mut max_valid_idx: Option<u64> = None;

    loop {
        match reader.next_entry() {
            Ok(Some((idx, _keys))) => {
                let idx_val = idx.value();

                if idx_val < expected_tree_size {
                    // This entry is within bounds
                    last_valid_pos = reader.valid_pos();
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
            Ok(None) => break,
            Err(e) => {
                // Torn write or bit rot in the tail. Truncate at the last
                // valid entry instead of refusing to start; this is exactly
                // the crash the WAL exists to survive. Anything the WAL
                // loses here was, by write ordering, never marked integrated
                // in the database (or the caller fails the behind-check).
                tracing::warn!(
                    "WAL corrupted at byte {}: {}. Truncating corrupted tail.",
                    last_valid_pos,
                    e
                );
                break;
            }
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

        // Binary v3 format: (1 version + 8 index + 1 count + 5*32 keys + 4 crc) * 100 entries
        // = (1 + 8 + 1 + 160 + 4) * 100 = 174 * 100 = 17,400 bytes
        let expected_size = 174 * 100;

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
    fn test_torn_tail_is_truncated() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Write 3 complete entries
        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..3 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // Simulate a crash mid-write: append a partial entry (version +
        // index but missing keys and checksum).
        {
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(&[3u8]).unwrap();
            file.write_all(&3u64.to_be_bytes()).unwrap();
            file.write_all(&[5u8]).unwrap(); // claims 5 keys, none follow
            file.sync_all().unwrap();
        }

        // Recovery must truncate the torn tail and keep the 3 good entries.
        let actual_size = validate_and_truncate_wal(path, 3).unwrap();
        assert_eq!(actual_size, 3);

        let mut reader = WalReader::open(path).unwrap();
        for i in 0..3 {
            let (idx, _) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), i);
        }
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_corrupted_entry_is_truncated() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..3 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // Flip a bit in a key byte of the last entry (offset from end: 4 crc
        // + 1 key byte). CRC validation must catch this.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = OpenOptions::new().read(true).write(true).open(path).unwrap();
            file.seek(SeekFrom::End(-5)).unwrap();
            file.write_all(&[0xFF]).unwrap();
            file.sync_all().unwrap();
        }

        // The corrupted third entry must be truncated; first two survive.
        let actual_size = validate_and_truncate_wal(path, 3).unwrap();
        assert_eq!(actual_size, 2);

        let mut reader = WalReader::open(path).unwrap();
        for i in 0..2 {
            let (idx, _) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), i);
        }
        assert!(reader.next_entry().unwrap().is_none());
    }

    #[test]
    fn test_stale_wal_with_zero_expected_size_is_truncated() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // A WAL left over from a previous deployment...
        {
            let mut writer = WalWriter::open(path).unwrap();
            let key = [1u8; 32];
            for i in 0..5 {
                writer.append(LogIndex::new(i), &[key]).unwrap();
            }
            writer.flush().unwrap();
        }

        // ...must be fully truncated when the database says the log is empty,
        // instead of replaying entries the log doesn't contain.
        let actual_size = validate_and_truncate_wal(path, 0).unwrap();
        assert_eq!(actual_size, 0);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn test_legacy_v2_entries_are_readable() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Hand-write v2 (no checksum) entries as an old binary would have.
        {
            use std::io::Write;
            let mut file = OpenOptions::new().append(true).open(path).unwrap();
            for i in 0..3u64 {
                file.write_all(&[2u8]).unwrap();
                file.write_all(&i.to_be_bytes()).unwrap();
                file.write_all(&[1u8]).unwrap();
                file.write_all(&[7u8; 32]).unwrap();
            }
            file.sync_all().unwrap();
        }

        let actual_size = validate_and_truncate_wal(path, 3).unwrap();
        assert_eq!(actual_size, 3);

        let mut reader = WalReader::open(path).unwrap();
        for i in 0..3 {
            let (idx, keys) = reader.next_entry().unwrap().unwrap();
            assert_eq!(idx.value(), i);
            assert_eq!(keys, vec![[7u8; 32]]);
        }
        assert!(reader.next_entry().unwrap().is_none());
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
