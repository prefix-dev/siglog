//! Snapshot persistence for the verifiable index.
//!
//! A snapshot is a point-in-time serialization of the full key → indices
//! map at a given tree size. Together with the WAL it bounds both WAL growth
//! and startup replay time: after a snapshot at tree size `T` is durably
//! written, the WAL is truncated and only needs to cover entries `>= T`.
//!
//! ## Format
//!
//! ```text
//! magic    "VSNP"                (4 bytes)
//! version  u8 = 1
//! tree_size u64 BE
//! key_count u64 BE
//! per key:
//!   key       32 bytes
//!   idx_count u32 BE
//!   indices   idx_count * u64 BE
//! crc32     u32 LE over all preceding bytes
//! ```
//!
//! Snapshots are written to a temp file, fsynced, and renamed into place, so
//! a crash mid-write can never leave a torn snapshot at the final path. A
//! snapshot that fails its CRC check is treated as absent (the caller falls
//! back to rebuilding from log storage).

use crate::error::{Error, Result};
use crate::types::LogIndex;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::IndexKey;

const SNAPSHOT_MAGIC: &[u8; 4] = b"VSNP";
const SNAPSHOT_VERSION: u8 = 1;

/// The snapshot path for a given WAL path (`<wal>.snapshot`).
pub fn snapshot_path(wal_path: &Path) -> PathBuf {
    let mut os = wal_path.as_os_str().to_os_string();
    os.push(".snapshot");
    PathBuf::from(os)
}

/// Serialize and durably write a snapshot (temp file + fsync + rename).
pub fn write_snapshot(
    path: &Path,
    tree_size: u64,
    index: &HashMap<IndexKey, Vec<LogIndex>>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(17 + index.len() * 48);
    buf.extend_from_slice(SNAPSHOT_MAGIC);
    buf.push(SNAPSHOT_VERSION);
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(&(index.len() as u64).to_be_bytes());

    for (key, indices) in index {
        buf.extend_from_slice(key);
        buf.extend_from_slice(&(indices.len() as u32).to_be_bytes());
        for idx in indices {
            buf.extend_from_slice(&idx.value().to_be_bytes());
        }
    }

    let crc = crc32fast::hash(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    let tmp_path = {
        let mut os = path.as_os_str().to_os_string();
        os.push(".tmp");
        PathBuf::from(os)
    };

    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| Error::Internal(format!("failed to create snapshot temp file: {}", e)))?;
        tmp.write_all(&buf)
            .map_err(|e| Error::Internal(format!("failed to write snapshot: {}", e)))?;
        tmp.sync_all()
            .map_err(|e| Error::Internal(format!("failed to sync snapshot: {}", e)))?;
    }

    std::fs::rename(&tmp_path, path)
        .map_err(|e| Error::Internal(format!("failed to rename snapshot into place: {}", e)))?;

    // Fsync the parent directory so the rename itself is durable.
    if let Some(parent) = path.parent() {
        let dir = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(dir_file) = File::open(dir) {
            let _ = dir_file.sync_all();
        }
    }

    Ok(())
}

/// Read a snapshot. Returns `Ok(None)` if the file does not exist or fails
/// validation (magic, version, structure, CRC) — a bad snapshot is treated
/// as absent so the caller can fall back to rebuilding.
pub fn read_snapshot(path: &Path) -> Option<(u64, HashMap<IndexKey, Vec<LogIndex>>)> {
    if !path.exists() {
        return None;
    }

    let mut data = Vec::new();
    match File::open(path).and_then(|mut f| f.read_to_end(&mut data)) {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("Failed to read vindex snapshot {}: {}", path.display(), e);
            return None;
        }
    }

    parse_snapshot(&data).map_err(|e| {
        tracing::warn!(
            "Ignoring invalid vindex snapshot {}: {}",
            path.display(),
            e
        );
    })
    .ok()
}

fn parse_snapshot(data: &[u8]) -> Result<(u64, HashMap<IndexKey, Vec<LogIndex>>)> {
    // magic(4) + version(1) + tree_size(8) + key_count(8) + crc(4)
    if data.len() < 25 {
        return Err(Error::Internal("snapshot too short".into()));
    }

    let (body, crc_bytes) = data.split_at(data.len() - 4);
    let stored_crc = u32::from_le_bytes(crc_bytes.try_into().unwrap());
    if crc32fast::hash(body) != stored_crc {
        return Err(Error::Internal("snapshot checksum mismatch".into()));
    }

    if &body[0..4] != SNAPSHOT_MAGIC {
        return Err(Error::Internal("bad snapshot magic".into()));
    }
    if body[4] != SNAPSHOT_VERSION {
        return Err(Error::Internal(format!(
            "unsupported snapshot version {}",
            body[4]
        )));
    }

    let tree_size = u64::from_be_bytes(body[5..13].try_into().unwrap());
    let key_count = u64::from_be_bytes(body[13..21].try_into().unwrap()) as usize;

    let mut pos = 21usize;
    let mut index = HashMap::with_capacity(key_count);
    for _ in 0..key_count {
        if body.len() < pos + 36 {
            return Err(Error::Internal("snapshot truncated in key record".into()));
        }
        let key: IndexKey = body[pos..pos + 32].try_into().unwrap();
        let idx_count = u32::from_be_bytes(body[pos + 32..pos + 36].try_into().unwrap()) as usize;
        pos += 36;

        if body.len() < pos + idx_count * 8 {
            return Err(Error::Internal("snapshot truncated in index list".into()));
        }
        let mut indices = Vec::with_capacity(idx_count);
        for i in 0..idx_count {
            let v = u64::from_be_bytes(body[pos + i * 8..pos + i * 8 + 8].try_into().unwrap());
            indices.push(LogIndex::new(v));
        }
        pos += idx_count * 8;
        index.insert(key, indices);
    }

    if pos != body.len() {
        return Err(Error::Internal("snapshot has trailing bytes".into()));
    }

    Ok((tree_size, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_index() -> HashMap<IndexKey, Vec<LogIndex>> {
        let mut index = HashMap::new();
        index.insert([1u8; 32], vec![LogIndex::new(0), LogIndex::new(5)]);
        index.insert([2u8; 32], vec![LogIndex::new(3)]);
        index.insert([3u8; 32], vec![]);
        index
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wal.snapshot");

        let index = sample_index();
        write_snapshot(&path, 6, &index).unwrap();

        let (tree_size, loaded) = read_snapshot(&path).unwrap();
        assert_eq!(tree_size, 6);
        assert_eq!(loaded, index);
    }

    #[test]
    fn test_missing_snapshot_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_snapshot(&dir.path().join("nope.snapshot")).is_none());
    }

    #[test]
    fn test_corrupt_snapshot_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wal.snapshot");

        write_snapshot(&path, 6, &sample_index()).unwrap();

        // Flip a byte in the middle.
        let mut data = std::fs::read(&path).unwrap();
        let mid = data.len() / 2;
        data[mid] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        assert!(read_snapshot(&path).is_none());
    }

    #[test]
    fn test_truncated_snapshot_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wal.snapshot");

        write_snapshot(&path, 6, &sample_index()).unwrap();

        let data = std::fs::read(&path).unwrap();
        std::fs::write(&path, &data[..data.len() - 10]).unwrap();

        assert!(read_snapshot(&path).is_none());
    }

    #[test]
    fn test_snapshot_path_suffix() {
        assert_eq!(
            snapshot_path(Path::new("/data/vindex.wal")),
            PathBuf::from("/data/vindex.wal.snapshot")
        );
    }
}
