//! tlog-tiles path formatting and parsing.
//!
//! Implements the path layout specified in <https://c2sp.org/tlog-tiles>

use crate::error::{Error, Result};

/// Path to the checkpoint file.
pub const CHECKPOINT_PATH: &str = "checkpoint";

/// Maximum number of levels a Merkle tree tile represents.
pub const TILE_HEIGHT: u64 = 8;

/// Maximum number of hashes in the bottom row of a tile.
pub const TILE_WIDTH: u64 = 1 << TILE_HEIGHT; // 256

/// Maximum number of entries in an entry bundle.
pub const ENTRY_BUNDLE_WIDTH: u64 = TILE_WIDTH; // 256

/// Format an index N into the tlog-tiles path format.
///
/// N is grouped into chunks of 3 decimal digits, starting with the most significant digit,
/// padding with zeroes as necessary. Digit groups are prefixed with "x", except for the
/// least-significant group which has no prefix, and separated with slashes.
///
/// Examples:
/// - 0 -> "000"
/// - 123 -> "123"
/// - 1234 -> "x001/234"
/// - 1234067 -> "x001/x234/067"
pub fn format_n(mut n: u64) -> String {
    let mut result = format!("{:03}", n % 1000);
    n /= 1000;

    while n > 0 {
        result = format!("x{:03}/{}", n % 1000, result);
        n /= 1000;
    }

    result
}

/// Format N with an optional partial suffix.
///
/// If partial > 0, appends ".p/{partial}" to the path.
pub fn format_n_with_suffix(n: u64, partial: u8) -> String {
    let base = format_n(n);
    if partial > 0 {
        format!("{}.p/{}", base, partial)
    } else {
        base
    }
}

/// Build the path to a hash tile.
///
/// Format: `tile/{level}/{index}[.p/{partial}]`
pub fn tile_path(level: u64, index: u64, partial: u8) -> String {
    format!("tile/{}/{}", level, format_n_with_suffix(index, partial))
}

/// Build the path to an entry bundle.
///
/// Format: `tile/entries/{index}[.p/{partial}]`
pub fn entries_path(index: u64, partial: u8) -> String {
    format!("tile/entries/{}", format_n_with_suffix(index, partial))
}

/// Build the path to an entry bundle for a given log index.
///
/// Multiple log indices can map to the same bundle (up to 256 entries per bundle).
pub fn entries_path_for_log_index(seq: u64, log_size: u64) -> String {
    let bundle_index = seq / ENTRY_BUNDLE_WIDTH;
    let partial = partial_tile_size(0, bundle_index, log_size);
    entries_path(bundle_index, partial)
}

/// Calculate the expected number of leaves in a tile at the given level and index
/// within a tree of the specified size, or 0 if the tile is fully populated.
pub fn partial_tile_size(level: u64, index: u64, log_size: u64) -> u8 {
    let size_at_level = log_size >> (level * TILE_HEIGHT);
    let full_tiles = size_at_level / TILE_WIDTH;

    if index < full_tiles {
        0
    } else {
        (size_at_level % TILE_WIDTH) as u8
    }
}

/// Parse a tile level string.
///
/// Validates that level is between 0 and 63.
pub fn parse_tile_level(level: &str) -> Result<u64> {
    let l: u64 = level
        .parse()
        .map_err(|_| Error::InvalidPath("invalid tile level".into()))?;

    if l > 63 {
        return Err(Error::InvalidPath("tile level must be 0-63".into()));
    }

    Ok(l)
}

/// Parse a tile index string with optional partial suffix.
///
/// Returns (index, partial) where partial is 0 for full tiles.
///
/// Examples:
/// - "000" -> (0, 0)
/// - "x001/234" -> (1234, 0)
/// - "x001/x234/067.p/8" -> (1234067, 8)
pub fn parse_tile_index(index_str: &str) -> Result<(u64, u8)> {
    let (index_part, partial) = if let Some(pos) = index_str.find(".p/") {
        let partial_str = &index_str[pos + 3..];
        let partial: u64 = partial_str
            .parse()
            .map_err(|_| Error::InvalidPath("invalid partial size".into()))?;

        if partial < 1 || partial >= TILE_WIDTH {
            return Err(Error::InvalidPath("partial size must be 1-255".into()));
        }

        (&index_str[..pos], partial as u8)
    } else {
        (index_str, 0u8)
    };

    // Parse the N-format index
    let parts: Vec<&str> = index_part.split('/').collect();

    // Validate x-prefix pattern: all but last should start with 'x'
    for (i, part) in parts.iter().enumerate() {
        if i < parts.len() - 1 {
            if !part.starts_with('x') {
                return Err(Error::InvalidPath("invalid index format".into()));
            }
        } else if part.starts_with('x') {
            return Err(Error::InvalidPath(
                "last index component should not have x prefix".into(),
            ));
        }
    }

    let mut index: u64 = 0;
    for part in parts {
        let digits = part.strip_prefix('x').unwrap_or(part);

        if digits.len() != 3 {
            return Err(Error::InvalidPath(
                "each index component must be 3 digits".into(),
            ));
        }

        let n: u64 = digits
            .parse()
            .map_err(|_| Error::InvalidPath("invalid index digits".into()))?;

        if n >= 1000 {
            return Err(Error::InvalidPath("index component must be < 1000".into()));
        }

        // Check for overflow
        if index > (u64::MAX - n) / 1000 {
            return Err(Error::InvalidPath("index overflow".into()));
        }

        index = index * 1000 + n;
    }

    Ok((index, partial))
}

/// Parse a full tile path: level and index with optional partial.
pub fn parse_tile_path(level: &str, index: &str) -> Result<(u64, u64, u8)> {
    let l = parse_tile_level(level)?;
    let (i, p) = parse_tile_index(index)?;
    Ok((l, i, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_n() {
        assert_eq!(format_n(0), "000");
        assert_eq!(format_n(1), "001");
        assert_eq!(format_n(123), "123");
        assert_eq!(format_n(999), "999");
        assert_eq!(format_n(1000), "x001/000");
        assert_eq!(format_n(1234), "x001/234");
        assert_eq!(format_n(1234067), "x001/x234/067");
        assert_eq!(format_n(999999999), "x999/x999/999");
    }

    #[test]
    fn test_format_n_with_suffix() {
        assert_eq!(format_n_with_suffix(123, 0), "123");
        assert_eq!(format_n_with_suffix(123, 8), "123.p/8");
        assert_eq!(format_n_with_suffix(1234067, 42), "x001/x234/067.p/42");
    }

    #[test]
    fn test_tile_path() {
        assert_eq!(tile_path(0, 0, 0), "tile/0/000");
        assert_eq!(tile_path(0, 123, 0), "tile/0/123");
        assert_eq!(tile_path(1, 1234067, 0), "tile/1/x001/x234/067");
        assert_eq!(tile_path(0, 1234067, 8), "tile/0/x001/x234/067.p/8");
    }

    /// Test vectors ported from tessera's TestTilePath in paths_test.go
    #[test]
    fn test_tile_path_tessera_vectors() {
        let test_cases = [
            (0, 0, 0, "tile/0/000"),
            (0, 0, 255, "tile/0/000.p/255"),
            (1, 0, 0, "tile/1/000"),
            (15, 455667, 0, "tile/15/x455/667"),
            (15, 123456789, 41, "tile/15/x123/x456/789.p/41"),
        ];

        for (level, index, partial, want_path) in test_cases {
            let got_path = tile_path(level, index, partial);
            assert_eq!(
                got_path, want_path,
                "tile_path({}, {}, {}) mismatch",
                level, index, partial
            );
        }
    }

    #[test]
    fn test_entries_path() {
        assert_eq!(entries_path(0, 0), "tile/entries/000");
        assert_eq!(entries_path(123, 0), "tile/entries/123");
        assert_eq!(entries_path(123, 8), "tile/entries/123.p/8");
    }

    /// Test vectors ported from tessera's TestEntriesPath in paths_test.go
    #[test]
    fn test_entries_path_tessera_vectors() {
        let test_cases = [
            (0, 0, "tile/entries/000"),
            (0, 8, "tile/entries/000.p/8"),
            (255, 0, "tile/entries/255"),
            (255, 253, "tile/entries/255.p/253"),
        ];

        for (n, partial, want_path) in test_cases {
            let got_path = entries_path(n, partial);
            assert_eq!(
                got_path, want_path,
                "entries_path({}, {}) mismatch",
                n, partial
            );
        }
    }

    /// Test vectors ported from tessera's TestEntriesPathForLogIndex in paths_test.go
    #[test]
    fn test_entries_path_for_log_index_tessera_vectors() {
        let test_cases = [
            (0, 256, "tile/entries/000"),
            (255, 256, "tile/entries/000"),
            (251, 255, "tile/entries/000.p/255"),
            (256, 512, "tile/entries/001"),
            (3, 257, "tile/entries/000"),
            (256, 257, "tile/entries/001.p/1"),
            (
                123456789 * 256,
                123456790 * 256,
                "tile/entries/x123/x456/789",
            ),
        ];

        for (seq, log_size, want_path) in test_cases {
            let got_path = entries_path_for_log_index(seq, log_size);
            assert_eq!(
                got_path, want_path,
                "entries_path_for_log_index({}, {}) mismatch",
                seq, log_size
            );
        }
    }

    #[test]
    fn test_partial_tile_size() {
        // Full tiles
        assert_eq!(partial_tile_size(0, 0, 256), 0);
        assert_eq!(partial_tile_size(0, 0, 512), 0);
        assert_eq!(partial_tile_size(0, 1, 512), 0);

        // Partial tiles
        assert_eq!(partial_tile_size(0, 0, 100), 100);
        assert_eq!(partial_tile_size(0, 1, 300), 44); // 300 - 256 = 44
        assert_eq!(partial_tile_size(0, 0, 1), 1);
    }

    #[test]
    fn test_parse_tile_index() {
        assert_eq!(parse_tile_index("000").unwrap(), (0, 0));
        assert_eq!(parse_tile_index("123").unwrap(), (123, 0));
        assert_eq!(parse_tile_index("x001/234").unwrap(), (1234, 0));
        assert_eq!(parse_tile_index("x001/x234/067").unwrap(), (1234067, 0));
        assert_eq!(parse_tile_index("123.p/8").unwrap(), (123, 8));
        assert_eq!(
            parse_tile_index("x001/x234/067.p/42").unwrap(),
            (1234067, 42)
        );
    }

    #[test]
    fn test_parse_tile_level() {
        assert_eq!(parse_tile_level("0").unwrap(), 0);
        assert_eq!(parse_tile_level("63").unwrap(), 63);
        assert!(parse_tile_level("64").is_err());
        assert!(parse_tile_level("abc").is_err());
    }

    #[test]
    fn test_roundtrip() {
        for n in [0, 1, 123, 999, 1000, 1234, 1234067, 999999999] {
            for p in [0, 1, 8, 42, 255] {
                let path = format_n_with_suffix(n, p);
                let (parsed_n, parsed_p) = parse_tile_index(&path).unwrap();
                assert_eq!(n, parsed_n, "index mismatch for {}", path);
                assert_eq!(p, parsed_p, "partial mismatch for {}", path);
            }
        }
    }
}
