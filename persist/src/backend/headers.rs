//! Binary fixed-record backend for the validated header chain.
//!
//! The file stores `magic || min_stored || raw headers`, where each raw
//! header is exactly `record_size` bytes and logical row keys are absolute
//! block heights encoded as decimal strings. The first record corresponds
//! to `min_stored`, so sparse 2016-boundary caches do not need placeholder
//! records for lower heights.

use std::{
    collections::BTreeMap,
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use super::{lock::DirLock, PersistenceBackend};
use crate::PersistError;

const CACHE_MAGIC: [u8; 4] = *b"BWKH";
const CACHE_PREFIX_LEN: usize = 8;

/// Fixed-record binary backend used by `bwk_electrum::header_store::HeaderStore`.
///
/// The header chain is always binary-backed through this backend, even when
/// the wallet's other stores use the JSON or SQLite backend: the fixed-record
/// layout gives a positional seek-write for the steady one-header-per-block
/// append and a compact contiguous file. (The JSON backend also cannot hold
/// raw header bytes at all: its values must parse as JSON.) A corrupt cache
/// is wiped and resynced from the server; headers are a refetchable cache,
/// not wallet state.
#[derive(Debug)]
pub struct HeaderBackend {
    path: PathBuf,
    record_size: usize,
    /// Advisory lock on `{path}.lock`, held for the backend's lifetime so a
    /// second opener of the same cache file can't interleave positional
    /// writes. A per-file sentinel (not the dir `.lock`) so it doesn't collide
    /// with a `JsonBackend` locking the account dir this cache lives in.
    _lock: DirLock,
}

impl HeaderBackend {
    /// Open a binary header cache at `path`.
    ///
    /// Takes an exclusive advisory lock on `{path}.lock` before any read or
    /// write, so a second opener fails fast with [`PersistError::AlreadyOpen`]
    /// instead of racing on the positional seek-writes.
    pub fn open(path: PathBuf, record_size: usize) -> Result<Self, PersistError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PersistError::Io(format!("create_dir_all {}: {e}", parent.display()))
            })?;
        }
        let lock = DirLock::acquire_path(Self::lock_path(&path))?;
        Ok(Self {
            path,
            record_size,
            _lock: lock,
        })
    }

    /// Sentinel path for the advisory lock: the cache file name with a
    /// `.lock` suffix, alongside the cache file.
    fn lock_path(path: &Path) -> PathBuf {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        path.with_file_name(name)
    }

    /// Path to the backing binary file.
    #[cfg(any(test, feature = "test"))]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn parse_key(key: &str) -> Result<u32, PersistError> {
        key.parse::<u32>()
            .map_err(|_| PersistError::Io(format!("invalid header height key {key:?}")))
    }

    fn load_map(&self) -> Result<BTreeMap<u32, Vec<u8>>, PersistError> {
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => {
                return Err(PersistError::Io(format!(
                    "read {}: {e}",
                    self.path.display()
                )))
            }
        };
        if bytes.len() < CACHE_PREFIX_LEN || bytes[0..4] != CACHE_MAGIC {
            if !bytes.is_empty() {
                log::warn!(
                    "HeaderBackend: unrecognized header cache at {:?}; wiping",
                    self.path
                );
            }
            // Headers are a refetchable cache, not wallet state: wipe +
            // resync is the correct recovery, unlike a wallet store where
            // corrupt data must propagate as an error instead.
            let _ = fs::remove_file(&self.path);
            return Ok(BTreeMap::new());
        }
        let min_stored = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let body = &bytes[CACHE_PREFIX_LEN..];
        if body.len() % self.record_size != 0 {
            log::warn!(
                "HeaderBackend: header cache at {:?} has a short trailing record; wiping",
                self.path
            );
            // Same wipe-and-resync exemption as the magic-mismatch arm above.
            let _ = fs::remove_file(&self.path);
            return Ok(BTreeMap::new());
        }

        let mut out = BTreeMap::new();
        for (i, chunk) in body.chunks_exact(self.record_size).enumerate() {
            out.insert(min_stored + i as u32, chunk.to_vec());
        }
        Ok(out)
    }

    fn write_map(&self, rows: &BTreeMap<u32, Vec<u8>>) -> Result<(), PersistError> {
        let min_stored = rows.keys().next().copied().unwrap_or(0);
        if let Some(max_stored) = rows.keys().next_back().copied() {
            let span = (max_stored - min_stored) as usize + 1;
            if span != rows.len() {
                return Err(PersistError::Io(format!(
                    "header rows must be contiguous from {min_stored} to {max_stored}"
                )));
            }
        }
        let mut bytes = Vec::with_capacity(CACHE_PREFIX_LEN + rows.len() * self.record_size);
        bytes.extend_from_slice(&CACHE_MAGIC);
        bytes.extend_from_slice(&min_stored.to_le_bytes());
        for raw in rows.values() {
            if raw.len() != self.record_size {
                return Err(PersistError::Io(format!(
                    "record length {} != expected {}",
                    raw.len(),
                    self.record_size
                )));
            }
            bytes.extend_from_slice(raw);
        }
        fs::write(&self.path, &bytes)
            .map_err(|e| PersistError::Io(format!("write {}: {e}", self.path.display())))
    }

    fn put_row_positional(&self, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        if bytes.len() != self.record_size {
            return Err(PersistError::Io(format!(
                "record length {} != expected {}",
                bytes.len(),
                self.record_size
            )));
        }
        let height = Self::parse_key(key)?;
        let rows = self.load_map()?;
        let Some(min_stored) = rows.keys().next().copied() else {
            let mut rows = BTreeMap::new();
            rows.insert(height, bytes.to_vec());
            return self.write_map(&rows);
        };
        let max_stored = rows.keys().next_back().copied().unwrap_or(min_stored);
        if height < min_stored || height > max_stored.saturating_add(1) {
            let mut rows = rows;
            rows.insert(height, bytes.to_vec());
            return self.write_map(&rows);
        }

        let offset =
            CACHE_PREFIX_LEN as u64 + (height - min_stored) as u64 * self.record_size as u64;
        let res = (|| -> std::io::Result<()> {
            let mut f = fs::OpenOptions::new().write(true).open(&self.path)?;
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(bytes)?;
            let new_len = CACHE_PREFIX_LEN as u64
                + (height - min_stored + 1) as u64 * self.record_size as u64;
            if height == max_stored.saturating_add(1) {
                f.set_len(new_len)?;
            }
            Ok(())
        })();
        res.map_err(|e| PersistError::Io(format!("positional write {}: {e}", self.path.display())))
    }
}

impl PersistenceBackend for HeaderBackend {
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError> {
        self.validate_store_name(store)?;
        let height = Self::parse_key(key)?;
        Ok(self.load_map()?.remove(&height))
    }

    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        self.validate_store_name(store)?;
        Ok(self
            .load_map()?
            .into_iter()
            .map(|(h, raw)| (h.to_string(), raw))
            .collect())
    }

    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        self.put_row_positional(key, bytes)
    }

    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        let height = Self::parse_key(key)?;
        let mut rows = self.load_map()?;
        rows.remove(&height);
        self.write_map(&rows)
    }

    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        if removed.is_empty() && inserts.len() == 1 {
            return self.put_row_positional(&inserts[0].0, &inserts[0].1);
        }

        let mut rows = self.load_map()?;
        for key in removed {
            rows.remove(&Self::parse_key(key)?);
        }
        for (key, bytes) in inserts {
            if bytes.len() != self.record_size {
                return Err(PersistError::Io(format!(
                    "record length {} != expected {}",
                    bytes.len(),
                    self.record_size
                )));
            }
            rows.insert(Self::parse_key(key)?, bytes.clone());
        }
        self.write_map(&rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HEADERS_STORE_KEY;
    use temp_dir::TempDir;

    const SIZE: usize = 80;

    fn backend(dir: &TempDir) -> HeaderBackend {
        HeaderBackend::open(dir.path().join("headers.bin"), SIZE).unwrap()
    }

    fn record(fill: u8) -> Vec<u8> {
        vec![fill; SIZE]
    }

    fn seed(b: &HeaderBackend, range: std::ops::RangeInclusive<u32>) {
        let inserts: Vec<(String, Vec<u8>)> =
            range.map(|h| (h.to_string(), record(h as u8))).collect();
        b.flush_batch(HEADERS_STORE_KEY, &inserts, &[]).unwrap();
    }

    #[test]
    fn missing_file_yields_empty() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        assert!(b.get_rows(HEADERS_STORE_KEY).unwrap().is_empty());
        assert_eq!(b.get_row(HEADERS_STORE_KEY, "0").unwrap(), None);
    }

    #[test]
    fn put_row_round_trip() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        b.put_row(HEADERS_STORE_KEY, "7", &record(7)).unwrap();
        assert_eq!(b.get_row(HEADERS_STORE_KEY, "7").unwrap(), Some(record(7)));
        let rows = b.get_rows(HEADERS_STORE_KEY).unwrap();
        assert_eq!(rows, vec![("7".to_string(), record(7))]);
    }

    #[test]
    fn positional_overwrite_and_append_with_sparse_floor() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        seed(&b, 5..=8);

        // Overwrite a mid-range row in place.
        b.put_row(HEADERS_STORE_KEY, "6", &record(0x66)).unwrap();
        // Append at max + 1 (the positional set_len path).
        b.put_row(HEADERS_STORE_KEY, "9", &record(9)).unwrap();

        assert_eq!(b.get_row(HEADERS_STORE_KEY, "5").unwrap(), Some(record(5)));
        assert_eq!(
            b.get_row(HEADERS_STORE_KEY, "6").unwrap(),
            Some(record(0x66))
        );
        assert_eq!(b.get_row(HEADERS_STORE_KEY, "9").unwrap(), Some(record(9)));
        // prefix (magic + min_stored) + 5 records exactly.
        let len = fs::metadata(dir.path().join("headers.bin")).unwrap().len();
        assert_eq!(len, (CACHE_PREFIX_LEN + 5 * SIZE) as u64);
    }

    #[test]
    fn out_of_range_put_below_floor_rewrites_or_rejects() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        seed(&b, 5..=8);

        // min - 1 keeps the range contiguous: full rewrite accepts it.
        b.put_row(HEADERS_STORE_KEY, "4", &record(4)).unwrap();
        assert_eq!(b.get_row(HEADERS_STORE_KEY, "4").unwrap(), Some(record(4)));

        // A row leaving a gap is rejected by the contiguity guard.
        assert!(b.put_row(HEADERS_STORE_KEY, "2", &record(2)).is_err());
    }

    #[test]
    fn flush_batch_rejects_gap() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        let inserts = vec![("0".to_string(), record(0)), ("2".to_string(), record(2))];
        assert!(b.flush_batch(HEADERS_STORE_KEY, &inserts, &[]).is_err());
    }

    #[test]
    fn wrong_size_record_rejected() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        assert!(b.put_row(HEADERS_STORE_KEY, "0", &[0u8; 10]).is_err());
        seed(&b, 0..=1);
        assert!(b
            .flush_batch(HEADERS_STORE_KEY, &[("2".to_string(), vec![0u8; 10])], &[])
            .is_err());
    }

    #[test]
    fn magic_mismatch_wipes() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        let path = dir.path().join("headers.bin");
        fs::write(&path, b"not a header cache").unwrap();
        assert!(b.get_rows(HEADERS_STORE_KEY).unwrap().is_empty());
        assert!(!path.exists(), "corrupt cache file must be wiped");
    }

    #[test]
    fn short_trailing_record_wipes() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        let path = dir.path().join("headers.bin");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CACHE_MAGIC);
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&record(5));
        bytes.extend_from_slice(&[0u8; 10]);
        fs::write(&path, &bytes).unwrap();
        assert!(b.get_rows(HEADERS_STORE_KEY).unwrap().is_empty());
        assert!(!path.exists(), "truncated cache file must be wiped");
    }

    #[test]
    fn delete_tip_row_round_trip() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        seed(&b, 0..=2);
        b.delete_row(HEADERS_STORE_KEY, "2").unwrap();
        assert_eq!(b.get_row(HEADERS_STORE_KEY, "2").unwrap(), None);
        assert_eq!(b.get_rows(HEADERS_STORE_KEY).unwrap().len(), 2);
    }

    #[test]
    fn get_rows_returns_decimal_height_keys() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        seed(&b, 2016..=2018);
        let keys: Vec<String> = b
            .get_rows(HEADERS_STORE_KEY)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(keys, vec!["2016", "2017", "2018"]);
    }

    #[test]
    fn unknown_store_name_rejected() {
        let dir = TempDir::new().unwrap();
        let b = backend(&dir);
        assert!(b.put_row("nope", "0", &record(0)).is_err());
    }

    #[test]
    fn second_open_while_held_returns_already_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let _held = HeaderBackend::open(path.clone(), SIZE).expect("first open");
        match HeaderBackend::open(path, SIZE) {
            Err(PersistError::AlreadyOpen { .. }) => {}
            other => panic!("expected AlreadyOpen, got {other:?}"),
        }
    }

    #[test]
    fn reopen_after_drop_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        {
            let _b = HeaderBackend::open(path.clone(), SIZE).unwrap();
        }
        // The lock fd is released on drop, so a fresh open must succeed.
        let _b2 = HeaderBackend::open(path, SIZE).unwrap();
    }
}
