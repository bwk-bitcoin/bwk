//! JSON file backend: one JSON file per store under a directory.
//!
//! On-disk layout for an account directory `{dir}`:
//! - `{dir}/version`: plain-text decimal integer, the
//!   [`DB_VERSION`] stamped when the wallet was
//!   first initialised. Deliberately kept as its own file for dumb
//!   parsing (no JSON framework needed to read it).
//! - `{dir}/{store}.json`: for every logical store, a JSON object
//!   mapping `key -> value` where `value` is the caller's serialized
//!   entry embedded as nested JSON.
//!
//! `replace_all` / `put_row` / `delete_row` write atomically via
//! tempfile + rename.
//!
//! The format is deliberately simple and human-readable. The DB is a
//! pure KV store. See the crate-level docs.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

use super::{lock::DirLock, PersistenceBackend};
use crate::{PersistError, DB_VERSION};

const VERSION_FILENAME: &str = "version";

/// JSON-on-disk persistence backend rooted at a directory.
#[derive(Debug)]
pub struct JsonBackend {
    /// Advisory lock on `{dir}/.lock`, held for the lifetime of the
    /// backend so no second process can open the same account
    /// directory and race on the shared store files.
    _lock: DirLock,
    dir: PathBuf,
    /// `true` once the `{dir}/version` file has been observed to equal
    /// [`DB_VERSION`]: either it was already stamped by a previous
    /// session or we've stamped it as part of this session's first
    /// write. While `false`, every mutating op writes the version file
    /// before the data file. Read-only ops never flip this.
    stamped: AtomicBool,
}

impl JsonBackend {
    /// Open (or initialise) a JSON backend at `dir`.
    ///
    /// Takes an exclusive advisory lock on `{dir}/.lock` before any
    /// read or write, so a second opener fails fast with
    /// [`PersistError::AlreadyOpen`] instead of silently racing on the
    /// read-merge-write sequence of each store file.
    ///
    /// Refuses to proceed if `{dir}/version` records a version greater
    /// than [`DB_VERSION`]. A fresh directory without a version file is
    /// NOT stamped at open time. The file is written lazily by the
    /// first mutating op (see [`Self::stamp_version_if_needed`]). This
    /// keeps an open-but-never-written dir usable by older binaries.
    pub fn open(dir: PathBuf) -> Result<Self, PersistError> {
        fs::create_dir_all(&dir)
            .map_err(|e| PersistError::Io(format!("create_dir_all {}: {e}", dir.display())))?;
        let lock = DirLock::acquire(&dir)?;
        let existing = check_version(&dir)?;
        Ok(Self {
            _lock: lock,
            dir,
            // If the on-disk version already matches DB_VERSION, skip
            // the stamp on every subsequent mutating op. Otherwise
            // (absent or older) the next write will stamp.
            stamped: AtomicBool::new(existing == Some(DB_VERSION)),
        })
    }

    /// Internal: filesystem path of `store`'s rows file.
    fn store_path(&self, store: &str) -> PathBuf {
        self.dir.join(format!("{store}.json"))
    }

    /// Path to the file that holds `store`'s rows.
    ///
    /// Test-only: lets tests assert on-disk layout. Production code
    /// must not depend on JSON's filesystem layout. Go through the
    /// [`PersistenceBackend`] trait.
    #[cfg(any(test, feature = "test"))]
    pub fn path_for(&self, store: &str) -> PathBuf {
        self.store_path(store)
    }

    fn version_path(&self) -> PathBuf {
        self.dir.join(VERSION_FILENAME)
    }

    /// Write [`DB_VERSION`] into the version file if this backend
    /// hasn't already done so (or observed it already stamped) this
    /// session. Called by every mutating op **before** the data write,
    /// so that a crash between the two leaves a benign
    /// "version-without-data" state rather than a dangerous
    /// "data-without-version" state that a lower binary might
    /// mis-read.
    fn stamp_version_if_needed(&self) -> Result<(), PersistError> {
        if self.stamped.load(Ordering::Acquire) {
            return Ok(());
        }
        Self::atomic_write(&self.version_path(), format!("{DB_VERSION}\n").as_bytes())?;
        self.stamped.store(true, Ordering::Release);
        Ok(())
    }

    /// Atomic write: write to `{path}.tmp`, fsync, then rename over `path`.
    fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<(), PersistError> {
        let parent = path
            .parent()
            .ok_or_else(|| PersistError::Io(format!("path has no parent: {}", path.display())))?;
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                PersistError::Io(format!("create_dir_all {}: {e}", parent.display()))
            })?;
        }
        let mut tmp = path.to_path_buf();
        let p = path
            .file_name()
            .ok_or_else(|| PersistError::Io("invalid path".into()))?
            .to_string_lossy();
        let tmp_name = format!("{p}.tmp");
        tmp.set_file_name(tmp_name);

        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| PersistError::Io(format!("create {}: {e}", tmp.display())))?;
            f.write_all(bytes)
                .map_err(|e| PersistError::Io(format!("write {}: {e}", tmp.display())))?;
            f.sync_all()
                .map_err(|e| PersistError::Io(format!("fsync {}: {e}", tmp.display())))?;
        } // <- file dropped here

        fs::rename(&tmp, path).map_err(|e| {
            PersistError::Io(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            ))
        })
    }

    /// Read `{dir}/{store}.json` into a map. Returns an empty map if
    /// the file is absent.
    fn read_store(&self, store: &str) -> Result<BTreeMap<String, Value>, PersistError> {
        let path = self.store_path(store);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, Value>>(&bytes)
                .map_err(|e| PersistError::Serde(format!("parse {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(PersistError::Io(format!("read {}: {e}", path.display()))),
        }
    }

    fn write_store(&self, store: &str, rows: &BTreeMap<String, Value>) -> Result<(), PersistError> {
        let bytes = serde_json::to_vec_pretty(rows)
            .map_err(|e| PersistError::Serde(format!("serialize {store}: {e}")))?;
        Self::atomic_write(&self.store_path(store), &bytes)
    }
}

/// Read-only version guard. Returns the recorded version if
/// `{dir}/version` exists, `None` for a fresh directory. Refuses to
/// proceed if the recorded version is greater than [`DB_VERSION`].
///
/// Never creates the file. Stamping is deferred to the first actual
/// write; see [`JsonBackend::stamp_version_if_needed`].
fn check_version(dir: &std::path::Path) -> Result<Option<u32>, PersistError> {
    let vp = dir.join(VERSION_FILENAME);
    match fs::read_to_string(&vp) {
        Ok(s) => {
            let v: u32 = s.trim().parse().map_err(|e| {
                PersistError::Serde(format!("parse version file {}: {e}", vp.display()))
            })?;
            if v > DB_VERSION {
                return Err(PersistError::DbVersionTooNew {
                    found: v,
                    max_supported: DB_VERSION,
                });
            }
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PersistError::Io(format!("read {}: {e}", vp.display()))),
    }
}

impl PersistenceBackend for JsonBackend {
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError> {
        self.validate_store_name(store)?;
        let rows = self.read_store(store)?;
        match rows.get(key) {
            None => Ok(None),
            Some(v) => serde_json::to_vec(v)
                .map(Some)
                .map_err(|e| PersistError::Serde(format!("encode row value: {e}"))),
        }
    }

    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        self.validate_store_name(store)?;
        let rows = self.read_store(store)?;
        rows.into_iter()
            .map(|(k, v)| {
                serde_json::to_vec(&v)
                    .map(|bytes| (k, bytes))
                    .map_err(|e| PersistError::Serde(format!("encode row value: {e}")))
            })
            .collect()
    }

    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|e| PersistError::Serde(format!("decode row value: {e}")))?;
        let mut rows = self.read_store(store)?;
        rows.insert(key.to_string(), value);
        // Stamp version BEFORE writing data: if we crash between the
        // two, the dir holds a version claim but no new data, which
        // older binaries handle fine. The inverse order would leave
        // data with no version marker, tempting a lower binary to
        // mis-parse it.
        self.stamp_version_if_needed()?;
        self.write_store(store, &rows)
    }

    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        let mut rows = self.read_store(store)?;
        if rows.remove(key).is_some() {
            self.write_store(store, &rows)?;
        }
        Ok(())
    }

    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        // Single read-merge-write: apply removed first (so a key in both
        // ends up with the inserted value), then inserts.
        let mut rows = self.read_store(store)?;
        for key in removed {
            rows.remove(key);
        }
        for (key, bytes) in inserts {
            let value: Value = serde_json::from_slice(bytes)
                .map_err(|e| PersistError::Serde(format!("decode row value: {e}")))?;
            rows.insert(key.clone(), value);
        }
        // Stamp version BEFORE writing data. See put_row.
        self.stamp_version_if_needed()?;
        self.write_store(store, &rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> temp_dir::TempDir {
        temp_dir::TempDir::new().expect("tempdir")
    }

    #[test]
    fn fresh_open_does_not_create_version_file() {
        // Opening a brand-new directory must not write the version
        // file. That keeps the dir compatible with older binaries
        // until we actually write data.
        let d = tmp_dir();
        let _b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        assert!(
            !d.path().join(VERSION_FILENAME).exists(),
            "version file should be absent on fresh open"
        );
    }

    #[test]
    fn read_only_ops_do_not_stamp_version() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        assert!(b.get_row("coins", "nope").unwrap().is_none());
        assert!(b.get_rows("coins").unwrap().is_empty());
        assert!(
            !d.path().join(VERSION_FILENAME).exists(),
            "read-only ops must not stamp"
        );
    }

    #[test]
    fn delete_only_does_not_stamp_version() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.delete_row("coins", "missing").unwrap();
        assert!(
            !d.path().join(VERSION_FILENAME).exists(),
            "delete-only session must not stamp"
        );
    }

    #[test]
    fn first_put_stamps_version() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "a", b"1").unwrap();
        let v = fs::read_to_string(d.path().join(VERSION_FILENAME)).unwrap();
        assert_eq!(v.trim(), DB_VERSION.to_string());
    }

    #[test]
    fn unknown_store_rejected() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        for bad in ["../escape", "", "coins; rm -rf", "transaciton"] {
            match b.put_row(bad, "a", b"1").unwrap_err() {
                PersistError::UnknownStore { found } => assert_eq!(found, bad),
                other => panic!("expected UnknownStore for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn first_flush_batch_stamps_version() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.flush_batch("coins", &[("a".to_string(), b"1".to_vec())], &[])
            .unwrap();
        let v = fs::read_to_string(d.path().join(VERSION_FILENAME)).unwrap();
        assert_eq!(v.trim(), DB_VERSION.to_string());
    }

    #[test]
    fn open_refuses_newer_version() {
        let d = tmp_dir();
        fs::create_dir_all(d.path()).unwrap();
        fs::write(
            d.path().join(VERSION_FILENAME),
            format!("{}\n", DB_VERSION + 1),
        )
        .unwrap();
        match JsonBackend::open(d.path().to_path_buf()) {
            Err(PersistError::DbVersionTooNew {
                found,
                max_supported,
            }) => {
                assert_eq!(found, DB_VERSION + 1);
                assert_eq!(max_supported, DB_VERSION);
            }
            other => panic!("expected DbVersionTooNew, got {other:?}"),
        }
    }

    #[test]
    fn put_and_load_row() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "a", b"1").unwrap();
        assert_eq!(b.get_row("coins", "a").unwrap(), Some(b"1".to_vec()));
    }

    #[test]
    fn missing_row_returns_none() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        assert!(b.get_row("coins", "missing").unwrap().is_none());
    }

    #[test]
    fn load_rows_iterates_in_key_order() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "b", b"2").unwrap();
        b.put_row("coins", "a", b"1").unwrap();
        let rows = b.get_rows("coins").unwrap();
        assert_eq!(
            rows,
            vec![
                ("a".to_string(), b"1".to_vec()),
                ("b".to_string(), b"2".to_vec()),
            ]
        );
    }

    #[test]
    fn delete_row_removes_it() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "a", b"1").unwrap();
        b.put_row("coins", "b", b"2").unwrap();
        b.delete_row("coins", "a").unwrap();
        let rows = b.get_rows("coins").unwrap();
        assert_eq!(rows, vec![("b".to_string(), b"2".to_vec())]);
    }

    #[test]
    fn flush_batch_applies_inserts_and_removed() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "a", b"1").unwrap();
        b.put_row("coins", "b", b"2").unwrap();
        // Remove a + b; insert c.
        b.flush_batch(
            "coins",
            &[("c".to_string(), b"3".to_vec())],
            &["a".to_string(), "b".to_string()],
        )
        .unwrap();
        let rows = b.get_rows("coins").unwrap();
        assert_eq!(rows, vec![("c".to_string(), b"3".to_vec())]);
    }

    #[test]
    fn store_file_is_human_readable() {
        let d = tmp_dir();
        let b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        b.put_row("coins", "abc", br#"{"amount":10000}"#).unwrap();
        let text = fs::read_to_string(b.path_for("coins")).unwrap();
        assert!(
            text.contains("\"amount\"") && text.contains("10000"),
            "file should contain the inlined value, got: {text}"
        );
    }

    #[test]
    fn second_open_on_same_dir_returns_already_open() {
        let d = tmp_dir();
        let _held = JsonBackend::open(d.path().to_path_buf()).unwrap();
        match JsonBackend::open(d.path().to_path_buf()) {
            Err(PersistError::AlreadyOpen { path }) => {
                assert_eq!(path, d.path().join(".lock"));
            }
            other => panic!("expected AlreadyOpen, got {other:?}"),
        }
    }

    #[test]
    fn reopen_after_drop_succeeds() {
        let d = tmp_dir();
        {
            let _b = JsonBackend::open(d.path().to_path_buf()).unwrap();
        } // <- lock dropped here
          // Second open on the same dir must succeed once the first
          // has released the lock.
        let _b2 = JsonBackend::open(d.path().to_path_buf()).expect("reopen");
    }
}
