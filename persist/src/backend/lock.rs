//! Per-datadir advisory file lock.
//!
//! [`JsonBackend`](crate::backend::json::JsonBackend) and
//! [`SqliteBackend`](crate::backend::sqlite::SqliteBackend) acquire a [`DirLock`] at
//! open time so a second process (or a second in-process opener)
//! can't share the same account directory. Wallet state has exactly
//! one owner; racing scanners / tip updates / store flushes corrupt
//! invariants even when the byte-level I/O itself is atomic.
//! [`HeaderBackend`](crate::backend::headers::HeaderBackend) reuses the same lock via a
//! per-file sentinel (`{file}.lock`) rather than the directory `.lock`,
//! since its cache file lives inside an account dir a `JsonBackend`
//! already locks.
//!
//! The lock is an OS-level advisory lock (`flock` on POSIX,
//! `LockFileEx` on Windows) on a sentinel file `{dir}/.lock`. The
//! kernel releases it automatically when the holding process exits,
//! so there is no stale-lock recovery path.
//!
//! The `.lock` filename is reserved; it starts with a dot and is
//! not a member of [`KNOWN_STORES`](crate::KNOWN_STORES), so
//! `validate_store_name` cannot collide with it.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::PersistError;

/// Name of the sentinel file holding the advisory lock.
pub(crate) const LOCK_FILENAME: &str = ".lock";

/// An exclusive advisory lock on `{dir}/.lock`.
///
/// Dropping the `DirLock` closes the underlying `File` handle, which
/// the OS treats as an implicit unlock. Crashes release the lock
/// the same way (kernel cleans up fds on process exit).
#[derive(Debug)]
pub(crate) struct DirLock {
    // Held for the Drop-time fd close, which is what releases the
    // advisory lock. The field name starts with `_` to document that
    // it is intentionally inert at the Rust level.
    _file: File,
}

impl DirLock {
    /// Acquire an exclusive advisory lock on `{dir}/.lock`, creating
    /// the sentinel file if it doesn't exist. Non-blocking: returns
    /// [`PersistError::AlreadyOpen`] if another holder has it.
    pub(crate) fn acquire(dir: &Path) -> Result<Self, PersistError> {
        Self::acquire_path(dir.join(LOCK_FILENAME))
    }

    /// Acquire an exclusive advisory lock on an explicit sentinel `path`.
    /// Used by backends whose file lives inside a directory another backend
    /// already locks, so they need a per-file sentinel instead of the shared
    /// `{dir}/.lock`. Same non-blocking semantics as [`acquire`](Self::acquire).
    pub(crate) fn acquire_path(path: PathBuf) -> Result<Self, PersistError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| PersistError::Io(format!("open lock {}: {e}", path.display())))?;
        file.try_lock_exclusive().map_err(|e| {
            // fs2 surfaces WouldBlock when the lock is already held
            // elsewhere. Any other error is a real I/O failure.
            if e.kind() == std::io::ErrorKind::WouldBlock {
                PersistError::AlreadyOpen { path }
            } else {
                PersistError::Io(format!("flock {}: {e}", path.display()))
            }
        })?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_then_release_allows_second_acquire() {
        let d = temp_dir::TempDir::new().unwrap();
        {
            let _lock = DirLock::acquire(d.path()).unwrap();
        } // <- lock dropped
          // Second acquire on the same dir must succeed now that the
          // first one has released its fd.
        let _lock2 = DirLock::acquire(d.path()).unwrap();
    }

    #[test]
    fn second_acquire_while_held_returns_already_open() {
        let d = temp_dir::TempDir::new().unwrap();
        let _held = DirLock::acquire(d.path()).expect("first acquire");
        match DirLock::acquire(d.path()) {
            Err(PersistError::AlreadyOpen { path }) => {
                assert_eq!(path, d.path().join(LOCK_FILENAME));
            }
            other => panic!("expected AlreadyOpen, got {other:?}"),
        }
    }

    #[test]
    fn acquire_creates_sentinel_file() {
        let d = temp_dir::TempDir::new().unwrap();
        let _lock = DirLock::acquire(d.path()).unwrap();
        assert!(
            d.path().join(LOCK_FILENAME).exists(),
            ".lock sentinel must exist after acquire"
        );
    }
}
