//! SQLite persistence backend (single file per account).
//!
//! The schema is deliberately simple: **one table per logical store**,
//! each table with a `("key" TEXT PRIMARY KEY, value BLOB NOT NULL)` shape.
//! The DB is a pure KV store. See the crate-level docs for the "no
//! relational structure, no schema migrations" principle.
//!
//! A dedicated `account` table holds the account-scoped singleton
//! fields (e.g. `receive_index`, `change_index` for bwk wallets or
//! `last_scanned_height`, `last_spend_height`, `birthday_height` for
//! silent-payment wallets) plus a `version` row stamped with
//! [`DB_VERSION`].
//!
//! # Version guard
//!
//! At open time we create the `account` table if needed, then read the
//! `version` row:
//! - missing -> fresh DB; stamp [`DB_VERSION`] and continue.
//! - recorded at or below [`DB_VERSION`] -> OK, continue.
//! - recorded > [`DB_VERSION`] -> return
//!   [`PersistError::DbVersionTooNew`] and **do not touch any other
//!   row**; the file was written by a newer binary.
//!
//! # Public surface
//!
//! The public constructor takes only a [`PathBuf`]; the live
//! [`rusqlite::Connection`] is held internally for the backend's
//! lifetime so there is no per-op `sqlite3_open` cost. WAL journaling
//! is enabled on open.
//!
//! Per-store tables are created lazily (`CREATE TABLE IF NOT EXISTS`)
//! on first access.

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use rusqlite::{params, Connection, OptionalExtension};

use super::{lock::DirLock, PersistenceBackend};
use crate::{PersistError, ACCOUNT_STORE_KEY, DB_VERSION, VERSION_ROW_KEY};

/// Encode the current [`DB_VERSION`] as the bytes we stamp into the
/// SQLite `account.version` row (4-byte little-endian).
fn encode_version(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Decode a `account.version` row's bytes back to a `u32`.
fn decode_version(bytes: &[u8]) -> Result<u32, PersistError> {
    let arr: [u8; 4] = bytes.try_into().map_err(|_| {
        PersistError::Serde(format!(
            "decode version: expected 4 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(u32::from_le_bytes(arr))
}

/// SQLite-backed persistence for a single account file.
pub struct SqliteBackend {
    /// Advisory lock on `{parent}/.lock` where `{parent}` is the
    /// directory holding the `.sqlite` file. Kept consistent with
    /// `JsonBackend`'s lock location so the same account dir can't be
    /// opened by both a JSON and a SQLite backend at once either.
    _lock: DirLock,
    conn: Mutex<Connection>,
    /// `true` once the `account.version` row has been observed to equal
    /// [`DB_VERSION`]: either it was already stamped by a previous
    /// session or we've stamped it as part of this session's first
    /// write. While `false`, every mutating op folds a stamp put
    /// into its transaction. Read-only ops never flip this.
    stamped: AtomicBool,
}

impl std::fmt::Debug for SqliteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBackend").finish()
    }
}

impl SqliteBackend {
    /// Open (or create) the SQLite database at `path`.
    ///
    /// Takes an exclusive advisory lock on `{parent}/.lock` before
    /// opening the SQLite connection, so a second opener on the same
    /// account directory fails fast with
    /// [`PersistError::AlreadyOpen`]. SQLite's own WAL locking still
    /// handles byte-level concurrency between threads inside this
    /// process; the DirLock is about process-level ownership of the
    /// whole account dir (including the stamped version row and the
    /// wallet invariants downstream of it).
    ///
    /// Ensures the `account` table exists and runs the DB version
    /// guard: refuses files whose stamped version is greater than
    /// [`DB_VERSION`]. Fresh files are NOT stamped at open time. The
    /// `account.version` row is written lazily by the first mutating
    /// op (see [`Self::stamp_version_if_needed`]). This keeps an
    /// open-but-never-written DB usable by older binaries.
    pub fn open(path: PathBuf) -> Result<Self, PersistError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|e| PersistError::Io(format!("create_dir_all {}: {e}", parent.display())))?;
        let lock = DirLock::acquire(parent)?;
        let conn = Connection::open(&path)
            .map_err(|e| PersistError::Sqlite(format!("open {}: {e}", path.display())))?;
        // Enable Write-Ahead Logging so the background scanner can persist
        // new rows while UI / query threads hold read transactions against
        // the same file. Under the default rollback journal, writers block
        // readers and vice-versa; under WAL they proceed concurrently, at
        // the cost of a sidecar `-wal` / `-shm` file next to the DB.
        let _: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(|e| PersistError::Sqlite(format!("PRAGMA journal_mode=WAL: {e}")))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| PersistError::Sqlite(format!("busy_timeout: {e}")))?;
        create_store_table_maybe(&conn, ACCOUNT_STORE_KEY)?;
        let existing = check_version(&conn)?;
        Ok(Self {
            _lock: lock,
            conn: Mutex::new(conn),
            // If the on-disk version already matches DB_VERSION, skip
            // the stamp put on every subsequent mutating op.
            // Otherwise (absent or older) the next write will stamp.
            stamped: AtomicBool::new(existing == Some(DB_VERSION)),
        })
    }

    fn with_conn<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<R, PersistError>,
    ) -> Result<R, PersistError> {
        let mut g = self
            .conn
            .lock()
            .map_err(|_| PersistError::Sqlite("connection mutex poisoned".into()))?;
        f(&mut g)
    }
}

fn create_store_table_maybe(conn: &Connection, store: &str) -> Result<(), PersistError> {
    // `store` has already been validated by the caller via
    // `<SqliteBackend as PersistenceBackend>::validate_store_name`.
    // Interpolating it into SQL is safe because [`KNOWN_STORES`] only
    // contains ASCII-identifier-shaped constants.
    let sql = format!(
        "CREATE TABLE IF NOT EXISTS \"{store}\" (\"key\" TEXT PRIMARY KEY, value BLOB NOT NULL)"
    );
    conn.execute(&sql, [])
        .map_err(|e| PersistError::Sqlite(format!("create table {store}: {e}")))?;
    Ok(())
}

/// Read-only version guard. Returns the recorded version if the
/// `account.version` row exists, `None` for a fresh DB. Refuses to
/// proceed if the recorded version is greater than [`DB_VERSION`].
///
/// Never mutates the DB. Stamping is deferred to the first actual
/// write; see [`SqliteBackend::stamp_version_if_needed`].
fn check_version(conn: &Connection) -> Result<Option<u32>, PersistError> {
    let found: Option<Vec<u8>> = conn
        .query_row(
            "SELECT value FROM account WHERE \"key\" = ?1",
            params![VERSION_ROW_KEY],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|e| PersistError::Sqlite(format!("read version: {e}")))?;

    match found {
        Some(bytes) => {
            let v = decode_version(&bytes)?;
            if v > DB_VERSION {
                return Err(PersistError::DbVersionTooNew {
                    found: v,
                    max_supported: DB_VERSION,
                });
            }
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

/// Write the version row as part of an in-progress SQLite
/// transaction. Called by `stamp_version_if_needed` on the first
/// mutating op after [`SqliteBackend::open`].
fn stamp_version_in_tx(tx: &rusqlite::Transaction<'_>) -> Result<(), PersistError> {
    tx.execute(
        "INSERT INTO account (\"key\", value) VALUES (?1, ?2) \
         ON CONFLICT(\"key\") DO UPDATE SET value = excluded.value",
        params![VERSION_ROW_KEY, encode_version(DB_VERSION)],
    )
    .map_err(|e| PersistError::Sqlite(format!("stamp version: {e}")))?;
    Ok(())
}

impl PersistenceBackend for SqliteBackend {
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError> {
        self.validate_store_name(store)?;
        self.with_conn(|c| {
            create_store_table_maybe(c, store)?;
            let sql = format!("SELECT value FROM \"{store}\" WHERE \"key\" = ?1");
            c.query_row(&sql, params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PersistError::Sqlite(format!("get_row {store}/{key}: {e}")))
        })
    }

    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        self.validate_store_name(store)?;
        self.with_conn(|c| {
            create_store_table_maybe(c, store)?;
            let sql = format!("SELECT \"key\", value FROM \"{store}\" ORDER BY \"key\"");
            let mut stmt = c
                .prepare(&sql)
                .map_err(|e| PersistError::Sqlite(format!("prepare get_rows {store}: {e}")))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| PersistError::Sqlite(format!("query get_rows {store}: {e}")))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(
                    r.map_err(|e| PersistError::Sqlite(format!("row get_rows {store}: {e}")))?,
                );
            }
            Ok(out)
        })
    }

    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        let needs_stamp = !self.stamped.load(Ordering::Acquire);
        self.with_conn(|c| {
            create_store_table_maybe(c, store)?;
            let tx = c
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| PersistError::Sqlite(format!("begin put_row {store}: {e}")))?;
            if needs_stamp {
                stamp_version_in_tx(&tx)?;
            }
            let sql = format!(
                "INSERT INTO \"{store}\" (\"key\", value) VALUES (?1, ?2) \
                 ON CONFLICT(\"key\") DO UPDATE SET value = excluded.value"
            );
            tx.execute(&sql, params![key, bytes])
                .map_err(|e| PersistError::Sqlite(format!("put_row {store}/{key}: {e}")))?;
            tx.commit()
                .map_err(|e| PersistError::Sqlite(format!("commit put_row {store}: {e}")))?;
            Ok(())
        })?;
        if needs_stamp {
            self.stamped.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        self.with_conn(|c| {
            create_store_table_maybe(c, store)?;
            let sql = format!("DELETE FROM \"{store}\" WHERE \"key\" = ?1");
            c.execute(&sql, params![key])
                .map_err(|e| PersistError::Sqlite(format!("delete_row {store}/{key}: {e}")))?;
            Ok(())
        })
    }

    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        let needs_stamp = !self.stamped.load(Ordering::Acquire);
        self.with_conn(|c| {
            create_store_table_maybe(c, store)?;
            let tx = c
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| PersistError::Sqlite(format!("begin flush_batch {store}: {e}")))?;
            {
                // Version stamp first, so the whole batch commits atomically
                // with the version bump.
                if needs_stamp {
                    stamp_version_in_tx(&tx)?;
                }
                // Deletes before inserts: a key in both lists ends up with
                // the inserted value. Refuse to touch the version row
                // either way: it's backend-owned.
                let delete_sql = format!("DELETE FROM \"{store}\" WHERE \"key\" = ?1");
                for key in removed {
                    if store == ACCOUNT_STORE_KEY && key == VERSION_ROW_KEY {
                        return Err(PersistError::Sqlite(format!(
                            "row {key:?} in store {store:?} is reserved for the backend"
                        )));
                    }
                    tx.execute(&delete_sql, params![key])
                        .map_err(|e| PersistError::Sqlite(format!("delete {store}/{key}: {e}")))?;
                }
                let insert_sql = format!(
                    "INSERT INTO \"{store}\" (\"key\", value) VALUES (?1, ?2) \
                     ON CONFLICT(\"key\") DO UPDATE SET value = excluded.value"
                );
                for (key, bytes) in inserts {
                    if store == ACCOUNT_STORE_KEY && key == VERSION_ROW_KEY {
                        return Err(PersistError::Sqlite(format!(
                            "row {key:?} in store {store:?} is reserved for the backend"
                        )));
                    }
                    tx.execute(&insert_sql, params![key, bytes])
                        .map_err(|e| PersistError::Sqlite(format!("insert {store}/{key}: {e}")))?;
                }
            }
            tx.commit()
                .map_err(|e| PersistError::Sqlite(format!("commit flush_batch {store}: {e}")))
        })?;
        if needs_stamp {
            self.stamped.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_in_dir(dir: &temp_dir::TempDir) -> SqliteBackend {
        SqliteBackend::open(dir.path().join("account.sqlite")).expect("open")
    }

    #[test]
    fn fresh_open_does_not_stamp_version() {
        // Opening a brand-new DB must not write the version row. That
        // keeps the file compatible with older binaries until we
        // actually write data.
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        assert!(
            b.get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
                .unwrap()
                .is_none(),
            "version row should be absent on fresh open"
        );
    }

    #[test]
    fn read_only_ops_do_not_stamp_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        assert!(b.get_row("coins", "nope").unwrap().is_none());
        assert!(b.get_rows("coins").unwrap().is_empty());
        assert!(
            b.get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
                .unwrap()
                .is_none(),
            "read-only ops must not stamp"
        );
    }

    #[test]
    fn delete_only_does_not_stamp_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.delete_row("coins", "missing").unwrap();
        assert!(
            b.get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
                .unwrap()
                .is_none(),
            "delete-only session must not stamp"
        );
    }

    #[test]
    fn first_put_stamps_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.put_row("coins", "a", b"hello").unwrap();
        let v = b
            .get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
            .unwrap()
            .expect("version row present after first put");
        assert_eq!(decode_version(&v).unwrap(), DB_VERSION);
    }

    #[test]
    fn first_flush_batch_stamps_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.flush_batch("coins", &[("a".to_string(), b"1".to_vec())], &[])
            .unwrap();
        let v = b
            .get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
            .unwrap()
            .expect("version row present after first flush_batch");
        assert_eq!(decode_version(&v).unwrap(), DB_VERSION);
    }

    #[test]
    fn open_refuses_newer_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let path = d.path().join("account.sqlite");
        {
            // Stamp a DB_VERSION+1 row by hand (bypassing the backend's
            // mutating API, which would insist on DB_VERSION).
            let b = SqliteBackend::open(path.clone()).unwrap();
            b.with_conn(|c| {
                c.execute(
                    "INSERT INTO account (\"key\", value) VALUES (?1, ?2) \
                     ON CONFLICT(\"key\") DO UPDATE SET value = excluded.value",
                    params![VERSION_ROW_KEY, encode_version(DB_VERSION + 1)],
                )
                .unwrap();
                Ok(())
            })
            .unwrap();
        }
        match SqliteBackend::open(path) {
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
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.put_row("coins", "a", b"hello").unwrap();
        assert_eq!(
            b.get_row("coins", "a").unwrap().as_deref(),
            Some(b"hello".as_ref())
        );
    }

    #[test]
    fn missing_row_returns_none() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        assert!(b.get_row("coins", "nope").unwrap().is_none());
    }

    #[test]
    fn load_rows_orders_by_pk() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
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
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.put_row("coins", "a", b"1").unwrap();
        b.put_row("coins", "b", b"2").unwrap();
        b.delete_row("coins", "a").unwrap();
        let rows = b.get_rows("coins").unwrap();
        assert_eq!(rows, vec![("b".to_string(), b"2".to_vec())]);
    }

    #[test]
    fn flush_batch_applies_inserts_and_removed() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.put_row("coins", "a", b"1").unwrap();
        b.put_row("coins", "b", b"2").unwrap();
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
    fn flush_batch_on_account_preserves_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        b.put_row(ACCOUNT_STORE_KEY, "receive_index", b"0").unwrap();
        b.flush_batch(
            ACCOUNT_STORE_KEY,
            &[
                ("receive_index".to_string(), b"5".to_vec()),
                ("change_index".to_string(), b"3".to_vec()),
            ],
            &[],
        )
        .unwrap();
        // Version row still there.
        let v = b
            .get_row(ACCOUNT_STORE_KEY, VERSION_ROW_KEY)
            .unwrap()
            .unwrap();
        assert_eq!(decode_version(&v).unwrap(), DB_VERSION);
        let rx = b
            .get_row(ACCOUNT_STORE_KEY, "receive_index")
            .unwrap()
            .unwrap();
        assert_eq!(rx, b"5".to_vec());
    }

    #[test]
    fn flush_batch_refuses_to_overwrite_version() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        let err = b
            .flush_batch(
                ACCOUNT_STORE_KEY,
                &[(VERSION_ROW_KEY.to_string(), encode_version(999))],
                &[],
            )
            .unwrap_err();
        assert!(matches!(err, PersistError::Sqlite(_)));
    }

    #[test]
    fn reopen_persists_data() {
        let d = temp_dir::TempDir::new().unwrap();
        let path = d.path().join("account.sqlite");
        {
            let b = SqliteBackend::open(path.clone()).unwrap();
            b.put_row("coins", "a", b"1").unwrap();
        }
        let b2 = SqliteBackend::open(path).unwrap();
        assert_eq!(
            b2.get_row("coins", "a").unwrap().as_deref(),
            Some(b"1".as_ref())
        );
    }

    #[test]
    fn unknown_store_rejected() {
        let d = temp_dir::TempDir::new().unwrap();
        let b = open_in_dir(&d);
        for bad in ["coins; DROP TABLE coins", "", "1coins", "transaciton"] {
            match b.put_row(bad, "a", b"1").unwrap_err() {
                PersistError::UnknownStore { found } => assert_eq!(found, bad),
                other => panic!("expected UnknownStore for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn second_open_on_same_dir_returns_already_open() {
        let d = temp_dir::TempDir::new().unwrap();
        let _held = open_in_dir(&d);
        match SqliteBackend::open(d.path().join("account.sqlite")) {
            Err(PersistError::AlreadyOpen { path }) => {
                assert_eq!(path, d.path().join(".lock"));
            }
            other => panic!("expected AlreadyOpen, got {other:?}"),
        }
    }

    #[test]
    fn reopen_after_drop_succeeds() {
        let d = temp_dir::TempDir::new().unwrap();
        let path = d.path().join("account.sqlite");
        {
            let _b = SqliteBackend::open(path.clone()).unwrap();
        } // <- lock dropped here
          // Second open on the same dir must succeed once the first
          // has released the lock.
        let _b2 = SqliteBackend::open(path).expect("reopen");
    }
}
