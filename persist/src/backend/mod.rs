//! Backend layer: byte-level KV persistence.
//!
//! A [`PersistenceBackend`] is the narrow interface that every concrete
//! on-disk (or no-op) store implements. Its rows are opaque bytes; the
//! typed [`Store`](crate::storage::Store) layer (in [`crate::storage`]) sits on
//! top and handles encoding.
//!
//! Concrete backends ship in their own submodule:
//! - [`NoopBackend`](noop::NoopBackend): discards all writes, reads as absent.
//! - [`JsonBackend`](json::JsonBackend): one JSON file per store inside a directory.
//! - [`HeaderBackend`](headers::HeaderBackend): one binary fixed-record file
//!   for validated headers.
//! - [`SqliteBackend`](sqlite::SqliteBackend): a single SQLite file per
//!   account (requires the `sqlite` Cargo feature).

use std::sync::Arc;

use crate::{PersistError, KNOWN_STORES};

mod lock;

pub mod headers;
pub mod json;
pub mod noop;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Trait abstracting where a store's rows live.
///
/// Every store is a set of `(key, value)` rows. `value` is always
/// opaque bytes (serde-encoded by the caller). Stores are identified by
/// a `store` name (e.g. `"coins"`, `"transactions"`, `"account"`).
///
/// Callers work at row granularity via [`put_row`](Self::put_row),
/// [`delete_row`](Self::delete_row), [`get_row`](Self::get_row), and
/// [`get_rows`](Self::get_rows). For batched writes (typical for stores
/// flushing a set of dirty / removed entries in one shot), use
/// [`flush_batch`](Self::flush_batch). Its default impl loops the row
/// primitives, but backends override it when they can do better (e.g.
/// [`JsonBackend`](json::JsonBackend) rewrites the per-store file in one I/O; the SQLite
/// impl folds every row into a single transaction).
pub trait PersistenceBackend: Send + Sync + std::fmt::Debug {
    /// Reject `store` names that aren't in [`KNOWN_STORES`].
    ///
    /// Backend impls call this at the top of every op. The default
    /// check prevents caller typos from silently creating new tables
    /// (SQLite) or new files (JSON), and closes the SQL-injection /
    /// path-traversal surfaces that a raw `&str` would open.
    fn validate_store_name(&self, store: &str) -> Result<(), PersistError> {
        if KNOWN_STORES.contains(&store) {
            Ok(())
        } else {
            Err(PersistError::UnknownStore {
                found: store.to_string(),
            })
        }
    }

    /// Read one row from `store`. Returns `Ok(None)` if absent.
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError>;

    /// Read all rows of `store`. Returns an empty vector if the store
    /// has never been written or is empty.
    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError>;

    /// Insert a row into `store`, or overwrite its `value` if the `key`
    /// already exists (KV-store "put" semantics).
    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError>;

    /// Delete one row inside `store`. No-op if absent.
    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError>;

    /// Apply a batch of `inserts` (put) and `removed` (delete) in one
    /// shot.
    ///
    /// The default impl calls `delete_row` for each removed key then
    /// `put_row` for each insert. Backends override this when they can
    /// amortise the calls (single file I/O for JSON, single transaction
    /// for SQLite).
    ///
    /// `removed` is applied before `inserts`, so a key appearing in both
    /// lists ends up with the inserted value.
    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        self.validate_store_name(store)?;
        for key in removed {
            self.delete_row(store, key)?;
        }
        for (key, bytes) in inserts {
            self.put_row(store, key, bytes)?;
        }
        Ok(())
    }
}

// Blanket impl so any smart pointer to a backend (notably
// `Arc<dyn PersistenceBackend>` and `Arc<ConcreteBackend>`) satisfies
// the bound: callers hold `Arc<B>` when several stores share one
// backend instance and never reach for `dyn` unless they opt in.
impl<T: PersistenceBackend + ?Sized> PersistenceBackend for Arc<T> {
    fn validate_store_name(&self, store: &str) -> Result<(), PersistError> {
        (**self).validate_store_name(store)
    }
    fn get_row(&self, store: &str, key: &str) -> Result<Option<Vec<u8>>, PersistError> {
        (**self).get_row(store, key)
    }
    fn get_rows(&self, store: &str) -> Result<Vec<(String, Vec<u8>)>, PersistError> {
        (**self).get_rows(store)
    }
    fn put_row(&self, store: &str, key: &str, bytes: &[u8]) -> Result<(), PersistError> {
        (**self).put_row(store, key, bytes)
    }
    fn delete_row(&self, store: &str, key: &str) -> Result<(), PersistError> {
        (**self).delete_row(store, key)
    }
    fn flush_batch(
        &self,
        store: &str,
        inserts: &[(String, Vec<u8>)],
        removed: &[String],
    ) -> Result<(), PersistError> {
        (**self).flush_batch(store, inserts, removed)
    }
}
