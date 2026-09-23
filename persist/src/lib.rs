//! Persistence backend abstraction for bwk.
//!
//! Stores (tx, label, coin, scan state, etc.) in `bwk` and `bwk-sp` do not
//! write files themselves. They hand their serialized bytes to a
//! [`PersistenceBackend`]. The main backends are:
//!
//! - [`JsonBackend`]: one JSON file per store inside a directory.
//! - [`HeaderBackend`](backend::headers::HeaderBackend): one binary
//!   fixed-record file for the validated header chain.
//! - [`SqliteBackend`]: a single SQLite file per account, behind the
//!   `sqlite` Cargo feature.
//!
//! [`NoopBackend`] replaces the old `persist: bool = false` escape hatch.
//!
//! The typed, cache-or-no-cache [`Store`](storage::Store) trait sits on top of a
//! backend; [`RamStore`](storage::ram::RamStore) is the RAM-cached + write-back reference
//! implementation.
//!
//! [`PersistenceKind`] and [`build_backend`] close the surface: config
//! picks `Json` / `Sqlite`, the factory hands back the concrete
//! backend wrapped in an `Arc<dyn PersistenceBackend>`.
//!
//! # The DB is always a pure key-value store
//!
//! Both on-disk layouts are treated as opaque key-value stores. Each
//! store has rows keyed by a primary-key string (`key`) with a BLOB value
//! holding serde-encoded bytes. There are **no typed columns, no
//! relational structure, no schema migrations**, ever.
//!
//! The reason this is safe: bwk holds the whole account state in RAM at
//! runtime. The DB is only a persistence medium, never a query layer;
//! lookups happen in-memory, so the DB gains nothing from typed columns
//! or indexes. Format evolution is handled entirely in Rust code:
//!
//! - **Reads** support multiple parse paths (backward-compatible
//!   deserialization of older byte formats).
//! - **Writes** always emit the latest format.
//!
//! No `ALTER TABLE`, no versioned SQL migrations. If a write-format
//! change would break older binaries, bump [`DB_VERSION`]; any DB whose
//! recorded version is greater than the running binary's [`DB_VERSION`]
//! is refused at [`SqliteBackend::open`] / [`JsonBackend::open`] time
//! with a [`PersistError::DbVersionTooNew`].
//!
//! Backends MUST:
//! - Record the current [`DB_VERSION`] the first time they initialise
//!   a fresh account directory / sqlite file.
//! - On subsequent opens, read the recorded version and refuse to
//!   proceed if it's greater than [`DB_VERSION`] in the running binary.

use std::sync::Arc;

#[cfg(feature = "sqlite")]
use crate::backend::sqlite::SqliteBackend;
use crate::backend::{json::JsonBackend, noop::NoopBackend, PersistenceBackend};

pub mod backend;
pub mod config_store;
pub mod storage;

/// Monotonic integer stamped into every persistence medium (both JSON
/// and SQLite) by the running binary.
///
/// Bump this only when introducing a write-format that older binaries
/// cannot parse. A DB whose recorded version is greater than the
/// running binary's `DB_VERSION` is refused at open time.
pub const DB_VERSION: u32 = 1;

/// Logical store name used for account-scoped singleton fields.
///
/// Every persistence medium has an `account` store that holds the
/// DB version row plus the flat scalar fields of whatever singleton
/// struct the account type owns (`Tip` for bwk accounts,
/// `ScanState` for bwk-sp accounts).
pub const ACCOUNT_STORE_KEY: &str = "account";

/// Logical store name for the bwk (Electrum) transaction store.
///
/// Named `transactions.v2` to break the on-disk format when `TxEntry`
/// gained the `Inclusion` enum (replacing `height` / `merkle`). Old
/// `transactions.json` files are simply not read; no migration is
/// performed.
pub const TRANSACTIONS_STORE_KEY: &str = "transactions.v2";

/// Logical store name for user-facing labels (used by both bwk and bwk-sp).
pub const LABELS_STORE_KEY: &str = "labels";

/// Logical store name for the bwk (Electrum) per-address subscription-status map.
pub const STATUSES_STORE_KEY: &str = "statuses";

/// Logical store name for the bwk-sp (silent-payment) coin store.
pub const COINS_STORE_KEY: &str = "coins";

/// Logical store name for the bwk-sp (silent-payment) transaction store.
pub const TXS_STORE_KEY: &str = "txs";

/// Logical store name for the bwk validated header chain.
///
/// The header chain uses a binary fixed-record cache keyed by block height.
/// Domain code still reaches it through the typed [`Store`](storage::Store) layer; the
/// binary layout is isolated inside [`HeaderBackend`](backend::headers::HeaderBackend).
pub const HEADERS_STORE_KEY: &str = "headers";

/// The complete set of logical store names the bwk ecosystem uses.
///
/// [`PersistenceBackend::validate_store_name`] consults this list to
/// reject typos and arbitrary caller-supplied strings (which would
/// otherwise become a SQL-injection surface for a SQLite backend and
/// a path-traversal surface for a JSON backend).
pub const KNOWN_STORES: &[&str] = &[
    ACCOUNT_STORE_KEY,
    TRANSACTIONS_STORE_KEY,
    LABELS_STORE_KEY,
    STATUSES_STORE_KEY,
    COINS_STORE_KEY,
    TXS_STORE_KEY,
    HEADERS_STORE_KEY,
];

/// Row key in the `account` store holding the stamped [`DB_VERSION`].
pub const VERSION_ROW_KEY: &str = "version";

/// Errors returned by [`PersistenceBackend`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistError {
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("sqlite error: {0}")]
    Sqlite(String),
    #[error("sqlite support disabled: rebuild with feature `sqlite`")]
    SqliteDisabled,
    /// Caller passed a `store` name that isn't in [`KNOWN_STORES`].
    #[error("unknown store {found:?} (expected one of {:?})", KNOWN_STORES)]
    UnknownStore { found: String },
    /// The persistence medium was written by a newer binary (recorded
    /// DB version is greater than [`DB_VERSION`]). We refuse to open
    /// for fear of truncating data whose shape we don't understand.
    #[error("persistence file is at version {found} but this binary only supports up to {max_supported}")]
    DbVersionTooNew { found: u32, max_supported: u32 },
    /// Another process (or another instance in this process) already
    /// holds the advisory lock on the account directory. Callers
    /// should surface this to the user rather than retry silently:
    /// wallet state has a single owner.
    #[error("account directory {path:?} is already opened by another instance")]
    AlreadyOpen { path: std::path::PathBuf },
}

/// How a wallet config wants its account-scoped data persisted.
///
/// `Json` (default) keeps each store in its own `{store}.json` file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PersistenceKind {
    #[default]
    Json,
    Sqlite,
}

/// Build a concrete backend from `(kind, account_dir)`.
///
/// - `None` -> [`NoopBackend`] (persistence disabled).
/// - `Some(Json)` -> [`JsonBackend`] rooted at `account_dir` (opened
///   with a version check).
/// - `Some(Sqlite)` -> [`SqliteBackend`] at `{account_dir}/account.sqlite`.
///   Returns [`PersistError::SqliteDisabled`] when the `sqlite` feature is
///   off.
pub fn build_backend(
    kind: Option<PersistenceKind>,
    account_dir: std::path::PathBuf,
) -> Result<Arc<dyn PersistenceBackend>, PersistError> {
    match kind {
        None => Ok(Arc::new(NoopBackend)),
        Some(PersistenceKind::Json) => Ok(Arc::new(JsonBackend::open(account_dir)?)),
        Some(PersistenceKind::Sqlite) => {
            #[cfg(feature = "sqlite")]
            {
                let mut path = account_dir;
                path.push("account.sqlite");
                Ok(Arc::new(SqliteBackend::open(path)?))
            }
            #[cfg(not(feature = "sqlite"))]
            {
                let _ = account_dir;
                Err(PersistError::SqliteDisabled)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_kind_default_is_json() {
        assert_eq!(PersistenceKind::default(), PersistenceKind::Json);
    }

    #[test]
    fn persistence_kind_serde_roundtrip() {
        let json = serde_json::to_string(&PersistenceKind::Json).unwrap();
        assert_eq!(json, "\"json\"");
        let sqlite = serde_json::to_string(&PersistenceKind::Sqlite).unwrap();
        assert_eq!(sqlite, "\"sqlite\"");
        let back: PersistenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, PersistenceKind::Json);
    }

    #[test]
    fn signers_store_name_is_rejected() {
        // bwk has no persistence path for signer material; "signers" must
        // be genuinely gone from KNOWN_STORES, not merely unused.
        let backend = NoopBackend;
        assert_eq!(
            backend.validate_store_name("signers"),
            Err(PersistError::UnknownStore {
                found: "signers".to_string()
            })
        );
    }
}
