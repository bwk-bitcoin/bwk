//! Storage profile for an Electrum scan.
//!
//! A [`ScanProfile`] names the typed stores a scan needs, binding each
//! to a concrete [`Store`] impl. The choice of profile is made at launch
//! time (typically by matching on
//! [`PersistenceKind`](bwk_persist::PersistenceKind)) and stays fixed for
//! the lifetime of the scan.
//!
//! Today's only shipped profile is [`RamProfile<B>`]: every store is a
//! RAM-cached, write-back [`RamStore<B, K, V>`] over some
//! [`PersistenceBackend`]. Future profiles (DB-through, online, LRU, ...)
//! plug in without touching the scan or any caller that works
//! through the `Store` trait.

use std::{marker::PhantomData, sync::Arc};

use bwk_persist::{PersistError, PersistenceBackend, RamStore, Store};
use miniscript::bitcoin::{block::Header, ScriptBuf, Txid};

use crate::{
    config::Tip,
    label_store::{self, LabelKey},
    tx_store::{self, TxEntry},
};

/// Convenient alias for the runtime-dispatched backend variant.
pub type DefaultBackend = Arc<dyn PersistenceBackend>;

/// The typed stores an Electrum scan needs.
///
/// Implementations pick each associated type; the standard
/// [`RamProfile<B>`] binds them all to [`RamStore<B, K, V>`].
pub trait ScanProfile: 'static + Send + Sync {
    type TxStore: Store<Key = Txid, Value = TxEntry> + Send + Sync + 'static;
    type LabelStore: Store<Key = LabelKey, Value = String> + Send + Sync + 'static;
    type HeaderStore: Store<Key = u32, Value = [u8; Header::SIZE]> + Send + Sync + 'static;
    type StatusesStore: Store<Key = ScriptBuf, Value = (Option<String>, u32, u32)>
        + Send
        + Sync
        + 'static;
    type AccountStore: Store<Key = String, Value = Vec<u8>> + Send + Sync + 'static;
}

/// The RAM-cached, write-back profile over any
/// [`PersistenceBackend`].
///
/// The only concrete `ScanProfile` shipped today. Parameterised
/// over the backend type so static-dispatch callers can monomorphise
/// on `SqliteBackend` / `JsonBackend` / `NoopBackend`, and
/// runtime-dispatch callers on `Arc<dyn PersistenceBackend>` via the
/// [`PersistenceBackend` blanket impl for
/// `Arc<T>`](bwk_persist#impl-PersistenceBackend-for-Arc%3CT%3E).
pub struct RamProfile<B: PersistenceBackend = DefaultBackend>(PhantomData<B>);

impl<B: PersistenceBackend> std::fmt::Debug for RamProfile<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RamProfile")
    }
}

impl<B: PersistenceBackend + Clone + 'static> ScanProfile for RamProfile<B> {
    type TxStore = RamStore<B, Txid, TxEntry>;
    type LabelStore = RamStore<B, LabelKey, String>;
    type HeaderStore = RamStore<B, u32, [u8; Header::SIZE]>;
    type StatusesStore = RamStore<B, ScriptBuf, (Option<String>, u32, u32)>;
    type AccountStore = RamStore<B, String, Vec<u8>>;
}

// Statuses encode/decode helpers for the StatusesStore slot.

pub fn encode_status_key(k: &ScriptBuf) -> String {
    serde_json::to_string(k).expect("ScriptBuf serialises as JSON")
}
pub fn decode_status_key(s: &str) -> Result<ScriptBuf, PersistError> {
    serde_json::from_str(s).map_err(|e| PersistError::Serde(format!("bad ScriptBuf pk: {e}")))
}
pub fn encode_status_value(v: &(Option<String>, u32, u32)) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode status: {e}")))
}
pub fn decode_status_value(bytes: &[u8]) -> Result<(Option<String>, u32, u32), PersistError> {
    serde_json::from_slice(bytes).map_err(|e| PersistError::Serde(format!("decode status: {e}")))
}

// Account-store (Tip) encode/decode helpers.

#[allow(clippy::ptr_arg)]
pub fn encode_account_key(k: &String) -> String {
    // Signature must match `fn(&K) -> String` with K = String, hence `&String`.
    k.clone()
}
pub fn decode_account_key(s: &str) -> Result<String, PersistError> {
    Ok(s.to_string())
}
#[allow(clippy::ptr_arg)]
pub fn encode_account_value(v: &Vec<u8>) -> Result<Vec<u8>, PersistError> {
    // Signature must match `fn(&V) -> Result<Vec<u8>, _>` with V = Vec<u8>, hence `&Vec<u8>`.
    Ok(v.clone())
}
pub fn decode_account_value(bytes: &[u8]) -> Result<Vec<u8>, PersistError> {
    Ok(bytes.to_vec())
}

/// Row keys used by [`Tip::persist`] / [`Tip::from_account_store`]
/// inside the `account` store.
pub const TIP_RECEIVE_ROW: &str = "receive_index";
pub const TIP_CHANGE_ROW: &str = "change_index";

impl Tip {
    /// Persist `receive` / `change` into `store` (typically a
    /// [`ScanProfile::AccountStore`]).
    pub fn persist(
        store: &mut impl Store<Key = String, Value = Vec<u8>>,
        receive: u32,
        change: u32,
    ) {
        // Bytes cross the PersistenceBackend boundary, so they must be
        // JSON-parseable for JsonBackend to accept them and keep writing
        // human-readable {store}.json files.
        let enc = |label: &str, v: u32| match serde_json::to_vec(&v) {
            Ok(b) => Some(b),
            Err(e) => {
                log::error!("Tip::persist encode {label}: {e}");
                None
            }
        };
        let Some(recv) = enc(TIP_RECEIVE_ROW, receive) else {
            return;
        };
        let Some(chg) = enc(TIP_CHANGE_ROW, change) else {
            return;
        };
        if let Err(e) = store.insert(TIP_RECEIVE_ROW.to_string(), recv) {
            log::error!("Tip::persist receive: {e}");
            return;
        }
        if let Err(e) = store.insert(TIP_CHANGE_ROW.to_string(), chg) {
            log::error!("Tip::persist change: {e}");
        }
    }

    /// Reconstruct [`Tip`] from the `account` store.
    pub fn from_account_store(store: &impl Store<Key = String, Value = Vec<u8>>) -> Tip {
        let read = |row: &str| -> u32 {
            match store.get(&row.to_string()) {
                Ok(Some(bytes)) => serde_json::from_slice::<u32>(&bytes).unwrap_or_default(),
                _ => 0,
            }
        };
        Tip {
            receive: read(TIP_RECEIVE_ROW),
            change: read(TIP_CHANGE_ROW),
        }
    }
}

/// Convenience bundle used by [`open_ram_stores`] to hand the
/// caller every store opened against the same backend, in one shot.
pub struct RamStores<B: PersistenceBackend + Clone + 'static> {
    pub tx: RamStore<B, Txid, TxEntry>,
    pub label: RamStore<B, LabelKey, String>,
    pub statuses: RamStore<B, ScriptBuf, (Option<String>, u32, u32)>,
    pub account: RamStore<B, String, Vec<u8>>,
}

/// Reopens the statuses store from the backend, the fallback a scanner takes
/// when a panicked listener could not hand its own store back.
pub type ReopenStatuses<P> =
    Arc<dyn Fn() -> Result<<P as ScanProfile>::StatusesStore, PersistError> + Send + Sync>;

/// Profile-generic counterpart of [`RamStores`]: the typed stores a
/// [`ScanProfile`] declares, opened and ready to be handed to
/// [`ElectrumScanner::from_stores`](crate::scanner::ElectrumScanner::from_stores).
pub struct ScanStores<P: ScanProfile> {
    pub tx: P::TxStore,
    pub label: P::LabelStore,
    pub statuses: P::StatusesStore,
    pub account: P::AccountStore,
}

/// Profiles that know how to open their store bundle from a pair of
/// runtime-dispatched [`PersistenceBackend`]s. Required by
/// `ElectrumScanner::try_new` so the constructor can be generic over `P`.
pub trait OpenScanFromBackend:
    ScanProfile<HeaderStore = RamStore<DefaultBackend, u32, [u8; Header::SIZE]>> + Sized
{
    fn open(backend: Arc<dyn PersistenceBackend>) -> Result<ScanStores<Self>, PersistError>;

    /// Reopen just the statuses store from `backend`, the recovery fallback
    /// when a panicked listener thread cannot hand its store back.
    fn open_statuses(
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self::StatusesStore, PersistError>;
}

impl OpenScanFromBackend for RamProfile<DefaultBackend> {
    fn open(backend: Arc<dyn PersistenceBackend>) -> Result<ScanStores<Self>, PersistError> {
        let ram = open_ram_stores(backend)?;
        Ok(ScanStores {
            tx: ram.tx,
            label: ram.label,
            statuses: ram.statuses,
            account: ram.account,
        })
    }

    fn open_statuses(
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self::StatusesStore, PersistError> {
        RamStore::open(
            backend,
            bwk_persist::STATUSES_STORE_KEY,
            encode_status_key,
            decode_status_key,
            encode_status_value,
            decode_status_value,
        )
    }
}

/// Open every `RamStore` a [`RamProfile`]-backed scan needs.
pub fn open_ram_stores<B: PersistenceBackend + Clone + 'static>(
    backend: B,
) -> Result<RamStores<B>, PersistError> {
    Ok(RamStores {
        tx: RamStore::open(
            backend.clone(),
            bwk_persist::TRANSACTIONS_STORE_KEY,
            tx_store::encode_txid,
            tx_store::decode_txid,
            tx_store::encode_entry,
            tx_store::decode_entry,
        )?,
        label: RamStore::open(
            backend.clone(),
            bwk_persist::LABELS_STORE_KEY,
            label_store::encode_key,
            label_store::decode_key,
            label_store::encode_label,
            label_store::decode_label,
        )?,
        statuses: RamStore::open(
            backend.clone(),
            bwk_persist::STATUSES_STORE_KEY,
            encode_status_key,
            decode_status_key,
            encode_status_value,
            decode_status_value,
        )?,
        account: RamStore::open(
            backend,
            bwk_persist::ACCOUNT_STORE_KEY,
            encode_account_key,
            decode_account_key,
            encode_account_value,
            decode_account_value,
        )?,
    })
}

#[cfg(test)]
mod tests {
    //! Regression coverage for the `Tip::persist` / `JsonBackend`
    //! round-trip. Before the fix, `Tip::persist` wrote
    //! `u32::to_le_bytes`, which the JSON backend rejects when it
    //! parses the value as `serde_json::Value`. The tip would silently
    //! stay dirty in the `RamStore` and never hit disk.
    //!
    //! These tests would fail with the pre-fix `Tip::persist` body.
    use super::*;
    use bwk_persist::{JsonBackend, ACCOUNT_STORE_KEY};

    fn open_account_store(
        backend: Arc<dyn PersistenceBackend>,
    ) -> RamStore<Arc<dyn PersistenceBackend>, String, Vec<u8>> {
        RamStore::open(
            backend,
            ACCOUNT_STORE_KEY,
            encode_account_key,
            decode_account_key,
            encode_account_value,
            decode_account_value,
        )
        .expect("open account RamStore")
    }

    #[test]
    fn tip_persist_flush_ok_through_json_backend() {
        // Under the old implementation this flush returned
        // `Err(Serde("decode row value ..."))` because JsonBackend parsed
        // the raw 4 LE bytes as serde_json::Value and rejected them.
        let dir = temp_dir::TempDir::new().expect("tempdir");
        let backend: Arc<dyn PersistenceBackend> =
            Arc::new(JsonBackend::open(dir.path().to_path_buf()).expect("open JsonBackend"));
        let mut store = open_account_store(backend);

        Tip::persist(&mut store, 7, 3);
        store.flush().expect("flush must succeed under JsonBackend");
    }

    #[test]
    fn tip_persist_roundtrip_through_json_backend() {
        // Persist, drop, reopen: the tip values must survive because
        // the flush actually hit disk.
        let dir = temp_dir::TempDir::new().expect("tempdir");

        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(JsonBackend::open(dir.path().to_path_buf()).expect("open JsonBackend"));
            let mut store = open_account_store(backend);
            Tip::persist(&mut store, 42, 19);
            store.flush().expect("flush");
        }

        let backend: Arc<dyn PersistenceBackend> =
            Arc::new(JsonBackend::open(dir.path().to_path_buf()).expect("reopen JsonBackend"));
        let store = open_account_store(backend);
        let tip = Tip::from_account_store(&store);
        assert_eq!(tip.receive, 42);
        assert_eq!(tip.change, 19);
    }

    #[test]
    fn tip_persist_on_disk_file_is_valid_json() {
        // The account-store file must be parseable as JSON and carry
        // the tip rows as JSON numbers: the whole point of JsonBackend
        // is human-readable on-disk files.
        let dir = temp_dir::TempDir::new().expect("tempdir");
        let typed_backend = JsonBackend::open(dir.path().to_path_buf()).expect("open JsonBackend");
        let account_path = typed_backend.path_for(ACCOUNT_STORE_KEY);
        let backend: Arc<dyn PersistenceBackend> = Arc::new(typed_backend);
        let mut store = open_account_store(backend);

        Tip::persist(&mut store, 5, 11);
        store.flush().expect("flush");

        let on_disk = std::fs::read_to_string(&account_path)
            .expect("account store file must exist after flush");
        let parsed: serde_json::Value =
            serde_json::from_str(&on_disk).expect("account store file must be valid JSON");
        assert_eq!(
            parsed.get(TIP_RECEIVE_ROW).and_then(|v| v.as_u64()),
            Some(5),
            "receive_index must be stored as a JSON number, got {on_disk}"
        );
        assert_eq!(
            parsed.get(TIP_CHANGE_ROW).and_then(|v| v.as_u64()),
            Some(11),
            "change_index must be stored as a JSON number, got {on_disk}"
        );
    }

    #[test]
    fn open_statuses_reopens_persisted_rows() {
        // The panic-recovery fallback (`reopen_statuses`, built from
        // `open_statuses`) must reopen the same statuses rows a running listener
        // persisted, so a restart after a lost handback keeps the wallet tracked.
        use miniscript::bitcoin::ScriptBuf;
        let dir = temp_dir::TempDir::new().expect("tempdir");
        let spk = ScriptBuf::from(vec![0x51u8]);
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(JsonBackend::open(dir.path().to_path_buf()).expect("open JsonBackend"));
            let mut store = RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                encode_status_key,
                decode_status_key,
                encode_status_value,
                decode_status_value,
            )
            .expect("open statuses RamStore");
            store
                .insert(spk.clone(), (Some("deadbeef".to_string()), 0, 7))
                .expect("insert status");
            store.flush().expect("flush");
        }

        let backend: Arc<dyn PersistenceBackend> =
            Arc::new(JsonBackend::open(dir.path().to_path_buf()).expect("reopen JsonBackend"));
        let reopened = RamProfile::<DefaultBackend>::open_statuses(backend).expect("open_statuses");
        assert_eq!(
            reopened.get(&spk).expect("get status"),
            Some((Some("deadbeef".to_string()), 0, 7))
        );
    }
}
