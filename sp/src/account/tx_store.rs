//! Transaction store for Silent Payment transactions.
//!
//! Generic wrapper around any `Store<Key = Txid, Value = SpTxEntry>`.

use std::{collections::HashSet, str::FromStr, sync::Arc};

use bitcoin::{Transaction, Txid};
use bwk::{
    bwk_electrum::profile::DefaultBackend,
    persist::{
        backend::{noop::NoopBackend, PersistenceBackend},
        storage::{ram::RamStore, Store},
        PersistError,
    },
};

use crate::profile::{SpRamProfile, SpStorageProfile};
use serde::{Deserialize, Serialize};

pub const STORE_KEY: &str = bwk::persist::TXS_STORE_KEY;

/// A transaction entry in the store.
///
/// Carries the full tx, confirmation height/time, fee, and label for txs the
/// wallet knows about. Direction and amount are NOT stored: they are derived by
/// the generic history aggregator from coin ownership across accounts, so the
/// change of a send nets out automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpTxEntry {
    pub txid: Txid,
    pub tx: Option<Transaction>,
    pub fee: Option<u64>,
    pub height: Option<u32>,
    pub timestamp: Option<u64>,
    pub label: Option<String>,
    /// SP-owned outputs derived when recording an outgoing send. Lets the
    /// history aggregator net the send amount while unconfirmed, before the
    /// block scan records the coins.
    pub change: u64,
}

impl SpTxEntry {
    pub fn new(txid: Txid) -> Self {
        Self {
            txid,
            tx: None,
            fee: None,
            height: None,
            timestamp: None,
            label: None,
            change: 0,
        }
    }
    pub fn with_tx(txid: Txid, tx: Transaction) -> Self {
        Self {
            txid,
            tx: Some(tx),
            fee: None,
            height: None,
            timestamp: None,
            label: None,
            change: 0,
        }
    }
    pub fn txid(&self) -> &Txid {
        &self.txid
    }
    pub fn tx(&self) -> Option<&Transaction> {
        self.tx.as_ref()
    }
    pub fn fee(&self) -> Option<u64> {
        self.fee
    }
    pub fn height(&self) -> Option<u32> {
        self.height
    }
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }
    pub fn label(&self) -> Option<&String> {
        self.label.as_ref()
    }
    pub fn is_confirmed(&self) -> bool {
        self.height.is_some()
    }
}

pub fn encode_txid(k: &Txid) -> String {
    k.to_string()
}
pub fn decode_txid(s: &str) -> Result<Txid, PersistError> {
    Txid::from_str(s).map_err(|e| PersistError::Serde(format!("bad Txid pk {s:?}: {e}")))
}
pub fn encode_entry(v: &SpTxEntry) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode SpTxEntry: {e}")))
}
pub fn decode_entry(bytes: &[u8]) -> Result<SpTxEntry, PersistError> {
    serde_json::from_slice(bytes).map_err(|e| PersistError::Serde(format!("decode SpTxEntry: {e}")))
}

/// Storage for silent-payment transactions. Generic over any
/// `S: Store<Key = Txid, Value = SpTxEntry>`.
pub struct SpTxStore<P: SpStorageProfile = SpRamProfile<DefaultBackend>> {
    store: P::SpTxStore,
}

impl<P: SpStorageProfile> std::fmt::Debug for SpTxStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpTxStore")
            .field("len", &self.store.len().ok())
            .finish()
    }
}

impl SpTxStore<SpRamProfile<DefaultBackend>> {
    pub fn new() -> Self {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        Self {
            store: RamStore::empty(backend, STORE_KEY, encode_txid, encode_entry),
        }
    }

    pub fn with_backend(backend: Arc<dyn PersistenceBackend>, store_key: &'static str) -> Self {
        Self {
            store: RamStore::empty(backend, store_key, encode_txid, encode_entry),
        }
    }

    pub fn load_from_backend(
        backend: Arc<dyn PersistenceBackend>,
        store_key: &'static str,
    ) -> Result<Self, PersistError> {
        let store = RamStore::open(
            backend,
            store_key,
            encode_txid,
            decode_txid,
            encode_entry,
            decode_entry,
        )?;
        Ok(Self { store })
    }
}

impl Default for SpTxStore<SpRamProfile<DefaultBackend>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: SpStorageProfile> SpTxStore<P> {
    pub fn from_store(store: P::SpTxStore) -> Self {
        Self { store }
    }

    pub fn get(&self, txid: &Txid) -> Option<SpTxEntry> {
        self.store.get(txid).ok().flatten()
    }

    pub fn insert(&mut self, entry: SpTxEntry) {
        let txid = entry.txid;
        if let Err(e) = self.store.insert(txid, entry) {
            log::error!("SpTxStore::insert: {e}");
        }
    }

    pub fn remove(&mut self, txid: &Txid) -> Option<SpTxEntry> {
        self.store.remove(txid).unwrap_or_default()
    }

    pub fn update_height(&mut self, txid: &Txid, height: Option<u32>) {
        if let Err(e) = self.store.modify(txid, |entry| entry.height = height) {
            log::error!("SpTxStore::update_height: {e}");
        }
    }

    pub fn update_timestamp(&mut self, txid: &Txid, timestamp: u64) {
        if let Err(e) = self
            .store
            .modify(txid, |entry| entry.timestamp = Some(timestamp))
        {
            log::error!("SpTxStore::update_timestamp: {e}");
        }
    }

    pub fn update_label(&mut self, txid: &Txid, label: String) {
        if let Err(e) = self.store.modify(txid, |entry| entry.label = Some(label)) {
            log::error!("SpTxStore::update_label: {e}");
        }
    }

    /// Undo the confirmations above `fork_height`: a tx in `pending` (still
    /// spending a coin of the wallet) goes back to unconfirmed, any other is
    /// dropped.
    pub fn roll_back(&mut self, fork_height: u32, pending: &HashSet<Txid>) {
        for entry in self.transactions() {
            if entry.height.is_none_or(|h| h <= fork_height) {
                continue;
            }
            if !pending.contains(&entry.txid) {
                self.remove(&entry.txid);
                continue;
            }
            if let Err(e) = self.store.modify(&entry.txid, |entry| {
                entry.height = None;
                entry.timestamp = None;
            }) {
                log::error!("SpTxStore::roll_back: {e}");
            }
        }
    }

    pub fn transactions(&self) -> Vec<SpTxEntry> {
        self.store
            .values()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.store.len().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn persist(&mut self) {
        if let Err(e) = self.store.flush() {
            log::error!("SpTxStore::persist() flush: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bitcoin::{hashes::Hash, Txid};

    use crate::account::tx_store::{SpTxEntry, SpTxStore};

    fn entry_at(n: u8, height: Option<u32>) -> SpTxEntry {
        let mut entry = SpTxEntry::new(Txid::from_byte_array([n; 32]));
        entry.height = height;
        entry.timestamp = height.map(u64::from);
        entry
    }

    #[test]
    fn test_tx_store_roll_back() {
        let mut store = SpTxStore::new();
        store.insert(entry_at(1, Some(100)));
        store.insert(entry_at(2, Some(111)));
        store.insert(entry_at(3, Some(112)));
        store.insert(entry_at(4, None));
        let pending = HashSet::from([Txid::from_byte_array([3; 32])]);

        store.roll_back(110, &pending);

        assert_eq!(store.len(), 3);
        assert!(store.get(&Txid::from_byte_array([2; 32])).is_none());
        let kept = store.get(&Txid::from_byte_array([1; 32])).unwrap();
        assert_eq!(kept.height(), Some(100));
        assert_eq!(kept.timestamp(), Some(100));
        let unconfirmed = store.get(&Txid::from_byte_array([3; 32])).unwrap();
        assert_eq!(unconfirmed.height(), None);
        assert_eq!(unconfirmed.timestamp(), None);
        let mempool = store.get(&Txid::from_byte_array([4; 32])).unwrap();
        assert_eq!(mempool.height(), None);
    }
}
