use std::sync::Arc;

use bwk_persist::{
    backend::{noop::NoopBackend, PersistenceBackend},
    storage::{ram::RamStore, Store},
    PersistError,
};
use miniscript::bitcoin::{self, address::NetworkUnchecked, OutPoint};
use serde::{Deserialize, Serialize};

use crate::profile::{DefaultBackend, RamProfile, ScanProfile};

/// Logical store name used by [`PersistenceBackend`] implementations for
/// the bwk label store.
pub const STORE_KEY: &str = bwk_persist::LABELS_STORE_KEY;

#[derive(Debug, Clone, Serialize, Deserialize, PartialOrd, Ord, Eq, PartialEq, Hash)]
pub enum LabelKey {
    OutPoint(bitcoin::OutPoint),
    Transaction(bitcoin::Txid),
    Address(bitcoin::Address<NetworkUnchecked>),
}

pub fn encode_key(k: &LabelKey) -> String {
    serde_json::to_string(k).expect("LabelKey serialises as JSON")
}
pub fn decode_key(s: &str) -> Result<LabelKey, PersistError> {
    serde_json::from_str(s).map_err(|e| PersistError::Serde(format!("bad LabelKey pk {s:?}: {e}")))
}
pub fn encode_label(v: &String) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode label: {e}")))
}
pub fn decode_label(bytes: &[u8]) -> Result<String, PersistError> {
    serde_json::from_slice(bytes).map_err(|e| PersistError::Serde(format!("decode label: {e}")))
}

/// A store for managing labels. Generic over any [`ScanProfile`];
/// internally wraps the profile's `LabelStore` slot (`P::LabelStore`).
pub struct LabelStore<P: ScanProfile = RamProfile<DefaultBackend>> {
    store: P::LabelStore,
}

impl<P: ScanProfile> std::fmt::Debug for LabelStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabelStore")
            .field("entries", &self.store.len().ok())
            .finish()
    }
}

impl LabelStore<RamProfile<DefaultBackend>> {
    /// Creates a new, empty `LabelStore` with no persistence.
    pub fn new() -> Self {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        LabelStore {
            store: RamStore::empty(backend, STORE_KEY, encode_key, encode_label),
        }
    }

    /// Creates a `LabelStore` that reads and writes through the given
    /// backend, eagerly loading any existing labels.
    ///
    /// Returns the backend error if an existing labels blob fails to
    /// decode, so a corrupt store surfaces to the caller instead of
    /// silently resetting to empty.
    pub fn load_from_backend(
        backend: Arc<dyn PersistenceBackend>,
        store_key: &'static str,
    ) -> Result<Self, PersistError> {
        let store = RamStore::open(
            backend,
            store_key,
            encode_key,
            decode_key,
            encode_label,
            decode_label,
        )?;
        Ok(LabelStore { store })
    }
}

impl Default for LabelStore<RamProfile<DefaultBackend>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ScanProfile> LabelStore<P> {
    /// Wrap any `P::LabelStore` impl produced by the profile.
    pub fn from_store(store: P::LabelStore) -> Self {
        Self { store }
    }

    /// Persists pending changes through the configured backend.
    pub fn persist(&mut self) {
        if let Err(e) = self.try_persist() {
            log::error!("LabelStore::persist() flush: {e}");
        }
    }

    /// Persists pending changes, returning any backend error. With a RAM profile,
    /// failed writes remain in memory and pending for the next call.
    pub fn try_persist(&mut self) -> Result<(), PersistError> {
        self.store.flush()
    }

    /// Retrieves the label associated with the given key (owned clone).
    pub fn get(&self, key: &LabelKey) -> Option<String> {
        self.store.get(key).ok().flatten()
    }

    /// Edits the label associated with the given key.
    pub fn edit(&mut self, key: LabelKey, value: Option<String>) {
        if let Err(e) = self.try_edit(key, value) {
            log::error!("LabelStore::edit: {e}");
        }
    }

    /// Edits or deletes a label without flushing, returning any store error.
    pub fn try_edit(&mut self, key: LabelKey, value: Option<String>) -> Result<(), PersistError> {
        match value {
            Some(v) => self.store.insert(key, v).map(|_| ()),
            None => self.try_remove(key),
        }
    }

    /// Removes the label associated with the given key.
    pub fn remove(&mut self, key: LabelKey) {
        if let Err(e) = self.try_remove(key) {
            log::error!("LabelStore::remove: {e}");
        }
    }

    /// Removes a label without flushing, returning any store error.
    pub fn try_remove(&mut self, key: LabelKey) -> Result<(), PersistError> {
        self.store.remove(&key).map(|_| ())
    }

    /// Retrieves the label associated with the given Bitcoin address.
    pub fn address(&self, address: bitcoin::Address) -> Option<String> {
        self.get(&LabelKey::Address(address.as_unchecked().clone()))
    }

    /// Retrieves the label associated with the given outpoint.
    pub fn outpoint(&self, outpoint: OutPoint) -> Option<String> {
        self.get(&LabelKey::OutPoint(outpoint))
    }

    /// Retrieves the label associated with the given transaction ID.
    pub fn transaction(&self, txid: bitcoin::Txid) -> Option<String> {
        self.get(&LabelKey::Transaction(txid))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use bwk_persist::{backend::json::JsonBackend, PersistError};
    use miniscript::bitcoin::OutPoint;

    use crate::label_store::{LabelKey, LabelStore, STORE_KEY};

    #[test]
    fn failed_label_flush_retains_edits_and_deletions_for_retry() {
        let key = LabelKey::OutPoint(OutPoint::null());

        for value in [Some("new".to_string()), None] {
            let dir = temp_dir::TempDir::new().unwrap();
            let backend = Arc::new(JsonBackend::open(dir.path().to_path_buf()).unwrap());
            let mut store = LabelStore::load_from_backend(backend.clone(), STORE_KEY).unwrap();
            let blocked = backend.path_for(STORE_KEY).with_extension("json.tmp");
            store.try_edit(key.clone(), Some("old".into())).unwrap();
            store.try_persist().unwrap();
            fs::create_dir(&blocked).unwrap();
            store.try_edit(key.clone(), value.clone()).unwrap();
            assert!(matches!(store.try_persist(), Err(PersistError::Io(_))));
            assert_eq!(store.get(&key), value);
            let disk = LabelStore::load_from_backend(backend.clone(), STORE_KEY).unwrap();
            assert_eq!(disk.get(&key).as_deref(), Some("old"));
            drop(disk);
            fs::remove_dir(&blocked).unwrap();
            store.try_persist().unwrap();
            drop(store);
            drop(backend);

            let reopened = Arc::new(JsonBackend::open(dir.path().to_path_buf()).unwrap());
            let store = LabelStore::load_from_backend(reopened, STORE_KEY).unwrap();
            assert_eq!(store.get(&key), value);
        }
    }
}
