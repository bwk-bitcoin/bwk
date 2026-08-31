use miniscript::bitcoin::{self, BlockHash, Txid};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, str::FromStr, sync::Arc};

use bwk_persist::{NoopBackend, PersistError, PersistenceBackend, RamStore, Store};

use crate::{
    coin_store::Update,
    profile::{DefaultBackend, RamProfile, ScanProfile},
};

/// Logical store name used by [`PersistenceBackend`] implementations for
/// the bwk transaction store.
pub const STORE_KEY: &str = bwk_persist::TRANSACTIONS_STORE_KEY;

pub fn encode_txid(k: &Txid) -> String {
    k.to_string()
}
pub fn decode_txid(s: &str) -> Result<Txid, PersistError> {
    Txid::from_str(s).map_err(|e| PersistError::Serde(format!("bad txid pk {s:?}: {e}")))
}
pub fn encode_entry(v: &TxEntry) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode TxEntry: {e}")))
}
pub fn decode_entry(bytes: &[u8]) -> Result<TxEntry, PersistError> {
    serde_json::from_slice(bytes).map_err(|e| PersistError::Serde(format!("decode TxEntry: {e}")))
}

/// Confirmation state of a transaction.
///
/// Tracks the progression from "not seen in any block" to "server claims
/// inclusion at height H" to "we have a verified merkle proof of
/// inclusion at height H". Block hash is carried on the confirmed variants
/// so consumers can reason about which chain the claim or proof refers to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Inclusion {
    /// Mempool tx, or no inclusion info yet.
    Unconfirmed,
    /// Server reported inclusion at `height` in the block identified by
    /// `block_hash`, but we haven't proved it via a merkle branch yet.
    /// Named to mirror [`CoinStatus::ConfirmedUnverified`].
    ConfirmedUnverified { height: u32, block_hash: BlockHash },
    /// We have verified a merkle proof of inclusion at `height` /
    /// `block_hash`. The proof itself is not retained: a reorg re-fetches it.
    Verified { height: u32, block_hash: BlockHash },
    /// A merkle proof for the claim at `height` / `block_hash` was fetched but
    /// failed verification against our stored header. Terminal: not retried
    /// until the stored header hash at `height` changes (a reorg).
    VerifyFailed { height: u32, block_hash: BlockHash },
}

impl Inclusion {
    /// Block height, if confirmed. `VerifyFailed` is not trusted as confirmed,
    /// so it yields `None`.
    pub fn height(&self) -> Option<u32> {
        match self {
            Inclusion::Unconfirmed | Inclusion::VerifyFailed { .. } => None,
            Inclusion::ConfirmedUnverified { height, .. } | Inclusion::Verified { height, .. } => {
                Some(*height)
            }
        }
    }

    /// Block hash, if confirmed. `VerifyFailed` is not trusted as confirmed,
    /// so it yields `None`.
    pub fn block_hash(&self) -> Option<BlockHash> {
        match self {
            Inclusion::Unconfirmed | Inclusion::VerifyFailed { .. } => None,
            Inclusion::ConfirmedUnverified { block_hash, .. }
            | Inclusion::Verified { block_hash, .. } => Some(*block_hash),
        }
    }
}

/// A structure to store Bitcoin transactions indexed by their txids.
///
/// Generic over any [`ScanProfile`]: the wrapper picks up the
/// profile's `TxStore` slot, so today's RAM-backed default is
/// [`RamStore`] via [`RamProfile`] but any other profile plugs in
/// without touching this wrapper or its callers.
pub struct TxStore<P: ScanProfile = RamProfile<DefaultBackend>> {
    store: P::TxStore,
}

impl<P: ScanProfile> Debug for TxStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxStore")
            .field("len", &self.store.len().ok())
            .finish()
    }
}

impl TxStore<RamProfile<DefaultBackend>> {
    /// Creates a `TxStore` with no persistence (in-memory only).
    pub fn new() -> Self {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        Self {
            store: RamStore::empty(backend, STORE_KEY, encode_txid, encode_entry),
        }
    }

    /// Creates a `TxStore` that persists through the given backend and
    /// eagerly loads any existing rows from it.
    pub fn with_backend(
        backend: Arc<dyn PersistenceBackend>,
        store_key: &'static str,
    ) -> Result<Self, PersistError> {
        Ok(Self {
            store: RamStore::open(
                backend,
                store_key,
                encode_txid,
                decode_txid,
                encode_entry,
                decode_entry,
            )?,
        })
    }
}

impl Default for TxStore<RamProfile<DefaultBackend>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ScanProfile> TxStore<P> {
    /// Wrap any `P::TxStore` impl produced by the profile.
    pub fn from_store(store: P::TxStore) -> Self {
        Self { store }
    }

    /// Returns every transaction entry as an owned `Vec`, key-ordered.
    pub fn transactions(&self) -> Vec<TxEntry> {
        self.store
            .values()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    /// Fetch a cloned entry by txid. `None` if absent.
    pub fn get(&self, txid: &Txid) -> Option<TxEntry> {
        self.store.get(txid).ok().flatten()
    }

    /// Number of transactions in the store.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.store.len().unwrap_or(0)
    }

    /// Iterate `(Txid, TxEntry)` pairs, key-ordered.
    pub fn iter(&self) -> Vec<(Txid, TxEntry)> {
        self.store
            .iter()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    /// Inserts updates (only txids not already in the store).
    pub fn insert_updates(&mut self, updates: Vec<Update>) {
        for upd in updates {
            if !upd.is_complete() {
                log::error!("TxStore::insert_updates: skipping incomplete update");
                continue;
            }
            for (txid, tx) in upd.txs {
                match self.store.contains_key(&txid) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => {
                        log::error!("TxStore::insert_updates contains_key: {e}");
                        continue;
                    }
                }
                let Some(tx) = tx else {
                    log::error!("TxStore::insert_updates: missing tx for {txid}");
                    continue;
                };
                let weight = tx.weight().to_wu();
                // NOTE: pending claims move to Inclusion::ConfirmedUnverified
                // once the corresponding block header is available via the
                // HeaderStore pending-claims queue.
                // For now every newly-inserted entry starts Unconfirmed
                // regardless of the server-reported height.
                let entry = TxEntry {
                    tx,
                    inclusion: Inclusion::Unconfirmed,
                    inputs: BTreeMap::new(),
                    outputs: BTreeMap::new(),
                    fees: 0,
                    weight,
                    timestamp: None,
                };
                if let Err(e) = self.store.insert(txid, entry) {
                    log::error!("TxStore::insert_updates insert: {e}");
                }
            }
        }
    }

    /// Updates (or inserts) a transaction entry in the store.
    pub fn update(&mut self, entry: TxEntry) {
        let txid = entry.txid();
        if let Err(e) = self.store.insert(txid, entry) {
            log::error!("TxStore::update insert: {e}");
        }
    }

    /// Retrieves the underlying Bitcoin transaction for a given txid.
    pub fn inner_get(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        self.store.get(txid).ok().flatten().map(|e| e.tx)
    }

    /// Removes a transaction from the store by its transaction ID.
    pub fn remove(&mut self, txid: &Txid) {
        if let Err(e) = self.store.remove(txid) {
            log::error!("TxStore::remove: {e}");
        }
    }

    /// Replaces the inclusion state of a transaction in the store.
    pub fn update_inclusion(&mut self, txid: &Txid, inclusion: Inclusion) {
        // A tx demoted back to unconfirmed (reorg) must drop its stale
        // confirmation time; it is re-stamped from the chain when it reconfirms.
        let clear_timestamp = matches!(inclusion, Inclusion::Unconfirmed);
        match self.store.modify(txid, |e| {
            e.inclusion = inclusion.clone();
            if clear_timestamp {
                e.timestamp = None;
            }
        }) {
            Ok(true) => {}
            // The txid may not be in the store yet: a History response can
            // report a height change for a tx whose body has not arrived via
            // the `Txs` round-trip. It will get the correct inclusion once its
            // entry lands and `resolve_reported_heights` re-claims it, so this
            // is a no-op rather than a panic (which would kill the listener).
            Ok(false) => log::debug!("TxStore::update_inclusion: missing txid {txid}"),
            Err(e) => log::error!("TxStore::update_inclusion: {e}"),
        }
    }

    /// Sets the confirming block time of a transaction, if it is in the store.
    pub fn update_timestamp(&mut self, txid: &Txid, timestamp: u64) {
        match self.store.modify(txid, |e| e.timestamp = Some(timestamp)) {
            Ok(true) => {}
            Ok(false) => log::debug!("TxStore::update_timestamp: missing txid {txid}, skipping"),
            Err(e) => log::error!("TxStore::update_timestamp: {e}"),
        }
    }

    /// Persists pending changes through the configured backend.
    pub fn persist(&mut self) {
        if let Err(e) = self.store.flush() {
            log::error!("TxStore::persist() flush: {e}");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputMetadata {
    pub value: Option<u64>,
    pub owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputMetadata {
    pub owned: bool,
}

/// A structure representing a Bitcoin transaction entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct TxEntry {
    /// Bitcoin tx
    tx: bitcoin::Transaction,
    /// Confirmation / verification state.
    inclusion: Inclusion,
    /// Inputs metadata
    pub inputs: BTreeMap<usize, InputMetadata>,
    /// Outputs metadata
    pub outputs: BTreeMap<usize, OutputMetadata>,
    /// Tx fees in sats
    fees: u64,
    /// Tx weight in wu
    weight: u64,
    /// Block time of the confirming block, when known.
    timestamp: Option<u64>,
}

impl Debug for TxEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxEntry")
            .field("tx", &self.tx.compute_txid())
            .field("inclusion", &self.inclusion)
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .field("fees", &self.fees)
            .field("weight", &self.weight)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl TxEntry {
    /// Test-only constructor that wraps a raw tx in a fully-defaulted
    /// [`TxEntry`], starting `Inclusion::Unconfirmed` like the production
    /// insert path. Tests that need a confirmed entry mutate the inclusion
    /// via [`TxStore::update_inclusion`] after insertion.
    #[cfg(any(test, feature = "test"))]
    pub fn for_test(tx: bitcoin::Transaction) -> Self {
        let weight = tx.weight().to_wu();
        Self {
            tx,
            inclusion: Inclusion::Unconfirmed,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            fees: 0,
            weight,
            timestamp: None,
        }
    }

    /// A just-broadcast, not-yet-confirmed entry: `Inclusion::Unconfirmed`, no
    /// input/output metadata yet (filled by `CoinStore::generate`).
    pub fn unconfirmed(tx: bitcoin::Transaction) -> Self {
        let weight = tx.weight().to_wu();
        Self {
            tx,
            inclusion: Inclusion::Unconfirmed,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            fees: 0,
            weight,
            timestamp: None,
        }
    }

    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }
    /// Block height of this tx, derived from its [`Inclusion`].
    pub fn height(&self) -> Option<u64> {
        self.inclusion.height().map(u64::from)
    }
    /// Block hash of this tx, derived from its [`Inclusion`].
    pub fn block_hash(&self) -> Option<BlockHash> {
        self.inclusion.block_hash()
    }
    pub fn inclusion(&self) -> &Inclusion {
        &self.inclusion
    }
    pub fn tx(&self) -> &bitcoin::Transaction {
        &self.tx
    }
    pub fn fees(&self) -> u64 {
        self.fees
    }
    pub fn set_fees(&mut self, fees: u64) {
        self.fees = fees;
    }
    pub fn weight(&self) -> u64 {
        self.weight
    }
    pub fn timestamp(&self) -> Option<u64> {
        self.timestamp
    }

    pub fn is_complete(&self) -> bool {
        let inputs_filled = self.tx().input.len() == self.inputs.len();
        let outputs_filled = self.tx().output.len() == self.outputs.len();
        inputs_filled && outputs_filled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::{
        absolute::LockTime, transaction::Version, BlockHash, Transaction, TxIn, TxOut,
    };
    use std::str::FromStr;

    fn dummy_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        }
    }

    fn dummy_block_hash() -> BlockHash {
        BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
    }

    fn entry_with(inclusion: Inclusion) -> TxEntry {
        let tx = dummy_tx();
        let weight = tx.weight().to_wu();
        TxEntry {
            tx,
            inclusion,
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            fees: 0,
            weight,
            timestamp: None,
        }
    }

    #[test]
    fn height_accessor_matches_variant() {
        let e = entry_with(Inclusion::Unconfirmed);
        assert_eq!(e.height(), None);

        let e = entry_with(Inclusion::ConfirmedUnverified {
            height: 42,
            block_hash: dummy_block_hash(),
        });
        assert_eq!(e.height(), Some(42));

        let e = entry_with(Inclusion::Verified {
            height: 7,
            block_hash: dummy_block_hash(),
        });
        assert_eq!(e.height(), Some(7));

        let e = entry_with(Inclusion::VerifyFailed {
            height: 7,
            block_hash: dummy_block_hash(),
        });
        assert_eq!(e.height(), None);
    }

    #[test]
    fn block_hash_accessor_matches_variant() {
        let e = entry_with(Inclusion::Unconfirmed);
        assert_eq!(e.block_hash(), None);

        let hash = dummy_block_hash();
        let e = entry_with(Inclusion::ConfirmedUnverified {
            height: 42,
            block_hash: hash,
        });
        assert_eq!(e.block_hash(), Some(hash));

        let e = entry_with(Inclusion::Verified {
            height: 7,
            block_hash: hash,
        });
        assert_eq!(e.block_hash(), Some(hash));

        let e = entry_with(Inclusion::VerifyFailed {
            height: 7,
            block_hash: hash,
        });
        assert_eq!(e.block_hash(), None);
    }

    const DUMMY_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn inclusion_json_round_trip_unconfirmed() {
        let v = Inclusion::Unconfirmed;
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, "\"Unconfirmed\"");
        let back: Inclusion = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn inclusion_json_round_trip_confirmed_unverified() {
        let v = Inclusion::ConfirmedUnverified {
            height: 12_345,
            block_hash: dummy_block_hash(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(
            s,
            format!("{{\"ConfirmedUnverified\":{{\"height\":12345,\"block_hash\":\"{DUMMY_HASH_HEX}\"}}}}")
        );
        let back: Inclusion = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn inclusion_json_round_trip_verified() {
        let v = Inclusion::Verified {
            height: 99,
            block_hash: dummy_block_hash(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(
            s,
            format!("{{\"Verified\":{{\"height\":99,\"block_hash\":\"{DUMMY_HASH_HEX}\"}}}}")
        );
        let back: Inclusion = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn inclusion_json_round_trip_verify_failed() {
        let v = Inclusion::VerifyFailed {
            height: 99,
            block_hash: dummy_block_hash(),
        };
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(
            s,
            format!("{{\"VerifyFailed\":{{\"height\":99,\"block_hash\":\"{DUMMY_HASH_HEX}\"}}}}")
        );
        let back: Inclusion = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn tx_entry_timestamp_round_trips() {
        let mut entry = entry_with(Inclusion::ConfirmedUnverified {
            height: 101,
            block_hash: dummy_block_hash(),
        });
        entry.timestamp = Some(1_700_000_000);
        let bytes = encode_entry(&entry).expect("encode");
        let decoded = decode_entry(&bytes).expect("decode");
        assert_eq!(decoded.height(), Some(101));
        assert_eq!(decoded.timestamp(), Some(1_700_000_000));
    }
}
