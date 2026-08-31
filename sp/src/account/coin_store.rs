//! Coin store for Silent Payment outputs.
//!
//! The `SpCoinStore` manages a collection of `SpCoinEntry` items, which wrap
//! an SPDK-derived `OwnedOutput` data shape with BWK-specific metadata and
//! persistence. This provides a similar interface to bwk's CoinStore but for
//! silent payment outputs.

use std::{
    collections::{BTreeMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use crate::{
    core::receiving::Label,
    profile::{SpRamProfile, SpStorageProfile},
    receiver::{OutputSpendStatus, OwnedOutput},
};
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf};
use bwk::{
    bwk_electrum::profile::DefaultBackend,
    persist::{NoopBackend, PersistError, PersistenceBackend, RamStore, Store},
};
use serde::{Deserialize, Serialize};

/// Logical store name used by [`PersistenceBackend`] implementations for
/// the silent-payment coin store. Re-export of the canonical constant
/// in [`bwk::persist`] so callers keep a single source of truth.
pub const STORE_KEY: &str = bwk::persist::COINS_STORE_KEY;

// SpCoinEntry

/// A silent payment coin entry wrapping an OutPoint and OwnedOutput.
///
/// This is the equivalent of bwk's `CoinEntry` but for silent payment outputs.
/// It provides accessor methods that mirror the bwk API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpCoinEntry {
    /// The outpoint (txid:vout) identifying this UTXO
    outpoint: OutPoint,
    /// SPDK-derived owned output data with BWK-specific metadata.
    output: OwnedOutput,
}

impl SpCoinEntry {
    // Constructors

    /// Create a new coin entry from an outpoint and owned output.
    pub fn new(outpoint: OutPoint, output: OwnedOutput) -> Self {
        Self { outpoint, output }
    } // Getters (accessors)

    /// Returns the block height where this output was confirmed.
    pub fn height(&self) -> u32 {
        self.output.blockheight.to_consensus_u32()
    }

    /// Returns the amount as a bitcoin::Amount.
    pub fn amount(&self) -> Amount {
        self.output.amount
    }

    /// Returns the amount in satoshis.
    pub fn amount_sat(&self) -> u64 {
        self.output.amount.to_sat()
    }

    /// Returns a reference to the output script.
    pub fn script(&self) -> &ScriptBuf {
        &self.output.script
    }

    /// Returns a reference to the outpoint.
    pub fn outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    /// Returns the outpoint as a string in "txid:vout" format.
    pub fn outpoint_str(&self) -> String {
        format!("{}:{}", self.outpoint.txid, self.outpoint.vout)
    }

    /// Returns a reference to the spend status.
    pub fn status(&self) -> &OutputSpendStatus {
        &self.output.spend_status
    }

    /// Returns true if the output is spendable (unspent).
    pub fn is_spendable(&self) -> bool {
        matches!(self.output.spend_status, OutputSpendStatus::Unspent)
    }

    /// Returns a reference to the tweak bytes.
    pub fn tweak(&self) -> &[u8; 32] {
        &self.output.tweak
    }

    /// Returns the SP label if present.
    pub fn label(&self) -> Option<&Label> {
        self.output.label.as_ref()
    }

    /// Returns a reference to the underlying OwnedOutput.
    pub fn owned_output(&self) -> &OwnedOutput {
        &self.output
    }

    /// Returns a mutable reference to the underlying OwnedOutput.
    pub fn owned_output_mut(&mut self) -> &mut OwnedOutput {
        &mut self.output
    }
}

// CoinState

/// Balance summary for the coin store.
///
/// Provides counts and totals for confirmed and unconfirmed coins.
/// For Silent Payments, we only see confirmed outputs, so unconfirmed
/// fields are always zero.
#[derive(Debug, Clone, Default)]
pub struct CoinState {
    /// Map of all spendable coins
    pub coins: BTreeMap<OutPoint, SpCoinEntry>,
    /// Number of confirmed (spendable) coins
    pub confirmed_coins: usize,
    /// Total balance of confirmed coins in satoshis
    pub confirmed_balance: u64,
    /// Number of unconfirmed coins (always 0 for SP)
    pub unconfirmed_coins: usize,
    /// Total balance of unconfirmed coins (always 0 for SP)
    pub unconfirmed_balance: u64,
}

// SpCoinStore

pub fn encode_outpoint(k: &OutPoint) -> String {
    k.to_string()
}
pub fn decode_outpoint(s: &str) -> Result<OutPoint, PersistError> {
    OutPoint::from_str(s).map_err(|e| PersistError::Serde(format!("bad OutPoint pk {s:?}: {e}")))
}
pub fn encode_coin(v: &SpCoinEntry) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode SpCoinEntry: {e}")))
}
pub fn decode_coin(bytes: &[u8]) -> Result<SpCoinEntry, PersistError> {
    serde_json::from_slice(bytes)
        .map_err(|e| PersistError::Serde(format!("decode SpCoinEntry: {e}")))
}

/// Storage for silent payment coins. Generic over any
/// `S: Store<Key = OutPoint, Value = SpCoinEntry>`.
pub struct SpCoinStore<P: SpStorageProfile = SpRamProfile<DefaultBackend>> {
    store: P::CoinStore,
}

impl Default for SpCoinStore<SpRamProfile<DefaultBackend>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: SpStorageProfile> std::fmt::Debug for SpCoinStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpCoinStore")
            .field("len", &self.store.len().ok())
            .finish()
    }
}

impl SpCoinStore<SpRamProfile<DefaultBackend>> {
    pub fn new() -> Self {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        Self {
            store: RamStore::empty(backend, STORE_KEY, encode_outpoint, encode_coin),
        }
    }

    pub fn with_backend(backend: Arc<dyn PersistenceBackend>, store_key: &'static str) -> Self {
        Self {
            store: RamStore::empty(backend, store_key, encode_outpoint, encode_coin),
        }
    }

    pub fn load_from_backend(
        backend: Arc<dyn PersistenceBackend>,
        store_key: &'static str,
    ) -> Result<Self, PersistError> {
        let store = RamStore::open(
            backend,
            store_key,
            encode_outpoint,
            decode_outpoint,
            encode_coin,
            decode_coin,
        )?;
        Ok(Self { store })
    }
}

impl<P: SpStorageProfile> SpCoinStore<P> {
    /// Wrap any `Store<Key = OutPoint, Value = SpCoinEntry>` impl.
    pub fn from_store(store: P::CoinStore) -> Self {
        Self { store }
    }

    /// Get an owned copy of a coin entry by outpoint.
    pub fn get(&self, outpoint: &OutPoint) -> Option<SpCoinEntry> {
        self.store.get(outpoint).ok().flatten()
    }

    /// Insert a new coin entry from an outpoint and owned output.
    pub fn insert(&mut self, outpoint: OutPoint, output: OwnedOutput) {
        let entry = SpCoinEntry::new(outpoint, output);
        if let Err(e) = self.store.insert(outpoint, entry) {
            log::error!("SpCoinStore::insert: {e}");
        }
    }

    pub fn insert_batch(&mut self, outputs: BTreeMap<OutPoint, OwnedOutput>) {
        for (outpoint, output) in outputs {
            self.insert(outpoint, output);
        }
    }

    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<SpCoinEntry> {
        self.store.remove(outpoint).unwrap_or_default()
    }

    pub fn mark_spent(&mut self, outpoint: &OutPoint, spending_txid: [u8; 32]) {
        if let Err(e) = self.store.modify(outpoint, |entry| {
            entry.output.spend_status = OutputSpendStatus::Spent {
                txid: spending_txid,
                block_hash: None,
            };
        }) {
            log::error!("SpCoinStore::mark_spent: {e}");
        }
    }

    /// Mark a spent output as confirmed in `block_hash`. A spend we already know
    /// the txid of (our own broadcast) keeps that txid; a spend first seen by a
    /// scan, with an unknown txid, becomes `Mined`.
    pub fn confirm_spend(&mut self, outpoint: &OutPoint, block_hash: [u8; 32]) {
        if let Err(e) = self.store.modify(outpoint, |entry| {
            entry.output.spend_status = match entry.output.spend_status {
                OutputSpendStatus::Spent { txid, .. } => OutputSpendStatus::Spent {
                    txid,
                    block_hash: Some(block_hash),
                },
                _ => OutputSpendStatus::Mined(block_hash),
            };
        }) {
            log::error!("SpCoinStore::confirm_spend: {e}");
        }
    }

    /// Returns a snapshot of every coin as a fresh `BTreeMap`.
    pub fn coins(&self) -> BTreeMap<OutPoint, SpCoinEntry> {
        self.store
            .iter()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    /// Returns a CoinState with only spendable (unspent) coins.
    pub fn spendable_coins(&self) -> CoinState {
        let mut state = CoinState::default();
        if let Ok(iter) = self.store.iter() {
            for (outpoint, entry) in iter {
                if entry.is_spendable() {
                    state.confirmed_coins += 1;
                    state.confirmed_balance += entry.amount_sat();
                    state.coins.insert(outpoint, entry);
                }
            }
        }
        state
    }

    pub fn all_outpoints(&self) -> HashSet<OutPoint> {
        self.store
            .keys()
            .ok()
            .map(|it| it.collect())
            .unwrap_or_default()
    }

    /// Outpoints whose spend can still be detected on chain, each paired with its
    /// creation height. A coin is watchable while `Unspent` or `Spent { block_hash:
    /// None }` (our own broadcast awaiting confirmation); a confirmed spend
    /// (`Spent { block_hash: Some }` / `Mined`) can never be spent again, so the
    /// spend sweep skips it. This is the sole seed for the sweep's watch set.
    pub fn watchable(&self) -> Vec<(OutPoint, u32)> {
        self.store
            .iter()
            .ok()
            .map(|it| {
                it.filter(|(_, entry)| {
                    matches!(
                        entry.status(),
                        OutputSpendStatus::Unspent
                            | OutputSpendStatus::Spent {
                                block_hash: None,
                                ..
                            }
                    )
                })
                .map(|(outpoint, entry)| (outpoint, entry.height()))
                .collect()
            })
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.store.len().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn balance(&self) -> Amount {
        let sats: u64 = self
            .store
            .values()
            .ok()
            .map(|it| {
                it.filter(|entry| entry.is_spendable())
                    .map(|entry| entry.amount_sat())
                    .sum()
            })
            .unwrap_or(0);
        Amount::from_sat(sats)
    }

    pub fn persist(&mut self) {
        if let Err(e) = self.store.flush() {
            log::error!("SpCoinStore::persist() flush: {e}");
        }
    }

    /// Group SP coins by their tweaked taproot spk and report
    /// status + funding/spending txids per address.
    ///
    /// In normal SP-flow operation each spk appears at most once
    /// (each per-output tweak is unique), so most entries are
    /// `Used` with a single funding txid. A `Reused` entry
    /// indicates external (non-SP-flow) activity that landed at
    /// the same spk, typically address poisoning, or a payer
    /// copying the on-chain address from an earlier tx and sending
    /// a regular Bitcoin payment to it. The wallet surfaces the
    /// signal; consumer policy decides how to react.
    pub fn addresses_with_status(&self) -> Vec<SpAddressEntry> {
        use std::collections::BTreeMap;
        let mut by_spk: BTreeMap<
            ScriptBuf,
            (
                std::collections::BTreeSet<bitcoin::Txid>,
                std::collections::BTreeSet<bitcoin::Txid>,
            ),
        > = BTreeMap::new();
        let Ok(iter) = self.store.iter() else {
            return Vec::new();
        };
        for (outpoint, entry) in iter {
            let bucket = by_spk.entry(entry.script().clone()).or_default();
            bucket.0.insert(outpoint.txid);
            if let OutputSpendStatus::Spent { txid, .. } = entry.status() {
                bucket.1.insert(bitcoin::Txid::from_byte_array(*txid));
            }
        }
        by_spk
            .into_iter()
            .map(|(script, (funding_txids, spending_txids))| {
                let status = match funding_txids.len() {
                    0 => bwk::bwk_electrum::address_store::AddressStatus::NotUsed,
                    1 => bwk::bwk_electrum::address_store::AddressStatus::Used,
                    _ => bwk::bwk_electrum::address_store::AddressStatus::Reused,
                };
                SpAddressEntry {
                    script,
                    status,
                    funding_txids,
                    spending_txids,
                }
            })
            .collect()
    }
}

/// Per-spk view over an [`SpCoinStore`]. One entry per unique
/// SP-derived taproot script we own, with the txids that funded
/// and (if any) spent it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpAddressEntry {
    pub script: ScriptBuf,
    pub status: bwk::bwk_electrum::address_store::AddressStatus,
    pub funding_txids: std::collections::BTreeSet<bitcoin::Txid>,
    pub spending_txids: std::collections::BTreeSet<bitcoin::Txid>,
}

// SpCoinSource (CoinSource for TxBuilder)

use std::sync::Mutex;

use bwk_coin::{Coin, CoinSource, CoinSpendInfo, CoinStatus};

use bitcoin::{
    bip32::{Fingerprint, Xpriv},
    secp256k1::{All, Secp256k1},
};

/// Taproot keyspend satisfaction weight in WU (1 Schnorr signature = 66 WU)
const TR_KEYSPEND_SATISFACTION_WEIGHT: u64 = 66;

/// Implements [`CoinSource`] for the SP coin store, providing spendable coins
/// to [`TxBuilder`](bwk_tx::TxBuilder). Generic over any `SpCoinStore<S>`.
pub struct SpCoinSource<P: SpStorageProfile = SpRamProfile<DefaultBackend>>(
    Arc<Mutex<SpCoinStore<P>>>,
);

impl<P: SpStorageProfile> SpCoinSource<P> {
    pub fn new(store: Arc<Mutex<SpCoinStore<P>>>) -> Self {
        Self(store)
    }
}

impl<P: SpStorageProfile + Send + Sync + 'static> CoinSource for SpCoinSource<P> {
    fn spendable_coins(&self) -> Vec<Coin> {
        let store = self.0.lock().expect("poisoned");
        store
            .spendable_coins()
            .coins
            .into_iter()
            .map(|(outpoint, entry)| Coin {
                txout: bitcoin::TxOut {
                    value: entry.amount(),
                    script_pubkey: entry.script().clone(),
                },
                outpoint,
                height: Some(entry.height() as u64),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                status: CoinStatus::Confirmed,
                label: None,
                satisfaction_size: TR_KEYSPEND_SATISFACTION_WEIGHT,
                spend_info: CoinSpendInfo::Sp {
                    derivation: bitcoin::bip32::DerivationPath::default(),
                    tweak: *entry.tweak(),
                },
            })
            .collect()
    }
}

// MergedCoinSource (SP + BIP32 sub-accounts)

/// A [`CoinSource`] that merges coins from the SP coin store and zero or more
/// BIP32 sub-account coin sources (segwit, taproot, etc.).
pub struct MergedCoinSource<P: SpStorageProfile = SpRamProfile<DefaultBackend>> {
    sp_source: SpCoinSource<P>,
    bip32_sources: Vec<Box<dyn CoinSource>>,
}

impl<P: SpStorageProfile> MergedCoinSource<P> {
    pub fn new(sp_source: SpCoinSource<P>, bip32_sources: Vec<Box<dyn CoinSource>>) -> Self {
        Self {
            sp_source,
            bip32_sources,
        }
    }
}

impl<P: SpStorageProfile + Send + Sync + 'static> CoinSource for MergedCoinSource<P> {
    fn spendable_coins(&self) -> Vec<Coin> {
        let mut coins = self.sp_source.spendable_coins();
        for source in &self.bip32_sources {
            coins.extend(source.spendable_coins());
        }
        coins
    }
}

// KeyedBip32Source (enriches BIP32 coins with secret keys for SP partial secret)

/// A [`CoinSource`] wrapper that populates the ephemeral `secret_key` field on
/// BIP32 coins so that [`SpPartialSecretProvider`] can compute the partial
/// secret when sending to SP addresses with mixed inputs.
pub struct KeyedBip32Source {
    inner: Box<dyn CoinSource>,
    xprivs: BTreeMap<Fingerprint, Xpriv>,
    secp: Secp256k1<All>,
}

impl KeyedBip32Source {
    pub fn new(inner: Box<dyn CoinSource>, xprivs: BTreeMap<Fingerprint, Xpriv>) -> Self {
        Self {
            inner,
            xprivs,
            secp: Secp256k1::new(),
        }
    }

    /// Derive the secret key for a BIP32 coin using its PSBT input derivation info.
    fn populate_secret_key(&self, coin: &mut Coin) {
        if !coin.is_bip32() {
            return;
        }

        let psbt_input = match coin.to_psbt_input() {
            Ok(inp) => inp,
            Err(_) => return,
        };

        // Try segwit bip32_derivation first, then taproot tap_key_origins
        let derived_key = if !psbt_input.bip32_derivation.is_empty() {
            psbt_input.bip32_derivation.values().find_map(|(fg, path)| {
                let xpriv = self.xprivs.get(fg)?;
                xpriv
                    .derive_priv(&self.secp, path)
                    .ok()
                    .map(|k| k.private_key)
            })
        } else if !psbt_input.tap_key_origins.is_empty() {
            psbt_input
                .tap_key_origins
                .values()
                .find_map(|(_, (fg, path))| {
                    let xpriv = self.xprivs.get(fg)?;
                    xpriv
                        .derive_priv(&self.secp, path)
                        .ok()
                        .map(|k| k.private_key)
                })
        } else {
            None
        };

        if let (Some(sk), CoinSpendInfo::Bip32 { secret_key, .. }) =
            (derived_key, &mut coin.spend_info)
        {
            *secret_key = Some(sk);
        }
    }
}

impl CoinSource for KeyedBip32Source {
    fn spendable_coins(&self) -> Vec<Coin> {
        let mut coins = self.inner.spendable_coins();
        for coin in &mut coins {
            self.populate_secret_key(coin);
        }
        coins
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::Height, hashes::Hash, Txid};
    use bwk::persist::JsonBackend;
    use std::fs;

    fn test_outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        }
    }

    fn test_outpoint_2() -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([2u8; 32]),
            vout: 1,
        }
    }

    fn test_outpoint_3() -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([3u8; 32]),
            vout: 2,
        }
    }

    fn test_owned_output(amount_sats: u64) -> OwnedOutput {
        OwnedOutput {
            blockheight: Height::from_consensus(100).unwrap(),
            tweak: [0u8; 32],
            amount: Amount::from_sat(amount_sats),
            script: ScriptBuf::new(),
            label: None,
            spend_status: OutputSpendStatus::Unspent,
        }
    }

    fn test_spent_output(amount_sats: u64) -> OwnedOutput {
        OwnedOutput {
            blockheight: Height::from_consensus(100).unwrap(),
            tweak: [0u8; 32],
            amount: Amount::from_sat(amount_sats),
            script: ScriptBuf::new(),
            label: None,
            spend_status: OutputSpendStatus::Spent {
                txid: [0u8; 32],
                block_hash: None,
            },
        }
    }

    #[test]
    fn test_coin_entry_accessors() {
        let outpoint = test_outpoint();
        let output = test_owned_output(10000);
        let entry = SpCoinEntry::new(outpoint, output);

        assert_eq!(entry.height(), 100);
        assert_eq!(entry.amount(), Amount::from_sat(10000));
        assert_eq!(entry.amount_sat(), 10000);
        assert_eq!(entry.outpoint(), &outpoint);
        assert!(entry.outpoint_str().contains(":0"));
        assert!(entry.is_spendable());
        assert_eq!(entry.tweak(), &[0u8; 32]);
        assert!(entry.label().is_none());
    }

    #[test]
    fn test_coin_entry_is_spendable() {
        let outpoint = test_outpoint();

        // Unspent should be spendable
        let unspent = SpCoinEntry::new(outpoint, test_owned_output(10000));
        assert!(unspent.is_spendable());

        // Spent should not be spendable
        let spent = SpCoinEntry::new(outpoint, test_spent_output(10000));
        assert!(!spent.is_spendable());
    }

    #[test]
    fn test_coin_store_new_empty() {
        let store = SpCoinStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.balance(), Amount::from_sat(0));
    }

    #[test]
    fn test_coin_store_insert_get() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        let output = test_owned_output(50000);

        store.insert(outpoint, output.clone());

        assert_eq!(store.len(), 1);
        let entry = store.get(&outpoint).expect("entry should exist");
        assert_eq!(entry.amount_sat(), 50000);
    }

    #[test]
    fn test_coin_store_insert_batch() {
        let mut store = SpCoinStore::new();
        let mut outputs = BTreeMap::new();
        outputs.insert(test_outpoint(), test_owned_output(10000));
        outputs.insert(test_outpoint_2(), test_owned_output(20000));
        outputs.insert(test_outpoint_3(), test_owned_output(30000));

        store.insert_batch(outputs);

        assert_eq!(store.len(), 3);
        assert!(store.get(&test_outpoint()).is_some());
        assert!(store.get(&test_outpoint_2()).is_some());
        assert!(store.get(&test_outpoint_3()).is_some());
    }

    #[test]
    fn test_coin_store_remove() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        store.insert(outpoint, test_owned_output(10000));

        assert!(!store.is_empty());

        let removed = store.remove(&outpoint);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().amount_sat(), 10000);
        assert!(store.is_empty());
        assert!(store.get(&outpoint).is_none());
    }

    #[test]
    fn test_coin_store_mark_spent() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        store.insert(outpoint, test_owned_output(10000));

        assert!(store.get(&outpoint).unwrap().is_spendable());

        let spending_txid = [42u8; 32];
        store.mark_spent(&outpoint, spending_txid);

        let entry = store.get(&outpoint).unwrap();
        assert!(!entry.is_spendable());
        assert!(
            matches!(entry.status(), OutputSpendStatus::Spent { txid, block_hash: None } if *txid == spending_txid)
        );
    }

    #[test]
    fn test_coin_store_confirm_spend_unknown_txid_is_mined() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        store.insert(outpoint, test_owned_output(10000));

        let block_hash = [99u8; 32];
        store.confirm_spend(&outpoint, block_hash);

        let entry = store.get(&outpoint).unwrap();
        assert!(matches!(entry.status(), OutputSpendStatus::Mined(hash) if *hash == block_hash));
    }

    #[test]
    fn test_coin_store_confirm_spend_keeps_known_txid() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        store.insert(outpoint, test_owned_output(10000));

        let spending_txid = [7u8; 32];
        store.mark_spent(&outpoint, spending_txid);
        let block_hash = [99u8; 32];
        store.confirm_spend(&outpoint, block_hash);

        let entry = store.get(&outpoint).unwrap();
        assert!(matches!(
            entry.status(),
            OutputSpendStatus::Spent { txid, block_hash: Some(h) }
                if *txid == spending_txid && *h == block_hash
        ));
    }

    #[test]
    fn test_coin_store_spendable_coins() {
        let mut store = SpCoinStore::new();

        // Insert 2 unspent and 1 spent
        store.insert(test_outpoint(), test_owned_output(10000));
        store.insert(test_outpoint_2(), test_owned_output(20000));
        store.insert(test_outpoint_3(), test_spent_output(30000));

        let state = store.spendable_coins();

        assert_eq!(state.confirmed_coins, 2);
        assert_eq!(state.confirmed_balance, 30000); // 10000 + 20000
        assert_eq!(state.unconfirmed_coins, 0);
        assert_eq!(state.unconfirmed_balance, 0);
        assert_eq!(state.coins.len(), 2);
    }

    #[test]
    fn test_coin_store_balance() {
        let mut store = SpCoinStore::new();

        store.insert(test_outpoint(), test_owned_output(10000));
        store.insert(test_outpoint_2(), test_owned_output(20000));
        store.insert(test_outpoint_3(), test_spent_output(50000)); // Spent, not counted

        assert_eq!(store.balance(), Amount::from_sat(30000));
    }

    #[test]
    fn test_coin_store_all_outpoints() {
        let mut store = SpCoinStore::new();
        store.insert(test_outpoint(), test_owned_output(10000));
        store.insert(test_outpoint_2(), test_owned_output(20000));

        let outpoints = store.all_outpoints();
        assert_eq!(outpoints.len(), 2);
        assert!(outpoints.contains(&test_outpoint()));
        assert!(outpoints.contains(&test_outpoint_2()));
    }

    #[test]
    fn test_coin_store_watchable() {
        let mut store = SpCoinStore::new();

        // Unspent at height 100 is watchable.
        store.insert(test_outpoint(), test_owned_output(10000));
        // Spent { block_hash: None } at height 100 is watchable.
        store.insert(test_outpoint_2(), test_spent_output(20000));
        // Spent { block_hash: Some } at height 200 is not watchable.
        let mut spent_confirmed = test_owned_output(30000);
        spent_confirmed.blockheight = Height::from_consensus(200).unwrap();
        spent_confirmed.spend_status = OutputSpendStatus::Spent {
            txid: [7u8; 32],
            block_hash: Some([9u8; 32]),
        };
        store.insert(test_outpoint_3(), spent_confirmed);
        // Mined at height 100 is not watchable.
        let outpoint_4 = OutPoint {
            txid: Txid::from_byte_array([4u8; 32]),
            vout: 3,
        };
        let mut mined = test_owned_output(40000);
        mined.spend_status = OutputSpendStatus::Mined([9u8; 32]);
        store.insert(outpoint_4, mined);

        let mut watchable = store.watchable();
        watchable.sort();
        assert_eq!(
            watchable,
            vec![(test_outpoint(), 100), (test_outpoint_2(), 100)]
        );
    }

    #[test]
    fn test_coin_store_persistence() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-coin-store-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        // Scoped so `store` drops at the closing brace, releasing
        // the DirLock before the reopener tries to acquire it.
        {
            let backend = JsonBackend::open(temp_dir.clone()).unwrap();
            let coins_path = backend.path_for(STORE_KEY);
            let mut store = SpCoinStore::with_backend(Arc::new(backend), STORE_KEY);
            store.insert(test_outpoint(), test_owned_output(10000));
            store.insert(test_outpoint_2(), test_owned_output(20000));
            store.persist();

            assert!(coins_path.exists());
        }

        // Load from dir
        let backend = Arc::new(JsonBackend::open(temp_dir.clone()).unwrap());
        let loaded = SpCoinStore::load_from_backend(backend, STORE_KEY).expect("load coin store");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&test_outpoint()).unwrap().amount_sat(), 10000);
        assert_eq!(loaded.get(&test_outpoint_2()).unwrap().amount_sat(), 20000);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_coin_store_persist_disabled() {
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-coin-store-no-persist-test");
        let _ = fs::remove_dir_all(&temp_dir);
        let _ = fs::create_dir_all(&temp_dir);

        // Compute the would-be on-disk path via the backend, then drop
        // the backend before exercising the no-persist path.
        let backend = JsonBackend::open(temp_dir.clone()).unwrap();
        let coins_path = backend.path_for(STORE_KEY);
        drop(backend);

        // Create store with persist disabled (NoopBackend via SpCoinStore::new)
        let mut store = SpCoinStore::new();
        store.insert(test_outpoint(), test_owned_output(10000));
        store.persist();

        // File should not exist
        assert!(!coins_path.exists());

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_coin_store_mark_spent_api() {
        let mut store = SpCoinStore::new();
        let outpoint = test_outpoint();
        store.insert(outpoint, test_owned_output(10000));

        // Modify through mark_spent (the closure-based `modify` that
        // replaces the old `get_mut`).
        store.mark_spent(&outpoint, [1u8; 32]);

        let entry = store.get(&outpoint).unwrap();
        assert!(!entry.is_spendable());
    }

    #[test]
    fn test_coin_state_default() {
        let state = CoinState::default();

        assert!(state.coins.is_empty());
        assert_eq!(state.confirmed_coins, 0);
        assert_eq!(state.confirmed_balance, 0);
        assert_eq!(state.unconfirmed_coins, 0);
        assert_eq!(state.unconfirmed_balance, 0);
    }

    #[test]
    fn test_coin_store_coins_reference() {
        let mut store = SpCoinStore::new();
        store.insert(test_outpoint(), test_owned_output(10000));

        let coins = store.coins();
        assert_eq!(coins.len(), 1);
        assert!(coins.contains_key(&test_outpoint()));
    }

    // ---------------------------------------------------------------
    // addresses_with_status: per-spk status + funding/spending view
    // ---------------------------------------------------------------

    /// Build an `OwnedOutput` pointing at a specific script_pubkey,
    /// optionally marked as spent. Pair with [`SpCoinStore::insert`].
    fn owned_at(spk: ScriptBuf, spending: Option<[u8; 32]>) -> OwnedOutput {
        let spend_status = match spending {
            None => OutputSpendStatus::Unspent,
            Some(txid_bytes) => OutputSpendStatus::Spent {
                txid: txid_bytes,
                block_hash: None,
            },
        };
        OwnedOutput {
            blockheight: Height::from_consensus(100).unwrap(),
            tweak: [0u8; 32],
            amount: Amount::from_sat(10_000),
            script: spk,
            label: None,
            spend_status,
        }
    }

    fn distinct_spk(seed: u8) -> ScriptBuf {
        // 22-byte witness program is enough to be a valid distinct
        // ScriptBuf for grouping purposes.
        ScriptBuf::from_bytes(vec![seed; 22])
    }

    #[test]
    fn addresses_with_status_empty_for_empty_store() {
        let store = SpCoinStore::new();
        assert!(store.addresses_with_status().is_empty());
    }

    #[test]
    fn addresses_with_status_normal_one_shot() {
        let mut store = SpCoinStore::new();
        let spk = distinct_spk(7);
        let op = test_outpoint();
        store.insert(op, owned_at(spk.clone(), None));

        let entries = store.addresses_with_status();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.script, spk);
        assert_eq!(
            e.status,
            bwk::bwk_electrum::address_store::AddressStatus::Used
        );
        assert_eq!(e.funding_txids.len(), 1);
        assert!(e.funding_txids.contains(&op.txid));
        assert!(e.spending_txids.is_empty());
    }

    #[test]
    fn addresses_with_status_reuse_marks_reused() {
        // Two coins landing at the SAME spk, anomalous in normal
        // SP flow (would need address poisoning or a non-SP payment
        // copying the on-chain address from history).
        let mut store = SpCoinStore::new();
        let spk = distinct_spk(11);
        let op_a = test_outpoint();
        let op_b = test_outpoint_2();
        store.insert(op_a, owned_at(spk.clone(), None));
        store.insert(op_b, owned_at(spk.clone(), None));

        let entries = store.addresses_with_status();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(
            e.status,
            bwk::bwk_electrum::address_store::AddressStatus::Reused
        );
        assert_eq!(e.funding_txids.len(), 2);
        assert!(e.funding_txids.contains(&op_a.txid));
        assert!(e.funding_txids.contains(&op_b.txid));
    }

    #[test]
    fn addresses_with_status_records_spending_txid() {
        let mut store = SpCoinStore::new();
        let spk = distinct_spk(13);
        let op = test_outpoint_3();
        let spending_txid_bytes = [0xAA; 32];
        store.insert(op, owned_at(spk, Some(spending_txid_bytes)));

        let entries = store.addresses_with_status();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(
            e.status,
            bwk::bwk_electrum::address_store::AddressStatus::Used
        );
        assert_eq!(e.spending_txids.len(), 1);
        assert!(e
            .spending_txids
            .contains(&Txid::from_byte_array(spending_txid_bytes)));
    }
}
