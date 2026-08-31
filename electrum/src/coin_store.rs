use bwk_coin::{
    max_input_satisfaction_size, ChangeTip, Coin, CoinSource, CoinSpendInfo, CoinStatus, KeyChain,
};
use bwk_descriptor::derivator::SpkDerivator;
use miniscript::{
    bitcoin::{self, address::NetworkUnchecked, OutPoint, ScriptBuf, Sequence, Txid},
    Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{mpsc, Arc, Mutex},
};

use crate::{
    address_store::{AddressEntry, AddressStatus, AddressStore, AddressTip},
    coin_state::CoinState,
    header_store::HeaderStore,
    label_store::{LabelKey, LabelStore},
    notification::Notification,
    profile::{DefaultBackend, RamProfile, ScanProfile},
    tx_store::{Inclusion, InputMetadata, OutputMetadata, TxEntry, TxStore},
};

impl From<&Inclusion> for CoinStatus {
    fn from(inclusion: &Inclusion) -> Self {
        match inclusion {
            // A failed merkle proof is not trusted as confirmed: surface it as
            // unconfirmed so it is never counted spendable-as-confirmed.
            Inclusion::Unconfirmed | Inclusion::VerifyFailed { .. } => CoinStatus::Unconfirmed,
            Inclusion::ConfirmedUnverified { .. } => CoinStatus::ConfirmedUnverified,
            Inclusion::Verified { .. } => CoinStatus::Confirmed,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PaymentType {
    Receive,
    Send,
    ToSelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    Unconfirmed,
    ConfirmedUnverified,
    Verified,
    VerifyFailed,
}

impl Default for PaymentStatus {
    fn default() -> Self {
        Self::Unconfirmed
    }
}

impl PaymentStatus {
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::VerifyFailed, _) | (_, Self::VerifyFailed) => Self::VerifyFailed,
            (Self::ConfirmedUnverified, _) | (_, Self::ConfirmedUnverified) => {
                Self::ConfirmedUnverified
            }
            (Self::Verified, _) | (_, Self::Verified) => Self::Verified,
            (Self::Unconfirmed, Self::Unconfirmed) => Self::Unconfirmed,
        }
    }
}

impl From<&Inclusion> for PaymentStatus {
    fn from(inclusion: &Inclusion) -> Self {
        match inclusion {
            Inclusion::Unconfirmed => Self::Unconfirmed,
            Inclusion::ConfirmedUnverified { .. } => Self::ConfirmedUnverified,
            Inclusion::Verified { .. } => Self::Verified,
            Inclusion::VerifyFailed { .. } => Self::VerifyFailed,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Payment {
    pub txid: String,
    pub payment_type: PaymentType,
    pub status: PaymentStatus,
    pub amount: u64,
    pub label: String,
    /// Confirmation height, `None` while unconfirmed.
    pub height: Option<u64>,
    /// Confirming block time, `None` until known.
    pub timestamp: Option<u64>,
}

pub struct CoinStoreSource<P: ScanProfile = RamProfile<DefaultBackend>>(Arc<Mutex<CoinStore<P>>>);

impl<P: ScanProfile> CoinStoreSource<P> {
    pub fn new(store: Arc<Mutex<CoinStore<P>>>) -> Self {
        Self(store)
    }
}

pub struct ChangeTipUpdater<P: ScanProfile = RamProfile<DefaultBackend>>(Arc<Mutex<CoinStore<P>>>);

impl<P: ScanProfile> Clone for ChangeTipUpdater<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: ScanProfile> ChangeTipUpdater<P> {
    pub fn new(store: Arc<Mutex<CoinStore<P>>>) -> Self {
        Self(store)
    }
}

impl<P: ScanProfile> ChangeTip for ChangeTipUpdater<P> {
    fn next_index(&mut self) -> u32 {
        let mut store = self.0.lock().expect("poisoned");
        let index = store
            .address_store
            .lock()
            .expect("poisoned")
            .next_change_index();
        store.generate();
        index
    }
}

pub struct SpendRecorder<P: ScanProfile = RamProfile<DefaultBackend>> {
    coin_store: Arc<Mutex<CoinStore<P>>>,
}

impl<P: ScanProfile> Clone for SpendRecorder<P> {
    fn clone(&self) -> Self {
        Self {
            coin_store: self.coin_store.clone(),
        }
    }
}

impl<P: ScanProfile> SpendRecorder<P> {
    pub fn new(coin_store: Arc<Mutex<CoinStore<P>>>) -> Self {
        Self { coin_store }
    }

    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .get(outpoint)
            .map(|e| e.coin)
    }

    pub fn address_scripts(&self) -> BTreeSet<ScriptBuf> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .entries()
            .into_iter()
            .map(|entry| entry.script())
            .collect()
    }

    pub fn record_unconfirmed_spend(&self, tx: &bitcoin::Transaction) {
        self.coin_store
            .lock()
            .expect("poisoned")
            .record_unconfirmed_tx(tx.clone());
    }
}

impl<P: ScanProfile> CoinSource for CoinStoreSource<P> {
    fn spendable_coins(&self) -> Vec<Coin> {
        self.0
            .lock()
            .expect("poisoned")
            .spendable_coins()
            .coins
            .into_values()
            .collect()
    }
}

#[derive(Debug)]
/// Represents a store for managing coins and their associated data.
///
/// The `CoinStore` is generated from the transaction store after every
/// TxStore update and acts as a cache for coins. It maintains mappings
/// of outpoints to coin entries and tracks the history of script public
/// keys (SPKs).
pub struct CoinStore<P: ScanProfile = RamProfile<DefaultBackend>> {
    store: BTreeMap<OutPoint, CoinEntry>,
    label_store: Arc<Mutex<LabelStore<P>>>,
    spk_to_outpoint: BTreeMap<ScriptBuf, HashSet<OutPoint>>,
    address_store: Arc<Mutex<AddressStore<P>>>,
    tx_store: TxStore<P>,
    spk_history: BTreeMap<ScriptBuf, SpkHistory>,
    updates: Vec<Update>,
    derivator: SpkDerivator,
    notification: mpsc::Sender<Notification>,
    /// Pending claims indexed by server-reported height. A txid lands
    /// here when the server reports it at height H but the HeaderStore
    /// doesn't yet have a header at H; the next CTA resolves it.
    pending_claims: BTreeMap<u32, BTreeSet<Txid>>,
    /// Claims with a `GetTxMerkle` fetch in flight, so a chain tick does not
    /// re-queue a proof already being fetched (fetch-storm guard). Cleared
    /// when the response lands (`clear_merkle_in_flight`) or the entry leaves
    /// `ConfirmedUnverified`. In-memory runtime state, never persisted.
    merkle_in_flight: BTreeSet<ClaimAt>,
}

#[derive(Debug, Default)]
/// Represents the history of transactions for a specific script public key (SPK).
///
/// The `SpkHistory` stores a history of txids and their associated
/// heights, allowing for tracking incremental changes over time.
pub struct SpkHistory {
    history: Vec<BTreeMap<bitcoin::Txid, Option<u64>>>,
}

#[derive(Debug, Default)]
/// Represents the differences in transaction history for a script public key.
///
/// The `HistoryDiff` struct contains the added, changed, and removed
/// transactions, allowing for easy tracking of updates to the SPK history.
pub struct HistoryDiff {
    pub added: BTreeMap<bitcoin::Txid, Option<u64>>,
    pub changed: BTreeMap<bitcoin::Txid, Option<u64>>,
    pub removed: BTreeMap<bitcoin::Txid, Option<u64>>,
}

/// A claim that transaction `txid` is confirmed at block `height`, awaiting
/// header lookup and merkle-proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaimAt {
    pub txid: Txid,
    pub height: u32,
}

#[derive(Debug, Default)]
pub struct HistoryOutcome {
    pub height_updated: bool,
    pub missing_txs: Vec<Txid>,
    pub reported: Vec<ClaimAt>,
}

/// What a CTA sub-pass produced: merkle fetches to queue and whether it
/// mutated any tx state.
#[derive(Debug, Default)]
pub struct ChainUpdateOutcome {
    pub to_fetch: Vec<ClaimAt>,
    pub changed: bool,
}

impl SpkHistory {
    /// Creates a new instance of `SpkHistory`.
    ///
    /// This method initializes the history with default values.
    pub fn new() -> Self {
        Self {
            history: vec![BTreeMap::default()],
        }
    }
    /// Inserts new transaction data into the SPK history and returns the differences.
    ///
    /// This method compares the new transaction data with the existing history
    /// and returns a `HistoryDiff` struct indicating added, changed, and removed
    /// transactions.
    pub fn insert(&mut self, new: Vec<(bitcoin::Txid, Option<u64>)>) -> HistoryDiff {
        let new: BTreeMap<_, _> = new.into_iter().collect();
        assert!(!self.history.is_empty());

        // last state have no txs
        let diff = if self.history.last().expect("not empty").is_empty() {
            if new.is_empty() {
                HistoryDiff::default()
            } else {
                self.history.push(new.clone());
                HistoryDiff {
                    added: new.clone(),
                    ..Default::default()
                }
            }
        } else {
            let mut diff = HistoryDiff::default();
            {
                let previous = self.history.last().expect("at least one element");

                new.iter().for_each(|(txid, height)| {
                    if !previous.contains_key(txid) {
                        diff.added.insert(*txid, *height);
                    } else {
                        let prev_height = previous.get(txid).expect("present");
                        if height != prev_height {
                            diff.changed.insert(*txid, *height);
                        }
                    }
                });

                previous.iter().for_each(|(txid, height)| {
                    if !new.contains_key(txid) {
                        diff.removed.insert(*txid, *height);
                    }
                });
            }
            // FIXME: do not insert if last == new
            self.history.push(new);
            diff
        };
        diff
    }
}

impl<P: ScanProfile> CoinStore<P> {
    /// Creates a new instance of `CoinStore`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: bitcoin::Network,
        descriptor: Descriptor<DescriptorPublicKey>,
        notification: mpsc::Sender<Notification>,
        recv_tip: u32,
        change_tip: u32,
        look_ahead: u32,
        tx_store: TxStore<P>,
        label_store: Arc<Mutex<LabelStore<P>>>,
        account_store: Arc<Mutex<P::AccountStore>>,
    ) -> Self {
        let derivator = SpkDerivator::new(descriptor, network).unwrap();
        let address_store = Arc::new(Mutex::new(AddressStore::with_account_store(
            derivator.clone(),
            notification.clone(),
            recv_tip,
            change_tip,
            look_ahead,
            account_store,
        )));
        Self {
            store: BTreeMap::new(),
            spk_to_outpoint: BTreeMap::new(),
            address_store,
            label_store,
            tx_store,
            updates: Vec::new(),
            spk_history: BTreeMap::new(),
            notification,
            derivator,
            pending_claims: BTreeMap::new(),
            merkle_in_flight: BTreeSet::new(),
        }
    }

    /// Stamp every confirmed, un-timestamped tx with its confirming block time,
    /// looked up from the validated header chain via `block_time`. Persists if
    /// any timestamp was written. Entries whose header the caller cannot resolve
    /// yet are left untouched and stamped on a later pass.
    pub fn stamp_confirmation_times(&mut self, block_time: impl Fn(u64) -> Option<u64>) {
        let mut stamp = Vec::<(Txid, u64)>::new();
        for (txid, entry) in self.tx_store.iter() {
            if entry.timestamp().is_some() {
                continue;
            }
            if let Some(height) = entry.height() {
                if let Some(time) = block_time(height) {
                    stamp.push((txid, time));
                }
            }
        }
        if stamp.is_empty() {
            return;
        }
        for (txid, time) in stamp {
            self.tx_store.update_timestamp(&txid, time);
        }
        self.tx_store.persist();
    }

    /// Initializes the address store with a channel to the tx listener.
    ///
    /// This method sets up the address store to send updates to the
    /// specified transaction listener.
    pub fn init(&mut self, tx_listener: mpsc::Sender<AddressTip>) {
        self.address_store
            .lock()
            .expect("poisoned")
            .init(tx_listener);
    }
    /// Returns a clone of the derivator used for generating addresses.
    ///
    /// # Returns
    /// A `Derivator` instance.
    pub fn derivator(&self) -> SpkDerivator {
        self.derivator.clone()
    }
    /// Returns a reference to the derivator used for generating addresses.
    ///
    /// # Returns
    /// A reference to a `SpkDerivator`.
    pub fn derivator_ref(&self) -> &SpkDerivator {
        &self.derivator
    }
    /// Returns the current receiving watch tip index.
    ///
    /// # Returns
    /// The index of the last generated receiving address.
    pub fn recv_watch_tip(&self) -> u32 {
        self.address_store
            .lock()
            .expect("poisoned")
            .recv_watch_tip()
    }

    /// Returns the current change watch tip index.
    ///
    /// # Returns
    /// The index of the last generated change address.
    pub fn change_watch_tip(&self) -> u32 {
        self.address_store
            .lock()
            .expect("poisoned")
            .change_watch_tip()
    }

    /// Generates a new receiving address.
    ///
    /// # Returns
    /// A new `bitcoin::Address` for receiving funds.
    pub fn new_recv_addr(&mut self) -> bitcoin::Address {
        let address = self.address_store.lock().expect("poisoned").new_recv_addr();
        self.generate();
        address
    }

    /// Returns the current receiving address tip index.
    ///
    /// # Returns
    /// The index of the last generated receiving address.
    pub fn recv_tip(&self) -> u32 {
        self.address_store.lock().expect("poisoned").recv_tip()
    }

    /// Generates a new change address.
    ///
    /// # Returns
    /// A new `bitcoin::Address` for change outputs.
    pub fn new_change_addr(&mut self) -> bitcoin::Address {
        let address = self
            .address_store
            .lock()
            .expect("poisoned")
            .new_change_addr();
        self.generate();
        address
    }

    /// Retrieves information about an address associated with the given script public key (SPK).
    ///
    /// This method queries the address store to find the entry corresponding to the provided SPK.
    ///
    /// # Parameters
    /// - `spk`: A reference to the `ScriptBuf` representing the script public key for which to retrieve the address information.
    ///
    /// # Returns
    /// An `Option<AddressEntry>` containing the address information if found, or `None` if no entry exists for the given SPK.
    pub fn address_info(&self, spk: &ScriptBuf) -> Option<AddressEntry> {
        self.address_store.lock().expect("poisoned").get_entry(spk)
    }

    /// Processes a received coin at the specified script public key.
    ///
    /// # Parameters
    /// - `spk`: The script public key of the received coin.
    fn recv_coin_at(&mut self, spk: &ScriptBuf) {
        self.address_store
            .lock()
            .expect("poisoned")
            .recv_coin_at(spk);
    }

    /// Handles the response containing transaction history for SPKs.
    ///
    /// This method processes the history and updates the internal state of the
    /// `CoinStore`.
    ///
    /// # Parameters
    /// - `hist`: A map of script public keys to their transaction history.
    ///
    /// # Returns
    /// A [`HistoryOutcome`] carrying the missing txids to fetch, the
    /// server-reported heights, and whether any stored height changed.
    pub fn handle_history_response(
        &mut self,
        hist: BTreeMap<ScriptBuf, Vec<(bitcoin::Txid, Option<u64>)>>,
    ) -> HistoryOutcome {
        let watch_tips = (self.recv_watch_tip(), self.change_watch_tip());
        let mut updates = vec![];
        let mut height_updated = false;

        // Server-reported confirmation heights, captured here before the
        // history is folded into `Inclusion::Unconfirmed`.
        let mut reported: Vec<ClaimAt> = Vec::new();

        // generate diff & drop double spent txs
        for (spk, history) in hist {
            for (txid, h) in &history {
                if let Some(height) = h.and_then(|h| u32::try_from(h).ok()) {
                    reported.push(ClaimAt {
                        txid: *txid,
                        height,
                    });
                }
            }
            self.recv_coin_at(&spk);
            let update = self.update_spk_history(spk, history);
            updates.push(update);
        }

        let mut updates: Vec<_> = updates
            .into_iter()
            .map(|(height, upd)| {
                if height {
                    height_updated = true;
                }
                upd
            })
            .collect();

        {
            // pre fill with tx we already have
            let store = &self.tx_store;
            for upd in &mut updates {
                for tx in &mut upd.txs {
                    if let Some(store_tx) = store.inner_get(&tx.0) {
                        tx.1 = Some(store_tx);
                    }
                }
            }
        } // <- release tx_store ref

        // request missing txs
        let mut txids = vec![];
        for upd in &updates {
            txids.append(&mut upd.missing());
        }

        {
            // apply updates that are already completes
            let store = &mut self.tx_store;
            updates = updates
                .into_iter()
                .filter_map(|u| {
                    if u.is_complete() {
                        store.insert_updates(vec![u]);
                        None
                    } else {
                        Some(u)
                    }
                })
                .collect();
        } // <- release &mut tx_store

        self.updates.append(&mut updates);
        if (self.recv_watch_tip(), self.change_watch_tip()) != watch_tips {
            self.generate();
        }
        HistoryOutcome {
            height_updated,
            missing_txs: txids,
            reported,
        }
    }

    /// Updates the history for a specific script public key (SPK).
    ///
    /// This method generates a diff of the SPK history and updates the
    /// transaction store accordingly.
    ///
    /// # Parameters
    /// - `spk`: The script public key to update.
    /// - `history`: The new transaction history for the SPK.
    ///
    /// # Returns
    /// An `Update` representing the changes made to the SPK history.
    ///
    /// Note: triggered on history_get response
    pub fn update_spk_history(
        &mut self,
        spk: ScriptBuf,
        history: Vec<(Txid, Option<u64> /* height */)>,
    ) -> (bool /* height_updated */, Update) {
        // insert a blank history if no one
        if !self.spk_history.contains_key(&spk) {
            self.spk_history.insert(spk.clone(), SpkHistory::new());
        }

        // generate the diff w/ the last spk history
        let diff = self
            .spk_history
            .get_mut(&spk)
            .expect("already inserted")
            .insert(history);

        {
            // drop tx in the tx_store & update heights
            let store = &mut self.tx_store;
            for txid in diff.removed.keys() {
                store.remove(txid);
            }
            // Reset to Unconfirmed; re-claim handled in resolve_reported_heights.
            for txid in diff.changed.keys() {
                store.update_inclusion(txid, Inclusion::Unconfirmed);
            }
        } // <- release &mut tx_store

        // A demoted tx must not keep a stale pending claim, or a later CTA
        // would re-promote it at the old height. Still-confirmed txs are
        // re-queued by resolve_reported_heights in the same history pass.
        for txid in diff.changed.keys() {
            self.drop_all_pending_claims(txid);
        }

        // A tx removed or demoted out of ConfirmedUnverified frees its
        // in-flight merkle slot so the set does not leak.
        for txid in diff.removed.keys().chain(diff.changed.keys()) {
            self.merkle_in_flight.retain(|claim| claim.txid != *txid);
        }

        (!diff.changed.is_empty(), Update::from_diff(spk, diff))
    }

    /// Handles the response containing transactions.
    ///
    /// This method processes the received transactions and updates the
    /// internal state of the `CoinStore`. It regenerates the coin store
    /// from the transaction store.
    ///
    /// # Parameters
    /// - `txs`: A vector of Bitcoin transactions received.
    pub fn handle_txs_response(&mut self, txs: Vec<bitcoin::Transaction>) {
        // iter over updates & populate where the transaction is required
        for new_tx in txs {
            let new_txid = new_tx.compute_txid();
            for Update { txs, .. } in &mut self.updates {
                txs.iter_mut().for_each(|(txid, tx)| {
                    if (*txid == new_txid) && tx.is_none() {
                        *tx = Some(new_tx.clone());
                    }
                });
            }
        }
        {
            // push every complete update to the tx store
            let store = &mut self.tx_store;
            self.updates = self
                .updates
                .clone()
                .into_iter()
                .filter_map(|update| {
                    if update.is_complete() {
                        store.insert_updates(vec![update]);
                        None
                    } else {
                        Some(update)
                    }
                })
                .collect();
        } // <- release &mut tx_store

        // re-generate coin store from tx store
        self.generate();
    }

    /// Record a just-broadcast transaction as unconfirmed and rebuild the coin
    /// view: owned inputs flip to `Spent`, any owned change is surfaced as an
    /// `Unconfirmed` coin. A later listener/scan confirmation upgrades it. No-op
    /// on the tx body if it is already known (do not clobber a confirmed entry).
    pub fn record_unconfirmed_tx(&mut self, tx: bitcoin::Transaction) {
        let owns_input = tx
            .input
            .iter()
            .any(|input| self.store.contains_key(&input.previous_output));
        let owns_output = tx.output.iter().any(|output| {
            self.address_store
                .lock()
                .expect("poisoned")
                .contains_spk(&output.script_pubkey)
        });
        if !owns_input && !owns_output {
            return;
        }
        let txid = tx.compute_txid();
        if self.tx_store.get(&txid).is_none() {
            self.tx_store.update(TxEntry::unconfirmed(tx));
        }
        self.generate();
    }

    /// Generates the coin store from the transaction store.
    ///
    /// This method populates the coin store with coins based on the
    /// transactions in the transaction store and updates the address
    /// statuses accordingly.
    pub fn generate(&mut self) {
        let addr_store = &mut self.address_store;
        let tx_store = &self.tx_store;

        let mut coins = BTreeMap::<OutPoint, CoinEntry>::new();
        let descriptor = self.derivator.descriptor();

        // NOTE: here we take the max satisfaction size at default, for descriptor with several
        // spending conditions, the correct satisfaction must be filled at tx crafting time.
        let satisfaction = max_input_satisfaction_size(&descriptor);

        // list all received coins
        for (_, entry) in tx_store.iter() {
            let tx = entry.tx();
            let txid = tx.compute_txid();
            for (vout, txout) in tx.output.iter().enumerate() {
                if let Some(addr) = addr_store
                    .lock()
                    .expect("poisoned")
                    .get_entry(&txout.script_pubkey)
                {
                    let txout = txout.clone();
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let height = entry.height();
                    let status = CoinStatus::from(entry.inclusion());
                    let spk = match addr.account() {
                        KeyChain::Receive => self.derivator.receive_at(addr.index()),
                        KeyChain::Change => self.derivator.change_at(addr.index()),
                        KeyChain::Custom(_) => unimplemented!(),
                    }
                    .script_pubkey();
                    assert!(spk == txout.script_pubkey);

                    let label = self
                        .label_store
                        .lock()
                        .expect("poisoned")
                        .outpoint(outpoint);
                    let coin = Coin {
                        txout,
                        outpoint,
                        height,
                        // Sequence is overwritten at spend time anyway
                        sequence: Sequence::ZERO,
                        status,
                        label,
                        satisfaction_size: satisfaction as u64,
                        spend_info: CoinSpendInfo::Bip32 {
                            coin_path: (addr.account(), addr.index()),
                            descriptor: descriptor.clone(),
                            secret_key: None,
                        },
                    };
                    let coin = CoinEntry {
                        coin,
                        address: addr.address(),
                    };
                    coins.insert(outpoint, coin);
                }
            }
        }
        // list all spent coins + collect spending txids per spk:
        // every input whose previous_output points at one of our
        // coins is, by definition, a tx that spent that spk.
        let mut spk_to_spending = BTreeMap::<ScriptBuf, BTreeSet<Txid>>::new();
        for (tx_txid, tx_entry) in tx_store.iter() {
            for inp in &tx_entry.tx().input {
                if let Some(spent_ce) = coins.get_mut(&inp.previous_output) {
                    spent_ce.coin.status = CoinStatus::Spent;
                    spk_to_spending
                        .entry(spent_ce.spk())
                        .or_default()
                        .insert(tx_txid);
                }
            }
        }
        let mut spk_to_outpoint = BTreeMap::<ScriptBuf, HashSet<OutPoint>>::new();
        let mut spk_to_funding = BTreeMap::<ScriptBuf, BTreeSet<Txid>>::new();
        coins.iter().for_each(|(op, ce)| {
            let spk = ce.spk();
            spk_to_outpoint
                .entry(spk.clone())
                .and_modify(|e| {
                    e.insert(*op);
                })
                .or_insert({
                    let mut h = HashSet::new();
                    h.insert(*op);
                    h
                });
            spk_to_funding.entry(spk).or_default().insert(op.txid);
        });

        // populate labels
        {
            let store = self.label_store.lock().expect("poisoned");
            for (op, coin) in &mut coins {
                coin.coin.label = store.get(&LabelKey::OutPoint(*op)).clone();
            }
        } // => release label_store lock

        self.store = coins;
        self.spk_to_outpoint = spk_to_outpoint;

        // update address_store statuses + per-address tx history
        self.spk_to_outpoint.iter().for_each(|(spk, op)| {
            let status = match op.len() {
                0 => AddressStatus::NotUsed,
                1 => AddressStatus::Used,
                _ => AddressStatus::Reused,
            };
            if let Some(e) = addr_store.lock().expect("poisoned").get_entry_mut(spk) {
                e.set_status(status);
                e.set_funding_txids(spk_to_funding.get(spk).cloned().unwrap_or_default());
                e.set_spending_txids(spk_to_spending.get(spk).cloned().unwrap_or_default());
            }
        });

        self.populate_tx_metadata();
        self.tx_store.persist();

        // FIXME: update statuses of those w/ CoinStatus::BeeingSpent

        if let Err(e) = self.notification.send(Notification::CoinUpdate) {
            log::error!("CoinStore::generate() fail to send notification: {e:?}");
        }
    }

    pub fn populate_tx_metadata(&mut self) {
        let transactions = self.tx_store.transactions();
        let mut txouts = BTreeMap::new();
        for tx in &transactions {
            let txid = tx.txid();
            for (vout, txout) in tx.tx().output.iter().enumerate() {
                txouts.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    txout.clone(),
                );
            }
        }

        let address_store = self.address_store.lock().expect("poisoned");
        for mut tx in transactions {
            let outputs = tx
                .tx()
                .output
                .iter()
                .enumerate()
                .map(|(i, txout)| {
                    (
                        i,
                        OutputMetadata {
                            owned: address_store.contains_spk(&txout.script_pubkey),
                        },
                    )
                })
                .collect();
            let inputs = tx
                .tx()
                .input
                .iter()
                .enumerate()
                .map(|(i, txin)| {
                    let input = if let Some(txout) = txouts.get(&txin.previous_output) {
                        let owned = address_store.contains_spk(&txout.script_pubkey);
                        InputMetadata {
                            value: owned.then_some(txout.value.to_sat()),
                            owned,
                        }
                    } else {
                        InputMetadata {
                            value: None,
                            owned: false,
                        }
                    };
                    (i, input)
                })
                .collect();

            if tx.outputs != outputs || tx.inputs != inputs {
                tx.outputs = outputs;
                tx.inputs = inputs;
                self.tx_store.update(tx);
            }
        }
    }

    /// Retrieves coins by their status.
    ///
    /// This method filters the coins in the store based on the specified
    /// status and returns them as a `Coins` object.
    ///
    /// # Parameters
    /// - `status`: The status of the coins to retrieve.
    pub fn get_by_status(&self, status: CoinStatus) -> Vec<CoinEntry> {
        self.store
            .clone()
            .into_iter()
            .filter_map(|(_, coin)| {
                if coin.coin.status == status {
                    Some(coin)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    /// Retrieves a coin entry from the store by its outpoint.
    ///
    /// # Parameters
    /// - `outpoint`: A reference to the `OutPoint` of the coin to retrieve.
    ///
    /// # Returns
    /// An `Option<CoinEntry>` containing the coin entry if found, or `None` if no entry exists for the given outpoint.
    pub fn get(&self, outpoint: &bitcoin::OutPoint) -> Option<CoinEntry> {
        self.store.get(outpoint).cloned()
    }

    /// Retrieves spendable coins from the store.
    ///
    /// This method filters the coins that are either unconfirmed or
    /// confirmed and returns them as a `Coins` object.
    pub fn spendable_coins(&self) -> CoinState {
        let mut coins: Vec<_> = self
            .store
            .clone()
            .into_iter()
            .filter_map(|(_, coin)| match coin.coin.status {
                CoinStatus::Unconfirmed
                | CoinStatus::ConfirmedUnverified
                | CoinStatus::Confirmed
                | CoinStatus::BeingSpend => Some(coin),
                CoinStatus::Spent => None,
            })
            .collect();
        coins.sort_by(|a, b| a.coin.outpoint.cmp(&b.coin.outpoint));
        let mut state = CoinState {
            coins: Default::default(),
            confirmed_coins: 0,
            confirmed_balance: 0,
            unconfirmed_coins: 0,
            unconfirmed_balance: 0,
        };
        for entry in &coins {
            match entry.coin.status {
                CoinStatus::Unconfirmed => {
                    state.unconfirmed_coins += 1;
                    state.unconfirmed_balance += entry.coin.txout.value.to_sat();
                }
                // ConfirmedUnverified is on-chain confirmed; only its SPV
                // proof is pending, so it counts as confirmed.
                CoinStatus::Confirmed | CoinStatus::ConfirmedUnverified => {
                    state.confirmed_coins += 1;
                    state.confirmed_balance += entry.coin.txout.value.to_sat();
                }
                // BeingSpend is selectable but excluded from displayed
                // balance; Spent is filtered out above.
                CoinStatus::BeingSpend | CoinStatus::Spent => {}
            }
        }
        state.coins = coins.into_iter().map(|c| (*c.outpoint(), c.coin)).collect();
        state
    }

    /// Returns a list of all historical transactions
    pub fn tx_history(&self) -> Vec<TxEntry> {
        self.tx_store.transactions()
    }

    /// Returns all coins in the store.
    ///
    /// # Returns
    /// A `BTreeMap` of outpoints to their corresponding `CoinEntry`.
    pub fn coins(&self) -> BTreeMap<bitcoin::OutPoint, CoinEntry> {
        self.store.clone()
    }

    /// Dumps the coin store as a JSON value.
    ///
    /// # Returns
    /// A `Result` containing the serialized JSON value of the coin store
    /// or an error if serialization fails.
    pub fn dump(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.store)
    }

    /// Restores the coin store from a JSON value.
    ///
    /// # Parameters
    /// - `value`: The JSON value to restore the coin store from.
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the restoration.
    pub fn restore(&mut self, value: serde_json::Value) -> Result<(), serde_json::Error> {
        self.store = serde_json::from_value(value)?;
        Ok(())
    }

    pub fn address_store(&self) -> Arc<Mutex<AddressStore<P>>> {
        self.address_store.clone()
    }

    /// Mutable access to the embedded [`TxStore`]. Required by the
    /// `bwk::account::handle_tx_merkle` promotion and the CTA persist in
    /// `bwk::account::on_chain_update`.
    pub fn tx_store_mut(&mut self) -> &mut TxStore<P> {
        &mut self.tx_store
    }

    /// Queues a pending claim, to be promoted by a future CTA once the
    /// HeaderStore has a header at that height.
    pub fn insert_pending_claim(&mut self, claim: ClaimAt) {
        self.pending_claims
            .entry(claim.height)
            .or_default()
            .insert(claim.txid);
    }

    /// Queue server-reported heights without promoting against the header store.
    pub fn queue_reported_heights(&mut self, reported: &[ClaimAt]) -> bool {
        let before = self.pending_claims.clone();
        for &claim in reported {
            self.prune_pending_claim(claim);
            match self
                .tx_store
                .get(&claim.txid)
                .map(|e| e.inclusion().clone())
            {
                Some(Inclusion::Unconfirmed) | None => self.insert_pending_claim(claim),
                Some(_) => {}
            }
        }
        before != self.pending_claims
    }

    /// Drops `keep.txid` from every pending-claim height set other than
    /// `keep.height`. A reorg can re-report the same tx at a new height;
    /// this keeps at most one pending claim per txid so a later CTA never
    /// promotes it at a stale height.
    pub(crate) fn prune_pending_claim(&mut self, keep: ClaimAt) {
        self.pending_claims.retain(|height, set| {
            if *height != keep.height {
                set.remove(&keep.txid);
            }
            !set.is_empty()
        });
    }

    /// Drops `txid` from every pending-claim height set. Used when a tx falls
    /// back to the mempool so no later CTA can promote it at a stale height.
    pub(crate) fn drop_all_pending_claims(&mut self, txid: &Txid) {
        self.pending_claims.retain(|_height, set| {
            set.remove(txid);
            !set.is_empty()
        });
    }

    /// Snapshot of the pending-claims queue.
    pub fn pending_claims_snapshot(&self) -> BTreeMap<u32, BTreeSet<Txid>> {
        self.pending_claims.clone()
    }

    pub fn pending_claim_height(&self, txid: &Txid) -> Option<u32> {
        self.pending_claims
            .iter()
            .find_map(|(height, txids)| txids.contains(txid).then_some(*height))
    }

    /// Clear `claim` from the in-flight merkle-fetch set. Called when a
    /// `TxMerkle` response lands (the fetch resolved), so a later CTA can
    /// re-queue it if the entry is still `ConfirmedUnverified`.
    pub fn clear_merkle_in_flight(&mut self, claim: &ClaimAt) {
        self.merkle_in_flight.remove(claim);
    }

    /// Removes a single resolved claim from the queue.
    pub(crate) fn remove_pending_claim(&mut self, claim: ClaimAt) {
        if let Some(set) = self.pending_claims.get_mut(&claim.height) {
            set.remove(&claim.txid);
            if set.is_empty() {
                self.pending_claims.remove(&claim.height);
            }
        }
    }

    /// Clone each tx's inclusion once so a CTA pass can walk a stable snapshot.
    fn snapshot_inclusions(&self) -> Vec<(Txid, Inclusion)> {
        self.tx_store
            .iter()
            .into_iter()
            .map(|(txid, e)| (txid, e.inclusion().clone()))
            .collect()
    }

    /// Promote `txid` to `ConfirmedUnverified` at `height`/`block_hash` and
    /// record a merkle-proof fetch for it. Shared by the live history path
    /// and the queued-claim resolver.
    fn promote_claim(
        tx_store: &mut TxStore<P>,
        merkle_in_flight: &mut BTreeSet<ClaimAt>,
        txid: &Txid,
        height: u32,
        block_hash: bitcoin::BlockHash,
        to_fetch: &mut Vec<ClaimAt>,
    ) {
        tx_store.update_inclusion(txid, Inclusion::ConfirmedUnverified { height, block_hash });
        let claim = ClaimAt {
            txid: *txid,
            height,
        };
        merkle_in_flight.insert(claim);
        to_fetch.push(claim);
    }

    /// Promote server-reported `(txid, height)` claims with a known header,
    /// queue the rest in `pending_claims`. The caller persists, regenerates
    /// and dispatches the returned fetches.
    pub fn resolve_reported_heights(
        &mut self,
        header_store: &HeaderStore<P::HeaderStore>,
        reported: &[ClaimAt],
    ) -> ChainUpdateOutcome {
        let mut to_fetch: Vec<ClaimAt> = Vec::new();
        for &ClaimAt { txid, height } in reported {
            // `reported` carries EVERY confirmed tx in each scripthash history,
            // not just the ones whose height changed. This pass is promote-only:
            // only an `Unconfirmed` tx may move forward. Demotion is owned solely
            // by history (`update_spk_history` resets changed txs to Unconfirmed),
            // so a tx already ConfirmedUnverified or Verified is left untouched.
            let current = self.tx_store.get(&txid).map(|e| e.inclusion().clone());
            let have_header = header_store.block_hash(height);

            // Invariant: a txid has AT MOST ONE pending claim, its latest
            // server-reported height. A reorg can re-report the same tx at a
            // new height; without this cleanup an earlier claim at the old height
            // would linger and, because `on_chain_update` iterates ascending,
            // promote the tx to the wrong (lower) height, wedging it
            // ConfirmedUnverified forever (its merkle proof at the old height
            // fails). So before inserting/queueing this claim, drop `txid` from
            // every OTHER height-set.
            //
            // (A tx fully removed from the chain, `diff.removed` -> `store.remove`,
            // is not re-reported here and so keeps its stale pending entry until
            // the next CTA: `resolve_pending_claims` drops any claim whose txid is
            // absent from the tx store.)
            self.prune_pending_claim(ClaimAt { txid, height });

            match current {
                // Unconfirmed with a known header: promote and fetch its proof.
                Some(Inclusion::Unconfirmed) if have_header.is_some() => {
                    let block_hash = have_header.expect("header present");
                    Self::promote_claim(
                        &mut self.tx_store,
                        &mut self.merkle_in_flight,
                        &txid,
                        height,
                        block_hash,
                        &mut to_fetch,
                    );
                }
                // Unconfirmed but no header yet, or tx not in the store yet:
                // queue the claim for a future CTA to promote.
                Some(Inclusion::Unconfirmed) | None => {
                    self.insert_pending_claim(ClaimAt { txid, height });
                }
                // Already ConfirmedUnverified or Verified: never demote here.
                Some(_) => {}
            }
        }
        let changed = !to_fetch.is_empty();
        ChainUpdateOutcome { to_fetch, changed }
    }

    /// Re-queue the merkle fetch of every still-`ConfirmedUnverified` entry
    /// and demote `Verified` entries whose stored `block_hash` differs from
    /// the header at the same height.
    pub fn reverify_remined_entries(
        &mut self,
        header_store: &HeaderStore<P::HeaderStore>,
    ) -> ChainUpdateOutcome {
        let mut to_fetch: Vec<ClaimAt> = Vec::new();
        let mut changed = false;
        for (txid, inclusion) in self.snapshot_inclusions() {
            match inclusion {
                Inclusion::ConfirmedUnverified { height, block_hash } => {
                    match header_store.block_hash(height) {
                        // Header unchanged but the entry is still unverified:
                        // the merkle fetch is single-shot and its response may
                        // have been dropped or errored, so re-queue it, unless
                        // one is already in flight (fetch-storm guard on header
                        // bursts). A hard proof failure moves it to
                        // VerifyFailed and stops the re-queue.
                        Some(current) if current == block_hash => {
                            let claim = ClaimAt { txid, height };
                            if self.merkle_in_flight.insert(claim) {
                                to_fetch.push(claim);
                            }
                        }
                        // A reorg re-stamped this height: refresh the stored
                        // hash and re-queue the proof fetch.
                        Some(current) => {
                            let claim = ClaimAt { txid, height };
                            if self.merkle_in_flight.contains(&claim) {
                                continue;
                            }
                            self.tx_store.update_inclusion(
                                &txid,
                                Inclusion::ConfirmedUnverified {
                                    height,
                                    block_hash: current,
                                },
                            );
                            self.merkle_in_flight.insert(claim);
                            changed = true;
                            to_fetch.push(claim);
                        }
                        // Header missing (pruned): retried on a later CTA once
                        // a header is present at this height again.
                        None => {}
                    }
                }
                // A Verified proof re-stamped by a reorg (a new hash at the
                // same height), or a failed proof cleared by that same reorg,
                // both reset to ConfirmedUnverified and re-fetch. A failed
                // proof whose header hash is unchanged stays terminal: no arm
                // mutates it and it is never re-queued.
                Inclusion::Verified { height, block_hash }
                | Inclusion::VerifyFailed { height, block_hash } => {
                    if let Some(current) = header_store.block_hash(height) {
                        if current != block_hash {
                            self.tx_store.update_inclusion(
                                &txid,
                                Inclusion::ConfirmedUnverified {
                                    height,
                                    block_hash: current,
                                },
                            );
                            self.merkle_in_flight.insert(ClaimAt { txid, height });
                            changed = true;
                            to_fetch.push(ClaimAt { txid, height });
                        }
                    }
                }
                Inclusion::Unconfirmed => {}
            }
        }
        ChainUpdateOutcome { to_fetch, changed }
    }

    /// Promote pending claims whose header is now known, drop claims for txs
    /// already `Verified` at another height.
    pub fn resolve_pending_claims(
        &mut self,
        header_store: &HeaderStore<P::HeaderStore>,
    ) -> ChainUpdateOutcome {
        let tip = header_store.tip();
        let pending_snapshot = self.pending_claims_snapshot();
        let mut to_fetch: Vec<ClaimAt> = Vec::new();
        let mut changed = false;
        // Per-claim removals so we never drop a still-pending sibling.
        let mut to_remove: Vec<ClaimAt> = Vec::new();
        for (h, txids) in &pending_snapshot {
            let hash = header_store.block_hash(*h);
            let header_ready = tip.map(|t| t >= *h).unwrap_or(false) && hash.is_some();
            for txid in txids {
                let entry = self.tx_store.get(txid);
                match entry.as_ref().map(|e| e.inclusion()) {
                    None => {
                        // Absent from the tx store AND from the in-flight
                        // updates: fully removed from the chain (a reorg
                        // dropped it via `store.remove`); drop the dead claim
                        // so `pending_claims` cannot accumulate stale entries.
                        // A txid still referenced by an incomplete update is
                        // just waiting for its `Txs` response; dropping its
                        // claim then would wedge the entry Unconfirmed forever.
                        if !self.update_in_flight(txid) {
                            to_remove.push(ClaimAt {
                                txid: *txid,
                                height: *h,
                            });
                        }
                    }
                    Some(Inclusion::Verified { height, .. }) if *height != *h => {
                        // Verified elsewhere; this queued claim is dead.
                        to_remove.push(ClaimAt {
                            txid: *txid,
                            height: *h,
                        });
                    }
                    Some(Inclusion::Unconfirmed) if header_ready => {
                        if let Some(hash) = hash {
                            Self::promote_claim(
                                &mut self.tx_store,
                                &mut self.merkle_in_flight,
                                txid,
                                *h,
                                hash,
                                &mut to_fetch,
                            );
                            changed = true;
                        }
                        to_remove.push(ClaimAt {
                            txid: *txid,
                            height: *h,
                        });
                    }
                    Some(Inclusion::ConfirmedUnverified { .. })
                    | Some(Inclusion::Verified { .. })
                    | Some(Inclusion::VerifyFailed { .. }) => {
                        // Already promoted or terminally resolved by a prior
                        // pass; drop the queue entry.
                        to_remove.push(ClaimAt {
                            txid: *txid,
                            height: *h,
                        });
                    }
                    // Present but not yet confirmable (no header at this height
                    // yet): leave the claim queued for a later pass.
                    Some(Inclusion::Unconfirmed) => {}
                }
            }
        }
        for claim in &to_remove {
            self.remove_pending_claim(*claim);
        }
        ChainUpdateOutcome { to_fetch, changed }
    }

    /// True while `txid` is referenced by an incomplete update, i.e. its
    /// `Txs` response has not been folded into the tx store yet.
    fn update_in_flight(&self, txid: &Txid) -> bool {
        self.updates
            .iter()
            .any(|u| u.txs.iter().any(|(t, _)| t == txid))
    }

    /// `ClaimAt` for every `ConfirmedUnverified` entry, so the listener can
    /// re-queue their merkle fetches on (re)connect.
    pub fn confirmed_unverified_claims(&self) -> Vec<ClaimAt> {
        self.snapshot_inclusions()
            .into_iter()
            .filter_map(|(txid, inclusion)| match inclusion {
                Inclusion::ConfirmedUnverified { height, .. } => Some(ClaimAt { txid, height }),
                _ => None,
            })
            .collect()
    }

    /// Distinct spks that own at least one coin whose funding tx is still
    /// `Inclusion::Unconfirmed`. Used on listener reconnect to force a
    /// `History` refresh: `pending_claims` is an in-memory cache that a
    /// restart wipes, so without re-reporting these spks a tx already
    /// confirmed at some height would stay Unconfirmed forever.
    pub fn spks_with_unconfirmed_txs(&self) -> Vec<ScriptBuf> {
        let unconfirmed: BTreeSet<Txid> = self
            .tx_store
            .iter()
            .into_iter()
            .filter_map(|(txid, e)| matches!(e.inclusion(), Inclusion::Unconfirmed).then_some(txid))
            .collect();
        if unconfirmed.is_empty() {
            return Vec::new();
        }
        let mut spks = BTreeSet::new();
        for (op, ce) in &self.store {
            if unconfirmed.contains(&op.txid) {
                spks.insert(ce.spk());
            }
        }
        spks.into_iter().collect()
    }
}

#[derive(Debug, Clone)]
/// Represents an update to the transaction history for a script public key (SPK).
///
/// The `Update` struct contains the script public key and a list of
/// transactions that have been added or changed.
pub struct Update {
    #[allow(unused)]
    spk: ScriptBuf,
    /// Confirmation heights are not carried here: they flow through
    /// `HistoryOutcome.reported` into the pending-claims path.
    pub txs: Vec<(bitcoin::Txid, Option<bitcoin::Transaction>)>,
}

impl Update {
    /// Creates an `Update` from the differences in SPK history.
    ///
    /// # Parameters
    /// - `spk`: The script public key associated with the update.
    /// - `diff`: The differences in the SPK history.
    ///
    /// # Returns
    /// A new `Update` instance.
    pub fn from_diff(spk: ScriptBuf, diff: HistoryDiff) -> Self {
        Update {
            spk,
            txs: diff.added.into_keys().map(|txid| (txid, None)).collect(),
        }
    }

    /// Checks if the update is complete.
    ///
    /// An update is considered complete if all transactions have been
    /// received.
    ///
    /// # Returns
    /// `true` if the update is complete, otherwise `false`.
    pub fn is_complete(&self) -> bool {
        self.txs.iter().all(|(_, tx)| tx.is_some())
    }

    /// Returns a list of missing transaction IDs in the update.
    ///
    /// # Returns
    /// A vector of `Txid` representing transactions that are missing.
    pub fn missing(&self) -> Vec<Txid> {
        self.txs
            .iter()
            .filter_map(|(txid, tx)| if tx.is_none() { Some(*txid) } else { None })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a coin entry in the coin store.
///
/// The `CoinEntry` struct contains information about the coin's height,
/// status, associated coin data, and the address it belongs to.
pub struct CoinEntry {
    pub coin: Coin,
    pub address: bitcoin::Address<NetworkUnchecked>,
}

impl From<CoinEntry> for Coin {
    fn from(value: CoinEntry) -> Self {
        value.coin
    }
}

impl CoinEntry {
    /// Returns the height of the coin in the blockchain.
    ///
    /// # Returns
    /// An `Option<u64>` representing the height of the coin,
    /// or `None` if the coin is not confirmed.
    pub fn height(&self) -> Option<u64> {
        self.coin.height
    }
    /// Returns the status of the coin.
    ///
    /// # Returns
    /// The `CoinStatus` of the coin.
    pub fn status(&self) -> CoinStatus {
        self.coin.status
    }
    /// Returns a string representation of the coin's status.
    ///
    /// # Returns
    /// A string describing the coin's status.
    pub fn status_str(&self) -> String {
        format!("{:?}", self.coin.status)
    }
    /// Returns the label associated with the coin.
    ///
    /// # Returns
    /// A string representation of the coin's label, or an empty string if no label is set.
    pub fn label(&self) -> String {
        self.coin.label.clone().unwrap_or_default()
    }
    /// Returns the amount of the coin in satoshis.
    ///
    /// # Returns
    /// The value of the coin in satoshis.
    pub fn amount_sat(&self) -> u64 {
        self.coin.txout.value.to_sat()
    }
    /// Returns the amount of the coin in Bitcoin.
    ///
    /// # Returns
    /// The value of the coin in Bitcoin.
    pub fn amount_btc(&self) -> f64 {
        self.coin.txout.value.to_btc()
    }
    /// Returns a reference to the coin's outpoint.
    ///
    /// # Returns
    /// A reference to the `OutPoint` of the coin.
    pub fn outpoint(&self) -> &OutPoint {
        &self.coin.outpoint
    }
    /// Returns a string representation of the coin's outpoint.
    ///
    /// # Returns
    /// A string describing the coin's outpoint.
    pub fn outpoint_str(&self) -> String {
        self.outpoint().to_string()
    }
    /// Generate the TxIn from the coin.
    ///
    /// # Returns
    /// A `bitcoin::TxIn` representing the input transaction associated with the coin.
    pub fn txin(&self) -> bitcoin::TxIn {
        bitcoin::TxIn {
            previous_output: self.coin.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        }
    }
    /// Returns the TxOut of this coin.
    ///
    /// # Returns
    /// A `bitcoin::TxOut` representing the output transaction associated with the coin.
    pub fn txout(&self) -> bitcoin::TxOut {
        self.coin.txout.clone()
    }
    /// Returns the derivation path associated with the coin.
    ///
    /// # Returns
    /// A tuple containing the `AddrAccount` and the index of the coin's derivation path.
    /// Returns `None` for non-descriptor coins (e.g., Silent Payment coins).
    pub fn deriv(&self) -> Option<(KeyChain, u32)> {
        match &self.coin.spend_info {
            CoinSpendInfo::Bip32 { coin_path, .. } => Some(*coin_path),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
    /// Returns a boxed version of the coin entry.
    ///
    /// # Returns
    /// A `Box` containing the coin entry.
    pub fn boxed(&self) -> Box<CoinEntry> {
        Box::new(self.clone())
    }
    /// Returns the address associated with the coin.
    ///
    /// # Returns
    /// A string representation of the coin's address.
    pub fn address(&self) -> String {
        self.address.clone().assume_checked().to_string()
    }
    /// Returns the address associated with the coin as an 'RustAddress'
    ///
    /// # Returns
    /// A boxed AddressEntry representation of the coin's address.
    /// Panics for non-descriptor coins.
    pub fn rust_address(&self) -> AddressEntry {
        let (account, index) = match &self.coin.spend_info {
            CoinSpendInfo::Bip32 { coin_path, .. } => *coin_path,
            #[allow(unreachable_patterns)]
            _ => panic!("rust_address not supported for non-descriptor coins"),
        };
        AddressEntry {
            status: AddressStatus::Unknown,
            address: self.address.clone(),
            account,
            index,
            funding_txids: std::collections::BTreeSet::new(),
            spending_txids: std::collections::BTreeSet::new(),
        }
    }
    /// Returns the script public key (SPK) associated with the coin.
    ///
    /// # Returns
    /// The `ScriptBuf` representing the coin's SPK.
    pub fn spk(&self) -> ScriptBuf {
        self.address.clone().assume_checked().script_pubkey()
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    //! Coverage for the per-address tx-history population in
    //! [`CoinStore::generate`]. Constructs a CoinStore directly
    //! with a NoopBackend (no electrsd, no listener thread) and
    //! drives funding/spending txs through the in-memory
    //! [`TxStore`].
    use super::*;
    use bwk_descriptor::wpkh_path;
    use bwk_sign::{bip39::Mnemonic, HotSigner};
    use bwk_utils::test::{funding_tx, spending_tx};
    use miniscript::bitcoin::bip32::ChildNumber;
    use std::sync::mpsc;

    fn build_coin_store() -> (CoinStore, SpkDerivator) {
        let network = bitcoin::Network::Regtest;
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(network, &mnemo.to_string()).unwrap();
        let path = wpkh_path(network, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        let xpub = signer.xpub(&path);
        let derivator = SpkDerivator::new_wpkh(xpub, network).unwrap();
        let descriptor = derivator.descriptor();

        let (notif_sender, _notif_recv) = mpsc::channel();
        let tx_store = TxStore::new();
        let label_store = Arc::new(Mutex::new(LabelStore::new()));
        let mock_backend: Arc<dyn bwk_persist::PersistenceBackend> =
            Arc::new(bwk_persist::NoopBackend);
        let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
            mock_backend,
            bwk_persist::ACCOUNT_STORE_KEY,
            crate::profile::encode_account_key,
            crate::profile::encode_account_value,
        )));
        let cs = CoinStore::new(
            network,
            descriptor,
            notif_sender,
            0, // recv_tip
            0, // change_tip
            5, // look_ahead: populates spk indices 0..=5
            tx_store,
            label_store,
            account_store,
        );
        (cs, derivator)
    }

    /// A server can hand back a tx whose input names a vout the funding tx
    /// does not have. The prevout is recorded as unowned with no value.
    #[test]
    fn an_input_naming_a_missing_vout_is_skipped() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(1);
        let funding = funding_tx(spk.clone(), 0.5);
        let funding_txid = funding.compute_txid();
        let vouts = funding.output.len() as u32;

        let spend = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(bitcoin::absolute::Height::ZERO),
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint::new(funding_txid, vouts),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence(0xFFFFFFFF),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let spend_txid = spend.compute_txid();
        cs.tx_store
            .update(crate::tx_store::TxEntry::for_test(funding));
        cs.tx_store
            .update(crate::tx_store::TxEntry::for_test(spend));

        cs.generate();

        let entry = cs.tx_store.get(&spend_txid).expect("the spend is stored");
        assert_eq!(entry.inputs.len(), 1);
        let input = entry.inputs.get(&0).expect("the input is populated");
        assert!(!input.owned, "an unresolvable prevout cannot be owned");
        assert_eq!(input.value, None);
    }

    #[test]
    fn funding_txids_empty_for_unused_address() {
        let (mut cs, deriv) = build_coin_store();
        cs.generate();
        let spk = deriv.receive_spk_at(2);
        let entry = cs.address_info(&spk).expect("populated by look-ahead");
        assert_eq!(entry.status(), AddressStatus::NotUsed);
        assert!(entry.funding_txids().is_empty());
        assert!(entry.spending_txids().is_empty());
    }

    #[test]
    fn funding_txids_single_for_used_address() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx));
        cs.generate();
        let entry = cs.address_info(&spk).expect("entry");
        assert_eq!(entry.status(), AddressStatus::Used);
        assert_eq!(entry.funding_txids().len(), 1);
        assert!(entry.funding_txids().contains(&txid));
        assert!(entry.spending_txids().is_empty());
    }

    #[test]
    fn funding_txids_multiple_for_reused_address() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx_a = funding_tx(spk.clone(), 0.5);
        let tx_b = funding_tx(spk.clone(), 0.25);
        let (txid_a, txid_b) = (tx_a.compute_txid(), tx_b.compute_txid());
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx_a));
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx_b));
        cs.generate();
        let entry = cs.address_info(&spk).expect("entry");
        assert_eq!(entry.status(), AddressStatus::Reused);
        assert_eq!(entry.funding_txids().len(), 2);
        assert!(entry.funding_txids().contains(&txid_a));
        assert!(entry.funding_txids().contains(&txid_b));
    }

    #[test]
    fn complete_output_reclassified_after_address_expansion() {
        let (mut cs, deriv) = build_coin_store();
        let index = cs.change_watch_tip() + 1;
        let spk = deriv.change_spk_at(index);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        let vout = tx.output.len() - 1;
        let outpoint = OutPoint {
            txid,
            vout: vout as u32,
        };
        cs.tx_store.update(TxEntry::for_test(tx));

        cs.generate();
        let entry = cs.tx_store.get(&txid).unwrap();
        assert!(entry.is_complete());
        assert!(!entry.outputs.get(&vout).unwrap().owned);
        assert!(!cs.coins().contains_key(&outpoint));

        cs.new_change_addr();

        assert!(
            cs.tx_store
                .get(&txid)
                .unwrap()
                .outputs
                .get(&vout)
                .unwrap()
                .owned
        );
        assert!(cs.coins().contains_key(&outpoint));
    }

    #[test]
    fn change_tip_updater_repairs_metadata_and_coin_view() {
        let (mut cs, deriv) = build_coin_store();
        let index = cs.change_watch_tip() + 1;
        let tx = funding_tx(deriv.change_spk_at(index), 0.5);
        let txid = tx.compute_txid();
        let vout = tx.output.len() - 1;
        let outpoint = OutPoint::new(txid, vout as u32);
        cs.tx_store.update(TxEntry::for_test(tx));
        cs.generate();
        assert!(!cs.tx_store.get(&txid).unwrap().outputs[&vout].owned);

        let cs = Arc::new(Mutex::new(cs));
        assert_eq!(ChangeTipUpdater::new(cs.clone()).next_index(), 1);

        let cs = cs.lock().unwrap();
        assert!(cs.tx_store.get(&txid).unwrap().outputs[&vout].owned);
        assert!(cs.coins().contains_key(&outpoint));
    }

    #[test]
    fn complete_input_refreshed_when_parent_arrives() {
        let (mut cs, deriv) = build_coin_store();
        let parent = funding_tx(deriv.receive_spk_at(2), 0.5);
        let parent_txid = parent.compute_txid();
        let outpoint = OutPoint {
            txid: parent_txid,
            vout: (parent.output.len() - 1) as u32,
        };
        let child = spending_tx(outpoint);
        let child_txid = child.compute_txid();
        cs.tx_store.update(TxEntry::for_test(child));

        cs.generate();
        let entry = cs.tx_store.get(&child_txid).unwrap();
        assert!(entry.is_complete());
        assert_eq!(entry.inputs.get(&0).unwrap().value, None);
        assert!(!entry.inputs.get(&0).unwrap().owned);

        cs.tx_store.update(TxEntry::for_test(parent));
        cs.generate();

        let input = cs
            .tx_store
            .get(&child_txid)
            .unwrap()
            .inputs
            .get(&0)
            .unwrap()
            .clone();
        assert_eq!(input.value, Some(50_000_000));
        assert!(input.owned);
    }

    #[test]
    fn known_tx_history_extension_repairs_metadata_and_coin_view() {
        let (mut cs, deriv) = build_coin_store();
        let index = cs.change_watch_tip() + 2;
        let spk = deriv.change_spk_at(index);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        let vout = tx.output.len() - 1;
        let outpoint = OutPoint {
            txid,
            vout: vout as u32,
        };
        cs.tx_store.update(TxEntry::for_test(tx));
        cs.generate();
        assert!(
            !cs.tx_store
                .get(&txid)
                .unwrap()
                .outputs
                .get(&vout)
                .unwrap()
                .owned
        );

        let outcome = cs.handle_history_response(BTreeMap::from([(spk, vec![(txid, None)])]));

        assert!(outcome.missing_txs.is_empty());
        assert!(
            cs.tx_store
                .get(&txid)
                .unwrap()
                .outputs
                .get(&vout)
                .unwrap()
                .owned
        );
        assert!(cs.coins().contains_key(&outpoint));
        assert_eq!(cs.spendable_coins().unconfirmed_balance, 50_000_000);
    }

    #[test]
    fn spending_txids_empty_when_unspent() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(3);
        let tx = funding_tx(spk.clone(), 0.5);
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx));
        cs.generate();
        let entry = cs.address_info(&spk).expect("entry");
        assert!(entry.spending_txids().is_empty());
    }

    #[test]
    fn spending_txids_recorded_when_outpoint_consumed() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(4);

        // Fund index 4.
        let funding = funding_tx(spk.clone(), 0.5);
        let funding_txid = funding.compute_txid();
        // The spk we paid is at the LAST output (funding_tx appends it).
        let funded_vout = (funding.output.len() - 1) as u32;
        cs.tx_store
            .update(crate::tx_store::TxEntry::for_test(funding));

        // Spend the freshly-funded outpoint.
        let outpoint = OutPoint {
            txid: funding_txid,
            vout: funded_vout,
        };
        let spending = spending_tx(outpoint);
        let spending_txid = spending.compute_txid();
        cs.tx_store
            .update(crate::tx_store::TxEntry::for_test(spending));

        cs.generate();
        let entry = cs.address_info(&spk).expect("entry");
        assert_eq!(entry.spending_txids().len(), 1);
        assert!(entry.spending_txids().contains(&spending_txid));
        // Funding still recorded too.
        assert!(entry.funding_txids().contains(&funding_txid));
    }

    fn dummy_block_hash() -> bitcoin::BlockHash {
        use std::str::FromStr;
        bitcoin::BlockHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap()
    }

    /// Helper: fund spk at index 2, set the funding tx's inclusion to
    /// `inclusion`, regenerate, and return the resulting status of the
    /// single produced coin.
    fn status_for_inclusion(inclusion: Inclusion) -> CoinStatus {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx));
        cs.tx_store.update_inclusion(&txid, inclusion);
        cs.generate();
        let coins = cs.coins();
        assert_eq!(coins.len(), 1);
        coins.into_iter().next().unwrap().1.status()
    }

    #[test]
    fn unconfirmed_inclusion_yields_unconfirmed_status() {
        assert_eq!(
            status_for_inclusion(Inclusion::Unconfirmed),
            CoinStatus::Unconfirmed
        );
    }

    #[test]
    fn claimed_inclusion_yields_confirmed_unverified_status() {
        assert_eq!(
            status_for_inclusion(Inclusion::ConfirmedUnverified {
                height: 100,
                block_hash: dummy_block_hash(),
            }),
            CoinStatus::ConfirmedUnverified
        );
    }

    #[test]
    fn verified_inclusion_yields_confirmed_status() {
        assert_eq!(
            status_for_inclusion(Inclusion::Verified {
                height: 100,
                block_hash: dummy_block_hash(),
            }),
            CoinStatus::Confirmed
        );
    }

    #[test]
    fn verify_failed_inclusion_yields_unconfirmed_status() {
        assert_eq!(
            status_for_inclusion(Inclusion::VerifyFailed {
                height: 100,
                block_hash: dummy_block_hash(),
            }),
            CoinStatus::Unconfirmed
        );
    }

    // Regression: a ConfirmedUnverified coin is in the spendable set, so it
    // must be counted in the confirmed balance, not silently dropped from
    // both balance buckets.
    #[test]
    fn confirmed_unverified_counts_in_confirmed_balance() {
        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx));
        cs.tx_store.update_inclusion(
            &txid,
            Inclusion::ConfirmedUnverified {
                height: 100,
                block_hash: dummy_block_hash(),
            },
        );
        cs.generate();

        let state = cs.spendable_coins();
        assert_eq!(state.coins.len(), 1);
        assert_eq!(state.confirmed_coins, 1);
        assert_eq!(state.confirmed_balance, 50_000_000);
        assert_eq!(state.unconfirmed_coins, 0);
        assert_eq!(state.unconfirmed_balance, 0);
    }

    // Regression: a tx queued in pending_claims that falls back to the
    // mempool must be dropped from the queue, so syncing its header does not
    // re-promote it at the stale height.
    #[test]
    fn demoted_tx_is_not_repromoted_from_stale_pending_claim() {
        use miniscript::bitcoin::{
            block::{Header, Version},
            consensus::serialize,
            hashes::Hash,
            CompactTarget, TxMerkleNode,
        };

        let (mut cs, deriv) = build_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.5);
        let txid = tx.compute_txid();
        cs.tx_store.update(crate::tx_store::TxEntry::for_test(tx));

        // Server reports the tx confirmed at height H. With no synced header,
        // resolve_reported_heights queues it and leaves it Unconfirmed.
        let height = 200u32;
        cs.update_spk_history(spk.clone(), vec![(txid, Some(height as u64))]);
        let no_header = HeaderStore::new_in_memory(bitcoin::Network::Regtest);
        cs.resolve_reported_heights(&no_header, &[ClaimAt { txid, height }]);
        assert!(cs
            .pending_claims_snapshot()
            .get(&height)
            .is_some_and(|set| set.contains(&txid)));
        assert_eq!(
            cs.tx_store.get(&txid).unwrap().inclusion(),
            &Inclusion::Unconfirmed
        );

        // The tx falls back to the mempool: its stale pending claim is dropped.
        cs.update_spk_history(spk.clone(), vec![(txid, None)]);
        assert!(cs.pending_claims_snapshot().is_empty());

        // Now header H is synced. With the claim gone, resolve_pending_claims
        // has nothing to promote: the tx stays Unconfirmed.
        let hdr = Header {
            version: Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let raw: [u8; Header::SIZE] = serialize(&hdr).try_into().expect("header is 80 bytes");
        let synced =
            HeaderStore::from_map(bitcoin::Network::Regtest, BTreeMap::from([(height, raw)]));
        cs.resolve_pending_claims(&synced);
        assert_eq!(
            cs.tx_store.get(&txid).unwrap().inclusion(),
            &Inclusion::Unconfirmed
        );

        cs.generate();
        let state = cs.spendable_coins();
        assert_eq!(state.confirmed_balance, 0);
        assert_eq!(state.unconfirmed_balance, 50_000_000);
    }
}
