use bwk_coin::{ChangeTip, KeyChain};
use bwk_descriptor::derivator::SpkDerivator;
use bwk_persist::Store;
use miniscript::bitcoin::{self, address::NetworkUnchecked, Script, ScriptBuf, Txid};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{mpsc, Arc, Mutex},
};

use crate::{
    config::Tip,
    notification::Notification,
    profile::{DefaultBackend, RamProfile, ScanProfile},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AddressStatus {
    NotUsed,
    Used,
    Reused,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
/// Represents the current tip of address generation for receiving and change.
///
/// # Fields
/// - `recv`: Last generated receiving address index.
/// - `change`: Last generated change address index.
pub struct AddressTip {
    pub recv: u32,
    pub change: u32,
}

pub struct ChangeTipUpdater<P: ScanProfile = RamProfile<DefaultBackend>>(
    Arc<Mutex<AddressStore<P>>>,
);

impl<P: ScanProfile> Clone for ChangeTipUpdater<P> {
    fn clone(&self) -> Self {
        ChangeTipUpdater(self.0.clone())
    }
}

impl<P: ScanProfile> ChangeTipUpdater<P> {
    pub fn new(store: Arc<Mutex<AddressStore<P>>>) -> Self {
        ChangeTipUpdater(store)
    }
}

impl<P: ScanProfile> ChangeTip for ChangeTipUpdater<P> {
    fn next_index(&mut self) -> u32 {
        self.0.lock().expect("poisoned").next_change_index()
    }
}

/// Manages storage and generation of Bitcoin addresses.
///
/// Tracks generated receiving and change addresses, notifies listeners,
/// and populates addresses as needed.
///
/// # Fields
/// - `store`: Map of script public keys to address entries.
/// - `recv_generated_tip`: Last generated receiving address index.
/// - `change_generated_tip`: Last generated change address index.
/// - `signer`: Signer used to generate new addresses.
/// - `notification`: Channel for sending notifications about address
///   tips changes.
/// - `tx_listener`: Optional channel for sending address tip changes.
/// - `look_ahead`: Number of addresses to generate ahead of the current tip.
pub struct AddressStore<P: ScanProfile = RamProfile<DefaultBackend>> {
    store: BTreeMap<ScriptBuf, AddressEntry>,
    recv_generated_tip: u32,
    change_generated_tip: u32,
    derivator: SpkDerivator,
    notification: mpsc::Sender<Notification>,
    tx_listener: Option<mpsc::Sender<AddressTip>>,
    look_ahead: u32,
    account_store: Arc<Mutex<P::AccountStore>>,
}

impl<P: ScanProfile> std::fmt::Debug for AddressStore<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressStore")
            .field("store_len", &self.store.len())
            .field("recv_generated_tip", &self.recv_generated_tip)
            .field("change_generated_tip", &self.change_generated_tip)
            .field("look_ahead", &self.look_ahead)
            .finish()
    }
}

impl AddressStore<RamProfile<DefaultBackend>> {
    /// Convenience constructor for the default RAM profile: wraps a
    /// noop-backed [`RamStore`](bwk_persist::RamStore) as the `AccountStore`
    /// so tests can use `AddressStore::new(...)` without threading a full
    /// profile.
    pub fn new(
        derivator: SpkDerivator,
        notification: mpsc::Sender<Notification>,
        recv_tip: u32,
        change_tip: u32,
        look_ahead: u32,
    ) -> Self {
        use bwk_persist::{NoopBackend, RamStore};
        use std::sync::Arc;
        let noop: Arc<dyn bwk_persist::PersistenceBackend> = Arc::new(NoopBackend);
        let account_store = Arc::new(Mutex::new(RamStore::empty(
            noop,
            bwk_persist::ACCOUNT_STORE_KEY,
            crate::profile::encode_account_key,
            crate::profile::encode_account_value,
        )));
        Self::with_account_store(
            derivator,
            notification,
            recv_tip,
            change_tip,
            look_ahead,
            account_store,
        )
    }
}

impl<P: ScanProfile> AddressStore<P> {
    /// Creates a new `AddressStore` wrapping the given account-store
    /// `Arc<Mutex<_>>` (used to persist the `Tip` singleton).
    pub fn with_account_store(
        derivator: SpkDerivator,
        notification: mpsc::Sender<Notification>,
        recv_tip: u32,
        change_tip: u32,
        look_ahead: u32,
        account_store: Arc<Mutex<P::AccountStore>>,
    ) -> Self {
        let mut store = Self {
            derivator,
            store: BTreeMap::new(),
            recv_generated_tip: recv_tip,
            change_generated_tip: change_tip,
            notification,
            tx_listener: None,
            look_ahead,
            account_store,
        };
        store.populate_maybe();
        store.update_watch_tip();

        store
    }

    /// Notifies [`Account`] owner of address tip changes.
    ///
    /// This method sends a notification to the channel and updates the watch tip.
    fn notify(&self) {
        if let Err(e) = self.notification.send(Notification::AddressTipChanged) {
            log::error!("AddressStore::notify() fail to send notification: {e:?}");
        }
        self.update_watch_tip();
    }

    /// Updates the watch tip for receiving and change addresses.
    ///
    /// This method sends the current address tips to the transaction listener.
    fn update_watch_tip(&self) {
        if let Some(tx_listener) = &self.tx_listener {
            let recv = self.recv_watch_tip();
            let change = self.change_watch_tip();
            // NOTE: tx_listener thread must send notification itself if
            // fail to connect to electrum
            let _ = tx_listener.send(AddressTip { recv, change });
        }
        let mut store = self.account_store.lock().expect("poisoned");
        Tip::persist(
            &mut *store,
            self.recv_generated_tip,
            self.change_generated_tip,
        );
        // Write the tip through the RamStore write-back so it survives a
        // restart; without this the account store stays dirty in RAM only
        // and the tip reloads as 0.
        if let Err(e) = store.flush() {
            log::error!("AddressStore::update_watch_tip(): account store flush: {e}");
        }
    }

    /// Processes a received coin at the specified script public key.
    ///
    /// # Parameters
    /// - `spk`: The script public key of the received coin.
    ///
    /// A coin reported for a script outside the regenerated store (e.g. a
    /// stale persisted subscription past the restored watch window) extends
    /// the store to cover that script rather than panicking. A script that is
    /// not derivable within the recovery window is logged and ignored.
    pub fn recv_coin_at(&mut self, spk: &ScriptBuf) {
        if let Some(AddressEntry { account, index, .. }) = self.store.get(spk) {
            let (account, index) = (*account, *index);
            match account {
                KeyChain::Receive => self.update_recv(index),
                KeyChain::Change => self.update_change(index),
                KeyChain::Custom(_) => unimplemented!(),
            }
            return;
        }
        match self.locate_spk(spk) {
            Some((KeyChain::Receive, index)) => self.update_recv(index),
            Some((KeyChain::Change, index)) => self.update_change(index),
            Some((KeyChain::Custom(_), _)) => unimplemented!(),
            None => log::error!(
                "AddressStore::recv_coin_at(): spk {spk:?} absent from store and not derivable \
                 within the recovery window; ignoring"
            ),
        }
    }

    /// Locates the keychain and index of `spk` by deriving past the current
    /// watch window. Backs [`Self::recv_coin_at`] when a coin is reported for
    /// a script the store has not generated yet. Bounded by `RECOVER_GAP` so a
    /// foreign script cannot spin forever.
    fn locate_spk(&self, spk: &ScriptBuf) -> Option<(KeyChain, u32)> {
        const RECOVER_GAP: u32 = 10_000;
        let recv_start = self.recv_watch_tip().saturating_add(1);
        let recv_end = recv_start.saturating_add(RECOVER_GAP);
        for i in recv_start..=recv_end {
            if self.derivator.receive_at(i).script_pubkey() == *spk {
                return Some((KeyChain::Receive, i));
            }
        }
        let change_start = self.change_watch_tip().saturating_add(1);
        let change_end = change_start.saturating_add(RECOVER_GAP);
        for i in change_start..=change_end {
            if self.derivator.change_at(i).script_pubkey() == *spk {
                return Some((KeyChain::Change, i));
            }
        }
        None
    }

    /// Populates the address store with addresses up to the current watch tips.
    ///
    /// This method generates receiving and change addresses and adds them if not present.
    pub fn populate_maybe(&mut self) {
        for i in 0..self.recv_watch_tip() + 1 {
            let addr = self.derivator.receive_at(i);
            let script = addr.script_pubkey();
            self.store.entry(script).or_insert_with(|| {
                let address = addr.as_unchecked().clone();
                AddressEntry {
                    status: AddressStatus::NotUsed,
                    address,
                    account: KeyChain::Receive,
                    index: i,
                    funding_txids: BTreeSet::new(),
                    spending_txids: BTreeSet::new(),
                }
            });
        }
        for i in 0..self.change_watch_tip() + 1 {
            let addr = self.derivator.change_at(i);
            let script = addr.script_pubkey();
            self.store.entry(script).or_insert_with(|| {
                let address = addr.as_unchecked().clone();
                AddressEntry {
                    status: AddressStatus::NotUsed,
                    address,
                    account: KeyChain::Change,
                    index: i,
                    funding_txids: BTreeSet::new(),
                    spending_txids: BTreeSet::new(),
                }
            });
        }
    }

    /// Updates the receiving address tip and populates addresses if necessary.
    ///
    /// # Parameters
    /// - `index`: The new index for the receiving address.
    pub fn update_recv(&mut self, index: u32) {
        if index > self.recv_generated_tip {
            self.recv_generated_tip = index;
        }
        self.populate_maybe();
        self.notify();
    }
    /// Updates the change address tip and populates addresses if necessary.
    ///
    /// # Parameters
    /// - `index`: The new index for the change address.
    pub fn update_change(&mut self, index: u32) {
        if index > self.change_generated_tip {
            self.change_generated_tip = index;
        }
        self.populate_maybe();
        self.notify();
    }

    /// Generates a new receiving address and updates the receiving address tip.
    ///
    /// # Returns
    /// The newly generated receiving address.
    pub fn new_recv_addr(&mut self) -> bitcoin::Address {
        self.recv_generated_tip += 1;
        self.update_recv(self.recv_generated_tip);
        self.derivator.receive_at(self.recv_generated_tip)
    }

    /// Generates a new change address and updates the change address tip.
    ///
    /// # Returns
    /// The newly generated change address.
    pub fn new_change_addr(&mut self) -> bitcoin::Address {
        let index = self.next_change_index();
        self.derivator.change_at(index)
    }

    pub fn next_change_index(&mut self) -> u32 {
        self.change_generated_tip += 1;
        let index = self.change_generated_tip;
        self.update_change(index);
        index
    }

    /// Returns the current change watch tip index.
    ///
    /// The watch tip is the index of the last generated change address plus
    /// the look-ahead.
    ///
    /// # Returns
    /// The current change watch tip index.
    pub fn change_watch_tip(&self) -> u32 {
        self.change_generated_tip + self.look_ahead + 1
    }

    /// Returns the current receiving watch tip index.
    ///
    /// The watch tip is the index of the last generated receiving address
    /// plus the look-ahead.
    ///
    /// # Returns
    /// The current receiving watch tip index.
    pub fn recv_watch_tip(&self) -> u32 {
        self.recv_generated_tip + self.look_ahead + 1
    }

    /// Returns the current receiving address tip index.
    ///
    /// # Returns
    /// The current receiving address tip index.
    pub fn recv_tip(&self) -> u32 {
        self.recv_generated_tip
    }

    /// Initializes the address store with a transaction poller.
    ///
    /// This method populates the address store and sets the transaction
    /// poller channel.
    ///
    /// # Parameters
    /// - `tx_listener`: The channel for sending address tips to the poller.
    pub fn init(&mut self, tx_listener: mpsc::Sender<AddressTip>) {
        self.populate_maybe();
        self.tx_listener = Some(tx_listener);
        self.notify();
    }

    /// Retrieves an address entry by its script public key.
    ///
    /// # Parameters
    /// - `spk`: The script public key of the address entry.
    ///
    /// # Returns
    /// An `Option<AddressEntry>` containing the address entry if found,
    /// or `None` if not.
    pub fn get_entry(&self, spk: &Script) -> Option<AddressEntry> {
        self.store.get(spk).cloned()
    }

    /// Retrieves a mutable reference to an address entry by its script
    /// public key.
    ///
    /// # Parameters
    /// - `spk`: The script public key of the address entry.
    ///
    /// # Returns
    /// An `Option<&mut AddressEntry>` containing a mutable reference to
    /// the address entry if found, or `None` if not.
    pub fn get_entry_mut(&mut self, spk: &Script) -> Option<&mut AddressEntry> {
        self.store.get_mut(spk)
    }

    /// Retrieves all unused receiving addresses.
    ///
    /// This method filters the address store for addresses that are not
    /// used and belong to the receiving account.
    ///
    /// # Returns
    /// An `Addresses` object containing all unused receiving addresses.
    pub fn get_unused(&self) -> Vec<AddressEntry> {
        let mut addrs = self
            .store
            .clone()
            .into_iter()
            .filter_map(|(_, entry)| {
                if entry.status == AddressStatus::NotUsed && entry.account == KeyChain::Receive {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        addrs.sort_by(|a, b| {
            a.account
                .cmp(&b.account)
                .then_with(|| a.index.cmp(&b.index))
        });
        addrs.into_iter().collect()
    }

    /// Retrieves all addresses for a specific account type.
    ///
    /// # Parameters
    /// - `account`: The account type (receiving or change).
    ///
    /// # Returns
    /// An `Addresses` object containing all addresses for the specified
    /// account type.
    pub fn get(&self, account: KeyChain) -> Vec<AddressEntry> {
        let mut addrs = self
            .store
            .clone()
            .into_iter()
            .filter_map(|(_, entry)| {
                if entry.account == account {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        addrs.sort_by(|a, b| {
            a.account
                .cmp(&b.account)
                .then_with(|| a.index.cmp(&b.index))
        });
        addrs.into_iter().collect()
    }

    /// Dumps the address store as a JSON value.
    ///
    /// # Returns
    /// A `Result` containing the serialized JSON value of the address store
    /// or an error if serialization fails.
    pub fn dump(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.store)
    }

    /// Restores the address store from a JSON value.
    ///
    /// # Parameters
    /// - `value`: The JSON value to restore the address store from.
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the restoration.
    pub fn restore(&mut self, value: serde_json::Value) -> Result<(), serde_json::Error> {
        self.store = serde_json::from_value(value)?;
        Ok(())
    }

    pub fn contains_spk(&self, spk: &ScriptBuf) -> bool {
        self.store.contains_key(spk)
    }

    /// Snapshot of every entry currently in the store. Cloned, so
    /// callers don't hold a borrow on the underlying map.
    pub fn entries(&self) -> Vec<AddressEntry> {
        self.store.values().cloned().collect()
    }

    pub fn get_generated_addresses(
        &self,
    ) -> (
        Vec<AddressEntry>, /* receive */
        Vec<AddressEntry>, /* change */
    ) {
        let mut recv = self
            .store
            .iter()
            .filter_map(|(_, entry)| {
                (entry.account == KeyChain::Receive && entry.index <= self.recv_generated_tip)
                    .then_some(entry)
            })
            .cloned()
            .collect::<Vec<_>>();
        recv.sort_by(|a, b| a.index.cmp(&b.index));
        let mut change = self
            .store
            .iter()
            .filter_map(|(_, entry)| {
                (entry.account == KeyChain::Change && entry.index <= self.change_generated_tip)
                    .then_some(entry)
            })
            .cloned()
            .collect::<Vec<_>>();
        change.sort_by(|a, b| a.index.cmp(&b.index));
        (recv, change)
    }
}

/// Represents an entry in the address store.
///
/// The `AddressEntry` contains information about a specific address, including its
/// status, account type, and index.
///
/// # Fields
/// - `status`: The status of the address (used, unused, etc.).
/// - `address`: The Bitcoin address associated with this entry.
/// - `account`: The account type (receiving or change).
/// - `index`: The index of the address in the generation sequence.
/// - `funding_txids`: txids of transactions that paid INTO this
///   address. Derived from the live coin map by
///   [`crate::coin_store::CoinStore::generate`]; rebuilt on every
///   generate call rather than stored independently.
/// - `spending_txids`: txids of transactions that SPENT outputs
///   paid to this address (i.e. an output at this spk appeared as
///   a `previous_output` of one of the tx's inputs). Same provenance
///   as `funding_txids`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub status: AddressStatus,
    pub address: bitcoin::Address<NetworkUnchecked>,
    pub account: KeyChain,
    pub index: u32,
    #[serde(default)]
    pub funding_txids: BTreeSet<Txid>,
    #[serde(default)]
    pub spending_txids: BTreeSet<Txid>,
}

impl AddressEntry {
    /// Returns the script public key of the address.
    ///
    /// # Returns
    /// The script public key associated with this entry.
    pub fn script(&self) -> ScriptBuf {
        self.address.clone().assume_checked().script_pubkey()
    }
    /// Sets the status of the address entry.
    ///
    /// # Parameters
    /// - `status`: The new status to set for this entry.
    ///
    /// # Note
    /// The status is based on the Electrum protocol.
    /// https://electrumx.readthedocs.io/en/latest/protocol-basics.html#status
    pub fn set_status(&mut self, status: AddressStatus) {
        self.status = status;
    }
    /// Returns the status of the address entry.
    ///
    /// # Returns
    /// The current status of this entry.
    pub fn status(&self) -> AddressStatus {
        self.status
    }
    /// Replace the set of funding txids (txs that paid into this
    /// address). Called from [`crate::coin_store::CoinStore::generate`]
    /// after rebuilding the in-memory coin map.
    pub fn set_funding_txids(&mut self, txids: BTreeSet<Txid>) {
        self.funding_txids = txids;
    }
    /// Returns the set of funding txids for this address.
    pub fn funding_txids(&self) -> &BTreeSet<Txid> {
        &self.funding_txids
    }
    /// Replace the set of spending txids (txs that consumed an
    /// output paid to this address). Called from
    /// [`crate::coin_store::CoinStore::generate`] alongside
    /// [`Self::set_funding_txids`].
    pub fn set_spending_txids(&mut self, txids: BTreeSet<Txid>) {
        self.spending_txids = txids;
    }
    /// Returns the set of spending txids for this address.
    pub fn spending_txids(&self) -> &BTreeSet<Txid> {
        &self.spending_txids
    }
    /// Returns the string representation of the address.
    ///
    /// # Returns
    /// The address as a string.
    pub fn value(&self) -> String {
        self.address.clone().assume_checked().to_string()
    }
    /// Returns the account type of the address entry.
    ///
    /// # Returns
    /// The account type (receiving or change) of this entry.
    pub fn account(&self) -> KeyChain {
        self.account
    }
    /// Returns the account type as a u32 value.
    ///
    /// # Returns
    /// `0` for receiving and `1` for change accounts.
    pub fn account_u32(&self) -> u32 {
        match self.account {
            KeyChain::Receive => 0,
            KeyChain::Change => 1,
            KeyChain::Custom(c) => c,
        }
    }
    /// Returns the index of the address entry.
    ///
    /// # Returns
    /// The derivation index of this address.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// Returns the Bitcoin address associated with this entry.
    ///
    /// # Returns
    /// The Bitcoin address of this entry.
    pub fn address(&self) -> bitcoin::Address<NetworkUnchecked> {
        self.address.clone()
    }

    /// Clones the address entry and returns it as a boxed instance.
    ///
    /// # Returns
    /// A `Box<Self>` containing the cloned address entry.
    pub fn clone_boxed(&self) -> Box<Self> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bwk_descriptor::{derivator::SpkDerivator, tr_path};
    use bwk_sign::HotSigner;
    use bwk_tx::{ChangeRecipientProvider, FinalizationContext, PsbtOutputInfo, RecipientProvider};
    use miniscript::bitcoin::{bip32::ChildNumber, Network};

    fn test_derivator() -> SpkDerivator {
        let nw = Network::Regtest;
        let signer = HotSigner::new(nw).unwrap();
        let path = tr_path(nw, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        let xpub = signer.xpub(&path);
        SpkDerivator::new_tr(xpub, nw).unwrap()
    }

    #[test]
    fn change_recipient_provider_tracks_correct_index() {
        let (tx, _rx) = mpsc::channel();
        let network = Network::Regtest;
        let derivator = test_derivator();
        let descriptor = derivator.descriptor();

        // Create AddressStore with change_generated_tip = 5
        let store = AddressStore::new(
            derivator, tx, 0,  // recv_tip
            5,  // change_tip - start at index 5
            20, // look_ahead
        );
        let store = Arc::new(Mutex::new(store));

        let tip_updater = ChangeTipUpdater::new(store);
        let mut provider =
            ChangeRecipientProvider::new_with_updater(tip_updater, descriptor, network);

        // Create a dummy finalization context
        let ctx = FinalizationContext {
            inputs: &[],
            partial_secret: None,
            network,
        };

        // Call create_script - this should use index 6 (5 + 1)
        let _script = provider.create_script(&ctx);

        // Verify psbt_output_info returns the correct index
        let info = provider.psbt_output_info();
        match info {
            PsbtOutputInfo::Bip32 { origin, .. } => {
                assert_eq!(origin.0, KeyChain::Change);
                assert_eq!(origin.1, 6, "Expected change index 6, got {}", origin.1);
            }
            _ => panic!("Expected PsbtOutputInfo::Bip32"),
        }

        // Call create_script again - should use index 7
        let _script2 = provider.create_script(&ctx);
        let info2 = provider.psbt_output_info();
        match info2 {
            PsbtOutputInfo::Bip32 { origin, .. } => {
                assert_eq!(origin.1, 7, "Expected change index 7, got {}", origin.1);
            }
            _ => panic!("Expected PsbtOutputInfo::Bip32"),
        }
    }

    #[test]
    fn get_generated_addresses_returns_freshly_generated_receive() {
        // Regression test for the receive bound bug: the RECEIVE filter must
        // compare against recv_generated_tip, not change_generated_tip. With
        // recv tip bumped (here index 1) while change tip stays at 0, the
        // newly-generated receive address must still be returned.
        let (tx, _rx) = mpsc::channel();
        let derivator = test_derivator();

        let mut store = AddressStore::new(
            derivator, tx, 0,  // recv_tip
            0,  // change_tip stays at 0
            20, // look_ahead
        );

        // Generate a fresh receive address; this bumps recv_generated_tip to 1
        // and leaves change_generated_tip at 0.
        let addr = store.new_recv_addr();
        let spk = addr.script_pubkey();

        let (recv, _change) = store.get_generated_addresses();
        assert!(
            recv.iter().any(|e| e.address().assume_checked().script_pubkey() == spk),
            "freshly generated receive address (index 1) must be returned even though change tip is 0"
        );
        // Index 1 entry must be present (it would be filtered out by the old
        // buggy `<= change_generated_tip` (0) bound).
        assert!(recv.iter().any(|e| e.index() == 1));
    }

    #[test]
    fn recv_coin_at_unknown_spk_does_not_panic() {
        // A coin reported for a script outside the watch window must extend
        // the store, and a foreign script must be ignored, never panic.
        let (tx, _rx) = mpsc::channel();
        let derivator = test_derivator();

        let mut store = AddressStore::new(derivator.clone(), tx, 0, 0, 2);

        let high_index = store.change_watch_tip() + 5;
        let spk = derivator.change_at(high_index).script_pubkey();
        assert!(!store.contains_spk(&spk));
        store.recv_coin_at(&spk);
        assert!(
            store.contains_spk(&spk),
            "store must be extended to cover the reported script"
        );

        // A script we never derive must be logged and ignored: the store is not
        // extended for it and neither watch tip moves.
        let foreign = ScriptBuf::from_bytes(vec![0x00; 22]);
        assert!(!store.contains_spk(&foreign));
        let recv_tip_before = store.recv_watch_tip();
        let change_tip_before = store.change_watch_tip();
        store.recv_coin_at(&foreign);
        assert!(
            !store.contains_spk(&foreign),
            "foreign spk must not be added to the store"
        );
        assert_eq!(
            store.recv_watch_tip(),
            recv_tip_before,
            "watch tip must not move for a foreign spk"
        );
        assert_eq!(store.change_watch_tip(), change_tip_before);
    }

    #[test]
    #[should_panic(expected = "psbt_output_info() called before create_script()")]
    fn change_recipient_provider_panics_without_create_script() {
        let (tx, _rx) = mpsc::channel();
        let network = Network::Regtest;
        let derivator = test_derivator();
        let descriptor = derivator.descriptor();

        let store = AddressStore::new(derivator, tx, 0, 0, 20);
        let store = Arc::new(Mutex::new(store));

        let tip_updater = ChangeTipUpdater::new(store);
        let provider = ChangeRecipientProvider::new_with_updater(tip_updater, descriptor, network);

        // This should panic because create_script() was never called
        let _info = provider.psbt_output_info();
    }
}
