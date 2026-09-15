//! Watching a descriptor against an Electrum server.
//!
//! An [`ElectrumScanner`] owns the stores that hold what the server reported
//! (coins, transactions, addresses, labels) and the listener thread that keeps
//! them current. It is deliberately ignorant of the chain: it never reads a
//! header, never verifies an inclusion proof and never promotes a claim. A
//! consumer that only wants coin state uses it on its own; a wallet
//! (`bwk::account::Account`) pairs it with a
//! [`HeaderStore`](crate::header_store::HeaderStore) and reconciles the two
//! through [`ElectrumScanner::coin_store`].

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
};

use bwk_coin::{Coin, KeyChain};
use bwk_descriptor::derivator::SpkDerivator;
use bwk_persist::{backend::PersistenceBackend, storage::Store};
use miniscript::{
    bitcoin::{self, OutPoint, Txid},
    Descriptor, DescriptorPublicKey,
};

use crate::{
    address_store::{AddressEntry, AddressStatus, AddressTip},
    client::{CoinRequest, CoinResponse},
    coin_state::CoinState,
    coin_store::{CoinEntry, CoinStore, CoinStoreSource, Payment, PaymentStatus, PaymentType},
    config::{ScannerConfig, Tip},
    fanout::Fanout,
    history::{aggregate_payments, AccountHistory, TxContribution},
    label_store::{LabelKey, LabelStore},
    listener::{listen_txs, ScanListeners, STATUS_KEYCHAIN_CHANGE, STATUS_KEYCHAIN_RECEIVE},
    notification::{Notification, TxListenerNotif},
    open,
    profile::{
        DefaultBackend, OpenScanFromBackend, RamProfile, ReopenStatuses, ScanProfile, ScanStores,
    },
    tx_listener,
    tx_store::{TxEntry, TxStore},
    worker::Worker,
};

/// How a freshly spawned listener thread obtains the statuses store: either
/// handed in directly (fresh or idle scanner), or received from the previous
/// listener's handback channel once that listener winds down. Resolving it
/// inside the thread keeps a stop and restart from blocking the caller.
enum StatusesSource<P: ScanProfile> {
    Direct(P::StatusesStore),
    Handback(mpsc::Receiver<P::StatusesStore>),
}

/// Largest receive and change index recorded in the statuses store. Used as a
/// floor for the restored tip. The statuses store covers the whole watch window
/// (generated tip plus look-ahead), so the caller subtracts the look-ahead to
/// get back to the generated tip.
fn max_tip_from_statuses<S>(statuses: &S) -> (u32, u32)
where
    S: Store<Value = (Option<String>, u32, u32)>,
{
    let mut max_recv = 0;
    let mut max_change = 0;
    match statuses.values() {
        Ok(values) => {
            for (_, keychain, index) in values {
                match keychain {
                    STATUS_KEYCHAIN_RECEIVE => max_recv = max_recv.max(index),
                    STATUS_KEYCHAIN_CHANGE => max_change = max_change.max(index),
                    _ => {}
                }
            }
        }
        Err(e) => log::error!("max_tip_from_statuses(): failed to read statuses values: {e}"),
    }
    (max_recv, max_change)
}

pub struct ElectrumScanner<P: ScanProfile = RamProfile<DefaultBackend>> {
    config: ScannerConfig,
    coin_store: Arc<Mutex<CoinStore<P>>>,
    label_store: Arc<Mutex<LabelStore<P>>>,
    sender: mpsc::Sender<Notification>,
    receiver: Option<mpsc::Receiver<Notification>>,
    listener: Worker,
    /// Live connection state, shared with the listener thread, which sets it
    /// once its client is up. Cleared by [`ElectrumScanner::stop`].
    online: Arc<AtomicBool>,
    /// Woken after each batch of folded state, so a reconciler runs its pass
    /// without polling the stores.
    scan_listeners: ScanListeners,
    /// Holds the statuses store while no listener owns it (fresh or idle
    /// scanner). `take()`-n in `spawn_listener` for the `Direct` source; once
    /// a listener has run, the store travels through `statuses_rx` instead.
    statuses_store: Option<P::StatusesStore>,
    /// Handback channel of the current or last listener. A stopping listener
    /// sends its statuses store here, so the next start reclaims it without the
    /// caller blocking on a thread join.
    statuses_rx: Option<mpsc::Receiver<P::StatusesStore>>,
    /// Reopen the statuses store from the backend, the fallback when a panicked
    /// listener cannot hand its store back. Cloned into the listener thread,
    /// which resolves the store itself. `None` for stores-only (test)
    /// construction with no backend.
    reopen_statuses: Option<ReopenStatuses<P>>,
}

impl<P: ScanProfile> std::fmt::Debug for ElectrumScanner<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumScanner").finish()
    }
}

impl<P: ScanProfile> Drop for ElectrumScanner<P> {
    fn drop(&mut self) {
        // The listener holds Arc clones of the persistence backend; without the
        // join the DirLock on the account directory would stay acquired past
        // Drop and refuse a subsequent reopen.
        self.listener.join();
    }
}

// Constructors over any profile that knows how to open its store bundle from a
// single `Arc<dyn PersistenceBackend>`.
impl<P: OpenScanFromBackend> ElectrumScanner<P> {
    /// Open the scan stores `config` selects and build a scanner over them.
    ///
    /// No listener is started: call [`ElectrumScanner::start`] once the caller
    /// is ready to talk to the server.
    ///
    /// Returns [`open::Error`] if the account name is empty, the descriptor is
    /// not one the scan can derive from (see
    /// [`ScannerConfig::validate_descriptor`]), the backend cannot be built
    /// (e.g. the account directory is already locked by another instance), or a
    /// stored blob fails to decode.
    pub fn try_new(config: ScannerConfig) -> Result<Self, open::Error> {
        let (sender, receiver) = mpsc::channel();
        let mut scanner = Self::try_new_with_sender(config, sender)?;
        scanner.receiver = Some(receiver);
        Ok(scanner)
    }

    /// Like [`ElectrumScanner::try_new`] but reporting through a notification
    /// channel the caller already owns.
    pub fn try_new_with_sender(
        config: ScannerConfig,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, open::Error> {
        if config.account.is_empty() {
            return Err(open::Error::EmptyAccount);
        }
        config.validate_descriptor()?;
        let backend: Arc<dyn PersistenceBackend> = config.build_backend()?;
        let stores = P::open(backend.clone())?;
        let reopen_statuses: ReopenStatuses<P> =
            Arc::new(move || P::open_statuses(backend.clone()));
        Ok(Self::from_stores(
            config,
            sender,
            stores,
            Some(reopen_statuses),
        ))
    }
}

impl<P: ScanProfile> ElectrumScanner<P> {
    /// Build a scanner over already-open stores. `reopen_statuses` is the
    /// panicked-listener recovery path; pass `None` when there is no backend
    /// to reopen from. The caller owns the descriptor check
    /// ([`ScannerConfig::validate_descriptor`]): the coin store derives from
    /// it and cannot be built without it.
    pub fn from_stores(
        config: ScannerConfig,
        sender: mpsc::Sender<Notification>,
        stores: ScanStores<P>,
        reopen_statuses: Option<ReopenStatuses<P>>,
    ) -> Self {
        let tx_store = TxStore::from_store(stores.tx);
        let label_store = Arc::new(Mutex::new(LabelStore::from_store(stores.label)));
        let account_store = Arc::new(Mutex::new(stores.account));
        // Tip is loaded from the account_store.
        let Tip { receive, change } = {
            let store = account_store.lock().expect("poisoned");
            Tip::from_account_store(&*store)
        };
        // Floor the tip with the highest index recorded in statuses, so the
        // regenerated watch window covers every persisted subscribed script even
        // when the tip rows are missing or stale. The statuses store spans the
        // whole watch window (generated tip plus look-ahead), so drop the
        // look-ahead to recover the generated tip. Without this the generated tip
        // would climb by one look-ahead window on every reopen.
        let (stat_recv, stat_change) = max_tip_from_statuses(&stores.statuses);
        let look_ahead = config.look_ahead;
        let receive = receive.max(stat_recv.saturating_sub(look_ahead));
        let change = change.max(stat_change.saturating_sub(look_ahead));
        let coin_store = Arc::new(Mutex::new(CoinStore::new(
            config.network,
            config.descriptor.clone(),
            sender.clone(),
            receive,
            change,
            look_ahead,
            tx_store,
            label_store.clone(),
            account_store,
        )));
        coin_store.lock().expect("poisoned").generate();
        ElectrumScanner {
            config,
            coin_store,
            label_store,
            sender,
            receiver: None,
            listener: Worker::default(),
            online: Arc::new(AtomicBool::new(false)),
            scan_listeners: Arc::new(Fanout::default()),
            statuses_store: Some(stores.statuses),
            statuses_rx: None,
            reopen_statuses,
        }
    }
}

// Non (b)locking API
impl<P: ScanProfile> ElectrumScanner<P> {
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    pub fn network(&self) -> bitcoin::Network {
        self.config.network
    }

    pub fn name(&self) -> String {
        self.config.account.clone()
    }

    pub fn descriptor(&self) -> Descriptor<DescriptorPublicKey> {
        self.config.descriptor.clone()
    }

    pub fn descriptor_str(&self) -> String {
        self.config.descriptor.to_string()
    }

    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.receiver.take()
    }

    /// The store the scan writes into, and the one door a reconciler writes
    /// back through: `bwk::account::Account` locks it here to apply what it
    /// resolved against the validated header chain (claim promotion,
    /// merkle-proof verification, confirmation timestamps).
    pub fn coin_store(&self) -> &Arc<Mutex<CoinStore<P>>> {
        &self.coin_store
    }

    pub fn label_store(&self) -> &Arc<Mutex<LabelStore<P>>> {
        &self.label_store
    }

    pub fn coin_source(&self) -> CoinStoreSource<P> {
        CoinStoreSource::<P>::new(self.coin_store.clone())
    }

    /// The fan-out woken (with an empty `()`) after each batch of scanned state
    /// the listener folded. A reconciler holds it from the moment it is paired
    /// with this scanner, and registers on it at every start.
    pub fn scan_listeners(&self) -> ScanListeners {
        self.scan_listeners.clone()
    }

    /// True once the listener thread has its Electrum connection up.
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }
}

// Locking API
impl<P: ScanProfile> ElectrumScanner<P> {
    pub fn balance(&self) -> (u64, Vec<Payment>) {
        let payments = self.payment_history();
        let total = payments.iter().fold(0i128, |a, b| match b.payment_type {
            PaymentType::Receive => a + (b.amount as i128),
            // A send and a self-send both reduce the balance by their outflow
            // (a self-send keeps the change but still pays the fee).
            PaymentType::Send | PaymentType::ToSelf => a - (b.amount as i128),
        });
        // A negative total means the history is inconsistent (e.g. a send whose
        // funding receive was dropped). Report zero loudly rather than wrapping
        // the cast into a huge balance.
        let balance = if total < 0 {
            log::error!("balance(): negative running total {total}, reporting 0");
            0
        } else {
            total as u64
        };
        (balance, payments)
    }

    /// Returns a map of coins associated with the scan.
    pub fn coins(&self) -> BTreeMap<OutPoint, CoinEntry> {
        self.coin_store.lock().expect("poisoned").coins()
    }

    /// Returns the coin matching the given outpoint if found, else None.
    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .get(outpoint)
            .map(|e| e.coin)
    }

    /// Returns spendable coins for the scan.
    pub fn spendable_coins(&self) -> CoinState {
        self.coin_store.lock().expect("poisoned").spendable_coins()
    }

    /// Returns a list of all historical transactions
    pub fn tx_history(&self) -> Vec<TxEntry> {
        self.coin_store.lock().expect("poisoned").tx_history()
    }

    /// Returns a list of all historical payments
    pub fn payment_history(&self) -> Vec<Payment> {
        aggregate_payments([self as &dyn AccountHistory])
    }

    /// Record a just-broadcast spend as unconfirmed: owned inputs flip to
    /// `Spent` and any owned change is surfaced immediately, before the listener
    /// or a scan sees the tx on-chain.
    pub fn record_unconfirmed_spend(&self, tx: &bitcoin::Transaction) {
        self.coin_store
            .lock()
            .expect("poisoned")
            .record_unconfirmed_tx(tx.clone());
    }

    /// Updates the label of a coin identified by the given outpoint.
    ///
    /// An empty `label` removes the label instead of setting it.
    pub fn update_coin_label(&self, outpoint: String, label: String) {
        if let Ok(outpoint) = bitcoin::OutPoint::from_str(&outpoint) {
            if !label.is_empty() {
                self.label_store
                    .lock()
                    .expect("poisoned")
                    .edit(LabelKey::OutPoint(outpoint), Some(label));
            } else {
                self.label_store
                    .lock()
                    .expect("poisoned")
                    .remove(LabelKey::OutPoint(outpoint));
            }
        }
        if let Ok(mut store) = self.coin_store.try_lock() {
            store.generate();
        }
    }

    /// Generates a new receiving address entry.
    pub fn new_addr(&mut self) -> AddressEntry {
        let addr = self.new_recv_addr();
        let index = self.coin_store.lock().expect("poisoned").recv_tip();
        AddressEntry {
            status: AddressStatus::NotUsed,
            address: addr.as_unchecked().clone(),
            account: KeyChain::Receive,
            index,
            funding_txids: BTreeSet::new(),
            spending_txids: BTreeSet::new(),
        }
    }

    pub fn new_recv_addr(&mut self) -> bitcoin::Address {
        self.coin_store.lock().expect("poisoned").new_recv_addr()
    }

    pub fn new_change_addr(&mut self) -> bitcoin::Address {
        self.coin_store.lock().expect("poisoned").new_change_addr()
    }

    /// Returns the derivator associated with the scan.
    pub fn derivator(&self) -> SpkDerivator {
        self.coin_store.lock().expect("poisoned").derivator()
    }

    pub fn recv_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .receive_at(index)
    }

    pub fn change_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .change_at(index)
    }

    /// Returns the current receiving watch tip index.
    pub fn recv_watch_tip(&self) -> u32 {
        self.coin_store.lock().expect("poisoned").recv_watch_tip()
    }

    /// Returns the current change watch tip index.
    pub fn change_watch_tip(&self) -> u32 {
        self.coin_store.lock().expect("poisoned").change_watch_tip()
    }

    pub fn generated_addresses(
        &self,
    ) -> (
        Vec<AddressEntry>, /* receive */
        Vec<AddressEntry>, /* change*/
    ) {
        self.coin_store
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .get_generated_addresses()
    }

    /// Snapshot of every address entry the scan currently tracks
    /// (receive + change, all derivation indices). Cloned, so the
    /// caller doesn't hold any lock.
    pub fn address_entries(&self) -> Vec<AddressEntry> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .entries()
    }

    /// Re-generate coin_store from tx_store
    pub fn generate_coins(&mut self) {
        self.coin_store.lock().expect("poisoned").generate();
    }
}

impl<P: ScanProfile> AccountHistory for ElectrumScanner<P> {
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
        let mut map = BTreeMap::new();
        // Read tx history (which locks coin_store) before taking the label
        // lock. On the listener thread CoinStore::generate holds coin_store and
        // then locks label_store; taking the two in the opposite order here
        // would deadlock the two threads.
        let history = {
            let store = self.coin_store.lock().expect("poisoned");
            store
                .tx_history()
                .into_iter()
                .map(|entry| {
                    let pending_height = store.pending_claim_height(&entry.txid());
                    (entry, pending_height)
                })
                .collect::<Vec<_>>()
        };
        let labels = self.label_store.lock().expect("poisoned");
        for (entry, pending_height) in history {
            let txid = entry.txid();
            let owned_in = entry
                .inputs
                .values()
                .filter(|m| m.owned)
                .map(|m| {
                    m.value.unwrap_or_else(|| {
                        // populate_tx_metadata guarantees an owned input carries
                        // its value; a missing one is a broken invariant.
                        log::error!("tx_contributions: owned input without value in tx {txid}");
                        0
                    })
                })
                .sum();
            let mut owned_out = 0u64;
            let mut owned_vouts = BTreeSet::new();
            for (idx, meta) in entry.outputs.iter() {
                if meta.owned {
                    if let Some(txout) = entry.tx().output.get(*idx) {
                        owned_out += txout.value.to_sat();
                        owned_vouts.insert(*idx as u32);
                    }
                }
            }
            // The tx label if set, else a label on any owned output's coin.
            let label = labels.transaction(txid).or_else(|| {
                owned_vouts
                    .iter()
                    .find_map(|vout| labels.outpoint(OutPoint::new(txid, *vout)))
            });
            let projected_height = pending_height
                .map(|height| height as u64)
                .or(entry.height());
            let projected_status = pending_height
                .map(|_| PaymentStatus::ConfirmedUnverified)
                .unwrap_or_else(|| PaymentStatus::from(entry.inclusion()));
            map.insert(
                txid,
                TxContribution {
                    owned_in,
                    owned_out,
                    owned_vouts,
                    height: projected_height,
                    status: projected_status,
                    timestamp: entry.timestamp(),
                    label,
                    tx: Some(entry.tx().clone()),
                },
            );
        }
        map
    }
}

// Electrum connection management
impl<P: ScanProfile> ElectrumScanner<P> {
    /// Point the scan at `url`/`port`. Takes effect on the next
    /// [`start`](Self::start); an already-running listener keeps its
    /// connection until it is restarted. A different endpoint resets the
    /// certificate policy, see
    /// [`ScannerConfig::set_electrum`](crate::config::ScannerConfig::set_electrum).
    pub fn set_electrum(&mut self, url: Option<String>, port: Option<u16>) {
        self.config.set_electrum(url, port);
    }

    /// Set how many unused addresses past the generated tip stay watched.
    /// Takes effect on the next open: the watch window is sized when the
    /// stores are built.
    pub fn set_look_ahead(&mut self, look_ahead: u32) {
        self.config.look_ahead = look_ahead;
    }

    /// Record the consumer's intent to keep this scan offline on the next
    /// open. Says nothing about the current connection, see
    /// [`online`](Self::online) for that.
    pub fn set_stay_offline(&mut self, stay_offline: bool) {
        self.config.set_stay_offline(stay_offline);
    }

    /// Start the listener against the configured endpoint. A no-op when no
    /// endpoint is configured or a listener is already running.
    pub fn start(&mut self) {
        // A listener that panicked never got to clear `online`, leaving the
        // scan claiming a connection it does not have; reclaim it first.
        if self.listener.finished() {
            self.stop();
        }
        let Some((addr, port)) = self.config.endpoint().server() else {
            return;
        };
        let addr = addr.to_string();
        if self.listener.running() {
            return;
        }
        let address_tip = self.spawn_listener(addr, port);
        self.coin_store.lock().expect("poisoned").init(address_tip);
    }

    /// Signal the listener to stop without blocking. The listener winds down on
    /// its own and hands its statuses store back through `statuses_rx`, which
    /// the next start reclaims. Its handle is kept for `Drop` to join.
    pub fn stop(&mut self) {
        self.listener.stop();
        self.online.store(false, Ordering::Relaxed);
    }

    /// Stop the current listener and start a fresh one in place, keeping the
    /// scanner and all its channels alive.
    pub fn restart(&mut self) {
        self.stop();
        self.start();
    }

    /// Spawn the listener thread and return the address-tip sender the coin
    /// store pushes watch-window growth through.
    fn spawn_listener(&mut self, addr: String, port: u16) -> mpsc::Sender<AddressTip> {
        log::debug!("ElectrumScanner::spawn_listener()");
        let (sender, address_tip) = mpsc::channel();
        let coin_store = self.coin_store.clone();
        let notification = self.sender.clone();
        let derivator = self.derivator();
        // A fresh scanner still holds the store directly; once a listener has
        // run, the store returns through the previous listener's handback
        // channel. Resolving it inside the thread keeps the caller unblocked.
        let source = match (self.statuses_store.take(), self.statuses_rx.take()) {
            (Some(store), _) => StatusesSource::<P>::Direct(store),
            (None, Some(rx)) => StatusesSource::Handback(rx),
            (None, None) => {
                // Unreachable in normal flow (one of the two always holds); route
                // it through the in-thread unavailable path rather than panic.
                let (_, rx) = mpsc::channel::<P::StatusesStore>();
                StatusesSource::Handback(rx)
            }
        };
        let (handback_tx, handback_rx) = mpsc::channel();
        self.statuses_rx = Some(handback_rx);
        // Shared with the thread so it can mark the scan online once the
        // connection is up, instead of the caller claiming it optimistically.
        let online = self.online.clone();
        let scan_listeners = self.scan_listeners.clone();
        // Fallback for a panicked previous listener that could not hand its
        // store back: the thread reopens it from disk rather than giving up.
        let reopen_statuses = self.reopen_statuses.clone();
        let certificate_check = self.config.endpoint().certificate_check();

        self.listener.start(move |stop_request| {
            let statuses_store = match source {
                StatusesSource::Direct(store) => store,
                StatusesSource::Handback(rx) => match rx.recv() {
                    Ok(store) => store,
                    Err(_) => match reopen_statuses.as_ref().map(|reopen| reopen()) {
                        Some(Ok(store)) => store,
                        other => {
                            if let Some(Err(e)) = other {
                                log::error!("spawn_listener(): reopen statuses failed: {e}");
                            }
                            log::error!(
                                "spawn_listener(): statuses store unavailable, listener not started"
                            );
                            let _ = notification.send(
                                TxListenerNotif::Error(tx_listener::Error::StatusesUnavailable)
                                    .into(),
                            );
                            return;
                        }
                    },
                },
            };
            // Resolving the source blocks on the previous listener winding
            // down, long enough for a stop to land: check before connecting.
            if stop_request.load(Ordering::Relaxed) {
                let _ = handback_tx.send(statuses_store);
                return;
            }
            let client = match crate::client::Client::new(&addr, port, certificate_check) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("spawn_listener(): fail to create electrum client {e}");
                    let _ = notification.send(TxListenerNotif::Error(e.into()).into());
                    let _ = handback_tx.send(statuses_store);
                    return;
                }
            };
            // Connecting takes a TLS handshake, long enough for the same race:
            // a stopped listener must not report itself online.
            if stop_request.load(Ordering::Relaxed) {
                let _ = handback_tx.send(statuses_store);
                return;
            }

            let addr = format!("{addr}:{port}");
            let _ = notification.send(TxListenerNotif::Connected(addr).into());
            online.store(true, Ordering::Relaxed);

            let (request, response) = client.listen_txs::<CoinRequest, CoinResponse>();

            let statuses_store = listen_txs(
                coin_store,
                derivator,
                notification,
                address_tip,
                stop_request,
                request,
                response,
                statuses_store,
                scan_listeners,
            );
            // Clear before the handback: a replacement listener blocks on that
            // handback, so it cannot have set the flag yet and this cannot
            // clobber its `online`.
            online.store(false, Ordering::Relaxed);
            let _ = handback_tx.send(statuses_store);
        });
        sender
    }
}

#[cfg(test)]
impl ElectrumScanner<RamProfile<DefaultBackend>> {
    /// A scanner over in-memory stores, watching a descriptor the scan derives
    /// from, with no endpoint configured: nothing it owns ever connects.
    pub fn offline_for_test() -> Self {
        use bwk_descriptor::descriptor::wpkh;
        use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
        use miniscript::bitcoin::{bip32::DerivationPath, Network};
        use std::path::PathBuf;

        let mnemo = Mnemonic::generate(12).expect("12 words");
        let signer = HotSigner::new_from_mnemonics(Network::Regtest, &mnemo.to_string())
            .expect("generated mnemonic");
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").expect("static path"));
        let config = ScannerConfig::new(
            wpkh(xpub),
            PathBuf::default(),
            String::new(),
            "test".into(),
            Network::Regtest,
            None,
        );
        Self::try_new(config).expect("in-memory stores, no backend to open")
    }
}

#[cfg(test)]
mod tests {
    use bwk_descriptor::derivator;
    use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
    use miniscript::{
        bitcoin::{bip32::DerivationPath, Network},
        Descriptor, DescriptorPublicKey,
    };
    use std::{collections::BTreeMap, path::PathBuf, str::FromStr};

    use crate::{
        coin_store::PaymentStatus,
        config::ScannerConfig,
        notification::Notification,
        open,
        profile::{DefaultBackend, RamProfile},
        scanner::ElectrumScanner,
    };

    /// A descriptor the scan cannot derive from (single path, no `<0;1>`) must
    /// fail the open rather than panic once the coin store derives from it.
    #[test]
    fn a_descriptor_the_scan_cannot_derive_from_fails_the_open() {
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let single_path = Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wpkh([{}/{}]{}/0/*)",
            xpub.origin.0, xpub.origin.1, xpub.xkey
        ))
        .unwrap();
        let config = ScannerConfig::new(
            single_path,
            PathBuf::default(),
            String::new(),
            "test".into(),
            Network::Regtest,
            None,
        );
        assert!(matches!(
            ElectrumScanner::<RamProfile<DefaultBackend>>::try_new(config),
            Err(open::Error::Descriptor(derivator::Error::NotMultiXpub))
        ));
    }

    /// A tx the server reported confirmed but the chain has not promoted yet
    /// must surface as `ConfirmedUnverified` at the reported height, so the
    /// payment does not read as unconfirmed while its proof is pending.
    #[cfg(feature = "test")]
    #[test]
    fn payment_history_projects_pending_claim_as_confirmed_unverified() {
        use crate::{coin_store::ClaimAt, tx_store::Inclusion};
        use bwk_utils::test::funding_tx;

        let scanner = ElectrumScanner::offline_for_test();
        let spk = scanner.recv_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();

        {
            let mut store = scanner.coin_store().lock().expect("poisoned");
            let mut history = BTreeMap::new();
            history.insert(spk, vec![(txid, None)]);
            let _ = store.handle_history_response(history);
            store.handle_txs_response(vec![tx]);
            assert!(store.record_reported_heights(&[ClaimAt { txid, height: 1 }]));
            store.generate();
        }

        let tx_entry = scanner
            .tx_history()
            .into_iter()
            .find(|entry| entry.txid() == txid)
            .expect("tx entry");
        assert!(matches!(tx_entry.inclusion(), Inclusion::Unconfirmed));

        let payment = scanner
            .payment_history()
            .into_iter()
            .find(|payment| payment.txid == txid.to_string())
            .expect("payment");
        assert_eq!(payment.status, PaymentStatus::ConfirmedUnverified);
        assert_eq!(payment.height, Some(1));
    }

    /// With no endpoint configured, `start()` must spawn no listener at all:
    /// nothing takes the statuses store, nothing reports a connection.
    #[test]
    fn a_scan_with_no_endpoint_starts_no_listener() {
        let mut scanner = ElectrumScanner::offline_for_test();
        let notifications = scanner.receiver().expect("try_new owns the channel");

        scanner.start();

        assert!(!scanner.listener.running());
        assert!(
            scanner.statuses_store.is_some(),
            "no listener took the statuses store"
        );
        assert!(!scanner.online());
        let reported: Vec<_> = notifications
            .try_iter()
            .filter(|n| matches!(n, Notification::Electrum(_)))
            .collect();
        assert!(reported.is_empty(), "listener reported {reported:?}");
    }

    /// The other half of the check above: once an endpoint is configured the
    /// same `start()` does spawn the listener, which takes the statuses store.
    #[test]
    fn a_scan_with_an_endpoint_starts_its_listener() {
        let mut scanner = ElectrumScanner::offline_for_test();
        scanner.set_electrum(Some("127.0.0.1".into()), Some(1));

        scanner.start();

        assert!(scanner.statuses_store.is_none(), "the listener took it");
        scanner.stop();
    }
}
