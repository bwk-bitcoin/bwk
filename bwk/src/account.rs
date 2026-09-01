use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
};

use bwk_backoff::Backoff;
use bwk_coin::{Coin, KeyChain};
use bwk_descriptor::derivator::SpkDerivator;
use bwk_electrum::client::{CoinError, CoinRequest, CoinResponse};
use bwk_persist::{ConfigStore, NoopConfigStore, PersistError, PersistenceBackend, Store};
use bwk_sign::signing_manager::SigningManager;
use bwk_tx::{tx_builder::TxBuilder, ChangeRecipientProvider};

use miniscript::{
    bitcoin::{self, BlockHash, OutPoint, ScriptBuf, TxMerkleNode, Txid},
    Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{
    address_store::{AddressEntry, AddressStatus, AddressTip},
    coin_store::{
        ChainUpdateOutcome, ChangeTipUpdater, ClaimAt, CoinEntry, CoinStore, CoinStoreSource,
        Payment, PaymentStatus, PaymentType,
    },
    config::{Config, Tip},
    header_store::{HeaderStore, InvalidCause},
    history::{AccountHistory, TxContribution},
    label_store::{LabelKey, LabelStore},
    profile::{
        DefaultBackend, OpenFromBackend, RamProfile, ReopenStatuses, StorageProfile, Stores,
    },
    tx_store::{Inclusion, TxEntry, TxStore},
};

#[cfg(test)]
use crate::profile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AddrAccount {
    Receive,
    Change,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// `confirmed_*` includes `ConfirmedUnverified` coins: confirmed on-chain,
/// SPV proof still pending.
pub struct CoinState {
    pub coins: BTreeMap<OutPoint, Coin>,
    pub confirmed_coins: usize,
    pub confirmed_balance: u64,
    pub unconfirmed_coins: usize,
    pub unconfirmed_balance: u64,
}

/// Silent Payments notification variants (behind `sp` feature).
#[cfg(feature = "sp")]
#[derive(Debug, Clone)]
pub enum SpNotification {
    /// Scanner is starting
    StartingScan,
    /// Scan has started
    ScanStarted { start: u32, end: u32 },
    /// Scanner failed to start
    FailStartScanning { message: String },
    /// Scan failed during scanning
    FailScan { message: String },
    /// Scanner is stopping
    StoppingScan,
    /// Scanner has stopped
    ScanStopped,
    /// Receive (output) scan progress update
    ScanReceiveProgress { current: u32, end: u32 },
    /// Spend (input) sweep progress update
    ScanSpendProgress { current: u32, end: u32 },
    /// Scan completed successfully
    ScanCompleted,
    /// A new output was found
    NewOutput(OutPoint),
    /// An output was spent
    OutputSpent(OutPoint),
    /// Broadcast completed and local state was updated
    Broadcasted { txid: Txid },
    /// Broadcast failed before local state was updated
    FailBroadcast { message: String },
    /// Continuous mode: at chain tip, waiting for new blocks
    WaitingForBlocks { tip_height: u32 },
    /// Continuous mode: new block(s) detected
    NewBlocksDetected { from_height: u32, to_height: u32 },
}

pub struct SpendRecorder<P: StorageProfile = RamProfile<DefaultBackend>> {
    coin_store: Arc<Mutex<CoinStore<P>>>,
}

impl<P: StorageProfile> Clone for SpendRecorder<P> {
    fn clone(&self) -> Self {
        Self {
            coin_store: self.coin_store.clone(),
        }
    }
}

impl<P: StorageProfile> SpendRecorder<P> {
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

/// Notifications sent by an Account to signal events.
#[derive(Debug)]
pub enum Notification {
    Electrum(TxListenerNotif),
    AddressTipChanged,
    CoinUpdate,
    PaymentHistoryUpdated,
    InvalidElectrumConfig,
    InvalidLookAhead,
    Stopped,
    Error(Error),
    /// A chain-tip-advance (CTA) pass mutated tx state in response to a
    /// HeaderStore update.
    HeaderStoreUpdated,
    HeaderProgress(crate::header_store::HeaderProgressEvent),
    /// A merkle proof failed verification, or the header store itself
    /// failed validation; the affected entry was refused promotion.
    ValidationFailed(ValidationFailure),
    #[cfg(feature = "sp")]
    Sp(SpNotification),
}

#[derive(Debug, Clone)]
pub enum ValidationFailure {
    /// Merkle proof for a tx at a height did not verify against the header.
    MerkleProof { txid: Txid, height: u32 },
    /// The header store rejected its own replay validation.
    HeaderStore(InvalidCause),
}

impl From<TxListenerNotif> for Notification {
    fn from(value: TxListenerNotif) -> Self {
        Notification::Electrum(value)
    }
}

impl From<Error> for Notification {
    fn from(value: Error) -> Self {
        Self::Error(value)
    }
}

#[cfg(feature = "sp")]
impl From<SpNotification> for Notification {
    fn from(sp: SpNotification) -> Self {
        Notification::Sp(sp)
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    CreatePool,
    JoinPool,
    InvalidOutPoint,
    CoinMissing,
    InvalidDenomination,
    RelayMissing,
    WrongElectrumConfig,
    PoolMissing,
    WrongKeyType,
    Satisfaction,
    HeaderStoreRestart,
}

/// Error returned when opening an [`Account`]'s stores from disk.
#[derive(Debug)]
pub enum OpenError {
    /// The config carried an empty account name.
    EmptyAccount,
    /// The persistence backend could not be built or the store bundle
    /// could not be read (e.g. the account directory is already locked,
    /// or a stored blob failed to decode).
    Persist(PersistError),
    /// The configured Electrum endpoint could not be reached while building
    /// the account's [`HeaderStore`]. Fails loud rather than silently
    /// opening a worker-less store (see [`Account::build_header_store`]).
    HeaderStore(crate::header_store::StartError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::EmptyAccount => write!(f, "account name must not be empty"),
            OpenError::Persist(e) => write!(f, "{e}"),
            OpenError::HeaderStore(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<PersistError> for OpenError {
    fn from(e: PersistError) -> Self {
        OpenError::Persist(e)
    }
}

impl From<crate::header_store::StartError> for OpenError {
    fn from(e: crate::header_store::StartError) -> Self {
        OpenError::HeaderStore(e)
    }
}

/// Represents notifications related to transaction listeners.
#[derive(Debug)]
pub enum TxListenerNotif {
    Started,
    Connected(String),
    Error(TxListenerError),
    Stopped,
}

/// Errors surfaced through [`TxListenerNotif::Error`].
#[derive(Debug, thiserror::Error)]
pub enum TxListenerError {
    #[error("failed to create electrum client: {0}")]
    Client(#[from] bwk_electrum::client::Error),
    #[error(transparent)]
    Coin(#[from] CoinError),
    #[error("address store disconnected")]
    AddressStoreDisconnected,
    #[error("statuses store unavailable")]
    StatusesUnavailable,
}

/// How a freshly spawned listener thread obtains the statuses store: either
/// handed in directly (fresh or idle account), or received from the previous
/// listener's handback channel once that listener winds down. Resolving it
/// inside the thread keeps a stop and restart from blocking the caller.
enum StatusesSource<P: StorageProfile> {
    Direct(P::StatusesStore),
    Handback(mpsc::Receiver<P::StatusesStore>),
}

pub struct Account<P: StorageProfile = RamProfile<DefaultBackend>> {
    coin_store: Arc<Mutex<CoinStore<P>>>,
    label_store: Arc<Mutex<LabelStore<P>>>,
    receiver: Option<mpsc::Receiver<Notification>>,
    sender: mpsc::Sender<Notification>,
    tx_listener: Option<JoinHandle<()>>,
    config: Config,
    /// Persistence sink for `config`. [`NoopConfigStore`] by default.
    /// Consumers wire whatever shape suits them, a
    /// [`bwk_persist::FileConfigStore`] for file-backed persistence, a
    /// [`bwk_persist::CallbackConfigStore`] to bridge save/load through
    /// host-supplied closures, or any other [`ConfigStore`] impl.
    config_store: Arc<dyn ConfigStore<Config>>,
    electrum_stop: Option<Arc<AtomicBool>>,
    signing_manager: SigningManager<P::SignerStore>,
    /// Holds the statuses store while no listener owns it (fresh or idle
    /// account). `take()`-n in `start_listen_txs` for the `Direct` source; once
    /// a listener has run, the store travels through `statuses_rx` instead.
    statuses_store: Option<P::StatusesStore>,
    /// Handback channel of the current or last listener. A stopping listener
    /// sends its statuses store here, so the next start reclaims it without the
    /// caller blocking on a thread join.
    statuses_rx: Option<mpsc::Receiver<P::StatusesStore>>,
    /// Validated header chain. Shared across Accounts; the Account
    /// reads `block_hash` / `tip` on every CTA to promote claims.
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    /// Live offline flag, shared with the Electrum listener thread. The
    /// listener clears it on `Connected`; `stop_electrum` sets it. Single
    /// runtime source for `electrum_offline()` and the persisted view.
    offline: Arc<AtomicBool>,
    /// Reopen the statuses store from the backend, the fallback when a panicked
    /// listener cannot hand its store back. Cloned into the listener thread,
    /// which resolves the store itself. `None` for stores-only (test)
    /// construction with no backend.
    reopen_statuses: Option<ReopenStatuses<P>>,
}

impl<P: StorageProfile> std::fmt::Debug for Account<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").finish()
    }
}

impl<P: StorageProfile> Drop for Account<P> {
    fn drop(&mut self) {
        // Signal the Electrum listener thread to stop, then block until
        // it has actually exited. The listener holds Arc clones of the
        // persistence backend; without the join, the DirLock on the
        // account directory would stay acquired past Drop and refuse a
        // subsequent reopen.
        if let Some(stop) = self.electrum_stop.as_mut() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.tx_listener.take() {
            let _ = handle.join();
        }
    }
}

// RAM-specific adapter for callers that already hold a `RamStores<B>`
// bundle. Forwards to the generic `from_stores`.
impl Account<RamProfile<DefaultBackend>> {
    #[cfg(test)]
    fn from_ram_stores(
        config: Config,
        header_store: Arc<HeaderStore>,
        sender: mpsc::Sender<Notification>,
        ram: profile::RamStores<DefaultBackend>,
    ) -> Self {
        Self::from_stores(
            config,
            header_store,
            sender,
            default_config_store(),
            Stores {
                tx: ram.tx,
                label: ram.label,
                statuses: ram.statuses,
                account: ram.account,
                signers: ram.signers,
            },
            None,
        )
    }
}

fn default_config_store() -> Arc<dyn ConfigStore<Config>> {
    Arc::new(NoopConfigStore::<Config>::default())
}

// Generic constructors over any profile that knows how to open its
// store bundle from a single `Arc<dyn PersistenceBackend>`.
impl<P: OpenFromBackend> Account<P> {
    /// Creates a new `Account` instance with the given configuration.
    ///
    /// Opens the profile's stores against whatever backend the config
    /// selects ([`JsonBackend`][bwk_persist::JsonBackend] by default,
    /// `SqliteBackend` under `PersistenceKind::Sqlite`). Defaults to
    /// the [`RamProfile<DefaultBackend>`] storage strategy via the
    /// `Account` struct's default type parameter.
    ///
    /// Builds its own [`HeaderStore`] from `config` (see
    /// [`Account::build_header_store`]); use
    /// [`Account::try_new_with_header_store`] to share an existing one
    /// instead.
    ///
    /// Config persistence defaults to [`NoopConfigStore`]; use
    /// [`Account::try_with_config_store`] to wire a concrete impl
    /// ([`bwk_persist::FileConfigStore`] for file-backed,
    /// [`bwk_persist::CallbackConfigStore`] to bridge through
    /// caller-supplied closures, or any other [`ConfigStore`]).
    ///
    /// Returns [`OpenError`] if the account name is empty, the backend
    /// cannot be built (e.g. the account directory is already locked by
    /// another instance), or a stored blob fails to decode.
    pub fn try_new(config: Config) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_with_header_store(config, header_store)
    }

    /// Like [`Account::try_new`] but sharing an existing [`HeaderStore`]
    /// handle instead of building one.
    pub fn try_new_with_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
    ) -> Result<Self, OpenError> {
        let (sender, receiver) = mpsc::channel();
        let mut account =
            Self::try_new_inner(config, header_store, sender, default_config_store())?;
        account.receiver = Some(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an explicit config store.
    pub fn try_with_config_store(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        let (sender, receiver) = mpsc::channel();
        let mut account = Self::try_new_inner(config, header_store, sender, config_store)?;
        account.receiver = Some(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an external notification sender.
    pub fn try_new_with_sender(
        config: Config,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_inner(config, header_store, sender, default_config_store())
    }

    /// Like [`Account::try_new_with_sender`] but sharing an existing
    /// [`HeaderStore`] handle instead of building one. Used to fan a
    /// shared chain across several accounts routed through the same
    /// notification channel (e.g. `bwk_sp::Account`'s BIP32 sub-accounts).
    pub fn try_new_with_sender_and_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        Self::try_new_inner(config, header_store, sender, default_config_store())
    }

    /// Infallible test helper. Not exposed to consumers: production
    /// callers use [`Account::try_new`] so a bad/locked store surfaces
    /// as an error instead of aborting.
    #[cfg(any(test, feature = "test"))]
    pub fn new(config: Config) -> Self {
        Self::try_new(config).expect("Account::new: failed to open stores")
    }

    /// Infallible test helper; see [`Account::new`].
    #[cfg(any(test, feature = "test"))]
    pub fn with_config_store(config: Config, config_store: Arc<dyn ConfigStore<Config>>) -> Self {
        Self::try_with_config_store(config, config_store)
            .expect("Account::with_config_store: failed to open stores")
    }

    /// Build this account's own [`HeaderStore`]: online (via
    /// [`HeaderStore::start`]) when `config` carries an Electrum endpoint
    /// and is not offline, file-backed/in-memory otherwise. Headers are
    /// always binary-backed through [`bwk_persist::HeaderBackend`] at
    /// [`Config::headers_path`], independent of the account's own
    /// persistence kind.
    ///
    /// Returns [`OpenError::HeaderStore`] if a configured (non-offline)
    /// endpoint cannot be reached: header-sync progress gates wallet
    /// `Verified` state, so a dead store must fail loud rather than open
    /// silently degraded.
    fn build_header_store(config: &Config) -> Result<Arc<HeaderStore<P::HeaderStore>>, OpenError> {
        let path = config.persist.then(|| config.headers_path());
        let (url, port) = if config.offline() {
            (None, None)
        } else {
            (config.electrum_url.clone(), config.electrum_port)
        };
        Ok(HeaderStore::start_or_open(
            url,
            port,
            config.network,
            path,
            None,
        )?)
    }

    fn try_new_inner(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, OpenError> {
        if config.account.is_empty() {
            return Err(OpenError::EmptyAccount);
        }
        let backend: Arc<dyn PersistenceBackend> = config.build_backend()?;
        // Hot-signer material must not land on the SQLite DB; route the
        // SignerStore slot through a NoopBackend in that case.
        let secrets_backend: Arc<dyn PersistenceBackend> =
            if matches!(config.persist_kind, bwk_persist::PersistenceKind::Sqlite) {
                Arc::new(bwk_persist::NoopBackend)
            } else {
                backend.clone()
            };
        let reopen_backend = backend.clone();
        let reopen_statuses: ReopenStatuses<P> =
            Arc::new(move || P::open_statuses(reopen_backend.clone()));
        let stores = P::open(backend, secrets_backend)?;
        Ok(Self::from_stores(
            config,
            header_store,
            sender,
            config_store,
            stores,
            Some(reopen_statuses),
        ))
    }

    /// Restart the Electrum listener in place, keeping the `Account` and all
    /// its channels alive. On a normal reconnect the offline flag is driven by
    /// the listener, which clears it once connected; with no endpoint configured
    /// nothing starts and `start_electrum` marks the account offline.
    pub fn restart_electrum(&mut self) {
        self.stop_listener();
        self.start_electrum();
        // The previous connection died; the shared HeaderStore worker still
        // holds the same dead socket, so reconnect it too or `Verified`
        // promotions would stall.
        if let (Some(url), Some(port)) =
            (self.config.electrum_url.clone(), self.config.electrum_port)
        {
            if let Err(e) = self.header_store.restart(url, port) {
                log::error!("restart_electrum(): header store restart failed: {e}");
                let _ = self
                    .sender
                    .send(Notification::Error(Error::HeaderStoreRestart));
            }
        }
    }
}

/// Keychain discriminants stored in the statuses value `(status, keychain,
/// index)`, shared by the writer (`handle_address_tip`) and the reader
/// (`max_tip_from_statuses`).
const STATUS_KEYCHAIN_RECEIVE: u32 = 0;
const STATUS_KEYCHAIN_CHANGE: u32 = 1;

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

impl<P: StorageProfile> Account<P> {
    fn from_stores(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
        stores: Stores<P>,
        reopen_statuses: Option<ReopenStatuses<P>>,
    ) -> Self {
        let tx_store = TxStore::from_store(stores.tx);
        let label_store = Arc::new(Mutex::new(LabelStore::from_store(stores.label)));
        let account_store = Arc::new(Mutex::new(stores.account));
        // Tip is loaded from the account_store.
        let tip = {
            let store = account_store.lock().expect("poisoned");
            Tip::from_account_store(&*store)
        };
        let Tip { receive, change } = tip;
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
            config.look_ahead,
            tx_store,
            label_store.clone(),
            config.clone(),
            account_store.clone(),
        )));
        coin_store.lock().expect("poisoned").generate();
        let mut signing_manager = SigningManager::from_store(stores.signers);
        if let Some(mnemo) = config.mnemonic.clone() {
            signing_manager.new_bip32_signer_from_mnemonic(config.network(), mnemo);
            signing_manager.register_bip32_descriptor(config.descriptor.clone());
        }
        let _ = account_store; // owned by CoinStore->AddressStore; not stored on Account
        let offline = Arc::new(AtomicBool::new(config.offline()));
        let mut account = Account {
            coin_store,
            label_store,
            tx_listener: None,
            electrum_stop: None,
            receiver: None,
            sender,
            config,
            config_store,
            signing_manager,
            statuses_store: Some(stores.statuses),
            statuses_rx: None,
            header_store,
            offline,
            reopen_statuses,
        };
        if !account.offline.load(Ordering::Relaxed) {
            account.start_electrum();
        }
        account
    }
}

impl<P: StorageProfile> Account<P> {
    /// Push the current config to the configured [`ConfigStore`].
    ///
    /// Under [`bwk_persist::PersistenceKind::Sqlite`] the saved view has
    /// signer material stripped via [`Config::for_persistence`].
    fn persist_config(&self) {
        let mut cfg = self.config.for_persistence();
        cfg.set_offline(self.offline.load(Ordering::Relaxed));
        if let Err(e) = self.config_store.save(&cfg) {
            log::warn!("config save failed: {e}");
        }
    }

    fn coin_store(&self) -> &Arc<Mutex<CoinStore<P>>> {
        &self.coin_store
    }

    fn label_store(&self) -> &Arc<Mutex<LabelStore<P>>> {
        &self.label_store
    }

    fn signing_manager(&self) -> &SigningManager<P::SignerStore> {
        &self.signing_manager
    }
}

// Non (b)locking API
impl<P: StorageProfile> Account<P> {
    pub fn network(&self) -> bitcoin::Network {
        self.config.network()
    }

    pub fn name(&self) -> String {
        self.config.account.clone()
    }

    pub fn descriptor_str(&self) -> String {
        self.config.descriptor.to_string()
    }

    pub fn descriptor(&self) -> Descriptor<DescriptorPublicKey> {
        self.config.descriptor.clone()
    }

    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.receiver.take()
    }

    /// Returns the configuration of the account.
    ///
    /// # Returns
    ///
    /// A boxed `Config` instance.
    pub fn get_config(&self) -> Config {
        self.config.clone()
    }

    pub fn coin_source(&self) -> CoinStoreSource<P> {
        CoinStoreSource::<P>::new(self.coin_store().clone())
    }

    pub fn sign(&self, psbt: String) {
        self.signing_manager().sign(psbt);
    }

    pub fn sign_psbt(&self, psbt: &mut bitcoin::Psbt) {
        self.signing_manager().sign_psbt(psbt);
    }

    /// Returns master xprivs from all BIP32 hot signers, keyed by fingerprint.
    pub fn master_xprivs(&self) -> BTreeMap<bitcoin::bip32::Fingerprint, bitcoin::bip32::Xpriv> {
        self.signing_manager().master_xprivs()
    }
}

// Locking API
impl<P: StorageProfile> Account<P> {
    pub fn tx_builder(&self) -> TxBuilder {
        let tip_updater = ChangeTipUpdater::new(self.coin_store().clone());
        let change_provider = Box::new(ChangeRecipientProvider::new_with_updater(
            tip_updater,
            self.descriptor(),
            self.network(),
        ));
        let coin_source = Box::new(CoinStoreSource::new(self.coin_store().clone()));
        TxBuilder::new(change_provider).coin_source(coin_source)
    }

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
    /// Returns a map of coins associated with the account.
    ///
    /// # Returns
    ///
    /// A `BTreeMap` of `OutPoint` to `CoinEntry`.
    pub fn coins(&self) -> BTreeMap<OutPoint, CoinEntry> {
        self.coin_store().lock().expect("poisoned").coins()
    }

    /// Returns the coin matching the given outpoint if found, else None.
    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .get(outpoint)
            .map(|e| e.coin)
    }

    /// Returns spendable coins for the account.
    pub fn spendable_coins(&self) -> CoinState {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .spendable_coins()
    }

    /// Returns a list of all historical transactions
    pub fn tx_history(&self) -> Vec<TxEntry> {
        self.coin_store().lock().expect("poisoned").tx_history()
    }

    /// Returns a list of all historical payments
    pub fn payment_history(&self) -> Vec<Payment> {
        crate::history::aggregate_payments([self as &dyn AccountHistory])
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

    pub fn spend_recorder(&self) -> SpendRecorder<P> {
        SpendRecorder {
            coin_store: self.coin_store.clone(),
        }
    }

    /// Updates the label of a coin identified by the given outpoint.
    ///
    /// # Arguments
    ///
    /// * `outpoint` - A string representation of the outpoint for the coin.
    /// * `label` - The new label to set for the coin. If the label is empty, the label will be removed.
    pub fn update_coin_label(&self, outpoint: String, label: String) {
        if let Ok(outpoint) = bitcoin::OutPoint::from_str(&outpoint) {
            if !label.is_empty() {
                self.label_store()
                    .lock()
                    .expect("poisoned")
                    .edit(LabelKey::OutPoint(outpoint), Some(label));
            } else {
                self.label_store()
                    .lock()
                    .expect("poisoned")
                    .remove(LabelKey::OutPoint(outpoint));
            }
        }
        if let Ok(mut store) = self.coin_store().try_lock() {
            store.generate();
        }
    }

    /// Generates a new receiving address entry for the account.
    ///
    /// # Returns
    ///
    /// A boxed `AddressEntry` instance.
    pub fn new_addr(&mut self) -> AddressEntry {
        let addr = self.new_recv_addr();
        let index = self.coin_store().lock().expect("poisoned").recv_tip();
        AddressEntry {
            status: AddressStatus::NotUsed,
            address: addr.as_unchecked().clone(),
            account: KeyChain::Receive,
            index,
            funding_txids: std::collections::BTreeSet::new(),
            spending_txids: std::collections::BTreeSet::new(),
        }
    }
    fn new_recv_addr(&mut self) -> bitcoin::Address {
        self.coin_store().lock().expect("poisoned").new_recv_addr()
    }
    #[allow(unused)]
    fn new_change_addr(&mut self) -> bitcoin::Address {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .new_change_addr()
    }
}

impl<P: StorageProfile> AccountHistory for Account<P> {
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
        let mut map = BTreeMap::new();
        // Read tx history (which locks coin_store) before taking the label
        // lock. On the listener thread CoinStore::generate holds coin_store and
        // then locks label_store; taking the two in the opposite order here
        // would deadlock the two threads.
        let history = {
            let store = self.coin_store().lock().expect("poisoned");
            store
                .tx_history()
                .into_iter()
                .map(|entry| {
                    let pending_height = store.pending_claim_height(&entry.txid());
                    (entry, pending_height)
                })
                .collect::<Vec<_>>()
        };
        let labels = self.label_store().lock().expect("poisoned");
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

// Derivation specific implementation
impl<P: StorageProfile> Account<P> {
    /// Returns the derivator associated with the account.
    ///
    /// # Returns
    ///
    /// A `Derivator` instance.
    pub fn derivator(&self) -> SpkDerivator {
        self.coin_store().lock().expect("poisoned").derivator()
    }
    #[allow(unused)] // Internal usage only
    fn recv_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .receive_at(index)
    }

    #[allow(unused)] // Internal usage only
    fn change_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .change_at(index)
    }

    /// Returns the current receiving watch tip index.
    ///
    /// # Returns
    ///
    /// The receiving watch tip index as a `u32`.
    pub fn recv_watch_tip(&self) -> u32 {
        self.coin_store().lock().expect("poisoned").recv_watch_tip()
    }

    /// Returns the current change watch tip index.
    ///
    /// # Returns
    ///
    /// The change watch tip index as a `u32`.
    pub fn change_watch_tip(&self) -> u32 {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .change_watch_tip()
    }

    pub fn generated_addresses(
        &self,
    ) -> (
        Vec<AddressEntry>, /* receive */
        Vec<AddressEntry>, /* change*/
    ) {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .get_generated_addresses()
    }

    /// Snapshot of every address entry the account currently tracks
    /// (receive + change, all derivation indices). Cloned, so the
    /// caller doesn't hold any lock.
    pub fn address_entries(&self) -> Vec<AddressEntry> {
        self.coin_store()
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .entries()
    }
}

// Electrum specific implementation
impl<P: StorageProfile> Account<P> {
    /// Re-generate coin_store from tx_store
    pub fn generate_coins(&mut self) {
        self.coin_store().lock().expect("poisoned").generate();
    }
    pub fn electrum_url(&self) -> String {
        self.config.electrum_url()
    }

    pub fn electrum_port(&self) -> String {
        self.config.electrum_port()
    }

    pub fn look_ahead(&self) -> String {
        self.config.look_ahead()
    }

    /// Starts listening for transactions on the specified address and port.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to listen on.
    /// * `port` - The port to listen on.
    ///
    /// # Returns
    ///
    /// A tuple containing a sender for address tips and a stop flag.
    fn start_listen_txs(
        &mut self,
        addr: String,
        port: u16,
    ) -> (mpsc::Sender<AddressTip>, Arc<AtomicBool>) {
        log::debug!("Account::start_poll_txs()");
        let (sender, address_tip) = mpsc::channel();
        let coin_store = self.coin_store().clone();
        let notification = self.sender.clone();
        let derivator = self.derivator();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_request = stop.clone();
        // A fresh account still holds the store directly; once a listener has
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
        let header_store = self.header_store.clone();
        // Register a fresh CTA receiver and hand it straight to the
        // listener thread; the Account never needs to hold it.
        let chain_rx = self.header_store.register();
        // Shared with the thread so it can mark the account online once the
        // connection is up, instead of the caller claiming it optimistically.
        let offline = self.offline.clone();
        let config_store = self.config_store.clone();
        let config = self.config.clone();
        // Fallback for a panicked previous listener that could not hand its
        // store back: the thread reopens it from disk rather than giving up.
        let reopen_statuses = self.reopen_statuses.clone();

        let poller = thread::spawn(move || {
            let statuses_store = match source {
                StatusesSource::Direct(store) => store,
                StatusesSource::Handback(rx) => match rx.recv() {
                    Ok(store) => store,
                    Err(_) => match reopen_statuses.as_ref().map(|reopen| reopen()) {
                        Some(Ok(store)) => store,
                        other => {
                            if let Some(Err(e)) = other {
                                log::error!("start_listen_txs(): reopen statuses failed: {e}");
                            }
                            log::error!(
                                "start_listen_txs(): statuses store unavailable, listener not started"
                            );
                            let _ = notification.send(
                                TxListenerNotif::Error(TxListenerError::StatusesUnavailable).into(),
                            );
                            return;
                        }
                    },
                },
            };
            let client = match bwk_electrum::client::Client::new(&addr, port) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("start_listen_txs(): fail to create electrum client {e}");
                    let _ = notification.send(TxListenerNotif::Error(e.into()).into());
                    let _ = handback_tx.send(statuses_store);
                    return;
                }
            };

            let addr = format!("{addr}:{port}");
            let _ = notification.send(TxListenerNotif::Connected(addr).into());
            offline.store(false, Ordering::Relaxed);
            let mut cfg = config.for_persistence();
            cfg.set_offline(false);
            if let Err(e) = config_store.save(&cfg) {
                log::warn!("start_listen_txs(): config save failed: {e}");
            }

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
                header_store,
                chain_rx,
            );
            let _ = handback_tx.send(statuses_store);
        });
        self.tx_listener = Some(poller);
        (sender, stop)
    }
    /// Sets the Electrum server URL and port for the account.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the Electrum server.
    /// * `port` - The port of the Electrum server.
    pub fn set_electrum(&mut self, url: String, port: String) {
        if let Ok(port) = port.parse::<u16>() {
            self.config.electrum_url = Some(url);
            self.config.electrum_port = Some(port);
            self.persist_config();
        } else {
            self.sender
                .send(Notification::InvalidElectrumConfig)
                .expect("cannot fail");
        }
    }

    /// Sets the Electrum URL and port in memory without writing to file.
    pub fn set_electrum_config(&mut self, url: Option<String>, port: Option<u16>) {
        self.config.electrum_url = url;
        self.config.electrum_port = port;
    }

    /// Starts the Electrum listener for the account.
    pub fn start_electrum(&mut self) {
        // A listener that already finished (e.g. failed to connect at startup)
        // still occupies `tx_listener`; reclaim it so this retry can restart.
        if self.tx_listener.as_ref().is_some_and(|h| h.is_finished()) {
            self.stop_listener();
        }
        match (self.config.electrum_url.clone(), self.config.electrum_port) {
            (Some(addr), Some(port)) if self.tx_listener.is_none() => {
                let (tx_listener, electrum_stop) = self.start_listen_txs(addr, port);
                self.coin_store()
                    .lock()
                    .expect("poisoned")
                    .init(tx_listener);
                self.electrum_stop = Some(electrum_stop);
            }
            (None, _) | (_, None) => {
                // No endpoint to connect to: nothing can listen, so report
                // offline honestly instead of leaving a stale online flag.
                self.offline.store(true, Ordering::Relaxed);
                self.persist_config();
            }
            _ => {}
        }
    }

    /// Signal the listener to stop and detach it, without blocking. The
    /// listener winds down on its own and hands its statuses store back through
    /// `statuses_rx`, which the next start reclaims. Mechanical only: leaves the
    /// offline flag and persisted config untouched.
    fn stop_listener(&mut self) {
        if let Some(stop) = self.electrum_stop.as_mut() {
            stop.store(true, Ordering::Relaxed);
        }
        self.electrum_stop = None;
        self.tx_listener = None;
    }

    /// Stops the Electrum listener for the account and marks it offline.
    pub fn stop_electrum(&mut self) {
        self.stop_listener();
        self.offline.store(true, Ordering::Relaxed);
        self.persist_config();
    }

    pub fn electrum_offline(&self) -> bool {
        self.offline.load(Ordering::Relaxed)
    }

    /// Test-only accessor for the account's `HeaderStore` handle, used to
    /// assert store identity (`Arc::ptr_eq`) across accounts sharing one.
    #[cfg(any(test, feature = "test"))]
    pub fn header_store(&self) -> &Arc<HeaderStore<P::HeaderStore>> {
        &self.header_store
    }

    /// Sets the look-ahead value for the account.
    ///
    /// # Arguments
    ///
    /// * `look_ahead` - The look-ahead value to set.
    pub fn set_look_ahead(&mut self, look_ahead: String) {
        if let Ok(la) = look_ahead.parse::<u32>() {
            self.config.look_ahead = la;
            self.persist_config();
        } else {
            self.sender
                .send(Notification::InvalidLookAhead)
                .expect("cannot fail");
        }
    }
}

// /// Creates a new account with the specified account name.
// ///
// /// # Arguments
// ///
// /// * `account` - The name of the account.
// ///
// /// # Returns
// ///
// /// A boxed `Account` instance.
// pub fn new_account(account: String) -> Box<Account> {
//     let config = Config::from_file(account);
//
//     let account = Account::new(config);
//     account.boxed()
// }

// On a dead channel the listener bails out and hands `$statuses` back to the
// caller (so a later restart can reuse it), mirroring the normal return paths.
macro_rules! send_notif {
    ($notification:expr, $request:expr, $statuses:expr, $msg:expr) => {
        let res = $notification.send($msg.into());
        if res.is_err() {
            // stop detached client
            let _ = $request.send(CoinRequest::Stop);
            return $statuses;
        }
    };
}

macro_rules! send_electrum {
    ($request:expr, $notification:expr, $statuses:expr, $msg:expr) => {
        if $request.send($msg).is_err() {
            send_notif!($notification, $request, $statuses, TxListenerNotif::Stopped);
            return $statuses;
        }
    };
}

/// Listens for transactions on the specified address and port.
///
/// # Arguments
///
/// * `addr` - The address to listen on.
/// * `port` - The port to listen on.
/// * `coin_store` - The coin store to update with transaction data.
/// * `signer` - The signer for the account.
/// * `notification` - The sender for notifications.
/// * `address_tip` - The receiver for address tips.
/// * `stop_request` - The stop flag for the listener.
#[allow(clippy::too_many_arguments)]
fn listen_txs<P>(
    coin_store: Arc<Mutex<CoinStore<P>>>,
    derivator: SpkDerivator,
    notification: mpsc::Sender<Notification>,
    address_tip: mpsc::Receiver<AddressTip>,
    stop_request: Arc<AtomicBool>,
    request: mpsc::Sender<CoinRequest>,
    response: mpsc::Receiver<CoinResponse>,
    mut statuses: P::StatusesStore,
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    chain_rx: mpsc::Receiver<()>,
) -> P::StatusesStore
where
    P: StorageProfile,
{
    log::info!("listen_txs(): started");
    send_notif!(notification, request, statuses, TxListenerNotif::Started);

    requeue_confirmed_unverified(&coin_store, &request);

    let initial_keys: Vec<ScriptBuf> = match statuses.keys() {
        Ok(it) => it.collect(),
        Err(e) => {
            log::error!("listen_txs(): statuses keys: {e}");
            Vec::new()
        }
    };
    if !initial_keys.is_empty() {
        send_electrum!(
            request,
            notification,
            statuses,
            CoinRequest::Subscribe(initial_keys)
        );
    }

    refresh_unconfirmed_history(&coin_store, &request);
    // Stamp any already-confirmed entries loaded from disk (e.g. a quiet wallet
    // that gets no fresh history traffic) from the validated header chain.
    stamp_confirmation_times(&coin_store, &header_store);

    let mut backoff = Backoff::new_ms(20);
    loop {
        // stop request from consumer side
        if stop_request.load(Ordering::Relaxed) {
            send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
            let _ = request.send(CoinRequest::Stop);
            return statuses;
        }

        let mut received = false;

        // listen for AddressTip update
        match address_tip.try_recv() {
            Ok(tip) => {
                log::debug!("listen_txs() receive {tip:?}");
                received = true;
                if handle_address_tip::<P>(tip, &derivator, &mut statuses, &request, &notification)
                    .is_break()
                {
                    return statuses;
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    log::error!("listen_txs(): address store disconnected");
                    send_notif!(
                        notification,
                        request,
                        statuses,
                        TxListenerNotif::Error(TxListenerError::AddressStoreDisconnected)
                    );
                    // FIXME: what should we do there?
                    // it's AddressStore being dropped, but she should keep upating
                    // the actual spk set even if it cannot grow anymore
                }
            },
        }

        // listen for response
        match response.try_recv() {
            Ok(rsp) => {
                log::debug!("listen_txs() receive {}", rsp.summary());
                received = true;
                match rsp {
                    CoinResponse::Status(elct_status) => {
                        if handle_status_response(
                            elct_status,
                            &mut statuses,
                            &coin_store,
                            &request,
                            &notification,
                        )
                        .is_break()
                        {
                            return statuses;
                        }
                    }
                    CoinResponse::History(map) => {
                        if handle_history_response_msg(
                            map,
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                        )
                        .is_break()
                        {
                            return statuses;
                        }
                        // Newly confirmed entries can now be stamped from the chain.
                        stamp_confirmation_times(&coin_store, &header_store);
                    }
                    CoinResponse::Txs(txs) => {
                        handle_txs_response_msg(
                            txs,
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                        );
                        // Tx bodies just completed newly confirmed entries; stamp them.
                        stamp_confirmation_times(&coin_store, &header_store);
                    }
                    CoinResponse::TxMerkle {
                        txid,
                        height,
                        branch,
                        pos,
                    } => {
                        handle_tx_merkle(
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                            txid,
                            height,
                            branch,
                            pos,
                        );
                    }
                    CoinResponse::Stopped => {
                        send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                        let _ = request.send(CoinRequest::Stop);
                        return statuses;
                    }
                    CoinResponse::Error(e) => {
                        if let Some(claim) = clear_merkle_in_flight_on_error(&coin_store, &e) {
                            retry_reorged_merkle_claim(
                                &coin_store,
                                &header_store,
                                &request,
                                &notification,
                                claim,
                            );
                        }
                        send_notif!(
                            notification,
                            request,
                            statuses,
                            TxListenerNotif::Error(e.into())
                        );
                    }
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    // NOTE: here the electrum client is dropped, we cannot continue
                    log::error!("listen_txs() electrum client stopped unexpectedly");
                    send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                    let _ = request.send(CoinRequest::Stop);
                    return statuses;
                }
            },
        }

        // Drain the HeaderStore CTA receiver. Multiple () are coalesced
        // into a single on_chain_update pass.
        let mut chain_tick = false;
        loop {
            match chain_rx.try_recv() {
                Ok(()) => {
                    chain_tick = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // HeaderStore was dropped. Stop draining; the
                    // Account itself still owns its Arc, so this only
                    // fires once the public Account is gone.
                    break;
                }
            }
        }
        if chain_tick {
            received = true;
            on_chain_update(&coin_store, &header_store, &request, &notification);
            // Promotions may have just given entries a height whose header has
            // now landed; stamp their confirmation time from the chain.
            stamp_confirmation_times(&coin_store, &header_store);
        }

        if received {
            continue;
        }
        backoff.snooze();
    }
}

fn flush_statuses<S: Store>(statuses: &mut S) {
    if let Err(e) = statuses.flush() {
        log::error!("listen_txs(): statuses flush: {e}");
    }
}

/// Replicate the `send_electrum!`/`send_notif!` failure path: tell the consumer
/// the listener stopped, and if even that fails, ask the client to stop. Returns
/// `Break` so the caller can end the listener thread.
fn signal_stopped(
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    if notification.send(TxListenerNotif::Stopped.into()).is_err() {
        let _ = request.send(CoinRequest::Stop);
    }
    ControlFlow::Break(())
}

/// Gate every claim-promotion pass on header validation: `true` when the
/// store is validated, otherwise notify `ValidationFailed(HeaderStore(_))`
/// (when the store rejected its own replay) and return `false` so the
/// caller refuses to promote against an unvalidated header.
fn header_store_ready<P: StorageProfile>(
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
) -> bool {
    if header_store.is_validated() {
        return true;
    }
    if let Some(reason) = header_store.validation_failed_reason() {
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::HeaderStore(reason),
        ));
    }
    false
}

fn clear_merkle_in_flight_on_error<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    error: &CoinError,
) -> Option<ClaimAt> {
    let claim = match error {
        CoinError::MerkleDecode { txid, height, .. }
        | CoinError::MerkleFetch { txid, height, .. } => ClaimAt {
            txid: *txid,
            height: *height,
        },
        _ => return None,
    };
    coin_store
        .lock()
        .expect("poisoned")
        .clear_merkle_in_flight(&claim);
    Some(claim)
}

fn retry_reorged_merkle_claim<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    claim: ClaimAt,
) {
    let stored_hash = coin_store
        .lock()
        .expect("poisoned")
        .tx_store_mut()
        .get(&claim.txid)
        .and_then(|entry| match entry.inclusion() {
            Inclusion::ConfirmedUnverified { height, block_hash } if *height == claim.height => {
                Some(*block_hash)
            }
            _ => None,
        });
    if stored_hash.is_some_and(|hash| {
        header_store
            .block_hash(claim.height)
            .is_some_and(|current| current != hash)
    }) {
        on_chain_update(coin_store, header_store, request, notification);
    }
}

/// Apply a resolved [`ChainUpdateOutcome`]: persist and regenerate when it
/// changed state, release the coin-store lock, dispatch the queued merkle
/// fetches, and notify `HeaderStoreUpdated` on a change.
fn apply_chain_update<P: StorageProfile>(
    mut store: MutexGuard<'_, CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    outcome: ChainUpdateOutcome,
) {
    if outcome.changed {
        store.tx_store_mut().persist();
        store.generate();
    }
    drop(store);
    queue_merkle_fetches(request, outcome.to_fetch);
    if outcome.changed {
        let _ = notification.send(Notification::HeaderStoreUpdated);
    }
}

/// Grow the watched spk set for an `AddressTip`: register the new receive/change
/// gaps in `statuses`, then subscribe to them. `Break` ends the listener thread.
fn handle_address_tip<P: StorageProfile>(
    tip: AddressTip,
    derivator: &SpkDerivator,
    statuses: &mut P::StatusesStore,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let AddressTip { recv, change } = tip;
    let mut sub = vec![];
    // `recv` is the tip the loop below stops before, so the highest index it
    // ever inserts is `recv - 1`. Testing `recv` itself never matches and the
    // rescan runs on every tip.
    let r_spk = derivator.receive_at(recv.saturating_sub(1)).script_pubkey();
    if !statuses.contains_key(&r_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..recv {
            let spk = derivator.receive_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_RECEIVE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    let c_spk = derivator
        .change_at(change.saturating_sub(1))
        .script_pubkey();
    if !statuses.contains_key(&c_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..change {
            let spk = derivator.change_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_CHANGE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    if !sub.is_empty() {
        flush_statuses(statuses);
        if request.send(CoinRequest::Subscribe(sub)).is_err() {
            return signal_stopped(request, notification);
        }
    }
    ControlFlow::Continue(())
}

/// Fold an Electrum `Status` response: diff against the local statuses, request
/// history for changed-non-empty scripthashes, clear the cleared ones, and flush
/// if any local status changed. `Break` ends the listener thread.
fn handle_status_response<P: StorageProfile>(
    elct_status: BTreeMap<ScriptBuf, Option<String>>,
    statuses: &mut P::StatusesStore,
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut history = vec![];
    let mut dirty = false;
    for (spk, status) in elct_status {
        match statuses.get(&spk) {
            Ok(Some((s, _, _))) => {
                // status is registered
                if s != status {
                    // status changed
                    if status.is_some() {
                        // not empty: ask for tx changes
                        history.push(spk.clone());
                    } else {
                        // Some(_) -> None: clear coin_store
                        let mut store = coin_store.lock().expect("poisoned");
                        let mut map = BTreeMap::new();
                        map.insert(spk.clone(), vec![]);
                        let _ = store.handle_history_response(map);
                        store.generate();
                    }
                    // record the local status change
                    let new_status = status.clone();
                    match statuses.modify(&spk, |v| v.0 = new_status.clone()) {
                        Ok(true) => dirty = true,
                        Ok(false) => {
                            // race-free under single-listener thread:
                            // we just observed the entry above
                        }
                        Err(e) => {
                            log::error!("listen_txs(): statuses modify: {e}");
                        }
                    }
                }
            }
            Ok(None) => {
                // not registered: previous behaviour was an
                // `entry(spk).and_modify(...)`, which is a no-op
                // for vacant entries. Preserve that, only the
                // history-side effect remains.
                if status.is_some() {
                    history.push(spk);
                } else {
                    let mut store = coin_store.lock().expect("poisoned");
                    let mut map = BTreeMap::new();
                    map.insert(spk.clone(), vec![]);
                    let _ = store.handle_history_response(map);
                }
            }
            Err(e) => {
                log::error!("listen_txs(): statuses get: {e}");
            }
        }
    }
    if !history.is_empty() {
        let hist = CoinRequest::History(history);
        log::debug!("listen_txs() send {}", hist.summary());
        if request.send(hist).is_err() {
            return signal_stopped(request, notification);
        }
    }
    if dirty {
        flush_statuses(statuses);
    }
    ControlFlow::Continue(())
}

/// Fold a `History` response into the coin store, fetch any missing txs, and
/// resolve the reported heights. `Break` ends the listener thread.
fn handle_history_response_msg<P: StorageProfile>(
    map: BTreeMap<ScriptBuf, Vec<(Txid, Option<u64>)>>,
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut store = coin_store.lock().expect("poisoned");
    let outcome = store.handle_history_response(map);
    if !outcome.missing_txs.is_empty()
        && request.send(CoinRequest::Txs(outcome.missing_txs)).is_err()
    {
        return signal_stopped(request, notification);
    }
    // Folding the history above is unconditional; promoting the reported
    // heights against an unvalidated header is not. When the store is not
    // validated, persist any folded height changes but skip promotion.
    if !header_store_ready::<P>(header_store, notification) {
        let pending_changed = store.queue_reported_heights(&outcome.reported);
        if outcome.height_updated {
            store.tx_store_mut().persist();
            store.generate();
        }
        drop(store);
        if pending_changed || outcome.height_updated {
            let _ = notification.send(Notification::PaymentHistoryUpdated);
        }
        return ControlFlow::Continue(());
    }
    // Promote (or queue) heights now that the history is folded into the tx store.
    let promo = store.resolve_reported_heights(header_store, &outcome.reported);
    let changed = outcome.height_updated || promo.changed;
    apply_chain_update(
        store,
        request,
        notification,
        ChainUpdateOutcome {
            to_fetch: promo.to_fetch,
            changed,
        },
    );
    ControlFlow::Continue(())
}

/// Fold a `Txs` response into the coin store, then run a resolve-only pass:
/// newly-inserted txs may have a `(txid, height)` already queued in
/// `pending_claims` from a prior `History`, so promote them now instead of
/// waiting for the next header tick. Only `resolve_pending_claims` runs here;
/// `reverify_remined_entries` stays on the chain-tick path.
fn handle_txs_response_msg<P: StorageProfile>(
    txs: Vec<bitcoin::Transaction>,
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) {
    let mut store = coin_store.lock().expect("poisoned");
    store.handle_txs_response(txs);
    if !header_store_ready::<P>(header_store, notification) {
        return;
    }
    let promote = store.resolve_pending_claims(header_store);
    apply_chain_update(store, request, notification, promote);
}

/// Verify a `TxMerkle` response and promote the entry to `Verified`, or mark it
/// terminally `VerifyFailed` on a hard proof mismatch.
#[allow(clippy::too_many_arguments)]
fn handle_tx_merkle<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    txid: Txid,
    height: u32,
    branch: Vec<[u8; 32]>,
    pos: u32,
) {
    // A TxMerkle response means the in-flight fetch resolved, whatever the
    // outcome; free the re-queue slot before anything else so a superseded
    // or dropped fetch can be re-issued by a later CTA pass.
    coin_store
        .lock()
        .expect("poisoned")
        .clear_merkle_in_flight(&ClaimAt { txid, height });

    if !header_store_ready::<P>(header_store, notification) {
        return;
    }
    let claim = ClaimAt { txid, height };
    let Some(target) = resolve_tx_merkle_target(coin_store, header_store, txid, height) else {
        retry_reorged_merkle_claim(coin_store, header_store, request, notification, claim);
        return;
    };
    apply_tx_merkle(coin_store, request, notification, target, &branch, pos);
}

/// The verified target of a `TxMerkle` response: the entry is
/// `ConfirmedUnverified` at exactly `height`, its stored hash still matches
/// the header there, and `expected_root` is that header's merkle root.
struct MerkleTarget {
    txid: Txid,
    height: u32,
    block_hash: BlockHash,
    expected_root: TxMerkleNode,
}

/// Guard a `TxMerkle` response against stale or mismatched state and return
/// the target to verify, or `None` (with a debug log) when it must be skipped.
fn resolve_tx_merkle_target<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    txid: Txid,
    height: u32,
) -> Option<MerkleTarget> {
    // Read header data first (without holding the coin_store lock). If
    // headers were pruned by a recent reorg between request and response,
    // the CTA re-fetch pass (`reverify_remined_entries`) re-queues the
    // proof once a header is present at this height again.
    let (expected_root, block_hash) = match header_store.merkle_root_and_hash(height) {
        Some(v) => v,
        None => {
            log::debug!(
                "handle_tx_merkle(): TxMerkle for {txid}@{height} but no header in header_store; skipping"
            );
            return None;
        }
    };

    let mut store = coin_store.lock().expect("poisoned");
    let current = match store.tx_store_mut().get(&txid) {
        Some(entry) => entry.inclusion().clone(),
        None => {
            log::debug!("handle_tx_merkle(): TxMerkle for unknown txid {txid}; skipping");
            return None;
        }
    };
    let (entry_height, entry_hash) = match current {
        Inclusion::ConfirmedUnverified { height, block_hash } => (height, block_hash),
        _ => {
            log::debug!(
                "handle_tx_merkle(): TxMerkle for {txid} not in ConfirmedUnverified state ({current:?}); skipping"
            );
            return None;
        }
    };
    // Only verify the proof against the height the entry is actually
    // claimed at; a stale response for a different height must not promote.
    if entry_height != height {
        log::debug!(
            "handle_tx_merkle(): TxMerkle height {height} != entry height {entry_height} for {txid}; skipping"
        );
        return None;
    }
    // The entry's stored hash no longer matches the header at this height:
    // a reorg raced the merkle fetch. This is not a lying server, so stay
    // silent; the reorg re-queue (reverify_remined_entries) owns recovery.
    if entry_hash != block_hash {
        log::debug!(
            "handle_tx_merkle(): TxMerkle for {txid}@{height} stored hash {entry_hash} != current hash {block_hash}; reorg race, skipping"
        );
        return None;
    }
    Some(MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    })
}

/// Verify the branch against `target` and update the entry: `Verified` via the
/// shared CTA apply on a good proof, else terminal `VerifyFailed` with a
/// one-shot `ValidationFailed(MerkleProof)` notification.
fn apply_tx_merkle<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    target: MerkleTarget,
    branch: &[[u8; 32]],
    pos: u32,
) {
    let MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    } = target;
    let mut store = coin_store.lock().expect("poisoned");
    // The branch arrives in internal (little-endian) order from
    // `decode_tx_merkle_branch`, so it feeds `verify_merkle_branch` directly.
    if crate::header_store::verify_merkle_branch(txid, branch, pos, expected_root) {
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::Verified { height, block_hash });
        apply_chain_update(
            store,
            request,
            notification,
            ChainUpdateOutcome {
                to_fetch: Vec::new(),
                changed: true,
            },
        );
    } else {
        // Hard proof mismatch: mark the entry terminally VerifyFailed so it is
        // not re-fetched every tick, and surface the failure exactly once.
        // reverify_remined_entries clears it only if the header hash changes.
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::VerifyFailed { height, block_hash });
        store.tx_store_mut().persist();
        store.generate();
        drop(store);
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::MerkleProof { txid, height },
        ));
    }
}

/// Stamp confirmed, un-timestamped txs with their block time, read from the
/// validated header chain. Entries whose header has not synced yet are left for
/// a later pass.
fn stamp_confirmation_times<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
) {
    let mut store = coin_store.lock().expect("poisoned");
    store.stamp_confirmation_times(|h| header_store.header(h as u32).map(|hdr| hdr.time as u64));
}

/// Chain-tip-advance pass: promote-only, resolves pending claims and queues merkle fetches against the validated chain.
fn on_chain_update<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    electrum_req: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) {
    if !header_store_ready::<P>(header_store, notification) {
        return;
    }

    let mut store = coin_store.lock().expect("poisoned");

    let reverify = store.reverify_remined_entries(header_store);
    let promote = store.resolve_pending_claims(header_store);
    let changed = reverify.changed || promote.changed;
    let mut to_fetch = reverify.to_fetch;
    to_fetch.extend(promote.to_fetch);

    apply_chain_update(
        store,
        electrum_req,
        notification,
        ChainUpdateOutcome { to_fetch, changed },
    );
}

/// Dispatch the collected merkle-proof fetches outside the CoinStore lock.
fn queue_merkle_fetches(electrum_req: &mpsc::Sender<CoinRequest>, to_fetch: Vec<ClaimAt>) {
    for ClaimAt { txid, height } in to_fetch {
        let _ = electrum_req.send(CoinRequest::GetTxMerkle { txid, height });
    }
}

/// Re-queue a `GetTxMerkle` fetch for every `ConfirmedUnverified` entry on
/// listener (re)connect, covering entries stranded while the listener was
/// down; between reconnects the CTA re-fetch pass retries them.
fn requeue_confirmed_unverified<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    electrum_req: &mpsc::Sender<CoinRequest>,
) {
    let to_fetch = coin_store
        .lock()
        .expect("poisoned")
        .confirmed_unverified_claims();
    queue_merkle_fetches(electrum_req, to_fetch);
}

/// On listener (re)connect, force a `History` refresh for every spk that
/// owns a still-`Inclusion::Unconfirmed` tx. `pending_claims` is an
/// in-memory cache a restart wipes, and the resubscribed status matches the
/// persisted `StatusesStore`, so no status-diff `History` fires on its own;
/// without this a tx already confirmed at some height would stay Unconfirmed
/// until an unrelated status change. The server re-reports the height, which
/// `resolve_reported_heights` turns back into a promotion or a fresh claim.
fn refresh_unconfirmed_history<P: StorageProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    electrum_req: &mpsc::Sender<CoinRequest>,
) {
    let spks = coin_store
        .lock()
        .expect("poisoned")
        .spks_with_unconfirmed_txs();
    if !spks.is_empty() {
        let _ = electrum_req.send(CoinRequest::History(spks));
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use crate::tx_store::TxStore;
    use bip39::Mnemonic;
    use bwk_coin::CoinStatus;
    use bwk_descriptor::descriptor::{wpkh, ScriptType};
    use bwk_electrum::{
        client::DecodeError,
        electrum::response::{ErrorResponse, ErrorResult},
    };
    use bwk_persist::NoopBackend;
    use bwk_sign::hot_signer::HotSigner;
    use bwk_utils::test::{funding_tx, setup_logger, spending_tx};
    use miniscript::bitcoin::{bip32::ChildNumber, Network};
    use std::{path::PathBuf, str::FromStr, sync::mpsc::TryRecvError, time::Duration};
    use temp_dir::TempDir;
    use {bip39, miniscript::bitcoin::bip32::DerivationPath};

    struct CoinStoreMock {
        pub store: Arc<Mutex<CoinStore>>,
        pub notif: mpsc::Receiver<Notification>,
        pub request: mpsc::Receiver<CoinRequest>,
        pub response: mpsc::Sender<CoinResponse>,
        pub listener: JoinHandle<()>,
        pub stop: Arc<AtomicBool>,
        pub derivator: SpkDerivator,
    }

    impl Drop for CoinStoreMock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    impl CoinStoreMock {
        fn new(recv_tip: u32, change_tip: u32, look_ahead: u32) -> Self {
            let (notif_sender, notif_recv) = mpsc::channel();
            let (tip_sender, tip_receiver) = mpsc::channel();
            let (req_sender, req_receiver) = mpsc::channel();
            let (resp_sender, resp_receiver) = mpsc::channel();
            let mnemo = Mnemonic::generate(12).unwrap();
            let dummy_config = Config::new(
                Some(mnemo.to_string()),
                "dummy".into(),
                Network::Regtest,
                ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
                PathBuf::default(),
                String::new(),
                false,
            )
            .unwrap();

            let mnemonic = bip39::Mnemonic::generate(12).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let signer =
                HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, &mnemonic.to_string())
                    .unwrap();
            let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
            let descriptor = wpkh(xpub);
            let derivator =
                SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();

            let tx_store = TxStore::new();
            let label_store = Arc::new(Mutex::new(LabelStore::new()));
            let mock_backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
            let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
                mock_backend.clone(),
                bwk_persist::ACCOUNT_STORE_KEY,
                crate::profile::encode_account_key,
                crate::profile::encode_account_value,
            )));
            let statuses_store = bwk_persist::RamStore::open(
                mock_backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .expect("open statuses RamStore");
            let coin_store = Arc::new(Mutex::new(CoinStore::new(
                bitcoin::Network::Regtest,
                descriptor.clone(),
                notif_sender.clone(),
                recv_tip,
                change_tip,
                look_ahead,
                tx_store,
                label_store,
                dummy_config,
                account_store,
            )));
            coin_store.lock().expect("poisoned").init(tip_sender);
            let store = coin_store.clone();
            let cloned_stop = stop.clone();
            let cloned_derivator = derivator.clone();

            let header_store = HeaderStore::new_in_memory(Network::Regtest);
            let chain_rx = header_store.register();
            let header_store_t = header_store.clone();

            let listener_handle = thread::spawn(move || {
                listen_txs::<RamProfile<DefaultBackend>>(
                    coin_store,
                    cloned_derivator,
                    notif_sender,
                    tip_receiver,
                    stop,
                    req_sender,
                    resp_receiver,
                    statuses_store,
                    header_store_t,
                    chain_rx,
                );
            });

            CoinStoreMock {
                store,
                notif: notif_recv,
                request: req_receiver,
                response: resp_sender,
                listener: listener_handle,
                stop: cloned_stop,
                derivator,
            }
        }

        fn coins(&mut self) -> BTreeMap<OutPoint, CoinEntry> {
            self.store.lock().expect("poisoned").coins()
        }

        fn stop(&self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    // Build a bare `CoinStore` (no listener thread) for testing the
    // CTA helpers directly.
    fn bare_coin_store() -> (Arc<Mutex<CoinStore>>, SpkDerivator) {
        let (notif_sender, _notif_recv) = mpsc::channel();
        let mnemo = Mnemonic::generate(12).unwrap();
        let dummy_config = Config::new(
            Some(mnemo.to_string()),
            "dummy".into(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            PathBuf::default(),
            String::new(),
            false,
        )
        .unwrap();
        let signer =
            HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let descriptor = wpkh(xpub);
        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        let label_store = Arc::new(Mutex::new(LabelStore::new()));
        let backend: Arc<dyn bwk_persist::PersistenceBackend> = Arc::new(NoopBackend);
        let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
            backend,
            bwk_persist::ACCOUNT_STORE_KEY,
            crate::profile::encode_account_key,
            crate::profile::encode_account_value,
        )));
        let coin_store = Arc::new(Mutex::new(CoinStore::new(
            bitcoin::Network::Regtest,
            descriptor,
            notif_sender,
            0,
            0,
            20,
            TxStore::new(),
            label_store,
            dummy_config,
            account_store,
        )));
        (coin_store, derivator)
    }

    /// Build a regtest header chain of `len` blocks (heights `0..len`),
    /// returning the (height -> raw) map and the tip block hash.
    fn build_header_map(len: u32) -> (BTreeMap<u32, [u8; 80]>, miniscript::bitcoin::BlockHash) {
        use miniscript::bitcoin::{
            block::{Header, Version},
            hashes::Hash,
            BlockHash, CompactTarget, TxMerkleNode,
        };
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut map = BTreeMap::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = prev;
        for h in 0..len {
            let hdr = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + h,
                bits,
                nonce: h,
            };
            prev = hdr.block_hash();
            tip = prev;
            let bytes = miniscript::bitcoin::consensus::serialize(&hdr);
            let mut arr = [0u8; 80];
            arr.copy_from_slice(&bytes);
            map.insert(h, arr);
        }
        (map, tip)
    }

    // Regression: after a deep reorg re-confirms a tx at a height
    // M different from the originally-claimed height N, the stale
    // `(N, txid)` entry must not linger in `pending_claims`.
    #[test]
    fn deep_reorg_clears_stale_pending_claims() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        // Seed a tx that is Verified at height M = 7.
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let m: u32 = 7;

        // Build a HeaderStore holding a header at M. `on_chain_update`
        // never demotes, so the Verified-at-M claim is left untouched; the
        // header is present so the seeded state is internally consistent.
        let (map, hash_at_m) = build_header_map(m + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: m,
                    block_hash: hash_at_m,
                },
            );
        }

        // Stale pending claim at the OLD height N = 4 (pre-reorg).
        let n: u32 = 4;
        coin_store
            .lock()
            .unwrap()
            .insert_pending_claim(ClaimAt { txid, height: n });

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // The stale (N, txid) entry must have been swept (tx is Verified
        // at M != N).
        let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
        assert!(
            snapshot.get(&n).map(|s| !s.contains(&txid)).unwrap_or(true),
            "stale pending claim at N={n} was not cleared: {snapshot:?}",
        );
    }

    // Regression: a claim whose tx is still in flight (History folded, Txs
    // response not yet) must survive a CTA pass. Dropping it as "removed
    // from the chain" wedges the tx Unconfirmed forever once it folds.
    #[test]
    fn pending_claim_survives_tx_fetch_in_flight() {
        use crate::header_store::HeaderStore;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();
        let (notif_tx, _notif_rx) = mpsc::channel();

        // History reports the confirmed tx before its bytes are known: the
        // update stays incomplete and the claim is queued, not promoted.
        {
            let mut store = coin_store.lock().unwrap();
            let mut hist = BTreeMap::new();
            hist.insert(spk, vec![(txid, Some(h as u64))]);
            let outcome = store.handle_history_response(hist);
            assert_eq!(outcome.missing_txs, vec![txid], "tx bytes must be missing");
            let promo = store.resolve_reported_heights(&header_store, &outcome.reported);
            assert!(promo.to_fetch.is_empty(), "nothing to fetch yet");
        }

        // CTA fires while the Txs response is still in flight: the claim
        // must survive (the txid is referenced by an incomplete update).
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        {
            let store = coin_store.lock().unwrap();
            let snapshot = store.pending_claims_snapshot();
            assert!(
                snapshot.get(&h).map(|s| s.contains(&txid)).unwrap_or(false),
                "in-flight claim was dropped: {snapshot:?}",
            );
        }

        // The Txs response folds the tx, then the next CTA promotes it.
        coin_store.lock().unwrap().handle_txs_response(vec![tx]);
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert_eq!(
                entry.inclusion(),
                &Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
                "claim was not promoted after the tx folded",
            );
        }
        match req_rx.try_recv() {
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) => {
                assert_eq!(t, txid);
                assert_eq!(height, h);
            }
            other => panic!("expected GetTxMerkle, got {other:?}"),
        }
    }

    // Regression: history re-reports EVERY confirmed tx, not just the ones
    // whose height changed. An already-Verified tx re-reported at its SAME
    // height must stay Verified (the pass is promote-only); it must not be
    // demoted to ConfirmedUnverified nor trigger a fresh GetTxMerkle.
    #[test]
    fn re_report_does_not_demote_verified() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        // HeaderStore holds a real header at H, so the seeded Verified state
        // is internally consistent.
        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();

        // Server re-reports the same tx at the same height.
        {
            let mut store = coin_store.lock().unwrap();
            let promo =
                store.resolve_reported_heights(&header_store, &[ClaimAt { txid, height: h }]);
            queue_merkle_fetches(&req_tx, promo.to_fetch);
        }

        // The entry is STILL Verified at H (not demoted).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::Verified {
                    height, block_hash, ..
                } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, hash_at_h, "block_hash changed");
                }
                other => panic!("expected Verified{{H}}, got {other:?}"),
            }
        }

        // No GetTxMerkle was queued.
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a re-reported Verified tx",
        );
    }

    // A ConfirmedUnverified entry whose stored hash still matches the header
    // (its single-shot merkle fetch was dropped or errored) must be
    // re-queued by the CTA pass, without mutating state or notifying.
    #[test]
    fn stuck_confirmed_unverified_refetched_by_cta() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // Exactly one re-queued fetch.
        assert!(matches!(
            req_rx.try_recv().unwrap(),
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // No state change: entry untouched, nothing notified.
        assert!(matches!(notif_rx.try_recv(), Err(TryRecvError::Empty)));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash }
                if *height == h && *block_hash == hash_at_h
        ));
    }

    // A Verified entry whose stored hash matches the header must NOT be
    // re-fetched by the CTA pass.
    #[test]
    fn verified_with_matching_hash_not_refetched_by_cta() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a Verified entry with a matching hash",
        );
    }

    // Same-height reorg re-verification: a tx left `Verified` at height H
    // against a now-stale `block_hash` (the server re-mined it at the SAME
    // height in a DIFFERENT block, so the scripthash status is unchanged and
    // the history path never demotes it). `on_chain_update` must notice the
    // stored hash no longer matches the HeaderStore header at H, reset the
    // entry to `ConfirmedUnverified { H, B_new }`, and queue a fresh
    // `GetTxMerkle { H }`. It must NOT push the entry to `Unconfirmed`.
    #[test]
    fn same_height_reorg_reverifies_stale_block_hash() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // Build a HeaderStore whose header at H has block hash B_new,
        // distinct from the B_old we seed the tx with below.
        let (map, b_new) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // A clearly different (stale) block hash B_old, distinct from B_new.
        let b_old = miniscript::bitcoin::BlockHash::from_byte_array([0x7au8; 32]);
        assert_ne!(b_old, b_new);

        // Seed the tx Verified at H with the stale hash B_old.
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: b_old,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // The entry was reset to ConfirmedUnverified at the SAME height with
        // the NEW block hash (re-verification, not demotion).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::ConfirmedUnverified { height, block_hash } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, b_new, "block_hash not updated to B_new");
                }
                other => panic!("expected ConfirmedUnverified{{H,B_new}}, got {other:?}"),
            }
        }

        // A GetTxMerkle for (txid, H) must have been queued.
        let mut saw_merkle = false;
        while let Ok(req) = req_rx.try_recv() {
            if let CoinRequest::GetTxMerkle { txid: t, height } = req {
                if t == txid && height == h {
                    saw_merkle = true;
                }
            }
        }
        assert!(saw_merkle, "GetTxMerkle{{H}} was not queued");
    }

    #[test]
    fn history_waits_for_header_validation_then_promotes_reported_claim() {
        use crate::header_store::{HeaderStore, HeaderValidationState};

        let (coin_store, derivator) = bare_coin_store();
        let spk = derivator.receive_spk_at(0);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 4;

        let (map, block_hash) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store.set_validation_state_for_test(HeaderValidationState::Validating);

        {
            let mut store = coin_store.lock().unwrap();
            store.insert_pending_claim(ClaimAt {
                txid,
                height: h - 1,
            });
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        assert!(handle_history_response_msg(
            BTreeMap::from([(spk, vec![(txid, Some(h as u64))])]),
            &coin_store,
            &header_store,
            &req_tx,
            &notif_tx,
        )
        .is_continue());
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::Txs(txids)) if txids == vec![txid]
        ));
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));
        {
            let mut store = coin_store.lock().unwrap();
            assert!(store.tx_store_mut().get(&txid).is_none());
            assert_eq!(
                store.pending_claims_snapshot(),
                BTreeMap::from([(h, BTreeSet::from([txid]))])
            );
        }

        header_store.set_validation_state_for_test(HeaderValidationState::Valid);
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            coin_store.lock().unwrap().pending_claims_snapshot(),
            BTreeMap::from([(h, BTreeSet::from([txid]))])
        );

        handle_txs_response_msg(vec![tx], &coin_store, &header_store, &req_tx, &notif_tx);

        let req = req_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("validation recovery should queue merkle proof");
        assert!(matches!(
            req,
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash: bh }
                if *height == h && *bh == block_hash
        ));
    }

    #[test]
    fn merkle_errors_release_only_their_in_flight_fetch() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 4;
        let (map, block_hash) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        {
            let mut store = coin_store.lock().unwrap();
            store.tx_store_mut().update(TxEntry::for_test(tx));
            store.tx_store_mut().update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash,
                },
            );
        }
        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        let server_error = ErrorResponse {
            id: 1,
            error: ErrorResult {
                code: 1,
                message: "failed".to_string(),
            },
        };
        clear_merkle_in_flight_on_error(&coin_store, &CoinError::Server(server_error.clone()));
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        clear_merkle_in_flight_on_error(
            &coin_store,
            &CoinError::MerkleFetch {
                txid,
                height: h - 1,
                error: server_error.clone(),
            },
        );
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        clear_merkle_in_flight_on_error(
            &coin_store,
            &CoinError::MerkleFetch {
                txid,
                height: h,
                error: server_error,
            },
        );
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        clear_merkle_in_flight_on_error(
            &coin_store,
            &CoinError::MerkleDecode {
                txid,
                height: h,
                source: DecodeError::MerkleHashLength { index: 0, got: 1 },
            },
        );
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).unwrap();
        assert_eq!(
            entry.inclusion(),
            &Inclusion::ConfirmedUnverified {
                height: h,
                block_hash,
            }
        );
    }

    // Regression for the stale-pending-claim wedge: a tx queued at an OLD
    // height N_old (whose header IS present) must not be promoted to N_old
    // after a reorg re-reports it at N_new. `resolve_reported_heights` must
    // drop the stale `(N_old, txid)` claim before queueing `(N_new, txid)`,
    // so the subsequent `on_chain_update` cannot promote the tx to the
    // wrong (N_old) height and wedge it ConfirmedUnverified forever.
    #[test]
    fn re_report_purges_stale_pending_claim() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let n_old: u32 = 4;
        let n_new: u32 = 9;

        // HeaderStore holds headers 0..=n_old only. Height n_new has NO
        // header yet, so the re-report at n_new takes the queue branch
        // while n_old IS reachable (the dangerous case).
        let (map, _tip) = build_header_map(n_old + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // Seed the tx as Unconfirmed (post-reorg history reset state).
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
        }

        // Pre-existing stale pending claim at the OLD height N_old.
        coin_store.lock().unwrap().insert_pending_claim(ClaimAt {
            txid,
            height: n_old,
        });

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        // History re-reports the tx at N_new (its new post-reorg height).
        {
            let mut store = coin_store.lock().unwrap();
            store.resolve_reported_heights(
                &header_store,
                &[ClaimAt {
                    txid,
                    height: n_new,
                }],
            );
        }

        // The stale (N_old, txid) entry is gone; only (N_new, txid) remains.
        {
            let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
            assert!(
                snapshot
                    .get(&n_old)
                    .map(|s| !s.contains(&txid))
                    .unwrap_or(true),
                "stale pending claim at N_old={n_old} not purged: {snapshot:?}",
            );
            assert!(
                snapshot
                    .get(&n_new)
                    .map(|s| s.contains(&txid))
                    .unwrap_or(false),
                "new pending claim at N_new={n_new} not queued: {snapshot:?}",
            );
        }

        // A subsequent CTA must NOT promote the tx to N_old (its header is
        // reachable, but the stale claim is gone). The tx stays Unconfirmed.
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "tx wrongly promoted to {:?} (expected Unconfirmed)",
            entry.inclusion(),
        );
    }

    fn persisted_offline_config(dir: &TempDir, look_ahead: u32) -> Config {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "acct".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            dir.path().to_path_buf(),
            ".bwk".to_string(),
            true, // persist
        )
        .unwrap();
        config.look_ahead = look_ahead;
        config.set_offline(true);
        config
    }

    #[test]
    fn restart_restores_deep_change_tip_and_high_index_history_no_panic() {
        // Regression for the `address_store.rs "must be there"` panic on
        // wallets whose used range exceeds look_ahead. Drive the change tip
        // past look_ahead, reopen, then deliver history for a script beyond
        // the restored window.
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 2);
        let saved = config.clone();

        let derivator;
        {
            let mut account: Account = Account::new(config);
            for _ in 0..10 {
                account.new_change_addr();
            }
            derivator = account.derivator();
            assert!(account.change_watch_tip() >= 10);
            drop(account);
        }

        // Reopen: the tip must be restored (fix 1), not reset to 0.
        let account: Account = Account::new(saved);
        assert!(
            account.change_watch_tip() >= 10,
            "change tip must survive restart, got {}",
            account.change_watch_tip()
        );

        // History for a change script past the restored window must extend the
        // store rather than panic (fix 3).
        let beyond = account.change_watch_tip() + 5;
        let spk = derivator.change_at(beyond).script_pubkey();
        {
            let mut store = account.coin_store.lock().expect("poisoned");
            let mut map = BTreeMap::new();
            map.insert(spk.clone(), vec![]);
            store.handle_history_response(map);
        }
        assert!(
            account.change_watch_tip() > beyond,
            "store must extend to cover the reported high-index script"
        );
        drop(account);
    }

    #[test]
    fn tip_restored_from_statuses_when_account_store_empty() {
        // The watch window must cover persisted subscriptions even when the
        // tip rows are absent (fix 2): seed statuses with a high-index change
        // script, write no tip, then open the account.
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 2);

        let account_dir = config.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .unwrap();
            statuses
                .insert(ScriptBuf::from_bytes(vec![0x00; 22]), (None, 1, 30))
                .unwrap();
            statuses.flush().unwrap();
        }

        let account: Account = Account::new(config);
        assert!(
            account.change_watch_tip() >= 30,
            "change tip must be floored by the statuses max index, got {}",
            account.change_watch_tip()
        );
        drop(account);
    }

    #[cfg(feature = "test")]
    #[test]
    fn statuses_floor_does_not_inflate_generated_tip() {
        // The statuses store spans the whole watch window (generated tip plus
        // look-ahead), so its max index is `generated + look_ahead`. Flooring the
        // restored tip with that raw max would climb the generated tip by one
        // look-ahead on every reopen. Seed a change status at the top of the
        // window for generated tip 10 (look-ahead 2, so index 12) and assert the
        // restored watch tip is 13 (generated 10 + 2 + 1), not 15 (an inflated
        // generated tip of 12).
        let look_ahead = 2u32;
        let generated = 10u32;
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, look_ahead);

        let account_dir = config.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .unwrap();
            statuses
                .insert(
                    ScriptBuf::from_bytes(vec![0x01; 22]),
                    (None, 1, generated + look_ahead),
                )
                .unwrap();
            statuses.flush().unwrap();
        }

        let account: Account = Account::new(config);
        assert_eq!(
            account.change_watch_tip(),
            generated + look_ahead + 1,
            "generated tip must not be inflated by the look-ahead on reopen"
        );
        drop(account);
    }

    #[test]
    fn simple_start_stop() {
        setup_logger();
        let mock = CoinStoreMock::new(0, 0, 20);
        thread::sleep(Duration::from_millis(10));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));
        mock.stop();
        thread::sleep(Duration::from_secs(1));
        assert!(mock.listener.is_finished());
    }

    fn simple_recv() -> (bitcoin::Transaction, CoinStoreMock) {
        setup_logger();
        let look_ahead = 5;
        let mut mock = CoinStoreMock::new(0, 0, look_ahead);
        thread::sleep(Duration::from_millis(500));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));

        let mut init_spks = vec![];
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.receive_spk_at(i);
            init_spks.push(spk);
        }
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.change_spk_at(i);
            init_spks.push(spk);
        }

        // receive initial subscriptions
        if let Ok(CoinRequest::Subscribe(v)) = mock.request.try_recv() {
            // NOTE: we expect (tip + 1 + look_ahead )
            assert_eq!(v.len(), 12);
            for spk in &init_spks {
                assert!(v.contains(spk));
            }
        } else {
            panic!()
        }

        // electrum server send spks statuses (None)
        let statuses: BTreeMap<_, _> = init_spks.clone().into_iter().map(|s| (s, None)).collect();
        mock.response.send(CoinResponse::Status(statuses)).unwrap();

        thread::sleep(Duration::from_millis(100));

        assert!(mock.coins().is_empty());

        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_unco".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        let tx_0 = funding_tx(spk_recv_0.clone(), 0.1);

        // server must send history response
        let mut history = BTreeMap::new();
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), None)]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_0.compute_txid()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_0.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);

        // NOTE: the coin is now confirmed

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_conf".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(1))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // NOTE: coin_store already have the tx it should not ask it
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // The server reports inclusion at height 1. `insert_history`
        // resets the entry to `Unconfirmed`, then `resolve_reported_heights`
        // tries to re-claim it, but this mock's HeaderStore is empty, so
        // there is no header at height 1 and the claim is queued in
        // `pending_claims` rather than promoted. The derived coin height
        // therefore stays None and the status stays Unconfirmed until a
        // header at that height arrives.
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);
        (tx_0, mock)
    }

    #[test]
    fn payment_history_projects_pending_claim_as_confirmed_unverified() {
        let mnemo = Mnemonic::generate(12).unwrap();
        let config = Config::new(
            Some(mnemo.to_string()),
            "dummy".into(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            PathBuf::default(),
            String::new(),
            false,
        )
        .unwrap();
        let header_store = HeaderStore::new_in_memory(Network::Regtest);
        let (sender, _receiver) = mpsc::channel();
        let stores =
            profile::open_ram_stores(Arc::new(NoopBackend) as DefaultBackend).expect("open stores");
        let account = Account::from_ram_stores(config, header_store, sender, stores);
        let spk = account.derivator().receive_spk_at(0);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();

        {
            let mut store = account.coin_store.lock().expect("poisoned");
            let mut history = BTreeMap::new();
            history.insert(spk, vec![(txid, None)]);
            let _ = store.handle_history_response(history);
            store.handle_txs_response(vec![tx]);
            assert!(store.queue_reported_heights(&[ClaimAt { txid, height: 1 }]));
            store.generate();
        }

        let tx_entry = account
            .tx_history()
            .into_iter()
            .find(|entry| entry.txid() == txid)
            .expect("tx entry");
        assert!(matches!(tx_entry.inclusion(), Inclusion::Unconfirmed));

        let payment = account
            .payment_history()
            .into_iter()
            .find(|payment| payment.txid == txid.to_string())
            .expect("payment");
        assert_eq!(payment.status, PaymentStatus::ConfirmedUnverified);
        assert_eq!(payment.height, Some(1));
    }

    #[test]
    fn recv_and_spend() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // spend this coin
        let outpoint = mock.coins().pop_first().unwrap().0;
        let tx_1 = spending_tx(outpoint);

        // NOTE: the coin is now spent

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_spent".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(
            spk_recv_0.clone(),
            vec![(tx_0.compute_txid(), Some(1)), (tx_1.compute_txid(), None)],
        );
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request only for tx_1
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_1.compute_txid()]);
        } else {
            panic!()
        }

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_1.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.status(), CoinStatus::Spent);
    }

    #[test]
    fn simple_reorg() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // NOTE: the coin is now spent we can reorg it

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_reorg".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // NOTE: confirmation height is changed to 2
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(2))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server do not receive a tx request as the store already go the tx
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // the store still contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // The server reorgs the entry to height 2. The reported-height
        // change drives `insert_history` to reset the entry to
        // `Inclusion::Unconfirmed` (this is the demotion path, owned by
        // history, not by `on_chain_update`). `resolve_reported_heights`
        // then re-claims it at height 2, but this mock's HeaderStore is
        // empty so the claim is only queued in `pending_claims` and the
        // entry stays Unconfirmed, hence the derived coin height is None.
        assert_eq!(coin.height(), None);
    }

    // Deterministic demotion: a tx seeded as `Inclusion::Verified` at height H
    // is reset to `Inclusion::Unconfirmed` when the server re-reports it at a
    // DIFFERENT height. This is the history-owned path
    // (`update_spk_history` resets `diff.changed` txids), distinct from the
    // same-height hash-change case (`Verified -> ConfirmedUnverified`).
    #[test]
    fn reported_height_change_demotes_verified_to_unconfirmed() {
        use crate::tx_store::TxEntry;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_spk_at(0);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // A concrete block hash at height H so the seeded Verified state is
        // internally consistent.
        let (_map, hash_at_h) = build_header_map(h + 1);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        // Prime the spk history at the seeded height: the tx lands in
        // `diff.added`, which never resets inclusion, so Verified survives.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some(h as u64))]);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert!(
                matches!(
                    entry.inclusion(),
                    Inclusion::Verified { height, block_hash }
                        if *height == h && *block_hash == hash_at_h
                ),
                "priming report must not demote; got {:?}",
                entry.inclusion(),
            );
        }

        // Server re-reports the SAME tx at a DIFFERENT height: the txid lands
        // in `diff.changed`, which resets it to Unconfirmed.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some((h + 3) as u64))]);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert_eq!(
            *entry.inclusion(),
            Inclusion::Unconfirmed,
            "reported-height change must demote Verified -> Unconfirmed",
        );
    }

    // Refusal path: when the HeaderStore itself is Invalid, `on_chain_update`
    // must refuse to promote any pending claim and instead notify
    // `ValidationFailed(HeaderStore(_))`.
    #[test]
    fn invalid_header_store_blocks_promotion() {
        use crate::header_store::{HeaderStore, HeaderValidationState, InvalidCause};
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        // Header at H is present, so a Valid store would promote the claim;
        // the Invalid state below is what must block it.
        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store
            .set_validation_state_for_test(HeaderValidationState::Invalid(InvalidCause::Sanity));

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
            store.insert_pending_claim(ClaimAt { txid, height: h });
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::HeaderStore(_))
            ),
            "expected ValidationFailed(HeaderStore(_)), got {notif:?}"
        );

        assert!(
            req_rx.try_recv().is_err(),
            "no merkle fetch should be queued while the header store is invalid"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "claim wrongly promoted to {:?} despite invalid header store",
            entry.inclusion(),
        );
    }

    // FIX A: after a restart, `pending_claims` (a non-persisted cache) is
    // empty while a confirmed tx sits `Unconfirmed`. The reconnect refresh
    // must issue a `History` for that tx's spk so the server re-reports its
    // height and the claim is rebuilt.
    #[test]
    fn reconnect_refreshes_history_for_unconfirmed_spk() {
        use crate::tx_store::TxEntry;

        let (coin_store, deriv) = bare_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        {
            let mut store = coin_store.lock().unwrap();
            store.tx_store_mut().update(TxEntry::for_test(tx));
            store
                .tx_store_mut()
                .update_inclusion(&txid, Inclusion::Unconfirmed);
            store.generate();
            // As after a restart: the in-memory pending-claims cache is empty.
            assert!(store.pending_claims_snapshot().is_empty());
        }

        let (req_tx, req_rx) = mpsc::channel();
        refresh_unconfirmed_history(&coin_store, &req_tx);

        match req_rx.try_recv() {
            Ok(CoinRequest::History(spks)) => assert!(
                spks.contains(&spk),
                "History must cover the spk owning the Unconfirmed tx"
            ),
            other => panic!("expected History for the unconfirmed spk, got {other:?}"),
        }
    }

    // FIX B: a pending claim whose txid was removed from the tx store (a
    // reorg dropped it) must be dropped by `resolve_pending_claims` rather
    // than left queued forever.
    #[test]
    fn resolve_pending_claims_drops_removed_txid() {
        let (coin_store, _deriv) = bare_coin_store();
        let (map, _tip) = build_header_map(5);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let txid = funding_tx(bitcoin::ScriptBuf::new(), 0.1).compute_txid();
        let h: u32 = 3;
        {
            let mut store = coin_store.lock().unwrap();
            store.insert_pending_claim(ClaimAt { txid, height: h });
            assert!(!store.pending_claims_snapshot().is_empty());
        }

        let mut store = coin_store.lock().unwrap();
        let outcome = store.resolve_pending_claims(&header_store);
        assert!(!outcome.changed, "no promotion for an absent txid");
        assert!(
            store.pending_claims_snapshot().is_empty(),
            "stale claim for a removed txid must be dropped"
        );
    }

    // Refusal path: a tampered merkle branch against a header whose hash
    // still matches the entry's stored hash must notify
    // `ValidationFailed(MerkleProof)` and move the entry to the terminal
    // `VerifyFailed` state so it is not re-fetched every tick.
    #[test]
    fn handle_tx_merkle_tampered_branch_notifies() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let block_hash = header_store.block_hash(h).expect("header at h present");

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash,
                },
            );
        }

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();
        // A sibling that does not fold to the header's (all-zero) merkle
        // root: the proof fails verification.
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &req_tx,
            &notif_tx,
            txid,
            h,
            vec![[0x11u8; 32]],
            0,
        );

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::MerkleProof { txid: t, height })
                    if t == txid && height == h
            ),
            "expected ValidationFailed(MerkleProof), got {notif:?}"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::VerifyFailed { height, block_hash: b }
                    if *height == h && *b == block_hash
            ),
            "entry not moved to VerifyFailed: {:?}",
            entry.inclusion(),
        );
    }

    // A stale proof response after a same-height reorg must requeue against
    // the replacement block instead of marking the transaction failed.
    #[test]
    fn handle_tx_merkle_hash_mismatch_requeues_replacement() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let stale_hash = bitcoin::BlockHash::all_zeros();
        assert_ne!(
            header_store.block_hash(h).expect("header at h present"),
            stale_hash
        );

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: stale_hash,
                },
            );
        }

        let current_hash = header_store.block_hash(h).unwrap();
        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &req_tx,
            &notif_tx,
            txid,
            h,
            Vec::new(),
            0,
        );

        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        assert!(matches!(
            notif_rx.try_recv(),
            Ok(Notification::HeaderStoreUpdated)
        ));
        assert!(matches!(notif_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::ConfirmedUnverified { height, block_hash: b }
                    if *height == h && *b == current_hash
            ),
            "entry was not restamped after hash mismatch: {:?}",
            entry.inclusion(),
        );
    }
}

#[cfg(test)]
mod integration_tests {

    use rand::random_range;
    use std::{
        collections::BTreeMap,
        sync::{mpsc, Once},
        thread::sleep,
        time::Duration,
    };

    use super::{Notification, TxListenerNotif};
    use crate::{
        coin_store::Payment,
        config::{maybe_create_dir, Config},
        Account,
    };
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_electrum::client::Client;
    use bwk_utils::test::{
        bootstrap_electrs as start_electrs_test, electrsd, wait_electrs_tip, TempDir, TestBitcoinD,
    };
    use miniscript::bitcoin::{
        self, bip32::ChildNumber, Address, Amount, Network, Transaction, Txid,
    };
    use miniscript::psbt::PsbtExt;

    use electrsd::{
        bitcoind::{
            bitcoincore_rpc::{jsonrpc::serde_json::Value, RpcApi},
            BitcoinD,
        },
        ElectrsD,
    };

    pub fn bootstrap_electrs() -> (
        String, /* url */
        u16,    /* port */
        ElectrsD,
        TestBitcoinD,
    ) {
        let (url, port, electrsd, bitcoind) = start_electrs_test(false);
        generate(&bitcoind, 101);

        // Without root we cannot raise electrsd's priority directly, so lower
        // the test process instead. Gives electrsd's indexer relatively more
        // CPU when the host is under load (the source of past flakes).
        #[cfg(unix)]
        unsafe {
            libc::nice(5);
        }

        // Wait until electrsd has caught up with bitcoind's tip before any
        // test starts pushing transactions. Avoids a race where the first
        // send_to_address lands while the indexer is still ingesting the
        // initial 101 blocks.
        wait_electrs_tip(&bitcoind, &electrsd);

        (url, port, electrsd, bitcoind)
    }

    #[allow(unused)]
    pub fn tcp_client() -> (Client, ElectrsD, TestBitcoinD) {
        let (url, port, e, b) = bootstrap_electrs();
        let client = Client::new(&url, port).unwrap();

        (client, e, b)
    }

    pub fn send_to_address(bitcoind: &BitcoinD, addr: &Address, amount: Amount) -> Txid {
        let txid = bitcoind
            .client
            .send_to_address(addr, amount, None, None, None, None, None, None)
            .unwrap();
        log::debug!("send_to_address({addr}, {amount}) => {txid}");
        txid
    }

    #[allow(unused)]
    pub fn get_tx(bitcoind: &BitcoinD, txid: Txid) -> Transaction {
        bitcoind.client.get_raw_transaction(&txid, None).unwrap()
    }

    #[allow(unused)]
    pub fn broadcast(bitcoind: &BitcoinD, transaction: Transaction) {
        let _txid = bitcoind.client.send_raw_transaction(&transaction).unwrap();
    }

    pub fn get_block_hash(bitcoind: &BitcoinD, height: u32) -> String {
        bitcoind
            .client
            .call("getblockhash", &[height.into()])
            .unwrap()
    }

    pub fn get_block_height(bitcoind: &BitcoinD) -> u32 {
        bitcoind.client.call("getblockcount", &[]).unwrap()
    }

    pub fn generate(bitcoind: &BitcoinD, blocks: u32) {
        let node_address = bitcoind.client.call::<Value>("getnewaddress", &[]).unwrap();
        bitcoind
            .client
            .call::<Value>("generatetoaddress", &[blocks.into(), node_address])
            .unwrap();
    }

    pub fn reorg_chain(bitcoind: &BitcoinD, blocks: u32) {
        let chain_height: u32 = get_block_height(bitcoind);
        let reorg_height = chain_height - blocks;
        let block_hash = get_block_hash(bitcoind, reorg_height);

        invalidate_block(bitcoind, block_hash);

        generate(bitcoind, blocks);
    }

    pub fn invalidate_block(bitcoind: &BitcoinD, block_hash: String) {
        bitcoind
            .client
            .call::<Value>("invalidateblock", &[block_hash.clone().into()])
            .unwrap();

        log::info!("Invalidated block with hash: {block_hash}");
    }

    pub fn dump_logs(e: &mut ElectrsD) {
        while let Ok(msg) = e.logs.try_recv() {
            println!("{msg}");
        }
    }

    static INIT: Once = Once::new();

    #[allow(unused)]
    pub fn setup_logger() {
        INIT.call_once(|| {
            env_logger::builder()
                .is_test(true)
                .filter_level(log::LevelFilter::Debug)
                .filter_module("bitcoind", log::LevelFilter::Info)
                .filter_module("bitcoincore_rpc", log::LevelFilter::Info)
                .filter_module("bwk::account", log::LevelFilter::Debug)
                .filter_module("bwk-electrum::electrum", log::LevelFilter::Debug)
                .filter_module("bwk-electrum::raw_client", log::LevelFilter::Debug)
                .init();
        });
    }

    pub fn wait_until_timeout<F>(condition: F, timeout: u64)
    where
        F: Fn() -> bool,
    {
        let delay = Duration::from_millis(100);
        let start_time = std::time::Instant::now();

        while start_time.elapsed().as_secs() < timeout {
            if condition() {
                return;
            }
            sleep(delay);
        }
        panic!("Timeout elapsed while waiting for condition.");
    }

    /// Per-block wait budget for integration tests.
    ///
    /// `n_blocks * 3` was the historical formula but flaked in CI when
    /// `random_range(2..15)` returned the low end (6 s isn't enough for
    /// electrs to index + notify + bwk to process under load). Floor at
    /// 30 s and use a higher per-block factor.
    pub fn block_wait(blocks: u32) -> u64 {
        ((blocks as u64) * 5).max(30)
    }

    #[test]
    fn test_reorg() {
        // setup_logger();
        let (_, _, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        reorg_chain(&bitcoind, 5);
    }

    #[test]
    fn simple_wallet() {
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        const TIMEOUT: u64 = 120;
        const BLOCKS: u32 = 1;

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.new_recv_addr();
        let change_addr = account.new_change_addr();

        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 1
            },
            TIMEOUT,
        );

        // Test change address
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        // receive at look_ahead bound
        let recv_addr = account.recv_at(look_ahead);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 3
            },
            TIMEOUT,
        );

        // change at look_ahead bound
        let change_addr = account.change_at(look_ahead);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 4
            },
            TIMEOUT,
        );

        let undiscovered_tip = account.recv_watch_tip() + 1;

        // receive beyond the look_ahead bound
        let recv_addr = account.recv_at(undiscovered_tip);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.coins();
        // the coin is not detected for receiving address
        assert_eq!(coins.len(), 4);

        // change beyond the look_ahead bound
        let change_addr = account.change_at(undiscovered_tip);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.coins();
        // the coin is not detected for change address
        assert_eq!(coins.len(), 4);

        // move the watch tip forward
        account.new_recv_addr();
        account.new_recv_addr();
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 5
            },
            TIMEOUT,
        );

        account.new_change_addr();
        account.new_change_addr();
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 6
            },
            TIMEOUT,
        );
    }

    #[test]
    fn simple_reorg_e2e() {
        // setup_logger();
        let (url, port, mut electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 110);

        const TIMEOUT: u64 = 120;

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.new_recv_addr();
        let change_addr = account.new_change_addr();

        sleep(Duration::from_secs(1));

        // send to recv address
        let recv_txid = send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        let recv_tx = bitcoind
            .client
            .get_raw_transaction(&recv_txid, None)
            .unwrap();

        generate(&bitcoind, 1);

        sleep(Duration::from_secs(1));
        dump_logs(&mut electrsd);

        // send to change address
        let change_txid = send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        let change_tx = bitcoind
            .client
            .get_raw_transaction(&change_txid, None)
            .unwrap();
        generate(&bitcoind, 1);

        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        let coins = account.coins();
        let coins_height: BTreeMap<_, _> =
            coins.into_iter().map(|(c, e)| (c, e.height())).collect();

        // With the pending-claims queue and merkle verification in
        // place, both coins are confirmed at this point and should carry
        // a height.
        assert!(coins_height.iter().all(|(_, e)| e.is_some()));

        let height_before_reorg = get_block_height(&bitcoind);
        let h_before_reorg = get_block_hash(&bitcoind, height_before_reorg);

        sleep(Duration::from_secs(2));

        electrsd.clear_logs();
        log::warn!(" ------------------------------- reorg now ------------------------");
        reorg_chain(&bitcoind, 7);
        generate(&bitcoind, 2);
        dump_logs(&mut electrsd);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        // FIXME:
        // NOTE: here we likely hitting an `electrs` bug:
        // - we can see in the electrs logs that 2 status (None) updates are assumed sent
        //   from electrs end
        // - only 1 status update is received on our raw client TCP stream end

        log::warn!(" ------------------------------- rebroadcast recv ------------------------");
        let _ = bitcoind.client.send_raw_transaction(&recv_tx);
        generate(&bitcoind, 1);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        log::warn!(" ------------------------------- rebroadcast change ------------------------");
        let _ = bitcoind.client.send_raw_transaction(&change_tx);
        generate(&bitcoind, 1);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        let new_h = get_block_hash(&bitcoind, height_before_reorg);
        assert_ne!(h_before_reorg, new_h);

        let coins = account.coins();
        // there is still 2 coins
        assert_eq!(coins.len(), 2);
    }

    #[cfg(feature = "test")]
    use bwk_tx::tx_builder::TxBuilder;

    #[cfg(feature = "test")]
    fn spend(
        account: &mut Account,
        builder: &mut TxBuilder,
        bitcoind: &BitcoinD,
        amount: u64,
    ) -> (bitcoin::Txid, u32) {
        let coins = account.spendable_coins().coins.into_values().collect();
        builder.new_template();
        builder.tx_template.inputs = coins;
        builder.dummy_external_output(amount);
        let mut psbt = builder.generate().unwrap();
        account.sign_psbt(&mut psbt);
        PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new()).unwrap();
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let txid = bitcoind.client.send_raw_transaction(&tx).unwrap();
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        (txid, blocks)
    }

    fn receive(account: &mut Account, bitcoind: &BitcoinD, amount: u64) -> u32 {
        let recv_addr = account.new_recv_addr();
        send_to_address(bitcoind, &recv_addr, Amount::from_sat(amount));
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        blocks
    }

    #[allow(unused)]
    fn sort_payments(payments: &Vec<Payment>) -> (usize, usize) {
        let mut recv = 0;
        let mut sent = 0;
        for p in payments {
            match p.payment_type {
                crate::coin_store::PaymentType::Receive => recv += 1,
                crate::coin_store::PaymentType::Send => sent += 1,
                crate::coin_store::PaymentType::ToSelf => {}
            }
        }
        (recv, sent)
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_list_payments() {
        // setup_logger();
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account = Account::new(config);
        sleep(Duration::from_millis(300));
        let mut builder = account.tx_builder();

        let blocks = receive(&mut account, &bitcoind, 200_000);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 1
            },
            block_wait(blocks),
        );
        let (_, blocks) = spend(&mut account, &mut builder, &bitcoind, 100_000);
        wait_until_timeout(
            || {
                let payments = account.payment_history();
                payments.len() == 2
            },
            block_wait(blocks),
        );

        let payments = account.payment_history();
        assert_eq!(2, payments.len());
        let sorted = sort_payments(&payments);
        assert_eq!(sorted, (1, 1));

        // Every confirmed payment gets a block timestamp from the listener.
        wait_until_timeout(
            || {
                account
                    .payment_history()
                    .iter()
                    .filter(|p| p.height.is_some())
                    .all(|p| p.timestamp.is_some_and(|t| t > 0))
            },
            block_wait(5),
        );
        let confirmed: Vec<_> = account
            .payment_history()
            .into_iter()
            .filter(|p| p.height.is_some())
            .collect();
        assert!(!confirmed.is_empty(), "expected a confirmed payment");
        for p in &confirmed {
            assert!(
                p.timestamp.is_some_and(|t| t > 0),
                "confirmed payment {} should have a block timestamp",
                p.txid
            );
        }
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_electrum_restart() {
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = 20;
        config.set_electrum_url(url);
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account = Account::new(config);
        let notif = account.receiver().expect("receiver");
        sleep(Duration::from_millis(300));

        // Blocks until a notification matching `want` arrives (drain first so
        // the match is post-restart).
        let wait_notif =
            |notif: &mpsc::Receiver<Notification>, want: fn(&Notification) -> bool| -> bool {
                let deadline = std::time::Instant::now() + Duration::from_secs(15);
                while std::time::Instant::now() < deadline {
                    if let Ok(n) = notif.recv_timeout(Duration::from_millis(200)) {
                        if want(&n) {
                            return true;
                        }
                    }
                }
                false
            };
        let is_started =
            |n: &Notification| matches!(n, Notification::Electrum(TxListenerNotif::Started));
        let is_stopped =
            |n: &Notification| matches!(n, Notification::Electrum(TxListenerNotif::Stopped));

        // The listener works before any restart.
        let blocks = receive(&mut account, &bitcoind, 200_000);
        wait_until_timeout(|| account.coins().len() == 1, block_wait(blocks));

        // stop marks the account offline and the listener emits Stopped; a
        // following start restarts it in place (no panic, fresh Started) and the
        // statuses store handed back through the channel keeps the wallet tracked.
        while notif.try_recv().is_ok() {}
        account.stop_electrum();
        assert!(
            account.electrum_offline(),
            "stop_electrum did not mark offline"
        );
        assert!(
            wait_notif(&notif, is_stopped),
            "listener did not emit Stopped"
        );
        account.start_electrum();
        assert!(
            wait_notif(&notif, is_started),
            "listener did not restart on stop+start"
        );
        wait_until_timeout(|| !account.electrum_offline(), 15);
        let blocks = receive(&mut account, &bitcoind, 150_000);
        wait_until_timeout(|| account.coins().len() == 2, block_wait(blocks));

        // restart_electrum() (the in-place path) behaves the same.
        while notif.try_recv().is_ok() {}
        account.restart_electrum();
        assert!(
            wait_notif(&notif, is_started),
            "listener did not restart on restart_electrum"
        );
        let blocks = receive(&mut account, &bitcoind, 120_000);
        wait_until_timeout(|| account.coins().len() == 3, block_wait(blocks));
    }

    #[test]
    fn test_persist_payments() {
        use rand::random;

        // setup_logger();
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let saved_config = config.clone();
        // Scoped so `builder` and `account` drop in reverse
        // declaration order at the closing brace, the tx_builder
        // holds Arc<Mutex<CoinStore>> clones that would otherwise
        // keep the backend (and its DirLock on the account dir)
        // alive past account's explicit drop.
        {
            let mut account = Account::new(config);
            sleep(Duration::from_millis(300));
            let mut builder = account.tx_builder();

            let mut prev_blocks = receive(&mut account, &bitcoind, 100_000_000);
            for _ in 0..15 {
                wait_until_timeout(
                    || !account.spendable_coins().coins.is_empty(),
                    block_wait(prev_blocks),
                );
                sleep(Duration::from_millis(1000));
                let coins = account.spendable_coins();
                let balance = coins
                    .coins
                    .into_iter()
                    .fold(0, |a, (_, c)| a + c.txout.value.to_sat());
                assert!(balance > 1_100_000);
                let pay: bool = random();
                if pay {
                    let blocks: u32 = random_range(1..5);
                    let addr = bitcoind
                        .client
                        .get_new_address(None, None)
                        .unwrap()
                        .assume_checked();
                    let amount = random_range(10_000..1_000_000);
                    // The wallet may not have synced a prior spend yet (electrum lag
                    // under CI load), so a freshly built tx can select an already
                    // spent coin (-25 bad-txns-inputs-missingorspent). Rebuild from
                    // the wallet's current coins and retry, letting sync catch up,
                    // until bitcoind accepts it.
                    let mut attempt = 0;
                    loop {
                        let mut psbt = builder.pay(amount, addr.clone(), 1000).unwrap();
                        account.sign_psbt(&mut psbt);
                        PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new())
                            .unwrap();
                        let tx = psbt.extract_tx_unchecked_fee_rate();
                        match bitcoind.client.send_raw_transaction(&tx) {
                            Ok(_) => break,
                            Err(_) if attempt < 30 => {
                                attempt += 1;
                                sleep(Duration::from_millis(500));
                            }
                            Err(e) => {
                                panic!("send_raw_transaction failed after {attempt} retries: {e:?}")
                            }
                        }
                    }
                    generate(&bitcoind, blocks);
                    prev_blocks = blocks;
                } else {
                    prev_blocks = receive(&mut account, &bitcoind, random_range(10_000..1_000_000));
                }
            }
            // Wait for the actual target (1 initial receive + 15 loop
            // iterations = 16 payments) rather than `len() == 15` plus a
            // 3 s grace. Use an absolute 120 s budget here: after 15
            // iterations of generate-and-index, the listener thread can
            // be queued up well past `block_wait(prev_blocks)`'s 30 s
            // floor under CI / CPU pressure.
            wait_until_timeout(|| account.payment_history().len() >= 16, 120);
            let payments = account.payment_history();
            assert_eq!(payments.len(), 16);
        }

        let account: Account = Account::new(saved_config);
        sleep(Duration::from_millis(300));
        let payments = account.payment_history();
        assert_eq!(payments.len(), 16);
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_signer_exclusion {
    use super::*;
    use crate::config::{Config, CONFIG_FILENAME};
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_persist::{FileConfigStore, PersistenceKind};
    use miniscript::bitcoin::{bip32::ChildNumber, Network};
    use temp_dir::TempDir;

    /// Recursively scan all files under `dir` and assert `needle` is not
    /// present in any of their bytes (text or binary).
    fn assert_needle_absent(dir: &std::path::Path, needle: &str) {
        let needle_bytes = needle.as_bytes();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(p) = stack.pop() {
            for entry in std::fs::read_dir(&p).expect("read_dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                let ft = entry.file_type().expect("file_type");
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    let bytes = std::fs::read(&path).expect("read file");
                    let found = bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes);
                    assert!(
                        !found,
                        "needle {needle:?} found in on-disk file {}",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn sqlite_mode_keeps_mnemonic_off_disk() {
        let temp = TempDir::new().expect("tempdir");
        let unique = Mnemonic::generate(12).expect("mnemonic").to_string();

        let mut cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            true,
        )
        .expect("config");
        cfg.set_offline(true);
        cfg.persist_kind = PersistenceKind::Sqlite;

        // Wire a FileConfigStore against the account dir's config.json,
        // build the account, drive a config save + a label write to
        // exercise multiple persist paths. SQLite mode must not write
        // the mnemonic anywhere under the account dir.
        let account_dir = cfg.account_dir();
        let config_store: Arc<dyn ConfigStore<Config>> = Arc::new(FileConfigStore::<Config>::new(
            account_dir.join(CONFIG_FILENAME),
        ));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        account.label_store().lock().expect("poisoned").persist();
        drop(account);

        assert!(account_dir.exists(), "account dir created");
        assert_needle_absent(&account_dir, &unique);
    }

    #[test]
    fn json_mode_writes_mnemonic_to_config_json() {
        let temp = TempDir::new().expect("tempdir");
        let unique = Mnemonic::generate(12).expect("mnemonic").to_string();

        let cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            true,
        )
        .expect("config")
        .with_persist_kind(PersistenceKind::Json);

        let account_dir = cfg.account_dir();
        let config_path = account_dir.join(CONFIG_FILENAME);
        let config_store: Arc<dyn ConfigStore<Config>> =
            Arc::new(FileConfigStore::<Config>::new(config_path.clone()));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        drop(account);

        let on_disk = std::fs::read_to_string(&config_path).expect("config.json");
        assert!(
            on_disk.contains(&unique),
            "mnemonic must appear in config.json under JSON mode (default)"
        );
    }
}
