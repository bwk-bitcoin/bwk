use std::{
    collections::BTreeMap,
    slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bwk_descriptor::descriptor::Descriptor;

use bwk_electrum::{
    coin_store::{ChangeTipUpdater, SpendRecorder},
    header_follower::HeaderFollower,
    header_store::HeaderStore,
    history::{AccountHistory, TxContribution},
    notification::Notification,
    open,
    profile::{
        DefaultBackend, OpenScanFromBackend, RamProfile, ReopenStatuses, ScanProfile, ScanStores,
    },
    reconcile::Reconciler,
    scanner::ElectrumScanner,
};
use bwk_persist::{
    backend::PersistenceBackend,
    config_store::{ConfigStore, NoopConfigStore},
};
use bwk_sign::{
    identity::{SignerId, SignerInfo, SignerState},
    manager::{self, SigningManager},
    protocol::{RequestId, Response},
    signing_manager::HotManager,
};
use bwk_tx::{recipient::ChangeRecipientProvider, tx_builder::TxBuilder};
use crossbeam::channel;

use miniscript::bitcoin::{self, Txid};

use crate::config::Config;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a signing manager is already attached under this name")]
    ManagerAlreadyAttached,
    #[error("no signer with that id")]
    UnknownSigner,
    #[error("signer is not ready")]
    SignerNotReady,
    #[error("signing error: {0}")]
    Signing(#[from] manager::Error),
}

/// Well-known name of the hot manager an `Account` attaches at construction
/// when the config carries a mnemonic.
const HOT_MANAGER_NAME: &str = "hot";

/// One runtime-attached signing manager plus the pump thread forwarding its
/// responses into the account's notification sender.
struct AttachedManager {
    manager: Box<dyn SigningManager>,
    stop: Arc<AtomicBool>,
    pump: Option<JoinHandle<()>>,
}

/// One cached signer identity plus the name of the manager it came from, so
/// [`Account::detach_signing_manager`] can drop exactly that manager's
/// entries.
struct CachedSigner {
    manager: String,
    info: SignerInfo,
}

/// Replaces every cached entry owned by `manager` with `list`: a signer whose
/// state changes is dropped and re-registered rather than mutated, so a roster
/// update is a wholesale replacement, not a merge.
fn replace_manager_signers(
    cache: &Mutex<BTreeMap<SignerId, CachedSigner>>,
    manager: &str,
    list: Vec<SignerInfo>,
) {
    let mut cache = cache.lock().expect("poisoned");
    cache.retain(|_, entry| entry.manager != manager);
    for info in list {
        cache.insert(
            info.id.clone(),
            CachedSigner {
                manager: manager.to_string(),
                info,
            },
        );
    }
}

/// Adapts a shared [`HotManager`] to [`SigningManager`] so it can sit in
/// [`Account::managers`] like any other attached manager.
struct HotManagerHandle(Arc<Mutex<HotManager>>);

impl SigningManager for HotManagerHandle {
    fn signers(&self) -> Vec<SignerInfo> {
        self.0.lock().expect("poisoned").signers()
    }

    fn subscribe(&mut self, sender: channel::Sender<Response>) {
        self.0.lock().expect("poisoned").subscribe(sender);
    }

    fn set_polling(&mut self, enabled: bool) {
        self.0.lock().expect("poisoned").set_polling(enabled);
    }

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        self.0.lock().expect("poisoned").init(signer)
    }

    fn info(&self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        self.0.lock().expect("poisoned").info(signer)
    }

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: bitcoin::bip32::DerivationPath,
        display: bool,
    ) -> Result<RequestId, manager::Error> {
        self.0
            .lock()
            .expect("poisoned")
            .get_xpub(signer, path, display)
    }

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        self.0
            .lock()
            .expect("poisoned")
            .is_descriptor_registered(signer, descriptor)
    }

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        self.0
            .lock()
            .expect("poisoned")
            .register_descriptor(signer, descriptor)
    }

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, manager::Error> {
        self.0
            .lock()
            .expect("poisoned")
            .sign(signer, descriptor, psbt)
    }

    fn raw(&self, signer: &SignerId, request: Vec<u8>) -> Result<RequestId, manager::Error> {
        self.0.lock().expect("poisoned").raw(signer, request)
    }
}

/// Maps a signing-manager [`Response`] onto a [`Notification`]. No variant
/// carries one, so every response is logged and dropped.
fn response_to_notification(response: &Response) -> Option<Notification> {
    log::debug!("signing manager response dropped, no Notification variant: {response:?}");
    None
}

/// Bridges an attached manager's `crossbeam` response channel onto the
/// account's `std::sync::mpsc` notification sender. Polls on a timeout so a
/// `stop` request is picked up promptly even when the manager never answers.
///
/// Also keeps `signers` current: `Response::Signers` and
/// `Response::SignersChanged` both carry a full roster for `manager_name`, so
/// either one replaces that manager's cached entries wholesale.
fn spawn_pump(
    manager_name: String,
    rx: channel::Receiver<Response>,
    sender: mpsc::Sender<Notification>,
    stop: Arc<AtomicBool>,
    signers: Arc<Mutex<BTreeMap<SignerId, CachedSigner>>>,
) -> JoinHandle<()> {
    thread::spawn(move || loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(response) => {
                if let Response::Signers { signers: list, .. }
                | Response::SignersChanged { signers: list } = &response
                {
                    replace_manager_signers(&signers, &manager_name, list.clone());
                }
                if let Some(notif) = response_to_notification(&response) {
                    if sender.send(notif).is_err() {
                        return;
                    }
                }
            }
            Err(channel::RecvTimeoutError::Timeout) => {}
            Err(channel::RecvTimeoutError::Disconnected) => return,
        }
    })
}

/// A descriptor wallet: one [`ElectrumScanner`] watching the descriptor, one
/// [`HeaderStore`] validating the chain, and the reconciliation between them.
///
/// The scanner records what the server reports and never reads a header. The
/// header store validates the chain and fetches inclusion proofs over its own
/// connection. This type owns both, plus the signers, and runs the pass that
/// promotes what the scanner recorded into verified state.
pub struct Account<P: ScanProfile = RamProfile<DefaultBackend>> {
    scanner: ElectrumScanner<P>,
    /// Validated header chain, this account's own or one shared across
    /// accounts. The reconcile thread reads it on every chain-tip advance and
    /// fetches its merkle proofs through it.
    headers: HeaderFollower<P>,
    managers: BTreeMap<String, AttachedManager>,
    /// Cache of every signer reachable through `managers`, keyed by its
    /// unique [`SignerId`] (never by fingerprint: several signers can share
    /// one). Seeded from a manager's `signers()` on attach, dropped on
    /// detach, and kept current by each manager's pump thread.
    signers: Arc<Mutex<BTreeMap<SignerId, CachedSigner>>>,
    /// Wallet-level half of [`Config`]; the scanner owns the rest.
    mnemonic: Option<String>,
    sender: mpsc::Sender<Notification>,
    receiver: Option<mpsc::Receiver<Notification>>,
    /// Persistence sink for the config. [`NoopConfigStore`] by default.
    /// Consumers wire whatever shape suits them, a
    /// [`bwk_persist::config_store::FileConfigStore`] for file-backed persistence, a
    /// [`bwk_persist::config_store::CallbackConfigStore`] to bridge save/load through
    /// host-supplied closures, or any other [`ConfigStore`] impl.
    config_store: Arc<dyn ConfigStore<Config>>,
    /// Declared last so its thread is joined after the scanner's: both hold the
    /// persistence backend alive, and the account directory stays locked until
    /// each of them has exited.
    reconciler: Reconciler<P>,
}

impl<P: ScanProfile> std::fmt::Debug for Account<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").finish()
    }
}

impl<P: ScanProfile> Drop for Account<P> {
    fn drop(&mut self) {
        let names: Vec<String> = self.managers.keys().cloned().collect();
        for name in names {
            self.detach_signing_manager(&name);
        }
    }
}

fn default_config_store() -> Arc<dyn ConfigStore<Config>> {
    Arc::new(NoopConfigStore::<Config>::default())
}

// Generic constructors over any profile that knows how to open its
// store bundle from a single `Arc<dyn PersistenceBackend>`.
impl<P: OpenScanFromBackend> Account<P> {
    /// Creates a new `Account` instance with the given configuration.
    ///
    /// Opens the profile's stores against whatever backend the config
    /// selects ([`JsonBackend`][bwk_persist::backend::json::JsonBackend] by default,
    /// `SqliteBackend` under `PersistenceKind::Sqlite`). Defaults to
    /// the [`RamProfile<DefaultBackend>`] storage strategy via the
    /// `Account` struct's default type parameter.
    ///
    /// Builds its own [`HeaderStore`] from `config`; use
    /// [`Account::try_new_with_header_store`] to share an existing one
    /// instead.
    ///
    /// Config persistence defaults to [`NoopConfigStore`]; use
    /// [`Account::try_with_config_store`] to wire a concrete impl
    /// ([`bwk_persist::config_store::FileConfigStore`] for file-backed,
    /// [`bwk_persist::config_store::CallbackConfigStore`] to bridge through
    /// caller-supplied closures, or any other [`ConfigStore`]).
    ///
    /// Returns [`open::Error`] if the account name is empty, the descriptor is
    /// not one the scan can derive from, the backend cannot be built (e.g. the
    /// account directory is already locked by another instance), or a stored
    /// blob fails to decode.
    pub fn try_new(config: Config) -> Result<Self, open::Error> {
        let (sender, receiver) = mpsc::channel();
        let mut account = Self::try_new_inner(config, None, sender, default_config_store())?;
        account.receiver = Some(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but sharing an existing [`HeaderStore`]
    /// handle instead of building one.
    pub fn try_new_with_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
    ) -> Result<Self, open::Error> {
        let (sender, receiver) = mpsc::channel();
        let mut account =
            Self::try_new_inner(config, Some(header_store), sender, default_config_store())?;
        account.receiver = Some(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an explicit config store.
    pub fn try_with_config_store(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, open::Error> {
        let (sender, receiver) = mpsc::channel();
        let mut account = Self::try_new_inner(config, None, sender, config_store)?;
        account.receiver = Some(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an external notification sender.
    pub fn try_new_with_sender(
        config: Config,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, open::Error> {
        Self::try_new_inner(config, None, sender, default_config_store())
    }

    /// Like [`Account::try_new_with_sender`] but sharing an existing
    /// [`HeaderStore`] handle instead of building one: one validated chain
    /// across several accounts routed through the same notification channel.
    pub fn try_new_with_sender_and_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, open::Error> {
        Self::try_new_inner(config, Some(header_store), sender, default_config_store())
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

    /// `header_store == None` builds the account its own store, which it then
    /// owns and may idle from [`Account::stop_electrum`].
    fn try_new_inner(
        config: Config,
        header_store: Option<Arc<HeaderStore<P::HeaderStore>>>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, open::Error> {
        if config.scanner.account.is_empty() {
            return Err(open::Error::EmptyAccount);
        }
        config.scanner.validate_descriptor()?;
        let headers = match header_store {
            Some(store) => HeaderFollower::borrowed(store, sender.clone()),
            None => HeaderFollower::open(
                // An account asked to stay offline opens its store idle; the
                // first start points it at the configured endpoint.
                (!config.scanner.stay_offline())
                    .then(|| config.scanner.endpoint().configured().cloned())
                    .flatten(),
                config.scanner.network,
                config.scanner.persistence,
                config.scanner.account_dir(),
                None,
                sender.clone(),
            )?,
        };
        let backend: Arc<dyn PersistenceBackend> = config.scanner.build_backend()?;
        let reopen_backend = backend.clone();
        let reopen_statuses: ReopenStatuses<P> =
            Arc::new(move || P::open_statuses(reopen_backend.clone()));
        let stores = <P as OpenScanFromBackend>::open(backend)?;
        Ok(Self::from_stores(
            config,
            headers,
            sender,
            config_store,
            stores,
            Some(reopen_statuses),
        ))
    }

    fn from_stores(
        config: Config,
        headers: HeaderFollower<P>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
        stores: ScanStores<P>,
        reopen_statuses: Option<ReopenStatuses<P>>,
    ) -> Self {
        let Config {
            scanner: scanner_config,
            mnemonic,
        } = config;
        let stay_offline = scanner_config.stay_offline();
        // Once per account, not per reconciler: a store shared by several
        // accounts would otherwise report the same event to this channel as
        // many times as it has reconcilers on it.
        headers.store().register_notifications(sender.clone());
        let scanner =
            ElectrumScanner::from_stores(scanner_config, sender.clone(), stores, reopen_statuses);
        let reconciler = Reconciler::spawn(&scanner, headers.store().clone(), sender.clone());
        let mut account = Account {
            scanner,
            headers,
            managers: BTreeMap::new(),
            signers: Arc::new(Mutex::new(BTreeMap::new())),
            mnemonic,
            sender,
            receiver: None,
            config_store,
            reconciler,
        };
        // A hot manager is seeded from the config mnemonic and attached like
        // any other manager; registration stays consumer-driven, so no
        // descriptor is pushed here.
        if let Some(mnemo) = account.mnemonic.clone() {
            let mut hot_manager = HotManager::new();
            hot_manager.new_bip32_signer_from_mnemonic(account.scanner.network(), mnemo);
            let hot = Arc::new(Mutex::new(hot_manager));
            if account
                .attach_signing_manager(HOT_MANAGER_NAME, Box::new(HotManagerHandle(hot)))
                .is_err()
            {
                log::error!("from_stores(): hot manager name unexpectedly already attached");
            }
        }
        if !stay_offline {
            account.start_electrum();
        }
        account
    }

    /// Reconnect every Electrum connection in place, keeping the `Account` and
    /// all its channels alive. The connection state is driven by the scanner,
    /// which marks itself online once connected; with no endpoint configured
    /// nothing starts and the account stays disconnected.
    pub fn restart_electrum(&mut self) {
        self.scanner.stop();
        // The header store still holds the same dead socket, which it cannot
        // see by itself, so reconnect it too or `Verified` promotions would
        // stall. Done first, so the `start_electrum` below finds it running and
        // leaves it.
        if let Some(target) = self.scanner.config().endpoint().configured().cloned() {
            self.headers
                .reconnect(target, slice::from_ref(&self.reconciler));
        }
        self.start_electrum();
    }
}

impl<P: ScanProfile> Account<P> {
    /// Push the current config to the configured [`ConfigStore`].
    ///
    /// Under [`bwk_persist::PersistenceKind::Sqlite`] the saved view has
    /// signer material stripped via [`Config::for_persistence`].
    fn persist_config(&self) {
        let cfg = self.get_config().for_persistence();
        if let Err(e) = self.config_store.save(&cfg) {
            log::warn!("config save failed: {e}");
        }
    }
}

// Non (b)locking API
impl<P: ScanProfile> Account<P> {
    /// The scanner this account watches its descriptor with.
    pub fn scanner(&self) -> &ElectrumScanner<P> {
        &self.scanner
    }

    /// Mutable counterpart of [`Account::scanner`], for the scanner calls that
    /// take `&mut self` (address generation, endpoint changes).
    pub fn scanner_mut(&mut self) -> &mut ElectrumScanner<P> {
        &mut self.scanner
    }

    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.receiver.take()
    }

    /// Returns the configuration of the account: the scanner's own config plus
    /// the wallet-level settings this type owns.
    pub fn get_config(&self) -> Config {
        Config {
            scanner: self.scanner.config().clone(),
            mnemonic: self.mnemonic.clone(),
        }
    }

    /// Attaches a runtime signing manager under `name`. Non-blocking: this
    /// only subscribes to the manager's response channel and spawns its pump
    /// thread, it never registers a descriptor, requests an xpub, or polls
    /// for devices.
    ///
    /// Refuses a duplicate `name` rather than replacing the existing
    /// manager.
    pub fn attach_signing_manager(
        &mut self,
        name: &str,
        mut manager: Box<dyn SigningManager>,
    ) -> Result<(), Error> {
        if self.managers.contains_key(name) {
            return Err(Error::ManagerAlreadyAttached);
        }
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let stop = Arc::new(AtomicBool::new(false));
        let pump = spawn_pump(
            name.to_string(),
            rx,
            self.sender.clone(),
            stop.clone(),
            self.signers.clone(),
        );
        // A synchronous read of what the manager already knows, not a
        // request, so it does not violate the non-blocking rule.
        let initial = manager.signers();
        replace_manager_signers(&self.signers, name, initial);
        self.managers.insert(
            name.to_string(),
            AttachedManager {
                manager,
                stop,
                pump: Some(pump),
            },
        );
        Ok(())
    }

    /// Detaches the manager registered under `name`, stopping its pump
    /// thread and dropping its signers from the cache. Returns whether a
    /// manager was actually removed.
    pub fn detach_signing_manager(&mut self, name: &str) -> bool {
        let Some(mut attached) = self.managers.remove(name) else {
            return false;
        };
        attached.stop.store(true, Ordering::Relaxed);
        drop(attached.manager);
        if let Some(pump) = attached.pump.take() {
            let _ = pump.join();
        }
        self.signers
            .lock()
            .expect("poisoned")
            .retain(|_, entry| entry.manager != name);
        true
    }

    /// Names of every currently attached signing manager.
    pub fn signing_manager_names(&self) -> Vec<String> {
        self.managers.keys().cloned().collect()
    }

    /// Every signer reachable through an attached manager, from the local
    /// cache. Keyed by unique id, never by fingerprint: two signers sharing a
    /// fingerprint both appear. Synchronous and never touches a device.
    pub fn signers(&self) -> Vec<SignerInfo> {
        self.signers
            .lock()
            .expect("poisoned")
            .values()
            .map(|cached| cached.info.clone())
            .collect()
    }

    /// The cached identity of one signer, if it is currently known.
    pub fn signer(&self, id: &SignerId) -> Option<SignerInfo> {
        self.signers
            .lock()
            .expect("poisoned")
            .get(id)
            .map(|cached| cached.info.clone())
    }

    /// Re-reads `signers()` from every attached manager and refreshes the
    /// cache. Synchronous and cheap: it only reads what each manager already
    /// holds, it never sends a request to a device.
    pub fn refresh_signers(&self) {
        for (name, attached) in self.managers.iter() {
            let list = attached.manager.signers();
            replace_manager_signers(&self.signers, name, list);
        }
    }

    /// Turns device discovery on and off on every attached manager, mirroring
    /// silent's `Host::requestSignerPolling`.
    pub fn set_signer_polling(&mut self, enabled: bool) {
        for attached in self.managers.values_mut() {
            attached.manager.set_polling(enabled);
        }
    }

    /// Resolves `signer_id` to the name of the manager that owns it,
    /// rejecting an unknown id or a signer that is not [`SignerState::Ready`]
    /// before any manager is touched. Shared by [`Account::dispatch`] and
    /// [`Account::dispatch_mut`] so the lookup exists once.
    fn resolve_manager(&self, signer_id: &SignerId) -> Result<String, Error> {
        let cache = self.signers.lock().expect("poisoned");
        let entry = cache.get(signer_id).ok_or(Error::UnknownSigner)?;
        if !matches!(entry.info.state, SignerState::Ready) {
            return Err(Error::SignerNotReady);
        }
        Ok(entry.manager.clone())
    }

    /// Routes a `&self` [`SigningManager`] operation to the manager owning
    /// `signer_id`.
    fn dispatch<F>(&self, signer_id: &SignerId, f: F) -> Result<RequestId, Error>
    where
        F: FnOnce(&dyn SigningManager) -> Result<RequestId, manager::Error>,
    {
        let name = self.resolve_manager(signer_id)?;
        let attached = self.managers.get(&name).ok_or(Error::UnknownSigner)?;
        f(attached.manager.as_ref()).map_err(Error::from)
    }

    /// Routes a `&mut self` [`SigningManager`] operation (`init`,
    /// `register_descriptor`) to the manager owning `signer_id`.
    fn dispatch_mut<F>(&mut self, signer_id: &SignerId, f: F) -> Result<RequestId, Error>
    where
        F: FnOnce(&mut dyn SigningManager) -> Result<RequestId, manager::Error>,
    {
        let name = self.resolve_manager(signer_id)?;
        let attached = self.managers.get_mut(&name).ok_or(Error::UnknownSigner)?;
        f(attached.manager.as_mut()).map_err(Error::from)
    }

    /// Initializes the signer, e.g. an unlock or pairing handshake. Returns
    /// immediately; the result arrives later as a notification.
    pub fn init_signer(&mut self, signer_id: &SignerId) -> Result<RequestId, Error> {
        self.dispatch_mut(signer_id, |manager| manager.init(signer_id))
    }

    /// Requests the signer's info payload. Returns immediately; the result
    /// arrives later as a notification.
    pub fn signer_info(&self, signer_id: &SignerId) -> Result<RequestId, Error> {
        self.dispatch(signer_id, |manager| manager.info(signer_id))
    }

    /// Requests an xpub at `path` from the signer. Returns immediately; the
    /// result arrives later as a notification.
    pub fn signer_xpub(
        &self,
        signer_id: &SignerId,
        path: bitcoin::bip32::DerivationPath,
        display: bool,
    ) -> Result<RequestId, Error> {
        self.dispatch(signer_id, |manager| {
            manager.get_xpub(signer_id, path, display)
        })
    }

    /// Asks the signer whether `descriptor` is already registered. Returns
    /// immediately; the result arrives later as a notification.
    pub fn is_descriptor_registered(
        &self,
        signer_id: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, Error> {
        self.dispatch(signer_id, |manager| {
            manager.is_descriptor_registered(signer_id, descriptor)
        })
    }

    /// Registers `descriptor` with the signer. Consumer-driven: nothing in
    /// `bwk` calls this on the consumer's behalf. Returns immediately; the
    /// result arrives later as a notification.
    pub fn register_descriptor(
        &mut self,
        signer_id: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, Error> {
        self.dispatch_mut(signer_id, |manager| {
            manager.register_descriptor(signer_id, descriptor)
        })
    }

    /// Asks the signer to sign `psbt` against `descriptor`. Non-blocking: the
    /// bytes cross untouched, never parsed, never stored, and the result
    /// arrives later as a notification.
    pub fn sign(
        &self,
        signer_id: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, Error> {
        self.dispatch(signer_id, |manager| {
            manager.sign(signer_id, descriptor, psbt)
        })
    }

    /// Sends an opaque, manager-defined request to the signer. Returns
    /// immediately; the result arrives later as a notification.
    pub fn signer_raw(&self, signer_id: &SignerId, request: Vec<u8>) -> Result<RequestId, Error> {
        self.dispatch(signer_id, |manager| manager.raw(signer_id, request))
    }
}

// Locking API
impl<P: ScanProfile> Account<P> {
    pub fn tx_builder(&self) -> TxBuilder {
        let tip_updater = ChangeTipUpdater::new(self.scanner.coin_store().clone());
        let change_provider = Box::new(ChangeRecipientProvider::new_with_updater(
            tip_updater,
            self.scanner.descriptor(),
            self.scanner.network(),
        ));
        let coin_source = Box::new(self.scanner.coin_source());
        TxBuilder::new(change_provider).coin_source(coin_source)
    }

    pub fn spend_recorder(&self) -> SpendRecorder<P> {
        SpendRecorder::new(self.scanner.coin_store().clone())
    }
}

impl<P: ScanProfile> AccountHistory for Account<P> {
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
        self.scanner.tx_contributions()
    }
}

// Electrum specific implementation. Bound to `OpenScanFromBackend`, which pins the
// header store to the concrete backend-backed one the worker drives.
impl<P: OpenScanFromBackend> Account<P> {
    /// Sets the Electrum server URL and port for the account.
    pub fn set_electrum(&mut self, url: String, port: String) {
        if let Ok(port) = port.parse::<u16>() {
            self.scanner.set_electrum(Some(url), Some(port));
            self.persist_config();
        } else {
            self.sender
                .send(Notification::InvalidElectrumConfig)
                .expect("cannot fail");
        }
    }

    /// Start every Electrum connection this account drives: the scanner's
    /// listener, the header store's worker and merkle clients, and the
    /// reconcile pass. Records that this account should come up online again on
    /// the next open.
    pub fn start_electrum(&mut self) {
        let Some(target) = self.scanner.config().endpoint().configured().cloned() else {
            // No endpoint to connect to: nothing can listen, so record staying
            // offline instead of persisting an online intent nothing honours.
            self.scanner.set_stay_offline(true);
            self.persist_config();
            return;
        };
        self.scanner.set_stay_offline(false);
        self.scanner.start();
        // A store this account owns comes back up with it; one already running
        // against this endpoint (the usual case at open) is left alone.
        self.headers
            .follow(Some(target), slice::from_ref(&self.reconciler));
        self.reconciler.start();
        self.persist_config();
    }

    /// Stop every Electrum connection this account drives, and record that it
    /// should stay offline on the next open. The header store is only idled
    /// when this account owns it: one shared across accounts (see
    /// [`Account::try_new_with_header_store`]) is the sharer's to stop.
    pub fn stop_electrum(&mut self) {
        self.scanner.stop();
        self.headers.stop();
        self.reconciler.stop();
        self.scanner.set_stay_offline(true);
        self.persist_config();
    }

    /// True while the scanner has no live Electrum connection. Says nothing
    /// about [`bwk_electrum::config::ScannerConfig::stay_offline`], which is
    /// the persisted intent to not connect at all.
    pub fn electrum_offline(&self) -> bool {
        !self.scanner.online()
    }

    /// Test-only accessor for the account's `HeaderStore` handle, used to
    /// assert store identity (`Arc::ptr_eq`) across accounts sharing one.
    #[cfg(any(test, feature = "test"))]
    pub fn header_store(&self) -> &Arc<HeaderStore<P::HeaderStore>> {
        self.headers.store()
    }

    /// Sets the look-ahead value for the account.
    pub fn set_look_ahead(&mut self, look_ahead: String) {
        if let Ok(la) = look_ahead.parse::<u32>() {
            self.scanner.set_look_ahead(la);
            self.persist_config();
        } else {
            self.sender
                .send(Notification::InvalidLookAhead)
                .expect("cannot fail");
        }
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_persist::{config_store::FileConfigStore, storage::Store, PersistenceKind};
    use bwk_sign::{hot_signer::HotSigner, identity::SignerState, manager::SigningManager};
    use miniscript::{
        bitcoin::{
            bip32::{self, ChildNumber, DerivationPath},
            Network, ScriptBuf,
        },
        Descriptor, DescriptorPublicKey,
    };
    use std::{path::PathBuf, str::FromStr, sync::mpsc::TryRecvError};
    use temp_dir::TempDir;

    use crate::config::CONFIG_FILENAME;

    fn persisted_offline_config(dir: &TempDir, look_ahead: u32) -> Config {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "acct".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            dir.path().to_path_buf(),
            ".bwk".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.look_ahead = look_ahead;
        config.scanner.set_stay_offline(true);
        config
    }

    // A descriptor the scan cannot derive from (single path, no `<0;1>`) must
    // fail the open: the coin store derives from it and would otherwise panic
    // while the account is being built.
    #[test]
    fn a_descriptor_the_scan_cannot_derive_from_fails_the_open() {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let signer =
            HotSigner::new_from_mnemonics(Network::Regtest, &mnemonic.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/1'/0'").unwrap());
        let single_path = Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wpkh([{}/{}]{}/0/*)",
            xpub.origin.0, xpub.origin.1, xpub.xkey
        ))
        .unwrap();
        let config = Config::new(
            Some(mnemonic.to_string()),
            "acct".to_string(),
            Network::Regtest,
            ScriptType::Descriptor(Box::new(single_path)),
            PathBuf::default(),
            ".bwk".to_string(),
            None,
        )
        .unwrap();

        let opened: Result<Account, _> = Account::try_new(config);
        assert!(matches!(opened, Err(open::Error::Descriptor(_))));
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
                account.scanner_mut().new_change_addr();
            }
            derivator = account.scanner().derivator();
            assert!(account.scanner().change_watch_tip() >= 10);
            drop(account);
        }

        // Reopen: the tip must be restored (fix 1), not reset to 0.
        let account: Account = Account::new(saved);
        assert!(
            account.scanner().change_watch_tip() >= 10,
            "change tip must survive restart, got {}",
            account.scanner().change_watch_tip()
        );

        // History for a change script past the restored window must extend the
        // store rather than panic (fix 3).
        let beyond = account.scanner().change_watch_tip() + 5;
        let spk = derivator.change_at(beyond).script_pubkey();
        {
            let mut store = account.scanner.coin_store().lock().expect("poisoned");
            let mut map = BTreeMap::new();
            map.insert(spk.clone(), vec![]);
            store.handle_history_response(map);
        }
        assert!(
            account.scanner().change_watch_tip() > beyond,
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

        let account_dir = config.scanner.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::backend::json::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::storage::ram::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                bwk_electrum::profile::encode_status_key,
                bwk_electrum::profile::decode_status_key,
                bwk_electrum::profile::encode_status_value,
                bwk_electrum::profile::decode_status_value,
            )
            .unwrap();
            statuses
                .insert(ScriptBuf::from_bytes(vec![0x00; 22]), (None, 1, 30))
                .unwrap();
            statuses.flush().unwrap();
        }

        let account: Account = Account::new(config);
        assert!(
            account.scanner().change_watch_tip() >= 30,
            "change tip must be floored by the statuses max index, got {}",
            account.scanner().change_watch_tip()
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

        let account_dir = config.scanner.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::backend::json::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::storage::ram::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                bwk_electrum::profile::encode_status_key,
                bwk_electrum::profile::decode_status_key,
                bwk_electrum::profile::encode_status_value,
                bwk_electrum::profile::decode_status_value,
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
            account.scanner().change_watch_tip(),
            generated + look_ahead + 1,
            "generated tip must not be inflated by the look-ahead on reopen"
        );
        drop(account);
    }

    #[test]
    fn account_rejects_sp_descriptor() {
        let sp_str = "sp(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,\
                       0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600)";
        let dir = TempDir::new().unwrap();
        let mut config = persisted_offline_config(&dir, 20);
        config.scanner.descriptor =
            bwk_descriptor::descriptor::Descriptor::from_str(sp_str).unwrap();
        let account_dir = config.scanner.account_dir();
        let header_store = HeaderStore::new_in_memory(config.scanner.network);

        let result: Result<Account, open::Error> =
            Account::try_new_with_header_store(config, header_store);

        assert!(matches!(result, Err(open::Error::SpDescriptor)));
        assert!(
            !account_dir.exists(),
            "account directory must not be created for a rejected config"
        );
    }

    #[test]
    fn wallet_descriptor_returns_the_enum() {
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 20);
        let account: Account = Account::new(config);

        let wallet_descriptor = account.scanner().wallet_descriptor();

        assert!(matches!(
            wallet_descriptor,
            bwk_descriptor::descriptor::Descriptor::Miniscript(_)
        ));
        assert_eq!(
            wallet_descriptor.to_string(),
            account.scanner().descriptor_str()
        );
    }

    #[test]
    fn no_signer_file_is_written() {
        let temp = TempDir::new().unwrap();
        let mnemonic = Mnemonic::generate(12).unwrap().to_string();

        let cfg = Config::new(
            Some(mnemonic),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();

        let account_dir = cfg.scanner.account_dir();
        let config_store: Arc<dyn ConfigStore<Config>> = Arc::new(FileConfigStore::<Config>::new(
            account_dir.join(CONFIG_FILENAME),
        ));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        drop(account);

        assert!(
            !account_dir.join("signers.json").exists(),
            "no signer file should ever be written, hot signers are in-memory only"
        );
    }

    #[test]
    fn mnemonic_still_yields_a_hot_signer() {
        // bwk has no persistence path for signer material; the config's
        // mnemonic must still yield a derived, in-memory hot signer.
        let mnemonic = Mnemonic::generate(12).unwrap();
        let dir = TempDir::new().unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "acct".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            dir.path().to_path_buf(),
            ".bwk".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.set_stay_offline(true);
        let account: Account = Account::new(config);

        let expected_fingerprint =
            HotSigner::new_from_mnemonics(Network::Regtest, &mnemonic.to_string())
                .unwrap()
                .fingerprint();
        let signers = account.signers();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].fingerprint, expected_fingerprint);
    }

    /// The signer, descriptor and PSBT bytes of the last `sign` call a
    /// [`StubManager`] received.
    type LastSign = Arc<Mutex<Option<(SignerId, bwk_descriptor::descriptor::Descriptor, Vec<u8>)>>>;

    /// Shared stub for the signing-manager attach/detach tests below.
    /// Records every call it receives and keeps the sender handed to it by
    /// `subscribe` in a shared slot, so a test can push a `Response` on it
    /// after attaching.
    struct StubManager {
        calls: Arc<Mutex<Vec<String>>>,
        captured_sender: Arc<Mutex<Option<channel::Sender<Response>>>>,
        requests: bwk_sign::protocol::RequestIdSource,
        initial_signers: Vec<SignerInfo>,
        /// When set, every request method panics instead of recording and
        /// answering, so a test can assert that a non-blocking call never
        /// reaches one.
        panic_on_request: bool,
        last_sign: LastSign,
        last_register_descriptor:
            Arc<Mutex<Option<(SignerId, bwk_descriptor::descriptor::Descriptor)>>>,
    }

    impl StubManager {
        fn new(
            calls: Arc<Mutex<Vec<String>>>,
            captured_sender: Arc<Mutex<Option<channel::Sender<Response>>>>,
        ) -> Self {
            Self {
                calls,
                captured_sender,
                requests: bwk_sign::protocol::RequestIdSource::new(),
                initial_signers: Vec::new(),
                panic_on_request: false,
                last_sign: Arc::new(Mutex::new(None)),
                last_register_descriptor: Arc::new(Mutex::new(None)),
            }
        }

        fn with_signers(mut self, signers: Vec<SignerInfo>) -> Self {
            self.initial_signers = signers;
            self
        }

        fn panicking(mut self) -> Self {
            self.panic_on_request = true;
            self
        }

        fn record(&self, call: &str) {
            self.calls.lock().expect("poisoned").push(call.to_string());
        }

        fn deny_request(&self, call: &str) {
            if self.panic_on_request {
                panic!("request method {call} reached on a non-blocking call");
            }
        }

        fn last_sign(&self) -> LastSign {
            self.last_sign.clone()
        }

        fn last_register_descriptor(
            &self,
        ) -> Arc<Mutex<Option<(SignerId, bwk_descriptor::descriptor::Descriptor)>>> {
            self.last_register_descriptor.clone()
        }
    }

    impl SigningManager for StubManager {
        fn signers(&self) -> Vec<SignerInfo> {
            self.record("signers");
            self.initial_signers.clone()
        }

        fn subscribe(&mut self, sender: channel::Sender<Response>) {
            self.record("subscribe");
            *self.captured_sender.lock().expect("poisoned") = Some(sender);
        }

        fn set_polling(&mut self, _enabled: bool) {
            self.record("set_polling");
        }

        fn init(&mut self, _signer: &SignerId) -> Result<RequestId, manager::Error> {
            self.deny_request("init");
            self.record("init");
            Ok(self.requests.next())
        }

        fn info(&self, _signer: &SignerId) -> Result<RequestId, manager::Error> {
            self.deny_request("info");
            self.record("info");
            Ok(self.requests.next())
        }

        fn get_xpub(
            &self,
            _signer: &SignerId,
            _path: DerivationPath,
            _display: bool,
        ) -> Result<RequestId, manager::Error> {
            self.deny_request("get_xpub");
            self.record("get_xpub");
            Ok(self.requests.next())
        }

        fn is_descriptor_registered(
            &self,
            _signer: &SignerId,
            _descriptor: bwk_descriptor::descriptor::Descriptor,
        ) -> Result<RequestId, manager::Error> {
            self.deny_request("is_descriptor_registered");
            self.record("is_descriptor_registered");
            Ok(self.requests.next())
        }

        fn register_descriptor(
            &mut self,
            signer: &SignerId,
            descriptor: bwk_descriptor::descriptor::Descriptor,
        ) -> Result<RequestId, manager::Error> {
            self.deny_request("register_descriptor");
            self.record("register_descriptor");
            *self.last_register_descriptor.lock().expect("poisoned") =
                Some((signer.clone(), descriptor));
            Ok(self.requests.next())
        }

        fn sign(
            &self,
            signer: &SignerId,
            descriptor: bwk_descriptor::descriptor::Descriptor,
            psbt: Vec<u8>,
        ) -> Result<RequestId, manager::Error> {
            self.deny_request("sign");
            self.record("sign");
            *self.last_sign.lock().expect("poisoned") = Some((signer.clone(), descriptor, psbt));
            Ok(self.requests.next())
        }

        fn raw(&self, _signer: &SignerId, _request: Vec<u8>) -> Result<RequestId, manager::Error> {
            self.deny_request("raw");
            self.record("raw");
            Ok(self.requests.next())
        }
    }

    fn account_for_signing_tests() -> (Account, TempDir) {
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 20);
        (Account::new(config), dir)
    }

    #[test]
    fn attach_then_detach_stops_the_pump() {
        let (mut account, _dir) = account_for_signing_tests();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured_sender = Arc::new(Mutex::new(None));
        let stub = StubManager::new(calls, captured_sender);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();
        assert!(account
            .signing_manager_names()
            .contains(&"stub".to_string()));

        assert!(account.detach_signing_manager("stub"));
        assert!(!account
            .signing_manager_names()
            .contains(&"stub".to_string()));
        assert!(!account.detach_signing_manager("stub"));
    }

    #[test]
    fn duplicate_manager_name_is_refused() {
        let (mut account, _dir) = account_for_signing_tests();
        let calls_a = Arc::new(Mutex::new(Vec::new()));
        let calls_b = Arc::new(Mutex::new(Vec::new()));
        account
            .attach_signing_manager(
                "stub",
                Box::new(StubManager::new(calls_a, Arc::new(Mutex::new(None)))),
            )
            .unwrap();

        let result = account.attach_signing_manager(
            "stub",
            Box::new(StubManager::new(calls_b, Arc::new(Mutex::new(None)))),
        );
        assert!(matches!(result, Err(Error::ManagerAlreadyAttached)));
        assert!(account
            .signing_manager_names()
            .contains(&"stub".to_string()));
    }

    #[test]
    fn manager_responses_reach_the_account_channel() {
        let (mut account, _dir) = account_for_signing_tests();
        let receiver = account.receiver().unwrap();
        // Drain whatever construction (coin store generation, the hot
        // manager's own subscribe) already queued, so the assertion below
        // only sees what happens after this test's response is sent.
        while receiver.try_recv().is_ok() {}
        let calls = Arc::new(Mutex::new(Vec::new()));
        let captured_sender = Arc::new(Mutex::new(None));
        let stub = StubManager::new(calls, captured_sender.clone());
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let sender = captured_sender.lock().unwrap().clone().unwrap();
        sender
            .send(Response::SignersChanged { signers: vec![] })
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // No Notification variant maps a signing-manager Response, so assert
        // the pump drained the response without panicking (the account
        // channel stays empty) and that the pump thread is still alive (the
        // channel accepts a second send).
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        sender
            .send(Response::SignersChanged { signers: vec![] })
            .unwrap();

        assert!(account.detach_signing_manager("stub"));
    }

    #[test]
    fn watch_only_account_attaches_no_manager() {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let signer =
            HotSigner::new_from_mnemonics(Network::Regtest, &mnemonic.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let descriptor = bwk_descriptor::descriptor::wpkh(xpub);
        let dir = TempDir::new().unwrap();
        let mut config = Config::new(
            None,
            "watch-only".to_string(),
            Network::Regtest,
            ScriptType::Descriptor(Box::new(descriptor)),
            dir.path().to_path_buf(),
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.set_stay_offline(true);

        let account: Account = Account::new(config);
        assert!(account.signing_manager_names().is_empty());
    }

    #[test]
    fn attach_does_not_register_descriptors() {
        let (mut account, _dir) = account_for_signing_tests();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stub = StubManager::new(calls.clone(), Arc::new(Mutex::new(None)));
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let seen = calls.lock().unwrap().clone();
        assert_eq!(seen, vec!["subscribe".to_string(), "signers".to_string()]);
    }

    fn signer_info(id: &str, fingerprint: [u8; 4], state: SignerState) -> SignerInfo {
        SignerInfo::new(
            SignerId::new(id),
            bip32::Fingerprint::from(fingerprint),
            "wallet".to_string(),
            state,
        )
    }

    #[test]
    fn attach_seeds_the_signer_list() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("seed-a", [1, 1, 1, 1], SignerState::Ready);
        let b = signer_info("seed-b", [2, 2, 2, 2], SignerState::Ready);
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone(), b.clone()]);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let ids: Vec<SignerId> = account
            .signers()
            .into_iter()
            .map(|info| info.id)
            .filter(|id| *id == a.id || *id == b.id)
            .collect();
        assert_eq!(ids, vec![a.id.clone(), b.id.clone()]);
    }

    #[test]
    fn two_signers_share_a_fingerprint() {
        let (mut account, _dir) = account_for_signing_tests();
        let fingerprint = [9, 9, 9, 9];
        let a = signer_info("dup-a", fingerprint, SignerState::Ready);
        let b = signer_info("dup-b", fingerprint, SignerState::Ready);
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone(), b.clone()]);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let signers = account.signers();
        assert!(signers.contains(&a));
        assert!(signers.contains(&b));
    }

    #[test]
    fn detach_removes_only_that_managers_signers() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("mgr-a-signer", [1, 1, 1, 1], SignerState::Ready);
        let b = signer_info("mgr-b-signer", [2, 2, 2, 2], SignerState::Ready);
        let stub_a = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        let stub_b = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![b.clone()]);
        account
            .attach_signing_manager("stub-a", Box::new(stub_a))
            .unwrap();
        account
            .attach_signing_manager("stub-b", Box::new(stub_b))
            .unwrap();

        assert!(account.detach_signing_manager("stub-a"));

        let signers = account.signers();
        assert!(!signers.contains(&a));
        assert!(signers.contains(&b));
    }

    #[test]
    fn roster_update_replaces_wholesale() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("roster-a", [3, 3, 3, 3], SignerState::Ready);
        let b = signer_info("roster-b", [4, 4, 4, 4], SignerState::Ready);
        let captured_sender = Arc::new(Mutex::new(None));
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), captured_sender.clone())
            .with_signers(vec![a.clone(), b.clone()]);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let a_locked = SignerInfo::new(
            a.id.clone(),
            a.fingerprint,
            a.wallet_name.clone(),
            SignerState::Locked,
        )
        .with_detail("locked");

        let sender = captured_sender.lock().unwrap().clone().unwrap();
        sender
            .send(Response::SignersChanged {
                signers: vec![a_locked.clone()],
            })
            .unwrap();

        let mut updated = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(20));
            let signers = account.signers();
            if signers.contains(&a_locked) && !signers.contains(&a) && !signers.contains(&b) {
                updated = true;
                break;
            }
        }
        assert!(updated, "roster update was not replaced wholesale in time");
    }

    #[test]
    fn signers_is_non_blocking() {
        let (mut account, _dir) = account_for_signing_tests();
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .panicking();
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let _ = account.signers();
        account.refresh_signers();
    }

    #[test]
    fn polling_flag_reaches_every_manager() {
        let (mut account, _dir) = account_for_signing_tests();
        let calls_a = Arc::new(Mutex::new(Vec::new()));
        let calls_b = Arc::new(Mutex::new(Vec::new()));
        account
            .attach_signing_manager(
                "stub-a",
                Box::new(StubManager::new(
                    calls_a.clone(),
                    Arc::new(Mutex::new(None)),
                )),
            )
            .unwrap();
        account
            .attach_signing_manager(
                "stub-b",
                Box::new(StubManager::new(
                    calls_b.clone(),
                    Arc::new(Mutex::new(None)),
                )),
            )
            .unwrap();

        account.set_signer_polling(true);
        account.set_signer_polling(false);

        let expected = vec![
            "subscribe".to_string(),
            "signers".to_string(),
            "set_polling".to_string(),
            "set_polling".to_string(),
        ];
        assert_eq!(calls_a.lock().unwrap().clone(), expected);
        assert_eq!(calls_b.lock().unwrap().clone(), expected);
    }

    fn test_miniscript_descriptor() -> bwk_descriptor::descriptor::Descriptor {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let signer =
            HotSigner::new_from_mnemonics(Network::Regtest, &mnemonic.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        bwk_descriptor::descriptor::wpkh(xpub).into()
    }

    fn test_sp_descriptor() -> bwk_descriptor::descriptor::Descriptor {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let scan = bip32::Xpriv::new_master(Network::Regtest, &[0x09; 64]).unwrap();
        let spend = bip32::Xpriv::new_master(Network::Regtest, &[0x0a; 64]).unwrap();
        let spend_xpub = bip32::Xpub::from_priv(&secp, &spend);
        bwk_descriptor::sp_descriptor::SpDescriptor::from_str(&format!(
            "sp([deadbeef/352h/1h/0h]{scan}/0h,{spend_xpub}/0h)"
        ))
        .unwrap()
        .into()
    }

    #[test]
    fn sign_forwards_bytes_untouched() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("signer-1", [1, 1, 1, 1], SignerState::Ready);
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        let last_sign = stub.last_sign();
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let descriptor = test_miniscript_descriptor();
        account
            .sign(&a.id, descriptor.clone(), vec![0xde, 0xad, 0xbe, 0xef])
            .unwrap();

        let (signer, sent_descriptor, bytes) = last_sign.lock().unwrap().clone().unwrap();
        assert_eq!(signer, a.id);
        assert_eq!(sent_descriptor, descriptor);
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn sign_returns_immediately() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("signer-1", [1, 1, 1, 1], SignerState::Ready);
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        // The stub records the call and never sends a `Response` on its
        // channel; if `sign` waited for one instead of returning the queued
        // `RequestId` straight away, this call would hang.
        account
            .sign(&a.id, test_miniscript_descriptor(), vec![1, 2, 3])
            .unwrap();
    }

    #[test]
    fn sign_rejects_unknown_signer() {
        let (mut account, _dir) = account_for_signing_tests();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stub = StubManager::new(calls.clone(), Arc::new(Mutex::new(None)));
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let unknown = SignerId::new("does-not-exist");
        let result = account.sign(&unknown, test_miniscript_descriptor(), vec![1]);
        assert!(matches!(result, Err(Error::UnknownSigner)));
        assert!(!calls.lock().unwrap().contains(&"sign".to_string()));
    }

    #[test]
    fn sign_rejects_locked_signer() {
        let (mut account, _dir) = account_for_signing_tests();
        let locked = signer_info("locked-1", [2, 2, 2, 2], SignerState::Locked);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stub = StubManager::new(calls.clone(), Arc::new(Mutex::new(None)))
            .with_signers(vec![locked.clone()]);
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let result = account.sign(&locked.id, test_miniscript_descriptor(), vec![1]);
        assert!(matches!(result, Err(Error::SignerNotReady)));
        assert!(!calls.lock().unwrap().contains(&"sign".to_string()));
    }

    #[test]
    fn register_descriptor_is_consumer_driven() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("signer-1", [3, 3, 3, 3], SignerState::Ready);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stub = StubManager::new(calls.clone(), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        let last_register = stub.last_register_descriptor();
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        assert!(!calls
            .lock()
            .unwrap()
            .contains(&"register_descriptor".to_string()));

        let descriptor = test_miniscript_descriptor();
        account
            .register_descriptor(&a.id, descriptor.clone())
            .unwrap();

        let seen = calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| *c == "register_descriptor")
            .count();
        assert_eq!(seen, 1);
        let (signer, sent) = last_register.lock().unwrap().clone().unwrap();
        assert_eq!(signer, a.id);
        assert_eq!(sent, descriptor);
    }

    #[test]
    fn sign_routes_to_the_owning_manager() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("mgr-a-signer", [4, 4, 4, 4], SignerState::Ready);
        let b = signer_info("mgr-b-signer", [5, 5, 5, 5], SignerState::Ready);
        let calls_a = Arc::new(Mutex::new(Vec::new()));
        let calls_b = Arc::new(Mutex::new(Vec::new()));
        let stub_a = StubManager::new(calls_a.clone(), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        let stub_b = StubManager::new(calls_b.clone(), Arc::new(Mutex::new(None)))
            .with_signers(vec![b.clone()]);
        account
            .attach_signing_manager("stub-a", Box::new(stub_a))
            .unwrap();
        account
            .attach_signing_manager("stub-b", Box::new(stub_b))
            .unwrap();

        account
            .sign(&b.id, test_miniscript_descriptor(), vec![9])
            .unwrap();

        assert!(!calls_a.lock().unwrap().contains(&"sign".to_string()));
        assert!(calls_b.lock().unwrap().contains(&"sign".to_string()));
    }

    #[test]
    fn sp_descriptor_reaches_the_manager() {
        let (mut account, _dir) = account_for_signing_tests();
        let a = signer_info("signer-1", [6, 6, 6, 6], SignerState::Ready);
        let stub = StubManager::new(Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)))
            .with_signers(vec![a.clone()]);
        let last_sign = stub.last_sign();
        account
            .attach_signing_manager("stub", Box::new(stub))
            .unwrap();

        let descriptor = test_sp_descriptor();
        account.sign(&a.id, descriptor.clone(), vec![7]).unwrap();

        let (_, sent, _) = last_sign.lock().unwrap().clone().unwrap();
        assert!(sent.is_sp());
        assert_eq!(sent, descriptor);
    }
}

#[cfg(test)]
mod integration_tests {

    use rand::random_range;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{mpsc, Once},
        thread::sleep,
        time::Duration,
    };

    use crate::{
        account::Account,
        config::{maybe_create_dir, Config},
    };
    use bip39::Mnemonic;
    use bwk_coin::CoinStatus;
    use bwk_descriptor::descriptor::{Descriptor, ScriptType};
    use bwk_electrum::{
        client::Client,
        coin_store::Payment,
        notification::{Notification, TxListenerNotif},
        raw_client::CertificateCheck,
        tx_store::Inclusion,
    };
    use bwk_persist::PersistenceKind;
    use bwk_sign::hot_signer::HotSigner;
    use bwk_utils::test::{
        electrsd,
        regtest::{
            self, generate, get_block_hash_str, get_block_height, invalidate_block, wait_until,
        },
        temp_dir::TempDir,
        TestBitcoinD,
    };
    use miniscript::bitcoin::{
        self, bip32::ChildNumber, Address, Amount, Network, Transaction, Txid,
    };
    use miniscript::psbt::PsbtExt;

    use electrsd::{
        bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD},
        ElectrsD,
    };

    pub fn bootstrap_electrs() -> (
        String, /* url */
        u16,    /* port */
        ElectrsD,
        TestBitcoinD,
    ) {
        let bootstrapped = regtest::bootstrap_electrs();

        // Without root we cannot raise electrsd's priority directly, so lower
        // the test process instead. Gives electrsd's indexer relatively more
        // CPU when the host is under load (the source of past flakes). Done
        // after the spawn so the daemons keep the priority they started with.
        #[cfg(unix)]
        unsafe {
            libc::nice(5);
        }

        bootstrapped
    }

    #[allow(unused)]
    pub fn tcp_client() -> (Client, ElectrsD, TestBitcoinD) {
        let (url, port, e, b) = bootstrap_electrs();
        let client = Client::new(&url, port, CertificateCheck::Validate).unwrap();

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

    pub fn reorg_chain(bitcoind: &BitcoinD, blocks: u32) {
        let chain_height: u32 = get_block_height(bitcoind);
        let reorg_height = chain_height - blocks;
        let block_hash = get_block_hash_str(bitcoind, reorg_height);

        invalidate_block(bitcoind, block_hash);

        generate(bitcoind, blocks);
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

    /// [`wait_until`] for a `timeout` in seconds, panicking when the condition
    /// never holds.
    pub fn wait_until_timeout<F>(condition: F, timeout: u64)
    where
        F: FnMut() -> bool,
    {
        assert!(
            wait_until(Duration::from_secs(timeout), condition),
            "Timeout elapsed while waiting for condition."
        );
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
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.network = Network::Regtest;
        config.scanner.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.scanner.new_recv_addr();
        let change_addr = account.scanner_mut().new_change_addr();

        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 1
            },
            TIMEOUT,
        );

        // Test change address
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        // receive at look_ahead bound
        let recv_addr = account.scanner().recv_at(look_ahead);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 3
            },
            TIMEOUT,
        );

        // change at look_ahead bound
        let change_addr = account.scanner().change_at(look_ahead);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 4
            },
            TIMEOUT,
        );

        let undiscovered_tip = account.scanner().recv_watch_tip() + 1;

        // receive beyond the look_ahead bound
        let recv_addr = account.scanner().recv_at(undiscovered_tip);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.scanner().coins();
        // the coin is not detected for receiving address
        assert_eq!(coins.len(), 4);

        // change beyond the look_ahead bound
        let change_addr = account.scanner().change_at(undiscovered_tip);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.scanner().coins();
        // the coin is not detected for change address
        assert_eq!(coins.len(), 4);

        // move the watch tip forward
        account.scanner.new_recv_addr();
        account.scanner.new_recv_addr();
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 5
            },
            TIMEOUT,
        );

        account.scanner_mut().new_change_addr();
        account.scanner_mut().new_change_addr();
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
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
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.scanner.new_recv_addr();
        let change_addr = account.scanner_mut().new_change_addr();

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
                let coins = account.scanner().coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        let coins = account.scanner().coins();
        let coins_height: BTreeMap<_, _> =
            coins.into_iter().map(|(c, e)| (c, e.height())).collect();

        // With the pending-claims queue and merkle verification in
        // place, both coins are confirmed at this point and should carry
        // a height.
        assert!(coins_height.iter().all(|(_, e)| e.is_some()));

        let height_before_reorg = get_block_height(&bitcoind);
        let h_before_reorg = get_block_hash_str(&bitcoind, height_before_reorg);

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

        let new_h = get_block_hash_str(&bitcoind, height_before_reorg);
        assert_ne!(h_before_reorg, new_h);

        let coins = account.scanner().coins();
        // there is still 2 coins
        assert_eq!(coins.len(), 2);
    }

    #[cfg(feature = "test")]
    use bwk_tx::tx_builder::TxBuilder;

    /// Signs `psbt` with a fresh [`HotSigner`] built from `mnemonic`,
    /// registering `descriptor` on it first.
    fn sign_with_mnemonic(
        psbt: &mut bitcoin::Psbt,
        network: Network,
        mnemonic: &str,
        descriptor: Descriptor,
    ) {
        let mut signer = HotSigner::new_from_mnemonics(network, mnemonic).unwrap();
        signer.inner_register_descriptor(descriptor);
        signer.sign(psbt);
    }

    #[cfg(feature = "test")]
    fn spend(
        account: &mut Account,
        builder: &mut TxBuilder,
        bitcoind: &BitcoinD,
        amount: u64,
        mnemonic: &str,
    ) -> (bitcoin::Txid, u32) {
        let coins = account
            .scanner()
            .spendable_coins()
            .coins
            .into_values()
            .collect();
        builder.new_template();
        builder.tx_template.inputs = coins;
        builder.dummy_external_output(amount);
        let mut psbt = builder.generate().unwrap();
        sign_with_mnemonic(
            &mut psbt,
            account.scanner().network(),
            mnemonic,
            account.scanner().wallet_descriptor(),
        );
        PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new()).unwrap();
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let txid = bitcoind.client.send_raw_transaction(&tx).unwrap();
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        (txid, blocks)
    }

    fn receive(account: &mut Account, bitcoind: &BitcoinD, amount: u64) -> u32 {
        let recv_addr = account.scanner.new_recv_addr();
        send_to_address(bitcoind, &recv_addr, Amount::from_sat(amount));
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        blocks
    }

    /// Wait for `account` to hold `count` coins the reconciler has verified. A
    /// coin only turns `CoinStatus::Confirmed` once its tx reaches
    /// `Inclusion::Verified`, so a reconciler that never comes back leaves the
    /// coins `ConfirmedUnverified` and this times out.
    #[cfg(feature = "test")]
    fn wait_coins_verified(account: &Account, count: usize, timeout: u64) {
        let verified = || {
            let coins = account.scanner().coins();
            if coins.len() != count || coins.values().any(|c| c.status() != CoinStatus::Confirmed) {
                return false;
            }
            let proved: BTreeSet<Txid> = account
                .scanner()
                .tx_history()
                .iter()
                .filter(|tx| matches!(tx.inclusion(), Inclusion::Verified { .. }))
                .map(|tx| tx.txid())
                .collect();
            coins.keys().all(|outpoint| proved.contains(&outpoint.txid))
        };
        assert!(
            wait_until(Duration::from_secs(timeout), verified),
            "expected {count} verified coins, got {:?}",
            account
                .scanner()
                .coins()
                .values()
                .map(|c| c.status())
                .collect::<Vec<_>>()
        );
    }

    #[allow(unused)]
    fn sort_payments(payments: &Vec<Payment>) -> (usize, usize) {
        let mut recv = 0;
        let mut sent = 0;
        for p in payments {
            match p.payment_type {
                bwk_electrum::coin_store::PaymentType::Receive => recv += 1,
                bwk_electrum::coin_store::PaymentType::Send => sent += 1,
                bwk_electrum::coin_store::PaymentType::ToSelf => {}
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
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.network = Network::Regtest;
        config.scanner.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account = Account::new(config);
        sleep(Duration::from_millis(300));
        let mut builder = account.tx_builder();

        let blocks = receive(&mut account, &bitcoind, 200_000);
        wait_until_timeout(
            || {
                let coins = account.scanner().coins();
                coins.len() == 1
            },
            block_wait(blocks),
        );
        let (_, blocks) = spend(
            &mut account,
            &mut builder,
            &bitcoind,
            100_000,
            &mnemonic.to_string(),
        );
        wait_until_timeout(
            || {
                let payments = account.scanner().payment_history();
                payments.len() == 2
            },
            block_wait(blocks),
        );

        let payments = account.scanner().payment_history();
        assert_eq!(2, payments.len());
        let sorted = sort_payments(&payments);
        assert_eq!(sorted, (1, 1));

        // Every confirmed payment gets a block timestamp from the listener.
        wait_until_timeout(
            || {
                account
                    .scanner()
                    .payment_history()
                    .iter()
                    .filter(|p| p.height.is_some())
                    .all(|p| p.timestamp.is_some_and(|t| t > 0))
            },
            block_wait(5),
        );
        let confirmed: Vec<_> = account
            .scanner()
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
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.network = Network::Regtest;
        config.scanner.look_ahead = 20;
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
        wait_coins_verified(&account, 1, block_wait(blocks));

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
        wait_coins_verified(&account, 2, block_wait(blocks));

        // restart_electrum() (the in-place path) behaves the same.
        while notif.try_recv().is_ok() {}
        account.restart_electrum();
        assert!(
            wait_notif(&notif, is_started),
            "listener did not restart on restart_electrum"
        );
        let blocks = receive(&mut account, &bitcoind, 120_000);
        wait_coins_verified(&account, 3, block_wait(blocks));
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
            Some(PersistenceKind::Json),
        )
        .unwrap();
        config.scanner.network = Network::Regtest;
        config.scanner.look_ahead = look_ahead;
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
                    || !account.scanner().spendable_coins().coins.is_empty(),
                    block_wait(prev_blocks),
                );
                sleep(Duration::from_millis(1000));
                let coins = account.scanner().spendable_coins();
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
                        sign_with_mnemonic(
                            &mut psbt,
                            account.scanner().network(),
                            &mnemonic.to_string(),
                            account.scanner().wallet_descriptor(),
                        );
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
            wait_until_timeout(|| account.scanner().payment_history().len() >= 16, 120);
            let payments = account.scanner().payment_history();
            assert_eq!(payments.len(), 16);
        }

        let account: Account = Account::new(saved_config);
        sleep(Duration::from_millis(300));
        let payments = account.scanner().payment_history();
        assert_eq!(payments.len(), 16);
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_signer_exclusion {
    use super::*;
    use crate::config::{Config, CONFIG_FILENAME};
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_persist::{config_store::FileConfigStore, PersistenceKind};
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
            Some(PersistenceKind::Json),
        )
        .expect("config");
        cfg.scanner.set_stay_offline(true);
        cfg.scanner.persistence = Some(PersistenceKind::Sqlite);

        // Wire a FileConfigStore against the account dir's config.json,
        // build the account, drive a config save + a label write to
        // exercise multiple persist paths. SQLite mode must not write
        // the mnemonic anywhere under the account dir.
        let account_dir = cfg.scanner.account_dir();
        let config_store: Arc<dyn ConfigStore<Config>> = Arc::new(FileConfigStore::<Config>::new(
            account_dir.join(CONFIG_FILENAME),
        ));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        account
            .scanner
            .label_store()
            .lock()
            .expect("poisoned")
            .persist();
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
            Some(PersistenceKind::Json),
        )
        .expect("config")
        .with_persistence(Some(PersistenceKind::Json));

        let account_dir = cfg.scanner.account_dir();
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

    #[test]
    fn sqlite_account_opens_without_a_secrets_backend() {
        // With no signer store, the SQLite path needs no special case: opening
        // must succeed and the mnemonic must still yield a derived hot signer.
        let temp = TempDir::new().unwrap();
        let mnemonic = Mnemonic::generate(12).unwrap().to_string();

        let mut cfg = Config::new(
            Some(mnemonic.clone()),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            Some(PersistenceKind::Sqlite),
        )
        .unwrap();
        cfg.scanner.set_stay_offline(true);

        let account: Account = Account::new(cfg);
        let expected_fingerprint =
            bwk_sign::hot_signer::HotSigner::new_from_mnemonics(Network::Regtest, &mnemonic)
                .unwrap()
                .fingerprint();
        let signers = account.signers();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].fingerprint, expected_fingerprint);
    }
}
