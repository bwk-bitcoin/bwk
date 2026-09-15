use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crossbeam::channel;

use bwk_descriptor::descriptor::Descriptor;
use bwk_persist::{
    backend::{noop::NoopBackend, PersistenceBackend},
    storage::{ram::RamStore, Store},
    PersistError,
};

use miniscript::{
    bitcoin::{
        self,
        bip32::{self, DerivationPath},
    },
    DescriptorPublicKey,
};

use crate::{
    error,
    hot_signer::{HotSigner, JsonSigner},
    identity::{SignerId, SignerInfo, SignerState},
    manager,
    protocol::{self, RequestId, RequestIdSource, Response},
    signer::{Signer, SignerNotif},
};

#[derive(Debug, Clone)]
pub enum Error {
    ParsePsbt,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    Hw(String),
}

pub enum SignerKind {
    Hot,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    External(bwk_hwi::DeviceKind),
}

#[cfg(all(feature = "hwi", not(target_os = "android")))]
impl Clone for SignerKind {
    fn clone(&self) -> Self {
        match self {
            SignerKind::Hot => SignerKind::Hot,
            SignerKind::External(k) => SignerKind::External(*k),
        }
    }
}

#[allow(clippy::mutable_key_type)]
struct ExternalSigner {
    signer: Box<dyn Signer>,
    fingerprint: bip32::Fingerprint,
    descriptors: BTreeSet<Descriptor>,
}

/// Logical store name used by [`PersistenceBackend`] implementations
/// for the BIP32 hot-signer store.
pub const STORE_KEY: &str = bwk_persist::SIGNERS_STORE_KEY;

pub fn encode_fingerprint(k: &bip32::Fingerprint) -> String {
    k.to_string()
}
pub fn decode_fingerprint(s: &str) -> Result<bip32::Fingerprint, PersistError> {
    bip32::Fingerprint::from_str(s)
        .map_err(|e| PersistError::Serde(format!("bad Fingerprint pk {s:?}: {e}")))
}
pub fn encode_json_signer(v: &JsonSigner) -> Result<Vec<u8>, PersistError> {
    serde_json::to_vec(v).map_err(|e| PersistError::Serde(format!("encode JsonSigner: {e}")))
}
pub fn decode_json_signer(bytes: &[u8]) -> Result<JsonSigner, PersistError> {
    serde_json::from_slice(bytes)
        .map_err(|e| PersistError::Serde(format!("decode JsonSigner: {e}")))
}

/// Default backing store for [`HotManager`]: RAM-cached + write-back
/// over a runtime-dispatched [`PersistenceBackend`].
pub type DefaultSignerStore = RamStore<Arc<dyn PersistenceBackend>, bip32::Fingerprint, JsonSigner>;

fn mint_id(counter: &AtomicU64, fingerprint: &bip32::Fingerprint) -> SignerId {
    let n = counter.fetch_add(1, Ordering::Relaxed);
    SignerId::new(format!("hot:{fingerprint}:{n}"))
}

fn notif_fingerprint(notif: &SignerNotif) -> Option<bip32::Fingerprint> {
    match notif {
        SignerNotif::Info(fg, _)
        | SignerNotif::Xpub(fg, _)
        | SignerNotif::Descriptor(fg, _)
        | SignerNotif::DescriptorRegistered(fg, _, _)
        | SignerNotif::Signed(fg, _)
        | SignerNotif::Error(fg, _) => Some(*fg),
        SignerNotif::Manager(_) => None,
        #[cfg(all(feature = "hwi", not(target_os = "android")))]
        SignerNotif::DeviceUpdate => None,
    }
}

enum ParsedPsbt {
    V0(bitcoin::Psbt),
    V2(bwk_psbt::PsbtV2),
}

impl ParsedPsbt {
    fn parse(bytes: &[u8]) -> Result<Self, manager::Error> {
        match bwk_psbt::PsbtV2::deserialize(bytes) {
            Ok(psbt) => Ok(Self::V2(psbt)),
            Err(_) => bitcoin::Psbt::deserialize(bytes)
                .map(Self::V0)
                .map_err(|_| manager::Error::Psbt),
        }
    }

    fn sign(
        self,
        hot: &HotSigner,
        descriptor: &miniscript::Descriptor<DescriptorPublicKey>,
    ) -> Result<Vec<u8>, error::Error> {
        match self {
            Self::V0(mut psbt) => {
                hot.inner_sign(&mut psbt, descriptor)?;
                Ok(psbt.serialize())
            }
            Self::V2(mut psbt) => {
                hot.sign_v2(&mut psbt, descriptor)?;
                psbt.serialize().map_err(|_| error::Error::PsbtV2)
            }
        }
    }
}

/// A manager for hot (BIP32, in-memory) signers, implementing
/// [`manager::SigningManager`].
///
/// Hot signing is CPU-bound and needs no IO, so every trait method here does
/// its work inline before returning: there is no in-flight request table and
/// no worker thread. The `RequestId`/[`Response`] contract is still honored,
/// though, so a caller written against a truly asynchronous back end (a
/// hardware device, a remote signer) works unmodified against this one.
pub struct HotManager<S = DefaultSignerStore>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    receiver: channel::Receiver<SignerNotif>,
    sender: channel::Sender<SignerNotif>,
    bip32_signers: BTreeMap<SignerId, HotSigner>,
    signers: BTreeMap<SignerId, ExternalSigner>,
    store: S,
    next_hot: AtomicU64,
    requests: RequestIdSource,
    subscriber: Option<channel::Sender<Response>>,
    /// Last [`RequestId`] issued per fingerprint, so an external signer's
    /// asynchronous [`SignerNotif`] (which carries no request id of its own)
    /// can be correlated back to the call that triggered it once [`pump`]
    /// forwards it.
    ///
    /// [`pump`]: HotManager::pump
    last_request: Mutex<BTreeMap<bip32::Fingerprint, RequestId>>,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    hw_service: Option<bwk_hwi::service::HwiService<crate::hwi::HwMessage>>,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    hw_receiver: Option<channel::Receiver<crate::hwi::HwMessage>>,
}

impl<S> std::fmt::Debug for HotManager<S>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotManager")
            .field("bip32_signers", &self.bip32_signers)
            .field("signers_count", &self.signers.len())
            .finish()
    }
}

impl HotManager<DefaultSignerStore> {
    /// In-memory only (no persistence).
    pub fn new() -> Self {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        let store = RamStore::empty(backend, STORE_KEY, encode_fingerprint, encode_json_signer);
        Self::from_store(store)
    }

    /// Open the signer store against `backend`, hydrating the in-memory
    /// signer map from any rows already present.
    pub fn with_backend(backend: Arc<dyn PersistenceBackend>, store_key: &'static str) -> Self {
        match RamStore::open(
            backend.clone(),
            store_key,
            encode_fingerprint,
            decode_fingerprint,
            encode_json_signer,
            decode_json_signer,
        ) {
            Ok(store) => Self::from_store(store),
            Err(e) => {
                log::error!("HotManager::with_backend: {e}");
                let noop: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
                let store =
                    RamStore::empty(noop, store_key, encode_fingerprint, encode_json_signer);
                Self::from_store(store)
            }
        }
    }
}

impl Default for HotManager<DefaultSignerStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> HotManager<S>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    /// Wrap a pre-opened signer store. Hydrates `bip32_signers` from
    /// every row already in the store.
    pub fn from_store(store: S) -> Self {
        let (sender, receiver) = channel::unbounded();
        let next_hot = AtomicU64::new(0);
        let mut bip32_signers: BTreeMap<SignerId, HotSigner> = BTreeMap::new();
        match store.iter() {
            Ok(iter) => {
                for (_, json) in iter {
                    let mut signer = HotSigner::from_json(json);
                    signer.init(sender.clone());
                    let id = mint_id(&next_hot, &signer.fingerprint());
                    bip32_signers.insert(id, signer);
                }
            }
            Err(e) => {
                log::error!("HotManager::from_store iter: {e}");
            }
        }
        Self {
            receiver,
            sender,
            bip32_signers,
            signers: BTreeMap::new(),
            store,
            next_hot,
            requests: RequestIdSource::new(),
            subscriber: None,
            last_request: Mutex::new(BTreeMap::new()),
            #[cfg(all(feature = "hwi", not(target_os = "android")))]
            hw_service: None,
            #[cfg(all(feature = "hwi", not(target_os = "android")))]
            hw_receiver: None,
        }
    }

    /// Persists pending changes through the backend.
    pub fn persist(&mut self) {
        if let Err(e) = self.store.flush() {
            log::error!("HotManager::persist() flush: {e}");
        }
    }

    /// Polls for a new signer notification.
    ///
    /// # Returns
    /// An `Option<SignerNotif>` which is `Some` if a notification is available,
    /// or `None` if there are no new notifications.
    pub fn poll(&self) -> Option<SignerNotif> {
        if let Ok(notif) = self.receiver.try_recv() {
            return Some(notif);
        }
        #[cfg(all(feature = "hwi", not(target_os = "android")))]
        if let Some(ref hw_rx) = self.hw_receiver {
            if let Ok(hw_msg) = hw_rx.try_recv() {
                return self.convert_hw_message(hw_msg);
            }
        }
        None
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    fn convert_hw_message(&self, msg: crate::hwi::HwMessage) -> Option<SignerNotif> {
        use bwk_hwi::service::SigningDeviceMsg;
        use bwk_keys::keys::OXpub;
        match msg {
            crate::hwi::HwMessage::Device(device_msg) => match device_msg {
                SigningDeviceMsg::Update => Some(SignerNotif::DeviceUpdate),
                SigningDeviceMsg::TransactionSigned(_, fg, psbt) => {
                    Some(SignerNotif::Signed(fg, psbt))
                }
                SigningDeviceMsg::XPub(_, fg, path, xpub) => {
                    let oxpub = OXpub {
                        origin: (fg, path),
                        xkey: xpub,
                    };
                    Some(SignerNotif::Xpub(fg, oxpub))
                }
                SigningDeviceMsg::Error(_, msg) => Some(SignerNotif::Manager(Error::Hw(msg))),
                _ => None,
            },
        }
    }

    fn mint_hot_id(&self, fingerprint: &bip32::Fingerprint) -> SignerId {
        mint_id(&self.next_hot, fingerprint)
    }

    /// Registers a fully constructed hot signer: initializes its
    /// notification channel, mints a [`SignerId`], persists the row and
    /// inserts it. Returns the freshly minted id.
    pub fn add_bip32_signer(&mut self, mut signer: HotSigner) -> SignerId {
        signer.init(self.sender.clone());
        let fg = signer.fingerprint();
        let id = self.mint_hot_id(&fg);
        if let Some(json) = signer.to_json() {
            if let Err(e) = self.store.insert(fg, json) {
                log::error!("HotManager::add_bip32_signer insert: {e}");
            }
        }
        self.bip32_signers.insert(id.clone(), signer);
        id
    }

    /// Returns whether any loaded hot signer holds `fingerprint`. The map is
    /// keyed by [`SignerId`], not by fingerprint, so this scans the values.
    pub fn has_bip32_signer(&self, fingerprint: &bip32::Fingerprint) -> bool {
        self.bip32_signers
            .values()
            .any(|s| s.fingerprint() == *fingerprint)
    }

    /// Creates a new hot signer with a generated mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    pub fn new_bip32_signer(&mut self, network: bitcoin::Network) -> SignerId {
        let mnemomic = bip39::Mnemonic::generate(12).unwrap();
        self.new_bip32_signer_from_mnemonic(network, mnemomic.to_string())
    }

    /// Creates a new hot signer from a given mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    /// - `mnemonic`: The mnemonic used to create the hot signer.
    pub fn new_bip32_signer_from_mnemonic(
        &mut self,
        network: bitcoin::Network,
        mnemonic: String,
    ) -> SignerId {
        let signer = HotSigner::new_from_mnemonics(network, &mnemonic).unwrap();
        self.add_bip32_signer(signer)
    }

    pub fn register_bip32_descriptor(&mut self, descriptor: Descriptor) {
        for signer in self.bip32_signers.values_mut() {
            signer.inner_register_descriptor(descriptor.clone());
        }
        // Re-snapshot so the new descriptor set survives a restart.
        let snapshots: Vec<(bip32::Fingerprint, JsonSigner)> = self
            .bip32_signers
            .values()
            .filter_map(|s| s.to_json().map(|j| (s.fingerprint(), j)))
            .collect();
        for (fg, json) in snapshots {
            if let Err(e) = self.store.insert(fg, json) {
                log::error!("HotManager::register_bip32_descriptor insert: {e}");
            }
        }
    }

    /// Signs `psbt` with every loaded hot signer, in place.
    pub fn sign_with_all_hot_signers(&self, psbt: &mut bitcoin::Psbt) {
        for signer in self.bip32_signers.values() {
            signer.sign(psbt);
        }
    }

    /// Returns master xprivs from all BIP32 hot signers, keyed by fingerprint.
    pub fn master_xprivs(&self) -> BTreeMap<bip32::Fingerprint, bip32::Xpriv> {
        self.bip32_signers
            .values()
            .map(|signer| (signer.fingerprint(), signer.master_xpriv()))
            .collect()
    }

    fn require_subscriber(&self) -> Result<channel::Sender<Response>, manager::Error> {
        self.subscriber.clone().ok_or(manager::Error::NoSubscriber)
    }

    fn remember_request(&self, fingerprint: bip32::Fingerprint, request: RequestId) {
        self.last_request
            .lock()
            .expect("poisoned")
            .insert(fingerprint, request);
    }

    fn signer_id_for_fingerprint(&self, fingerprint: bip32::Fingerprint) -> Option<SignerId> {
        if let Some((id, _)) = self
            .bip32_signers
            .iter()
            .find(|(_, hot)| hot.fingerprint() == fingerprint)
        {
            return Some(id.clone());
        }
        self.signers
            .iter()
            .find(|(_, ext)| ext.fingerprint == fingerprint)
            .map(|(id, _)| id.clone())
    }

    /// Drains any pending [`SignerNotif`] and forwards it to the subscribed
    /// channel. Hot-signer calls already answer inline before returning;
    /// this exists for external signers, which report from their own thread
    /// and whose result is only recoverable this way.
    pub fn pump(&self) {
        let Some(sender) = self.subscriber.as_ref() else {
            return;
        };
        while let Some(notif) = self.poll() {
            let Some(fingerprint) = notif_fingerprint(&notif) else {
                continue;
            };
            let Some(id) = self.signer_id_for_fingerprint(fingerprint) else {
                continue;
            };
            let request = self
                .last_request
                .lock()
                .expect("poisoned")
                .remove(&fingerprint);
            let Some(request) = request else {
                continue;
            };
            let _ = sender.send(protocol::from_signer_notif(notif, request, id));
        }
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn start_hw_service(&mut self, network: bitcoin::Network) {
        let (hw_sender, hw_receiver) = channel::unbounded();
        let service = bwk_hwi::service::HwiService::new(network);
        service.start(hw_sender);
        self.hw_service = Some(service);
        self.hw_receiver = Some(hw_receiver);
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn stop_hw_service(&mut self) {
        if let Some(service) = self.hw_service.as_ref() {
            service.stop();
        }
        self.hw_service = None;
        self.hw_receiver = None;
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn hw_devices(
        &self,
    ) -> BTreeMap<String, bwk_hwi::service::SigningDevice<crate::hwi::HwMessage>> {
        if let Some(ref service) = self.hw_service {
            service.list()
        } else {
            BTreeMap::new()
        }
    }

    /// Adopts a discovered hardware device as an external signer, minting a
    /// [`SignerId`] from the device's own stable id.
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn add_hw_signer(&mut self, device_id: &str) -> Option<SignerId> {
        let service = self.hw_service.as_ref()?;
        let devices = service.list();
        let device = devices.get(device_id)?;
        if let bwk_hwi::service::SigningDevice::Supported(supported) = device {
            let fingerprint = *supported.fingerprint();
            let mut signer = crate::hwi::HwSigner::new(supported.clone(), device_id.to_string());
            signer.init(self.sender.clone());
            let id = SignerId::new(format!("hwi:{device_id}"));
            let ext = ExternalSigner {
                signer: Box::new(signer),
                fingerprint,
                descriptors: BTreeSet::new(),
            };
            self.signers.insert(id.clone(), ext);
            Some(id)
        } else {
            None
        }
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn remove_hw_signer(&mut self, signer: &SignerId) {
        self.signers.remove(signer);
    }

    /// Register a descriptor for a hardware signer identified by its
    /// [`SignerId`].
    ///
    /// This stores the descriptor in the ExternalSigner for use during signing,
    /// and delegates to the underlying signer (which calls device.register_wallet()).
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn register_hw_descriptor(&mut self, signer: &SignerId, descriptor: Descriptor) {
        if let Some(ext) = self.signers.get_mut(signer) {
            ext.descriptors.insert(descriptor.clone());
            ext.signer.register_descriptor(descriptor);
        }
    }
}

impl<S> manager::SigningManager for HotManager<S>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner> + Send + Sync,
{
    fn signers(&self) -> Vec<SignerInfo> {
        let mut result: Vec<SignerInfo> = self
            .bip32_signers
            .iter()
            .map(|(id, hot)| {
                let wallet_name = hot
                    .descriptors()
                    .first()
                    .map(|d| bwk_utils::short_string(d.to_string(), 18))
                    .unwrap_or_else(|| hot.fingerprint().to_string());
                SignerInfo::new(
                    id.clone(),
                    hot.fingerprint(),
                    wallet_name,
                    SignerState::Ready,
                )
            })
            .collect();
        result.extend(self.signers.iter().map(|(id, ext)| {
            let wallet_name = ext
                .descriptors
                .iter()
                .next()
                .map(|d| bwk_utils::short_string(d.to_string(), 18))
                .unwrap_or_else(|| ext.fingerprint.to_string());
            SignerInfo::new(id.clone(), ext.fingerprint, wallet_name, SignerState::Ready)
        }));
        result.sort();
        result
    }

    fn subscribe(&mut self, sender: channel::Sender<Response>) {
        let list = self.signers();
        let _ = sender.send(Response::SignersChanged { signers: list });
        self.subscriber = Some(sender);
    }

    fn set_polling(&mut self, _enabled: bool) {
        // The hot manager has no device discovery, so there is nothing to
        // turn on or off.
    }

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        let exists = self.bip32_signers.contains_key(signer) || self.signers.contains_key(signer);
        if !exists {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        }
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        let _ = sender.send(Response::Initialized {
            request,
            signer: signer.clone(),
        });
        Ok(request)
    }

    fn info(&self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        if let Some(hot) = self.bip32_signers.get(signer) {
            let sender = self.require_subscriber()?;
            let request = self.requests.next();
            // Hot signers answer inline; there is no IO to wait on, so the
            // response is built straight from `hot` rather than by pushing a
            // notif and popping it back off the shared SignerNotif channel,
            // which other signers also write to and which never fully
            // drains (see HotSigner::init's own Info notif).
            let _ = sender.send(Response::Info {
                request,
                signer: signer.clone(),
                info: protocol::info_map(hot.info_value()),
            });
            return Ok(request);
        }
        if let Some(ext) = self.signers.get(signer) {
            self.require_subscriber()?;
            let request = self.requests.next();
            self.remember_request(ext.fingerprint, request);
            ext.signer.info();
            return Ok(request);
        }
        Err(manager::Error::UnknownSigner(signer.clone()))
    }

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: DerivationPath,
        display: bool,
    ) -> Result<RequestId, manager::Error> {
        if let Some(hot) = self.bip32_signers.get(signer) {
            let sender = self.require_subscriber()?;
            let request = self.requests.next();
            // Hot signers have no display step and no IO, so the xpub is
            // read straight off `hot` instead of round-tripping through the
            // shared SignerNotif channel (see the comment in `info` above).
            let _ = sender.send(Response::Xpub {
                request,
                signer: signer.clone(),
                xpub: hot.xpub(&path),
            });
            return Ok(request);
        }
        if let Some(ext) = self.signers.get(signer) {
            self.require_subscriber()?;
            let request = self.requests.next();
            self.remember_request(ext.fingerprint, request);
            ext.signer.get_xpub(path, display);
            return Ok(request);
        }
        Err(manager::Error::UnknownSigner(signer.clone()))
    }

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        if let Some(hot) = self.bip32_signers.get(signer) {
            let sender = self.require_subscriber()?;
            let request = self.requests.next();
            let registered = hot.descriptors().contains(&descriptor);
            let _ = sender.send(Response::DescriptorIsRegistered {
                request,
                signer: signer.clone(),
                registered,
            });
            return Ok(request);
        }
        if let Some(ext) = self.signers.get(signer) {
            let sender = self.require_subscriber()?;
            let request = self.requests.next();
            let registered = ext.descriptors.contains(&descriptor);
            let _ = sender.send(Response::DescriptorIsRegistered {
                request,
                signer: signer.clone(),
                registered,
            });
            return Ok(request);
        }
        Err(manager::Error::UnknownSigner(signer.clone()))
    }

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        if self.bip32_signers.contains_key(signer) {
            let sender = self.require_subscriber()?;
            let request = self.requests.next();
            let hot = self.bip32_signers.get_mut(signer).expect("checked above");
            hot.inner_register_descriptor(descriptor);
            if let Some(json) = hot.to_json() {
                let fingerprint = hot.fingerprint();
                if let Err(e) = self.store.insert(fingerprint, json) {
                    log::error!("HotManager::register_descriptor insert: {e}");
                }
            }
            let _ = sender.send(Response::DescriptorRegistered {
                request,
                signer: signer.clone(),
                registered: true,
            });
            return Ok(request);
        }
        if self.signers.contains_key(signer) {
            self.require_subscriber()?;
            let request = self.requests.next();
            let fingerprint = self.signers.get(signer).expect("checked above").fingerprint;
            self.remember_request(fingerprint, request);
            let ext = self.signers.get_mut(signer).expect("checked above");
            ext.descriptors.insert(descriptor.clone());
            ext.signer.register_descriptor(descriptor);
            return Ok(request);
        }
        Err(manager::Error::UnknownSigner(signer.clone()))
    }

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, manager::Error> {
        if let Some(hot) = self.bip32_signers.get(signer) {
            let sender = self.require_subscriber()?;
            let parsed = ParsedPsbt::parse(&psbt)?;
            let request = self.requests.next();
            match descriptor.as_miniscript() {
                Some(inner) => match parsed.sign(hot, inner) {
                    Ok(signed) => {
                        let _ = sender.send(Response::Signed {
                            request,
                            signer: signer.clone(),
                            psbt: signed,
                        });
                    }
                    Err(e) => {
                        let _ =
                            sender.send(Response::error(request, signer.clone(), e.to_string()));
                    }
                },
                None => {
                    let _ = sender.send(Response::error(
                        request,
                        signer.clone(),
                        "silent payment descriptors are not signable yet",
                    ));
                }
            }
            return Ok(request);
        }
        if let Some(ext) = self.signers.get(signer) {
            self.require_subscriber()?;
            let parsed = bitcoin::Psbt::deserialize(&psbt).map_err(|_| manager::Error::Psbt)?;
            let request = self.requests.next();
            self.remember_request(ext.fingerprint, request);
            ext.signer.sign_with_descriptor(parsed, descriptor);
            return Ok(request);
        }
        Err(manager::Error::UnknownSigner(signer.clone()))
    }

    fn raw(&self, signer: &SignerId, _request: Vec<u8>) -> Result<RequestId, manager::Error> {
        if self.bip32_signers.contains_key(signer) || self.signers.contains_key(signer) {
            Err(manager::Error::Unsupported(signer.clone()))
        } else {
            Err(manager::Error::UnknownSigner(signer.clone()))
        }
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use bip32::Fingerprint;
    use bwk_descriptor::{derivator::SpkDerivator, descriptor::wpkh, sp_descriptor::SpDescriptor};
    use bwk_utils::test::{random_output, txid};
    use miniscript::bitcoin::{
        absolute::LockTime, secp256k1::Secp256k1, transaction::Version, Amount, ScriptBuf, TxIn,
        TxOut,
    };

    use super::*;
    use crate::{hot_signer::deriv_path, manager::SigningManager};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_manager_bip32_signer() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        if let SignerNotif::Info(fg, _info) = manager.poll().unwrap() {
            assert_eq!(fg, Fingerprint::from_str("73c5da0a").unwrap());
        } else {
            panic!("expect info");
        }
    }

    fn sp_descriptor(fingerprint: &str) -> Descriptor {
        let secp = Secp256k1::new();
        let scan = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x11; 64]).unwrap();
        let spend_xpriv = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x12; 64]).unwrap();
        let spend_xpub = bip32::Xpub::from_priv(&secp, &spend_xpriv);
        let s = format!("sp([{fingerprint}/352h/0h/0h]{scan}/0h,{spend_xpub}/0h)");
        SpDescriptor::from_str(&s).unwrap().into()
    }

    fn base_psbt() -> bitcoin::Psbt {
        let txin = TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        let txout = random_output();
        let tx = bitcoin::Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };
        bitcoin::Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn two_signers_one_fingerprint() {
        let mut manager = HotManager::new();
        let signer_a = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC).unwrap();
        let signer_b = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC).unwrap();
        let id_a = manager.add_bip32_signer(signer_a);
        let id_b = manager.add_bip32_signer(signer_b);
        assert_ne!(id_a, id_b);

        let infos = manager.signers();
        assert_eq!(infos.len(), 2);
        let fingerprints: BTreeSet<_> = infos.iter().map(|i| i.fingerprint).collect();
        assert_eq!(fingerprints.len(), 1);
        let ids: BTreeSet<_> = infos.iter().map(|i| i.id.clone()).collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn signers_are_ready() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        for info in manager.signers() {
            assert_eq!(info.state, SignerState::Ready);
            assert_eq!(info.state_detail, "");
        }
    }

    #[test]
    fn subscribe_pushes_the_signer_list() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        match rx.recv().unwrap() {
            Response::SignersChanged { signers } => assert_eq!(signers, manager.signers()),
            other => panic!("expected SignersChanged, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signer_id_errors() {
        let mut manager = HotManager::new();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let id = SignerId::new("nope");
        assert_eq!(manager.info(&id), Err(manager::Error::UnknownSigner(id)));
    }

    #[test]
    fn no_subscriber_errors() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        assert_eq!(manager.info(&id), Err(manager::Error::NoSubscriber));
    }

    fn sign_wpkh_psbt(serialize: fn(bitcoin::Psbt) -> Vec<u8>) -> Vec<u8> {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let account_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let descriptor: Descriptor = wpkh(hot.xpub(&account_path)).into();

        manager
            .register_descriptor(&id, descriptor.clone())
            .unwrap();
        let _ = rx.recv().unwrap(); // DescriptorRegistered

        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let pubkey = hot.public_key_at(&deriv_p);
        let fingerprint = hot.fingerprint();
        let derivator = SpkDerivator::new(
            descriptor.as_miniscript().unwrap().clone(),
            bitcoin::Network::Regtest,
        )
        .unwrap();

        let mut psbt = base_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, (fingerprint, deriv_p));

        let request = manager.sign(&id, descriptor, serialize(psbt)).unwrap();
        match rx.recv().unwrap() {
            Response::Signed {
                request: req,
                signer,
                psbt,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, id);
                psbt
            }
            other => panic!("expected Signed, got {other:?}"),
        }
    }

    #[test]
    fn sign_produces_a_signed_psbt() {
        let signed = sign_wpkh_psbt(|psbt| psbt.serialize());
        let signed = bitcoin::Psbt::deserialize(&signed).unwrap();
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn sign_produces_a_signed_psbt_v2() {
        let signed = sign_wpkh_psbt(|psbt| {
            bwk_psbt::PsbtV2::from_bitcoin_psbt(psbt)
                .unwrap()
                .serialize()
                .unwrap()
        });
        let signed = bwk_psbt::PsbtV2::deserialize(&signed).unwrap();
        assert!(!signed.inputs[0].psbt.partial_sigs.is_empty());
    }

    #[test]
    fn sign_rejects_a_bad_psbt() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let deriv_p = deriv_path(&(false, 0)).unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let descriptor: Descriptor = wpkh(hot.xpub(&deriv_p)).into();

        assert_eq!(
            manager.sign(&id, descriptor, vec![0xff; 8]),
            Err(manager::Error::Psbt)
        );
    }

    #[test]
    fn sign_with_sp_descriptor_reports_an_error() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let fingerprint = manager.bip32_signers.get(&id).unwrap().fingerprint();
        let descriptor = sp_descriptor(&fingerprint.to_string());
        let psbt = base_psbt();

        let request = manager.sign(&id, descriptor, psbt.serialize()).unwrap();
        match rx.recv().unwrap() {
            Response::Error {
                request: req,
                signer,
                ..
            } => {
                assert_eq!(req, Some(request));
                assert_eq!(signer, Some(id));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_xpub_does_not_cross_contaminate_between_hot_signers() {
        const OTHER_MNEMONIC: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let mut manager = HotManager::new();
        let mnemonic_a =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let mnemonic_b = manager
            .new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, OTHER_MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
        let hot_a = manager.bip32_signers.get(&mnemonic_a).unwrap();
        let expected_a = hot_a.xpub(&path);
        let hot_b = manager.bip32_signers.get(&mnemonic_b).unwrap();
        let expected_b = hot_b.xpub(&path);
        assert_ne!(expected_a, expected_b);

        // Two prior queries against signer A (mirroring one hot signer's
        // own init() notif plus one info() call) used to leave the shared
        // SignerNotif channel with a backlog that a later, unrelated call
        // could pop instead of its own answer.
        manager.info(&mnemonic_a).unwrap();
        let _ = rx.recv().unwrap();
        manager.get_xpub(&mnemonic_a, path.clone(), false).unwrap();
        let _ = rx.recv().unwrap();

        let request = manager.get_xpub(&mnemonic_b, path, false).unwrap();
        match rx.recv().unwrap() {
            Response::Xpub {
                request: req,
                signer,
                xpub,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, mnemonic_b);
                assert_eq!(xpub, expected_b);
            }
            other => panic!("expected Xpub, got {other:?}"),
        }
    }

    #[test]
    fn raw_is_unsupported() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        assert_eq!(
            manager.raw(&id, vec![]),
            Err(manager::Error::Unsupported(id))
        );
    }
}
