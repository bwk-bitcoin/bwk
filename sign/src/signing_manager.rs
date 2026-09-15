use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

use crossbeam::channel;

use bwk_persist::{
    backend::{noop::NoopBackend, PersistenceBackend},
    storage::{ram::RamStore, Store},
    PersistError,
};

use miniscript::{
    bitcoin::{self, bip32},
    Descriptor, DescriptorPublicKey, ForEachKey,
};

use crate::{
    hot_signer::{HotSigner, JsonSigner},
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
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    kind: SignerKind,
    id: String,
    descriptors: BTreeSet<Descriptor<DescriptorPublicKey>>,
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

/// Default backing store for [`SigningManager`]: RAM-cached + write-back
/// over a runtime-dispatched [`PersistenceBackend`].
pub type DefaultSignerStore = RamStore<Arc<dyn PersistenceBackend>, bip32::Fingerprint, JsonSigner>;

/// A manager for handling hot signers and their notifications.
pub struct SigningManager<S = DefaultSignerStore>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    receiver: channel::Receiver<SignerNotif>,
    sender: channel::Sender<SignerNotif>,
    bip32_signers: BTreeMap<bip32::Fingerprint, HotSigner>,
    signers: BTreeMap<bip32::Fingerprint, ExternalSigner>,
    store: S,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    hw_service: Option<bwk_hwi::service::HwiService<crate::hwi::HwMessage>>,
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    hw_receiver: Option<channel::Receiver<crate::hwi::HwMessage>>,
}

impl<S> std::fmt::Debug for SigningManager<S>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningManager")
            .field("bip32_signers", &self.bip32_signers)
            .field("signers_count", &self.signers.len())
            .finish()
    }
}

impl SigningManager<DefaultSignerStore> {
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
                log::error!("SigningManager::with_backend: {e}");
                let noop: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
                let store =
                    RamStore::empty(noop, store_key, encode_fingerprint, encode_json_signer);
                Self::from_store(store)
            }
        }
    }
}

impl Default for SigningManager<DefaultSignerStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> SigningManager<S>
where
    S: Store<Key = bip32::Fingerprint, Value = JsonSigner>,
{
    /// Wrap a pre-opened signer store. Hydrates `bip32_signers` from
    /// every row already in the store.
    pub fn from_store(store: S) -> Self {
        let (sender, receiver) = channel::unbounded();
        let mut bip32_signers: BTreeMap<bip32::Fingerprint, HotSigner> = BTreeMap::new();
        match store.iter() {
            Ok(iter) => {
                for (fg, json) in iter {
                    let mut signer = HotSigner::from_json(json);
                    signer.init(sender.clone());
                    bip32_signers.insert(fg, signer);
                }
            }
            Err(e) => {
                log::error!("SigningManager::from_store iter: {e}");
            }
        }
        Self {
            receiver,
            sender,
            bip32_signers,
            signers: BTreeMap::new(),
            store,
            #[cfg(all(feature = "hwi", not(target_os = "android")))]
            hw_service: None,
            #[cfg(all(feature = "hwi", not(target_os = "android")))]
            hw_receiver: None,
        }
    }

    /// Persists pending changes through the backend.
    pub fn persist(&mut self) {
        if let Err(e) = self.store.flush() {
            log::error!("SigningManager::persist() flush: {e}");
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

    /// Creates a new hot signer with a generated mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    pub fn new_bip32_signer(&mut self, network: bitcoin::Network) {
        let mnemomic = bip39::Mnemonic::generate(12).unwrap();
        self.new_bip32_signer_from_mnemonic(network, mnemomic.to_string());
    }

    /// Creates a new hot signer from a given mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    /// - `mnemonic`: The mnemonic used to create the hot signer.
    pub fn new_bip32_signer_from_mnemonic(&mut self, network: bitcoin::Network, mnemonic: String) {
        let signer = HotSigner::new_from_mnemonics(network, &mnemonic).unwrap();
        self.add_bip32_signer(signer);
    }

    /// Take over an already-built hot signer, keyed by its fingerprint. One
    /// registered under the same fingerprint is replaced, along with the
    /// descriptors registered on it.
    pub fn add_bip32_signer(&mut self, mut signer: HotSigner) {
        signer.init(self.sender.clone());
        let fg = signer.fingerprint();
        if let Some(json) = signer.to_json() {
            if let Err(e) = self.store.insert(fg, json) {
                log::error!("SigningManager::add_bip32_signer insert: {e}");
            }
        }
        self.bip32_signers.insert(fg, signer);
    }

    /// Whether a hot signer with this fingerprint is already registered.
    pub fn has_bip32_signer(&self, fingerprint: &bip32::Fingerprint) -> bool {
        self.bip32_signers.contains_key(fingerprint)
    }

    pub fn register_bip32_descriptor(&mut self, descriptor: Descriptor<DescriptorPublicKey>) {
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
                log::error!("SigningManager::register_bip32_descriptor insert: {e}");
            }
        }
    }

    pub fn sign(&self, psbt: String) {
        let mut psbt = match bitcoin::Psbt::from_str(&psbt) {
            Ok(p) => p,
            Err(_) => {
                if self
                    .sender
                    .send(SignerNotif::Manager(Error::ParsePsbt))
                    .is_err()
                {
                    log::error!("SigningManager::sign() fails to send notif")
                }
                return;
            }
        };

        self.sign_psbt(&mut psbt);

        let fg = self
            .bip32_signers
            .keys()
            .next()
            .copied()
            .unwrap_or_default();
        if self.sender.send(SignerNotif::Signed(fg, psbt)).is_err() {
            log::error!("SigningManager::sign() fails to send notif")
        }
    }

    pub fn sign_psbt(&self, psbt: &mut bitcoin::Psbt) {
        for signer in self.bip32_signers.values() {
            signer.sign(psbt);
        }
    }

    /// Returns master xprivs from all BIP32 hot signers, keyed by fingerprint.
    pub fn master_xprivs(&self) -> BTreeMap<bip32::Fingerprint, bip32::Xpriv> {
        self.bip32_signers
            .iter()
            .map(|(fg, signer)| (*fg, signer.master_xpriv()))
            .collect()
    }

    pub fn list_signers(&self) -> Vec<(bip32::Fingerprint, SignerKind)> {
        #[cfg_attr(
            not(all(feature = "hwi", not(target_os = "android"))),
            allow(unused_mut)
        )]
        let mut result: Vec<_> = self
            .bip32_signers
            .keys()
            .map(|fg| (*fg, SignerKind::Hot))
            .collect();
        #[cfg(all(feature = "hwi", not(target_os = "android")))]
        for (fg, ext) in &self.signers {
            result.push((*fg, ext.kind.clone()));
        }
        result
    }

    pub fn sign_with(
        &self,
        fingerprint: bip32::Fingerprint,
        id: Option<&str>,
        psbt: &mut bitcoin::Psbt,
    ) {
        // Hot signers: sign in-place synchronously
        if let Some(signer) = self.bip32_signers.get(&fingerprint) {
            signer.sign(psbt);
            return;
        }
        // External signers: fire-and-forget, result via poll()
        if let Some(ext) = self.signers.get(&fingerprint) {
            if let Some(req_id) = id {
                if ext.id != req_id {
                    return;
                }
            }
            // Find first registered descriptor and trigger async signing
            if let Some(descriptor) = psbt_matching_descriptor(psbt, fingerprint, &ext.descriptors)
            {
                ext.signer.sign_with_descriptor(psbt.clone(), descriptor);
            } else {
                log::warn!("sign_with: no matching descriptor found for fingerprint {fingerprint}");
            }
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

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn add_hw_signer(&mut self, device_id: &str) -> Option<bip32::Fingerprint> {
        let service = self.hw_service.as_ref()?;
        let devices = service.list();
        let device = devices.get(device_id)?;
        if let bwk_hwi::service::SigningDevice::Supported(supported) = device {
            let fg = *supported.fingerprint();
            let kind = *supported.kind();
            let mut signer = crate::hwi::HwSigner::new(supported.clone(), device_id.to_string());
            signer.init(self.sender.clone());
            let ext = ExternalSigner {
                signer: Box::new(signer),
                kind: SignerKind::External(kind),
                id: device_id.to_string(),
                descriptors: BTreeSet::new(),
            };
            self.signers.insert(fg, ext);
            Some(fg)
        } else {
            None
        }
    }

    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn remove_hw_signer(&mut self, fingerprint: &bip32::Fingerprint) {
        self.signers.remove(fingerprint);
    }

    /// Register a descriptor for a hardware signer identified by fingerprint.
    ///
    /// This stores the descriptor in the ExternalSigner for use during signing,
    /// and delegates to the underlying signer (which calls device.register_wallet()).
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    pub fn register_hw_descriptor(
        &mut self,
        fingerprint: &bip32::Fingerprint,
        descriptor: Descriptor<DescriptorPublicKey>,
    ) {
        if let Some(ext) = self.signers.get_mut(fingerprint) {
            ext.descriptors.insert(descriptor.clone());
            ext.signer.register_descriptor(descriptor);
        }
    }
}

/// Find a registered descriptor that references the given fingerprint, confirmed by the PSBT.
/// Iterates the signer's registered descriptors and returns the first one whose key origins
/// include the given fingerprint.
#[allow(clippy::mutable_key_type)]
fn psbt_matching_descriptor(
    psbt: &bitcoin::Psbt,
    fingerprint: bip32::Fingerprint,
    descriptors: &BTreeSet<Descriptor<DescriptorPublicKey>>,
) -> Option<Descriptor<DescriptorPublicKey>> {
    // Collect all fingerprints referenced in this PSBT for quick lookup
    let mut psbt_fingerprints = BTreeSet::new();
    for input in &psbt.inputs {
        for (fg, _) in input.bip32_derivation.values() {
            psbt_fingerprints.insert(*fg);
        }
        for (_, (fg, _)) in input.tap_key_origins.values() {
            psbt_fingerprints.insert(*fg);
        }
    }

    if !psbt_fingerprints.contains(&fingerprint) {
        return None;
    }

    // Find the first registered descriptor that references this fingerprint
    for descriptor in descriptors {
        let matches = descriptor.for_any_key(|k| match k {
            DescriptorPublicKey::XPub(key) => key
                .origin
                .as_ref()
                .is_some_and(|(fg, _)| *fg == fingerprint),
            DescriptorPublicKey::MultiXPub(key) => key
                .origin
                .as_ref()
                .is_some_and(|(fg, _)| *fg == fingerprint),
            DescriptorPublicKey::Single(_) => false,
        });
        if matches {
            return Some(descriptor.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use bip32::Fingerprint;

    use super::*;

    #[test]
    fn test_manager_bip32_signer() {
        let mut manager = SigningManager::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, mnemonic);
        if let SignerNotif::Info(fg, _info) = manager.poll().unwrap() {
            assert_eq!(fg, Fingerprint::from_str("73c5da0a").unwrap());
        } else {
            panic!("expect info");
        }
    }
}
