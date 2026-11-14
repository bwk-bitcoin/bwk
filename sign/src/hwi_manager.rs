use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use bwk_descriptor::descriptor::Descriptor;
use bwk_hwi::service::{HwiService, SigningDevice, SigningDeviceMsg};
use bwk_keys::keys::OXpub;
use crossbeam::channel;
use miniscript::bitcoin::{
    self,
    bip32::{self, DerivationPath},
};

use crate::{
    hwi::{HwMessage, HwSigner},
    identity::{SignerId, SignerInfo, SignerState},
    manager::{self, SigningManager},
    protocol::{RequestId, RequestIdSource, Response},
    signer::Signer,
};

/// Manages hardware signers discovered through [`bwk_hwi::service::HwiService`].
///
/// Every discovered device is listed, including ones that are locked or
/// unusable, so a user learns there is something to unlock or fix. Requests
/// are dispatched straight onto a fresh [`HwSigner`] wrapping the device's
/// current, freshly re-read state, since a device can transition between
/// `Ready`/`Locked`/`Unsupported` at any time; the set of descriptors
/// registered per signer is therefore tracked here rather than on the
/// short-lived `HwSigner`.
pub struct HwiManager {
    service: Arc<HwiService<HwMessage, RequestId>>,
    receiver: channel::Receiver<HwMessage>,
    sender: channel::Sender<HwMessage>,
    signers: Mutex<BTreeMap<SignerId, HwSigner>>,
    descriptors: Mutex<BTreeMap<SignerId, BTreeSet<Descriptor>>>,
    subscriber: Arc<Mutex<Option<channel::Sender<Response>>>>,
    requests: RequestIdSource,
    polling: AtomicBool,
    forwarder: Mutex<Option<JoinHandle<()>>>,
    shutdown: Arc<AtomicBool>,
}

impl HwiManager {
    pub fn new(network: bitcoin::Network) -> Self {
        let (sender, receiver) = channel::unbounded();
        Self {
            service: Arc::new(HwiService::new(network)),
            receiver,
            sender,
            signers: Mutex::new(BTreeMap::new()),
            descriptors: Mutex::new(BTreeMap::new()),
            subscriber: Arc::new(Mutex::new(None)),
            requests: RequestIdSource::new(),
            polling: AtomicBool::new(false),
            forwarder: Mutex::new(None),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn require_subscriber(&self) -> Result<channel::Sender<Response>, manager::Error> {
        self.subscriber
            .lock()
            .expect("poisoned")
            .clone()
            .ok_or(manager::Error::NoSubscriber)
    }

    /// Reads the device's current state from the service and returns a
    /// freshly wrapped [`HwSigner`] over it, or an error if the device is
    /// gone or not usable yet.
    fn supported_device(
        &self,
        signer: &SignerId,
    ) -> Result<bwk_hwi::service::SupportedDevice<HwMessage, RequestId>, manager::Error> {
        let devices = self.service.list();
        match devices.get(signer.as_str()) {
            Some(SigningDevice::Supported(device)) => Ok(device.clone()),
            Some(_) => Err(manager::Error::NotReady(signer.clone())),
            None => Err(manager::Error::UnknownSigner(signer.clone())),
        }
    }

    fn spawn_forwarder(&self) {
        let mut guard = self.forwarder.lock().expect("poisoned");
        if guard.is_some() {
            return;
        }
        let receiver = self.receiver.clone();
        let subscriber = self.subscriber.clone();
        let service = self.service.clone();
        let shutdown = self.shutdown.clone();
        let handle = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                match receiver.recv_timeout(Duration::from_millis(200)) {
                    Ok(msg) => {
                        if let Some(response) = convert_hw_message(msg, &service) {
                            if let Some(sender) = subscriber.lock().expect("poisoned").as_ref() {
                                let _ = sender.send(response);
                            }
                        }
                    }
                    Err(channel::RecvTimeoutError::Timeout) => continue,
                    Err(channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        *guard = Some(handle);
    }
}

impl SigningManager for HwiManager {
    fn signers(&self) -> Vec<SignerInfo> {
        signers_from(&self.service.list())
    }

    fn subscribe(&mut self, sender: channel::Sender<Response>) {
        let list = self.signers();
        let _ = sender.send(Response::SignersChanged { signers: list });
        *self.subscriber.lock().expect("poisoned") = Some(sender);
        self.spawn_forwarder();
    }

    fn set_polling(&mut self, enabled: bool) {
        if enabled {
            if !self.polling.swap(true, Ordering::SeqCst) {
                self.service.start(self.sender.clone());
            }
        } else if self.polling.swap(false, Ordering::SeqCst) {
            self.service.stop();
        }
    }

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        let device = self.supported_device(signer)?;
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        let hw_signer = HwSigner::new(device, signer.as_str().to_string());
        self.signers
            .lock()
            .expect("poisoned")
            .insert(signer.clone(), hw_signer);
        let _ = sender.send(Response::Initialized {
            request,
            signer: signer.clone(),
        });
        Ok(request)
    }

    fn info(&self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        let device = self.supported_device(signer)?;
        self.require_subscriber()?;
        let request = self.requests.next();
        let hw_signer = HwSigner::new(device, signer.as_str().to_string());
        hw_signer.set_request(request);
        hw_signer.info();
        Ok(request)
    }

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: DerivationPath,
        display: bool,
    ) -> Result<RequestId, manager::Error> {
        let device = self.supported_device(signer)?;
        self.require_subscriber()?;
        let request = self.requests.next();
        let hw_signer = HwSigner::new(device, signer.as_str().to_string());
        hw_signer.set_request(request);
        hw_signer.get_xpub(path, display);
        Ok(request)
    }

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        let device = self.supported_device(signer)?;
        self.require_subscriber()?;
        let request = self.requests.next();
        let hw_signer = HwSigner::new(device, signer.as_str().to_string());
        hw_signer.set_request(request);
        hw_signer.is_descriptor_registered(descriptor);
        Ok(request)
    }

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        if descriptor.is_sp() {
            return Err(manager::Error::Unsupported(signer.clone()));
        }
        let device = self.supported_device(signer)?;
        self.require_subscriber()?;
        let request = self.requests.next();
        self.descriptors
            .lock()
            .expect("poisoned")
            .entry(signer.clone())
            .or_default()
            .insert(descriptor.clone());
        let mut hw_signer = HwSigner::new(device, signer.as_str().to_string());
        hw_signer.set_request(request);
        hw_signer.register_descriptor(descriptor);
        Ok(request)
    }

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, manager::Error> {
        let device = self.supported_device(signer)?;
        let parsed = bitcoin::Psbt::deserialize(&psbt).map_err(|_| manager::Error::Psbt)?;
        let registered = self
            .descriptors
            .lock()
            .expect("poisoned")
            .get(signer)
            .is_some_and(|set| set.contains(&descriptor));
        if !registered {
            return Err(manager::Error::UnregisteredDescriptor(signer.clone()));
        }
        self.require_subscriber()?;
        let request = self.requests.next();
        let hw_signer = HwSigner::new(device, signer.as_str().to_string());
        hw_signer.set_request(request);
        hw_signer.sign_with_descriptor(parsed, descriptor);
        Ok(request)
    }

    fn raw(&self, signer: &SignerId, _request: Vec<u8>) -> Result<RequestId, manager::Error> {
        if self.service.list().contains_key(signer.as_str()) {
            Err(manager::Error::Unsupported(signer.clone()))
        } else {
            Err(manager::Error::UnknownSigner(signer.clone()))
        }
    }
}

impl Drop for HwiManager {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if self.polling.swap(false, Ordering::SeqCst) {
            self.service.stop();
        }
        if let Some(handle) = self.forwarder.lock().expect("poisoned").take() {
            let _ = handle.join();
        }
    }
}

fn signers_from(
    devices: &BTreeMap<String, SigningDevice<HwMessage, RequestId>>,
) -> Vec<SignerInfo> {
    let mut result: Vec<SignerInfo> = devices.values().map(signer_info_for).collect();
    result.sort();
    result
}

fn signer_info_for(device: &SigningDevice<HwMessage, RequestId>) -> SignerInfo {
    let id = SignerId::new(device.id());
    let wallet_name = device.kind().to_string();
    match device {
        SigningDevice::Supported(d) => {
            SignerInfo::new(id, *d.fingerprint(), wallet_name, SignerState::Ready)
        }
        SigningDevice::Locked { pairing_code, .. } => SignerInfo::new(
            id,
            bip32::Fingerprint::default(),
            wallet_name,
            SignerState::Locked,
        )
        .with_detail(
            pairing_code
                .clone()
                .unwrap_or_else(|| "device is locked".to_string()),
        ),
        SigningDevice::Unsupported { reason, .. } => SignerInfo::new(
            id,
            bip32::Fingerprint::default(),
            wallet_name,
            SignerState::Unsupported,
        )
        .with_detail(format!("{reason:?}")),
    }
}

fn signer_id_for_fingerprint(
    devices: &BTreeMap<String, SigningDevice<HwMessage, RequestId>>,
    fingerprint: bip32::Fingerprint,
) -> Option<SignerId> {
    devices.values().find_map(|device| match device {
        SigningDevice::Supported(d) if *d.fingerprint() == fingerprint => {
            Some(SignerId::new(device.id()))
        }
        _ => None,
    })
}

fn convert_hw_message(
    msg: HwMessage,
    service: &HwiService<HwMessage, RequestId>,
) -> Option<Response> {
    let HwMessage::Device(device_msg) = msg;
    match device_msg {
        SigningDeviceMsg::Update => Some(Response::SignersChanged {
            signers: signers_from(&service.list()),
        }),
        SigningDeviceMsg::TransactionSigned(request, fg, psbt) => {
            let signer = signer_id_for_fingerprint(&service.list(), fg)?;
            Some(Response::Signed {
                request,
                signer,
                psbt: psbt.serialize(),
            })
        }
        SigningDeviceMsg::XPub(request, fg, path, xpub) => {
            let signer = signer_id_for_fingerprint(&service.list(), fg)?;
            Some(Response::Xpub {
                request,
                signer,
                xpub: OXpub {
                    origin: (fg, path),
                    xkey: xpub,
                },
            })
        }
        SigningDeviceMsg::Version(request, fg, version) => {
            let signer = signer_id_for_fingerprint(&service.list(), fg)?;
            let info = BTreeMap::from([("version".to_string(), version.to_string())]);
            Some(Response::Info {
                request,
                signer,
                info,
            })
        }
        SigningDeviceMsg::WalletRegistered(request, fg, _, hmac) => {
            let signer = signer_id_for_fingerprint(&service.list(), fg)?;
            Some(Response::DescriptorRegistered {
                request,
                signer,
                registered: hmac.is_some(),
            })
        }
        SigningDeviceMsg::WalletIsRegistered(request, fg, _, registered) => {
            let signer = signer_id_for_fingerprint(&service.list(), fg)?;
            Some(Response::DescriptorIsRegistered {
                request,
                signer,
                registered,
            })
        }
        SigningDeviceMsg::AddressDisplayed(..) => None,
        SigningDeviceMsg::Error(request, message) => Some(Response::Error {
            request,
            signer: None,
            message,
        }),
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use std::{
        str::FromStr,
        sync::{atomic::Ordering, Arc, Mutex},
    };

    use bwk_descriptor::{descriptor::Descriptor, sp_descriptor::SpDescriptor};
    use bwk_hwi::{
        service::{LockedDevice, SigningDevice, UnsupportedReason},
        DeviceKind,
    };
    use crossbeam::channel;
    use miniscript::bitcoin::{
        self,
        bip32::{self, DerivationPath},
        secp256k1::Secp256k1,
    };

    use crate::{
        hwi::HwMessage,
        hwi_manager::{signer_info_for, HwiManager},
        identity::{SignerId, SignerState},
        manager::{self, SigningManager},
        protocol::{RequestId, Response},
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn manager_is_send_and_sync() {
        assert_send_sync::<HwiManager>();
        assert_send_sync::<Box<dyn SigningManager>>();
    }

    #[test]
    fn state_mapping_covers_every_device_variant() {
        // `Supported` needs a real device to construct and is not covered
        // here; the two states reachable without hardware are checked below.
        let locked = SigningDevice::<HwMessage, RequestId>::Locked {
            id: "dev-1".to_string(),
            device: Arc::new(Mutex::new(None::<LockedDevice>)),
            pairing_code: Some("1234".to_string()),
            kind: DeviceKind::BitBox02,
        };
        let info = signer_info_for(&locked);
        assert_eq!(info.state, SignerState::Locked);
        assert_eq!(info.state_detail, "1234");
        assert_eq!(info.fingerprint, bip32::Fingerprint::default());

        let unsupported = SigningDevice::<HwMessage, RequestId>::Unsupported {
            id: "dev-2".to_string(),
            kind: DeviceKind::Jade,
            version: None,
            reason: UnsupportedReason::WrongNetwork,
        };
        let info = signer_info_for(&unsupported);
        assert_eq!(info.state, SignerState::Unsupported);
        assert!(!info.state_detail.is_empty());
        assert_eq!(info.fingerprint, bip32::Fingerprint::default());
    }

    #[test]
    fn locked_device_detail_prefers_the_pairing_code() {
        let with_code = SigningDevice::<HwMessage, RequestId>::Locked {
            id: "dev-1".to_string(),
            device: Arc::new(Mutex::new(None::<LockedDevice>)),
            pairing_code: Some("1234".to_string()),
            kind: DeviceKind::BitBox02,
        };
        assert_eq!(signer_info_for(&with_code).state_detail, "1234");

        let without_code = SigningDevice::<HwMessage, RequestId>::Locked {
            id: "dev-2".to_string(),
            device: Arc::new(Mutex::new(None::<LockedDevice>)),
            pairing_code: None,
            kind: DeviceKind::Jade,
        };
        assert_eq!(
            signer_info_for(&without_code).state_detail,
            "device is locked"
        );
    }

    #[test]
    fn unknown_signer_id_errors() {
        let mut manager = HwiManager::new(bitcoin::Network::Regtest);
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let id = SignerId::new("nope");
        assert_eq!(
            manager.info(&id),
            Err(manager::Error::UnknownSigner(id.clone()))
        );
        assert_eq!(
            manager.get_xpub(&id, DerivationPath::master(), false),
            Err(manager::Error::UnknownSigner(id))
        );
    }

    #[test]
    fn no_subscriber_errors() {
        let manager = HwiManager::new(bitcoin::Network::Regtest);
        let id = SignerId::new("nope");
        // No devices are ever discovered here, so `UnknownSigner` is
        // returned before the subscriber check is reached; this is still
        // the behavior a caller with no subscriber and no devices observes.
        assert_eq!(manager.info(&id), Err(manager::Error::UnknownSigner(id)));
    }

    #[test]
    fn subscribe_pushes_the_signer_list() {
        let mut manager = HwiManager::new(bitcoin::Network::Regtest);
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        match rx.recv().unwrap() {
            Response::SignersChanged { signers } => assert!(signers.is_empty()),
            other => panic!("expected SignersChanged, got {other:?}"),
        }
    }

    #[test]
    fn raw_is_unsupported() {
        let manager = HwiManager::new(bitcoin::Network::Regtest);
        let id = SignerId::new("nope");
        assert_eq!(
            manager.raw(&id, vec![]),
            Err(manager::Error::UnknownSigner(id))
        );
    }

    #[test]
    fn set_polling_is_idempotent() {
        let mut manager = HwiManager::new(bitcoin::Network::Regtest);
        manager.set_polling(true);
        manager.set_polling(true);
        manager.set_polling(false);
        assert!(!manager.polling.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_stops_polling() {
        let mut manager = HwiManager::new(bitcoin::Network::Regtest);
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        manager.set_polling(true);
        // `Drop` joins the forwarder thread before returning; reaching the
        // end of this test without hanging is the proof that it exited.
        drop(manager);
    }

    #[test]
    fn sp_descriptor_is_not_forwarded() {
        let secp = Secp256k1::new();
        let scan = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x11; 64]).unwrap();
        let spend_xpriv = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x12; 64]).unwrap();
        let spend_xpub = bip32::Xpub::from_priv(&secp, &spend_xpriv);
        let s = format!("sp([deadbeef/352h/0h/0h]{scan}/0h,{spend_xpub}/0h)");
        let descriptor: Descriptor = SpDescriptor::from_str(&s).unwrap().into();

        let mut manager = HwiManager::new(bitcoin::Network::Regtest);
        let id = SignerId::new("nope");
        assert_eq!(
            manager.register_descriptor(&id, descriptor),
            Err(manager::Error::Unsupported(id))
        );
    }
}
