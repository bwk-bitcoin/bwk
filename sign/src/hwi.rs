use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicU64, Ordering},
};

use bwk_descriptor::descriptor::Descriptor;
use bwk_hwi::service::{SigningDeviceMsg, SupportedDevice};
use crossbeam::channel;
use miniscript::bitcoin::{
    bip32::{self, DerivationPath},
    hashes::{sha256, Hash},
    Psbt,
};

use crate::{
    error::Error,
    protocol::RequestId,
    send,
    signer::{Signer, SignerNotif},
};

#[derive(Debug, Clone)]
pub enum HwMessage {
    Device(SigningDeviceMsg<RequestId>),
}

impl From<SigningDeviceMsg<RequestId>> for HwMessage {
    fn from(msg: SigningDeviceMsg<RequestId>) -> Self {
        HwMessage::Device(msg)
    }
}

pub struct HwSigner {
    device: SupportedDevice<HwMessage, RequestId>,
    id: String,
    sender: Option<channel::Sender<SignerNotif>>,
    /// The [`Signer`] trait predates the [`RequestId`]-carrying protocol and
    /// its methods take no request id, so the id to use for the next
    /// dispatch is stashed here right before the call.
    request: AtomicU64,
    pub descriptors: BTreeSet<Descriptor>,
}

impl HwSigner {
    pub fn new(device: SupportedDevice<HwMessage, RequestId>, id: String) -> Self {
        Self {
            device,
            id,
            sender: None,
            request: AtomicU64::new(0),
            descriptors: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn fingerprint(&self) -> bip32::Fingerprint {
        *self.device.fingerprint()
    }

    pub fn set_request(&self, request: RequestId) {
        self.request.store(request.as_u64(), Ordering::SeqCst);
    }

    fn request(&self) -> RequestId {
        RequestId::new(self.request.load(Ordering::SeqCst))
    }

    fn wallet_name(descriptor: &Descriptor) -> String {
        let policy = descriptor.to_string();
        let hash = sha256::Hash::hash(policy.as_bytes());
        let bytes = hash.as_byte_array();
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

impl Signer for HwSigner {
    fn init(&mut self, channel: channel::Sender<SignerNotif>) {
        self.sender = Some(channel);
        self.info();
    }

    fn info(&self) {
        let payload = serde_json::json!({
            "kind": self.device.kind().to_string(),
            "fingerprint": self.device.fingerprint().to_string(),
        });
        send!(self, Info(payload));
    }

    fn get_xpub(&self, deriv: DerivationPath, _display: bool) {
        self.device.get_extended_pubkey(self.request(), &deriv);
    }

    fn is_descriptor_registered(&self, descriptor: Descriptor) {
        if descriptor.is_sp() {
            send!(self, Error(Error::SpDescriptor));
            return;
        }
        let policy = descriptor.to_string();
        let name = Self::wallet_name(&descriptor);
        self.device
            .is_wallet_registered(self.request(), &name, &policy);
    }

    fn register_descriptor(&mut self, descriptor: Descriptor) {
        if descriptor.is_sp() {
            send!(self, Error(Error::SpDescriptor));
            return;
        }
        self.descriptors.insert(descriptor.clone());
        let policy = descriptor.to_string();
        let name = Self::wallet_name(&descriptor);
        self.device.register_wallet(self.request(), &name, &policy);
    }

    fn sign_with_descriptor(&self, psbt: Psbt, _descriptor: Descriptor) {
        self.device.sign_tx(self.request(), psbt);
    }
}
