use std::collections::BTreeSet;

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
    send,
    signer::{Signer, SignerNotif},
};

#[derive(Debug, Clone)]
pub enum HwMessage {
    Device(SigningDeviceMsg),
}

impl From<SigningDeviceMsg> for HwMessage {
    fn from(msg: SigningDeviceMsg) -> Self {
        HwMessage::Device(msg)
    }
}

pub struct HwSigner {
    device: SupportedDevice<HwMessage>,
    id: String,
    sender: Option<channel::Sender<SignerNotif>>,
    pub descriptors: BTreeSet<Descriptor>,
}

impl HwSigner {
    pub fn new(device: SupportedDevice<HwMessage>, id: String) -> Self {
        Self {
            device,
            id,
            sender: None,
            descriptors: BTreeSet::new(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn fingerprint(&self) -> bip32::Fingerprint {
        *self.device.fingerprint()
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
        self.device.get_extended_pubkey((), &deriv);
    }

    fn is_descriptor_registered(&self, descriptor: Descriptor) {
        if descriptor.is_sp() {
            send!(self, Error(Error::SpDescriptor));
            return;
        }
        let policy = descriptor.to_string();
        let name = Self::wallet_name(&descriptor);
        self.device.is_wallet_registered((), &name, &policy);
    }

    fn register_descriptor(&mut self, descriptor: Descriptor) {
        if descriptor.is_sp() {
            send!(self, Error(Error::SpDescriptor));
            return;
        }
        self.descriptors.insert(descriptor.clone());
        let policy = descriptor.to_string();
        let name = Self::wallet_name(&descriptor);
        self.device.register_wallet((), &name, &policy);
    }

    fn sign_with_descriptor(&self, psbt: Psbt, _descriptor: Descriptor) {
        self.device.sign_tx((), psbt);
    }
}
