use crossbeam::channel;

use crate::error::Error;
use crate::signing_manager;
use bwk_descriptor::descriptor::Descriptor;
use bwk_keys::keys::OXpub;
use miniscript::{
    bitcoin::{
        bip32::{self, DerivationPath},
        Psbt,
    },
    descriptor::DescriptorMultiXKey,
};

#[derive(Debug)]
pub enum SignerNotif {
    Info(bip32::Fingerprint, serde_json::Value),
    Xpub(bip32::Fingerprint, OXpub),
    Descriptor(bip32::Fingerprint, DescriptorMultiXKey<bip32::Xpub>),
    DescriptorRegistered(bip32::Fingerprint, Descriptor, bool),
    Signed(bip32::Fingerprint, Psbt),
    Error(bip32::Fingerprint, Error),
    Manager(signing_manager::Error),
    #[cfg(all(feature = "hwi", not(target_os = "android")))]
    DeviceUpdate,
}

/// This trait implement features that are available when the signer is connected.
pub trait Signer: Send {
    /// Initialyse the signer with a new channel, in return the signer
    /// must return a [`SignerNotif::Info`] notification to the newly
    /// registered channel.
    fn init(&mut self, channel: channel::Sender<SignerNotif>);
    /// Request general informations from the signer.
    /// The signer must return a [`SignerNotif::Info`] notification.
    fn info(&self);
    /// Request descriptor to generate an Xpub using the given derivation
    /// path. `display` must be set to true for non standard derivation path,
    /// allow some signer to generate non-standard Xpub with user approval.
    /// The signer must return a [`SignerNotif::Xpub`] notification.
    fn get_xpub(&self, deriv: DerivationPath, display: bool);
    /// Request signer if the given descriptor is registered.
    /// The signer must return a [`SignerNotif::DescriptorRegistered`] notification.
    fn is_descriptor_registered(&self, descriptor: Descriptor);
    /// Prompt user to register given descriptor.
    /// The signer must return a [`SignerNotif::DescriptorRegistered`] notification.
    fn register_descriptor(&mut self, descriptor: Descriptor);
    /// Request the signer to sign the given psbt. A descriptor must be loaded
    /// prior to call this function.
    /// The signer must return a [`SignerNotif::Signed`] notification.
    fn sign_with_descriptor(&self, psbt: Psbt, descriptor: Descriptor);
    /// Request the signer to display the address for verification.
    /// No notification is expected in return.
    fn display_address(&self, _deriv: (bool /* is_change */, u32)) {}
}

#[macro_export]
macro_rules! send {
    ($s:ident, $notif:ident($val1:expr)) => {
        if let Some(sender) = &$s.sender {
            if let Err(e) = sender.send(SignerNotif::$notif($s.fingerprint(), $val1)) {
                log::error!("Signer fail to send notification: {e:?}");
            }
        }
    };
    ($s:ident, $notif:ident($val1:expr, $val2:expr)) => {
        if let Some(sender) = &$s.sender {
            if let Err(e) = sender.send(SignerNotif::$notif($s.fingerprint(), $val1, $val2)) {
                log::error!("Signer fail to send notification: {e:?}");
            }
        }
    };
}
