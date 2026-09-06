//! The signing manager trait: one object-safe, store-free abstraction that
//! every signing back end (hot, hardware, remote, mock) implements.

use crossbeam::channel;

use miniscript::bitcoin::bip32::DerivationPath;

use bwk_descriptor::descriptor::Descriptor;

use crate::{
    identity::{SignerId, SignerInfo},
    protocol::{RequestId, Response},
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no signer with id {0}")]
    UnknownSigner(SignerId),
    #[error("signer {0} is not ready")]
    NotReady(SignerId),
    #[error("signer {0} does not support this operation")]
    Unsupported(SignerId),
    #[error("descriptor is not registered with signer {0}")]
    UnregisteredDescriptor(SignerId),
    #[error("psbt is not deserializable")]
    Psbt,
    #[error("no notification channel is subscribed")]
    NoSubscriber,
    #[error("the signing back end is disconnected")]
    Disconnected,
}

/// A signing back end managing a group of signers.
///
/// Every operation queues work and returns immediately with a [`RequestId`];
/// none of them blocks and none of them carries a result. The result arrives
/// later as a [`Response`] on the channel supplied through `subscribe`, and
/// the `RequestId` correlates that notification back to the call that
/// triggered it. Errors that no call asked for (a device unplugged, a remote
/// link dropped) may also arrive on that channel, with an optional request
/// id.
pub trait SigningManager: Send + Sync {
    /// Signers currently known to the manager, from a local cache. Never
    /// performs IO.
    fn signers(&self) -> Vec<SignerInfo>;

    /// Delivers every [`Response`] on the most recently subscribed channel.
    /// Subscribing again replaces the previous one. A manager with no
    /// subscriber returns [`Error::NoSubscriber`] from every operation that
    /// would otherwise have nothing to report to.
    fn subscribe(&mut self, sender: channel::Sender<Response>);

    /// Turns device discovery on and off, mirroring silent's
    /// `Host::requestSignerPolling`. A manager with no discovery (the hot
    /// manager) implements this as a no-op.
    fn set_polling(&mut self, enabled: bool);

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, Error>;

    fn info(&self, signer: &SignerId) -> Result<RequestId, Error>;

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: DerivationPath,
        display: bool,
    ) -> Result<RequestId, Error>;

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, Error>;

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, Error>;

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, Error>;

    fn raw(&self, signer: &SignerId, request: Vec<u8>) -> Result<RequestId, Error>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        identity::SignerId,
        manager::{Error, SigningManager},
    };

    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn SigningManager) {}

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn trait_is_object_safe_and_thread_safe() {
        assert_send_sync::<Box<dyn SigningManager>>();
    }

    #[test]
    fn error_messages_name_the_signer() {
        let id = SignerId::from_str("abc").unwrap();
        assert!(Error::UnknownSigner(id).to_string().contains("abc"));
    }
}
