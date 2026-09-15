use bwk_keys::keys::OXpub;
use miniscript::{
    bitcoin::{self, Network, ScriptBuf},
    descriptor::Wildcard,
    Descriptor, DescriptorPublicKey, ForEachKey,
};

use crate::{tr, wpkh};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("descriptor is not a multipath xpub")]
    NotMultiXpub,
    #[error("descriptor network mismatch")]
    WrongNetwork,
    #[error("unexpected number of derivation paths")]
    MultiPathCount,
    #[error("invalid multipath descriptor")]
    MultiPath,
    #[error("descriptor is missing a wildcard")]
    Wildcard,
}

/// A struct that manages Bitcoin address derivation from a descriptor.
///
/// It holds the main descriptor, the receiving descriptor, the change descriptor,
/// and the network type. It ensures that the descriptors are valid at creation.
#[derive(Debug, Clone)]
pub struct SpkDerivator {
    descriptor: Descriptor<DescriptorPublicKey>, // DesciptorPublicKey::MultiXpub
    recv: Descriptor<DescriptorPublicKey>,       // DescriptorPublicKey::Xpub
    change: Descriptor<DescriptorPublicKey>,     // DescriptorPublicKey::Xpub
    network: bitcoin::Network,
}

impl SpkDerivator {
    /// Creates a new `Derivator` instance.
    ///
    /// # Parameters
    /// - `descriptor`: A `Descriptor<DescriptorPublicKey>` that must be a multi-signature
    ///   descriptor.
    /// - `network`: The Bitcoin network type.
    ///
    /// # Returns
    /// - `Result<Self, Error>`: Returns an instance of `Derivator` if successful,
    ///   or an `Error` if the descriptor is not valid.
    ///
    /// # Note: the descriptor is expected to have this properties:
    /// - It must be of type [`DescriptorPublicKey::MultiXpub`]
    /// - All keys must have a multipath of size 2, the first element being the receive index,
    ///   the second being the change index.
    /// - Multipath elements must be of unhardened type.
    /// - It must have an Unhardened wildcard.
    /// - All key must be for the given network.
    pub fn new(
        descriptor: Descriptor<DescriptorPublicKey>,
        network: bitcoin::Network,
    ) -> Result<Self, Error> {
        let is_multi_xpub =
            descriptor.for_each_key(|k| matches!(k, DescriptorPublicKey::MultiXPub(_)));
        if !is_multi_xpub {
            return Err(Error::NotMultiXpub);
        }

        let mut wrong_network = false;
        let mut wrong_multipath = false;
        let mut wrong_wildcard = false;
        descriptor.for_each_key(|k| {
            if let DescriptorPublicKey::MultiXPub(key) = k {
                if key.xkey.network != network.into() {
                    wrong_network = true;
                }
                let paths = key.derivation_paths.paths();
                for p in paths {
                    let v = p.to_u32_vec();
                    // expected 1 multipath + 1 wildcard
                    if v.len() != 1 {
                        wrong_multipath = true;
                    }
                    for child in v {
                        // if hardened derivation path
                        if child >= 0x80000000 {
                            wrong_multipath = true;
                        }
                    }
                    if key.wildcard != Wildcard::Unhardened {
                        wrong_wildcard = true;
                    }
                }
            }
            true
        });
        if wrong_network {
            return Err(Error::WrongNetwork);
        }
        if wrong_multipath {
            return Err(Error::MultiPath);
        }
        if wrong_wildcard {
            return Err(Error::Wildcard);
        }

        let single_descriptors = descriptor
            .clone()
            .into_single_descriptors()
            .expect("multipath already sanitized");

        if single_descriptors.len() != 2 {
            return Err(Error::MultiPathCount);
        }

        let mut single_descriptors = single_descriptors.into_iter();
        let recv = single_descriptors.next().expect("length checked");
        let change = single_descriptors.next().expect("length checked");

        Ok(Self {
            descriptor,
            recv,
            change,
            network,
        })
    }

    /// Creates a new `SpkDerivator` instance for a Witness-PubKey-Hash (WPKH) descriptor.
    ///
    /// # Parameters
    /// - `xpub`: An `OXpub` extended public key.
    /// - `network`: The Bitcoin network type.
    ///
    /// # Returns
    /// - `Result<Self, Error>`: Returns an instance of `SpkDerivator` if successful,
    ///   or an `Error` if the descriptor construction fails.
    pub fn new_wpkh(xpub: OXpub, network: Network) -> Result<Self, Error> {
        let descriptor = wpkh(xpub);
        Self::new(descriptor, network)
    }

    /// Creates a new `SpkDerivator` instance for a Taproot (key spend) descriptor.
    ///
    /// # Parameters
    /// - `xpub`: An `OXpub` extended public key.
    /// - `network`: The Bitcoin network type.
    ///
    /// # Returns
    /// - `Result<Self, Error>`: Returns an instance of `SpkDerivator` if successful,
    ///   or an `Error` if the descriptor construction fails.
    pub fn new_tr(xpub: OXpub, network: Network) -> Result<Self, Error> {
        let descriptor = tr(xpub);
        Self::new(descriptor, network)
    }

    /// Returns the main descriptor of the `Derivator`.
    ///
    /// # Returns
    /// - `Descriptor<DescriptorPublicKey>`: The main descriptor associated with this
    ///   `Derivator`.
    pub fn descriptor(&self) -> Descriptor<DescriptorPublicKey> {
        self.descriptor.clone()
    }

    /// Derives a receiving address at the specified index.
    ///
    /// # Parameters
    /// - `index`: The index at which to derive the receiving address.
    ///
    /// # Returns
    /// - `bitcoin::Address`: The derived receiving address.
    pub fn receive_at(&self, index: u32) -> bitcoin::Address {
        self.recv
            .at_derivation_index(index)
            .expect("wildcard checked")
            .address(self.network)
            .expect("valid")
    }

    /// Derives a change address at the specified index.
    ///
    /// # Parameters
    /// - `index`: The index at which to derive the change address.
    ///
    /// # Returns
    /// - `bitcoin::Address`: The derived change address.
    pub fn change_at(&self, index: u32) -> bitcoin::Address {
        self.change
            .at_derivation_index(index)
            .expect("wildcard checked")
            .address(self.network)
            .expect("valid")
    }

    /// Returns the script public key for the receiving address at the specified index.
    ///
    /// # Parameters
    /// - `index`: The index at which to derive the receiving address.
    ///
    /// # Returns
    /// - `ScriptBuf`: The script public key of the derived receiving address.
    pub fn receive_spk_at(&self, index: u32) -> ScriptBuf {
        self.receive_at(index).script_pubkey()
    }

    /// Returns the script public key for the change address at the specified index.
    ///
    /// # Parameters
    /// - `index`: The index at which to derive the change address.
    ///
    /// # Returns
    /// - `ScriptBuf`: The script public key of the derived change address.
    pub fn change_spk_at(&self, index: u32) -> ScriptBuf {
        self.change_at(index).script_pubkey()
    }
}
