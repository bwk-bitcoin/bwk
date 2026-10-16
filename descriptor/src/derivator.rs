use bwk_keys::keys::OXpub;
use miniscript::{
    bitcoin::{self, Network, ScriptBuf},
    ForEachKey,
};

use crate::{
    descriptor::{tr, wpkh},
    wallet::{to_wallet, WalletDescriptor, WalletDescriptorExt, WalletKeyExt},
};

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

impl Error {
    /// `SpkDerivator::new` reports the lowest rank seen over every key.
    fn rank(&self) -> u8 {
        match self {
            Error::NotMultiXpub => 0,
            Error::WrongNetwork => 1,
            Error::MultiPath => 2,
            Error::Wildcard => 3,
            Error::MultiPathCount => 4,
        }
    }
}

/// A struct that manages Bitcoin address derivation from a descriptor.
///
/// It holds the main descriptor, the receiving descriptor, the change descriptor,
/// and the network type. It ensures that the descriptors are valid at creation.
#[derive(Debug, Clone)]
pub struct SpkDerivator {
    descriptor: WalletDescriptor, // multipath
    recv: WalletDescriptor,       // single path
    change: WalletDescriptor,     // single path
    network: bitcoin::Network,
}

impl SpkDerivator {
    /// Creates a new `Derivator` instance.
    ///
    /// # Parameters
    /// - `descriptor`: A `WalletDescriptor` that must be a multi-signature
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
    pub fn new(descriptor: WalletDescriptor, network: bitcoin::Network) -> Result<Self, Error> {
        let mut worst: Option<Error> = None;
        descriptor.for_each_key(|k| {
            if let Err(e) = k.check_derivation(network) {
                if worst.as_ref().is_none_or(|w| e.rank() < w.rank()) {
                    worst = Some(e);
                }
            }
            true
        });
        if let Some(e) = worst {
            return Err(e);
        }

        let single_descriptors = descriptor.single_paths().map_err(|_| Error::MultiPath)?;

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
        let descriptor = to_wallet(wpkh(xpub));
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
        let descriptor = to_wallet(tr(xpub));
        Self::new(descriptor, network)
    }

    /// Returns the main descriptor of the `Derivator`.
    ///
    /// # Returns
    /// - `WalletDescriptor`: The main descriptor associated with this `Derivator`.
    pub fn descriptor(&self) -> WalletDescriptor {
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
            .derive_at(index)
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
            .derive_at(index)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{bitcoin::Network, DescriptorPublicKey};

    use crate::{
        derivator::{Error, SpkDerivator},
        wallet::to_wallet,
    };

    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const TPUB: &str = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x";

    #[test]
    fn error_priority_is_unchanged() {
        // miniscript walks the leaf first, its key has a two-step multipath; the
        // internal key, walked after it, is on the wrong network: that error still wins.
        let d = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "tr({XPUB}/<0;1>/*,pk({TPUB}/0/<0;1>/*))"
        ))
        .unwrap();
        assert!(matches!(
            SpkDerivator::new(to_wallet(d), Network::Regtest),
            Err(Error::WrongNetwork)
        ));
    }
}
