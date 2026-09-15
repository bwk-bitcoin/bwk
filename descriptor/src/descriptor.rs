use std::str::FromStr;

use bwk_keys::keys::OXpub;
use miniscript::{
    bitcoin::{
        self,
        bip32::{ChildNumber, DerivationPath},
    },
    Descriptor, DescriptorPublicKey,
};

use crate::SpkDerivator;

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum Error {
    #[error("account derivation must be hardened")]
    UnhardenedAccount,
    #[error("not implemented")]
    NotImplemented,
}

pub enum ScriptType {
    Segwit(ChildNumber /* account */),
    Taproot(ChildNumber /* account */),
    Descriptor(Box<Descriptor<DescriptorPublicKey>>),
}

impl ScriptType {
    pub fn to_descriptor<X>(
        self,
        network: bitcoin::Network,
        xpub: X,
    ) -> Result<Descriptor<DescriptorPublicKey>, Error>
    where
        X: Fn(DerivationPath) -> OXpub,
    {
        match self {
            ScriptType::Segwit(acc) => {
                let deriv = wpkh_path(network, acc)?;
                Ok(wpkh(xpub(deriv)))
            }
            ScriptType::Taproot(acc) => {
                let deriv = tr_path(network, acc)?;
                Ok(tr(xpub(deriv)))
            }
            ScriptType::Descriptor(descriptor) => Ok(*descriptor),
        }
    }
}

pub fn tr_path(network: bitcoin::Network, account: ChildNumber) -> Result<DerivationPath, Error> {
    if !account.is_hardened() {
        return Err(Error::UnhardenedAccount);
    }
    let script_path = ChildNumber::from_hardened_idx(86).expect("taproot");
    let n_path = match network {
        bitcoin::Network::Bitcoin => 0,
        _ => 1,
    };
    let network = ChildNumber::from_hardened_idx(n_path).expect("0 or 1");
    Ok(vec![script_path, network, account].into())
}

pub fn wpkh_path(network: bitcoin::Network, account: ChildNumber) -> Result<DerivationPath, Error> {
    if !account.is_hardened() {
        return Err(Error::UnhardenedAccount);
    }
    let script_path = ChildNumber::from_hardened_idx(84).expect("segwit");
    let n_path = match network {
        bitcoin::Network::Bitcoin => 0,
        _ => 1,
    };
    let network = ChildNumber::from_hardened_idx(n_path).expect("0 or 1");
    Ok(vec![script_path, network, account].into())
}

/// Creates a WPKH descriptor from the given extended public key (OXpub).
///
/// # Arguments
/// * `xpub` - An instance of `OXpub` representing the extended public key.
///
/// # Returns
/// A `Descriptor<DescriptorPublicKey>` that represents the wpkh descriptor.
pub fn wpkh(xpub: OXpub) -> Descriptor<DescriptorPublicKey> {
    let descr_str = format!(
        "wpkh([{}/{}]{}/<0;1>/*)",
        xpub.origin.0, xpub.origin.1, xpub.xkey
    );
    Descriptor::<DescriptorPublicKey>::from_str(&descr_str).expect("hardcoded descriptor")
}

/// Creates a TR descriptor from the given extended public key (OXpub).
///
/// # Arguments
/// * `xpub` - An instance of `OXpub` representing the extended public key.
///
/// # Returns
/// A `Descriptor<DescriptorPublicKey>` that represents the wpkh descriptor.
pub fn tr(xpub: OXpub) -> Descriptor<DescriptorPublicKey> {
    let descr_str = format!(
        "tr([{}/{}]{}/<0;1>/*)",
        xpub.origin.0, xpub.origin.1, xpub.xkey
    );
    Descriptor::<DescriptorPublicKey>::from_str(&descr_str).expect("hardcoded descriptor")
}

pub trait DescriptorDerivator {
    type Error;
    fn spk_derivator(&self, network: bitcoin::Network) -> Result<SpkDerivator, Self::Error>;
}

impl DescriptorDerivator for Descriptor<DescriptorPublicKey> {
    type Error = crate::derivator::Error;
    fn spk_derivator(
        &self,
        network: bitcoin::Network,
    ) -> Result<SpkDerivator, crate::derivator::Error> {
        SpkDerivator::new(self.clone(), network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::bitcoin::bip32::{Fingerprint, Xpub};

    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn oxpub_at(path: DerivationPath) -> OXpub {
        OXpub {
            origin: (Fingerprint::from([0u8; 4]), path),
            xkey: Xpub::from_str(XPUB).unwrap(),
        }
    }

    fn descriptor_for(script: ScriptType) -> String {
        script
            .to_descriptor(bitcoin::Network::Bitcoin, oxpub_at)
            .unwrap()
            .to_string()
    }

    #[test]
    fn each_script_type_builds_the_descriptor_it_names() {
        let account = ChildNumber::from_hardened_idx(0).unwrap();

        assert_eq!(
            descriptor_for(ScriptType::Segwit(account)),
            format!("wpkh([00000000/84'/0'/0']{XPUB}/<0;1>/*)#taah38uk")
        );
        assert_eq!(
            descriptor_for(ScriptType::Taproot(account)),
            format!("tr([00000000/86'/0'/0']{XPUB}/<0;1>/*)#vess5qrq")
        );

        // A shape neither other arm can build, so a rebuilt descriptor would
        // not match what went in.
        let given = format!("pkh([00000000/44'/0'/0']{XPUB}/<0;1>/*)");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&given).unwrap();
        assert_eq!(
            descriptor_for(ScriptType::Descriptor(Box::new(descriptor.clone()))),
            descriptor.to_string()
        );
    }

    #[test]
    fn every_network_but_mainnet_derives_under_coin_type_one() {
        let account = ChildNumber::from_hardened_idx(0).unwrap();
        for network in [
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ] {
            assert_eq!(
                wpkh_path(network, account).unwrap().to_string(),
                "84'/1'/0'"
            );
            assert_eq!(tr_path(network, account).unwrap().to_string(), "86'/1'/0'");
        }
    }

    #[test]
    fn an_unhardened_account_is_refused() {
        let account = ChildNumber::from_normal_idx(0).unwrap();
        let network = bitcoin::Network::Bitcoin;

        assert!(matches!(
            wpkh_path(network, account),
            Err(Error::UnhardenedAccount)
        ));
        assert!(matches!(
            tr_path(network, account),
            Err(Error::UnhardenedAccount)
        ));
        assert!(matches!(
            ScriptType::Segwit(account).to_descriptor(network, oxpub_at),
            Err(Error::UnhardenedAccount)
        ));
        assert!(matches!(
            ScriptType::Taproot(account).to_descriptor(network, oxpub_at),
            Err(Error::UnhardenedAccount)
        ));
    }
}
