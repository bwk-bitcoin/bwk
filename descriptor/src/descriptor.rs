use std::{fmt, str::FromStr};

use bwk_keys::keys::OXpub;
use miniscript::{
    bitcoin::{
        self,
        bip32::{self, ChildNumber, DerivationPath},
    },
    DescriptorPublicKey, ForEachKey,
};

use crate::{derivator::SpkDerivator, sp_descriptor::SpDescriptor};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("account derivation must be hardened")]
    UnhardenedAccount,
    #[error("not implemented")]
    NotImplemented,
    #[error("not a miniscript descriptor")]
    NotMiniscript,
    #[error("not an sp descriptor")]
    NotSp,
    #[error("{0}")]
    Parse(String),
}

pub enum ScriptType {
    Segwit(ChildNumber /* account */),
    Taproot(ChildNumber /* account */),
    Descriptor(Box<miniscript::Descriptor<DescriptorPublicKey>>),
}

impl ScriptType {
    pub fn to_descriptor<X>(
        self,
        network: bitcoin::Network,
        xpub: X,
    ) -> Result<miniscript::Descriptor<DescriptorPublicKey>, Error>
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
pub fn wpkh(xpub: OXpub) -> miniscript::Descriptor<DescriptorPublicKey> {
    let descr_str = format!(
        "wpkh([{}/{}]{}/<0;1>/*)",
        xpub.origin.0, xpub.origin.1, xpub.xkey
    );
    miniscript::Descriptor::<DescriptorPublicKey>::from_str(&descr_str)
        .expect("hardcoded descriptor")
}

/// Creates a TR descriptor from the given extended public key (OXpub).
///
/// # Arguments
/// * `xpub` - An instance of `OXpub` representing the extended public key.
///
/// # Returns
/// A `Descriptor<DescriptorPublicKey>` that represents the wpkh descriptor.
pub fn tr(xpub: OXpub) -> miniscript::Descriptor<DescriptorPublicKey> {
    let descr_str = format!(
        "tr([{}/{}]{}/<0;1>/*)",
        xpub.origin.0, xpub.origin.1, xpub.xkey
    );
    miniscript::Descriptor::<DescriptorPublicKey>::from_str(&descr_str)
        .expect("hardcoded descriptor")
}

pub trait DescriptorDerivator {
    type Error;
    fn spk_derivator(&self, network: bitcoin::Network) -> Result<SpkDerivator, Self::Error>;
}

impl DescriptorDerivator for miniscript::Descriptor<DescriptorPublicKey> {
    type Error = crate::derivator::Error;
    fn spk_derivator(
        &self,
        network: bitcoin::Network,
    ) -> Result<SpkDerivator, crate::derivator::Error> {
        SpkDerivator::new(self.clone(), network)
    }
}

/// A descriptor bwk understands, either a standard `miniscript::Descriptor` or a
/// BIP392 `sp()` silent-payment descriptor.
///
/// This type shares its short name with `miniscript::Descriptor`. The convention
/// used across the workspace is to import this one as `Descriptor` via
/// `use bwk_descriptor::descriptor::Descriptor;`, and to write the miniscript one
/// out in full as `miniscript::Descriptor<DescriptorPublicKey>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    Miniscript(Box<miniscript::Descriptor<DescriptorPublicKey>>),
    Sp(Box<SpDescriptor>),
}

impl Descriptor {
    pub fn as_miniscript(&self) -> Option<&miniscript::Descriptor<DescriptorPublicKey>> {
        match self {
            Descriptor::Miniscript(d) => Some(d),
            Descriptor::Sp(_) => None,
        }
    }

    pub fn as_sp(&self) -> Option<&SpDescriptor> {
        match self {
            Descriptor::Sp(d) => Some(d),
            Descriptor::Miniscript(_) => None,
        }
    }

    pub fn is_sp(&self) -> bool {
        matches!(self, Descriptor::Sp(_))
    }

    pub fn into_miniscript(self) -> Result<miniscript::Descriptor<DescriptorPublicKey>, Error> {
        match self {
            Descriptor::Miniscript(d) => Ok(*d),
            Descriptor::Sp(_) => Err(Error::NotMiniscript),
        }
    }

    pub fn to_string_no_checksum(&self) -> String {
        format!("{self:#}")
    }

    pub fn fingerprint(&self) -> Option<bip32::Fingerprint> {
        match self {
            Descriptor::Sp(d) => d.fingerprint(),
            Descriptor::Miniscript(d) => {
                let mut fingerprint = None;
                d.for_any_key(|key| {
                    let origin = match key {
                        DescriptorPublicKey::Single(k) => k.origin.as_ref(),
                        DescriptorPublicKey::XPub(k) => k.origin.as_ref(),
                        DescriptorPublicKey::MultiXPub(k) => k.origin.as_ref(),
                    };
                    match origin {
                        Some((fg, _)) => {
                            fingerprint = Some(*fg);
                            true
                        }
                        None => false,
                    }
                });
                fingerprint
            }
        }
    }
}

impl FromStr for Descriptor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim_start().starts_with("sp(") {
            SpDescriptor::from_str(s)
                .map(|d| Descriptor::Sp(Box::new(d)))
                .map_err(|e| Error::Parse(e.to_string()))
        } else {
            miniscript::Descriptor::<DescriptorPublicKey>::from_str(s)
                .map(|d| Descriptor::Miniscript(Box::new(d)))
                .map_err(|e| Error::Parse(e.to_string()))
        }
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Descriptor::Miniscript(d) => {
                if f.alternate() {
                    write!(f, "{d:#}")
                } else {
                    write!(f, "{d}")
                }
            }
            Descriptor::Sp(d) => {
                if f.alternate() {
                    write!(f, "{d:#}")
                } else {
                    write!(f, "{d}")
                }
            }
        }
    }
}

impl Ord for Descriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for Descriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl serde::Serialize for Descriptor {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Descriptor {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Descriptor::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl From<miniscript::Descriptor<DescriptorPublicKey>> for Descriptor {
    fn from(d: miniscript::Descriptor<DescriptorPublicKey>) -> Self {
        Descriptor::Miniscript(Box::new(d))
    }
}

impl From<SpDescriptor> for Descriptor {
    fn from(d: SpDescriptor) -> Self {
        Descriptor::Sp(Box::new(d))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr};

    use bwk_keys::keys::OXpub;
    use miniscript::{
        bitcoin::{
            self,
            bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
            secp256k1::Secp256k1,
            Network,
        },
        DescriptorPublicKey,
    };

    use crate::descriptor::{tr_path, wpkh_path, Descriptor, Error, ScriptType};

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
        let descriptor = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&given).unwrap();
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

    fn xprv(seed: u8) -> Xpriv {
        Xpriv::new_master(Network::Testnet, &[seed; 64]).unwrap()
    }

    fn miniscript_str(origin: Option<&str>) -> String {
        let secp = Secp256k1::new();
        let xpub = Xpub::from_priv(&secp, &xprv(0x01));
        match origin {
            Some(fingerprint) => format!("wpkh([{fingerprint}/84h/1h/0h]{xpub}/<0;1>/*)"),
            None => format!("wpkh({xpub}/<0;1>/*)"),
        }
    }

    fn sp_str(fingerprint: &str, spend_seed: u8) -> String {
        let secp = Secp256k1::new();
        let scan = xprv(0x02);
        let spend_xpub = Xpub::from_priv(&secp, &xprv(spend_seed));
        format!("sp([{fingerprint}/352h/0h/0h]{scan}/0h,{spend_xpub}/0h)")
    }

    #[test]
    fn parses_miniscript() {
        let d = Descriptor::from_str(&miniscript_str(Some("9d69155f"))).unwrap();
        assert!(matches!(d, Descriptor::Miniscript(_)));
        assert!(d.as_sp().is_none());
    }

    #[test]
    fn parses_sp() {
        let d = Descriptor::from_str(&sp_str("deadbeef", 0x03)).unwrap();
        assert!(matches!(d, Descriptor::Sp(_)));
        assert!(d.as_miniscript().is_none());
    }

    #[test]
    fn roundtrips_both_kinds() {
        for s in [miniscript_str(Some("9d69155f")), sp_str("deadbeef", 0x03)] {
            let d1 = Descriptor::from_str(&s).unwrap();
            let rendered = d1.to_string();
            let d2 = Descriptor::from_str(&rendered).unwrap();
            assert_eq!(d1, d2);
            assert_eq!(rendered, d2.to_string());
        }
    }

    #[test]
    fn into_miniscript_rejects_sp() {
        let d = Descriptor::from_str(&sp_str("deadbeef", 0x03)).unwrap();
        assert_eq!(d.into_miniscript(), Err(Error::NotMiniscript));
    }

    #[test]
    fn serde_is_a_bare_string() {
        let s = miniscript_str(Some("9d69155f"));
        let inner = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&s).unwrap();
        let d = Descriptor::Miniscript(Box::new(inner.clone()));
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            serde_json::to_string(&inner).unwrap()
        );
    }

    #[test]
    fn serde_roundtrips_sp() {
        let d = Descriptor::from_str(&sp_str("deadbeef", 0x03)).unwrap();
        let json = serde_json::to_string(&d).unwrap();
        let parsed: Descriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn deserializes_a_legacy_config_string() {
        let s = miniscript_str(Some("9d69155f"));
        let json = serde_json::to_string(&s).unwrap();
        let d: Descriptor = serde_json::from_str(&json).unwrap();
        assert!(matches!(d, Descriptor::Miniscript(_)));
    }

    #[test]
    fn ord_is_total_and_by_string() {
        let miniscript_d = Descriptor::from_str(&miniscript_str(Some("9d69155f"))).unwrap();
        let sp_d1 = Descriptor::from_str(&sp_str("deadbeef", 0x03)).unwrap();
        let sp_d2 = Descriptor::from_str(&sp_str("cafebabe", 0x04)).unwrap();

        #[allow(clippy::mutable_key_type)]
        let mut set = BTreeSet::new();
        set.insert(miniscript_d.clone());
        set.insert(sp_d1.clone());
        set.insert(sp_d2);
        assert_eq!(set.len(), 3);

        set.insert(miniscript_d);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn alternate_display_forwards() {
        for s in [miniscript_str(Some("9d69155f")), sp_str("deadbeef", 0x03)] {
            let d = Descriptor::from_str(&s).unwrap();
            assert!(!format!("{d:#}").contains('#'));
        }
    }

    #[test]
    fn fingerprint_reads_both_kinds() {
        let miniscript_d = Descriptor::from_str(&miniscript_str(Some("9d69155f"))).unwrap();
        assert_eq!(
            miniscript_d.fingerprint(),
            Some(Fingerprint::from_str("9d69155f").unwrap())
        );

        let sp_d = Descriptor::from_str(&sp_str("deadbeef", 0x03)).unwrap();
        assert_eq!(
            sp_d.fingerprint(),
            Some(Fingerprint::from_str("deadbeef").unwrap())
        );

        let no_origin = Descriptor::from_str(&miniscript_str(None)).unwrap();
        assert_eq!(no_origin.fingerprint(), None);
    }
}
