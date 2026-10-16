//! The wallet key type: `DescriptorPublicKey`, or `MusigKey` under `musig`.

#[cfg(feature = "musig")]
use std::convert::Infallible;

#[cfg(feature = "musig")]
use bwk_keys::musig::{DefiniteMusigKey, MusigAggregate, MusigKey};
#[cfg(not(feature = "musig"))]
use miniscript::DefiniteDescriptorKey;
#[cfg(feature = "musig")]
use miniscript::{
    bitcoin::bip32::ChildNumber, translate_hash_clone, MiniscriptKey, TranslateErr, TranslatePk,
    Translator,
};
use miniscript::{bitcoin::Network, descriptor::Wildcard, DescriptorPublicKey, ForEachKey};

#[cfg(feature = "musig")]
use crate::derivator::Error as DerivatorError;

#[cfg(not(feature = "musig"))]
pub type WalletKey = DescriptorPublicKey;
#[cfg(feature = "musig")]
pub type WalletKey = MusigKey;
#[cfg(not(feature = "musig"))]
pub type WalletDefiniteKey = DefiniteDescriptorKey;
#[cfg(feature = "musig")]
pub type WalletDefiniteKey = DefiniteMusigKey;
pub type WalletDescriptor = miniscript::Descriptor<WalletKey>;
pub type WalletDefiniteDescriptor = miniscript::Descriptor<WalletDefiniteKey>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("descriptor is not multipath")]
    NotMultipath,
    #[error("derivation failed: {0}")]
    Derivation(String),
}

/// Identity without `musig`, every key `MusigKey::Plain` with it.
#[cfg(not(feature = "musig"))]
pub fn to_wallet(descriptor: miniscript::Descriptor<DescriptorPublicKey>) -> WalletDescriptor {
    descriptor
}

/// Identity without `musig`, every key `MusigKey::Plain` with it.
#[cfg(feature = "musig")]
pub fn to_wallet(descriptor: miniscript::Descriptor<DescriptorPublicKey>) -> WalletDescriptor {
    descriptor
        .translate_pk(&mut ToPlain)
        .expect("plain keys always translate")
}

#[cfg(feature = "musig")]
struct ToPlain;

#[cfg(feature = "musig")]
impl Translator<DescriptorPublicKey, MusigKey, Infallible> for ToPlain {
    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<MusigKey, Infallible> {
        Ok(MusigKey::Plain(pk.clone()))
    }
    translate_hash_clone!(DescriptorPublicKey, MusigKey, Infallible);
}

/// Picks the `self.0`-th path of every multipath key.
#[cfg(feature = "musig")]
struct PathChoser(usize);

#[cfg(feature = "musig")]
impl Translator<MusigKey, MusigKey, Error> for PathChoser {
    fn pk(&mut self, pk: &MusigKey) -> Result<MusigKey, Error> {
        if pk.num_der_paths() > 1 {
            pk.clone()
                .into_single_keys()
                .get(self.0)
                .cloned()
                .ok_or(Error::Derivation("multipath length mismatch".into()))
        } else {
            Ok(pk.clone())
        }
    }
    translate_hash_clone!(MusigKey, MusigKey, Error);
}

/// Derives every key at `self.0`.
#[cfg(feature = "musig")]
struct IndexDerivator(u32);

#[cfg(feature = "musig")]
impl Translator<MusigKey, DefiniteMusigKey, Error> for IndexDerivator {
    fn pk(&mut self, pk: &MusigKey) -> Result<DefiniteMusigKey, Error> {
        pk.at_derivation_index(self.0)
            .map_err(|e| Error::Derivation(e.to_string()))
    }
    translate_hash_clone!(MusigKey, DefiniteMusigKey, Error);
}

#[cfg(feature = "musig")]
fn translate_error(e: TranslateErr<Error>) -> Error {
    match e {
        TranslateErr::TranslatorErr(e) => e,
        TranslateErr::OuterError(e) => Error::Derivation(e.to_string()),
    }
}

/// Per-key queries the stack used to match on `DescriptorPublicKey` for.
pub trait WalletKeyExt {
    /// The key itself, or every musig cosigner.
    fn plain_keys(&self) -> Vec<&DescriptorPublicKey>;
    /// The `SpkDerivator::new` shape check of one key.
    fn check_derivation(&self, network: Network) -> Result<(), crate::derivator::Error>;
}

impl WalletKeyExt for DescriptorPublicKey {
    fn plain_keys(&self) -> Vec<&DescriptorPublicKey> {
        vec![self]
    }

    fn check_derivation(&self, network: Network) -> Result<(), crate::derivator::Error> {
        let DescriptorPublicKey::MultiXPub(key) = self else {
            return Err(crate::derivator::Error::NotMultiXpub);
        };
        if key.xkey.network != network.into() {
            return Err(crate::derivator::Error::WrongNetwork);
        }
        let mut wrong_multipath = false;
        let mut wrong_wildcard = false;
        for p in key.derivation_paths.paths() {
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
        if wrong_multipath {
            return Err(crate::derivator::Error::MultiPath);
        }
        if wrong_wildcard {
            return Err(crate::derivator::Error::Wildcard);
        }
        Ok(())
    }
}

#[cfg(feature = "musig")]
impl WalletKeyExt for MusigKey {
    fn plain_keys(&self) -> Vec<&DescriptorPublicKey> {
        MusigKey::plain_keys(self)
    }

    fn check_derivation(&self, network: Network) -> Result<(), crate::derivator::Error> {
        match self {
            MusigKey::Plain(key) => key.check_derivation(network),
            MusigKey::Musig(aggregate) => check_musig_derivation(aggregate, network),
        }
    }
}

/// The `musig()` expression stands in for a key: its own derivation must be a
/// multipath one; without one, every cosigner must pass on its own.
#[cfg(feature = "musig")]
fn check_musig_derivation(
    aggregate: &MusigAggregate,
    network: Network,
) -> Result<(), DerivatorError> {
    match aggregate.derivation() {
        Some(derivation) if derivation.paths.paths().len() > 1 => {
            let wrong_network = aggregate.cosigners().iter().any(|key| match key {
                DescriptorPublicKey::Single(_) => false,
                DescriptorPublicKey::XPub(xpub) => xpub.xkey.network != network.into(),
                DescriptorPublicKey::MultiXPub(xpub) => xpub.xkey.network != network.into(),
            });
            if wrong_network {
                return Err(DerivatorError::WrongNetwork);
            }
            let wrong_multipath = derivation
                .paths
                .paths()
                .iter()
                .any(|path| path.len() != 1 || path.into_iter().any(ChildNumber::is_hardened));
            if wrong_multipath {
                return Err(DerivatorError::MultiPath);
            }
            if derivation.wildcard != Wildcard::Unhardened {
                return Err(DerivatorError::Wildcard);
            }
            Ok(())
        }
        Some(_) => Err(DerivatorError::NotMultiXpub),
        None => aggregate
            .cosigners()
            .iter()
            .filter_map(|key| key.check_derivation(network).err())
            .min_by_key(DerivatorError::rank)
            .map_or(Ok(()), Err),
    }
}

/// Descriptor-level calls that exist inherently only for `DescriptorPublicKey`.
pub trait WalletDescriptorExt {
    /// `into_single_descriptors`.
    fn single_paths(&self) -> Result<Vec<WalletDescriptor>, Error>;
    /// `at_derivation_index`.
    fn derive_at(&self, index: u32) -> Result<WalletDefiniteDescriptor, Error>;
    /// Every plain key and cosigner, deduplicated.
    fn plain_keys(&self) -> Vec<DescriptorPublicKey>;
    fn has_musig(&self) -> bool;
}

impl WalletDescriptorExt for WalletDescriptor {
    #[cfg(not(feature = "musig"))]
    fn single_paths(&self) -> Result<Vec<WalletDescriptor>, Error> {
        self.clone()
            .into_single_descriptors()
            .map_err(|e| Error::Derivation(e.to_string()))
    }

    #[cfg(feature = "musig")]
    fn single_paths(&self) -> Result<Vec<WalletDescriptor>, Error> {
        let mut count = 0;
        if !self.for_any_key(|key| {
            count = key.num_der_paths();
            count > 1
        }) {
            return Ok(vec![self.clone()]);
        }
        (0..count)
            .map(|i| {
                self.translate_pk(&mut PathChoser(i))
                    .map_err(translate_error)
            })
            .collect()
    }

    #[cfg(not(feature = "musig"))]
    fn derive_at(&self, index: u32) -> Result<WalletDefiniteDescriptor, Error> {
        self.at_derivation_index(index)
            .map_err(|e| Error::Derivation(e.to_string()))
    }

    #[cfg(feature = "musig")]
    fn derive_at(&self, index: u32) -> Result<WalletDefiniteDescriptor, Error> {
        self.translate_pk(&mut IndexDerivator(index))
            .map_err(translate_error)
    }

    fn plain_keys(&self) -> Vec<DescriptorPublicKey> {
        let mut keys: Vec<DescriptorPublicKey> = Vec::new();
        self.for_each_key(|key| {
            for plain in WalletKeyExt::plain_keys(key) {
                if !keys.contains(plain) {
                    keys.push(plain.clone());
                }
            }
            true
        });
        keys
    }

    #[cfg(not(feature = "musig"))]
    fn has_musig(&self) -> bool {
        false
    }

    #[cfg(feature = "musig")]
    fn has_musig(&self) -> bool {
        self.for_any_key(MusigKey::is_musig)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[cfg(feature = "musig")]
    use bwk_keys::musig::MusigKey;
    use miniscript::{bitcoin::Network, DescriptorPublicKey};

    use crate::wallet::{to_wallet, WalletDescriptor, WalletDescriptorExt};
    #[cfg(feature = "musig")]
    use crate::{derivator::Error as DerivatorError, wallet::WalletKeyExt};

    const XPUB1: &str = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x";
    const XPUB2: &str = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";

    fn plain(s: &str) -> miniscript::Descriptor<DescriptorPublicKey> {
        miniscript::Descriptor::<DescriptorPublicKey>::from_str(s).unwrap()
    }

    fn wpkh() -> miniscript::Descriptor<DescriptorPublicKey> {
        plain(&format!("wpkh([9d69155f/84h/1h/0h]{XPUB1}/<0;1>/*)"))
    }

    fn tr_with_leaf() -> miniscript::Descriptor<DescriptorPublicKey> {
        plain(&format!(
            "tr([9d69155f/86h/1h/0h]{XPUB1}/<0;1>/*,pk([deadbeef/86h/1h/0h]{XPUB2}/<0;1>/*))"
        ))
    }

    #[test]
    fn to_wallet_prints_byte_identical() {
        for d in [wpkh(), tr_with_leaf()] {
            let wallet = to_wallet(d.clone());
            assert_eq!(wallet.to_string(), d.to_string());
            let parsed = WalletDescriptor::from_str(&wallet.to_string()).unwrap();
            assert_eq!(parsed, wallet);
        }
    }

    #[test]
    fn single_paths_split_receive_and_change() {
        for d in [wpkh(), tr_with_leaf()] {
            let singles = to_wallet(d.clone()).single_paths().unwrap();
            let expected = d.into_single_descriptors().unwrap();
            assert_eq!(singles.len(), 2);
            for (single, expected) in singles.iter().zip(expected) {
                assert_eq!(
                    single
                        .derive_at(5)
                        .unwrap()
                        .address(Network::Regtest)
                        .unwrap(),
                    expected
                        .at_derivation_index(5)
                        .unwrap()
                        .address(Network::Regtest)
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn plain_keys_dedup_in_order() {
        let k1 = format!("[9d69155f/86h/1h/0h]{XPUB1}/<0;1>/*");
        let k2 = format!("[deadbeef/86h/1h/0h]{XPUB2}/<0;1>/*");
        let d = plain(&format!("tr({k1},{{pk({k2}),pk({k1})}})"));
        let xpubs: Vec<String> = to_wallet(d)
            .plain_keys()
            .into_iter()
            .map(|k| match k {
                DescriptorPublicKey::MultiXPub(x) => x.xkey.to_string(),
                _ => panic!(),
            })
            .collect();
        // miniscript walks the leaves before the internal key.
        assert_eq!(xpubs, vec![XPUB2.to_string(), XPUB1.to_string()]);
    }

    #[test]
    fn has_musig_is_false_on_plain() {
        for d in [wpkh(), tr_with_leaf()] {
            assert!(!to_wallet(d).has_musig());
        }
    }

    // BIP-390 test vector xpubs (mainnet).
    #[cfg(feature = "musig")]
    const X1: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    #[cfg(feature = "musig")]
    const X2: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";

    #[cfg(feature = "musig")]
    fn musig(keys: &[&str], suffix: &str) -> MusigKey {
        MusigKey::from_str(&format!("musig|{}|{suffix}", keys.join("|"))).unwrap()
    }

    #[cfg(feature = "musig")]
    #[test]
    fn musig_key_plain_keys_lists_cosigners() {
        let x1 = DescriptorPublicKey::from_str(X1).unwrap();
        let x2 = DescriptorPublicKey::from_str(X2).unwrap();
        let key = musig(&[X1, X2], "/<0;1>/*");
        assert_eq!(WalletKeyExt::plain_keys(&key), vec![&x1, &x2]);
        let plain = MusigKey::Plain(x1.clone());
        assert_eq!(WalletKeyExt::plain_keys(&plain), vec![&x1]);
    }

    #[cfg(feature = "musig")]
    #[test]
    fn musig_key_check_derivation_shapes() {
        let x1_multipath = format!("{X1}/<0;1>/*");
        let x2_multipath = format!("{X2}/<0;1>/*");
        let x2_single = format!("{X2}/0/*");
        let bitcoin = Network::Bitcoin;
        assert!(musig(&[X1, X2], "/<0;1>/*")
            .check_derivation(bitcoin)
            .is_ok());
        assert!(matches!(
            musig(&[X1, X2], "/<0;1>/*").check_derivation(Network::Testnet),
            Err(DerivatorError::WrongNetwork)
        ));
        assert!(matches!(
            musig(&[X1, X2], "/<0;1>/0/*").check_derivation(bitcoin),
            Err(DerivatorError::MultiPath)
        ));
        assert!(matches!(
            musig(&[X1, X2], "/<0;1>").check_derivation(bitcoin),
            Err(DerivatorError::Wildcard)
        ));
        assert!(matches!(
            musig(&[X1, X2], "/0/*").check_derivation(bitcoin),
            Err(DerivatorError::NotMultiXpub)
        ));
        assert!(musig(&[&x1_multipath, &x2_multipath], "")
            .check_derivation(bitcoin)
            .is_ok());
        assert!(matches!(
            musig(&[&x1_multipath, &x2_single], "").check_derivation(bitcoin),
            Err(DerivatorError::NotMultiXpub)
        ));
    }
}
