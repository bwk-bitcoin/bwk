//! `MusigKey`: a BIP-390 key expression, a plain key or a musig() aggregate.
//! Miniscript sees the aggregate key; signers read the cosigners.

#![allow(dead_code, unused_variables)]

use std::{fmt, str::FromStr};

use bitcoin::{
    bip32::{Fingerprint, KeySource, Xpub},
    hashes::{hash160, ripemd160, sha256},
    secp256k1::PublicKey,
    taproot::TapNodeHash,
    NetworkKind,
};
use bwk_musig::{rust_bitcoin::RustBitcoin, KeyAgg, Tweak};
use miniscript::{
    descriptor::{DerivPaths, Wildcard},
    hash256, DefiniteDescriptorKey, DescriptorPublicKey, MiniscriptKey, ToPublicKey,
};

/// Prefix and separator of the paren-free token miniscript is handed.
pub const MUSIG_TOKEN_PREFIX: &str = "musig|";
pub const MUSIG_TOKEN_SEPARATOR: char = '|';

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid musig key expression: {0}")]
    Parse(String),
    /// A plain key's `DescriptorPublicKey` parse error, its text unchanged.
    #[error("{0}")]
    PlainKey(String),
    /// A BIP-390 shape rule; the message names it.
    #[error("invalid musig key shape: {0}")]
    InvalidShape(&'static str),
    #[error("hardened derivation after aggregation")]
    HardenedDerivation,
    #[error("cosigners disagree on the multipath length")]
    MultipathMismatch,
    #[error("derivation failed: {0}")]
    Derivation(String),
    #[error("aggregation failed: {0}")]
    Aggregation(bwk_musig::Error),
}

/// Derivation after aggregation: `musig(...)/<0;1>/*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigDerivation {
    pub paths: DerivPaths,
    pub wildcard: Wildcard,
}

/// A musig() key expression before derivation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigAggregate {
    /// Written order, with origin, multipath and wildcard as written.
    cosigners: Vec<DescriptorPublicKey>,
    /// KeySort order of the cosigner keys; empty when a cosigner is ranged.
    participants: Vec<PublicKey>,
    /// KeyAgg output; None when a cosigner is ranged (derive then aggregate).
    aggregate: Option<PublicKey>,
    /// BIP-328 synthetic xpub of `aggregate`.
    synthetic_xpub: Option<Xpub>,
    derivation: Option<MusigDerivation>,
}

impl MusigAggregate {
    pub fn new(
        cosigners: Vec<DescriptorPublicKey>,
        derivation: Option<MusigDerivation>,
        network: NetworkKind,
    ) -> Result<Self, Error> {
        todo!()
    }

    pub fn cosigners(&self) -> &[DescriptorPublicKey] {
        &self.cosigners
    }

    pub fn participants(&self) -> &[PublicKey] {
        &self.participants
    }

    pub fn aggregate(&self) -> Option<PublicKey> {
        self.aggregate
    }

    pub fn synthetic_xpub(&self) -> Option<&Xpub> {
        self.synthetic_xpub.as_ref()
    }

    /// The synthetic xpub's own fingerprint, the origin of the derived aggregate.
    pub fn synthetic_fingerprint(&self) -> Option<Fingerprint> {
        todo!()
    }

    pub fn derivation(&self) -> Option<&MusigDerivation> {
        self.derivation.as_ref()
    }

    /// True when the cosigners are ranged (derive then aggregate).
    pub fn derives_cosigners(&self) -> bool {
        todo!()
    }
}

/// A BIP-390 key expression.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MusigKey {
    Plain(DescriptorPublicKey),
    Musig(MusigAggregate),
}

impl MusigKey {
    /// The plain key, or every cosigner.
    pub fn plain_keys(&self) -> Vec<&DescriptorPublicKey> {
        match self {
            MusigKey::Plain(key) => vec![key],
            MusigKey::Musig(aggregate) => aggregate.cosigners.iter().collect(),
        }
    }

    pub fn is_musig(&self) -> bool {
        match self {
            MusigKey::Plain(_) => false,
            MusigKey::Musig(_) => true,
        }
    }

    pub fn has_wildcard(&self) -> bool {
        match self {
            MusigKey::Plain(key) => key.has_wildcard(),
            MusigKey::Musig(_) => todo!(),
        }
    }

    pub fn is_multipath(&self) -> bool {
        match self {
            MusigKey::Plain(key) => key.is_multipath(),
            MusigKey::Musig(_) => todo!(),
        }
    }

    /// One key per multipath element, like `DescriptorPublicKey::into_single_keys`.
    pub fn into_single_keys(self) -> Vec<MusigKey> {
        match self {
            MusigKey::Plain(key) => key
                .into_single_keys()
                .into_iter()
                .map(MusigKey::Plain)
                .collect(),
            MusigKey::Musig(_) => todo!(),
        }
    }

    pub fn at_derivation_index(&self, index: u32) -> Result<DefiniteMusigKey, Error> {
        match self {
            MusigKey::Plain(key) => key
                .clone()
                .at_derivation_index(index)
                .map(DefiniteMusigKey::Plain)
                .map_err(|e| Error::Derivation(e.to_string())),
            MusigKey::Musig(_) => todo!(),
        }
    }

    /// Every cosigner's origin fingerprint (master fingerprint when it has none).
    pub fn master_fingerprints(&self) -> Vec<Fingerprint> {
        match self {
            MusigKey::Plain(key) => vec![key.master_fingerprint()],
            MusigKey::Musig(_) => todo!(),
        }
    }

    /// The BIP-390 text of this key.
    pub fn to_bip390_string(&self) -> String {
        match self {
            MusigKey::Plain(key) => key.to_string(),
            MusigKey::Musig(_) => todo!(),
        }
    }
}

impl From<DescriptorPublicKey> for MusigKey {
    fn from(key: DescriptorPublicKey) -> Self {
        MusigKey::Plain(key)
    }
}

/// Token form for musig, `DescriptorPublicKey` text for plain.
impl fmt::Display for MusigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MusigKey::Plain(key) => write!(f, "{key}"),
            MusigKey::Musig(_) => todo!(),
        }
    }
}

/// Accepts the token form and plain `DescriptorPublicKey` text.
impl FromStr for MusigKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(MUSIG_TOKEN_PREFIX) {
            todo!()
        } else {
            DescriptorPublicKey::from_str(s)
                .map(MusigKey::Plain)
                .map_err(|e| Error::PlainKey(e.to_string()))
        }
    }
}

impl MiniscriptKey for MusigKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        match self {
            MusigKey::Plain(key) => key.is_uncompressed(),
            MusigKey::Musig(_) => false,
        }
    }

    fn is_x_only_key(&self) -> bool {
        match self {
            MusigKey::Plain(key) => key.is_x_only_key(),
            MusigKey::Musig(_) => false,
        }
    }

    fn num_der_paths(&self) -> usize {
        match self {
            MusigKey::Plain(key) => key.num_der_paths(),
            MusigKey::Musig(_) => todo!(),
        }
    }
}

/// A musig() aggregate at one derivation index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefiniteMusigAggregate {
    /// Written order, derived at the index.
    cosigners: Vec<DefiniteDescriptorKey>,
    /// KeySort order of the derived cosigner keys: what KeyAgg took.
    participants: Vec<PublicKey>,
    /// KeyAgg output, untweaked.
    aggregate: PublicKey,
    /// BIP-32 steps after aggregation, as plain tweaks.
    tweaks: Vec<Tweak>,
    /// `aggregate` with `tweaks`: the key the script or internal key holds.
    key: PublicKey,
    /// (synthetic fingerprint, path after aggregation); None for derive then aggregate.
    origin: Option<KeySource>,
}

impl DefiniteMusigAggregate {
    pub fn cosigners(&self) -> &[DefiniteDescriptorKey] {
        &self.cosigners
    }

    pub fn participants(&self) -> &[PublicKey] {
        &self.participants
    }

    pub fn aggregate(&self) -> PublicKey {
        self.aggregate
    }

    pub fn tweaks(&self) -> &[Tweak] {
        &self.tweaks
    }

    pub fn key(&self) -> PublicKey {
        self.key
    }

    pub fn origin(&self) -> Option<&KeySource> {
        self.origin.as_ref()
    }

    /// BIP-32 tweaks then the BIP-341 taptweak, for the internal key.
    pub fn key_path_tweaks(&self, merkle_root: Option<TapNodeHash>) -> Vec<Tweak> {
        todo!()
    }

    /// KeyAgg with `tweaks` applied (script path).
    pub fn key_agg(&self) -> Result<KeyAgg<RustBitcoin>, Error> {
        todo!()
    }

    /// KeyAgg with `key_path_tweaks(merkle_root)` applied.
    pub fn key_path_key_agg(
        &self,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<KeyAgg<RustBitcoin>, Error> {
        todo!()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefiniteMusigKey {
    Plain(DefiniteDescriptorKey),
    Musig(DefiniteMusigAggregate),
}

impl DefiniteMusigKey {
    pub fn plain_keys(&self) -> Vec<&DefiniteDescriptorKey> {
        match self {
            DefiniteMusigKey::Plain(key) => vec![key],
            DefiniteMusigKey::Musig(aggregate) => aggregate.cosigners.iter().collect(),
        }
    }

    pub fn as_musig(&self) -> Option<&DefiniteMusigAggregate> {
        match self {
            DefiniteMusigKey::Plain(_) => None,
            DefiniteMusigKey::Musig(aggregate) => Some(aggregate),
        }
    }

    /// The `DefiniteDescriptorKey` miniscript's updater sees: the plain key, or the
    /// derived aggregate as a single key with `origin`.
    pub fn to_plain_definite(&self) -> Result<DefiniteDescriptorKey, Error> {
        match self {
            DefiniteMusigKey::Plain(key) => Ok(key.clone()),
            DefiniteMusigKey::Musig(_) => todo!(),
        }
    }
}

impl fmt::Display for DefiniteMusigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefiniteMusigKey::Plain(key) => write!(f, "{key}"),
            DefiniteMusigKey::Musig(_) => todo!(),
        }
    }
}

impl MiniscriptKey for DefiniteMusigKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        match self {
            DefiniteMusigKey::Plain(key) => key.is_uncompressed(),
            DefiniteMusigKey::Musig(_) => false,
        }
    }

    fn is_x_only_key(&self) -> bool {
        match self {
            DefiniteMusigKey::Plain(key) => key.is_x_only_key(),
            DefiniteMusigKey::Musig(_) => false,
        }
    }
}

impl ToPublicKey for DefiniteMusigKey {
    /// The derived aggregate for musig.
    fn to_public_key(&self) -> bitcoin::PublicKey {
        match self {
            DefiniteMusigKey::Plain(key) => key.to_public_key(),
            DefiniteMusigKey::Musig(_) => todo!(),
        }
    }

    fn to_sha256(hash: &sha256::Hash) -> sha256::Hash {
        *hash
    }

    fn to_hash256(hash: &hash256::Hash) -> hash256::Hash {
        *hash
    }

    fn to_ripemd160(hash: &ripemd160::Hash) -> ripemd160::Hash {
        *hash
    }

    fn to_hash160(hash: &hash160::Hash) -> hash160::Hash {
        *hash
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{DefiniteDescriptorKey, DescriptorPublicKey, MiniscriptKey, ToPublicKey};

    use crate::musig::{DefiniteMusigKey, MusigKey};

    const SINGLE: &str =
        "[d34db33f/86h/1h/0h]02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";
    const XPUB: &str = "[d34db33f/86h/1h/0h]tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/0/*";
    const MULTIPATH: &str = "[d34db33f/86h/1h/0h]tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x/<0;1>/*";

    #[test]
    fn plain_key_roundtrips_through_text() {
        for text in [SINGLE, XPUB, MULTIPATH] {
            let plain = DescriptorPublicKey::from_str(text).unwrap();
            let key = MusigKey::from_str(text).unwrap();
            assert_eq!(key, MusigKey::Plain(plain.clone()));
            assert_eq!(key.to_string(), plain.to_string());
        }
    }

    #[test]
    fn plain_key_queries_delegate() {
        for text in [SINGLE, XPUB, MULTIPATH] {
            let plain = DescriptorPublicKey::from_str(text).unwrap();
            let key = MusigKey::from_str(text).unwrap();
            assert!(!key.is_musig());
            assert_eq!(key.plain_keys(), vec![&plain]);
            assert_eq!(key.num_der_paths(), plain.num_der_paths());
            assert_eq!(key.has_wildcard(), plain.has_wildcard());
            assert_eq!(key.is_multipath(), plain.is_multipath());
            assert_eq!(key.is_x_only_key(), plain.is_x_only_key());
            assert_eq!(key.is_uncompressed(), plain.is_uncompressed());
            assert_eq!(key.master_fingerprints(), vec![plain.master_fingerprint()]);
            assert_eq!(key.to_bip390_string(), plain.to_string());
            let singles: Vec<MusigKey> = plain
                .clone()
                .into_single_keys()
                .into_iter()
                .map(MusigKey::Plain)
                .collect();
            assert_eq!(key.into_single_keys(), singles);
        }
    }

    #[test]
    fn plain_key_parse_error_is_miniscript_text() {
        for text in ["", "02e6", "[d34db33f]xpub"] {
            let plain = DescriptorPublicKey::from_str(text).unwrap_err();
            let key = MusigKey::from_str(text).unwrap_err();
            assert_eq!(key.to_string(), plain.to_string());
        }
    }

    #[test]
    fn plain_definite_key_to_public_key() {
        for text in [SINGLE, XPUB] {
            let plain = DescriptorPublicKey::from_str(text).unwrap();
            let key = MusigKey::from_str(text).unwrap();
            let definite: DefiniteDescriptorKey = plain.at_derivation_index(7).unwrap();
            let musig_definite = key.at_derivation_index(7).unwrap();
            assert_eq!(musig_definite, DefiniteMusigKey::Plain(definite.clone()));
            assert_eq!(musig_definite.to_public_key(), definite.to_public_key());
            assert_eq!(musig_definite.to_plain_definite().unwrap(), definite);
            assert_eq!(musig_definite.to_string(), definite.to_string());
        }
    }
}
