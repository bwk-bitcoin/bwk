//! `MusigKey`: a BIP-390 key expression, a plain key or a musig() aggregate.
//! Miniscript sees the aggregate key; signers read the cosigners.

use std::{fmt, str::FromStr, sync::LazyLock};

use bitcoin::{
    bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub},
    hashes::{hash160, ripemd160, sha256, Hash},
    secp256k1::{PublicKey, Secp256k1, VerifyOnly},
    taproot::{TapNodeHash, TapTweakHash},
    NetworkKind,
};
use bwk_musig::{rust_bitcoin::RustBitcoin, KeyAgg, Tweak, BIP328_CHAIN_CODE};
use miniscript::{
    descriptor::{DerivPaths, SinglePub, SinglePubKey, Wildcard},
    hash256, DefiniteDescriptorKey, DescriptorPublicKey, MiniscriptKey, ToPublicKey,
};

/// Prefix and separator of the paren-free token miniscript is handed.
pub const MUSIG_TOKEN_PREFIX: &str = "musig|";
pub const MUSIG_TOKEN_SEPARATOR: char = '|';

/// Start of the standard BIP-390 text, which miniscript cannot split.
const BIP390_PREFIX: &str = "musig(";

// bwk-keys alone does not enable secp256k1's global context.
static SECP: LazyLock<Secp256k1<VerifyOnly>> = LazyLock::new(Secp256k1::verification_only);

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

fn to_bytes(pk: &PublicKey) -> [u8; 33] {
    pk.serialize()
}

fn from_bytes(bytes: &[u8; 33]) -> Result<PublicKey, Error> {
    PublicKey::from_slice(bytes).map_err(|_| Error::Aggregation(bwk_musig::Error::InvalidPoint))
}

fn derive_pubkey(key: &DescriptorPublicKey) -> Result<PublicKey, Error> {
    let definite = DefiniteDescriptorKey::new(key.clone())
        .ok_or(Error::Derivation("ranged or hardened key".into()))?;
    definite
        .derive_public_key(&SECP)
        .map(|key| key.inner)
        .map_err(|e| Error::Derivation(e.to_string()))
}

/// KeySort then KeyAgg: (participants in KeySort order, aggregate).
fn aggregate_of(keys: &[PublicKey]) -> Result<(Vec<PublicKey>, PublicKey), Error> {
    let bytes: Vec<[u8; 33]> = keys.iter().map(to_bytes).collect();
    let key_agg = KeyAgg::sorted(&RustBitcoin, &bytes).map_err(Error::Aggregation)?;
    let participants = key_agg
        .participants()
        .iter()
        .map(from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((participants, from_bytes(&key_agg.aggregate())?))
}

/// The BIP-328 synthetic xpub of `aggregate`.
fn synthetic(aggregate: PublicKey, network: NetworkKind) -> Xpub {
    Xpub {
        network,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: aggregate,
        chain_code: ChainCode::from(BIP328_CHAIN_CODE),
    }
}

/// The text after `musig(...)`, e.g. `/<0;1>/*`.
fn derivation_suffix(derivation: &MusigDerivation) -> String {
    let paths = derivation.paths.paths();
    let mut suffix = String::new();
    for (i, step) in paths[0].into_iter().enumerate() {
        if paths.len() > 1 && *step != paths[1][i] {
            let steps: Vec<String> = paths.iter().map(|p| p[i].to_string()).collect();
            suffix.push_str(&format!("/<{}>", steps.join(";")));
        } else {
            suffix.push_str(&format!("/{step}"));
        }
    }
    match derivation.wildcard {
        Wildcard::None => {}
        Wildcard::Unhardened => suffix.push_str("/*"),
        Wildcard::Hardened => suffix.push_str("/*h"),
    }
    suffix
}

fn parse_step(step: &str) -> Result<ChildNumber, Error> {
    ChildNumber::from_str(step).map_err(|e| Error::Parse(format!("derivation step {step:?}: {e}")))
}

/// Parses the text after `musig(...)`; an empty text is no derivation.
fn parse_derivation(s: &str) -> Result<Option<MusigDerivation>, Error> {
    if s.is_empty() {
        return Ok(None);
    }
    let steps = s.strip_prefix('/').ok_or(Error::Parse(format!(
        "derivation {s:?} must start with '/'"
    )))?;
    let mut steps: Vec<&str> = steps.split('/').collect();
    let wildcard = match steps.last() {
        Some(&"*") => Wildcard::Unhardened,
        Some(&"*h") | Some(&"*'") => Wildcard::Hardened,
        _ => Wildcard::None,
    };
    if wildcard != Wildcard::None {
        steps.pop();
    }
    let mut prefix = Vec::new();
    let mut multipath: Option<Vec<ChildNumber>> = None;
    let mut postfix = Vec::new();
    for step in steps {
        match step.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            Some(group) => {
                if multipath.is_some() {
                    return Err(Error::Parse("more than one multipath group".into()));
                }
                let values = group
                    .split(';')
                    .map(parse_step)
                    .collect::<Result<Vec<_>, _>>()?;
                if values.len() < 2 {
                    return Err(Error::Parse(
                        "a multipath group needs two values or more".into(),
                    ));
                }
                multipath = Some(values);
            }
            None if multipath.is_some() => postfix.push(parse_step(step)?),
            None => prefix.push(parse_step(step)?),
        }
    }
    let paths: Vec<DerivationPath> = match multipath {
        None => vec![prefix.into()],
        Some(values) => values
            .into_iter()
            .map(|value| {
                let mut path = prefix.clone();
                path.push(value);
                path.extend_from_slice(&postfix);
                path.into()
            })
            .collect(),
    };
    let paths = DerivPaths::new(paths).ok_or(Error::Parse("empty derivation".into()))?;
    Ok(Some(MusigDerivation { paths, wildcard }))
}

/// The network of the first xpub cosigner; raw keys do not depend on it.
fn network_of(cosigners: &[DescriptorPublicKey]) -> NetworkKind {
    cosigners
        .iter()
        .find_map(|key| match key {
            DescriptorPublicKey::Single(_) => None,
            DescriptorPublicKey::XPub(xpub) => Some(xpub.xkey.network),
            DescriptorPublicKey::MultiXPub(xpub) => Some(xpub.xkey.network),
        })
        .unwrap_or(NetworkKind::Main)
}

fn is_ranged(cosigners: &[DescriptorPublicKey]) -> bool {
    cosigners
        .iter()
        .any(|key| key.has_wildcard() || key.is_multipath())
}

/// BIP-390: a cosigner of a `musig()` with derivation after it.
fn check_derived_cosigner(key: &DescriptorPublicKey) -> Result<(), Error> {
    match key {
        DescriptorPublicKey::Single(_) => Err(Error::InvalidShape(
            "derivation after musig() needs xpub keys",
        )),
        key if key.has_wildcard() => {
            Err(Error::InvalidShape("ranged key inside a derived musig()"))
        }
        DescriptorPublicKey::MultiXPub(_) => Err(Error::InvalidShape(
            "multipath key inside a derived musig()",
        )),
        DescriptorPublicKey::XPub(_) => Ok(()),
    }
}

/// BIP-389: the paths of a multipath derivation have one length, are distinct and
/// differ at one step only.
fn check_multipath_step(paths: &[DerivationPath]) -> Result<(), Error> {
    if paths.len() < 2 {
        return Ok(());
    }
    if paths.iter().any(|path| path.len() != paths[0].len()) {
        return Err(Error::InvalidShape("multipath paths of different lengths"));
    }
    if (1..paths.len()).any(|i| paths[..i].contains(&paths[i])) {
        return Err(Error::InvalidShape("duplicate multipath values"));
    }
    let differing = (0..paths[0].len())
        .filter(|&i| paths.iter().any(|path| path[i] != paths[0][i]))
        .count();
    if differing != 1 {
        return Err(Error::InvalidShape(
            "multipath paths must differ at exactly one step",
        ));
    }
    Ok(())
}

/// True when `key` ends with a hardened wildcard (`/*h`).
fn has_hardened_wildcard(key: &DescriptorPublicKey) -> bool {
    match key {
        DescriptorPublicKey::Single(_) => false,
        DescriptorPublicKey::XPub(xpub) => xpub.wildcard == Wildcard::Hardened,
        DescriptorPublicKey::MultiXPub(xpub) => xpub.wildcard == Wildcard::Hardened,
    }
}

/// Derivation after aggregation: `musig(...)/<0;1>/*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigDerivation {
    pub paths: DerivPaths,
    pub wildcard: Wildcard,
}

impl MusigDerivation {
    fn is_hardened(&self) -> bool {
        self.wildcard == Wildcard::Hardened
            || self
                .paths
                .paths()
                .iter()
                .any(|path| path.into_iter().any(ChildNumber::is_hardened))
    }
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
    /// Checks the BIP-390 shape rules, then KeySort and KeyAgg when no cosigner is
    /// ranged. A cosigner with a hardened step or wildcard is rejected: without its
    /// private key it can never be derived.
    pub fn new(
        cosigners: Vec<DescriptorPublicKey>,
        derivation: Option<MusigDerivation>,
        network: NetworkKind,
    ) -> Result<Self, Error> {
        if cosigners.is_empty() {
            return Err(Error::InvalidShape("musig() needs at least one key"));
        }
        for key in &cosigners {
            if key.is_x_only_key() {
                return Err(Error::InvalidShape("x-only key in musig()"));
            }
            if key.is_uncompressed() {
                return Err(Error::InvalidShape("uncompressed key in musig()"));
            }
            if key.has_hardened_step() {
                return Err(Error::InvalidShape("hardened step in a musig() key"));
            }
            if has_hardened_wildcard(key) {
                return Err(Error::InvalidShape("hardened wildcard in a musig() key"));
            }
            if let DescriptorPublicKey::MultiXPub(xpub) = key {
                check_multipath_step(xpub.derivation_paths.paths())?;
            }
        }
        match &derivation {
            Some(derivation) => {
                if derivation.is_hardened() {
                    return Err(Error::HardenedDerivation);
                }
                for key in &cosigners {
                    check_derived_cosigner(key)?;
                }
                check_multipath_step(derivation.paths.paths())?;
            }
            None => {
                let mut lengths = cosigners
                    .iter()
                    .filter(|key| key.is_multipath())
                    .map(DescriptorPublicKey::num_der_paths);
                if let Some(first) = lengths.next() {
                    if lengths.any(|len| len != first) {
                        return Err(Error::MultipathMismatch);
                    }
                }
            }
        }
        if is_ranged(&cosigners) {
            return Ok(Self {
                cosigners,
                participants: Vec::new(),
                aggregate: None,
                synthetic_xpub: None,
                derivation,
            });
        }
        let keys = cosigners
            .iter()
            .map(derive_pubkey)
            .collect::<Result<Vec<_>, _>>()?;
        let (participants, aggregate) = aggregate_of(&keys)?;
        Ok(Self {
            cosigners,
            participants,
            aggregate: Some(aggregate),
            synthetic_xpub: Some(synthetic(aggregate, network)),
            derivation,
        })
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
        self.synthetic_xpub.as_ref().map(Xpub::fingerprint)
    }

    pub fn derivation(&self) -> Option<&MusigDerivation> {
        self.derivation.as_ref()
    }

    /// True when the cosigners are ranged (derive then aggregate).
    pub fn derives_cosigners(&self) -> bool {
        is_ranged(&self.cosigners)
    }

    fn joined_cosigners(&self, separator: &str) -> String {
        let keys: Vec<String> = self.cosigners.iter().map(ToString::to_string).collect();
        keys.join(separator)
    }

    fn suffix(&self) -> String {
        self.derivation
            .as_ref()
            .map(derivation_suffix)
            .unwrap_or_default()
    }

    fn into_single_aggregates(self) -> Vec<MusigAggregate> {
        if let Some(derivation) = &self.derivation {
            if derivation.paths.paths().len() > 1 {
                return derivation
                    .paths
                    .paths()
                    .iter()
                    .filter_map(|path| DerivPaths::new(vec![path.clone()]))
                    .map(|paths| MusigAggregate {
                        derivation: Some(MusigDerivation {
                            paths,
                            wildcard: derivation.wildcard,
                        }),
                        ..self.clone()
                    })
                    .collect();
            }
        }
        let count = self
            .cosigners
            .iter()
            .map(DescriptorPublicKey::num_der_paths)
            .max()
            .unwrap_or(0);
        if count < 2 {
            return vec![self];
        }
        let network = network_of(&self.cosigners);
        let split: Vec<Vec<DescriptorPublicKey>> = self
            .cosigners
            .into_iter()
            .map(DescriptorPublicKey::into_single_keys)
            .collect();
        (0..count)
            .map(|i| {
                let cosigners = split
                    .iter()
                    .map(|keys| keys.get(i).unwrap_or(&keys[0]).clone())
                    .collect();
                // Split keys are derivable; only BIP-32 or KeyAgg could fail, with
                // negligible probability.
                MusigAggregate::new(cosigners, None, network)
                    .expect("a split of a valid musig() is valid")
            })
            .collect()
    }

    fn at_derivation_index(&self, index: u32) -> Result<DefiniteMusigAggregate, Error> {
        let cosigners = self
            .cosigners
            .iter()
            .map(|key| {
                key.clone()
                    .at_derivation_index(index)
                    .map_err(|e| Error::Derivation(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        match &self.derivation {
            Some(derivation) => self.derive_aggregate(cosigners, derivation, index),
            None => {
                let (participants, aggregate) = match self.aggregate {
                    Some(aggregate) => (self.participants.clone(), aggregate),
                    None => {
                        let keys = cosigners
                            .iter()
                            .map(|key| {
                                key.derive_public_key(&SECP)
                                    .map(|key| key.inner)
                                    .map_err(|e| Error::Derivation(e.to_string()))
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        aggregate_of(&keys)?
                    }
                };
                // Bitcoin Core lists a static aggregate with the synthetic fingerprint
                // and an empty path; derive then aggregate has no synthetic xpub.
                let origin = self
                    .synthetic_fingerprint()
                    .map(|fingerprint| (fingerprint, DerivationPath::master()));
                Ok(DefiniteMusigAggregate {
                    cosigners,
                    participants,
                    aggregate,
                    tweaks: Vec::new(),
                    key: aggregate,
                    origin,
                })
            }
        }
    }

    /// Aggregate then derive: BIP-32 from the synthetic xpub (BIP-328).
    fn derive_aggregate(
        &self,
        cosigners: Vec<DefiniteDescriptorKey>,
        derivation: &MusigDerivation,
        index: u32,
    ) -> Result<DefiniteMusigAggregate, Error> {
        let [path] = derivation.paths.paths().as_slice() else {
            return Err(Error::Derivation(
                "multipath key: split it with into_single_keys first".into(),
            ));
        };
        let path = match derivation.wildcard {
            Wildcard::None => path.clone(),
            Wildcard::Unhardened => path.child(
                ChildNumber::from_normal_idx(index)
                    .map_err(|e| Error::Derivation(e.to_string()))?,
            ),
            Wildcard::Hardened => return Err(Error::HardenedDerivation),
        };
        let (Some(aggregate), Some(synthetic_xpub)) = (self.aggregate, self.synthetic_xpub) else {
            return Err(Error::Derivation("no aggregate to derive from".into()));
        };
        let mut xpub = synthetic_xpub;
        let mut tweaks = Vec::with_capacity(path.len());
        for step in &path {
            let (il, _) = xpub
                .ckd_pub_tweak(*step)
                .map_err(|e| Error::Derivation(e.to_string()))?;
            tweaks.push(Tweak {
                scalar: il.secret_bytes(),
                x_only: false,
            });
            xpub = xpub
                .ckd_pub(&SECP, *step)
                .map_err(|e| Error::Derivation(e.to_string()))?;
        }
        Ok(DefiniteMusigAggregate {
            cosigners,
            participants: self.participants.clone(),
            aggregate,
            tweaks,
            key: xpub.public_key,
            origin: Some((synthetic_xpub.fingerprint(), path)),
        })
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
            MusigKey::Musig(aggregate) => {
                aggregate
                    .derivation
                    .as_ref()
                    .is_some_and(|derivation| derivation.wildcard != Wildcard::None)
                    || aggregate
                        .cosigners
                        .iter()
                        .any(DescriptorPublicKey::has_wildcard)
            }
        }
    }

    pub fn is_multipath(&self) -> bool {
        match self {
            MusigKey::Plain(key) => key.is_multipath(),
            MusigKey::Musig(aggregate) => {
                aggregate
                    .derivation
                    .as_ref()
                    .is_some_and(|derivation| derivation.paths.paths().len() > 1)
                    || aggregate
                        .cosigners
                        .iter()
                        .any(DescriptorPublicKey::is_multipath)
            }
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
            MusigKey::Musig(aggregate) => aggregate
                .into_single_aggregates()
                .into_iter()
                .map(MusigKey::Musig)
                .collect(),
        }
    }

    pub fn at_derivation_index(&self, index: u32) -> Result<DefiniteMusigKey, Error> {
        match self {
            MusigKey::Plain(key) => key
                .clone()
                .at_derivation_index(index)
                .map(DefiniteMusigKey::Plain)
                .map_err(|e| Error::Derivation(e.to_string())),
            MusigKey::Musig(aggregate) => aggregate
                .at_derivation_index(index)
                .map(DefiniteMusigKey::Musig),
        }
    }

    /// Every cosigner's origin fingerprint (master fingerprint when it has none).
    pub fn master_fingerprints(&self) -> Vec<Fingerprint> {
        self.plain_keys()
            .into_iter()
            .map(DescriptorPublicKey::master_fingerprint)
            .collect()
    }

    /// The BIP-390 text of this key.
    pub fn to_bip390_string(&self) -> String {
        match self {
            MusigKey::Plain(key) => key.to_string(),
            MusigKey::Musig(aggregate) => format!(
                "{BIP390_PREFIX}{}){}",
                aggregate.joined_cosigners(","),
                aggregate.suffix()
            ),
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
            MusigKey::Musig(aggregate) => write!(
                f,
                "{MUSIG_TOKEN_PREFIX}{}{MUSIG_TOKEN_SEPARATOR}{}",
                aggregate.joined_cosigners(&MUSIG_TOKEN_SEPARATOR.to_string()),
                aggregate.suffix()
            ),
        }
    }
}

/// Accepts the token form and plain `DescriptorPublicKey` text.
impl FromStr for MusigKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(BIP390_PREFIX) {
            return Err(Error::Parse(
                "BIP-390 text: convert it to the token form".into(),
            ));
        }
        let Some(token) = s.strip_prefix(MUSIG_TOKEN_PREFIX) else {
            return DescriptorPublicKey::from_str(s)
                .map(MusigKey::Plain)
                .map_err(|e| Error::PlainKey(e.to_string()));
        };
        let (keys, suffix) = token
            .rsplit_once(MUSIG_TOKEN_SEPARATOR)
            .ok_or(Error::Parse(
                "missing the separator closing the keys".into(),
            ))?;
        let cosigners = keys
            .split(MUSIG_TOKEN_SEPARATOR)
            .map(|key| {
                if key.is_empty() {
                    return Err(Error::Parse("empty key".into()));
                }
                DescriptorPublicKey::from_str(key).map_err(|e| Error::Parse(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let derivation = parse_derivation(suffix)?;
        let network = network_of(&cosigners);
        MusigAggregate::new(cosigners, derivation, network).map(MusigKey::Musig)
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
            MusigKey::Musig(aggregate) => match &aggregate.derivation {
                Some(derivation) => derivation.paths.paths().len(),
                None => aggregate
                    .cosigners
                    .iter()
                    .map(DescriptorPublicKey::num_der_paths)
                    .max()
                    .unwrap_or(0),
            },
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
        let taptweak =
            TapTweakHash::from_key_and_tweak(self.key.x_only_public_key().0, merkle_root);
        let mut tweaks = self.tweaks.clone();
        // KeyAgg's x-only tweak handles the parity of the internal key (BIP-327).
        tweaks.push(Tweak {
            scalar: taptweak.to_byte_array(),
            x_only: true,
        });
        tweaks
    }

    /// KeyAgg with `tweaks` applied (script path).
    pub fn key_agg(&self) -> Result<KeyAgg<RustBitcoin>, Error> {
        self.key_agg_with(&self.tweaks)
    }

    /// KeyAgg with `key_path_tweaks(merkle_root)` applied.
    pub fn key_path_key_agg(
        &self,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<KeyAgg<RustBitcoin>, Error> {
        self.key_agg_with(&self.key_path_tweaks(merkle_root))
    }

    /// `participants` are already in KeySort order: aggregated as stored.
    fn key_agg_with(&self, tweaks: &[Tweak]) -> Result<KeyAgg<RustBitcoin>, Error> {
        let participants: Vec<[u8; 33]> = self.participants.iter().map(to_bytes).collect();
        KeyAgg::new(&RustBitcoin, &participants)
            .and_then(|key_agg| key_agg.with_tweaks(&RustBitcoin, tweaks))
            .map_err(Error::Aggregation)
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
    /// derived aggregate as a single key with `origin`. The key path and the script
    /// path both start from this key.
    pub fn to_plain_definite(&self) -> Result<DefiniteDescriptorKey, Error> {
        match self {
            DefiniteMusigKey::Plain(key) => Ok(key.clone()),
            DefiniteMusigKey::Musig(aggregate) => {
                DefiniteDescriptorKey::new(DescriptorPublicKey::Single(SinglePub {
                    origin: aggregate.origin.clone(),
                    key: SinglePubKey::FullKey(bitcoin::PublicKey::new(aggregate.key)),
                }))
                .ok_or(Error::Derivation("aggregate key is not definite".into()))
            }
        }
    }
}

/// Token form of the derived cosigners, then the path after aggregation.
impl fmt::Display for DefiniteMusigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DefiniteMusigKey::Plain(key) => write!(f, "{key}"),
            DefiniteMusigKey::Musig(aggregate) => {
                f.write_str(MUSIG_TOKEN_PREFIX)?;
                for key in &aggregate.cosigners {
                    write!(f, "{key}{MUSIG_TOKEN_SEPARATOR}")?;
                }
                if let Some((_, path)) = &aggregate.origin {
                    for step in path {
                        write!(f, "/{step}")?;
                    }
                }
                Ok(())
            }
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

    fn num_der_paths(&self) -> usize {
        match self {
            DefiniteMusigKey::Plain(key) => key.num_der_paths(),
            DefiniteMusigKey::Musig(_) => 0,
        }
    }
}

impl ToPublicKey for DefiniteMusigKey {
    /// The derived aggregate for musig.
    fn to_public_key(&self) -> bitcoin::PublicKey {
        match self {
            DefiniteMusigKey::Plain(key) => key.to_public_key(),
            DefiniteMusigKey::Musig(aggregate) => bitcoin::PublicKey::new(aggregate.key),
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

    use bitcoin::{
        bip32::{DerivationPath, Fingerprint, Xpub},
        hashes::Hash,
        key::TapTweak,
        secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey},
        taproot::TapNodeHash,
        NetworkKind,
    };
    use miniscript::{
        descriptor::{DerivPaths, SinglePub, SinglePubKey, Wildcard},
        DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, MiniscriptKey, ToPublicKey,
    };

    use crate::musig::{
        synthetic, DefiniteMusigAggregate, DefiniteMusigKey, Error, MusigAggregate,
        MusigDerivation, MusigKey,
    };

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

    // BIP-390 test vector xpubs.
    const X1: &str = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
    const X2: &str = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
    // BIP-373 MuSig2 participants, also the BIP-390 raw keys.
    const P1: &str = "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00";
    const P2: &str = "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c";
    const P3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const R2: &str = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
    const R3: &str = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66";
    // (aggregate_pubkey, xpub) of bip-0328/vectors.json.
    const BIP328_VECTORS: [(&str, &str); 3] = [
        (
            "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
        ),
        (
            "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
        ),
        (
            "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
            "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
        ),
    ];

    fn token(keys: &[&str], suffix: &str) -> String {
        format!("musig|{}|{suffix}", keys.join("|"))
    }

    fn musig(keys: &[&str], suffix: &str) -> MusigKey {
        MusigKey::from_str(&token(keys, suffix)).unwrap()
    }

    fn musig_err(keys: &[&str], suffix: &str) -> Error {
        MusigKey::from_str(&token(keys, suffix)).unwrap_err()
    }

    fn aggregate(key: &MusigKey) -> &MusigAggregate {
        match key {
            MusigKey::Musig(aggregate) => aggregate,
            MusigKey::Plain(_) => panic!(),
        }
    }

    fn definite(key: &MusigKey, index: u32) -> DefiniteMusigAggregate {
        key.at_derivation_index(index)
            .unwrap()
            .as_musig()
            .unwrap()
            .clone()
    }

    fn pubkey(hex: &str) -> PublicKey {
        PublicKey::from_str(hex).unwrap()
    }

    fn x_only(key: [u8; 33]) -> XOnlyPublicKey {
        PublicKey::from_slice(&key).unwrap().x_only_public_key().0
    }

    /// The output key of a `5120` P2TR scriptPubKey.
    fn p2tr_xonly(spk: &str) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(spk.strip_prefix("5120").unwrap()).unwrap()
    }

    fn path(s: &str) -> DerivationPath {
        DerivationPath::from_str(s).unwrap()
    }

    fn derive_xpub(xpub: &Xpub, p: &str) -> PublicKey {
        xpub.derive_pub(&Secp256k1::verification_only(), &path(p))
            .unwrap()
            .public_key
    }

    #[test]
    fn token_round_trips_through_display_and_from_str() {
        let o1 = format!("[d34db33f/87'/0'/0'/2]{X1}");
        let o2 = format!("[d34db33f/87'/0'/0'/2]{X2}");
        for s in [
            X1.to_string(),
            token(&[P1, P2, P3], ""),
            token(&[X1, X2], "/*"),
            token(&[X1, X2], "/<0;1>/*"),
            token(&[&o1, &o2], "/<0;1>/*"),
        ] {
            assert_eq!(MusigKey::from_str(&s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn plain_key_parses_as_plain() {
        let key = MusigKey::from_str(X1).unwrap();
        let plain = DescriptorPublicKey::from_str(X1).unwrap();
        assert_eq!(key, MusigKey::Plain(plain.clone()));
        assert!(!key.is_musig());
        assert_eq!(key.plain_keys(), vec![&plain]);
    }

    #[test]
    fn bip390_string_uses_standard_form() {
        let key = musig(&[X1, X2], "/<0;1>/*");
        assert_eq!(key.to_bip390_string(), format!("musig({X1},{X2})/<0;1>/*"));
        assert_eq!(MusigKey::from_str(X1).unwrap().to_bip390_string(), X1);
        assert!(matches!(
            MusigKey::from_str(&key.to_bip390_string()),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn participants_are_key_sorted_and_cosigners_keep_written_order() {
        let key = musig(&[P3, P1, P2], "");
        let cosigners: Vec<String> = aggregate(&key)
            .cosigners()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(cosigners, vec![P3, P1, P2]);
        assert_eq!(
            aggregate(&key).participants(),
            &[pubkey(P1), pubkey(P2), pubkey(P3)]
        );
    }

    #[test]
    fn bip373_aggregate_and_synthetic_fingerprint() {
        let key = musig(&[P1, P2, P3], "");
        let fingerprint = Fingerprint::from_str("2680dd6e").unwrap();
        assert_eq!(
            aggregate(&key).aggregate(),
            Some(pubkey(
                "030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4"
            ))
        );
        assert_eq!(aggregate(&key).synthetic_fingerprint(), Some(fingerprint));
        let derived = definite(&key, 0);
        assert_eq!(
            derived.origin(),
            Some(&(fingerprint, DerivationPath::master()))
        );
        assert_eq!(
            x_only(derived.key_path_key_agg(None).unwrap().output_key()),
            XOnlyPublicKey::from_str(
                "2967d2d020a9795da72b51be4f3fca25bb0e57e91c5b3e7a81abfa7232a34942"
            )
            .unwrap()
        );
    }

    #[test]
    fn bip328_synthetic_xpub_matches_vectors() {
        for (aggregate, xpub) in BIP328_VECTORS {
            assert_eq!(
                synthetic(pubkey(aggregate), NetworkKind::Main).to_string(),
                xpub
            );
        }
    }

    #[test]
    fn bip390_tr_key_path_vectors() {
        let x1_1 = format!("{X1}/1");
        for (key, spk) in [
            (
                musig(&[P3, R2, R3], ""),
                "512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312",
            ),
            (
                musig(&[&x1_1, &x1_1], "/2"),
                "5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c",
            ),
        ] {
            let output = definite(&key, 0)
                .key_path_key_agg(None)
                .unwrap()
                .output_key();
            assert_eq!(x_only(output), p2tr_xonly(spk));
        }
    }

    #[test]
    fn bip390_rawtr_ranged_vectors() {
        let key = musig(&[X1, X2], "/0/*");
        let fingerprint = aggregate(&key).synthetic_fingerprint().unwrap();
        for (i, spk) in [
            "51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc",
            "51205ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298",
            "51207dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166",
        ]
        .into_iter()
        .enumerate()
        {
            let derived = key.at_derivation_index(i as u32).unwrap();
            let derived = derived.as_musig().unwrap();
            assert_eq!(derived.key().x_only_public_key().0, p2tr_xonly(spk));
            assert_eq!(
                derived.origin(),
                Some(&(fingerprint, path(&format!("m/0/{i}"))))
            );
        }
    }

    #[test]
    fn bip390_invalid_key_shapes() {
        let x1_ranged = format!("{X1}/*");
        let x2_ranged = format!("{X2}/*");
        let x1_multipath = format!("{X1}/<0;1>");
        let x1_hardened = format!("{X1}/0h");
        let x1_hardened_wildcard = format!("{X1}/0/*h");
        let x1_same_branches = format!("{X1}/<0;0>/*");
        let x2_multipath = format!("{X2}/<0;1>/*");
        let x_only_key = &P3[2..];
        for (err, expected) in [
            (
                musig_err(&[P3, R2, R3], "/0/0"),
                Error::InvalidShape("derivation after musig() needs xpub keys"),
            ),
            (
                musig_err(&[&x1_ranged, X2], "/0/*"),
                Error::InvalidShape("ranged key inside a derived musig()"),
            ),
            (
                musig_err(&[&x1_multipath, X2], "/<2;3>"),
                Error::InvalidShape("multipath key inside a derived musig()"),
            ),
            (musig_err(&[X1, X2], "/0h/*"), Error::HardenedDerivation),
            (musig_err(&[X1, X2], "/0/*h"), Error::HardenedDerivation),
            (
                musig_err(&[&x1_ranged, &x2_ranged], "/1/2"),
                Error::InvalidShape("ranged key inside a derived musig()"),
            ),
            (
                MusigKey::from_str("musig||").unwrap_err(),
                Error::Parse("empty key".into()),
            ),
            (
                musig_err(&[x_only_key, P1], ""),
                Error::InvalidShape("x-only key in musig()"),
            ),
            (
                musig_err(&[X1, X2], "/<0;0;1>/*"),
                Error::InvalidShape("duplicate multipath values"),
            ),
            (
                musig_err(&[X1, X2], "/<0;0>/*"),
                Error::InvalidShape("duplicate multipath values"),
            ),
            (
                musig_err(&[&x1_hardened, X2], ""),
                Error::InvalidShape("hardened step in a musig() key"),
            ),
            (
                musig_err(&[&x1_hardened_wildcard, X2], ""),
                Error::InvalidShape("hardened wildcard in a musig() key"),
            ),
            (
                musig_err(&[&x1_same_branches, &x2_multipath], ""),
                Error::InvalidShape("duplicate multipath values"),
            ),
        ] {
            assert_eq!(err, expected);
        }
    }

    #[test]
    fn multipath_derivation_shape_is_checked() {
        let keys = vec![
            DescriptorPublicKey::from_str(X1).unwrap(),
            DescriptorPublicKey::from_str(X2).unwrap(),
        ];
        for (paths, expected) in [
            (
                vec![path("m/0/1"), path("m/1/2")],
                "multipath paths must differ at exactly one step",
            ),
            (
                vec![path("m/0"), path("m/1/2")],
                "multipath paths of different lengths",
            ),
        ] {
            let derivation = MusigDerivation {
                paths: DerivPaths::new(paths).unwrap(),
                wildcard: Wildcard::Unhardened,
            };
            assert_eq!(
                MusigAggregate::new(keys.clone(), Some(derivation), NetworkKind::Main),
                Err(Error::InvalidShape(expected))
            );
        }
    }

    #[test]
    fn key_agg_tweaks_reproduce_derived_key() {
        let singles = musig(&[X1, X2], "/<0;1>/*").into_single_keys();
        assert_eq!(singles.len(), 2);
        for (i, single) in singles.iter().enumerate() {
            let derived = definite(single, 7);
            assert_eq!(
                derived.key_agg().unwrap().output_key(),
                derived.key().serialize()
            );
            let xpub = aggregate(single).synthetic_xpub().unwrap();
            assert_eq!(derived.key(), derive_xpub(xpub, &format!("m/{i}/7")));
        }
    }

    #[test]
    fn key_path_key_agg_matches_rust_bitcoin_taptweak() {
        let single = musig(&[X1, X2], "/<0;1>/*").into_single_keys().remove(0);
        let derived = definite(&single, 7);
        let root = TapNodeHash::from_byte_array([7; 32]);
        let expected = derived
            .key()
            .x_only_public_key()
            .0
            .tap_tweak(&Secp256k1::verification_only(), Some(root))
            .0
            .to_x_only_public_key();
        let output = derived.key_path_key_agg(Some(root)).unwrap().output_key();
        assert_eq!(x_only(output), expected);
    }

    #[test]
    fn derive_then_aggregate_has_no_aggregate_until_derived() {
        let key = musig(&[&format!("{X1}/0/*"), &format!("{X2}/0/*")], "");
        let unresolved = aggregate(&key);
        assert_eq!(unresolved.aggregate(), None);
        assert_eq!(unresolved.synthetic_xpub(), None);
        assert!(unresolved.derives_cosigners());
        assert!(unresolved.participants().is_empty());
        let derived = definite(&key, 3);
        let mut expected = vec![
            derive_xpub(&Xpub::from_str(X1).unwrap(), "m/0/3").serialize(),
            derive_xpub(&Xpub::from_str(X2).unwrap(), "m/0/3").serialize(),
        ];
        expected.sort();
        let participants: Vec<[u8; 33]> = derived
            .participants()
            .iter()
            .map(PublicKey::serialize)
            .collect();
        assert_eq!(participants, expected);
        assert_eq!(derived.aggregate(), derived.key());
        assert!(derived.tweaks().is_empty());
        assert_eq!(derived.origin(), None);
    }

    #[test]
    fn into_single_keys_splits_multipath() {
        let key = musig(&[X1, X2], "/<0;1>/*");
        assert_eq!(key.num_der_paths(), 2);
        assert!(key.is_multipath());
        let singles = key.clone().into_single_keys();
        let texts: Vec<String> = singles.iter().map(ToString::to_string).collect();
        assert_eq!(
            texts,
            vec![token(&[X1, X2], "/0/*"), token(&[X1, X2], "/1/*")]
        );
        for single in &singles {
            assert_eq!(aggregate(single).aggregate(), aggregate(&key).aggregate());
        }

        let multipath = [format!("{X1}/<0;1>/*"), format!("{X2}/<0;1>/*")];
        let key = musig(&[&multipath[0], &multipath[1]], "");
        let singles = key.into_single_keys();
        let texts: Vec<String> = singles.iter().map(ToString::to_string).collect();
        assert_eq!(
            texts,
            vec![
                token(&[&format!("{X1}/0/*"), &format!("{X2}/0/*")], ""),
                token(&[&format!("{X1}/1/*"), &format!("{X2}/1/*")], ""),
            ]
        );
        assert!(singles
            .iter()
            .all(|single| aggregate(single).derives_cosigners()));
    }

    #[test]
    fn multipath_mismatch_is_rejected() {
        let k1 = format!("{X1}/<0;1>/*");
        let k2 = format!("{X2}/<0;1;2>/*");
        assert_eq!(musig_err(&[&k1, &k2], ""), Error::MultipathMismatch);
    }

    #[test]
    fn at_derivation_index_rejects_multipath() {
        let key = musig(&[X1, X2], "/<0;1>/*");
        assert!(matches!(
            key.at_derivation_index(0),
            Err(Error::Derivation(_))
        ));
    }

    #[test]
    fn to_plain_definite_carries_origin() {
        let key = musig(&[X1, X2], "/0/*");
        let fingerprint = aggregate(&key).synthetic_fingerprint().unwrap();
        let derived = key.at_derivation_index(1).unwrap();
        let expected = DefiniteDescriptorKey::new(DescriptorPublicKey::Single(SinglePub {
            origin: Some((fingerprint, path("m/0/1"))),
            key: SinglePubKey::FullKey(bitcoin::PublicKey::new(derived.as_musig().unwrap().key())),
        }))
        .unwrap();
        assert_eq!(derived.to_plain_definite().unwrap(), expected);

        let plain = format!("{X1}/0/*");
        let definite_plain = DescriptorPublicKey::from_str(&plain)
            .unwrap()
            .at_derivation_index(1)
            .unwrap();
        let derived = MusigKey::from_str(&plain)
            .unwrap()
            .at_derivation_index(1)
            .unwrap();
        assert_eq!(derived.to_plain_definite().unwrap(), definite_plain);
    }

    #[test]
    fn to_public_key_is_derived_aggregate() {
        let derived = musig(&[X1, X2], "/0/*").at_derivation_index(1).unwrap();
        assert_eq!(
            ToPublicKey::to_public_key(&derived),
            bitcoin::PublicKey::new(derived.as_musig().unwrap().key())
        );

        let plain = DescriptorPublicKey::from_str(&format!("{X1}/0/*"))
            .unwrap()
            .at_derivation_index(1)
            .unwrap();
        let derived = DefiniteMusigKey::Plain(plain.clone());
        assert_eq!(
            ToPublicKey::to_public_key(&derived),
            plain
                .derive_public_key(&Secp256k1::verification_only())
                .unwrap()
        );
    }

    #[test]
    fn master_fingerprints_lists_cosigners() {
        let k1 = format!("[aaaaaaaa/87'/0'/0'/2]{X1}");
        let k2 = format!("[bbbbbbbb/87'/0'/0'/2]{X2}");
        assert_eq!(
            musig(&[&k1, &k2], "/<0;1>/*").master_fingerprints(),
            vec![
                Fingerprint::from_str("aaaaaaaa").unwrap(),
                Fingerprint::from_str("bbbbbbbb").unwrap(),
            ]
        );
        assert_eq!(
            MusigKey::from_str(X1).unwrap().master_fingerprints(),
            vec![Xpub::from_str(X1).unwrap().fingerprint()]
        );
    }

    #[test]
    fn miniscript_descriptor_round_trips_token_form() {
        for text in [
            format!("tr({})", token(&[X1, X2], "/<0;1>/*")),
            format!("tr({P3},pk({}))", token(&[X1, X2], "/0/*")),
        ] {
            let descriptor = Descriptor::<MusigKey>::from_str(&text).unwrap();
            let printed = descriptor.to_string();
            assert_eq!(printed.split('#').next().unwrap(), text);
        }
    }
}
