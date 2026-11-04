//! Taproot descriptor and template on rust-miniscript. The wallet descriptor
//! stays with the signing key holder and the coordinator: it carries every key's
//! chain code and fixed derivation steps. The delegator only ever gets the
//! template, the same descriptor with every key reduced to its base key and
//! slot number.
//! Only `tr()` with multipath extended keys (`<a;b>/*`) over non-hardened
//! steps is accepted, because the tweak path must be derivable without
//! private keys.

use core::{fmt, str::FromStr};

use crate::{
    backend::Xpub,
    slot::{self, DescriptorSlot, Slot},
    Error,
};
use miniscript::{
    bitcoin::{
        bip32::ChildNumber,
        hashes::{hash160, ripemd160, sha256, Hash},
        key::ParsePublicKeyError,
        taproot::LeafVersion,
        PublicKey, TapLeafHash,
    },
    descriptor::{Tr, Wildcard},
    hash256, translate_hash_clone, Descriptor, DescriptorPublicKey, ForEachKey, MiniscriptKey,
    TranslateErr, TranslatePk, Translator,
};

/// A key of the template: a base key and one of its slot numbers. Slot 0 is
/// written as the bare key, so a template whose keys all have one slot is the
/// plain descriptor over base keys. Slot N above 0 is written `KEY@N`, N in
/// decimal with no leading zero: a number, never a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateKey {
    pub key: PublicKey,
    pub slot: u8,
}

impl TemplateKey {
    fn to_slot(self) -> Slot {
        Slot {
            key: self.key.inner.serialize(),
            number: self.slot,
        }
    }
}

impl fmt::Display for TemplateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.slot {
            0 => write!(f, "{}", self.key),
            slot => write!(f, "{}@{}", self.key, slot),
        }
    }
}

/// Why a template key does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateKeyError {
    /// The part before `@` is not a public key.
    Key(ParsePublicKeyError),
    /// The part after `@` is not a decimal number from 1 to 255 with no
    /// leading zero.
    Slot,
}

impl fmt::Display for TemplateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateKeyError::Key(e) => write!(f, "invalid template key: {e}"),
            TemplateKeyError::Slot => write!(f, "invalid template key slot"),
        }
    }
}

impl FromStr for TemplateKey {
    type Err = TemplateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key, slot) = match s.split_once('@') {
            None => (s, 0),
            Some((key, slot)) => (key, parse_slot(slot)?),
        };
        let key = PublicKey::from_str(key).map_err(TemplateKeyError::Key)?;
        Ok(TemplateKey { key, slot })
    }
}

/// The slot after `@`: 1 to 255, digits only, no leading zero, so each slot
/// has one spelling and slot 0 has none.
fn parse_slot(s: &str) -> Result<u8, TemplateKeyError> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TemplateKeyError::Slot);
    }
    s.parse().map_err(|_| TemplateKeyError::Slot)
}

impl MiniscriptKey for TemplateKey {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn is_uncompressed(&self) -> bool {
        self.key.is_uncompressed()
    }
}

struct TweakTranslator<'a> {
    tweaked: &'a [(Slot, [u8; 33])],
}

impl Translator<TemplateKey, PublicKey, Error> for TweakTranslator<'_> {
    fn pk(&mut self, pk: &TemplateKey) -> Result<PublicKey, Error> {
        let slot = pk.to_slot();
        let pos = self
            .tweaked
            .binary_search_by(|(base, _)| base.cmp(&slot))
            .map_err(|_| Error::MissingTweak)?;
        PublicKey::from_slice(&self.tweaked[pos].1).map_err(|_| Error::InvalidPoint)
    }

    translate_hash_clone!(TemplateKey, PublicKey, Error);
}

/// Replaces each key expression with its template key: its base key and the
/// number of its slot among `slots`.
struct SlotTranslator {
    slots: Vec<DescriptorSlot>,
}

impl Translator<DescriptorPublicKey, TemplateKey, Error> for SlotTranslator {
    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<TemplateKey, Error> {
        let xpub = xpub_from_key(pk)?;
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.xpub == xpub)
            .ok_or(Error::Template)?;
        let key = PublicKey::from_slice(&xpub.key).map_err(|_| Error::InvalidPoint)?;
        Ok(TemplateKey {
            key,
            slot: slot.number,
        })
    }

    translate_hash_clone!(DescriptorPublicKey, TemplateKey, Error);
}

/// A translator error as is; a miniscript error on the translated `tr()` is
/// `Template`.
fn translate_err(e: TranslateErr<Error>) -> Error {
    match e {
        TranslateErr::TranslatorErr(e) => e,
        TranslateErr::OuterError(_) => Error::Template,
    }
}

/// The template of `d`: its `tr()` with every key reduced to its template
/// key.
pub(crate) fn template(d: &Descriptor<DescriptorPublicKey>) -> Result<Tr<TemplateKey>, Error> {
    let slots = slot::slots(xpubs(d)?)?;
    let Descriptor::Tr(tr) = d else {
        return Err(Error::NotTaproot);
    };
    tr.translate_pk(&mut SlotTranslator { slots })
        .map_err(translate_err)
}

/// The `tr()` of template `t` with each template key replaced by its tweaked
/// key.
pub(crate) fn tweak_template(
    t: &Descriptor<TemplateKey>,
    tweaked: &[(Slot, [u8; 33])],
) -> Result<Tr<PublicKey>, Error> {
    let Descriptor::Tr(tr) = t else {
        return Err(Error::NotTaproot);
    };
    tr.translate_pk(&mut TweakTranslator { tweaked })
        .map_err(translate_err)
}

pub(crate) fn slots(t: &Descriptor<TemplateKey>) -> Vec<Slot> {
    let mut slots = Vec::new();
    t.for_each_key(|pk| {
        slots.push(pk.to_slot());
        true
    });
    slots.sort();
    slots.dedup();
    slots
}

pub(crate) fn leaf_hashes(
    t: &Descriptor<TemplateKey>,
    tweaked: &[(Slot, [u8; 33])],
    key: &[u8; 33],
) -> Result<Vec<[u8; 32]>, Error> {
    let target = PublicKey::from_slice(key).map_err(|_| Error::InvalidPoint)?;
    let tr = tweak_template(t, tweaked)?;
    Ok(tr
        .iter_scripts()
        .filter(|(_, ms)| ms.iter_pk().any(|pk| pk == target))
        .map(|(_, ms)| {
            TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript).to_byte_array()
        })
        .collect())
}

fn xpub_from_key(pk: &DescriptorPublicKey) -> Result<Xpub, Error> {
    let DescriptorPublicKey::MultiXPub(x) = pk else {
        return Err(Error::KeyType);
    };
    let paths = x.derivation_paths.paths();
    if paths.len() != 2 {
        return Err(Error::Multipath);
    }
    if x.wildcard != Wildcard::Unhardened {
        return Err(Error::Wildcard);
    }
    let mut branches: [Vec<u32>; 2] = [Vec::new(), Vec::new()];
    for (branch, path) in branches.iter_mut().zip(paths.iter()) {
        for step in path.as_ref() {
            match step {
                ChildNumber::Normal { index } => branch.push(*index),
                ChildNumber::Hardened { .. } => return Err(Error::HardenedStep),
            }
        }
    }
    Ok(Xpub {
        key: x.xkey.public_key.serialize(),
        chain_code: *x.xkey.chain_code.as_bytes(),
        branches,
    })
}

/// Validates `d` and returns its keys sorted by base key, an identical key
/// repeated only once.
pub(crate) fn xpubs(d: &Descriptor<DescriptorPublicKey>) -> Result<Vec<Xpub>, Error> {
    if !matches!(d, Descriptor::Tr(_)) {
        return Err(Error::NotTaproot);
    }
    let mut keys = Vec::new();
    d.for_each_key(|pk| {
        keys.push(pk.clone());
        true
    });

    let mut entries = Vec::with_capacity(keys.len());
    for pk in &keys {
        entries.push(xpub_from_key(pk)?);
    }
    if entries.is_empty() {
        return Err(Error::NoKeys);
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));

    let mut deduped: Vec<Xpub> = Vec::with_capacity(entries.len());
    for entry in entries {
        match deduped.last() {
            Some(prev) if prev.key == entry.key => {
                if *prev != entry {
                    return Err(Error::ConflictingKey);
                }
            }
            _ => deduped.push(entry),
        }
    }
    Ok(deduped)
}
