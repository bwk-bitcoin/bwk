//! Taproot descriptor and template on rust-miniscript. The wallet descriptor
//! stays with the signing key holder and the coordinator: it carries every key's
//! chain code and fixed derivation steps. The delegator only ever gets the
//! template, the same descriptor with every key reduced to its base key.
//! Only `tr()` with multipath extended keys (`<a;b>/*`) over non-hardened
//! steps is accepted, because the tweak path must be derivable without
//! private keys.

use crate::{backend::Xpub, Error};
use miniscript::{
    bitcoin::{bip32::ChildNumber, hashes::Hash, taproot::LeafVersion, PublicKey, TapLeafHash},
    descriptor::{Tr, Wildcard},
    translate_hash_clone, Descriptor, DescriptorPublicKey, ForEachKey, TranslateErr, TranslatePk,
    Translator,
};

struct TweakTranslator<'a> {
    tweaked: &'a [([u8; 33], [u8; 33])],
}

impl Translator<PublicKey, PublicKey, Error> for TweakTranslator<'_> {
    fn pk(&mut self, pk: &PublicKey) -> Result<PublicKey, Error> {
        let key = pk.inner.serialize();
        let pos = self
            .tweaked
            .binary_search_by(|(base, _)| base.cmp(&key))
            .map_err(|_| Error::MissingTweak)?;
        PublicKey::from_slice(&self.tweaked[pos].1).map_err(|_| Error::InvalidPoint)
    }

    translate_hash_clone!(PublicKey, PublicKey, Error);
}

struct BaseKeyTranslator;

impl Translator<DescriptorPublicKey, PublicKey, Error> for BaseKeyTranslator {
    fn pk(&mut self, pk: &DescriptorPublicKey) -> Result<PublicKey, Error> {
        match pk {
            DescriptorPublicKey::MultiXPub(x) => Ok(PublicKey::new(x.xkey.public_key)),
            _ => Err(Error::KeyType),
        }
    }

    translate_hash_clone!(DescriptorPublicKey, PublicKey, Error);
}

/// A translator error as is; a miniscript error on the translated `tr()` is
/// `Template`.
fn translate_err(e: TranslateErr<Error>) -> Error {
    match e {
        TranslateErr::TranslatorErr(e) => e,
        TranslateErr::OuterError(_) => Error::Template,
    }
}

/// The template of `d`: its `tr()` with every key reduced to its base key.
pub(crate) fn template(d: &Descriptor<DescriptorPublicKey>) -> Result<Tr<PublicKey>, Error> {
    let Descriptor::Tr(tr) = d else {
        return Err(Error::NotTaproot);
    };
    tr.translate_pk(&mut BaseKeyTranslator)
        .map_err(translate_err)
}

/// The `tr()` of template `t` with each base key replaced by its tweaked key.
pub(crate) fn tweak_template(
    t: &Descriptor<PublicKey>,
    tweaked: &[([u8; 33], [u8; 33])],
) -> Result<Tr<PublicKey>, Error> {
    let Descriptor::Tr(tr) = t else {
        return Err(Error::NotTaproot);
    };
    tr.translate_pk(&mut TweakTranslator { tweaked })
        .map_err(translate_err)
}

pub(crate) fn base_keys(t: &Descriptor<PublicKey>) -> Vec<[u8; 33]> {
    let mut keys = Vec::new();
    t.for_each_key(|pk| {
        keys.push(pk.inner.serialize());
        true
    });
    keys.sort();
    keys.dedup();
    keys
}

pub(crate) fn leaf_hashes(
    t: &Descriptor<PublicKey>,
    tweaked: &[([u8; 33], [u8; 33])],
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
