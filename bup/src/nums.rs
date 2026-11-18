//! BIP-341 NUMS unspendable key + the deterministic NUMS xpub derivation used as a
//! Tr internal key in policies that have no key-path spender.
//!
//! Pulled out of liana's `descriptors::analysis` so this crate stays independent.

use bwk_descriptor::wallet::WalletKey;
#[cfg(feature = "musig")]
use bwk_keys::musig::MusigKey;
use miniscript::{
    bitcoin::{
        bip32,
        hashes::{sha256, Hash},
    },
    descriptor,
};

use crate::multipath::{plain_key, wallet_key};

pub use bwk_keys::nums::bip341_nums;

/// The xpub whose public key a leaf key adds to the NUMS chain code: a plain
/// `MultiXPub`'s own, or with `musig` an aggregate-then-derive musig()'s BIP-328 synthetic
/// xpub (its public key is the untweaked KeyAgg output). None for any other key.
pub(crate) fn chain_code_xkey(key: &WalletKey) -> Option<&bip32::Xpub> {
    #[cfg(feature = "musig")]
    if let MusigKey::Musig(aggregate) = key {
        return aggregate.synthetic_xpub();
    }
    if let Some(descriptor::DescriptorPublicKey::MultiXPub(descriptor::DescriptorMultiXKey {
        xkey,
        ..
    })) = plain_key(key)
    {
        Some(xkey)
    } else {
        None
    }
}

/// Construct an unspendable xpub to be used as internal key in a Taproot descriptor.
///
/// Returns `None` if the descriptor does not contain a tap tree with at least a key in each
/// leaf, or if the keys contained in the descriptor aren't all `MultiXPub`s (or, with
/// `musig`, aggregate-then-derive musig() keys).
///
/// See <https://delvingbitcoin.org/t/unspendable-keys-in-descriptors/304/21>.
fn unspendable_internal_xpub(desc: &descriptor::Tr<WalletKey>) -> Option<bip32::Xpub> {
    let tap_tree = desc.tap_tree().as_ref()?;

    let first_key = tap_tree.iter().flat_map(|(_, ms)| ms.iter_pk()).next()?;
    let network = chain_code_xkey(&first_key)?.network;

    let concat =
        tap_tree
            .iter()
            .flat_map(|(_, ms)| ms.iter_pk())
            .try_fold(Vec::new(), |mut acc, pk| {
                let xkey = chain_code_xkey(&pk)?;
                acc.extend_from_slice(&xkey.public_key.serialize());
                Some(acc)
            })?;
    let chain_code = bip32::ChainCode::from(sha256::Hash::hash(&concat).as_ref());

    let public_key = bip341_nums();
    Some(bip32::Xpub {
        public_key,
        chain_code,
        depth: 0,
        parent_fingerprint: [0; 4].into(),
        child_number: 0.into(),
        network,
    })
}

/// Wrap [`unspendable_internal_xpub`] into a multipath [`WalletKey`]. Used by
/// `Policy::from_descriptor` for legacy NUMS detection.
pub fn unspendable_internal_key(desc: &descriptor::Tr<WalletKey>) -> Option<WalletKey> {
    Some(wallet_key(descriptor::DescriptorPublicKey::MultiXPub(
        descriptor::DescriptorMultiXKey {
            origin: None,
            xkey: unspendable_internal_xpub(desc)?,
            derivation_paths: descriptor::DerivPaths::new(vec![
                [0.into()][..].into(),
                [1.into()][..].into(),
            ])
            .expect("Non empty vec"),
            wildcard: descriptor::Wildcard::Unhardened,
        },
    )))
}
