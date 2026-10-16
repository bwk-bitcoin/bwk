//! BIP-341 NUMS unspendable key + the deterministic NUMS xpub derivation used as a
//! Tr internal key in policies that have no key-path spender.
//!
//! Pulled out of liana's `descriptors::analysis` so this crate stays independent.

use std::str::FromStr;

use bwk_descriptor::wallet::WalletKey;
use miniscript::{
    bitcoin::{
        bip32,
        hashes::{sha256, Hash},
        secp256k1,
    },
    descriptor,
};

use crate::multipath::{plain_key, wallet_key};

/// The BIP-341 NUMS ("Nothing Up My Sleeve") point.
///
/// See BIP-341:
/// > One example of such a point is H =
/// > lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0) which is
/// > constructed by taking the hash of the standard uncompressed encoding of the secp256k1
/// > base point G as X coordinate.
pub fn bip341_nums() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_str(
        "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .expect("Valid pubkey: NUMS from BIP341")
}

fn get_multi_xkey(desc_key: &WalletKey) -> Option<&bip32::Xpub> {
    if let Some(descriptor::DescriptorPublicKey::MultiXPub(descriptor::DescriptorMultiXKey {
        xkey,
        ..
    })) = plain_key(desc_key)
    {
        Some(xkey)
    } else {
        None
    }
}

/// Construct an unspendable xpub to be used as internal key in a Taproot descriptor.
///
/// Returns `None` if the descriptor does not contain a tap tree with at least a key in each
/// leaf, or if the keys contained in the descriptor aren't all `MultiXPub`s.
///
/// See <https://delvingbitcoin.org/t/unspendable-keys-in-descriptors/304/21>.
fn unspendable_internal_xpub(desc: &descriptor::Tr<WalletKey>) -> Option<bip32::Xpub> {
    let tap_tree = desc.tap_tree().as_ref()?;

    let first_key = tap_tree.iter().flat_map(|(_, ms)| ms.iter_pk()).next()?;
    let network = get_multi_xkey(&first_key)?.network;

    let concat =
        tap_tree
            .iter()
            .flat_map(|(_, ms)| ms.iter_pk())
            .try_fold(Vec::new(), |mut acc, pk| {
                let xkey = get_multi_xkey(&pk)?;
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
