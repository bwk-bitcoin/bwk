#![cfg(feature = "rust-bitcoin")]

mod common;

use bitcoin::{
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpub},
    hashes::Hash,
    key::{TapTweak, UntweakedPublicKey},
    secp256k1::{PublicKey, Secp256k1},
    taproot::TapTweakHash,
    NetworkKind,
};
use bwk_musig::{
    key_sort, rust_bitcoin::RustBitcoin, synthetic_xpub, Error, KeyAgg, MusigBackend, Tweak,
};

use crate::common::{hex_arr, hex_keys};

/// The participant keys of the BIP-373 MuSig2 test vectors.
fn bip373_keys() -> Vec<[u8; 33]> {
    hex_keys(&[
        "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00",
        "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c",
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    ])
}

fn x_only(key: &[u8; 33]) -> [u8; 32] {
    key[1..].try_into().unwrap()
}

fn plain(scalar: [u8; 32]) -> Tweak {
    Tweak {
        scalar,
        x_only: false,
    }
}

/// The BIP-341 x-only tweak of `key` with no script tree.
fn taptweak(key: &[u8; 33]) -> Tweak {
    let internal = UntweakedPublicKey::from_slice(&key[1..]).unwrap();
    Tweak {
        scalar: TapTweakHash::from_key_and_tweak(internal, None).to_byte_array(),
        x_only: true,
    }
}

#[test]
fn sorted_matches_new_over_key_sort() {
    let keys = bip373_keys();
    let sorted = KeyAgg::sorted(&RustBitcoin, &keys).unwrap();
    let new = KeyAgg::new(&RustBitcoin, &key_sort(&RustBitcoin, &keys)).unwrap();
    assert_eq!(sorted.aggregate(), new.aggregate());
    assert_eq!(sorted.participants(), new.participants());
}

#[test]
fn sorted_is_order_independent() {
    let keys = bip373_keys();
    let reversed = keys.iter().rev().copied().collect::<Vec<_>>();
    assert_eq!(
        KeyAgg::sorted(&RustBitcoin, &keys).unwrap().aggregate(),
        KeyAgg::sorted(&RustBitcoin, &reversed).unwrap().aggregate()
    );
    assert_ne!(
        KeyAgg::new(&RustBitcoin, &keys).unwrap().aggregate(),
        KeyAgg::new(&RustBitcoin, &reversed).unwrap().aggregate()
    );
}

#[test]
fn bip373_test_aggregate() {
    let keyagg = KeyAgg::sorted(&RustBitcoin, &bip373_keys()).unwrap();
    assert_eq!(
        keyagg.aggregate(),
        hex_arr::<33>("030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4")
    );
}

#[test]
fn bip373_derived_internal_key() {
    let secp = Secp256k1::verification_only();
    let keyagg = KeyAgg::sorted(&RustBitcoin, &bip373_keys()).unwrap();
    let synthetic = synthetic_xpub(&keyagg.aggregate());
    let xpub = Xpub {
        network: NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_slice(&synthetic.key).unwrap(),
        chain_code: ChainCode::from(synthetic.chain_code),
    };
    assert_eq!(
        xpub.fingerprint(),
        "2680dd6e".parse::<Fingerprint>().unwrap()
    );

    let path = [
        ChildNumber::Normal { index: 1 },
        ChildNumber::Normal { index: 2 },
    ];
    let mut parent = xpub;
    let mut tweaks = Vec::new();
    for child in path {
        let (tweak, _) = parent.ckd_pub_tweak(child).unwrap();
        tweaks.push(plain(tweak.secret_bytes()));
        parent = parent.ckd_pub(&secp, child).unwrap();
    }
    let derived = keyagg.with_tweaks(&RustBitcoin, &tweaks).unwrap();
    let internal = derived.output_key();
    assert_eq!(
        x_only(&internal),
        hex_arr::<32>("8dd96ab858b259c518218c014a46eb4e6ac899e51c675ef774fbb68a8799ce2f")
    );
    assert_eq!(
        internal,
        xpub.derive_pub(&secp, &path)
            .unwrap()
            .public_key
            .serialize()
    );

    let output = derived
        .with_tweaks(&RustBitcoin, &[taptweak(&internal)])
        .unwrap();
    assert_eq!(
        x_only(&output.output_key()),
        hex_arr::<32>("d0b226c6599f273874df8fe684ab6c3028081bee8a2cbed31a136f5865f6cfa4")
    );
}

#[test]
fn x_only_taptweak_matches_rust_bitcoin() {
    let secp = Secp256k1::verification_only();
    let keyagg = KeyAgg::sorted(&RustBitcoin, &bip373_keys()).unwrap();
    let aggregate = keyagg.aggregate();
    let output = keyagg
        .with_tweaks(&RustBitcoin, &[taptweak(&aggregate)])
        .unwrap();
    let (expected, _) = UntweakedPublicKey::from_slice(&aggregate[1..])
        .unwrap()
        .tap_tweak(&secp, None);
    assert_eq!(x_only(&output.output_key()), expected.serialize());
    assert_eq!(
        x_only(&output.output_key()),
        hex_arr::<32>("2967d2d020a9795da72b51be4f3fca25bb0e57e91c5b3e7a81abfa7232a34942")
    );
}

#[test]
fn apply_tweak_keeps_aggregate_and_records_tweaks() {
    let mut keyagg = KeyAgg::sorted(&RustBitcoin, &bip373_keys()).unwrap();
    let aggregate = keyagg.aggregate();
    let first = plain([1; 32]);
    let second = taptweak(&aggregate);
    keyagg.apply_tweak(&RustBitcoin, first).unwrap();
    keyagg.apply_tweak(&RustBitcoin, second).unwrap();
    assert_eq!(keyagg.aggregate(), aggregate);
    assert_eq!(keyagg.tweaks(), [first, second]);
    assert_ne!(keyagg.output_key(), aggregate);
}

#[test]
fn failed_tweak_leaves_key_agg_unchanged() {
    let mut keyagg = KeyAgg::sorted(&RustBitcoin, &bip373_keys()).unwrap();
    keyagg.apply_tweak(&RustBitcoin, plain([1; 32])).unwrap();
    let output_key = keyagg.output_key();
    let tweaks = keyagg.tweaks().to_vec();
    let cache_key = RustBitcoin.agg_pk(keyagg.cache());

    // n, the curve order: out of range.
    let n = hex_arr("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    assert_eq!(
        keyagg.apply_tweak(&RustBitcoin, plain(n)),
        Err(Error::InvalidTweak)
    );
    assert_eq!(keyagg.output_key(), output_key);
    assert_eq!(keyagg.tweaks(), tweaks);
    assert_eq!(RustBitcoin.agg_pk(keyagg.cache()), cache_key);
}

#[test]
fn empty_key_list_is_rejected() {
    assert_eq!(KeyAgg::new(&RustBitcoin, &[]).err(), Some(Error::NoKeys));
}

#[test]
fn point_is_valid_rejects_bad_encodings() {
    assert!(RustBitcoin.point_is_valid(&bip373_keys()[0]));
    for invalid in [
        "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "020000000000000000000000000000000000000000000000000000000000000005",
    ] {
        assert!(!RustBitcoin.point_is_valid(&hex_arr(invalid)));
    }
}
