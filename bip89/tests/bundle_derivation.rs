mod common;

use bwk_bip89::{bundle::derive_bundle, tweak::compute_bip32_tweak, Error, Xpub};
use common::{hex_arr, SliceDescriptor, VectorBackend};

fn xpub0() -> Xpub {
    Xpub {
        key: hex_arr("0296928602758150d2b4a8a253451b887625b94ab0a91f801f1408cb33b9cf0f83"),
        chain_code: hex_arr("433cf1154e61c4eb9793488880f8a795a3a72052ad14a7367852542425609640"),
        branches: [vec![0], vec![1]],
    }
}

fn xpub1() -> Xpub {
    Xpub {
        key: hex_arr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        chain_code: [0x01; 32],
        branches: [vec![7, 0], vec![7, 1]],
    }
}

fn xpub2() -> Xpub {
    Xpub {
        key: hex_arr("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        chain_code: [0x02; 32],
        branches: [vec![3, 4, 0], vec![3, 4, 1]],
    }
}

fn xpubs() -> Vec<Xpub> {
    vec![xpub0(), xpub1(), xpub2()]
}

#[test]
fn derive_bundle_matches_compute_bip32_tweak() {
    let c = VectorBackend::default();
    let desc = SliceDescriptor(xpubs());
    for keychain in [0u32, 1] {
        for index in [0u32, 7, 0x7fff_ffff] {
            let bundle = derive_bundle(&c, &desc, keychain, index).unwrap();
            assert_eq!(bundle.entries().len(), 3);
            for xpub in xpubs() {
                let mut path = xpub.branches[keychain as usize].clone();
                path.push(index);
                let expected = compute_bip32_tweak(&c, &xpub.key, &xpub.chain_code, &path)
                    .unwrap()
                    .tweak;
                assert_eq!(bundle.tweak(&xpub.key), Some(expected));
            }
        }
    }
}

#[test]
fn derive_bundle_literal_tweak() {
    let c = VectorBackend::default();
    let desc = SliceDescriptor(xpubs());
    let bundle = derive_bundle(&c, &desc, 0, 1).unwrap();
    let expected: [u8; 32] =
        hex_arr("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b");
    assert_eq!(bundle.tweak(&xpub0().key), Some(expected));
}

#[test]
fn derive_bundle_rejects_keychain_2() {
    let c = VectorBackend::default();
    let desc = SliceDescriptor(xpubs());
    assert_eq!(derive_bundle(&c, &desc, 2, 0), Err(Error::InvalidKeychain));
}

#[test]
fn derive_bundle_rejects_hardened_index() {
    let c = VectorBackend::default();
    let desc = SliceDescriptor(xpubs());
    assert_eq!(
        derive_bundle(&c, &desc, 0, 0x8000_0000),
        Err(Error::HardenedIndex)
    );
}

#[test]
fn derive_bundle_rejects_duplicate_xpub_key() {
    let c = VectorBackend::default();
    let desc = SliceDescriptor(vec![xpub0(), xpub0()]);
    assert_eq!(derive_bundle(&c, &desc, 0, 0), Err(Error::DuplicateKey));
}
