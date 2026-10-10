mod common;

use bwk_bip89::{
    rust_bitcoin::{
        miniscript::bitcoin::{
            hashes::{sha256, sha512, Hash, HashEngine, Hmac, HmacEngine},
            taproot::{LeafVersion, TapLeafHash},
            Script,
        },
        RustBitcoin,
    },
    scalar::{add_opt, lift_x, point_neg, tagged_hash256, tagged_hash512, xbytes, HmacSha512, N},
    BitcoinBackend, Sha256Engine, Sha512Engine,
};
use common::hex_arr;

const ZERO: [u8; 32] = [0u8; 32];
const ONE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};
const TWO: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
};
const K11: [u8; 32] = [0x11; 32];
const N_MINUS_1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
];
const N_MINUS_2: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x3f,
];
const HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa1,
];
const G: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];
const G2: [u8; 33] = [
    0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c,
    0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e,
    0xe5,
];
const K11_G: [u8; 33] = [
    0x03, 0x4f, 0x35, 0x5b, 0xdc, 0xb7, 0xcc, 0x0a, 0xf7, 0x28, 0xef, 0x3c, 0xce, 0xb9, 0x61, 0x5d,
    0x90, 0x68, 0x4b, 0xb5, 0xb2, 0xca, 0x5f, 0x85, 0x9a, 0xb0, 0xf0, 0xb7, 0x04, 0x07, 0x58, 0x71,
    0xaa,
];

#[test]
fn sha256_matches_bitcoin_hashes() {
    let c = RustBitcoin::new();
    let mut engine = c.sha256();
    engine.update(b"a");
    engine.update(b"bc");
    let out = engine.finalize();
    assert_eq!(out, sha256::Hash::hash(b"abc").to_byte_array());
    assert_eq!(
        out,
        hex_arr::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn sha512_matches_bitcoin_hashes() {
    let c = RustBitcoin::new();
    let mut engine = c.sha512();
    engine.update(b"ab");
    engine.update(b"c");
    let out = engine.finalize();
    assert_eq!(out, sha512::Hash::hash(b"abc").to_byte_array());
    assert_eq!(
        out,
        hex_arr::<64>(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );
}

#[test]
fn tagged_hash256_matches_tap_leaf_hash() {
    let c = RustBitcoin::new();
    let mut engine = tagged_hash256(&c, b"TapLeaf");
    engine.update(&[0xc0, 0x01, 0x51]);
    let out = engine.finalize();
    let expected = TapLeafHash::from_script(Script::from_bytes(&[0x51]), LeafVersion::TapScript);
    assert_eq!(out, expected.to_byte_array());
    assert_eq!(
        out,
        hex_arr::<32>("a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d675")
    );
}

#[test]
fn tagged_hash512_matches_manual() {
    let c = RustBitcoin::new();
    let mut engine = tagged_hash512(&c, b"CCD/blindfactor");
    engine.update(b"abc");
    let out = engine.finalize();

    let t = sha512::Hash::hash(b"CCD/blindfactor").to_byte_array();
    let mut manual = Vec::new();
    manual.extend_from_slice(&t);
    manual.extend_from_slice(&t);
    manual.extend_from_slice(b"abc");
    let expected = sha512::Hash::hash(&manual).to_byte_array();

    assert_eq!(out, expected);
    assert_eq!(
        out,
        hex_arr::<64>(
            "8c2c6efbcd6d5b366e310276e7390881075e5a523e5fefd6cf829f1a6002dcb5b0e13c1ccebe4d64ab29a2870340b59bf4ea9c068679e5a913692e589b34d0e0"
        )
    );
}

#[test]
fn hmac_sha512_matches_bitcoin_hashes() {
    let c = RustBitcoin::new();
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);

    let mut hmac = HmacSha512::new(&c, &key);
    hmac.update(b"Hi ");
    hmac.update(b"There");
    let out = hmac.finalize();

    let mut e = HmacEngine::<sha512::Hash>::new(&key);
    e.input(b"Hi There");
    let expected = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();

    assert_eq!(out, expected);
    assert_eq!(
        out,
        hex_arr::<64>(
            "9f64dc8a455a0f7467a7152f8d10916e596c56566c78789c936b3a3ebc627353f1bfb4aede1d2650d84536b516864e8d651ba3c325f62a27fa1805fa7430c634"
        )
    );
}

#[test]
fn point_validity() {
    let c = RustBitcoin::new();
    assert!(c.point_is_valid(&G));

    let mut uncompressed = [0u8; 33];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(&xbytes(&G));
    assert!(!c.point_is_valid(&uncompressed));

    let mut zero_x = [0u8; 33];
    zero_x[0] = 0x02;
    assert!(!c.point_is_valid(&zero_x));

    assert_eq!(lift_x(&c, &xbytes(&G)), Some(G));
    assert_eq!(lift_x(&c, &[0u8; 32]), None);
}

#[test]
fn point_arithmetic() {
    let c = RustBitcoin::new();

    assert_eq!(c.point_add(&G, &G), Some(G2));
    assert_eq!(c.point_add(&G2, &point_neg(&G2)), None);

    assert_eq!(c.base_mul(&ONE), Some(G));
    assert_eq!(c.base_mul(&K11), Some(K11_G));
    assert_eq!(c.point_mul(&G, &K11), Some(K11_G));

    assert_eq!(c.base_mul(&[0u8; 32]), None);
    assert_eq!(c.base_mul(&N), None);
    assert_eq!(c.point_mul(&G, &[0u8; 32]), None);

    assert_eq!(add_opt(&c, None, Some(G)), Some(G));
    assert_eq!(add_opt(&c, Some(G), None), Some(G));
    assert_eq!(add_opt(&c, None, None), None);
    assert_eq!(add_opt(&c, Some(G), Some(G)), Some(G2));
}

#[test]
fn scalar_add_edges() {
    let c = RustBitcoin::new();
    assert_eq!(c.scalar_add(&ZERO, &K11), K11);
    assert_eq!(c.scalar_add(&K11, &ZERO), K11);
    assert_eq!(c.scalar_add(&ZERO, &ZERO), ZERO);
    assert_eq!(c.scalar_add(&ONE, &N_MINUS_1), ZERO);
    assert_eq!(c.scalar_add(&N_MINUS_1, &N_MINUS_1), N_MINUS_2);
}

#[test]
fn scalar_mul_edges() {
    let c = RustBitcoin::new();
    assert_eq!(c.scalar_mul(&ZERO, &K11), ZERO);
    assert_eq!(c.scalar_mul(&K11, &ZERO), ZERO);
    assert_eq!(c.scalar_mul(&TWO, &HALF), ONE);
    assert_eq!(c.scalar_mul(&ONE, &K11), K11);
}
