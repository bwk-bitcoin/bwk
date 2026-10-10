mod common;

use bwk_bip89::{
    bip340,
    rust_bitcoin::{
        miniscript::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey},
        RustBitcoin,
    },
    scalar::{xbytes, N},
    BitcoinBackend, Error,
};
use common::hex_arr;

const MSG: [u8; 32] = [
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0, 0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
];
const AUX: [u8; 32] = [0x01; 32];

struct Vector {
    secret: &'static str,
    point: &'static str,
    sig: &'static str,
}

const VECTORS: [Vector; 4] = [
    Vector {
        secret: "0000000000000000000000000000000000000000000000000000000000000001",
        point: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        sig: "6db6826246392dda1c23a396a129d3e2795b685fe90673bba05f4987bb21da622fdd86d7744ddfc8c12881eb88856bf2d59c9dd135f2789567e2b1afc9d5a260",
    },
    Vector {
        secret: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        point: "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        sig: "6db6826246392dda1c23a396a129d3e2795b685fe90673bba05f4987bb21da622fdd86d7744ddfc8c12881eb88856bf2d59c9dd135f2789567e2b1afc9d5a260",
    },
    Vector {
        secret: "0000000000000000000000000000000000000000000000000000000000000003",
        point: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        sig: "bc803c082cf6c00e932b16bb4dbcd5f4263d97dff36ae60a4666ae137ffe1f019bb0b05b24f488bade09b506ad59a696c6c68e633b506462f57e5deb235209e8",
    },
    Vector {
        secret: "1111111111111111111111111111111111111111111111111111111111111111",
        point: "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
        sig: "b5de215dfbde77fa1237034d2306796567763138ac291fd032efce42cec6cec094c12a3f2f9dd5dad0cf0d93a6a3bcc3c6a2b6d742598ec527e85ecb2e7cc4c0",
    },
];

#[test]
fn sign_matches_libsecp256k1() {
    let c = RustBitcoin::new();
    let secp = Secp256k1::new();

    for v in &VECTORS {
        let secret: [u8; 32] = hex_arr(v.secret);
        let point: [u8; 33] = hex_arr(v.point);
        let sig: [u8; 64] = hex_arr(v.sig);

        assert_eq!(c.base_mul(&secret), Some(point));

        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap());
        let (xonly, _) = keypair.x_only_public_key();
        assert_eq!(xbytes(&point), xonly.serialize());

        let expected = secp
            .sign_schnorr_with_aux_rand(&Message::from_digest(MSG), &keypair, &AUX)
            .serialize();
        assert_eq!(expected, sig);

        assert_eq!(bip340::sign(&c, &secret, &MSG, &AUX).unwrap(), sig);
    }
}

#[test]
fn sign_bip340_vector_0() {
    let c = RustBitcoin::new();
    let secret: [u8; 32] =
        hex_arr("0000000000000000000000000000000000000000000000000000000000000003");
    let msg = [0u8; 32];
    let aux = [0u8; 32];
    let expected: [u8; 64] = hex_arr(
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    );
    assert_eq!(bip340::sign(&c, &secret, &msg, &aux).unwrap(), expected);
}

#[test]
fn verify_accepts_valid() {
    let c = RustBitcoin::new();
    for v in &VECTORS {
        let point: [u8; 33] = hex_arr(v.point);
        let sig: [u8; 64] = hex_arr(v.sig);
        assert!(bip340::verify(&c, &xbytes(&point), &MSG, &sig));
    }
}

#[test]
fn verify_rejects_tampering() {
    let c = RustBitcoin::new();
    let point: [u8; 33] = hex_arr(VECTORS[2].point);
    let sig: [u8; 64] = hex_arr(VECTORS[2].sig);
    let xonly = xbytes(&point);

    let mut tampered_msg = MSG;
    tampered_msg[0] ^= 0x01;
    assert!(!bip340::verify(&c, &xonly, &tampered_msg, &sig));

    let mut tampered_sig = sig;
    tampered_sig[0] ^= 0x01;
    assert!(!bip340::verify(&c, &xonly, &MSG, &tampered_sig));

    let mut tampered_sig = sig;
    tampered_sig[63] ^= 0x01;
    assert!(!bip340::verify(&c, &xonly, &MSG, &tampered_sig));

    let mut tampered_sig = sig;
    tampered_sig[32..64].copy_from_slice(&N);
    assert!(!bip340::verify(&c, &xonly, &MSG, &tampered_sig));

    let mut tampered_sig = sig;
    tampered_sig[32..64].copy_from_slice(&[0xffu8; 32]);
    assert!(!bip340::verify(&c, &xonly, &MSG, &tampered_sig));

    let not_on_curve: [u8; 32] =
        hex_arr("eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34");
    assert!(!bip340::verify(&c, &not_on_curve, &MSG, &sig));

    let x_at_field_prime: [u8; 32] =
        hex_arr("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    assert!(!bip340::verify(&c, &x_at_field_prime, &MSG, &sig));
}

#[test]
fn sign_rejects_invalid_secret() {
    let c = RustBitcoin::new();
    assert_eq!(
        bip340::sign(&c, &[0u8; 32], &MSG, &AUX),
        Err(Error::SecretKey)
    );
    assert_eq!(bip340::sign(&c, &N, &MSG, &AUX), Err(Error::SecretKey));
    assert_eq!(
        bip340::sign(&c, &[0xffu8; 32], &MSG, &AUX),
        Err(Error::SecretKey)
    );
}
