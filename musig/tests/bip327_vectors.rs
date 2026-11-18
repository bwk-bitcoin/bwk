#![cfg(feature = "rust-bitcoin")]

mod common;

use bwk_musig::{
    key_sort, nonce_agg, nonce_gen_with_rand, partial_agg, partial_verify,
    rust_bitcoin::RustBitcoin, Error, KeyAgg, MusigBackend, Tweak,
};
use serde::Deserialize;

use crate::common::{
    bip327_secnonce, hex_arr, hex_arrs, hex_keys, hex_vec, key_agg_with, load, verify_bip340,
};

/// The `error` field of a BIP-327 error vector.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum VectorError {
    InvalidContribution { contrib: String },
    Value { message: String },
}

impl VectorError {
    fn expected(&self) -> Error {
        match self {
            VectorError::InvalidContribution { contrib } => match contrib.as_str() {
                "pubkey" => Error::InvalidPoint,
                "pubnonce" | "aggnonce" => Error::InvalidPubNonce,
                "psig" => Error::InvalidPartialSig,
                other => panic!("unknown contribution {other}"),
            },
            VectorError::Value { message } => match message.as_str() {
                "The tweak must be less than n." | "The result of tweaking cannot be infinity." => {
                    Error::InvalidTweak
                }
                "The signer's pubkey must be included in the list of pubkeys." => {
                    Error::NotParticipant
                }
                "first secnonce value is out of range." => Error::InvalidSecNonce,
                other => panic!("unknown error {other}"),
            },
        }
    }
}

#[derive(Deserialize)]
struct KeySortVectors {
    pubkeys: Vec<String>,
    sorted_pubkeys: Vec<String>,
}

#[derive(Deserialize)]
struct KeyAggVectors {
    pubkeys: Vec<String>,
    tweaks: Vec<String>,
    valid_test_cases: Vec<KeyAggValid>,
    error_test_cases: Vec<KeyAggError>,
}

#[derive(Deserialize)]
struct KeyAggValid {
    key_indices: Vec<usize>,
    expected: String,
}

/// An error case of the KeyAgg and tweak vectors.
#[derive(Deserialize)]
struct KeyAggError {
    key_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    error: VectorError,
    comment: String,
}

#[derive(Deserialize)]
struct TweakVectors {
    sk: String,
    pubkeys: Vec<String>,
    secnonce: String,
    pnonces: Vec<String>,
    aggnonce: String,
    tweaks: Vec<String>,
    msg: String,
    valid_test_cases: Vec<TweakValid>,
    error_test_cases: Vec<KeyAggError>,
}

#[derive(Deserialize)]
struct TweakValid {
    key_indices: Vec<usize>,
    nonce_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    signer_index: usize,
    expected: String,
    comment: String,
}

#[derive(Deserialize)]
struct NonceGenVectors {
    test_cases: Vec<NonceGenCase>,
}

#[derive(Deserialize)]
struct NonceGenCase {
    rand_: String,
    sk: Option<String>,
    pk: String,
    aggpk: Option<String>,
    msg: Option<String>,
    extra_in: Option<String>,
    expected_secnonce: String,
    expected_pubnonce: String,
}

#[derive(Deserialize)]
struct NonceAggVectors {
    pnonces: Vec<String>,
    valid_test_cases: Vec<NonceAggValid>,
    error_test_cases: Vec<NonceAggError>,
}

#[derive(Deserialize)]
struct NonceAggValid {
    pnonce_indices: Vec<usize>,
    expected: String,
}

#[derive(Deserialize)]
struct NonceAggError {
    pnonce_indices: Vec<usize>,
    error: VectorError,
    comment: String,
}

#[derive(Deserialize)]
struct SignVerifyVectors {
    sk: String,
    pubkeys: Vec<String>,
    secnonces: Vec<String>,
    pnonces: Vec<String>,
    aggnonces: Vec<String>,
    msgs: Vec<String>,
    valid_test_cases: Vec<SignValid>,
    sign_error_test_cases: Vec<SignError>,
    verify_fail_test_cases: Vec<VerifyCase>,
    verify_error_test_cases: Vec<VerifyCase>,
}

#[derive(Deserialize)]
struct SignValid {
    key_indices: Vec<usize>,
    nonce_indices: Vec<usize>,
    aggnonce_index: usize,
    msg_index: usize,
    signer_index: usize,
    expected: String,
}

#[derive(Deserialize)]
struct SignError {
    key_indices: Vec<usize>,
    aggnonce_index: usize,
    msg_index: usize,
    secnonce_index: usize,
    error: VectorError,
    comment: String,
}

/// A verify fail case, or a verify error case when `error` is set.
#[derive(Deserialize)]
struct VerifyCase {
    sig: String,
    key_indices: Vec<usize>,
    nonce_indices: Vec<usize>,
    msg_index: usize,
    signer_index: usize,
    error: Option<VectorError>,
    comment: String,
}

#[derive(Deserialize)]
struct SigAggVectors {
    pubkeys: Vec<String>,
    tweaks: Vec<String>,
    psigs: Vec<String>,
    msg: String,
    valid_test_cases: Vec<SigAggCase>,
    error_test_cases: Vec<SigAggCase>,
}

/// A sig-agg valid case, or an error case when `error` is set.
#[derive(Deserialize)]
struct SigAggCase {
    aggnonce: String,
    key_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    psig_indices: Vec<usize>,
    expected: Option<String>,
    error: Option<VectorError>,
}

fn pick<T: Copy>(items: &[T], indices: &[usize]) -> Vec<T> {
    indices.iter().map(|i| items[*i]).collect()
}

fn tweaks(scalars: &[String], indices: &[usize], is_xonly: &[bool]) -> Vec<Tweak> {
    indices
        .iter()
        .zip(is_xonly)
        .map(|(i, x_only)| Tweak {
            scalar: hex_arr(&scalars[*i]),
            x_only: *x_only,
        })
        .collect()
}

#[test]
fn key_sort_vectors() {
    let v: KeySortVectors = load("bip327/key_sort_vectors.json");
    let sorted = key_sort(&RustBitcoin, &hex_keys(&v.pubkeys));
    assert_eq!(sorted, hex_keys(&v.sorted_pubkeys));
}

#[test]
fn key_agg_valid_vectors() {
    let v: KeyAggVectors = load("bip327/key_agg_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    for case in &v.valid_test_cases {
        let keyagg = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices)).unwrap();
        let expected: [u8; 32] = hex_arr(&case.expected);
        assert_eq!(keyagg.aggregate()[1..], expected);
        assert_eq!(keyagg.output_key(), keyagg.aggregate());
        assert!(keyagg.tweaks().is_empty());
    }
}

#[test]
fn key_agg_error_vectors() {
    let v: KeyAggVectors = load("bip327/key_agg_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    assert_eq!(v.error_test_cases.len(), 5);
    for case in &v.error_test_cases {
        let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
        let result = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices))
            .and_then(|keyagg| keyagg.with_tweaks(&RustBitcoin, &tweaks));
        assert_eq!(
            result.err(),
            Some(case.error.expected()),
            "{}",
            case.comment
        );
    }
}

#[test]
fn tweak_error_vectors() {
    let v: TweakVectors = load("bip327/tweak_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    assert_eq!(v.error_test_cases.len(), 1);
    for case in &v.error_test_cases {
        let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
        let result = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices))
            .and_then(|keyagg| keyagg.with_tweaks(&RustBitcoin, &tweaks));
        assert_eq!(
            result.err(),
            Some(case.error.expected()),
            "{}",
            case.comment
        );
    }
}

/// The 32-byte message at `index`, or None for the empty and 38-byte messages:
/// libsecp signs 32-byte messages only, so rust-secp256k1 cannot express those cases.
fn msg32(msgs: &[String], index: usize) -> Option<[u8; 32]> {
    hex_vec(&msgs[index]).try_into().ok()
}

#[test]
fn nonce_gen_vectors() {
    let v: NonceGenVectors = load("bip327/nonce_gen_vectors.json");
    // Cases 0 to 2 cannot be expressed: libsecp hashes the aggpk of a KeyAgg cache, not
    // a raw value, and case 1 has an empty message, case 2 a 38-byte one.
    let mut tested = 0;
    for case in v.test_cases.iter().filter(|c| c.aggpk.is_none()) {
        let rand = hex_arr(&case.rand_);
        let sk = case.sk.as_deref().map(hex_arr::<32>);
        let pk = hex_arr(&case.pk);
        let msg = case.msg.as_deref().map(hex_arr::<32>);
        let extra_in = case.extra_in.as_deref().map(hex_arr::<32>);
        let expected_secnonce: [u8; 97] = hex_arr(&case.expected_secnonce);
        let expected_pubnonce: [u8; 66] = hex_arr(&case.expected_pubnonce);

        let (secnonce, pubnonce) = nonce_gen_with_rand(
            &RustBitcoin,
            &rand,
            None,
            &pk,
            sk.as_ref(),
            msg.as_ref(),
            extra_in.as_ref(),
        )
        .unwrap();
        assert_eq!(pubnonce, expected_pubnonce);
        assert_eq!(secnonce.public_key()[..], expected_secnonce[64..]);

        let (inner, pubnonce) = RustBitcoin
            .nonce_gen(
                &rand,
                sk.as_ref(),
                &pk,
                None,
                msg.as_ref(),
                extra_in.as_ref(),
            )
            .unwrap();
        assert_eq!(pubnonce, expected_pubnonce);
        assert_eq!(inner.dangerous_into_bytes()[4..68], expected_secnonce[..64]);
        tested += 1;
    }
    assert_eq!(tested, 1);
}

#[test]
fn nonce_agg_valid_vectors() {
    let v: NonceAggVectors = load("bip327/nonce_agg_vectors.json");
    let pnonces = hex_arrs::<66>(&v.pnonces);
    assert_eq!(v.valid_test_cases.len(), 2);
    for case in &v.valid_test_cases {
        let aggnonce = nonce_agg(&RustBitcoin, &pick(&pnonces, &case.pnonce_indices)).unwrap();
        assert_eq!(aggnonce, hex_arr::<66>(&case.expected));
    }
}

#[test]
fn nonce_agg_error_vectors() {
    let v: NonceAggVectors = load("bip327/nonce_agg_vectors.json");
    let pnonces = hex_arrs::<66>(&v.pnonces);
    assert_eq!(v.error_test_cases.len(), 3);
    for case in &v.error_test_cases {
        let result = nonce_agg(&RustBitcoin, &pick(&pnonces, &case.pnonce_indices));
        assert_eq!(result, Err(case.error.expected()), "{}", case.comment);
    }
}

#[test]
fn sign_valid_vectors() {
    let v: SignVerifyVectors = load("bip327/sign_verify_vectors.json");
    let sk = hex_arr(&v.sk);
    let keys = hex_keys(&v.pubkeys);
    let secnonce: [u8; 97] = hex_arr(&v.secnonces[0]);
    let pnonces = hex_arrs::<66>(&v.pnonces);
    let aggnonces = hex_arrs::<66>(&v.aggnonces);
    let mut tested = 0;
    for case in &v.valid_test_cases {
        let Some(msg) = msg32(&v.msgs, case.msg_index) else {
            continue;
        };
        let keyagg = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices)).unwrap();
        let aggnonce = aggnonces[case.aggnonce_index];
        let psig = RustBitcoin
            .partial_sign(
                bip327_secnonce(&secnonce),
                &sk,
                keyagg.cache(),
                &aggnonce,
                &msg,
            )
            .unwrap();
        assert_eq!(psig, hex_arr::<32>(&case.expected));
        assert!(partial_verify(
            &RustBitcoin,
            &psig,
            &pnonces[case.nonce_indices[case.signer_index]],
            &keys[case.key_indices[case.signer_index]],
            &keyagg,
            &aggnonce,
            &msg,
        ));
        tested += 1;
    }
    assert_eq!(tested, 4);
}

#[test]
fn sign_error_vectors() {
    let v: SignVerifyVectors = load("bip327/sign_verify_vectors.json");
    let sk = hex_arr(&v.sk);
    let keys = hex_keys(&v.pubkeys);
    let secnonces = hex_arrs::<97>(&v.secnonces);
    let aggnonces = hex_arrs::<66>(&v.aggnonces);
    let mut tested = 0;
    for case in &v.sign_error_test_cases {
        let expected = case.error.expected();
        // The backend has no key list: `partial_sign_rejects_non_participant` in
        // tests/sign.rs runs this case through `bwk_musig::partial_sign`.
        if expected == Error::NotParticipant {
            continue;
        }
        let msg = msg32(&v.msgs, case.msg_index).unwrap();
        let result =
            KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices)).and_then(|keyagg| {
                RustBitcoin.partial_sign(
                    bip327_secnonce(&secnonces[case.secnonce_index]),
                    &sk,
                    keyagg.cache(),
                    &aggnonces[case.aggnonce_index],
                    &msg,
                )
            });
        assert_eq!(result, Err(expected), "{}", case.comment);
        tested += 1;
    }
    assert_eq!(tested, 5);
}

#[test]
fn verify_fail_vectors() {
    let v: SignVerifyVectors = load("bip327/sign_verify_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    let pnonces = hex_arrs::<66>(&v.pnonces);
    assert_eq!(v.verify_fail_test_cases.len(), 3);
    for case in &v.verify_fail_test_cases {
        assert!(case.error.is_none());
        let msg = msg32(&v.msgs, case.msg_index).unwrap();
        let keyagg = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices)).unwrap();
        let aggnonce = nonce_agg(&RustBitcoin, &pick(&pnonces, &case.nonce_indices)).unwrap();
        assert!(
            !partial_verify(
                &RustBitcoin,
                &hex_arr(&case.sig),
                &pnonces[case.nonce_indices[case.signer_index]],
                &keys[case.key_indices[case.signer_index]],
                &keyagg,
                &aggnonce,
                &msg,
            ),
            "{}",
            case.comment
        );
    }
}

#[test]
fn verify_error_vectors() {
    let v: SignVerifyVectors = load("bip327/sign_verify_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    let pnonces = hex_arrs::<66>(&v.pnonces);
    let valid_aggnonce = hex_arr::<66>(&v.aggnonces[0]);
    assert_eq!(v.verify_error_test_cases.len(), 2);
    for case in &v.verify_error_test_cases {
        let msg = msg32(&v.msgs, case.msg_index).unwrap();
        let keyagg = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices));
        let aggnonce = nonce_agg(&RustBitcoin, &pick(&pnonces, &case.nonce_indices));
        match case.error.as_ref().unwrap().expected() {
            Error::InvalidPoint => {
                assert_eq!(keyagg.err(), Some(Error::InvalidPoint), "{}", case.comment);
            }
            Error::InvalidPubNonce => {
                assert_eq!(aggnonce, Err(Error::InvalidPubNonce), "{}", case.comment);
                assert!(!partial_verify(
                    &RustBitcoin,
                    &hex_arr(&case.sig),
                    &pnonces[case.nonce_indices[case.signer_index]],
                    &keys[case.key_indices[case.signer_index]],
                    &keyagg.unwrap(),
                    &valid_aggnonce,
                    &msg,
                ));
            }
            other => panic!("unexpected verify error {other:?}"),
        }
    }
}

#[test]
fn tweak_valid_vectors() {
    let v: TweakVectors = load("bip327/tweak_vectors.json");
    let sk = hex_arr(&v.sk);
    let keys = hex_keys(&v.pubkeys);
    let secnonce: [u8; 97] = hex_arr(&v.secnonce);
    let pnonces = hex_arrs::<66>(&v.pnonces);
    let aggnonce = hex_arr(&v.aggnonce);
    let msg = hex_arr(&v.msg);
    assert_eq!(v.valid_test_cases.len(), 5);
    for case in &v.valid_test_cases {
        let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
        let keyagg = key_agg_with(&pick(&keys, &case.key_indices), &tweaks);
        let psig = RustBitcoin
            .partial_sign(
                bip327_secnonce(&secnonce),
                &sk,
                keyagg.cache(),
                &aggnonce,
                &msg,
            )
            .unwrap();
        assert_eq!(psig, hex_arr::<32>(&case.expected), "{}", case.comment);
        assert!(partial_verify(
            &RustBitcoin,
            &psig,
            &pnonces[case.nonce_indices[case.signer_index]],
            &keys[case.key_indices[case.signer_index]],
            &keyagg,
            &aggnonce,
            &msg,
        ));
    }
}

#[test]
fn sig_agg_valid_vectors() {
    let v: SigAggVectors = load("bip327/sig_agg_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    let psigs = hex_arrs::<32>(&v.psigs);
    let msg = hex_arr(&v.msg);
    assert_eq!(v.valid_test_cases.len(), 4);
    for case in &v.valid_test_cases {
        let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
        let keyagg = key_agg_with(&pick(&keys, &case.key_indices), &tweaks);
        let sig = partial_agg(
            &RustBitcoin,
            &keyagg,
            &hex_arr(&case.aggnonce),
            &msg,
            &pick(&psigs, &case.psig_indices),
        )
        .unwrap();
        assert_eq!(sig, hex_arr::<64>(case.expected.as_ref().unwrap()));
        assert!(verify_bip340(&sig, &msg, &keyagg.output_key()));
    }
}

#[test]
fn sig_agg_error_vectors() {
    let v: SigAggVectors = load("bip327/sig_agg_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    let psigs = hex_arrs::<32>(&v.psigs);
    let msg = hex_arr(&v.msg);
    assert_eq!(v.error_test_cases.len(), 1);
    for case in &v.error_test_cases {
        let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
        let keyagg = key_agg_with(&pick(&keys, &case.key_indices), &tweaks);
        let result = partial_agg(
            &RustBitcoin,
            &keyagg,
            &hex_arr(&case.aggnonce),
            &msg,
            &pick(&psigs, &case.psig_indices),
        );
        assert_eq!(result, Err(case.error.as_ref().unwrap().expected()));
    }
}
