#![cfg(feature = "rust-bitcoin")]

mod common;

use bwk_musig::{key_sort, rust_bitcoin::RustBitcoin, Error, KeyAgg, Tweak};
use serde::Deserialize;

use crate::common::{hex_arr, hex_keys, load};

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

#[derive(Deserialize)]
struct KeyAggError {
    key_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    comment: String,
}

#[derive(Deserialize)]
struct TweakVectors {
    pubkeys: Vec<String>,
    tweaks: Vec<String>,
    error_test_cases: Vec<TweakError>,
}

#[derive(Deserialize)]
struct TweakError {
    key_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
}

fn pick(keys: &[[u8; 33]], indices: &[usize]) -> Vec<[u8; 33]> {
    indices.iter().map(|i| keys[*i]).collect()
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
    for (i, case) in v.error_test_cases.iter().enumerate() {
        let participants = pick(&keys, &case.key_indices);
        if i < 3 {
            // Invalid public key contributions.
            assert!(case.tweak_indices.is_empty(), "{}", case.comment);
            assert_eq!(
                KeyAgg::new(&RustBitcoin, &participants).err(),
                Some(Error::InvalidPoint),
                "{}",
                case.comment
            );
        } else {
            // Tweak out of range, then a tweak whose result is infinity.
            let mut keyagg = KeyAgg::new(&RustBitcoin, &participants).unwrap();
            let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
            assert_eq!(tweaks.len(), 1);
            assert_eq!(
                keyagg.apply_tweak(&RustBitcoin, tweaks[0]),
                Err(Error::InvalidTweak),
                "{}",
                case.comment
            );
        }
    }
}

#[test]
fn tweak_error_vectors() {
    let v: TweakVectors = load("bip327/tweak_vectors.json");
    let keys = hex_keys(&v.pubkeys);
    assert_eq!(v.error_test_cases.len(), 1);
    let case = &v.error_test_cases[0];
    assert_eq!(case.key_indices, [1, 2, 0]);
    let keyagg = KeyAgg::new(&RustBitcoin, &pick(&keys, &case.key_indices)).unwrap();
    let tweaks = tweaks(&v.tweaks, &case.tweak_indices, &case.is_xonly);
    assert!(!tweaks[0].x_only);
    assert_eq!(
        keyagg.with_tweaks(&RustBitcoin, &tweaks).err(),
        Some(Error::InvalidTweak)
    );
}
