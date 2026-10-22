#![cfg(feature = "rust-bitcoin")]

mod common;

use std::str::FromStr;

use bitcoin::{
    bip32::{ChildNumber, Fingerprint, Xpub},
    hashes::{sha256, Hash},
};
use bwk_musig::{rust_bitcoin::RustBitcoin, synthetic_xpub, KeyAgg, BIP328_CHAIN_CODE};
use serde::Deserialize;

use crate::common::{hex_arr, hex_keys, load};

#[derive(Deserialize)]
struct Vector {
    aggregate_pubkey: String,
    keys: Vec<String>,
    xpub: String,
}

#[test]
fn bip328_chain_code_is_sha256_of_tag() {
    assert_eq!(
        BIP328_CHAIN_CODE,
        sha256::Hash::hash(b"MuSig2MuSig2MuSig2").to_byte_array()
    );
}

#[test]
fn bip328_synthetic_xpub_vectors() {
    let vectors: Vec<Vector> = load("bip328/vectors.json");
    assert_eq!(vectors.len(), 3);
    for v in &vectors {
        let keyagg = KeyAgg::new(&RustBitcoin, &hex_keys(&v.keys)).unwrap();
        let aggregate = keyagg.aggregate();
        assert_eq!(aggregate, hex_arr::<33>(&v.aggregate_pubkey));

        let synthetic = synthetic_xpub(&aggregate);
        let xpub = Xpub::from_str(&v.xpub).unwrap();
        assert_eq!(xpub.depth, 0);
        assert_eq!(xpub.parent_fingerprint, Fingerprint::default());
        assert_eq!(xpub.child_number, ChildNumber::Normal { index: 0 });
        assert_eq!(xpub.chain_code.to_bytes(), synthetic.chain_code);
        assert_eq!(xpub.public_key.serialize(), synthetic.key);
    }
}
