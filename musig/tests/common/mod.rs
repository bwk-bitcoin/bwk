#![allow(dead_code)]

use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bwk_musig::{
    rust_bitcoin::{
        secp256k1_musig::{
            ffi::{CPtr, MUSIG_SECNONCE_SIZE},
            musig::SecretNonce,
            PublicKey,
        },
        RustBitcoin,
    },
    KeyAgg, Rng, Tweak,
};
use serde::de::DeserializeOwned;

pub fn hex_vec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

pub fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex_vec(s).try_into().unwrap()
}

/// Decodes each hex string of `keys` into a 33-byte encoding.
pub fn hex_keys<S: AsRef<str>>(keys: &[S]) -> Vec<[u8; 33]> {
    keys.iter().map(|k| hex_arr(k.as_ref())).collect()
}

/// Decodes each hex string of `items` into an `N`-byte array.
pub fn hex_arrs<const N: usize>(items: &[String]) -> Vec<[u8; N]> {
    items.iter().map(|i| hex_arr(i)).collect()
}

/// Loads the JSON vector file at `file`, relative to `test_vectors/`.
pub fn load<T: DeserializeOwned>(file: &str) -> T {
    let path = format!("{}/test_vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A BIP-327 97-byte secnonce (`k1 || k2 || pk`) in libsecp's 132-byte layout: magic,
/// k1, k2, then the signer key in libsecp's internal storage.
pub fn bip327_secnonce(bytes: &[u8; 97]) -> SecretNonce {
    let pk = PublicKey::from_byte_array_compressed(bytes[64..].try_into().unwrap()).unwrap();
    let mut raw = [0u8; MUSIG_SECNONCE_SIZE];
    raw[..4].copy_from_slice(&[0x22, 0x0e, 0xdc, 0xf1]);
    raw[4..68].copy_from_slice(&bytes[..64]);
    // SAFETY: `as_c_ptr` points at the `ffi::PublicKey` field of the live `pk`, so the
    // read is in bounds and aligned; `underlying_bytes` copies it out.
    raw[68..].copy_from_slice(&unsafe { (*pk.as_c_ptr()).underlying_bytes() });
    SecretNonce::dangerous_from_bytes(raw)
}

/// A deterministic `Rng` for tests: each call fills the buffer with the next non-zero
/// byte.
pub struct CounterRng(pub u8);

impl Rng for CounterRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.0 = self.0.checked_add(1).unwrap_or(1);
        buf.fill(self.0);
    }
}

/// KeyAgg over `keys` in the given order, then `tweaks`.
pub fn key_agg_with(keys: &[[u8; 33]], tweaks: &[Tweak]) -> KeyAgg<RustBitcoin> {
    KeyAgg::new(&RustBitcoin, keys)
        .unwrap()
        .with_tweaks(&RustBitcoin, tweaks)
        .unwrap()
}

/// The compressed public key of `secret_key`.
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 33] {
    let sk = SecretKey::from_slice(secret_key).unwrap();
    sk.public_key(&Secp256k1::signing_only()).serialize()
}

/// Whether `sig` is a valid BIP-340 signature of `msg` under the x-only `key`, checked
/// with rust-bitcoin.
pub fn verify_bip340(sig: &[u8; 64], msg: &[u8; 32], key: &[u8; 33]) -> bool {
    let sig = Signature::from_slice(sig).unwrap();
    let key = XOnlyPublicKey::from_slice(&key[1..]).unwrap();
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(*msg), &key)
        .is_ok()
}
