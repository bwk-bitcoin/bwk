#![allow(dead_code)]

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

/// Loads the JSON vector file at `file`, relative to `test_vectors/`.
pub fn load<T: DeserializeOwned>(file: &str) -> T {
    let path = format!("{}/test_vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
