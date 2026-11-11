//! Nonce cache sessions (bip-nonce-cache/BIP-DRAFT.md): a session's nonces derive
//! from its random secret, the input index, the key expression index and the
//! signer's key only, never from a policy, an aggregate key or a transaction.

use bwk_musig::{nonce_gen_with_rand, rust_bitcoin::RustBitcoin, SecNonce};
use miniscript::bitcoin::hashes::{sha256, Hash, HashEngine};

use crate::{
    error::Error,
    hot_signer::{fresh_rand, wipe},
};

pub const SESSION_ID_LEN: usize = 4;
pub const SECRET_LEN: usize = 32;
const NONCE_SEED_TAG: &[u8] = b"BIPXXXX_NONCE_SEED";
const SESSION_REF_TAG: &[u8] = b"BIPXXXX_SESSION_REF";

/// The secret of one session: drawn from the OS, never derived from the seed or a
/// key, and never exported. Erased when dropped; `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionSecret([u8; SECRET_LEN]);

impl SessionSecret {
    pub fn random() -> Result<Self, Error> {
        let mut secret = Self([0; SECRET_LEN]);
        fresh_rand(&mut secret.0)?;
        Ok(secret)
    }

    /// A secret read back from the signer's own session store.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// The first 4 bytes of tagged_hash("BIPXXXX_SESSION_REF", secret).
    pub fn session_ref(&self) -> [u8; SESSION_ID_LEN] {
        let hash = tagged_hash(SESSION_REF_TAG, &[&self.0]);
        let mut session_ref = [0; SESSION_ID_LEN];
        session_ref.copy_from_slice(&hash[..SESSION_ID_LEN]);
        session_ref
    }

    /// tagged_hash("BIPXXXX_NONCE_SEED", secret | ser32(i) | ser32(j)).
    fn seed(&self, input_index: u32, key_expression_index: u32) -> [u8; 32] {
        tagged_hash(
            NONCE_SEED_TAG,
            &[
                &self.0,
                &input_index.to_be_bytes(),
                &key_expression_index.to_be_bytes(),
            ],
        )
    }

    /// BIP-327 NonceGen with the seed of (`input_index`, `key_expression_index`) as
    /// rand', and the aggregate key, the message and extra_in omitted.
    pub fn nonce(
        &self,
        input_index: u32,
        key_expression_index: u32,
        secret_key: &[u8; 32],
        public_key: &[u8; 33],
    ) -> Result<(SecNonce<RustBitcoin>, [u8; 66]), Error> {
        let mut seed = self.seed(input_index, key_expression_index);
        let generated = nonce_gen_with_rand(
            &RustBitcoin,
            &seed,
            None,
            public_key,
            Some(secret_key),
            None,
            None,
        );
        wipe(&mut seed);
        Ok(generated?)
    }
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionSecret(..)")
    }
}

impl Drop for SessionSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// The BIP-340 tagged hash of the concatenation of `parts`.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag.as_byte_array());
    engine.input(tag.as_byte_array());
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use crate::nonce_cache::SessionSecret;

    fn hex_array<const N: usize>(vector: &serde_json::Value, field: &str) -> [u8; N] {
        let text = vector[field].as_str().unwrap();
        (0..N)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn vectors(json: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(json).unwrap()
    }

    fn secret(vector: &serde_json::Value) -> SessionSecret {
        SessionSecret::from_bytes(hex_array(vector, "secret"))
    }

    fn index(vector: &serde_json::Value, field: &str) -> u32 {
        vector[field].as_u64().unwrap() as u32
    }

    #[test]
    fn seed_vectors() {
        for vector in vectors(include_str!("../../bip-nonce-cache/test_vectors/seed.json")) {
            assert_eq!(
                secret(&vector).seed(index(&vector, "i"), index(&vector, "j")),
                hex_array(&vector, "seed")
            );
        }
    }

    #[test]
    fn session_ref_vectors() {
        for vector in vectors(include_str!(
            "../../bip-nonce-cache/test_vectors/session_ref.json"
        )) {
            assert_eq!(secret(&vector).session_ref(), hex_array(&vector, "ref"));
        }
    }

    #[test]
    fn nonce_vectors() {
        for vector in vectors(include_str!(
            "../../bip-nonce-cache/test_vectors/nonce.json"
        )) {
            let (secnonce, pubnonce) = secret(&vector)
                .nonce(
                    index(&vector, "i"),
                    index(&vector, "j"),
                    &hex_array(&vector, "sk"),
                    &hex_array(&vector, "pk"),
                )
                .unwrap();
            assert_eq!(pubnonce, hex_array::<66>(&vector, "pubnonce"));
            assert_eq!(secnonce.public_key(), hex_array::<33>(&vector, "pk"));
        }
    }

    #[test]
    fn debug_hides_the_secret() {
        let secret = SessionSecret::from_bytes([7; 32]);
        assert_eq!(format!("{secret:?}"), "SessionSecret(..)");
    }
}
