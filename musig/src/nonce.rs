#![allow(dead_code, unused_variables)]

use crate::{
    backend::{MusigBackend, Rng},
    keyagg::KeyAgg,
    Error,
};

/// A secret nonce bound to its signer key. Not Clone, not serializable.
pub struct SecNonce<B: MusigBackend> {
    inner: B::SecNonce,
    public_key: [u8; 33],
}

impl<B: MusigBackend> SecNonce<B> {
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }
}

/// Fresh randomness from `rng`, optionally bound to `msg`.
pub fn nonce_gen<B: MusigBackend, R: Rng>(
    backend: &B,
    rng: &mut R,
    keyagg: &KeyAgg<B>,
    public_key: &[u8; 33],
    secret_key: Option<&[u8; 32]>,
    msg: Option<&[u8; 32]>,
) -> Result<(SecNonce<B>, [u8; 66]), Error> {
    todo!()
}

/// NonceGen with explicit `rand`, for the BIP-327 vectors.
pub fn nonce_gen_with_rand<B: MusigBackend>(
    backend: &B,
    rand: &[u8; 32],
    keyagg: Option<&KeyAgg<B>>,
    public_key: &[u8; 33],
    secret_key: Option<&[u8; 32]>,
    msg: Option<&[u8; 32]>,
    extra_in: Option<&[u8; 32]>,
) -> Result<(SecNonce<B>, [u8; 66]), Error> {
    todo!()
}

pub fn nonce_agg<B: MusigBackend>(backend: &B, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error> {
    todo!()
}
