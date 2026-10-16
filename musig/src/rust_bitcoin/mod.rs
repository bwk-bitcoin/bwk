//! `RustBitcoin`, the `MusigBackend` on rust-secp256k1 0.33's musig module.

#![allow(dead_code, unused_variables)]

pub use secp256k1_musig;

use secp256k1_musig::{musig::KeyAggCache, PublicKey, Scalar};

use crate::{backend::MusigBackend, Error};

/// The backend on rust-secp256k1 0.33 (global context).
#[derive(Debug, Clone, Copy, Default)]
pub struct RustBitcoin;

impl RustBitcoin {
    pub fn new() -> Self {
        Self
    }
}

impl MusigBackend for RustBitcoin {
    type KeyAggCache = secp256k1_musig::musig::KeyAggCache;
    type SecNonce = secp256k1_musig::musig::SecretNonce;

    fn point_is_valid(&self, p: &[u8; 33]) -> bool {
        public_key(p).is_ok()
    }

    fn key_sort(&self, keys: &mut [[u8; 33]]) {
        // `secp256k1::sort_pubkeys` parses the keys: a byte sort also orders invalid ones.
        keys.sort_unstable();
    }

    fn key_agg(&self, keys: &[[u8; 33]]) -> Result<Self::KeyAggCache, Error> {
        // `KeyAggCache::new` panics on an empty slice.
        if keys.is_empty() {
            return Err(Error::NoKeys);
        }
        let keys = keys.iter().map(public_key).collect::<Result<Vec<_>, _>>()?;
        let refs = keys.iter().collect::<Vec<_>>();
        Ok(KeyAggCache::new(&refs))
    }

    fn agg_pk(&self, cache: &Self::KeyAggCache) -> [u8; 33] {
        cache.agg_pk_full().serialize()
    }

    fn tweak_add(
        &self,
        cache: &mut Self::KeyAggCache,
        tweak: &[u8; 32],
        x_only: bool,
    ) -> Result<[u8; 33], Error> {
        let tweak = scalar(tweak)?;
        let key = if x_only {
            cache.pubkey_xonly_tweak_add(&tweak)
        } else {
            cache.pubkey_ec_tweak_add(&tweak)
        };
        key.map(|key| key.serialize())
            .map_err(|_| Error::InvalidTweak)
    }

    fn nonce_gen(
        &self,
        rand: &[u8; 32],
        secret_key: Option<&[u8; 32]>,
        public_key: &[u8; 33],
        cache: Option<&Self::KeyAggCache>,
        msg: Option<&[u8; 32]>,
        extra_in: Option<&[u8; 32]>,
    ) -> Result<(Self::SecNonce, [u8; 66]), Error> {
        todo!()
    }

    fn nonce_agg(&self, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error> {
        todo!()
    }

    fn partial_sign(
        &self,
        secnonce: Self::SecNonce,
        secret_key: &[u8; 32],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        todo!()
    }

    fn partial_verify(
        &self,
        partial_sig: &[u8; 32],
        pubnonce: &[u8; 66],
        public_key: &[u8; 33],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> bool {
        todo!()
    }

    fn partial_agg(
        &self,
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
        partial_sigs: &[[u8; 32]],
    ) -> Result<[u8; 64], Error> {
        todo!()
    }
}

fn public_key(p: &[u8; 33]) -> Result<PublicKey, Error> {
    PublicKey::from_byte_array_compressed(*p).map_err(|_| Error::InvalidPoint)
}

fn scalar(t: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(*t).map_err(|_| Error::InvalidTweak)
}
