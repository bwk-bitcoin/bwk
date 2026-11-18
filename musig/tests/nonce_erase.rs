#![cfg(feature = "rust-bitcoin")]

mod common;

use std::{cell::Cell, rc::Rc};

use bwk_musig::{
    nonce_agg, nonce_gen, partial_sign,
    rust_bitcoin::{
        secp256k1_musig::{ffi::MUSIG_SECNONCE_SIZE, musig::SecretNonce},
        RustBitcoin,
    },
    Error, KeyAgg, MusigBackend,
};

use crate::common::{public_key, CounterRng};

const MSG: [u8; 32] = [0x42; 32];

const SECRET_KEYS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

/// A RustBitcoin nonce that counts its erasures.
struct Tracked {
    nonce: SecretNonce,
    erased: Rc<Cell<usize>>,
}

/// RustBitcoin, with nonces counting their erasures in `erased`.
#[derive(Default)]
struct Counting {
    erased: Rc<Cell<usize>>,
}

impl MusigBackend for Counting {
    type KeyAggCache = <RustBitcoin as MusigBackend>::KeyAggCache;
    type SecNonce = Tracked;

    fn point_is_valid(&self, p: &[u8; 33]) -> bool {
        RustBitcoin.point_is_valid(p)
    }

    fn key_sort(&self, keys: &mut [[u8; 33]]) {
        RustBitcoin.key_sort(keys)
    }

    fn key_agg(&self, keys: &[[u8; 33]]) -> Result<Self::KeyAggCache, Error> {
        RustBitcoin.key_agg(keys)
    }

    fn agg_pk(&self, cache: &Self::KeyAggCache) -> [u8; 33] {
        RustBitcoin.agg_pk(cache)
    }

    fn tweak_add(
        &self,
        cache: &mut Self::KeyAggCache,
        tweak: &[u8; 32],
        x_only: bool,
    ) -> Result<[u8; 33], Error> {
        RustBitcoin.tweak_add(cache, tweak, x_only)
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
        let (nonce, pubnonce) =
            RustBitcoin.nonce_gen(rand, secret_key, public_key, cache, msg, extra_in)?;
        let tracked = Tracked {
            nonce,
            erased: self.erased.clone(),
        };
        Ok((tracked, pubnonce))
    }

    fn nonce_agg(&self, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error> {
        RustBitcoin.nonce_agg(pubnonces)
    }

    fn erase_secnonce(secnonce: &mut Self::SecNonce) {
        RustBitcoin::erase_secnonce(&mut secnonce.nonce);
        secnonce.erased.set(secnonce.erased.get() + 1);
    }

    fn partial_sign(
        &self,
        secnonce: Self::SecNonce,
        secret_key: &[u8; 32],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        RustBitcoin.partial_sign(secnonce.nonce, secret_key, cache, aggnonce, msg)
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
        RustBitcoin.partial_verify(partial_sig, pubnonce, public_key, cache, aggnonce, msg)
    }

    fn partial_agg(
        &self,
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
        partial_sigs: &[[u8; 32]],
    ) -> Result<[u8; 64], Error> {
        RustBitcoin.partial_agg(cache, aggnonce, msg, partial_sigs)
    }
}

#[test]
fn rust_bitcoin_erase_zeroes_the_nonce() {
    let keyagg = KeyAgg::sorted(&RustBitcoin, &SECRET_KEYS.map(|sk| public_key(&sk))).unwrap();
    let pk = public_key(&SECRET_KEYS[0]);
    let (nonce, _) = RustBitcoin
        .nonce_gen(&[7; 32], None, &pk, Some(keyagg.cache()), Some(&MSG), None)
        .unwrap();
    assert_ne!(nonce.dangerous_into_bytes(), [0; MUSIG_SECNONCE_SIZE]);
    let (mut nonce, _) = RustBitcoin
        .nonce_gen(&[7; 32], None, &pk, Some(keyagg.cache()), Some(&MSG), None)
        .unwrap();
    RustBitcoin::erase_secnonce(&mut nonce);
    assert_eq!(nonce.dangerous_into_bytes(), [0; MUSIG_SECNONCE_SIZE]);
}

#[test]
fn unused_nonce_is_erased_on_drop() {
    let backend = Counting::default();
    let keyagg = KeyAgg::sorted(&backend, &SECRET_KEYS.map(|sk| public_key(&sk))).unwrap();
    let pk = public_key(&SECRET_KEYS[0]);
    let (secnonce, _) = nonce_gen(
        &backend,
        &mut CounterRng(0),
        &keyagg,
        &pk,
        Some(&SECRET_KEYS[0]),
        Some(&MSG),
    )
    .unwrap();
    assert_eq!(backend.erased.get(), 0);
    drop(secnonce);
    assert_eq!(backend.erased.get(), 1);
}

#[test]
fn nonce_refused_by_partial_sign_is_erased() {
    let backend = Counting::default();
    let keyagg = KeyAgg::sorted(&backend, &SECRET_KEYS.map(|sk| public_key(&sk))).unwrap();
    // A key outside the participants: partial_sign refuses before the backend.
    let outsider = [3; 32];
    let (secnonce, pubnonce) = nonce_gen(
        &backend,
        &mut CounterRng(0),
        &keyagg,
        &public_key(&outsider),
        Some(&outsider),
        Some(&MSG),
    )
    .unwrap();
    let aggnonce = nonce_agg(&backend, &[pubnonce]).unwrap();
    assert_eq!(
        partial_sign(&backend, secnonce, &outsider, &keyagg, &aggnonce, &MSG),
        Err(Error::NotParticipant)
    );
    assert_eq!(backend.erased.get(), 1);
}

#[test]
fn nonce_consumed_by_partial_sign_is_not_erased_again() {
    let backend = Counting::default();
    let keys = SECRET_KEYS.map(|sk| public_key(&sk));
    let keyagg = KeyAgg::sorted(&backend, &keys).unwrap();
    let mut rng = CounterRng(0);
    let mut secnonces = Vec::new();
    let mut pubnonces = Vec::new();
    for (sk, pk) in SECRET_KEYS.iter().zip(&keys) {
        let (secnonce, pubnonce) =
            nonce_gen(&backend, &mut rng, &keyagg, pk, Some(sk), Some(&MSG)).unwrap();
        secnonces.push(secnonce);
        pubnonces.push(pubnonce);
    }
    let aggnonce = nonce_agg(&backend, &pubnonces).unwrap();
    for (sk, secnonce) in SECRET_KEYS.iter().zip(secnonces) {
        partial_sign(&backend, secnonce, sk, &keyagg, &aggnonce, &MSG).unwrap();
    }
    assert_eq!(backend.erased.get(), 0);
}
