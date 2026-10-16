#![allow(dead_code, unused_variables)]

use crate::{backend::MusigBackend, keyagg::KeyAgg, nonce::SecNonce, Error};

pub fn partial_sign<B: MusigBackend>(
    backend: &B,
    secnonce: SecNonce<B>,
    secret_key: &[u8; 32],
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
) -> Result<[u8; 32], Error> {
    todo!()
}

pub fn partial_verify<B: MusigBackend>(
    backend: &B,
    partial_sig: &[u8; 32],
    pubnonce: &[u8; 66],
    public_key: &[u8; 33],
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
) -> bool {
    todo!()
}

pub fn partial_agg<B: MusigBackend>(
    backend: &B,
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
    partial_sigs: &[[u8; 32]],
) -> Result<[u8; 64], Error> {
    todo!()
}
