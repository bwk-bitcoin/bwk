//! BIP-327 Sign, PartialSigVerify and PartialSigAgg.

use crate::{backend::MusigBackend, keyagg::KeyAgg, nonce::SecNonce, Error};

/// BIP-327 Sign. Consumes `secnonce`, also on error, so it never signs twice. The
/// tweaks of `keyagg` are applied. `Error::NotParticipant` when the nonce's signer
/// key is not one of the participants.
pub fn partial_sign<B: MusigBackend>(
    backend: &B,
    secnonce: SecNonce<B>,
    secret_key: &[u8; 32],
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
) -> Result<[u8; 32], Error> {
    if !keyagg.participants().contains(&secnonce.public_key()) {
        return Err(Error::NotParticipant);
    }
    backend.partial_sign(
        secnonce.into_inner(),
        secret_key,
        keyagg.cache(),
        aggnonce,
        msg,
    )
}

/// BIP-327 PartialSigVerify of the share of `public_key`; false on any invalid input.
pub fn partial_verify<B: MusigBackend>(
    backend: &B,
    partial_sig: &[u8; 32],
    pubnonce: &[u8; 66],
    public_key: &[u8; 33],
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
) -> bool {
    backend.partial_verify(
        partial_sig,
        pubnonce,
        public_key,
        keyagg.cache(),
        aggnonce,
        msg,
    )
}

/// BIP-327 PartialSigAgg: one share per participant, repeated keys included, else
/// `Error::PartialSigCount`. The result is not verified: the caller checks it against
/// `keyagg.output_key()`.
pub fn partial_agg<B: MusigBackend>(
    backend: &B,
    keyagg: &KeyAgg<B>,
    aggnonce: &[u8; 66],
    msg: &[u8; 32],
    partial_sigs: &[[u8; 32]],
) -> Result<[u8; 64], Error> {
    if partial_sigs.len() != keyagg.participants().len() {
        return Err(Error::PartialSigCount);
    }
    backend.partial_agg(keyagg.cache(), aggnonce, msg, partial_sigs)
}
