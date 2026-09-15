//! BIP340 Schnorr signing and verification over the backend. Used by
//! delegator signing; signing self-verifies so a faulty backend cannot leak a
//! bad signature.

use crate::{
    backend::{BitcoinBackend, Sha256Engine},
    scalar::{
        add_opt, has_even_y, lift_x, scalar_is_valid, scalar_is_zero, scalar_neg, scalar_reduce,
        tagged_hash256, xbytes,
    },
    Error,
};

/// Signs a 32-byte message with BIP340 Schnorr. `aux` is caller-supplied
/// randomness, sourced by the caller through the `Rng` trait.
pub fn sign<B: BitcoinBackend>(
    c: &B,
    secret: &[u8; 32],
    msg: &[u8; 32],
    aux: &[u8; 32],
) -> Result<[u8; 64], Error> {
    if !scalar_is_valid(secret) || scalar_is_zero(secret) {
        return Err(Error::SecretKey);
    }
    let point = c.base_mul(secret).ok_or(Error::SecretKey)?;
    let d = if has_even_y(&point) {
        *secret
    } else {
        scalar_neg(secret)
    };

    let mut aux_engine = tagged_hash256(c, b"BIP0340/aux");
    aux_engine.update(aux);
    let aux_hash = aux_engine.finalize();
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = d[i] ^ aux_hash[i];
    }

    let mut nonce_engine = tagged_hash256(c, b"BIP0340/nonce");
    nonce_engine.update(&t);
    nonce_engine.update(&xbytes(&point));
    nonce_engine.update(msg);
    let k_prime = scalar_reduce(&nonce_engine.finalize());
    if scalar_is_zero(&k_prime) {
        return Err(Error::ZeroNonce);
    }

    let r_point = c.base_mul(&k_prime).ok_or(Error::ZeroNonce)?;
    let k = if has_even_y(&r_point) {
        k_prime
    } else {
        scalar_neg(&k_prime)
    };

    let mut challenge_engine = tagged_hash256(c, b"BIP0340/challenge");
    challenge_engine.update(&xbytes(&r_point));
    challenge_engine.update(&xbytes(&point));
    challenge_engine.update(msg);
    let e = scalar_reduce(&challenge_engine.finalize());

    let s = c.scalar_add(&k, &c.scalar_mul(&e, &d));

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&xbytes(&r_point));
    sig[32..].copy_from_slice(&s);

    if !verify(c, &xbytes(&point), msg, &sig) {
        return Err(Error::SecretKey);
    }
    Ok(sig)
}

/// Verifies a BIP340 Schnorr signature over a 32-byte message.
pub fn verify<B: BitcoinBackend>(c: &B, xonly: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Some(point) = lift_x(c, xonly) else {
        return false;
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !scalar_is_valid(&s) {
        return false;
    }

    let mut challenge_engine = tagged_hash256(c, b"BIP0340/challenge");
    challenge_engine.update(&r);
    challenge_engine.update(xonly);
    challenge_engine.update(msg);
    let e = scalar_reduce(&challenge_engine.finalize());

    let Some(r_computed) = add_opt(c, c.base_mul(&s), c.point_mul(&point, &scalar_neg(&e))) else {
        return false;
    };
    has_even_y(&r_computed) && xbytes(&r_computed) == r
}
