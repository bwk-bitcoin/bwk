//! BIP89 blinded signing: the tweak context that folds plain and x-only
//! tweaks into a running public key, blind nonce generation, blind challenge
//! generation, the signer's blind sign and verify, and the delegatee's
//! unblinding into the final BIP340 signature. This is the plain blind
//! Schnorr flow, not concurrency safe: a signer must never run two blind
//! signing sessions at once. `BlindSecNonce` cannot be cloned, copied or
//! printed, so a caller cannot accidentally duplicate or log a nonce that
//! must be used exactly once.

use alloc::vec::Vec;

use crate::{
    backend::{BitcoinBackend, Rng, Sha256Engine, Sha512Engine},
    scalar::{
        add_opt, has_even_y, point_neg, scalar_is_valid, scalar_is_zero, scalar_neg, scalar_reduce,
        tagged_hash256, tagged_hash512, xbytes,
    },
    Error,
};

/// A running tweak state: the tweaked point, whether the accumulated parity
/// factor is minus one, and the accumulated tweak scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TweakContext {
    pub q: [u8; 33],
    pub gacc_neg: bool,
    pub tacc: [u8; 32],
}

/// Starts a tweak context at the base public key, with no tweaks applied.
pub fn tweak_ctx_init<B: BitcoinBackend>(c: &B, pk: &[u8; 33]) -> Result<TweakContext, Error> {
    if !c.point_is_valid(pk) {
        return Err(Error::InvalidPoint);
    }
    Ok(TweakContext {
        q: *pk,
        gacc_neg: false,
        tacc: [0u8; 32],
    })
}

/// Folds one more tweak into the context. For an x-only tweak on a point
/// with odd y, the point is negated first so the result keeps an even y as
/// BIP340 tweaking requires.
pub fn apply_tweak<B: BitcoinBackend>(
    c: &B,
    ctx: &TweakContext,
    tweak: &[u8; 32],
    is_xonly: bool,
) -> Result<TweakContext, Error> {
    if !scalar_is_valid(tweak) {
        return Err(Error::ScalarRange);
    }
    let neg = is_xonly && !has_even_y(&ctx.q);
    let q = if neg { point_neg(&ctx.q) } else { ctx.q };
    let q2 = add_opt(c, Some(q), c.base_mul(tweak)).ok_or(Error::Infinity)?;
    let gacc_neg = ctx.gacc_neg != neg;
    let prior_tacc = if neg { scalar_neg(&ctx.tacc) } else { ctx.tacc };
    let tacc = c.scalar_add(tweak, &prior_tacc);
    Ok(TweakContext {
        q: q2,
        gacc_neg,
        tacc,
    })
}

/// A blind secret nonce: `k' (32 bytes)` and, when the caller supplied a
/// public key to `blind_nonce_gen`, that key appended (33 bytes). Fields are
/// private and the type derives neither `Clone`, `Copy` nor `Debug`, so a
/// secret nonce cannot be duplicated or printed by accident.
pub struct BlindSecNonce {
    bytes: [u8; 65],
    len: usize,
}

impl BlindSecNonce {
    /// Builds a secret nonce from its wire bytes. Only lengths 32 (no public
    /// key) and 65 (with public key) are valid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.len() {
            32 | 65 => {
                let mut buf = [0u8; 65];
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(Self {
                    bytes: buf,
                    len: bytes.len(),
                })
            }
            _ => Err(Error::SecNonceLength),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Big-endian 4-byte length prefix, as the nonce hash layout requires.
/// Fails when `extra_in` does not fit the 4-byte length prefix.
fn len32(len: usize) -> Result<[u8; 4], Error> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| Error::ExtraInLength)
}

/// Generates a blind secret nonce and its public counterpart. When `sk` is
/// present, the drawn randomness is mixed with it under the `CCD/aux` tag so
/// the randomness source and the secret key are not combined directly.
pub fn blind_nonce_gen<B: BitcoinBackend, R: Rng>(
    c: &B,
    rng: &mut R,
    sk: Option<&[u8; 32]>,
    pk: Option<&[u8; 33]>,
    extra_in: Option<&[u8]>,
) -> Result<(BlindSecNonce, [u8; 33]), Error> {
    let mut rand_ = [0u8; 32];
    rng.fill_bytes(&mut rand_);

    let rand = match sk {
        Some(sk) => {
            let mut aux_engine = tagged_hash256(c, b"CCD/aux");
            aux_engine.update(&rand_);
            let aux = aux_engine.finalize();
            let mut rand = [0u8; 32];
            for i in 0..32 {
                rand[i] = sk[i] ^ aux[i];
            }
            rand
        }
        None => rand_,
    };

    let pk_bytes: &[u8] = pk.map_or(&[][..], |pk| &pk[..]);
    let extra = extra_in.unwrap_or(&[]);

    let mut engine = tagged_hash256(c, b"CCD/blindnonce");
    engine.update(&rand);
    engine.update(&[pk_bytes.len() as u8]);
    engine.update(pk_bytes);
    engine.update(&len32(extra.len())?);
    engine.update(extra);
    let k_prime = scalar_reduce(&engine.finalize());

    if scalar_is_zero(&k_prime) {
        return Err(Error::ZeroNonce);
    }
    let pubnonce = c.base_mul(&k_prime).ok_or(Error::ZeroNonce)?;

    let mut bytes = [0u8; 65];
    bytes[..32].copy_from_slice(&k_prime);
    let len = match pk {
        Some(pk) => {
            bytes[32..65].copy_from_slice(pk);
            65
        }
        None => 32,
    };

    Ok((BlindSecNonce { bytes, len }, pubnonce))
}

/// The state a delegatee keeps between round 2 and round 4 of blind signing:
/// the base key, the blind factor and challenge it computed, the combined
/// public nonce, and the tweaks that were folded into the running key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub pk: [u8; 33],
    pub blindfactor: [u8; 32],
    pub challenge: [u8; 32],
    pub pubnonce: [u8; 33],
    pub tweaks: Vec<[u8; 32]>,
    pub is_xonly: Vec<bool>,
}

/// The output of `blind_challenge_gen`: the session the delegatee keeps, and
/// the blinded challenge and parity bits sent to the signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindChallenge {
    pub session: SessionContext,
    pub blindchallenge: [u8; 32],
    pub pk_parity: bool,
    pub nonce_parity: bool,
}

/// Rebuilds the tweak context from a base key and its tweaks. Checks the
/// tweaks and is_xonly lengths match before folding, matching the reference
/// implementation's error order.
fn pubkey_and_tweak<B: BitcoinBackend>(
    c: &B,
    pk: &[u8; 33],
    tweaks: &[[u8; 32]],
    is_xonly: &[bool],
) -> Result<TweakContext, Error> {
    if tweaks.len() != is_xonly.len() {
        return Err(Error::TweakCount);
    }
    let mut ctx = tweak_ctx_init(c, pk)?;
    for (tweak, xonly) in tweaks.iter().zip(is_xonly.iter()) {
        ctx = apply_tweak(c, &ctx, tweak, *xonly)?;
    }
    Ok(ctx)
}

/// Blinds a challenge for the signer over the tweaked key `pk`, given the
/// signer's public nonce. The returned `SessionContext` stays with the
/// delegatee for unblinding later; only `blindchallenge` and the two parities
/// go to the signer.
#[allow(clippy::too_many_arguments)]
pub fn blind_challenge_gen<B: BitcoinBackend, R: Rng>(
    c: &B,
    rng: &mut R,
    msg: &[u8],
    blindpubnonce: &[u8; 33],
    pk: &[u8; 33],
    tweaks: &[[u8; 32]],
    is_xonly: &[bool],
    extra_in: Option<&[u8]>,
) -> Result<BlindChallenge, Error> {
    let ctx = pubkey_and_tweak(c, pk, tweaks, is_xonly)?;
    let q = ctx.q;

    if !c.point_is_valid(blindpubnonce) {
        return Err(Error::InvalidPoint);
    }

    let mut rand = [0u8; 32];
    rng.fill_bytes(&mut rand);
    let extra = extra_in.unwrap_or(&[]);

    let mut engine = tagged_hash512(c, b"CCD/blindfactor");
    engine.update(&rand);
    engine.update(&[33]);
    engine.update(&q);
    engine.update(&[33]);
    engine.update(blindpubnonce);
    engine.update(&(msg.len() as u64).to_be_bytes());
    engine.update(msg);
    engine.update(&len32(extra.len())?);
    engine.update(extra);
    let z = engine.finalize();

    let mut a_prime = [0u8; 32];
    a_prime.copy_from_slice(&z[0..32]);
    let a_prime = scalar_reduce(&a_prime);
    let mut b_prime = [0u8; 32];
    b_prime.copy_from_slice(&z[32..64]);
    let b_prime = scalar_reduce(&b_prime);
    if scalar_is_zero(&a_prime) || scalar_is_zero(&b_prime) {
        return Err(Error::ZeroNonce);
    }

    let pk_parity = has_even_y(&q) != ctx.gacc_neg;
    let x = if pk_parity { *pk } else { point_neg(pk) };

    let r = add_opt(
        c,
        add_opt(c, Some(*blindpubnonce), c.base_mul(&a_prime)),
        c.point_mul(&x, &b_prime),
    )
    .ok_or(Error::Infinity)?;

    let nonce_parity = has_even_y(&r);
    let (a, b) = if nonce_parity {
        (a_prime, b_prime)
    } else {
        (scalar_neg(&a_prime), scalar_neg(&b_prime))
    };

    let mut challenge_engine = tagged_hash256(c, b"BIP0340/challenge");
    challenge_engine.update(&xbytes(&r));
    challenge_engine.update(&xbytes(&q));
    challenge_engine.update(msg);
    let e = scalar_reduce(&challenge_engine.finalize());
    let e_prime = c.scalar_add(&e, &b);

    Ok(BlindChallenge {
        session: SessionContext {
            pk: *pk,
            blindfactor: a,
            challenge: e,
            pubnonce: r,
            tweaks: tweaks.to_vec(),
            is_xonly: is_xonly.to_vec(),
        },
        blindchallenge: e_prime,
        pk_parity,
        nonce_parity,
    })
}

/// Verifies a blind signature against the signer's public nonce, before
/// unblinding. A malformed input errors; a signature that does not match
/// returns `Ok(false)`.
pub fn verify_blind_signature<B: BitcoinBackend>(
    c: &B,
    pk: &[u8; 33],
    blindpubnonce: &[u8; 33],
    blindchallenge: &[u8; 32],
    blindsignature: &[u8; 32],
    pk_parity: bool,
    nonce_parity: bool,
) -> Result<bool, Error> {
    if !c.point_is_valid(pk) || !c.point_is_valid(blindpubnonce) {
        return Err(Error::InvalidPoint);
    }
    if !scalar_is_valid(blindchallenge) || !scalar_is_valid(blindsignature) {
        return Err(Error::ScalarRange);
    }

    let p = if pk_parity { *pk } else { point_neg(pk) };
    let r = if nonce_parity {
        *blindpubnonce
    } else {
        point_neg(blindpubnonce)
    };

    let calc = add_opt(
        c,
        c.base_mul(blindsignature),
        c.point_mul(&p, &scalar_neg(blindchallenge)),
    );
    Ok(calc == Some(r))
}

/// Signs under a blinded challenge with the secret nonce from
/// `blind_nonce_gen`. The secnonce is zeroed once its bytes are read, so a
/// second call on the same secnonce fails with `NonceReuse`; reusing a nonce
/// across two blind signatures would reveal the secret key.
pub fn blind_sign<B: BitcoinBackend>(
    c: &B,
    sk: &[u8; 32],
    blindchallenge: &[u8; 32],
    secnonce: &mut BlindSecNonce,
    pk_parity: bool,
    nonce_parity: bool,
) -> Result<[u8; 32], Error> {
    if !scalar_is_valid(sk) || scalar_is_zero(sk) {
        return Err(Error::SecretKey);
    }
    let p = c.base_mul(sk).ok_or(Error::SecretKey)?;
    let d = if pk_parity { *sk } else { scalar_neg(sk) };

    if !scalar_is_valid(blindchallenge) {
        return Err(Error::ScalarRange);
    }

    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&secnonce.bytes[..32]);
    if scalar_is_zero(&k_prime) || !scalar_is_valid(&k_prime) {
        return Err(Error::NonceReuse);
    }
    let k = if nonce_parity {
        k_prime
    } else {
        scalar_neg(&k_prime)
    };

    let used = secnonce.len.min(64);
    secnonce.bytes[..used].fill(0);

    let r_prime = c.base_mul(&k_prime).ok_or(Error::Infinity)?;
    let s_prime = c.scalar_add(&k, &c.scalar_mul(blindchallenge, &d));

    match verify_blind_signature(
        c,
        &p,
        &r_prime,
        blindchallenge,
        &s_prime,
        pk_parity,
        nonce_parity,
    ) {
        Ok(true) => Ok(s_prime),
        _ => Err(Error::BlindSignature),
    }
}

/// Unblinds a signer's blind signature into the final BIP340 signature over
/// the tweaked key, using the session the delegatee kept from
/// `blind_challenge_gen`.
pub fn unblind_signature<B: BitcoinBackend>(
    c: &B,
    session: &SessionContext,
    blindsignature: &[u8; 32],
) -> Result<[u8; 64], Error> {
    let ctx = pubkey_and_tweak(c, &session.pk, &session.tweaks, &session.is_xonly)?;

    if !scalar_is_valid(&session.blindfactor) || !scalar_is_valid(&session.challenge) {
        return Err(Error::ScalarRange);
    }
    if !c.point_is_valid(&session.pubnonce) {
        return Err(Error::InvalidPoint);
    }
    if !scalar_is_valid(blindsignature) {
        return Err(Error::ScalarRange);
    }

    let mut et = c.scalar_mul(&session.challenge, &ctx.tacc);
    if !has_even_y(&ctx.q) {
        et = scalar_neg(&et);
    }
    let s = c.scalar_add(&c.scalar_add(blindsignature, &session.blindfactor), &et);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&xbytes(&session.pubnonce));
    sig[32..].copy_from_slice(&s);
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use crate::{
        blind::{len32, BlindSecNonce},
        Error,
    };

    #[test]
    fn len32_prefix() {
        assert_eq!(len32(1), Ok([0, 0, 0, 1]));
        assert_eq!(len32(u32::MAX as usize), Ok([0xff; 4]));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(len32(u32::MAX as usize + 1), Err(Error::ExtraInLength));
    }

    #[test]
    fn secnonce_from_bytes_lengths() {
        for len in [32usize, 65] {
            let bytes: Vec<u8> = (1u8..).take(len).collect();
            let sec = BlindSecNonce::from_bytes(&bytes).unwrap();
            assert_eq!(sec.as_bytes(), bytes.as_slice());
        }
        for len in [0usize, 31, 33, 64, 66] {
            let bytes: Vec<u8> = (1u8..).take(len).collect();
            assert!(matches!(
                BlindSecNonce::from_bytes(&bytes).err(),
                Some(Error::SecNonceLength)
            ));
        }
    }
}
