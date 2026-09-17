//! BIP32 public derivation, reduced to what BIP89 needs. A delegatee holds no
//! private key, so only non-hardened child steps are supported; a hardened
//! step is refused. `compute_bip32_tweak` walks a path of such steps and adds
//! up their scalars into one aggregated tweak, which `tweak_key` can later
//! apply to a base public key to get the same child key without repeating
//! the walk, and `tweak_secret` to the matching base secret to get that
//! child's secret.

use crate::{
    backend::BitcoinBackend,
    scalar::{add_opt, scalar_is_valid, scalar_is_zero, HmacSha512},
    Error,
};

/// The result of a BIP32 non-hardened derivation: the scalar tweak, the
/// resulting public key and its chain code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derived {
    pub tweak: [u8; 32],
    pub key: [u8; 33],
    pub chain_code: [u8; 32],
}

/// BIP32 CKDpub: derives one non-hardened child from a public key and chain
/// code.
pub(crate) fn ckd_pub<B: BitcoinBackend>(
    c: &B,
    key: &[u8; 33],
    chain_code: &[u8; 32],
    index: u32,
) -> Result<Derived, Error> {
    if index >= 0x8000_0000 {
        return Err(Error::HardenedIndex);
    }

    let mut hmac = HmacSha512::new(c, chain_code);
    hmac.update(key);
    hmac.update(&index.to_be_bytes());
    let i = hmac.finalize();
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);

    if !scalar_is_valid(&il) {
        return Err(Error::InvalidChild);
    }

    let child = add_opt(c, Some(*key), c.base_mul(&il)).ok_or(Error::InvalidChild)?;

    Ok(Derived {
        tweak: il,
        key: child,
        chain_code: ir,
    })
}

/// Runs BIP89's ComputeBIP32Tweak: walks a path of non-hardened child
/// indices from `key`/`chain_code` and adds up each step's scalar into a
/// single tweak. An empty path returns the zero tweak with the key and chain
/// code unchanged.
pub fn compute_bip32_tweak<B: BitcoinBackend>(
    c: &B,
    key: &[u8; 33],
    chain_code: &[u8; 32],
    path: &[u32],
) -> Result<Derived, Error> {
    if !c.point_is_valid(key) {
        return Err(Error::InvalidPoint);
    }

    let mut acc = Derived {
        tweak: [0u8; 32],
        key: *key,
        chain_code: *chain_code,
    };
    for &index in path {
        let d = ckd_pub(c, &acc.key, &acc.chain_code, index)?;
        acc = Derived {
            tweak: c.scalar_add(&acc.tweak, &d.tweak),
            key: d.key,
            chain_code: d.chain_code,
        };
    }
    Ok(acc)
}

/// Applies an aggregated tweak to a base public key, without walking the
/// path again. A zero tweak returns `base` unchanged.
pub fn tweak_key<B: BitcoinBackend>(
    c: &B,
    base: &[u8; 33],
    tweak: &[u8; 32],
) -> Result<[u8; 33], Error> {
    if !c.point_is_valid(base) {
        return Err(Error::InvalidPoint);
    }
    if !scalar_is_valid(tweak) {
        return Err(Error::ScalarRange);
    }
    add_opt(c, Some(*base), c.base_mul(tweak)).ok_or(Error::Infinity)
}

/// Applies an aggregated tweak to a base secret key, giving the secret of the
/// key `tweak_key` derives from that secret's public key. A zero tweak returns
/// `secret` unchanged.
pub fn tweak_secret<B: BitcoinBackend>(
    c: &B,
    secret: &[u8; 32],
    tweak: &[u8; 32],
) -> Result<[u8; 32], Error> {
    if !scalar_is_valid(secret) || scalar_is_zero(secret) {
        return Err(Error::SecretKey);
    }
    if !scalar_is_valid(tweak) {
        return Err(Error::ScalarRange);
    }
    let tweaked = c.scalar_add(secret, tweak);
    if scalar_is_zero(&tweaked) {
        return Err(Error::SecretKey);
    }
    Ok(tweaked)
}
