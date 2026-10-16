//! BIP-327 NonceGen and NonceAgg.

use crate::{
    backend::{MusigBackend, Rng},
    keyagg::KeyAgg,
    Error,
};

/// A secret nonce bound to its signer key. Not Clone, not serializable: it is moved
/// into `partial_sign` and signs once.
///
/// ```compile_fail
/// fn reuse<B: bwk_musig::MusigBackend>(n: bwk_musig::SecNonce<B>) {
///     let _copy = n.clone();
/// }
/// ```
pub struct SecNonce<B: MusigBackend> {
    inner: B::SecNonce,
    public_key: [u8; 33],
}

impl<B: MusigBackend> SecNonce<B> {
    /// The key of the signer this nonce was generated for.
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }

    pub(crate) fn into_inner(self) -> B::SecNonce {
        self.inner
    }
}

/// Fresh randomness from `rng`, optionally bound to `msg`.
///
/// `rng` must be a cryptographically secure RNG, and each signing session needs its
/// own call: a nonce reused across two sessions leaks the secret key. Binding `msg`
/// (the sighash) is recommended when it is known.
pub fn nonce_gen<B: MusigBackend, R: Rng>(
    backend: &B,
    rng: &mut R,
    keyagg: &KeyAgg<B>,
    public_key: &[u8; 33],
    secret_key: Option<&[u8; 32]>,
    msg: Option<&[u8; 32]>,
) -> Result<(SecNonce<B>, [u8; 66]), Error> {
    let mut rand = [0u8; 32];
    rng.fill_bytes(&mut rand);
    let result = nonce_gen_with_rand(
        backend,
        &rand,
        Some(keyagg),
        public_key,
        secret_key,
        msg,
        None,
    );
    rand.fill(0);
    core::hint::black_box(&rand);
    result
}

/// NonceGen with explicit `rand`, for the BIP-327 vectors and tests only.
///
/// Two calls with the same `rand` give the same nonce, and signing two messages with
/// it leaks the secret key: never reuse `rand`, wallets call [`nonce_gen`].
pub fn nonce_gen_with_rand<B: MusigBackend>(
    backend: &B,
    rand: &[u8; 32],
    keyagg: Option<&KeyAgg<B>>,
    public_key: &[u8; 33],
    secret_key: Option<&[u8; 32]>,
    msg: Option<&[u8; 32]>,
    extra_in: Option<&[u8; 32]>,
) -> Result<(SecNonce<B>, [u8; 66]), Error> {
    let (inner, pubnonce) = backend.nonce_gen(
        rand,
        secret_key,
        public_key,
        keyagg.map(KeyAgg::cache),
        msg,
        extra_in,
    )?;
    let secnonce = SecNonce {
        inner,
        public_key: *public_key,
    };
    Ok((secnonce, pubnonce))
}

/// BIP-327 NonceAgg. `Error::NoNonces` for an empty slice.
pub fn nonce_agg<B: MusigBackend>(backend: &B, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error> {
    if pubnonces.is_empty() {
        return Err(Error::NoNonces);
    }
    backend.nonce_agg(pubnonces)
}
