use crate::Error;

/// A source of randomness for nonces, supplied per call.
pub trait Rng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// The secp256k1 library the protocol runs on.
///
/// Points are 33-byte compressed encodings, scalars 32-byte big-endian.
pub trait MusigBackend {
    /// KeyAgg context with its tweaks applied in order.
    type KeyAggCache: Clone;
    /// A secret nonce: never cloned, serialized or reused.
    type SecNonce;

    /// Whether `p` is a compressed encoding (0x02 or 0x03) of a point on the curve.
    fn point_is_valid(&self, p: &[u8; 33]) -> bool;
    /// BIP-327 KeySort, in place: a lexicographic sort of the encodings, valid or not.
    fn key_sort(&self, keys: &mut [[u8; 33]]);
    /// BIP-327 KeyAgg over `keys` in the given order. `Error::NoKeys` for an empty
    /// slice, `Error::InvalidPoint` for any invalid encoding.
    fn key_agg(&self, keys: &[[u8; 33]]) -> Result<Self::KeyAggCache, Error>;
    /// The cache's aggregate key, tweaks included.
    fn agg_pk(&self, cache: &Self::KeyAggCache) -> [u8; 33];
    /// Applies a plain or x-only tweak and returns the new aggregate key.
    /// `Error::InvalidTweak` for a tweak >= n or an infinite result, the cache is then
    /// left in an unspecified state: callers tweak a copy.
    fn tweak_add(
        &self,
        cache: &mut Self::KeyAggCache,
        tweak: &[u8; 32],
        x_only: bool,
    ) -> Result<[u8; 33], Error>;
    /// BIP-327 NonceGen with caller supplied `rand`.
    fn nonce_gen(
        &self,
        rand: &[u8; 32],
        secret_key: Option<&[u8; 32]>,
        public_key: &[u8; 33],
        cache: Option<&Self::KeyAggCache>,
        msg: Option<&[u8; 32]>,
        extra_in: Option<&[u8; 32]>,
    ) -> Result<(Self::SecNonce, [u8; 66]), Error>;
    fn nonce_agg(&self, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error>;
    /// Consumes `secnonce`: a nonce signs once.
    fn partial_sign(
        &self,
        secnonce: Self::SecNonce,
        secret_key: &[u8; 32],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> Result<[u8; 32], Error>;
    fn partial_verify(
        &self,
        partial_sig: &[u8; 32],
        pubnonce: &[u8; 66],
        public_key: &[u8; 33],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> bool;
    /// The BIP-340 signature of the aggregate key over `msg`.
    fn partial_agg(
        &self,
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
        partial_sigs: &[[u8; 32]],
    ) -> Result<[u8; 64], Error>;
}
