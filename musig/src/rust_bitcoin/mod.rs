//! `RustBitcoin`, the `MusigBackend` on rust-secp256k1 0.33's musig module.

pub use secp256k1_musig;

use secp256k1_musig::{
    ffi::{CPtr, MUSIG_SECNONCE_SIZE},
    musig::{
        new_nonce_pair, AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SecretNonce,
        Session, SessionSecretRand,
    },
    Keypair, PublicKey, Scalar, SecretKey,
};

use crate::{backend::MusigBackend, Error};

/// First 4 bytes of a libsecp secret nonce that was never used.
const SECNONCE_MAGIC: [u8; 4] = [0x22, 0x0e, 0xdc, 0xf1];

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

    // Callers go through `bwk_musig::nonce_gen`: the upstream `SecretNonce` `Debug`
    // prints its secret bytes, never format it.
    fn nonce_gen(
        &self,
        rand: &[u8; 32],
        secret_key: Option<&[u8; 32]>,
        public_key: &[u8; 33],
        cache: Option<&Self::KeyAggCache>,
        msg: Option<&[u8; 32]>,
        extra_in: Option<&[u8; 32]>,
    ) -> Result<(Self::SecNonce, [u8; 66]), Error> {
        // `SessionSecretRand` panics on an all-zero value.
        if *rand == [0; 32] {
            return Err(Error::InvalidSecNonce);
        }
        let secret_key = secret_key
            .map(|sk| SecretKey::from_secret_bytes(*sk).map_err(|_| Error::InvalidSecretKey))
            .transpose()?;
        let public_key = self::public_key(public_key)?;
        // libsecp mixes the secret key into rand itself (BIP-327 NonceGen): rand goes
        // in raw, not through `assume_unique_per_nonce_gen`.
        let (secnonce, pubnonce) = new_nonce_pair(
            SessionSecretRand::assume_uniformly_random(*rand),
            cache,
            secret_key,
            public_key,
            msg,
            extra_in.copied(),
        );
        Ok((secnonce, pubnonce.serialize()))
    }

    fn nonce_agg(&self, pubnonces: &[[u8; 66]]) -> Result<[u8; 66], Error> {
        // `AggregatedNonce::new` panics on an empty slice.
        if pubnonces.is_empty() {
            return Err(Error::NoNonces);
        }
        let nonces = pubnonces
            .iter()
            .map(|n| PublicNonce::from_byte_array(n).map_err(|_| Error::InvalidPubNonce))
            .collect::<Result<Vec<_>, _>>()?;
        let refs = nonces.iter().collect::<Vec<_>>();
        Ok(AggregatedNonce::new(&refs).serialize())
    }

    /// `Session::partial_sign` asserts on a used nonce or one of another key: the
    /// nonce goes through its bytes to be checked first. The bytes stay local to this
    /// call and are zeroed, never stored.
    fn partial_sign(
        &self,
        secnonce: Self::SecNonce,
        secret_key: &[u8; 32],
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        let mut bytes = secnonce.dangerous_into_bytes();
        let (aggnonce, keypair) = match sign_inputs(&bytes, secret_key, aggnonce) {
            Ok(inputs) => inputs,
            Err(e) => {
                erase(&mut bytes);
                return Err(e);
            }
        };
        let secnonce = SecretNonce::dangerous_from_bytes(bytes);
        erase(&mut bytes);
        let session = Session::new(cache, aggnonce, msg);
        Ok(session.partial_sign(secnonce, &keypair, cache).serialize())
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
        let (Ok(sig), Ok(nonce), Ok(pk), Ok(aggnonce)) = (
            PartialSignature::from_byte_array(partial_sig),
            PublicNonce::from_byte_array(pubnonce),
            self::public_key(public_key),
            agg_nonce(aggnonce),
        ) else {
            return false;
        };
        Session::new(cache, aggnonce, msg).partial_verify(cache, &sig, &nonce, pk)
    }

    fn partial_agg(
        &self,
        cache: &Self::KeyAggCache,
        aggnonce: &[u8; 66],
        msg: &[u8; 32],
        partial_sigs: &[[u8; 32]],
    ) -> Result<[u8; 64], Error> {
        // `Session::partial_sig_agg` panics on an empty slice.
        if partial_sigs.is_empty() {
            return Err(Error::PartialSigCount);
        }
        let aggnonce = agg_nonce(aggnonce)?;
        let sigs = partial_sigs
            .iter()
            .map(|s| PartialSignature::from_byte_array(s).map_err(|_| Error::InvalidPartialSig))
            .collect::<Result<Vec<_>, _>>()?;
        let refs = sigs.iter().collect::<Vec<_>>();
        let session = Session::new(cache, aggnonce, msg);
        Ok(session
            .partial_sig_agg(&refs)
            .assume_valid()
            .to_byte_array())
    }
}

fn public_key(p: &[u8; 33]) -> Result<PublicKey, Error> {
    PublicKey::from_byte_array_compressed(*p).map_err(|_| Error::InvalidPoint)
}

fn scalar(t: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(*t).map_err(|_| Error::InvalidTweak)
}

fn agg_nonce(n: &[u8; 66]) -> Result<AggregatedNonce, Error> {
    AggregatedNonce::from_byte_array(n).map_err(|_| Error::InvalidPubNonce)
}

/// The parsed aggregate nonce and signer keypair, once `secnonce` passed
/// `check_secnonce`.
fn sign_inputs(
    secnonce: &[u8; MUSIG_SECNONCE_SIZE],
    secret_key: &[u8; 32],
    aggnonce: &[u8; 66],
) -> Result<(AggregatedNonce, Keypair), Error> {
    let aggnonce = agg_nonce(aggnonce)?;
    let keypair = Keypair::from_secret_bytes(*secret_key).map_err(|_| Error::InvalidSecretKey)?;
    check_secnonce(secnonce, &keypair)?;
    Ok((aggnonce, keypair))
}

/// What libsecp asserts on in `partial_sign`: an unused nonce (magic), k1 and k2 in
/// 1..n (BIP-327 Sign), and the signer key of `keypair`.
fn check_secnonce(bytes: &[u8; MUSIG_SECNONCE_SIZE], keypair: &Keypair) -> Result<(), Error> {
    if bytes[0..4] != SECNONCE_MAGIC || !is_scalar(&bytes[4..36]) || !is_scalar(&bytes[36..68]) {
        return Err(Error::InvalidSecNonce);
    }
    if bytes[68..] != internal_bytes(&keypair.public_key()) {
        return Err(Error::NonceKeyMismatch);
    }
    Ok(())
}

/// Whether `b` is a 32-byte scalar in 1..n.
fn is_scalar(b: &[u8]) -> bool {
    <[u8; 32]>::try_from(b).is_ok_and(|b| SecretKey::from_secret_bytes(b).is_ok())
}

/// The 64-byte libsecp internal storage of `pk`, the encoding a secret nonce keeps
/// its signer key in.
fn internal_bytes(pk: &PublicKey) -> [u8; 64] {
    // SAFETY: `as_c_ptr` points at the `ffi::PublicKey` field of the live `pk`, so the
    // read is in bounds and aligned; `underlying_bytes` copies it out.
    unsafe { (*pk.as_c_ptr()).underlying_bytes() }
}

fn erase(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}
