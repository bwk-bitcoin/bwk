use alloc::vec::Vec;

pub const EXTENDED_KEY_LEN: usize = 78;
pub const FINGERPRINT_LEN: usize = 4;
pub const PUBLIC_KEY_LEN: usize = 33;
pub const SECRET_KEY_LEN: usize = 32;
pub const MUSIG_PUB_NONCE_LEN: usize = 66;
pub const MUSIG_PARTIAL_SIG_LEN: usize = 32;
pub const TAP_LEAF_HASH_LEN: usize = 32;
/// A BIP-374 DLEQ proof, `e || s`.
pub const DLEQ_PROOF_LEN: usize = 64;
/// The secp256k1 curve order, big-endian, so a byte-wise comparison is a numeric one.
const CURVE_ORDER: [u8; SECRET_KEY_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// BIP-32 child numbers with the hardened bit set, exactly as they sit on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

/// The 78-byte BIP-32 serialization of an extended public or private key, the form
/// BIP-32 base58-encodes. A private one carries `0x00 || 32-byte key` in place of the
/// 33-byte public key, and its own version bytes, so both have the same length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; EXTENDED_KEY_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

/// A compressed secp256k1 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

/// A secp256k1 secret key as a 32-byte big-endian scalar.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey(pub [u8; SECRET_KEY_LEN]);

impl SecretKey {
    /// Nonzero and below the curve order.
    pub fn is_valid(&self) -> bool {
        self.0 != [0; SECRET_KEY_LEN] && self.0 < CURVE_ORDER
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"[redacted]").finish()
    }
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ExtendedKey(bitcoin::bip32::Error),
    PublicKey(bitcoin::key::FromSliceError),
    UncompressedPublicKey,
    SecretKey(bitcoin::secp256k1::Error),
}

#[cfg(feature = "bitcoin")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ExtendedKey(e) => write!(f, "invalid extended key: {e}"),
            Self::PublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::UncompressedPublicKey => f.write_str("public key is not compressed"),
            Self::SecretKey(e) => write!(f, "invalid secret key: {e}"),
        }
    }
}

#[cfg(feature = "bitcoin")]
impl core::error::Error for Error {}

#[cfg(feature = "bitcoin")]
impl From<&bitcoin::bip32::DerivationPath> for DerivationPath {
    fn from(path: &bitcoin::bip32::DerivationPath) -> Self {
        Self(path.as_ref().iter().copied().map(u32::from).collect())
    }
}

#[cfg(feature = "bitcoin")]
impl From<&DerivationPath> for bitcoin::bip32::DerivationPath {
    fn from(path: &DerivationPath) -> Self {
        path.0
            .iter()
            .copied()
            .map(bitcoin::bip32::ChildNumber::from)
            .collect()
    }
}

#[cfg(feature = "bitcoin")]
impl From<&bitcoin::bip32::Xpub> for ExtendedKey {
    fn from(xpub: &bitcoin::bip32::Xpub) -> Self {
        Self(xpub.encode())
    }
}

#[cfg(feature = "bitcoin")]
impl From<&bitcoin::bip32::Xpriv> for ExtendedKey {
    fn from(xpriv: &bitcoin::bip32::Xpriv) -> Self {
        Self(xpriv.encode())
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&ExtendedKey> for bitcoin::bip32::Xpub {
    type Error = Error;

    fn try_from(key: &ExtendedKey) -> Result<Self, Error> {
        Self::decode(&key.0).map_err(Error::ExtendedKey)
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&ExtendedKey> for bitcoin::bip32::Xpriv {
    type Error = Error;

    fn try_from(key: &ExtendedKey) -> Result<Self, Error> {
        Self::decode(&key.0).map_err(Error::ExtendedKey)
    }
}

#[cfg(feature = "bitcoin")]
impl From<&bitcoin::bip32::Fingerprint> for Fingerprint {
    fn from(fingerprint: &bitcoin::bip32::Fingerprint) -> Self {
        Self(fingerprint.to_bytes())
    }
}

#[cfg(feature = "bitcoin")]
impl From<&Fingerprint> for bitcoin::bip32::Fingerprint {
    fn from(fingerprint: &Fingerprint) -> Self {
        Self::from(fingerprint.0)
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&bitcoin::PublicKey> for PublicKey {
    type Error = Error;

    fn try_from(key: &bitcoin::PublicKey) -> Result<Self, Error> {
        if !key.compressed {
            return Err(Error::UncompressedPublicKey);
        }
        Ok(Self(key.inner.serialize()))
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&PublicKey> for bitcoin::PublicKey {
    type Error = Error;

    fn try_from(key: &PublicKey) -> Result<Self, Error> {
        Self::from_slice(&key.0).map_err(Error::PublicKey)
    }
}

#[cfg(feature = "bitcoin")]
impl From<&bitcoin::secp256k1::SecretKey> for SecretKey {
    fn from(key: &bitcoin::secp256k1::SecretKey) -> Self {
        Self(key.secret_bytes())
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&SecretKey> for bitcoin::secp256k1::SecretKey {
    type Error = Error;

    fn try_from(key: &SecretKey) -> Result<Self, Error> {
        Self::from_slice(&key.0).map_err(Error::SecretKey)
    }
}
