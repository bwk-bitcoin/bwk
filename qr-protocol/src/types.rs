use alloc::vec::Vec;

pub const XPUB_LEN: usize = 78;
pub const FINGERPRINT_LEN: usize = 4;
pub const PUBLIC_KEY_LEN: usize = 33;

/// BIP-32 child numbers with the hardened bit set, exactly as they sit on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

/// A serialized extended public key, the form BIP-32 base58-encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xpub(pub [u8; XPUB_LEN]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

/// A compressed secp256k1 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Xpub(bitcoin::bip32::Error),
    PublicKey(bitcoin::key::FromSliceError),
    UncompressedPublicKey,
}

#[cfg(feature = "bitcoin")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Xpub(e) => write!(f, "invalid xpub: {e}"),
            Self::PublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::UncompressedPublicKey => f.write_str("public key is not compressed"),
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
impl From<&bitcoin::bip32::Xpub> for Xpub {
    fn from(xpub: &bitcoin::bip32::Xpub) -> Self {
        Self(xpub.encode())
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&Xpub> for bitcoin::bip32::Xpub {
    type Error = Error;

    fn try_from(xpub: &Xpub) -> Result<Self, Error> {
        Self::decode(&xpub.0).map_err(Error::Xpub)
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
