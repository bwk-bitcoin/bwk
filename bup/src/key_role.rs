//! Key role (business installer `KeyType`) in the last unhardened origin step R.

use std::fmt;

use miniscript::{
    bitcoin::{
        bip32::{DerivationPath, Fingerprint, Xpub},
        NetworkKind,
    },
    DescriptorPublicKey,
};

use crate::OXpub;

pub const BIP87_PURPOSE: u32 = 87;
/// Bits of R holding the role; the bits above hold the occurrence index.
pub const KEY_ROLE_BITS: u32 = 4;
pub const KEY_ROLE_MASK: u32 = (1 << KEY_ROLE_BITS) - 1;
/// Largest occurrence index keeping R unhardened.
pub const KEY_ROLE_MAX_INDEX: u32 = (1 << (31 - KEY_ROLE_BITS)) - 1;

/// Role of a key, as liana-connect's `ws_business::models::KeyType`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum KeyType {
    Internal,
    External,
    Cosigner,
    SafetyNet,
}

impl KeyType {
    pub const ALL: [KeyType; 4] = [
        Self::Internal,
        Self::External,
        Self::Cosigner,
        Self::SafetyNet,
    ];

    /// Its role nibble (0 to 3).
    pub const fn nibble(self) -> u32 {
        todo!()
    }

    /// R for this role at occurrence `index`.
    pub fn child_index(self, index: u32) -> Result<u32, KeyRoleError> {
        let _ = index;
        todo!()
    }

    /// The role and occurrence index in R, None for a reserved nibble.
    pub fn from_child_index(r: u32) -> Option<(Self, u32)> {
        let _ = r;
        todo!()
    }
}

/// "Internal", "External", "Cosigner", "Safety Net".
impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = f;
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRoleError {
    /// The account path is not `87'/coin'/account'`, all hardened.
    NotBip87Account,
    /// `coin'` does not match the xpub's network.
    NetworkMismatch,
    /// Occurrence index above `KEY_ROLE_MAX_INDEX`.
    IndexOutOfRange,
    Derivation(String),
}

impl fmt::Display for KeyRoleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotBip87Account => {
                write!(f, "origin path is not 87'/coin'/account', all hardened")
            }
            Self::NetworkMismatch => write!(f, "coin type does not match the xpub network"),
            Self::IndexOutOfRange => {
                write!(f, "key role occurrence index above {KEY_ROLE_MAX_INDEX}")
            }
            Self::Derivation(e) => write!(f, "key role derivation failed: {e}"),
        }
    }
}

impl std::error::Error for KeyRoleError {}

/// `m/87'/coin'/account'` for `network`.
pub fn bip87_account_path(network: NetworkKind, account: u32) -> DerivationPath {
    let _ = (network, account);
    todo!()
}

/// A BIP-87 account xpub, fetched once per key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip87Account {
    fingerprint: Fingerprint,
    path: DerivationPath,
    xpub: Xpub,
}

impl Bip87Account {
    /// Checks `path` is `87'/coin'/account'` (any hardened account) and `coin'`
    /// matches `xpub`'s network.
    pub fn new(
        fingerprint: Fingerprint,
        path: DerivationPath,
        xpub: Xpub,
    ) -> Result<Self, KeyRoleError> {
        let _ = (fingerprint, path, xpub);
        todo!()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        todo!()
    }

    pub fn path(&self) -> &DerivationPath {
        todo!()
    }

    pub fn account(&self) -> u32 {
        todo!()
    }

    /// `[fp/87'/coin'/account'/R]xpub`, R = `(index << 4) | role`, xpub the child R.
    pub fn role_key(&self, key_type: KeyType, index: u32) -> Result<OXpub, KeyRoleError> {
        let _ = (key_type, index);
        todo!()
    }
}

/// The role in `key`'s origin: origin path `87'/coin'/account'/R` with any hardened
/// account and a known role nibble in R; None otherwise. Returns the role and index.
pub fn key_type(key: &OXpub) -> Option<(KeyType, u32)> {
    let _ = key;
    todo!()
}

/// Same, for a plain descriptor key.
pub fn key_type_of(key: &DescriptorPublicKey) -> Option<(KeyType, u32)> {
    let _ = key;
    todo!()
}
