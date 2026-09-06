use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bwk_utils::short_string;
use std::fmt::{Debug, Display};

/// A struct that represents an extended private key.
///
/// This struct contains the origin fingerprint and derivation path
/// associated with the extended private key, as well as the key itself.
///
/// # Fields
/// * `origin` - A tuple containing the fingerprint and derivation path.
/// * `xkey` - The extended private key.
pub struct OXpriv {
    pub origin: (Fingerprint, DerivationPath),
    pub xkey: Xpriv,
}

impl Debug for OXpriv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OXpriv")
            .field("origin", &self.origin)
            .field("xkey", &"[redacted]")
            .finish()
    }
}

/// A struct that represents an extended public key.
///
/// This struct contains the origin fingerprint and derivation path
/// associated with the extended public key, as well as the key itself.
///
/// # Fields
/// * `origin` - A tuple containing the fingerprint and derivation path.
/// * `xkey` - The extended public key.
#[derive(Clone, PartialEq, Eq)]
pub struct OXpub {
    pub origin: (Fingerprint, DerivationPath),
    pub xkey: Xpub,
}

impl Debug for OXpub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OXpub")
            .field("origin", &self.origin)
            .field("xkey", &short_string(self.xkey.to_string(), 18))
            .finish()
    }
}

impl Display for OXpub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}/{}]{}", self.origin.0, self.origin.1, self.xkey)
    }
}
