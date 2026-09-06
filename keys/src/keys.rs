use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use std::fmt::{Debug, Display};

/// Duplicated from `bwk_utils::short_string` rather than depending on
/// `bwk-utils`, which would create a dependency cycle (`bwk-utils` depends on
/// `bwk-sign`, which depends on `bwk-keys`). Covered by a test asserting the
/// two agree so the duplication cannot drift silently.
fn short_string(s: String, len: usize) -> String {
    assert!(len > 6);
    let separator = if len % 2 != 0 { "." } else { ".." };
    let head = (len - 2).div_ceil(2);
    let tail = head;
    if s.len() <= head + tail + 2 {
        return s.to_string();
    }
    format!("{}{separator}{}", &s[..head], &s[s.len() - tail..])
}

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

#[cfg(test)]
mod tests {
    use crate::keys::short_string;

    #[test]
    fn short_string_truncates_a_long_xpub() {
        let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        assert_eq!(short_string(xpub.to_string(), 18), "xpub6CUG..Au3fDVmz");
    }

    #[test]
    fn short_string_leaves_a_short_string_untouched() {
        assert_eq!(short_string("abc".to_string(), 18), "abc");
    }
}
