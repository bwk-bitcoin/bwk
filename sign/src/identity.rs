//! Signer identity and state, shared by every signing manager.

use std::{fmt, str::FromStr};

use miniscript::bitcoin::bip32;

/// Unique identity of a live signer.
///
/// A fingerprint identifies a seed, not a signer: several signers (a hot
/// signer and a hardware device, or two devices) can hold the same seed and
/// therefore report the same fingerprint. `SignerId` is what actually
/// identifies one live entry, and is what every manager operation takes.
///
/// Managers mint their own ids in whatever shape fits them (a hot manager
/// uses a counter, the hwi manager uses the device serial, a remote manager
/// passes through whatever the far side sent); the only rule enforced here
/// is that the id is not empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignerId(String);

impl SignerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SignerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(Error::EmptyId);
        }
        Ok(Self(s.to_string()))
    }
}

impl From<SignerId> for String {
    fn from(value: SignerId) -> Self {
        value.0
    }
}

impl AsRef<str> for SignerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Whether a signer can be used right now.
///
/// A signer the host can see but cannot use is still listed with a
/// non-`Ready` state, so the user learns there is something to unlock or fix.
///
/// Maps one to one onto [`bwk_hwi::service::SigningDevice`]:
///
/// ```text
/// +------------------------------------+-------------+
/// | SigningDevice                      | SignerState |
/// +------------------------------------+-------------+
/// | Supported(SupportedDevice { .. })  | Ready       |
/// | Locked { pairing_code, .. }        | Locked      |
/// | Unsupported { reason, .. }         | Unsupported |
/// +------------------------------------+-------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignerState {
    /// Usable: fingerprint known, requests work.
    Ready,
    /// Seen, needs an unlock step (device pairing, PIN).
    Locked,
    /// Seen, unusable as-is: wrong network, app not open, too old.
    Unsupported,
}

impl SignerState {
    pub fn is_ready(&self) -> bool {
        matches!(self, SignerState::Ready)
    }
}

impl fmt::Display for SignerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SignerState::Ready => "ready",
            SignerState::Locked => "locked",
            SignerState::Unsupported => "unsupported",
        };
        write!(f, "{s}")
    }
}

/// Description of one live signer.
///
/// Every field is set at construction and never mutated: a signer whose
/// state changes is dropped from the manager's list and registered again as
/// a new entry, so a reader never sees a `SignerInfo` change underneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub id: SignerId,
    pub fingerprint: bip32::Fingerprint,
    pub wallet_name: String,
    pub state: SignerState,
    /// Single line meant for a UI: a pairing code, `"app is not open"`,
    /// `"wrong network"`. Empty when `state` is `Ready`.
    pub state_detail: String,
}

impl SignerInfo {
    pub fn new(
        id: SignerId,
        fingerprint: bip32::Fingerprint,
        wallet_name: String,
        state: SignerState,
    ) -> Self {
        Self {
            id,
            fingerprint,
            wallet_name,
            state,
            state_detail: String::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.state_detail = detail.into();
        self
    }
}

impl PartialOrd for SignerInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SignerInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("signer id must not be empty")]
    EmptyId,
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr};

    use miniscript::bitcoin::bip32;

    use crate::identity::{Error, SignerId, SignerInfo, SignerState};

    #[test]
    fn signer_id_roundtrips() {
        let id = SignerId::from_str("hot:73c5da0a:0").unwrap();
        assert_eq!(id.to_string(), "hot:73c5da0a:0");
    }

    #[test]
    fn empty_signer_id_rejected() {
        assert_eq!(SignerId::from_str(""), Err(Error::EmptyId));
    }

    #[test]
    fn fingerprint_is_not_the_identity() {
        let fingerprint = bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]);
        let a = SignerInfo::new(
            SignerId::new("a"),
            fingerprint,
            "wallet".to_string(),
            SignerState::Ready,
        );
        let b = SignerInfo::new(
            SignerId::new("b"),
            fingerprint,
            "wallet".to_string(),
            SignerState::Ready,
        );
        assert_ne!(a, b);

        let mut set = BTreeSet::new();
        set.insert(a.clone());
        set.insert(b.clone());
        assert_eq!(set.len(), 2);
        assert_eq!(set.into_iter().collect::<Vec<_>>(), vec![a, b]);
    }

    #[test]
    fn same_id_is_the_same_signer() {
        let a = SignerInfo::new(
            SignerId::new("same"),
            bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]),
            "wallet-a".to_string(),
            SignerState::Ready,
        );
        let b = SignerInfo::new(
            SignerId::new("same"),
            bip32::Fingerprint::from([0x05, 0x06, 0x07, 0x08]),
            "wallet-b".to_string(),
            SignerState::Locked,
        );
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn state_is_ready_only_for_ready() {
        assert!(SignerState::Ready.is_ready());
        assert!(!SignerState::Locked.is_ready());
        assert!(!SignerState::Unsupported.is_ready());
    }

    #[test]
    fn state_display_is_lowercase() {
        assert_eq!(SignerState::Ready.to_string(), "ready");
        assert_eq!(SignerState::Locked.to_string(), "locked");
        assert_eq!(SignerState::Unsupported.to_string(), "unsupported");
    }

    #[test]
    fn with_detail_sets_the_line() {
        let info = SignerInfo::new(
            SignerId::new("id"),
            bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]),
            "wallet".to_string(),
            SignerState::Locked,
        )
        .with_detail("pair 1234");
        assert_eq!(info.state_detail, "pair 1234");

        let info = SignerInfo::new(
            SignerId::new("id"),
            bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]),
            "wallet".to_string(),
            SignerState::Ready,
        );
        assert_eq!(info.state_detail, "");
    }
}
