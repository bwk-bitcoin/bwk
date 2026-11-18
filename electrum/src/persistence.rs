//! Caller-owned persistence, independent of a native filesystem layout.

use std::{fmt::Debug, sync::Arc};

use bwk_persist::{backend::PersistenceBackend, PersistError};
use miniscript::bitcoin::Network;
use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "test"))]
pub mod test_support;

/// The wallet data a backend owns. Logical store names remain the constants in
/// `bwk-persist`; a backend must keep different identities separate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    #[default]
    Wallet,
    SilentPayment,
    SubAccount(usize),
    Headers,
}

impl BackendKind {
    pub(crate) fn is_wallet(&self) -> bool {
        matches!(self, Self::Wallet)
    }
}

/// Logical identity, not a directory or an authorization token. Sub-account
/// requests use their scanner's stable account name and descriptor index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BackendIdentity {
    pub account: String,
    pub network: Network,
    pub kind: BackendKind,
}

/// Opens caller-owned byte-row storage. Retained only at runtime; consumers must
/// supply it again after deserializing account metadata. Errors never select a
/// different backend. Implementations own layout, authorization and version checks.
pub trait BackendFactory: Debug + Send + Sync {
    fn open(&self, identity: &BackendIdentity)
        -> Result<Arc<dyn PersistenceBackend>, PersistError>;
}
