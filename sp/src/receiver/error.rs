//! Source: adapted from cygnet3/spdk. See `sp/NOTICE`.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // Client creation
    #[error("failed to generate master key from seed")]
    SeedDerivation,
    #[error("failed to derive {0} key")]
    KeyDerivation(&'static str),
    #[error("secret spend key not available")]
    MissingSecretKey,

    // Validation
    #[error("invalid scan range: start ({0}) > end ({1})")]
    InvalidRange(u32, u32),
    #[error("missing block hash for scanned block {0}")]
    MissingBlockHash(u32),
    #[error("reorg deeper than {0} blocks")]
    ReorgTooDeep(u32),
    #[error("unknown recipient address type")]
    UnknownAddressType,
    #[error(
        "silent payment address network ({address:?}) does not match account network ({account:?})"
    )]
    SpNetworkMismatch {
        address: crate::core::utils::common::Network,
        account: crate::core::utils::common::Network,
    },

    // Wrapped external errors
    #[error(transparent)]
    SilentPayments(#[from] crate::core::error::Error),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[error(transparent)]
    Bip32(#[from] bitcoin::bip32::Error),
    #[error(transparent)]
    BlockFilter(#[from] bitcoin::bip158::Error),
    #[error(transparent)]
    InvalidHeight(#[from] bitcoin::absolute::ConversionError),
    #[error(transparent)]
    Address(#[from] bitcoin::address::ParseError),

    // Backend pass-through for downstream crates
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}
