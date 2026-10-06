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
    #[error("scan range {0}..={1} is wider than {2} blocks; the backend tip is not plausible")]
    RangeTooLarge(u32, u32, u32),
    #[error("missing block hash for scanned block {0}")]
    MissingBlockHash(u32),
    #[error("unknown recipient address type")]
    UnknownAddressType,

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

    // Backend pass-through for downstream crates
    #[error(transparent)]
    Backend(Box<dyn std::error::Error + Send + Sync>),
}
