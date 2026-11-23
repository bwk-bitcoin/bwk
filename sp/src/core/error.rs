//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported version {0}, only version 0 is supported")]
    UnsupportedVersion(u32),
    #[error("no input provided")]
    NoInputProvided,
    #[error("no outpoints provided")]
    NoOutpointsProvided,
    #[error("invalid txid hex representation: {0}")]
    InvalidTxidHex(#[source] hex::FromHexError),
    #[error("txid must be 32 bytes, got {0}")]
    TxidLength(usize),
    #[error("unexpected empty outpoints vector")]
    EmptyOutpoints,
    #[error("invalid transaction input: {0}")]
    InvalidInput(String),
    #[error(transparent)]
    InvalidLabel(#[from] hex::FromHexError),
    #[error("label must be 32 bytes (256 bits) long")]
    LabelLength,
    #[error(transparent)]
    Secp256k1Error(#[from] crate::core::secp256k1::Error),
    #[error(transparent)]
    OutOfRangeError(#[from] crate::core::secp256k1::scalar::OutOfRangeError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("malformed tweak: not a valid secp256k1 point")]
    MalformedTweak,
}

impl From<secp256k1_spscan_sys::MalformedPubkey> for Error {
    fn from(_: secp256k1_spscan_sys::MalformedPubkey) -> Self {
        Error::MalformedTweak
    }
}
