//! The error type shared by the protocol code and every backend.

/// Errors from the MuSig2 protocol and its backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "rust-bitcoin", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "rust-bitcoin", error("invalid public key"))]
    InvalidPoint,
    #[cfg_attr(feature = "rust-bitcoin", error("no key to aggregate"))]
    NoKeys,
    #[cfg_attr(feature = "rust-bitcoin", error("invalid tweak"))]
    InvalidTweak,
    #[cfg_attr(feature = "rust-bitcoin", error("invalid secret key"))]
    InvalidSecretKey,
    #[cfg_attr(feature = "rust-bitcoin", error("invalid public nonce"))]
    InvalidPubNonce,
    #[cfg_attr(feature = "rust-bitcoin", error("no nonce to aggregate"))]
    NoNonces,
    #[cfg_attr(
        feature = "rust-bitcoin",
        error("secret nonce does not belong to this key")
    )]
    NonceKeyMismatch,
    #[cfg_attr(feature = "rust-bitcoin", error("invalid partial signature"))]
    InvalidPartialSig,
    #[cfg_attr(
        feature = "rust-bitcoin",
        error("partial signature count does not match")
    )]
    PartialSigCount,
}
