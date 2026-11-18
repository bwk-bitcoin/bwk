#[cfg(feature = "protocol")]
use bipqr::ll::{decode, encode};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("QR payload is too long")]
    TooLong,
    #[error("invalid QR frame")]
    BadFrame,
    #[error("BBQR part is not alphanumeric")]
    PartNotAlphanumeric,
    #[cfg(feature = "bbqr")]
    #[error(transparent)]
    Bbqr(#[from] bwk_bbqr::Error),
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Encode(#[from] encode::Error),
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Decode(#[from] decode::Error),
}
