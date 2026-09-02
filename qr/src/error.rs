#[cfg(feature = "protocol")]
use crate::protocol::{decode, encode};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("QR payload is too long")]
    TooLong,
    #[error("invalid QR frame")]
    BadFrame,
    #[error("QR version {0} is out of range")]
    QrVersion(u8),
    #[error("BBQR part size is zero")]
    ZeroPartSize,
    #[error("image limit is zero")]
    ZeroImageLimit,
    #[error("BBQR part of {bytes} bytes does not fit QR version {version}")]
    PartTooLarge { bytes: usize, version: u8 },
    #[error("BBQR part is not alphanumeric")]
    PartNotAlphanumeric,
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Bbqr(#[from] bbqr::Error),
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Encode(#[from] encode::Error),
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Decode(#[from] decode::Error),
}
