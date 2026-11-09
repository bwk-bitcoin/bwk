//! Shared validation for the Get Info response in both codec directions.

use crate::ErrorInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    MaxAliasTooLarge(u8),
    FingerprintWhenNotReady,
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::MaxAliasTooLarge(_) => {
                error_info!(700, "maximum alias length exceeds the alias bound")
            }
            Self::FingerprintWhenNotReady => {
                error_info!(701, "fingerprint is present while the signer is not ready")
            }
        }
    }
}

error_display!(Error);
