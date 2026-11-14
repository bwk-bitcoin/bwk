//! Shared validation for the signature entries of a Signing response in both codec
//! directions.

use crate::ErrorInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TaprootLength(usize),
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::TaprootLength(_) => {
                error_info!(800, "taproot signature is not 64 or 65 bytes")
            }
        }
    }
}

error_display!(Error);
