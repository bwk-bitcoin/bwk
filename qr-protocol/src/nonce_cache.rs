//! Shared validation for nonce preparation in both codec directions.

use crate::{ErrorInfo, MAX_NONCE_EXPRESSIONS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InputCoverage,
    ExpressionRange,
    NonceCount,
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::InputCoverage => {
                error_info!(900, "nonce cache input coverage must be at least 1")
            }
            Self::ExpressionRange => error_info!(
                901,
                "key expression range must be ordered and span at most MAX_NONCE_EXPRESSIONS"
            ),
            Self::NonceCount => error_info!(
                902,
                "nonce count must be the key expression span times the input coverage"
            ),
        }
    }
}

error_display!(Error);

pub(crate) fn validate_coverage(max_inputs: u8, start: u32, end: u32) -> Result<(), Error> {
    if max_inputs == 0 {
        return Err(Error::InputCoverage);
    }
    if start > end || end - start >= MAX_NONCE_EXPRESSIONS as u32 {
        return Err(Error::ExpressionRange);
    }
    Ok(())
}

pub(crate) fn validate_nonce_count(
    count: usize,
    max_inputs: u8,
    start: u32,
    end: u32,
) -> Result<(), Error> {
    validate_coverage(max_inputs, start, end)?;
    let span = (end - start) as usize + 1;
    if count != span * usize::from(max_inputs) {
        return Err(Error::NonceCount);
    }
    Ok(())
}
