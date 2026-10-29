//! Shared validation for cached MuSig preparation in both codec directions.

use alloc::collections::BTreeSet;

use crate::{
    request::MusigDerivation, response::MusigNonce, ErrorInfo, MAX_MUSIG_DERIVATIONS,
    MAX_MUSIG_INPUTS, MAX_VEC,
};

pub(crate) const HARDENED_INDEX: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InputCoverage,
    DerivationCount,
    DuplicateDerivation,
    HardenedIndex,
    MissingDescriptor,
    NonceCount,
    NonceInputIndex,
    DuplicateNonce,
    MissingInput,
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::InputCoverage => error_info!(500, "MuSig input coverage must be 1 through 8"),
            Self::DerivationCount => {
                error_info!(501, "MuSig derivation count must be 1 through 32")
            }
            Self::DuplicateDerivation => error_info!(502, "duplicate MuSig derivation"),
            Self::HardenedIndex => error_info!(503, "hardened MuSig derivation index"),
            Self::MissingDescriptor => {
                error_info!(504, "MuSig preparation requires a full descriptor")
            }
            Self::NonceCount => {
                error_info!(505, "MuSig nonce count must be 1 through MAX_VEC")
            }
            Self::NonceInputIndex => error_info!(506, "MuSig nonce input exceeds coverage"),
            Self::DuplicateNonce => error_info!(507, "duplicate MuSig nonce attribution"),
            Self::MissingInput => error_info!(508, "MuSig nonces do not cover every input"),
        }
    }
}

error_display!(Error);

pub(crate) fn validate_input_coverage(max_inputs: u8) -> Result<(), Error> {
    if !(1..=MAX_MUSIG_INPUTS).contains(&max_inputs) {
        return Err(Error::InputCoverage);
    }
    Ok(())
}

pub(crate) fn validate_derivations(derivations: &[MusigDerivation]) -> Result<(), Error> {
    if derivations.is_empty() || derivations.len() > MAX_MUSIG_DERIVATIONS {
        return Err(Error::DerivationCount);
    }
    let mut seen = BTreeSet::new();
    for derivation in derivations {
        derivation.validate()?;
        if !seen.insert(*derivation) {
            return Err(Error::DuplicateDerivation);
        }
    }
    Ok(())
}

pub(crate) fn validate_nonces(nonces: &[MusigNonce], max_inputs: u8) -> Result<(), Error> {
    if nonces.is_empty() || nonces.len() > MAX_VEC {
        return Err(Error::NonceCount);
    }
    let mut seen = BTreeSet::new();
    let mut covered = [false; MAX_MUSIG_INPUTS as usize];
    for nonce in nonces {
        nonce.derivation.validate()?;
        if nonce.input_index >= u32::from(max_inputs) {
            return Err(Error::NonceInputIndex);
        }
        covered[nonce.input_index as usize] = true;
        if !seen.insert((
            nonce.derivation,
            nonce.input_index,
            nonce.expression_index,
            nonce.participant.0,
            nonce.aggregate.0,
            nonce.leaf_hash,
        )) {
            return Err(Error::DuplicateNonce);
        }
    }
    if covered[..max_inputs as usize].contains(&false) {
        return Err(Error::MissingInput);
    }
    Ok(())
}
