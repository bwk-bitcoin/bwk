//! Shared validation for the silent payment keys form and the silent payment entries
//! of a Signing response in both codec directions.

use alloc::collections::BTreeSet;

use crate::{
    response::{SignatureEntry, SpScope},
    types::PUBLIC_KEY_LEN,
    ErrorInfo,
};

/// The `INPUT_INDEX` a global entry carries on the wire.
pub const GLOBAL_INPUT_INDEX: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    DuplicateShare,
    DuplicateProof,
    MissingProof,
    MissingShare,
}

impl Error {
    pub fn info(&self) -> ErrorInfo {
        match self {
            Self::DuplicateShare => {
                error_info!(600, "duplicate silent payment ECDH share for a scan key")
            }
            Self::DuplicateProof => {
                error_info!(601, "duplicate silent payment DLEQ proof for a scan key")
            }
            Self::MissingProof => {
                error_info!(602, "silent payment ECDH share without its DLEQ proof")
            }
            Self::MissingShare => {
                error_info!(603, "silent payment DLEQ proof without its ECDH share")
            }
        }
    }
}

error_display!(Error);

/// Each scope and scan key carries exactly one share and one proof, as BIP-375 pairs
/// every ECDH share with the DLEQ proof that lets the wallet verify it. Whether every
/// scan key and eligible input is covered depends on the PSBT, so the wallet checks it.
pub(crate) fn validate_entries(entries: &[SignatureEntry]) -> Result<(), Error> {
    let mut shares = BTreeSet::<(SpScope, [u8; PUBLIC_KEY_LEN])>::new();
    let mut proofs = BTreeSet::new();
    for entry in entries {
        match entry {
            SignatureEntry::SpEcdhShare {
                scope, scan_key, ..
            } => {
                if !shares.insert((*scope, scan_key.0)) {
                    return Err(Error::DuplicateShare);
                }
            }
            SignatureEntry::SpDleqProof {
                scope, scan_key, ..
            } => {
                if !proofs.insert((*scope, scan_key.0)) {
                    return Err(Error::DuplicateProof);
                }
            }
            _ => {}
        }
    }
    if shares.difference(&proofs).next().is_some() {
        return Err(Error::MissingProof);
    }
    if proofs.difference(&shares).next().is_some() {
        return Err(Error::MissingShare);
    }
    Ok(())
}
