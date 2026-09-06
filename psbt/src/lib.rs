//! Native BIP370 PSBTv2 support.

use std::collections::BTreeMap;

use bitcoin::{
    absolute, bip32,
    psbt::{
        self,
        raw::{Key, ProprietaryKey},
    },
    transaction, Amount, OutPoint, ScriptBuf, Sequence,
};

const TX_MODIFIABLE_MASK: u8 = 0b0000_0111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxModifiable(u8);

impl TxModifiable {
    pub const INPUTS: u8 = 1;
    pub const OUTPUTS: u8 = 1 << 1;
    pub const SIGHASH_SINGLE: u8 = 1 << 2;

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn inputs_modifiable(self) -> bool {
        self.0 & Self::INPUTS != 0
    }

    pub fn outputs_modifiable(self) -> bool {
        self.0 & Self::OUTPUTS != 0
    }

    pub fn has_sighash_single(self) -> bool {
        self.0 & Self::SIGHASH_SINGLE != 0
    }

    pub fn none() -> Self {
        Self(0)
    }
}

impl TryFrom<u8> for TxModifiable {
    type Error = Error;

    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        if bits & !TX_MODIFIABLE_MASK != 0 {
            return Err(Error::InvalidModifiableFlags);
        }
        Ok(Self(bits))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub previous_output: OutPoint,
    pub sequence: Sequence,
    pub required_time_lock_time: Option<absolute::LockTime>,
    pub required_height_lock_time: Option<absolute::LockTime>,
    pub psbt: psbt::Input,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub amount: Amount,
    // Absent until a signer derives it, which is the reason this crate exists:
    // a silent-payment output has no script at PSBT-construction time.
    pub script_pubkey: Option<ScriptBuf>,
    pub psbt: psbt::Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtV2 {
    pub tx_version: transaction::Version,
    pub fallback_lock_time: Option<absolute::LockTime>,
    pub tx_modifiable: Option<TxModifiable>,
    pub xpub: BTreeMap<bip32::Xpub, bip32::KeySource>,
    pub proprietary: BTreeMap<ProprietaryKey, Vec<u8>>,
    // Keytypes BIP375/BIP376 define but rust-bitcoin does not model, kept
    // under their real keytype numbers so the wire bytes stay spec-correct.
    pub unknown: BTreeMap<Key, Vec<u8>>,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid PSBT magic")]
    InvalidMagic,
    #[error("invalid compact size")]
    InvalidCompactSize,
    #[error("truncated PSBT")]
    Truncated,
    #[error("duplicate PSBT key")]
    DuplicateKey,
    #[error("missing required PSBTv2 field")]
    MissingField,
    #[error("invalid PSBTv2 field")]
    InvalidField,
    #[error("PSBT version is not 2")]
    InvalidVersion,
    #[error("PSBTv2 contains an unsigned transaction")]
    UnsignedTransaction,
    #[error("invalid transaction modifiable flags")]
    InvalidModifiableFlags,
    #[error("input and output counts do not match PSBT maps")]
    CountMismatch,
    #[error("output script is missing")]
    MissingOutputScript,
    #[error("input locktime requirements are incompatible")]
    IncompatibleLockTimes,
    #[error("bitcoin PSBT conversion failed")]
    BitcoinPsbt,
    #[error("PSBTv0 conversion requires version 0")]
    NotPsbtV0,
    #[error("PSBTv2 reserved field is present in an unknown map")]
    ReservedField,
}

#[cfg(test)]
mod tests {
    use crate::{Error, TxModifiable};

    #[test]
    fn rejects_unknown_modifiable_bits() {
        assert_eq!(
            TxModifiable::try_from(0b1000),
            Err(Error::InvalidModifiableFlags)
        );

        assert_eq!(TxModifiable::none().bits(), 0);

        let modifiable =
            TxModifiable::try_from(TxModifiable::INPUTS | TxModifiable::OUTPUTS).unwrap();
        assert!(modifiable.inputs_modifiable());
        assert!(modifiable.outputs_modifiable());
        assert!(!modifiable.has_sighash_single());
    }
}
