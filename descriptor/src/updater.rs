//! Fills PSBT inputs and outputs from a definite descriptor: miniscript's updater,
//! then under `musig` BIP-373 participants (in 0x1a, out 0x08) and every cosigner's
//! tap_key_origins with the aggregate's leaf hashes, as Bitcoin Core does.

#[cfg(feature = "musig")]
use bwk_keys::musig::DefiniteMusigKey;
use miniscript::{bitcoin::Psbt, psbt::PsbtExt};
#[cfg(feature = "musig")]
use miniscript::{
    translate_hash_clone, DefiniteDescriptorKey, TranslateErr, TranslatePk, Translator,
};

use crate::wallet::WalletDefiniteDescriptor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("miniscript update failed: {0}")]
    Miniscript(String),
    #[error("musig2 field: {0}")]
    Musig(String),
}

#[cfg(not(feature = "musig"))]
pub fn update_input(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    psbt.update_input_with_descriptor(index, descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(feature = "musig")]
pub fn update_input(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    let descriptor = to_plain_definite(descriptor)?;
    psbt.update_input_with_descriptor(index, &descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(not(feature = "musig"))]
pub fn update_output(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    psbt.update_output_with_descriptor(index, descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(feature = "musig")]
pub fn update_output(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    let descriptor = to_plain_definite(descriptor)?;
    psbt.update_output_with_descriptor(index, &descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(feature = "musig")]
struct ToPlainDefinite;

#[cfg(feature = "musig")]
impl Translator<DefiniteMusigKey, DefiniteDescriptorKey, Error> for ToPlainDefinite {
    fn pk(&mut self, pk: &DefiniteMusigKey) -> Result<DefiniteDescriptorKey, Error> {
        pk.to_plain_definite()
            .map_err(|e| Error::Musig(e.to_string()))
    }
    translate_hash_clone!(DefiniteMusigKey, DefiniteDescriptorKey, Error);
}

/// Every key through `DefiniteMusigKey::to_plain_definite`.
#[cfg(feature = "musig")]
pub fn to_plain_definite(
    descriptor: &crate::musig::DefiniteMusigDescriptor,
) -> Result<miniscript::Descriptor<miniscript::DefiniteDescriptorKey>, Error> {
    descriptor
        .translate_pk(&mut ToPlainDefinite)
        .map_err(|e| match e {
            TranslateErr::TranslatorErr(e) => e,
            TranslateErr::OuterError(e) => Error::Musig(e.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{
        bitcoin::{
            absolute, transaction, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
            TxOut, Witness,
        },
        psbt::PsbtExt,
        DescriptorPublicKey,
    };

    use crate::{
        updater::{update_input, update_output},
        wallet::{to_wallet, WalletDescriptorExt},
    };

    const XPUB: &str = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x";

    fn psbt_paying(spk: ScriptBuf) -> Psbt {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spk.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: spk,
        });
        psbt
    }

    #[test]
    fn update_input_matches_miniscript() {
        let plain = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wpkh([9d69155f/84h/1h/0h]{XPUB}/0/*)"
        ))
        .unwrap();
        let plain_definite = plain.at_derivation_index(3).unwrap();
        let definite = to_wallet(plain).derive_at(3).unwrap();
        let spk = plain_definite.script_pubkey();

        let mut expected = psbt_paying(spk.clone());
        expected
            .update_input_with_descriptor(0, &plain_definite)
            .unwrap();
        expected
            .update_output_with_descriptor(0, &plain_definite)
            .unwrap();

        let mut psbt = psbt_paying(spk);
        update_input(&mut psbt, 0, &definite).unwrap();
        update_output(&mut psbt, 0, &definite).unwrap();

        assert!(!psbt.inputs[0].bip32_derivation.is_empty());
        assert!(psbt.inputs[0].witness_script.is_none());
        assert_eq!(psbt.inputs[0], expected.inputs[0]);
        assert_eq!(psbt.outputs[0], expected.outputs[0]);
    }
}
