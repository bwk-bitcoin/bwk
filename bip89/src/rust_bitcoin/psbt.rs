//! The spec's PSBT fields on a rust-bitcoin PSBT. Fields are scoped to one
//! input or output map, so the binding between bundle, proof and script is
//! structural. The unsigned transaction is the truth: a map without
//! a transaction entry is ignored, and a transaction entry without a map
//! carries nothing. Nothing here writes derivation or taproot origin fields.

use std::collections::BTreeMap;

use crate::{
    accumulator::tree::Proof,
    backend::Output,
    bundle::{Bundle, Entry},
    Error,
};
use miniscript::bitcoin::{
    hashes::Hash,
    psbt::{raw::ProprietaryKey, Psbt},
    secp256k1::schnorr,
    sighash::{Prevouts, SighashCache},
    taproot, TapLeafHash, TapSighashType, XOnlyPublicKey,
};

/// Proprietary field identifier for BIP89 fields.
pub const PREFIX: &[u8] = b"BIPXXX";
/// Bundle entry: keydata is the 33-byte base key, value is the 32-byte tweak.
pub const SUBTYPE_TWEAK: u8 = 0x00;
/// Accumulator proof, outputs only: empty keydata, 289-byte value.
pub const SUBTYPE_PROOF: u8 = 0x01;

type Proprietary = BTreeMap<ProprietaryKey, Vec<u8>>;

/// The entry at `index`, bounded by the transaction count; a missing entry is `Psbt`.
pub(crate) fn entry<T>(entries: &[T], tx_len: usize, index: usize) -> Result<&T, Error> {
    if index >= tx_len {
        return Err(Error::Psbt);
    }
    entries.get(index).ok_or(Error::Psbt)
}

/// Same as `entry`, mutable.
pub(crate) fn entry_mut<T>(
    entries: &mut [T],
    tx_len: usize,
    index: usize,
) -> Result<&mut T, Error> {
    if index >= tx_len {
        return Err(Error::Psbt);
    }
    entries.get_mut(index).ok_or(Error::Psbt)
}

/// The `(keydata, value)` pairs of the BIP89 fields of `subtype`, in map order.
fn fields(map: &Proprietary, subtype: u8) -> Vec<(&[u8], &[u8])> {
    map.iter()
        .filter(|(key, _)| key.prefix == PREFIX && key.subtype == subtype)
        .map(|(key, value)| (key.key.as_slice(), value.as_slice()))
        .collect()
}

fn insert(map: &mut Proprietary, subtype: u8, key: Vec<u8>, value: Vec<u8>) {
    map.insert(
        ProprietaryKey {
            prefix: PREFIX.to_vec(),
            subtype,
            key,
        },
        value,
    );
}

/// Decodes a bundle from its subtype 0x00 fields. No entries is `Ok(None)`; a
/// keydata other than 33 bytes or a value other than 32 bytes is
/// `EntryLength`.
pub(crate) fn read_bundle(map: &Proprietary) -> Result<Option<Bundle>, Error> {
    let fields = fields(map, SUBTYPE_TWEAK);
    if fields.is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        let (Ok(key), Ok(tweak)) = (key.try_into(), value.try_into()) else {
            return Err(Error::EntryLength);
        };
        entries.push(Entry { key, tweak });
    }
    Bundle::new(entries).map(Some)
}

/// Writes `bundle` as one subtype 0x00 field per entry.
pub(crate) fn write_bundle(map: &mut Proprietary, bundle: &Bundle) {
    for entry in bundle.entries() {
        insert(map, SUBTYPE_TWEAK, entry.key.to_vec(), entry.tweak.to_vec());
    }
}

/// Decodes the accumulator proof. No entry is `Ok(None)`; more than one
/// entry, or a non-empty keydata, is `ProofLength`.
pub(crate) fn read_proof(map: &Proprietary) -> Result<Option<Proof>, Error> {
    match fields(map, SUBTYPE_PROOF).as_slice() {
        [] => Ok(None),
        [([], value)] => Proof::from_bytes(value).map(Some),
        _ => Err(Error::ProofLength),
    }
}

/// Writes `proof` as the single subtype 0x01 field.
pub(crate) fn write_proof(map: &mut Proprietary, proof: &Proof) {
    insert(map, SUBTYPE_PROOF, Vec::new(), proof.to_bytes().to_vec());
}

/// The witness UTXO of `input`.
pub(crate) fn spent_output(psbt: &Psbt, input: usize) -> Result<Output, Error> {
    let inp = entry(&psbt.inputs, psbt.unsigned_tx.input.len(), input)?;
    let utxo = inp.witness_utxo.as_ref().ok_or(Error::MissingUtxo(input))?;
    Ok(Output {
        script_pubkey: utxo.script_pubkey.to_bytes(),
        value: utxo.value.to_sat(),
    })
}

pub(crate) fn tap_leaf_sighash(
    psbt: &Psbt,
    input: usize,
    leaf_hash: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let count = psbt.unsigned_tx.input.len();
    if input >= count {
        return Err(Error::Psbt);
    }
    let mut prevouts = Vec::with_capacity(count);
    for i in 0..count {
        let utxo = entry(&psbt.inputs, count, i)?
            .witness_utxo
            .clone()
            .ok_or(Error::MissingUtxo(i))?;
        prevouts.push(utxo);
    }
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input,
            &Prevouts::All(&prevouts),
            TapLeafHash::from_byte_array(*leaf_hash),
            TapSighashType::Default,
        )
        .map_err(|_| Error::Psbt)?;
    Ok(sighash.to_byte_array())
}

pub(crate) fn add_tap_script_sig(
    psbt: &mut Psbt,
    input: usize,
    xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let count = psbt.unsigned_tx.input.len();
    let inp = entry_mut(&mut psbt.inputs, count, input)?;
    let xonly = XOnlyPublicKey::from_slice(xonly).map_err(|_| Error::InvalidPoint)?;
    let signature = schnorr::Signature::from_slice(sig).map_err(|_| Error::Psbt)?;
    inp.tap_script_sigs.insert(
        (xonly, TapLeafHash::from_byte_array(*leaf_hash)),
        taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );
    Ok(())
}
