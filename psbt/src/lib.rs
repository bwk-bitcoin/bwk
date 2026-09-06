//! Native BIP370 PSBTv2 support.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{
    absolute, bip32, consensus,
    psbt::{
        self,
        raw::{Key, ProprietaryKey},
    },
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
};

const MAGIC: &[u8; 5] = b"psbt\xff";
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const PSBT_GLOBAL_VERSION: u8 = 0xfb;
const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
const PSBT_IN_SEQUENCE: u8 = 0x10;
const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
const PSBT_OUT_AMOUNT: u8 = 0x03;
const PSBT_OUT_SCRIPT: u8 = 0x04;
// BIP370 keytypes this crate reads and writes itself, outside rust-bitcoin's maps.
const GLOBAL_TYPES: [u8; 7] = [
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_GLOBAL_VERSION,
];
const INPUT_TYPES: [u8; 5] = [
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_SEQUENCE,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
];
const OUTPUT_TYPES: [u8; 2] = [PSBT_OUT_AMOUNT, PSBT_OUT_SCRIPT];
const TX_MODIFIABLE_MASK: u8 = 0b0000_0111;

#[derive(Clone)]
struct RawPair {
    key: Key,
    value: Vec<u8>,
}

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

impl Input {
    fn txin(&self) -> TxIn {
        TxIn {
            previous_output: self.previous_output,
            script_sig: ScriptBuf::new(),
            sequence: self.sequence,
            witness: bitcoin::Witness::new(),
        }
    }
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

impl PsbtV2 {
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut maps = maps_from_v0(&self.v0_bridge()?)?;
        let global = maps.first_mut().ok_or(Error::BitcoinPsbt)?;
        remove_types(global, &GLOBAL_TYPES);
        global.push(pair(
            PSBT_GLOBAL_TX_VERSION,
            self.tx_version.0.to_le_bytes().to_vec(),
        ));
        if let Some(lock_time) = self.fallback_lock_time {
            global.push(pair(
                PSBT_GLOBAL_FALLBACK_LOCKTIME,
                lock_time.to_consensus_u32().to_le_bytes().to_vec(),
            ));
        }
        global.push(pair(
            PSBT_GLOBAL_INPUT_COUNT,
            compact_size(self.inputs.len() as u64),
        ));
        global.push(pair(
            PSBT_GLOBAL_OUTPUT_COUNT,
            compact_size(self.outputs.len() as u64),
        ));
        if let Some(flags) = self.tx_modifiable {
            global.push(pair(PSBT_GLOBAL_TX_MODIFIABLE, vec![flags.bits()]));
        }
        global.push(pair(PSBT_GLOBAL_VERSION, 2u32.to_le_bytes().to_vec()));

        for (map, input) in maps[1..1 + self.inputs.len()].iter_mut().zip(&self.inputs) {
            map.push(pair(
                PSBT_IN_PREVIOUS_TXID,
                consensus::serialize(&input.previous_output.txid),
            ));
            map.push(pair(
                PSBT_IN_OUTPUT_INDEX,
                input.previous_output.vout.to_le_bytes().to_vec(),
            ));
            // BIP370: Sequence::MAX is the implicit default, omit it on the wire.
            if input.sequence != Sequence::MAX {
                map.push(pair(
                    PSBT_IN_SEQUENCE,
                    input.sequence.to_consensus_u32().to_le_bytes().to_vec(),
                ));
            }
            if let Some(lock_time) = input.required_time_lock_time {
                map.push(pair(
                    PSBT_IN_REQUIRED_TIME_LOCKTIME,
                    lock_time.to_consensus_u32().to_le_bytes().to_vec(),
                ));
            }
            if let Some(lock_time) = input.required_height_lock_time {
                map.push(pair(
                    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
                    lock_time.to_consensus_u32().to_le_bytes().to_vec(),
                ));
            }
        }

        for (map, output) in maps[1 + self.inputs.len()..].iter_mut().zip(&self.outputs) {
            map.push(pair(
                PSBT_OUT_AMOUNT,
                output.amount.to_sat().to_le_bytes().to_vec(),
            ));
            if let Some(script) = &output.script_pubkey {
                map.push(pair(PSBT_OUT_SCRIPT, script.as_bytes().to_vec()));
            }
        }

        serialize_maps(&maps)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut maps = parse_maps(bytes, spec_key_type)?;
        let mut global = maps.first().ok_or(Error::MissingField)?.clone();
        maps.remove(0);
        let version = take_unkeyed(&mut global, PSBT_GLOBAL_VERSION)?
            .ok_or(Error::MissingField)
            .and_then(u32_value)?;
        if version != 2 {
            return Err(Error::InvalidVersion);
        }
        if has_type(&global, PSBT_GLOBAL_UNSIGNED_TX) {
            return Err(Error::UnsignedTransaction);
        }
        let tx_version = transaction::Version(i32::from_le_bytes(fixed::<4>(
            take_unkeyed(&mut global, PSBT_GLOBAL_TX_VERSION)?.ok_or(Error::MissingField)?,
        )?));
        let fallback_lock_time = take_unkeyed(&mut global, PSBT_GLOBAL_FALLBACK_LOCKTIME)?
            .map(lock_time)
            .transpose()?;
        let input_count = compact_size_value(
            take_unkeyed(&mut global, PSBT_GLOBAL_INPUT_COUNT)?.ok_or(Error::MissingField)?,
        )?;
        let output_count = compact_size_value(
            take_unkeyed(&mut global, PSBT_GLOBAL_OUTPUT_COUNT)?.ok_or(Error::MissingField)?,
        )?;
        let tx_modifiable = take_unkeyed(&mut global, PSBT_GLOBAL_TX_MODIFIABLE)?
            .map(single_byte)
            .transpose()?
            .map(TxModifiable::try_from)
            .transpose()?;
        reject_types(&global, &GLOBAL_TYPES)?;
        let input_count = usize::try_from(input_count).map_err(|_| Error::InvalidField)?;
        let output_count = usize::try_from(output_count).map_err(|_| Error::InvalidField)?;
        let map_count = input_count
            .checked_add(output_count)
            .ok_or(Error::InvalidField)?;
        if maps.len() != map_count {
            return Err(Error::CountMismatch);
        }

        let mut inputs = Vec::with_capacity(input_count);
        let mut input_maps = Vec::with_capacity(input_count);
        for map in maps.drain(..input_count) {
            let (input, map) = parse_input(map)?;
            inputs.push(input);
            input_maps.push(map);
        }
        let mut outputs = Vec::with_capacity(output_count);
        let mut output_maps = Vec::with_capacity(output_count);
        for map in maps {
            let (output, map) = parse_output(map)?;
            outputs.push(output);
            output_maps.push(map);
        }

        let bridge = v0_from_maps(&global, &input_maps, &output_maps, &inputs, &outputs)?;
        let mut psbt = bitcoin::Psbt::deserialize(&bridge).map_err(|_| Error::BitcoinPsbt)?;
        if psbt.inputs.len() != inputs.len() || psbt.outputs.len() != outputs.len() {
            return Err(Error::CountMismatch);
        }
        restore_high_type_unknowns(&global, &mut psbt.unknown);
        for (map, input) in input_maps.iter().zip(&mut psbt.inputs) {
            restore_high_type_unknowns(map, &mut input.unknown);
        }
        for (map, output) in output_maps.iter().zip(&mut psbt.outputs) {
            restore_high_type_unknowns(map, &mut output.unknown);
        }
        for (input, psbt_input) in inputs.iter_mut().zip(psbt.inputs) {
            input.psbt = psbt_input;
        }
        for (output, psbt_output) in outputs.iter_mut().zip(psbt.outputs) {
            output.psbt = psbt_output;
        }

        Ok(Self {
            tx_version,
            fallback_lock_time,
            tx_modifiable,
            xpub: psbt.xpub,
            proprietary: psbt.proprietary,
            unknown: psbt.unknown,
            inputs,
            outputs,
        })
    }

    fn v0_bridge(&self) -> Result<bitcoin::Psbt, Error> {
        let unsigned_tx = bridge_tx(
            self.tx_version,
            self.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO),
            &self.inputs,
            &self.outputs,
        );
        Ok(bitcoin::Psbt {
            unsigned_tx,
            version: 0,
            xpub: self.xpub.clone(),
            proprietary: self.proprietary.clone(),
            unknown: self.unknown.clone(),
            inputs: self.inputs.iter().map(|input| input.psbt.clone()).collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| output.psbt.clone())
                .collect(),
        })
    }
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

fn parse_input(mut map: Vec<RawPair>) -> Result<(Input, Vec<RawPair>), Error> {
    let txid = consensus::deserialize::<Txid>(
        &take_unkeyed(&mut map, PSBT_IN_PREVIOUS_TXID)?.ok_or(Error::MissingField)?,
    )
    .map_err(|_| Error::InvalidField)?;
    let vout =
        u32_value(take_unkeyed(&mut map, PSBT_IN_OUTPUT_INDEX)?.ok_or(Error::MissingField)?)?;
    let sequence = take_unkeyed(&mut map, PSBT_IN_SEQUENCE)?
        .map(u32_value)
        .transpose()?
        .map(Sequence::from_consensus)
        .unwrap_or(Sequence::MAX);
    let required_time_lock_time = take_unkeyed(&mut map, PSBT_IN_REQUIRED_TIME_LOCKTIME)?
        .map(required_time_lock)
        .transpose()?;
    let required_height_lock_time = take_unkeyed(&mut map, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)?
        .map(required_height_lock)
        .transpose()?;
    reject_types(&map, &INPUT_TYPES)?;
    Ok((
        Input {
            previous_output: OutPoint { txid, vout },
            sequence,
            required_time_lock_time,
            required_height_lock_time,
            psbt: psbt::Input::default(),
        },
        map,
    ))
}

fn parse_output(mut map: Vec<RawPair>) -> Result<(Output, Vec<RawPair>), Error> {
    // An unsigned output amount above the money range must round-trip, since a
    // PSBT under construction is allowed to hold one.
    let amount = u64::from_le_bytes(fixed::<8>(
        take_unkeyed(&mut map, PSBT_OUT_AMOUNT)?.ok_or(Error::MissingField)?,
    )?);
    let amount = Amount::from_sat(amount);
    let script_pubkey = take_unkeyed(&mut map, PSBT_OUT_SCRIPT)?.map(ScriptBuf::from_bytes);
    reject_types(&map, &OUTPUT_TYPES)?;
    Ok((
        Output {
            amount,
            script_pubkey,
            psbt: psbt::Output::default(),
        },
        map,
    ))
}

fn v0_from_maps(
    global: &[RawPair],
    input_maps: &[Vec<RawPair>],
    output_maps: &[Vec<RawPair>],
    inputs: &[Input],
    outputs: &[Output],
) -> Result<Vec<u8>, Error> {
    // rust-bitcoin only needs the unsigned_tx to know the input and output
    // counts here, so its version and locktime are arbitrary placeholders.
    let unsigned_tx = bridge_tx(
        transaction::Version::TWO,
        absolute::LockTime::ZERO,
        inputs,
        outputs,
    );
    let mut global = global.to_vec();
    global.push(pair(
        PSBT_GLOBAL_UNSIGNED_TX,
        consensus::serialize(&unsigned_tx),
    ));
    let mut maps = vec![global];
    maps.extend_from_slice(input_maps);
    maps.extend_from_slice(output_maps);
    serialize_maps(&maps)
}

fn bridge_tx(
    version: transaction::Version,
    lock_time: absolute::LockTime,
    inputs: &[Input],
    outputs: &[Output],
) -> Transaction {
    Transaction {
        version,
        lock_time,
        input: inputs.iter().map(Input::txin).collect(),
        output: outputs
            .iter()
            .map(|output| TxOut {
                value: output.amount,
                script_pubkey: output.script_pubkey.clone().unwrap_or_default(),
            })
            .collect(),
    }
}

fn required_time_lock(value: Vec<u8>) -> Result<absolute::LockTime, Error> {
    let lock_time = lock_time(value)?;
    if lock_time.is_block_time() {
        Ok(lock_time)
    } else {
        Err(Error::InvalidField)
    }
}

fn required_height_lock(value: Vec<u8>) -> Result<absolute::LockTime, Error> {
    let lock_time = lock_time(value)?;
    if lock_time.is_block_height() && lock_time != absolute::LockTime::ZERO {
        Ok(lock_time)
    } else {
        Err(Error::InvalidField)
    }
}

fn lock_time(value: Vec<u8>) -> Result<absolute::LockTime, Error> {
    Ok(absolute::LockTime::from_consensus(u32_value(value)?))
}

fn take_unkeyed(map: &mut Vec<RawPair>, type_value: u8) -> Result<Option<Vec<u8>>, Error> {
    let index = map
        .iter()
        .position(|pair| pair.key.type_value == type_value && pair.key.key.is_empty());
    Ok(index.map(|index| map.remove(index).value))
}

fn has_type(map: &[RawPair], type_value: u8) -> bool {
    map.iter().any(|pair| pair.key.type_value == type_value)
}

fn remove_types(map: &mut Vec<RawPair>, type_values: &[u8]) {
    map.retain(|pair| !type_values.contains(&pair.key.type_value));
}

fn reject_types(map: &[RawPair], type_values: &[u8]) -> Result<(), Error> {
    if map
        .iter()
        .any(|pair| type_values.contains(&pair.key.type_value))
    {
        return Err(Error::InvalidField);
    }
    Ok(())
}

fn pair(type_value: u8, value: Vec<u8>) -> RawPair {
    RawPair {
        key: Key {
            type_value,
            key: Vec::new(),
        },
        value,
    }
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::InvalidField)
}

fn u32_value(value: Vec<u8>) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(fixed(value)?))
}

fn single_byte(value: Vec<u8>) -> Result<u8, Error> {
    fixed::<1>(value).map(|value| value[0])
}

fn compact_size(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut bytes = vec![0xfd];
            bytes.extend_from_slice(&(value as u16).to_le_bytes());
            bytes
        }
        0x1_0000..=0xffff_ffff => {
            let mut bytes = vec![0xfe];
            bytes.extend_from_slice(&(value as u32).to_le_bytes());
            bytes
        }
        _ => {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes
        }
    }
}

fn compact_size_value(value: Vec<u8>) -> Result<u64, Error> {
    let mut bytes = value.as_slice();
    let result = read_compact_size(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(Error::InvalidField);
    }
    Ok(result)
}

fn parse_maps(
    bytes: &[u8],
    read_key_type: fn(&mut &[u8]) -> Result<u8, Error>,
) -> Result<Vec<Vec<RawPair>>, Error> {
    let mut bytes = bytes;
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Error::InvalidMagic);
    }
    bytes = &bytes[MAGIC.len()..];
    let mut maps = Vec::new();
    while !bytes.is_empty() {
        maps.push(read_map(&mut bytes, read_key_type)?);
    }
    Ok(maps)
}

fn maps_from_v0(psbt: &bitcoin::Psbt) -> Result<Vec<Vec<RawPair>>, Error> {
    parse_maps(&psbt.serialize(), bitcoin_psbt_key_type).map_err(|_| Error::BitcoinPsbt)
}

fn serialize_maps(maps: &[Vec<RawPair>]) -> Result<Vec<u8>, Error> {
    let mut bytes = MAGIC.to_vec();
    for map in maps {
        let mut keys = BTreeSet::new();
        let mut map = map.clone();
        map.sort_by(|left, right| left.key.cmp(&right.key));
        for pair in map {
            if !keys.insert(pair.key.clone()) {
                return Err(Error::DuplicateKey);
            }
            write_pair(&mut bytes, &pair);
        }
        bytes.push(0);
    }
    Ok(bytes)
}

fn read_map(
    bytes: &mut &[u8],
    read_key_type: fn(&mut &[u8]) -> Result<u8, Error>,
) -> Result<Vec<RawPair>, Error> {
    let mut map = Vec::new();
    let mut keys = BTreeSet::new();
    loop {
        let key_length = read_compact_size(bytes)?;
        if key_length == 0 {
            return Ok(map);
        }
        let key_length = usize::try_from(key_length).map_err(|_| Error::InvalidField)?;
        let mut key_bytes = take(bytes, key_length)?;
        let type_value = read_key_type(&mut key_bytes)?;
        let key = Key {
            type_value,
            key: key_bytes.to_vec(),
        };
        if !keys.insert(key.clone()) {
            return Err(Error::DuplicateKey);
        }
        let value_length =
            usize::try_from(read_compact_size(bytes)?).map_err(|_| Error::InvalidField)?;
        map.push(RawPair {
            key,
            value: take(bytes, value_length)?.to_vec(),
        });
    }
}

// BIP174 key types are compact-size integers on the wire, but rust-bitcoin
// reads a key's type as a single raw byte. The two conventions agree below
// 0xfd and diverge above it, so this crate needs a key type reader for each
// source: `spec_key_type` for bytes written per spec, `bitcoin_psbt_key_type`
// for bytes rust-bitcoin itself produced.
fn spec_key_type(key_bytes: &mut &[u8]) -> Result<u8, Error> {
    u8::try_from(read_compact_size(key_bytes)?).map_err(|_| Error::InvalidField)
}

fn bitcoin_psbt_key_type(key_bytes: &mut &[u8]) -> Result<u8, Error> {
    let (&type_value, rest) = (*key_bytes).split_first().ok_or(Error::InvalidField)?;
    *key_bytes = rest;
    Ok(type_value)
}

fn restore_high_type_unknowns(map: &[RawPair], unknown: &mut BTreeMap<Key, Vec<u8>>) {
    for pair in map {
        if pair.key.type_value < 0xfd {
            continue;
        }
        let key_type = compact_size(pair.key.type_value as u64);
        let wrong = Key {
            type_value: key_type[0],
            key: [key_type[1..].to_vec(), pair.key.key.clone()].concat(),
        };
        unknown.remove(&wrong);
        unknown.insert(pair.key.clone(), pair.value.clone());
    }
}

fn write_pair(bytes: &mut Vec<u8>, pair: &RawPair) {
    let key_type = compact_size(pair.key.type_value as u64);
    bytes.extend_from_slice(&compact_size((key_type.len() + pair.key.key.len()) as u64));
    bytes.extend_from_slice(&key_type);
    bytes.extend_from_slice(&pair.key.key);
    bytes.extend_from_slice(&compact_size(pair.value.len() as u64));
    bytes.extend_from_slice(&pair.value);
}

// Decoding then re-encoding and comparing the leading byte is what rejects a
// non-canonical compact size (e.g. a value below 0xfd written with the 0xfd
// prefix): without it the same PSBT would have two valid byte encodings.
fn read_compact_size(bytes: &mut &[u8]) -> Result<u64, Error> {
    let first = *take(bytes, 1)?.first().ok_or(Error::Truncated)?;
    let value = match first {
        0..=0xfc => u64::from(first),
        0xfd => u64::from(u16::from_le_bytes(fixed(take(bytes, 2)?.to_vec())?)),
        0xfe => u64::from(u32::from_le_bytes(fixed(take(bytes, 4)?.to_vec())?)),
        0xff => u64::from_le_bytes(fixed(take(bytes, 8)?.to_vec())?),
    };
    if compact_size(value).first().copied() != Some(first) {
        return Err(Error::InvalidCompactSize);
    }
    Ok(value)
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    if bytes.len() < length {
        return Err(Error::Truncated);
    }
    let (head, tail) = bytes.split_at(length);
    *bytes = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{
        absolute,
        hashes::Hash,
        psbt::{self, raw::Key},
        transaction, Amount, OutPoint, ScriptBuf, Sequence, Txid,
    };

    use crate::{
        read_map, spec_key_type, Error, Input, Output, PsbtV2, TxModifiable,
        PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION,
    };

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

    fn psbt(script_pubkey: Option<ScriptBuf>) -> PsbtV2 {
        PsbtV2 {
            tx_version: transaction::Version::TWO,
            fallback_lock_time: Some(absolute::LockTime::ZERO),
            tx_modifiable: Some(TxModifiable::try_from(TxModifiable::INPUTS).unwrap()),
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
                },
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                required_time_lock_time: None,
                required_height_lock_time: None,
                psbt: psbt::Input::default(),
            }],
            outputs: vec![Output {
                amount: Amount::from_sat(42_000),
                script_pubkey,
                psbt: psbt::Output::default(),
            }],
        }
    }

    fn psbt_with_script() -> PsbtV2 {
        psbt(Some(ScriptBuf::from_bytes(vec![0x51])))
    }

    fn unkeyed(type_value: u8) -> Key {
        Key {
            type_value,
            key: Vec::new(),
        }
    }

    fn compact_size_key_type_psbt() -> Vec<u8> {
        let mut bytes = vec![
            0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x02, 0x04, 0x02, 0x00, 0x00, 0x00, 0x01, 0x03,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01, 0x01,
            0x06, 0x01, 0x01, 0x01, 0xfb, 0x04, 0x02, 0x00, 0x00, 0x00, 0x03, 0xfd, 0xfd, 0x00,
            0x01, 0x2a, 0x00, 0x01, 0x0e, 0x20,
        ];
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&[
            0x01, 0x0f, 0x04, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x04, 0xfd, 0xff, 0xff, 0xff,
            0x00, 0x01, 0x03, 0x08, 0x10, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04,
            0x01, 0x51, 0x00,
        ]);
        bytes
    }

    #[test]
    fn serializes_and_deserializes_v2() {
        let psbt = psbt_with_script();
        let bytes = psbt.serialize().unwrap();
        let parsed = PsbtV2::deserialize(&bytes).unwrap();
        assert_eq!(parsed, psbt);
    }

    #[test]
    fn preserves_metadata_maps() {
        let mut psbt = psbt_with_script();
        psbt.unknown.insert(unkeyed(0xfd), vec![1, 2, 3]);
        psbt.inputs[0]
            .psbt
            .unknown
            .insert(unkeyed(0xfe), vec![4, 5, 6]);
        psbt.outputs[0]
            .psbt
            .unknown
            .insert(unkeyed(0xff), vec![7, 8, 9]);

        let bytes = psbt.serialize().unwrap();
        let parsed = PsbtV2::deserialize(&bytes).unwrap();
        assert_eq!(parsed, psbt);
    }

    #[test]
    fn parses_compact_size_key_type() {
        let parsed = PsbtV2::deserialize(&compact_size_key_type_psbt()).unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(unkeyed(0xfd), vec![0x2a]);
        assert_eq!(parsed.unknown, expected);
    }

    #[test]
    fn serializes_compact_size_key_type() {
        let mut psbt = psbt_with_script();
        psbt.unknown.insert(unkeyed(0xfd), vec![0x2a]);
        assert_eq!(psbt.serialize().unwrap(), compact_size_key_type_psbt());
    }

    #[test]
    fn accepts_unsigned_output_amounts() {
        for amount in [i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let mut psbt = psbt_with_script();
            psbt.outputs[0].amount = Amount::from_sat(amount);
            let bytes = psbt.serialize().unwrap();
            let parsed = PsbtV2::deserialize(&bytes).unwrap();
            assert_eq!(parsed.outputs[0].amount, Amount::from_sat(amount));
        }
    }

    #[test]
    fn rejects_v0_unsigned_transaction() {
        let mut bytes = psbt_with_script().serialize().unwrap();
        let marker = [1, PSBT_GLOBAL_VERSION, 4, 2, 0, 0, 0];
        let index = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        bytes.splice(index..index, [1, PSBT_GLOBAL_UNSIGNED_TX, 1, 0]);
        assert_eq!(PsbtV2::deserialize(&bytes), Err(Error::UnsignedTransaction));
    }

    #[test]
    fn rejects_noncanonical_key_length() {
        assert!(matches!(
            read_map(&mut &[0xfd, 1, 0, 0][..], spec_key_type),
            Err(Error::InvalidCompactSize)
        ));
    }
}
