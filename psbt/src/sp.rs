//! BIP375 and BIP376 silent-payment PSBT fields.

use std::collections::BTreeMap;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource},
    psbt::{raw, Input, Output},
    secp256k1::PublicKey,
    Psbt,
};

use crate::PsbtV2;

pub const PSBT_GLOBAL_SP_ECDH_SHARE: u8 = 0x07;
pub const PSBT_GLOBAL_SP_DLEQ: u8 = 0x08;
pub const PSBT_OUT_SP_V0_INFO: u8 = 0x09;
pub const PSBT_OUT_SP_V0_LABEL: u8 = 0x0a;
pub const PSBT_IN_SP_ECDH_SHARE: u8 = 0x1d;
pub const PSBT_IN_SP_DLEQ: u8 = 0x1e;
pub const PSBT_IN_SP_SPEND_BIP32_DERIVATION: u8 = 0x1f;
pub const PSBT_IN_SP_TWEAK: u8 = 0x20;
const ECDH_SHARE_LEN: usize = 33;
const SP_V0_INFO_LEN: usize = 66;
const DLEQ_PROOF_LEN: usize = 64;
const TWEAK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid silent payment field value")]
    InvalidValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpV0Output {
    pub scan_key: PublicKey,
    pub spend_key: PublicKey,
    pub label: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpShare {
    pub scan_key: PublicKey,
    pub share: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpProof {
    pub scan_key: PublicKey,
    pub proof: [u8; DLEQ_PROOF_LEN],
}

fn key(type_value: u8, key: Vec<u8>) -> raw::Key {
    raw::Key { type_value, key }
}

fn scan_key(type_value: u8, scan_key: PublicKey) -> raw::Key {
    key(type_value, scan_key.serialize().to_vec())
}

fn get_scan_key(key: &[u8]) -> Result<PublicKey, Error> {
    get_public_key(key)
}

fn get_public_key(value: &[u8]) -> Result<PublicKey, Error> {
    if value.len() != ECDH_SHARE_LEN {
        return Err(Error::InvalidValue);
    }
    PublicKey::from_slice(value).map_err(|_| Error::InvalidValue)
}

fn get_fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::InvalidValue)
}

fn get_key_source(value: &[u8]) -> Result<KeySource, Error> {
    if value.len() < 4 || value.len() % 4 != 0 {
        return Err(Error::InvalidValue);
    }

    let fingerprint = Fingerprint::from(get_fixed::<4>(&value[..4])?);
    let path = value[4..]
        .chunks_exact(4)
        .map(|chunk| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            ChildNumber::from(u32::from_le_bytes(bytes))
        })
        .collect::<Vec<_>>();
    Ok((fingerprint, DerivationPath::from(path)))
}

fn set_key_source(value: &mut Vec<u8>, key_source: &KeySource) {
    value.extend_from_slice(key_source.0.as_bytes());
    for child in &key_source.1 {
        value.extend_from_slice(&u32::from(*child).to_le_bytes());
    }
}

fn set_ecdh_share(
    unknown: &mut BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    scan: PublicKey,
    share: PublicKey,
) {
    unknown.insert(scan_key(type_value, scan), share.serialize().to_vec());
}

fn get_ecdh_share(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    scan: PublicKey,
) -> Result<Option<PublicKey>, Error> {
    unknown
        .get(&scan_key(type_value, scan))
        .map(|value| get_public_key(value))
        .transpose()
}

fn get_ecdh_shares(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
) -> Result<Vec<SpShare>, Error> {
    unknown
        .iter()
        .filter(|(key, _)| key.type_value == type_value)
        .map(|(key, value)| {
            Ok(SpShare {
                scan_key: get_scan_key(&key.key)?,
                share: get_public_key(value)?,
            })
        })
        .collect()
}

fn set_dleq(
    unknown: &mut BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    scan: PublicKey,
    proof: [u8; DLEQ_PROOF_LEN],
) {
    unknown.insert(scan_key(type_value, scan), proof.to_vec());
}

fn get_dleq(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    scan: PublicKey,
) -> Result<Option<[u8; DLEQ_PROOF_LEN]>, Error> {
    unknown
        .get(&scan_key(type_value, scan))
        .map(|value| get_fixed(value))
        .transpose()
}

fn get_dleqs(unknown: &BTreeMap<raw::Key, Vec<u8>>, type_value: u8) -> Result<Vec<SpProof>, Error> {
    unknown
        .iter()
        .filter(|(key, _)| key.type_value == type_value)
        .map(|(key, value)| {
            Ok(SpProof {
                scan_key: get_scan_key(&key.key)?,
                proof: get_fixed(value)?,
            })
        })
        .collect()
}

pub fn set_sp_global_ecdh_share(psbt: &mut Psbt, scan: PublicKey, share: PublicKey) {
    set_ecdh_share(&mut psbt.unknown, PSBT_GLOBAL_SP_ECDH_SHARE, scan, share);
}

pub fn set_sp_global_ecdh_share_v2(psbt: &mut PsbtV2, scan: PublicKey, share: PublicKey) {
    set_ecdh_share(&mut psbt.unknown, PSBT_GLOBAL_SP_ECDH_SHARE, scan, share);
}

pub fn sp_global_ecdh_share(psbt: &Psbt, scan: PublicKey) -> Result<Option<PublicKey>, Error> {
    get_ecdh_share(&psbt.unknown, PSBT_GLOBAL_SP_ECDH_SHARE, scan)
}

pub fn sp_global_ecdh_share_v2(psbt: &PsbtV2, scan: PublicKey) -> Result<Option<PublicKey>, Error> {
    get_ecdh_share(&psbt.unknown, PSBT_GLOBAL_SP_ECDH_SHARE, scan)
}

pub fn sp_global_ecdh_shares_v2(psbt: &PsbtV2) -> Result<Vec<SpShare>, Error> {
    get_ecdh_shares(&psbt.unknown, PSBT_GLOBAL_SP_ECDH_SHARE)
}

pub fn set_sp_global_dleq(psbt: &mut Psbt, scan: PublicKey, proof: [u8; DLEQ_PROOF_LEN]) {
    set_dleq(&mut psbt.unknown, PSBT_GLOBAL_SP_DLEQ, scan, proof);
}

pub fn set_sp_global_dleq_v2(psbt: &mut PsbtV2, scan: PublicKey, proof: [u8; DLEQ_PROOF_LEN]) {
    set_dleq(&mut psbt.unknown, PSBT_GLOBAL_SP_DLEQ, scan, proof);
}

pub fn sp_global_dleq(psbt: &Psbt, scan: PublicKey) -> Result<Option<[u8; DLEQ_PROOF_LEN]>, Error> {
    get_dleq(&psbt.unknown, PSBT_GLOBAL_SP_DLEQ, scan)
}

pub fn sp_global_dleq_v2(
    psbt: &PsbtV2,
    scan: PublicKey,
) -> Result<Option<[u8; DLEQ_PROOF_LEN]>, Error> {
    get_dleq(&psbt.unknown, PSBT_GLOBAL_SP_DLEQ, scan)
}

pub fn sp_global_dleqs_v2(psbt: &PsbtV2) -> Result<Vec<SpProof>, Error> {
    get_dleqs(&psbt.unknown, PSBT_GLOBAL_SP_DLEQ)
}

pub fn set_sp_v0_output(
    output: &mut Output,
    scan_key: PublicKey,
    spend_key: PublicKey,
    label: Option<u32>,
) {
    let mut info = Vec::with_capacity(SP_V0_INFO_LEN);
    info.extend_from_slice(&scan_key.serialize());
    info.extend_from_slice(&spend_key.serialize());
    output
        .unknown
        .insert(key(PSBT_OUT_SP_V0_INFO, Vec::new()), info);
    if let Some(label) = label {
        output.unknown.insert(
            key(PSBT_OUT_SP_V0_LABEL, Vec::new()),
            label.to_le_bytes().to_vec(),
        );
    }
}

pub fn sp_v0_output(output: &Output) -> Result<Option<SpV0Output>, Error> {
    let info = match output.unknown.get(&key(PSBT_OUT_SP_V0_INFO, Vec::new())) {
        Some(info) => info,
        None => return Ok(None),
    };
    if info.len() != SP_V0_INFO_LEN {
        return Err(Error::InvalidValue);
    }
    let label = output
        .unknown
        .get(&key(PSBT_OUT_SP_V0_LABEL, Vec::new()))
        .map(|value| get_fixed::<4>(value).map(u32::from_le_bytes))
        .transpose()?;
    Ok(Some(SpV0Output {
        scan_key: PublicKey::from_slice(&info[..ECDH_SHARE_LEN])
            .map_err(|_| Error::InvalidValue)?,
        spend_key: PublicKey::from_slice(&info[ECDH_SHARE_LEN..])
            .map_err(|_| Error::InvalidValue)?,
        label,
    }))
}

pub fn has_sp_v0_label(output: &Output) -> bool {
    output
        .unknown
        .contains_key(&key(PSBT_OUT_SP_V0_LABEL, Vec::new()))
}

pub fn set_sp_input_ecdh_share(input: &mut Input, scan: PublicKey, share: PublicKey) {
    set_ecdh_share(&mut input.unknown, PSBT_IN_SP_ECDH_SHARE, scan, share);
}

pub fn sp_input_ecdh_share(input: &Input, scan: PublicKey) -> Result<Option<PublicKey>, Error> {
    get_ecdh_share(&input.unknown, PSBT_IN_SP_ECDH_SHARE, scan)
}

pub fn sp_input_ecdh_shares(input: &Input) -> Result<Vec<SpShare>, Error> {
    get_ecdh_shares(&input.unknown, PSBT_IN_SP_ECDH_SHARE)
}

pub fn set_sp_input_dleq(input: &mut Input, scan: PublicKey, proof: [u8; DLEQ_PROOF_LEN]) {
    set_dleq(&mut input.unknown, PSBT_IN_SP_DLEQ, scan, proof);
}

pub fn sp_input_dleq(
    input: &Input,
    scan: PublicKey,
) -> Result<Option<[u8; DLEQ_PROOF_LEN]>, Error> {
    get_dleq(&input.unknown, PSBT_IN_SP_DLEQ, scan)
}

pub fn sp_input_dleqs(input: &Input) -> Result<Vec<SpProof>, Error> {
    get_dleqs(&input.unknown, PSBT_IN_SP_DLEQ)
}

pub fn set_sp_input_spend_bip32_derivation(
    input: &mut Input,
    spend: PublicKey,
    key_source: KeySource,
) {
    let mut value = Vec::with_capacity(4 + key_source.1.len() * 4);
    set_key_source(&mut value, &key_source);
    input
        .unknown
        .insert(scan_key(PSBT_IN_SP_SPEND_BIP32_DERIVATION, spend), value);
}

pub fn sp_input_spend_bip32_derivation(
    input: &Input,
    spend: PublicKey,
) -> Result<Option<KeySource>, Error> {
    input
        .unknown
        .get(&scan_key(PSBT_IN_SP_SPEND_BIP32_DERIVATION, spend))
        .map(|value| get_key_source(value))
        .transpose()
}

/// The tweak `t` such that the input's output key is `b_spend + t`: a signer
/// holding `b_spend` derives `b_spend + t` and compares it to the prevout
/// script to recognise its own silent-payment inputs.
pub fn set_sp_input_tweak(input: &mut Input, tweak: [u8; TWEAK_LEN]) {
    input
        .unknown
        .insert(key(PSBT_IN_SP_TWEAK, Vec::new()), tweak.to_vec());
}

pub fn sp_input_tweak(input: &Input) -> Result<Option<[u8; TWEAK_LEN]>, Error> {
    input
        .unknown
        .get(&key(PSBT_IN_SP_TWEAK, Vec::new()))
        .map(|value| get_fixed(value))
        .transpose()
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        bip32::{ChildNumber, DerivationPath, Fingerprint},
        psbt::{Input, Output},
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        Psbt,
    };

    use crate::sp::{
        key, scan_key, set_sp_global_dleq, set_sp_global_ecdh_share, set_sp_input_dleq,
        set_sp_input_ecdh_share, set_sp_input_spend_bip32_derivation, set_sp_input_tweak,
        set_sp_v0_output, sp_global_dleq, sp_global_ecdh_share, sp_input_dleq, sp_input_dleqs,
        sp_input_ecdh_share, sp_input_ecdh_shares, sp_input_spend_bip32_derivation, sp_input_tweak,
        sp_v0_output, Error, SpProof, SpShare, DLEQ_PROOF_LEN, PSBT_GLOBAL_SP_DLEQ,
        PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE,
        PSBT_IN_SP_SPEND_BIP32_DERIVATION, PSBT_IN_SP_TWEAK, PSBT_OUT_SP_V0_INFO, SP_V0_INFO_LEN,
        TWEAK_LEN,
    };

    fn public_key(b: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap())
    }

    fn psbt_spending(input: Vec<bitcoin::TxIn>) -> Psbt {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn global_fields_round_trip() {
        let scan = public_key(1);
        let share = public_key(2);
        let proof = [3; DLEQ_PROOF_LEN];
        let mut psbt = psbt_spending(Vec::new());

        set_sp_global_ecdh_share(&mut psbt, scan, share);
        set_sp_global_dleq(&mut psbt, scan, proof);

        let bytes = psbt.serialize();
        let parsed = Psbt::deserialize(&bytes).unwrap();
        assert_eq!(sp_global_ecdh_share(&parsed, scan), Ok(Some(share)));
        assert_eq!(sp_global_dleq(&parsed, scan), Ok(Some(proof)));
    }

    #[test]
    fn sp_v0_output_round_trips_with_label() {
        let scan = public_key(1);
        let spend = public_key(2);
        let mut output = Output::default();

        set_sp_v0_output(&mut output, scan, spend, Some(9));

        let parsed = sp_v0_output(&output).unwrap().unwrap();
        assert_eq!(parsed.scan_key, scan);
        assert_eq!(parsed.spend_key, spend);
        assert_eq!(parsed.label, Some(9));
        let raw_info = output
            .unknown
            .get(&key(PSBT_OUT_SP_V0_INFO, Vec::new()))
            .unwrap();
        assert_eq!(raw_info.len(), SP_V0_INFO_LEN);
    }

    #[test]
    fn global_getters_reject_invalid_values() {
        let scan = public_key(1);
        let mut psbt = psbt_spending(Vec::new());

        psbt.unknown
            .insert(scan_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan), vec![0; 32]);
        psbt.unknown
            .insert(scan_key(PSBT_GLOBAL_SP_DLEQ, scan), vec![0; 63]);

        assert_eq!(sp_global_ecdh_share(&psbt, scan), Err(Error::InvalidValue));
        assert_eq!(sp_global_dleq(&psbt, scan), Err(Error::InvalidValue));
    }

    fn one_input_psbt() -> Psbt {
        psbt_spending(vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }])
    }

    #[test]
    fn sp_fields_round_trip() {
        let scan = public_key(1);
        let share = public_key(2);
        let spend = public_key(3);
        let proof = [4; DLEQ_PROOF_LEN];
        let tweak = [5; TWEAK_LEN];
        let key_source = (
            Fingerprint::from([6; 4]),
            DerivationPath::from(vec![ChildNumber::from(7), ChildNumber::from(8)]),
        );
        let mut psbt = one_input_psbt();

        set_sp_global_ecdh_share(&mut psbt, scan, share);
        set_sp_global_dleq(&mut psbt, scan, proof);
        set_sp_input_ecdh_share(&mut psbt.inputs[0], scan, share);
        set_sp_input_dleq(&mut psbt.inputs[0], scan, proof);
        set_sp_input_spend_bip32_derivation(&mut psbt.inputs[0], spend, key_source.clone());
        set_sp_input_tweak(&mut psbt.inputs[0], tweak);
        set_sp_v0_output(&mut psbt.outputs[0], scan, spend, Some(9));

        let parsed = Psbt::deserialize(&psbt.serialize()).unwrap();
        assert_eq!(sp_global_ecdh_share(&parsed, scan), Ok(Some(share)));
        assert_eq!(sp_global_dleq(&parsed, scan), Ok(Some(proof)));
        assert_eq!(
            sp_input_ecdh_share(&parsed.inputs[0], scan),
            Ok(Some(share))
        );
        assert_eq!(sp_input_dleq(&parsed.inputs[0], scan), Ok(Some(proof)));
        assert_eq!(
            sp_input_spend_bip32_derivation(&parsed.inputs[0], spend),
            Ok(Some(key_source))
        );
        assert_eq!(sp_input_tweak(&parsed.inputs[0]), Ok(Some(tweak)));
        let output = sp_v0_output(&parsed.outputs[0]).unwrap().unwrap();
        assert_eq!(output.scan_key, scan);
        assert_eq!(output.spend_key, spend);
        assert_eq!(output.label, Some(9));
    }

    #[test]
    fn input_getters_reject_invalid_values() {
        let scan = public_key(1);
        let spend = public_key(2);
        let mut psbt = one_input_psbt();

        psbt.inputs[0]
            .unknown
            .insert(scan_key(PSBT_IN_SP_ECDH_SHARE, scan), vec![0; 32]);
        psbt.inputs[0]
            .unknown
            .insert(scan_key(PSBT_IN_SP_DLEQ, scan), vec![0; 63]);
        psbt.inputs[0]
            .unknown
            .insert(key(PSBT_IN_SP_TWEAK, Vec::new()), vec![0; 31]);
        psbt.inputs[0].unknown.insert(
            scan_key(PSBT_IN_SP_SPEND_BIP32_DERIVATION, spend),
            vec![0; 5],
        );

        assert_eq!(
            sp_input_ecdh_share(&psbt.inputs[0], scan),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            sp_input_dleq(&psbt.inputs[0], scan),
            Err(Error::InvalidValue)
        );
        assert_eq!(sp_input_tweak(&psbt.inputs[0]), Err(Error::InvalidValue));
        assert_eq!(
            sp_input_spend_bip32_derivation(&psbt.inputs[0], spend),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn sp_input_shares_and_dleqs_list_every_scan_key() {
        let scan_a = public_key(1);
        let scan_b = public_key(2);
        let share_a = public_key(3);
        let share_b = public_key(4);
        let proof_a = [5; DLEQ_PROOF_LEN];
        let proof_b = [6; DLEQ_PROOF_LEN];
        let mut psbt = one_input_psbt();

        set_sp_input_ecdh_share(&mut psbt.inputs[0], scan_a, share_a);
        set_sp_input_ecdh_share(&mut psbt.inputs[0], scan_b, share_b);
        set_sp_input_dleq(&mut psbt.inputs[0], scan_a, proof_a);
        set_sp_input_dleq(&mut psbt.inputs[0], scan_b, proof_b);

        let shares = sp_input_ecdh_shares(&psbt.inputs[0]).unwrap();
        assert_eq!(shares.len(), 2);
        assert!(shares.contains(&SpShare {
            scan_key: scan_a,
            share: share_a
        }));
        assert!(shares.contains(&SpShare {
            scan_key: scan_b,
            share: share_b
        }));

        let proofs = sp_input_dleqs(&psbt.inputs[0]).unwrap();
        assert_eq!(proofs.len(), 2);
        assert!(proofs.contains(&SpProof {
            scan_key: scan_a,
            proof: proof_a
        }));
        assert!(proofs.contains(&SpProof {
            scan_key: scan_b,
            proof: proof_b
        }));
    }

    #[test]
    fn hardened_derivation_path_round_trips() {
        let spend = public_key(1);
        let key_source = (
            Fingerprint::from([9; 4]),
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_normal_idx(1).unwrap(),
            ]),
        );
        let mut input = Input::default();

        set_sp_input_spend_bip32_derivation(&mut input, spend, key_source.clone());

        assert_eq!(
            sp_input_spend_bip32_derivation(&input, spend),
            Ok(Some(key_source))
        );
    }
}
