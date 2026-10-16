//! BIP-373 MuSig2 PSBT fields.

#![allow(dead_code, unused_variables)]

use bitcoin::{
    psbt::{Input, Output},
    secp256k1::PublicKey,
    taproot::TapLeafHash,
};

pub const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1a;
pub const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1b;
pub const PSBT_IN_MUSIG2_PARTIAL_SIG: u8 = 0x1c;
pub const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;
const PUBLIC_KEY_LEN: usize = 33;
const LEAF_HASH_LEN: usize = 32;
const PUB_NONCE_LEN: usize = 66;
const PARTIAL_SIG_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid musig2 field key")]
    InvalidKey,
    #[error("invalid musig2 field value")]
    InvalidValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusigParticipants {
    pub aggregate: PublicKey,
    pub participants: Vec<PublicKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MusigPubNonce {
    pub participant: PublicKey,
    pub aggregate: PublicKey,
    pub leaf_hash: Option<TapLeafHash>,
    pub nonce: [u8; PUB_NONCE_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MusigPartialSig {
    pub participant: PublicKey,
    pub aggregate: PublicKey,
    pub leaf_hash: Option<TapLeafHash>,
    pub signature: [u8; PARTIAL_SIG_LEN],
}

pub fn set_musig_input_participants(
    input: &mut Input,
    aggregate: PublicKey,
    participants: &[PublicKey],
) {
    todo!()
}

pub fn musig_input_participants(
    input: &Input,
    aggregate: PublicKey,
) -> Result<Option<Vec<PublicKey>>, Error> {
    todo!()
}

pub fn musig_input_participants_all(input: &Input) -> Result<Vec<MusigParticipants>, Error> {
    todo!()
}

pub fn set_musig_input_pub_nonce(input: &mut Input, nonce: &MusigPubNonce) {
    todo!()
}

pub fn musig_input_pub_nonce(
    input: &Input,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> Result<Option<[u8; PUB_NONCE_LEN]>, Error> {
    todo!()
}

pub fn musig_input_pub_nonces(input: &Input) -> Result<Vec<MusigPubNonce>, Error> {
    todo!()
}

/// Drops every 0x1b entry; the count removed.
pub fn remove_musig_input_pub_nonces(input: &mut Input) -> usize {
    todo!()
}

pub fn set_musig_input_partial_sig(input: &mut Input, sig: &MusigPartialSig) {
    todo!()
}

pub fn musig_input_partial_sig(
    input: &Input,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> Result<Option<[u8; PARTIAL_SIG_LEN]>, Error> {
    todo!()
}

pub fn musig_input_partial_sigs(input: &Input) -> Result<Vec<MusigPartialSig>, Error> {
    todo!()
}

/// Drops every 0x1c entry; the count removed.
pub fn remove_musig_input_partial_sigs(input: &mut Input) -> usize {
    todo!()
}

pub fn set_musig_output_participants(
    output: &mut Output,
    aggregate: PublicKey,
    participants: &[PublicKey],
) {
    todo!()
}

pub fn musig_output_participants(output: &Output) -> Result<Vec<MusigParticipants>, Error> {
    todo!()
}
