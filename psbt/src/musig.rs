//! BIP-373 MuSig2 PSBT fields.
//!
//! rust-bitcoin does not model these keytypes: they live in the `unknown` map of
//! a `bitcoin::psbt::Input` / `Output` under their real keytype numbers, so the
//! same functions serve `bitcoin::Psbt` (`psbt.inputs[i]`) and `PsbtV2`
//! (`psbt.inputs[i].psbt`).
//!
//! ```text
//! +------+----------------------------------------------+----------------------+
//! | type | keydata                                      | value                |
//! +------+----------------------------------------------+----------------------+
//! | 0x1a | aggregate (33)                               | participant (33) * n |
//! | 0x1b | participant (33) aggregate (33) [leaf (32)]  | public nonce (66)    |
//! | 0x1c | participant (33) aggregate (33) [leaf (32)]  | partial sig (32)     |
//! | 0x08 | aggregate (33), on an output                 | participant (33) * n |
//! +------+----------------------------------------------+----------------------+
//! ```
//!
//! Participants are listed in aggregation order (sorted when KeySort was used),
//! at least one.
//!
//! Which key goes in the aggregate slot:
//! - 0x1a and 0x08: the plain KeyAgg output, with no tweak. The path from it to
//!   the internal or script key is a `tap_key_origins` entry under the BIP-328
//!   synthetic xpub fingerprint.
//! - 0x1b and 0x1c on the key path: the taproot output key (BIP-32 tweaks then the
//!   BIP-341 taptweak), with no leaf hash.
//! - 0x1b and 0x1c on a script path: the key as it appears in the leaf (BIP-32
//!   tweaks only), with the leaf hash.
//!
//! This module stores what the caller passes and only checks lengths and key
//! encodings; applying the slot rule is the caller's job.

use std::collections::BTreeMap;

use bitcoin::{
    hashes::Hash,
    psbt::{raw, Input, Output},
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
const KEY_PATH_KEY_LEN: usize = 2 * PUBLIC_KEY_LEN;
const SCRIPT_PATH_KEY_LEN: usize = KEY_PATH_KEY_LEN + LEAF_HASH_LEN;

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

// The keydata of a 0x1b / 0x1c entry.
struct ParticipantAggregate {
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
}

fn key(type_value: u8, key: Vec<u8>) -> raw::Key {
    raw::Key { type_value, key }
}

// A 33-byte compressed key on the curve: refuses an x-only or uncompressed key.
fn get_public_key(bytes: &[u8]) -> Option<PublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return None;
    }
    PublicKey::from_slice(bytes).ok()
}

fn get_fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], Error> {
    value.try_into().map_err(|_| Error::InvalidValue)
}

fn participants_value(participants: &[PublicKey]) -> Vec<u8> {
    participants
        .iter()
        .flat_map(|participant| participant.serialize())
        .collect()
}

// BIP-327 KeyAgg needs at least one key, so an empty list is refused.
fn get_participants(value: &[u8]) -> Result<Vec<PublicKey>, Error> {
    if value.is_empty() || value.len() % PUBLIC_KEY_LEN != 0 {
        return Err(Error::InvalidValue);
    }
    value
        .chunks_exact(PUBLIC_KEY_LEN)
        .map(|chunk| get_public_key(chunk).ok_or(Error::InvalidValue))
        .collect()
}

fn participant_aggregate_key(
    type_value: u8,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> raw::Key {
    let mut keydata = Vec::with_capacity(SCRIPT_PATH_KEY_LEN);
    keydata.extend_from_slice(&participant.serialize());
    keydata.extend_from_slice(&aggregate.serialize());
    if let Some(leaf_hash) = leaf_hash {
        keydata.extend_from_slice(&leaf_hash.to_byte_array());
    }
    key(type_value, keydata)
}

fn parse_participant_aggregate_key(key: &[u8]) -> Result<ParticipantAggregate, Error> {
    let leaf_hash = match key.len() {
        KEY_PATH_KEY_LEN => None,
        SCRIPT_PATH_KEY_LEN => Some(TapLeafHash::from_byte_array(
            get_fixed(&key[KEY_PATH_KEY_LEN..]).map_err(|_| Error::InvalidKey)?,
        )),
        _ => return Err(Error::InvalidKey),
    };
    Ok(ParticipantAggregate {
        participant: get_public_key(&key[..PUBLIC_KEY_LEN]).ok_or(Error::InvalidKey)?,
        aggregate: get_public_key(&key[PUBLIC_KEY_LEN..KEY_PATH_KEY_LEN])
            .ok_or(Error::InvalidKey)?,
        leaf_hash,
    })
}

// Helpers shared by the input and output maps, parameterized by keytype.

fn set_participants(
    unknown: &mut BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    aggregate: PublicKey,
    participants: &[PublicKey],
) {
    // BIP-327 KeyAgg needs at least one key: an empty list would be unreadable.
    debug_assert!(!participants.is_empty());
    unknown.insert(
        key(type_value, aggregate.serialize().to_vec()),
        participants_value(participants),
    );
}

fn get_participants_for(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    aggregate: PublicKey,
) -> Result<Option<Vec<PublicKey>>, Error> {
    unknown
        .get(&key(type_value, aggregate.serialize().to_vec()))
        .map(|value| get_participants(value))
        .transpose()
}

fn list_participants(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
) -> Result<Vec<MusigParticipants>, Error> {
    unknown
        .iter()
        .filter(|(key, _)| key.type_value == type_value)
        .map(|(key, value)| {
            Ok(MusigParticipants {
                aggregate: get_public_key(&key.key).ok_or(Error::InvalidKey)?,
                participants: get_participants(value)?,
            })
        })
        .collect()
}

fn get_signer_value<const N: usize>(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> Result<Option<[u8; N]>, Error> {
    unknown
        .get(&participant_aggregate_key(
            type_value,
            participant,
            aggregate,
            leaf_hash,
        ))
        .map(|value| get_fixed(value))
        .transpose()
}

fn list_signer_values<const N: usize, T>(
    unknown: &BTreeMap<raw::Key, Vec<u8>>,
    type_value: u8,
    entry: fn(ParticipantAggregate, [u8; N]) -> T,
) -> Result<Vec<T>, Error> {
    unknown
        .iter()
        .filter(|(key, _)| key.type_value == type_value)
        .map(|(key, value)| {
            Ok(entry(
                parse_participant_aggregate_key(&key.key)?,
                get_fixed(value)?,
            ))
        })
        .collect()
}

fn remove_type(unknown: &mut BTreeMap<raw::Key, Vec<u8>>, type_value: u8) -> usize {
    let before = unknown.len();
    unknown.retain(|key, _| key.type_value != type_value);
    before - unknown.len()
}

/// Replaces any participant list already stored for `aggregate`. The order is
/// kept as given.
pub fn set_musig_input_participants(
    input: &mut Input,
    aggregate: PublicKey,
    participants: &[PublicKey],
) {
    set_participants(
        &mut input.unknown,
        PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
        aggregate,
        participants,
    );
}

pub fn musig_input_participants(
    input: &Input,
    aggregate: PublicKey,
) -> Result<Option<Vec<PublicKey>>, Error> {
    get_participants_for(
        &input.unknown,
        PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
        aggregate,
    )
}

pub fn musig_input_participants_all(input: &Input) -> Result<Vec<MusigParticipants>, Error> {
    list_participants(&input.unknown, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)
}

pub fn set_musig_input_pub_nonce(input: &mut Input, nonce: &MusigPubNonce) {
    input.unknown.insert(
        participant_aggregate_key(
            PSBT_IN_MUSIG2_PUB_NONCE,
            nonce.participant,
            nonce.aggregate,
            nonce.leaf_hash,
        ),
        nonce.nonce.to_vec(),
    );
}

/// Only the nonce length is checked here; bwk-musig `nonce_agg` checks that its
/// points are valid.
pub fn musig_input_pub_nonce(
    input: &Input,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> Result<Option<[u8; PUB_NONCE_LEN]>, Error> {
    get_signer_value(
        &input.unknown,
        PSBT_IN_MUSIG2_PUB_NONCE,
        participant,
        aggregate,
        leaf_hash,
    )
}

/// Every 0x1b entry in keydata order; only the nonce lengths are checked.
pub fn musig_input_pub_nonces(input: &Input) -> Result<Vec<MusigPubNonce>, Error> {
    list_signer_values(&input.unknown, PSBT_IN_MUSIG2_PUB_NONCE, |key, nonce| {
        MusigPubNonce {
            participant: key.participant,
            aggregate: key.aggregate,
            leaf_hash: key.leaf_hash,
            nonce,
        }
    })
}

/// Drops every 0x1b entry; the count removed.
pub fn remove_musig_input_pub_nonces(input: &mut Input) -> usize {
    remove_type(&mut input.unknown, PSBT_IN_MUSIG2_PUB_NONCE)
}

pub fn set_musig_input_partial_sig(input: &mut Input, sig: &MusigPartialSig) {
    input.unknown.insert(
        participant_aggregate_key(
            PSBT_IN_MUSIG2_PARTIAL_SIG,
            sig.participant,
            sig.aggregate,
            sig.leaf_hash,
        ),
        sig.signature.to_vec(),
    );
}

/// Only the signature length is checked here; bwk-musig checks that it is a
/// valid scalar.
pub fn musig_input_partial_sig(
    input: &Input,
    participant: PublicKey,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
) -> Result<Option<[u8; PARTIAL_SIG_LEN]>, Error> {
    get_signer_value(
        &input.unknown,
        PSBT_IN_MUSIG2_PARTIAL_SIG,
        participant,
        aggregate,
        leaf_hash,
    )
}

/// Every 0x1c entry in keydata order; only the signature lengths are checked.
pub fn musig_input_partial_sigs(input: &Input) -> Result<Vec<MusigPartialSig>, Error> {
    list_signer_values(
        &input.unknown,
        PSBT_IN_MUSIG2_PARTIAL_SIG,
        |key, signature| MusigPartialSig {
            participant: key.participant,
            aggregate: key.aggregate,
            leaf_hash: key.leaf_hash,
            signature,
        },
    )
}

/// Drops every 0x1c entry; the count removed.
pub fn remove_musig_input_partial_sigs(input: &mut Input) -> usize {
    remove_type(&mut input.unknown, PSBT_IN_MUSIG2_PARTIAL_SIG)
}

/// Replaces any participant list already stored for `aggregate`. The order is
/// kept as given.
pub fn set_musig_output_participants(
    output: &mut Output,
    aggregate: PublicKey,
    participants: &[PublicKey],
) {
    set_participants(
        &mut output.unknown,
        PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS,
        aggregate,
        participants,
    );
}

pub fn musig_output_participants(output: &Output) -> Result<Vec<MusigParticipants>, Error> {
    list_participants(&output.unknown, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS)
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, psbt::Output, taproot::TapLeafHash, Psbt};

    use crate::{
        musig::{
            key, musig_input_partial_sig, musig_input_partial_sigs, musig_input_participants,
            musig_input_participants_all, musig_input_pub_nonce, musig_input_pub_nonces,
            musig_output_participants, participant_aggregate_key, remove_musig_input_partial_sigs,
            remove_musig_input_pub_nonces, set_musig_input_partial_sig,
            set_musig_input_participants, set_musig_input_pub_nonce, set_musig_output_participants,
            Error, MusigPartialSig, MusigParticipants, MusigPubNonce, PARTIAL_SIG_LEN,
            PSBT_IN_MUSIG2_PARTIAL_SIG, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
            PSBT_IN_MUSIG2_PUB_NONCE, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, PUB_NONCE_LEN,
        },
        test_utils::{one_input_psbt, public_key},
        PsbtV2,
    };

    fn leaf_hash(b: u8) -> TapLeafHash {
        TapLeafHash::from_byte_array([b; 32])
    }

    fn pub_nonce(participant: u8, leaf_hash: Option<TapLeafHash>, b: u8) -> MusigPubNonce {
        MusigPubNonce {
            participant: public_key(participant),
            aggregate: public_key(9),
            leaf_hash,
            nonce: [b; PUB_NONCE_LEN],
        }
    }

    fn partial_sig(participant: u8, leaf_hash: Option<TapLeafHash>, b: u8) -> MusigPartialSig {
        MusigPartialSig {
            participant: public_key(participant),
            aggregate: public_key(9),
            leaf_hash,
            signature: [b; PARTIAL_SIG_LEN],
        }
    }

    #[test]
    fn input_participants_round_trip() {
        let participants = [public_key(3), public_key(1), public_key(2)];
        let mut psbt = one_input_psbt();

        set_musig_input_participants(&mut psbt.inputs[0], public_key(9), &participants);

        assert_eq!(
            musig_input_participants(&psbt.inputs[0], public_key(9)),
            Ok(Some(participants.to_vec()))
        );
        assert_eq!(
            musig_input_participants(&psbt.inputs[0], public_key(8)),
            Ok(None)
        );
    }

    #[test]
    fn input_participants_all_lists_every_aggregate() {
        let first = vec![public_key(1), public_key(2)];
        let second = vec![public_key(3), public_key(4), public_key(5)];
        let mut psbt = one_input_psbt();

        set_musig_input_participants(&mut psbt.inputs[0], public_key(8), &first);
        set_musig_input_participants(&mut psbt.inputs[0], public_key(9), &second);

        let all = musig_input_participants_all(&psbt.inputs[0]).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&MusigParticipants {
            aggregate: public_key(8),
            participants: first,
        }));
        assert!(all.contains(&MusigParticipants {
            aggregate: public_key(9),
            participants: second,
        }));
    }

    #[test]
    fn pub_nonce_round_trip_key_path_and_script_path() {
        let key_path = pub_nonce(1, None, 4);
        let script_path = pub_nonce(1, Some(leaf_hash(7)), 5);
        let mut psbt = one_input_psbt();

        set_musig_input_pub_nonce(&mut psbt.inputs[0], &key_path);
        set_musig_input_pub_nonce(&mut psbt.inputs[0], &script_path);

        assert_eq!(
            musig_input_pub_nonce(&psbt.inputs[0], public_key(1), public_key(9), None),
            Ok(Some(key_path.nonce))
        );
        assert_eq!(
            musig_input_pub_nonce(
                &psbt.inputs[0],
                public_key(1),
                public_key(9),
                Some(leaf_hash(7))
            ),
            Ok(Some(script_path.nonce))
        );
        let nonces = musig_input_pub_nonces(&psbt.inputs[0]).unwrap();
        assert_eq!(nonces.len(), 2);
        assert!(nonces.contains(&key_path));
        assert!(nonces.contains(&script_path));
    }

    #[test]
    fn partial_sig_round_trip_key_path_and_script_path() {
        let key_path = partial_sig(1, None, 4);
        let script_path = partial_sig(1, Some(leaf_hash(7)), 5);
        let mut psbt = one_input_psbt();

        set_musig_input_partial_sig(&mut psbt.inputs[0], &key_path);
        set_musig_input_partial_sig(&mut psbt.inputs[0], &script_path);

        assert_eq!(
            musig_input_partial_sig(&psbt.inputs[0], public_key(1), public_key(9), None),
            Ok(Some(key_path.signature))
        );
        assert_eq!(
            musig_input_partial_sig(
                &psbt.inputs[0],
                public_key(1),
                public_key(9),
                Some(leaf_hash(7))
            ),
            Ok(Some(script_path.signature))
        );
        let sigs = musig_input_partial_sigs(&psbt.inputs[0]).unwrap();
        assert_eq!(sigs.len(), 2);
        assert!(sigs.contains(&key_path));
        assert!(sigs.contains(&script_path));
    }

    #[test]
    fn remove_pub_nonces_and_partial_sigs_counts() {
        let participants = [public_key(1), public_key(2), public_key(3)];
        let mut psbt = one_input_psbt();
        let input = &mut psbt.inputs[0];

        set_musig_input_participants(input, public_key(9), &participants);
        for participant in 1..=3 {
            set_musig_input_pub_nonce(input, &pub_nonce(participant, None, participant));
        }
        for participant in 1..=2 {
            set_musig_input_partial_sig(input, &partial_sig(participant, None, participant));
        }

        assert_eq!(remove_musig_input_pub_nonces(input), 3);
        assert_eq!(musig_input_pub_nonces(input), Ok(Vec::new()));
        assert_eq!(musig_input_partial_sigs(input).unwrap().len(), 2);
        assert_eq!(
            musig_input_participants(input, public_key(9)),
            Ok(Some(participants.to_vec()))
        );
        assert_eq!(remove_musig_input_partial_sigs(input), 2);
        assert_eq!(musig_input_partial_sigs(input), Ok(Vec::new()));
        assert_eq!(remove_musig_input_pub_nonces(input), 0);
        assert_eq!(remove_musig_input_partial_sigs(input), 0);
    }

    #[test]
    fn output_participants_round_trip() {
        let participants = vec![public_key(2), public_key(1)];
        let mut output = Output::default();

        set_musig_output_participants(&mut output, public_key(9), &participants);

        assert_eq!(
            musig_output_participants(&output),
            Ok(vec![MusigParticipants {
                aggregate: public_key(9),
                participants,
            }])
        );
    }

    #[test]
    fn getters_reject_invalid_keys() {
        let x_only = public_key(9).x_only_public_key().0.serialize().to_vec();
        let mut psbt = one_input_psbt();
        psbt.inputs[0].unknown.insert(
            key(PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, x_only.clone()),
            public_key(1).serialize().to_vec(),
        );
        psbt.outputs[0].unknown.insert(
            key(PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, x_only),
            public_key(1).serialize().to_vec(),
        );
        assert_eq!(
            musig_input_participants_all(&psbt.inputs[0]),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            musig_output_participants(&psbt.outputs[0]),
            Err(Error::InvalidKey)
        );

        let key_path = participant_aggregate_key(0, public_key(1), public_key(9), None).key;
        let script_path =
            participant_aggregate_key(0, public_key(1), public_key(9), Some(leaf_hash(7))).key;
        let mut off_curve = key_path.clone();
        off_curve[1..33].fill(0xff);
        for keydata in [
            key_path[..65].to_vec(),
            script_path[..97].to_vec(),
            off_curve,
        ] {
            let mut psbt = one_input_psbt();
            psbt.inputs[0].unknown.insert(
                key(PSBT_IN_MUSIG2_PUB_NONCE, keydata.clone()),
                vec![0; PUB_NONCE_LEN],
            );
            psbt.inputs[0].unknown.insert(
                key(PSBT_IN_MUSIG2_PARTIAL_SIG, keydata),
                vec![0; PARTIAL_SIG_LEN],
            );
            assert_eq!(
                musig_input_pub_nonces(&psbt.inputs[0]),
                Err(Error::InvalidKey)
            );
            assert_eq!(
                musig_input_partial_sigs(&psbt.inputs[0]),
                Err(Error::InvalidKey)
            );
        }
    }

    #[test]
    fn getters_reject_invalid_values() {
        let aggregate = public_key(9).serialize().to_vec();
        for value in [vec![0x02; 98], Vec::new()] {
            let mut psbt = one_input_psbt();
            psbt.inputs[0].unknown.insert(
                key(PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS, aggregate.clone()),
                value.clone(),
            );
            psbt.outputs[0].unknown.insert(
                key(PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS, aggregate.clone()),
                value,
            );
            assert_eq!(
                musig_input_participants(&psbt.inputs[0], public_key(9)),
                Err(Error::InvalidValue)
            );
            assert_eq!(
                musig_input_participants_all(&psbt.inputs[0]),
                Err(Error::InvalidValue)
            );
            assert_eq!(
                musig_output_participants(&psbt.outputs[0]),
                Err(Error::InvalidValue)
            );
        }

        let mut psbt = one_input_psbt();
        psbt.inputs[0].unknown.insert(
            participant_aggregate_key(PSBT_IN_MUSIG2_PUB_NONCE, public_key(1), public_key(9), None),
            vec![0; PUB_NONCE_LEN - 1],
        );
        psbt.inputs[0].unknown.insert(
            participant_aggregate_key(
                PSBT_IN_MUSIG2_PARTIAL_SIG,
                public_key(1),
                public_key(9),
                None,
            ),
            vec![0; PARTIAL_SIG_LEN - 1],
        );
        assert_eq!(
            musig_input_pub_nonce(&psbt.inputs[0], public_key(1), public_key(9), None),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            musig_input_pub_nonces(&psbt.inputs[0]),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            musig_input_partial_sig(&psbt.inputs[0], public_key(1), public_key(9), None),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            musig_input_partial_sigs(&psbt.inputs[0]),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn fields_survive_v0_and_v2_serialization() {
        let participants = [public_key(1), public_key(2)];
        let nonce = pub_nonce(1, Some(leaf_hash(7)), 4);
        let sig = partial_sig(2, None, 5);
        let mut psbt = one_input_psbt();
        set_musig_input_participants(&mut psbt.inputs[0], public_key(9), &participants);
        set_musig_input_pub_nonce(&mut psbt.inputs[0], &nonce);
        set_musig_input_partial_sig(&mut psbt.inputs[0], &sig);
        set_musig_output_participants(&mut psbt.outputs[0], public_key(9), &participants);

        let v0 = Psbt::deserialize(&psbt.serialize()).unwrap();
        assert_eq!(v0, psbt);
        let v2 = PsbtV2::deserialize(&PsbtV2::from_bitcoin_psbt(v0).unwrap().serialize().unwrap())
            .unwrap();

        let input = &v2.inputs[0].psbt;
        assert_eq!(
            musig_input_participants(input, public_key(9)),
            Ok(Some(participants.to_vec()))
        );
        assert_eq!(musig_input_pub_nonces(input), Ok(vec![nonce]));
        assert_eq!(
            musig_input_pub_nonce(input, public_key(1), public_key(9), Some(leaf_hash(7))),
            Ok(Some(nonce.nonce))
        );
        assert_eq!(musig_input_partial_sigs(input), Ok(vec![sig]));
        assert_eq!(
            musig_input_partial_sig(input, public_key(2), public_key(9), None),
            Ok(Some(sig.signature))
        );
        assert_eq!(
            musig_output_participants(&v2.outputs[0].psbt),
            Ok(vec![MusigParticipants {
                aggregate: public_key(9),
                participants: participants.to_vec(),
            }])
        );
    }
}
