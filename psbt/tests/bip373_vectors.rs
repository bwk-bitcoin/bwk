#![cfg(feature = "musig")]
//! The BIP-373 "Test Vectors" section, extracted into `test_vectors/bip373.json`.

use bitcoin::{
    hashes::Hash,
    psbt::{Input, Output},
    secp256k1::PublicKey,
    taproot::TapLeafHash,
    Psbt,
};
use bwk_psbt::{
    musig::{
        musig_input_partial_sigs, musig_input_participants_all, musig_input_pub_nonces,
        musig_output_participants, Error, MusigPartialSig, MusigParticipants, MusigPubNonce,
    },
    PsbtV2,
};
use serde_json::Value;

const AGGREGATE: &str = "030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4";
// Sorted, as KeySort leaves them.
const PARTICIPANTS: [&str; 3] = [
    "02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00",
    "024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
];
const ONE_LEAF_MERKLE_ROOT: &str =
    "b11fedaa63a0956501a7308c93b5637371e7613d9b8ade1783d49e26c06cfa2c";

struct Vector {
    comment: String,
    psbt: Psbt,
}

#[derive(Debug, PartialEq)]
struct InputFields {
    participants: Vec<MusigParticipants>,
    pub_nonces: Vec<MusigPubNonce>,
    partial_sigs: Vec<MusigPartialSig>,
}

#[derive(Debug, PartialEq)]
struct Fields {
    inputs: Vec<InputFields>,
    outputs: Vec<Vec<MusigParticipants>>,
}

fn vectors(kind: &str) -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test_vectors/bip373.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    json[kind]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| Vector {
            comment: vector["comment"].as_str().unwrap().to_string(),
            psbt: Psbt::deserialize(&hex::decode(vector["hex"].as_str().unwrap()).unwrap())
                .unwrap(),
        })
        .collect()
}

fn vector(kind: &str, comment: &str) -> Psbt {
    vectors(kind)
        .into_iter()
        .find(|vector| vector.comment == comment)
        .unwrap()
        .psbt
}

fn public_key(hex: &str) -> PublicKey {
    hex.parse().unwrap()
}

fn input_fields(input: &Input) -> InputFields {
    InputFields {
        participants: musig_input_participants_all(input).unwrap(),
        pub_nonces: musig_input_pub_nonces(input).unwrap(),
        partial_sigs: musig_input_partial_sigs(input).unwrap(),
    }
}

fn fields(inputs: &[&Input], outputs: &[&Output]) -> Fields {
    Fields {
        inputs: inputs.iter().map(|input| input_fields(input)).collect(),
        outputs: outputs
            .iter()
            .map(|output| musig_output_participants(output).unwrap())
            .collect(),
    }
}

fn v0_fields(psbt: &Psbt) -> Fields {
    fields(
        &psbt.inputs.iter().collect::<Vec<_>>(),
        &psbt.outputs.iter().collect::<Vec<_>>(),
    )
}

fn v2_fields(psbt: &PsbtV2) -> Fields {
    fields(
        &psbt
            .inputs
            .iter()
            .map(|input| &input.psbt)
            .collect::<Vec<_>>(),
        &psbt
            .outputs
            .iter()
            .map(|output| &output.psbt)
            .collect::<Vec<_>>(),
    )
}

fn expected_participants() -> MusigParticipants {
    MusigParticipants {
        aggregate: public_key(AGGREGATE),
        participants: PARTICIPANTS.map(public_key).to_vec(),
    }
}

fn output_key(input: &Input) -> [u8; 32] {
    input
        .witness_utxo
        .as_ref()
        .unwrap()
        .script_pubkey
        .as_bytes()[2..34]
        .try_into()
        .unwrap()
}

// The aggregate slot and leaf hash of every 0x1b and 0x1c entry.
fn signed_for(fields: &InputFields) -> Vec<(PublicKey, Option<TapLeafHash>)> {
    fields
        .pub_nonces
        .iter()
        .map(|nonce| (nonce.aggregate, nonce.leaf_hash))
        .chain(
            fields
                .partial_sigs
                .iter()
                .map(|sig| (sig.aggregate, sig.leaf_hash)),
        )
        .collect()
}

#[test]
fn bip373_valid_vectors_parse() {
    let vectors = vectors("valid");
    assert_eq!(vectors.len(), 14);
    for vector in vectors {
        let fields = v0_fields(&vector.psbt);
        for participants in fields
            .inputs
            .iter()
            .flat_map(|input| &input.participants)
            .chain(fields.outputs.iter().flatten())
        {
            assert_eq!(participants, &expected_participants(), "{}", vector.comment);
        }
        let pub_nonces = fields
            .inputs
            .iter()
            .map(|input| input.pub_nonces.len())
            .sum::<usize>();
        let partial_sigs = fields
            .inputs
            .iter()
            .map(|input| input.partial_sigs.len())
            .sum::<usize>();
        if vector.comment.ends_with("With all pubnonces") {
            assert_eq!(pub_nonces, 3, "{}", vector.comment);
        }
        if vector.comment.ends_with("With all partial signatures") {
            assert_eq!(partial_sigs, 3, "{}", vector.comment);
        }
    }
}

#[test]
fn bip373_valid_vectors_round_trip_v2() {
    for vector in vectors("valid") {
        let v2 = PsbtV2::from_bitcoin_psbt(vector.psbt.clone()).unwrap();
        let v2 = PsbtV2::deserialize(&v2.serialize().unwrap()).unwrap();
        assert_eq!(
            v2_fields(&v2),
            v0_fields(&vector.psbt),
            "{}",
            vector.comment
        );
        assert_eq!(
            v2.into_bitcoin_psbt().unwrap(),
            vector.psbt,
            "{}",
            vector.comment
        );
    }
}

#[test]
fn bip373_invalid_vectors_rejected() {
    let vectors = vectors("invalid");
    assert_eq!(vectors.len(), 10);
    let input = |index: usize| &vectors[index].psbt.inputs[0];
    let output = |index: usize| &vectors[index].psbt.outputs[0];

    assert_eq!(
        musig_input_participants_all(input(0)),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        musig_input_participants_all(input(1)),
        Err(Error::InvalidValue)
    );
    assert_eq!(musig_output_participants(output(2)), Err(Error::InvalidKey));
    // The BIP text gives this "x-only output participant" case the same bytes as
    // the "x-only aggregate in output participants keydata" one above.
    assert_eq!(vectors[3].psbt, vectors[2].psbt);
    assert_eq!(musig_output_participants(output(3)), Err(Error::InvalidKey));
    assert_eq!(musig_input_pub_nonces(input(4)), Err(Error::InvalidKey));
    assert_eq!(musig_input_pub_nonces(input(5)), Err(Error::InvalidKey));
    assert_eq!(musig_input_pub_nonces(input(6)), Err(Error::InvalidValue));
    assert_eq!(musig_input_partial_sigs(input(7)), Err(Error::InvalidKey));
    assert_eq!(musig_input_partial_sigs(input(8)), Err(Error::InvalidKey));
    assert_eq!(musig_input_partial_sigs(input(9)), Err(Error::InvalidValue));
}

#[test]
fn bip373_aggregate_slot_is_signed_key() {
    // Key path: the nonces and shares name the taproot output key, with no leaf
    // hash, while the participant list stays under the untweaked aggregate.
    for case in [
        "Spend of a Taproot output where the output key is a MuSig2 Aggregate Pubkey",
        "Spend of a Taproot output where the internal key is a MuSig2 Aggregate Pubkey",
        "Spend of a Taproot output where the internal key is derived from a MuSig2 Aggregate Pubkey",
    ] {
        for sub in ["With all pubnonces", "With all partial signatures"] {
            let comment = format!("{case} / {sub}");
            let psbt = vector("valid", &comment);
            let input = &psbt.inputs[0];
            let fields = input_fields(input);
            assert_eq!(fields.participants, vec![expected_participants()]);
            let signed_for = signed_for(&fields);
            assert!(!signed_for.is_empty(), "{comment}");
            for (aggregate, leaf_hash) in signed_for {
                assert_eq!(
                    aggregate.x_only_public_key().0.serialize(),
                    output_key(input),
                    "{comment}"
                );
                assert_eq!(leaf_hash, None, "{comment}");
            }
        }
    }

    // Script path: the key as it appears in the leaf, with the leaf hash.
    for sub in ["With all pubnonces", "With all partial signatures"] {
        let comment = format!(
            "Spend of a Taproot output where a key in a script is a MuSig2 Aggregate Pubkey / {sub}"
        );
        let psbt = vector("valid", &comment);
        let input = &psbt.inputs[0];
        let merkle_root = input.tap_merkle_root.unwrap().to_byte_array();
        assert_eq!(hex::encode(merkle_root), ONE_LEAF_MERKLE_ROOT);
        let signed_for = signed_for(&input_fields(input));
        assert!(!signed_for.is_empty(), "{comment}");
        for (aggregate, leaf_hash) in signed_for {
            assert_eq!(aggregate, public_key(AGGREGATE), "{comment}");
            assert_eq!(
                leaf_hash.map(|hash| hash.to_byte_array()),
                Some(merkle_root),
                "{comment}"
            );
        }
    }
}
