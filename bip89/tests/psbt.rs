mod common;

use bwk_bip89::{
    accumulator::tree::Proof,
    bundle::derive_bundle,
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                hashes::Hash,
                psbt::{raw::ProprietaryKey, Input, Output as PsbtOutput},
                sighash::{Prevouts, SighashCache},
                taproot::LeafVersion,
                TapLeafHash, TapSighashType, TxIn, TxOut, XOnlyPublicKey,
            },
            Descriptor as MsDescriptor,
        },
        RustBitcoin, SUBTYPE_PROOF, SUBTYPE_TWEAK,
    },
    BitcoinBackend, Error, Output,
};
use common::{field_key, hex_arr, hex_vec, DELEGATOR_KEY, OWNER2_KEY};

const EXTERNAL_SCRIPT: &str =
    "51203d5b271037bf8ac843db767c6cf7fe4acc341bf053b51e0a4f88515e3ce34190";
const SPK_0_5: &str = "51203e6b0f1e356824c411053f149a99075345130b773ab48a69b8a2b0392decdb7c";
const SPK_1_3: &str = "5120b7c91c73fa1b1b90f7b9f789b22265985a4ed894e32338d43b9cdbaa2896cbb6";
const SPK_0_9: &str = "512098577771c1f38d766d15f37f28832e7781e1162b9fdbe23aa012ccd287bc5128";
const LEAF_0_5: &str = "207c17af83390bb0de2146733fe837d30cd68b4c16a22f75edbc2b2fe8a580ee";
const SIGHASH_0_5: &str = "46d0f22f045bb6ef0ab388edbd95d8cb8a9a4dd23f6e6262d0890bd5e0607a16";
const OWNER2_TWEAK_0_5: &str = "de40653e76c28b3920faeeb3022343cdf479803740ed8ae92f83a49af603c45c";

fn xbytes(compressed: &str) -> [u8; 32] {
    let key = hex_arr::<33>(compressed);
    let mut xonly = [0u8; 32];
    xonly.copy_from_slice(&key[1..]);
    xonly
}

fn output(script: &str, value: u64) -> Output {
    Output {
        script_pubkey: hex_vec(script),
        value,
    }
}

#[test]
fn builder_shape() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let psbt = common::spend_psbt(&w);

    assert_eq!(c.input_count(&psbt), 1);
    assert_eq!(c.output_count(&psbt), 3);

    assert_eq!(
        c.spent_output(&psbt, 0),
        Ok(output(SPK_0_5, common::INPUT_VALUE))
    );
    assert_eq!(
        c.output(&psbt, 0),
        Ok(output(EXTERNAL_SCRIPT, common::EXTERNAL_VALUE))
    );
    assert_eq!(
        c.output(&psbt, 1),
        Ok(output(SPK_1_3, common::CHANGE_VALUE))
    );
    assert_eq!(
        c.output(&psbt, 2),
        Ok(output(SPK_0_9, common::SELF_SEND_VALUE))
    );

    assert_eq!(
        common::INPUT_VALUE
            - common::EXTERNAL_VALUE
            - common::CHANGE_VALUE
            - common::SELF_SEND_VALUE,
        common::FEE
    );

    assert_eq!(c.output(&psbt, 3), Err(Error::Psbt));
    assert_eq!(c.spent_output(&psbt, 1), Err(Error::Psbt));
}

#[test]
fn bundle_roundtrip_on_input_and_output() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);

    let input_bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    c.set_input_bundle(&mut psbt, 0, &input_bundle).unwrap();
    assert_eq!(c.input_bundle(&psbt, 0), Ok(Some(input_bundle.clone())));
    assert_eq!(psbt.inputs[0].proprietary.len(), 4);

    let output_bundle = derive_bundle(&c, &w.descriptor, 1, 3).unwrap();
    c.set_output_bundle(&mut psbt, 1, &output_bundle).unwrap();
    assert_eq!(c.output_bundle(&psbt, 1), Ok(Some(output_bundle.clone())));
    assert_eq!(psbt.outputs[1].proprietary.len(), 4);

    c.set_input_bundle(&mut psbt, 0, &input_bundle).unwrap();
    assert_eq!(psbt.inputs[0].proprietary.len(), 4);

    assert_eq!(
        c.set_output_bundle(&mut psbt, 3, &output_bundle),
        Err(Error::Psbt)
    );
}

#[test]
fn proof_roundtrip() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);

    let proof = Proof {
        nonce: [0x03; 32],
        position: 7,
        siblings: [[0x04; 32]; 8],
    };
    c.set_output_proof(&mut psbt, 2, &proof).unwrap();
    assert_eq!(c.output_proof(&psbt, 2), Ok(Some(proof)));

    assert_eq!(psbt.outputs[2].proprietary.len(), 1);
    let (key, value) = psbt.outputs[2].proprietary.iter().next().unwrap();
    assert!(key.key.is_empty());
    assert_eq!(value.len(), 289);
}

#[test]
fn wrong_lengths_rejected() {
    let c = RustBitcoin::new();
    let w = common::wallet();

    let mut psbt = common::spend_psbt(&w);
    psbt.inputs[0]
        .proprietary
        .insert(field_key(SUBTYPE_TWEAK, vec![0x02; 32]), vec![0; 32]);
    assert_eq!(c.input_bundle(&psbt, 0), Err(Error::EntryLength));

    let mut psbt = common::spend_psbt(&w);
    psbt.outputs[1]
        .proprietary
        .insert(field_key(SUBTYPE_TWEAK, vec![0x02; 33]), vec![0; 31]);
    assert_eq!(c.output_bundle(&psbt, 1), Err(Error::EntryLength));

    let mut psbt = common::spend_psbt(&w);
    psbt.outputs[2]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, Vec::new()), vec![0; 288]);
    assert_eq!(c.output_proof(&psbt, 2), Err(Error::ProofLength));
}

#[test]
fn two_proofs_rejected() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let valid_value = vec![0u8; 289];

    let mut psbt = common::spend_psbt(&w);
    psbt.outputs[2]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, Vec::new()), valid_value.clone());
    psbt.outputs[2]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, vec![0x01]), valid_value.clone());
    assert_eq!(c.output_proof(&psbt, 2), Err(Error::ProofLength));

    let mut psbt = common::spend_psbt(&w);
    psbt.outputs[2]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, vec![0x01]), valid_value);
    assert_eq!(c.output_proof(&psbt, 2), Err(Error::ProofLength));
}

#[test]
fn no_entries_gives_none() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);

    assert_eq!(c.input_bundle(&psbt, 0), Ok(None));
    assert_eq!(c.output_bundle(&psbt, 0), Ok(None));
    assert_eq!(c.output_proof(&psbt, 1), Ok(None));

    psbt.inputs[0].proprietary.insert(
        ProprietaryKey {
            prefix: b"OTHER".to_vec(),
            subtype: SUBTYPE_TWEAK,
            key: vec![0x02; 33],
        },
        vec![0; 32],
    );
    assert_eq!(c.input_bundle(&psbt, 0), Ok(None));

    psbt.outputs[1]
        .proprietary
        .insert(field_key(2, Vec::new()), vec![0; 32]);
    assert_eq!(c.output_bundle(&psbt, 1), Ok(None));
}

#[test]
fn raw_proprietary_key_bytes() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);

    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    c.set_input_bundle(&mut psbt, 0, &bundle).unwrap();

    let (key, value) = psbt.inputs[0].proprietary.iter().next().unwrap();
    let raw = key.to_key();
    let mut bytes = vec![raw.type_value];
    bytes.extend_from_slice(&raw.key);
    let expected = [
        hex_vec("fc06424950585858"),
        hex_vec("00"),
        hex_vec(OWNER2_KEY),
    ]
    .concat();
    assert_eq!(bytes, expected);
    assert_eq!(*value, hex_vec(OWNER2_TWEAK_0_5));
}

#[test]
fn tap_leaf_sighash_matches_sighash_cache() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let psbt = common::spend_psbt(&w);
    let leaf = hex_arr::<32>(LEAF_0_5);

    let expected = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[psbt.inputs[0].witness_utxo.clone().unwrap()]),
            TapLeafHash::from_byte_array(leaf),
            TapSighashType::Default,
        )
        .unwrap()
        .to_byte_array();
    assert_eq!(c.tap_leaf_sighash(&psbt, 0, &leaf), Ok(expected));
    assert_eq!(expected, hex_arr::<32>(SIGHASH_0_5));

    let single = w.descriptor.clone().into_single_descriptors().unwrap();
    let derived = single[0]
        .at_derivation_index(5)
        .unwrap()
        .derived_descriptor(&w.secp)
        .unwrap();
    let MsDescriptor::Tr(tr) = derived else {
        panic!("expected a tr descriptor");
    };
    let (_, only_leaf) = tr.iter_scripts().next().unwrap();
    assert_eq!(
        TapLeafHash::from_script(&only_leaf.encode(), LeafVersion::TapScript).to_byte_array(),
        leaf
    );

    assert_eq!(c.tap_leaf_sighash(&psbt, 1, &leaf), Err(Error::Psbt));
}

#[test]
fn add_tap_script_sig_lands_in_tap_script_sigs() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    let leaf = hex_arr::<32>(LEAF_0_5);
    let xonly = xbytes(DELEGATOR_KEY);

    assert_eq!(
        c.add_tap_script_sig(&mut psbt, 0, &xonly, &leaf, &[0x05; 64]),
        Ok(())
    );

    assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 1);
    let key = (
        XOnlyPublicKey::from_slice(&xonly).unwrap(),
        TapLeafHash::from_byte_array(leaf),
    );
    let sig = psbt.inputs[0].tap_script_sigs.get(&key).unwrap();
    assert_eq!(sig.signature.serialize(), [0x05; 64]);
    assert_eq!(sig.sighash_type, TapSighashType::Default);

    assert_eq!(
        c.add_tap_script_sig(&mut psbt, 0, &[0xff; 32], &leaf, &[0x05; 64]),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        c.add_tap_script_sig(&mut psbt, 1, &xonly, &leaf, &[0x05; 64]),
        Err(Error::Psbt)
    );
}

#[test]
fn missing_witness_utxo() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    psbt.inputs[0].witness_utxo = None;

    assert_eq!(c.spent_output(&psbt, 0), Err(Error::MissingUtxo(0)));
    let leaf = hex_arr::<32>(LEAF_0_5);
    assert_eq!(
        c.tap_leaf_sighash(&psbt, 0, &leaf),
        Err(Error::MissingUtxo(0))
    );
}

#[test]
fn tx_input_without_map_refused() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    psbt.unsigned_tx.input.push(TxIn::default());
    let leaf = hex_arr::<32>(LEAF_0_5);
    let xonly = xbytes(DELEGATOR_KEY);
    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();

    assert_eq!(c.input_count(&psbt), 2);
    assert_eq!(c.spent_output(&psbt, 1), Err(Error::Psbt));
    assert_eq!(c.input_bundle(&psbt, 1), Ok(None));
    assert_eq!(c.set_input_bundle(&mut psbt, 1, &bundle), Err(Error::Psbt));
    assert_eq!(
        c.add_tap_script_sig(&mut psbt, 1, &xonly, &leaf, &[0x05; 64]),
        Err(Error::Psbt)
    );
    assert_eq!(c.tap_leaf_sighash(&psbt, 0, &leaf), Err(Error::Psbt));
}

#[test]
fn input_map_without_tx_input_ignored() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    let mut extra = Input {
        witness_utxo: psbt.inputs[0].witness_utxo.clone(),
        ..Default::default()
    };
    extra
        .proprietary
        .insert(field_key(SUBTYPE_TWEAK, vec![0x02; 33]), vec![0; 32]);
    psbt.inputs.push(extra);

    assert_eq!(c.input_count(&psbt), 1);
    assert_eq!(c.spent_output(&psbt, 1), Err(Error::Psbt));
    assert_eq!(c.input_bundle(&psbt, 1), Ok(None));
    assert_eq!(c.set_input_bundle(&mut psbt, 1, &bundle), Err(Error::Psbt));
    assert_eq!(
        c.tap_leaf_sighash(&psbt, 0, &hex_arr(LEAF_0_5)),
        Ok(hex_arr(SIGHASH_0_5))
    );
}

#[test]
fn tx_output_without_map_outflow() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    psbt.unsigned_tx.output.push(TxOut::NULL);
    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();

    assert_eq!(c.output_count(&psbt), 4);
    assert_eq!(
        c.output(&psbt, 3),
        Ok(Output {
            script_pubkey: vec![],
            value: u64::MAX
        })
    );
    assert_eq!(c.output_bundle(&psbt, 3), Ok(None));
    assert_eq!(c.output_proof(&psbt, 3), Ok(None));
    assert_eq!(c.set_output_bundle(&mut psbt, 3, &bundle), Err(Error::Psbt));
}

#[test]
fn output_map_without_tx_output_ignored() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let mut psbt = common::spend_psbt(&w);
    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    psbt.outputs.push(PsbtOutput::default());

    assert_eq!(c.output_count(&psbt), 3);
    assert_eq!(c.output(&psbt, 3), Err(Error::Psbt));
    assert_eq!(c.output_bundle(&psbt, 3), Ok(None));
    assert_eq!(c.set_output_bundle(&mut psbt, 3, &bundle), Err(Error::Psbt));
}
