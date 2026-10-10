mod common;

use bwk_bip89::{
    accumulator::{record::build_tree, tree::verify_proof},
    bundle::derive_bundle,
    coordinator::{prepare, Owned},
    rust_bitcoin::RustBitcoin,
    BitcoinBackend, Error,
};
use common::{hex_arr, standard_lists, wallet};

const ROOT_0_0: &str = "5cac3809f3f1f1453bec2970a05f06898ecc5e20d43b800f6ce2528d9059b504";
const ROOT_1_0: &str = "6692aa17194acaf0924373a301d4b18bc5f6b85791dc6504ba8f3dfc98591be9";

#[test]
fn prepare_writes_bundles_and_proofs() {
    let c = RustBitcoin::new();
    let w = wallet();
    let mut psbt = common::spend_psbt(&w);
    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (inputs, outputs) = standard_lists();

    assert_eq!(
        prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt),
        Ok(())
    );

    assert_eq!(
        c.input_bundle(&psbt, 0),
        Ok(Some(derive_bundle(&c, &w.descriptor, 0, 5).unwrap()))
    );
    assert_eq!(
        c.output_bundle(&psbt, 1),
        Ok(Some(derive_bundle(&c, &w.descriptor, 1, 3).unwrap()))
    );
    assert_eq!(
        c.output_bundle(&psbt, 2),
        Ok(Some(derive_bundle(&c, &w.descriptor, 0, 9).unwrap()))
    );

    let p1 = c.output_proof(&psbt, 1).unwrap().unwrap();
    assert_eq!(p1.position, 85);
    assert!(verify_proof(
        &c,
        &derive_bundle(&c, &w.descriptor, 1, 3).unwrap(),
        &p1,
        &hex_arr::<32>(ROOT_1_0)
    ));

    let p2 = c.output_proof(&psbt, 2).unwrap().unwrap();
    assert_eq!(p2.position, 37);
    assert!(verify_proof(
        &c,
        &derive_bundle(&c, &w.descriptor, 0, 9).unwrap(),
        &p2,
        &hex_arr::<32>(ROOT_0_0)
    ));

    assert_eq!(psbt.inputs[0].proprietary.len(), 4);
    assert_eq!(psbt.outputs[1].proprietary.len(), 5);
    assert_eq!(psbt.outputs[2].proprietary.len(), 5);
}

#[test]
fn external_output_gets_nothing() {
    let c = RustBitcoin::new();
    let w = wallet();
    let mut psbt = common::spend_psbt(&w);
    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (inputs, outputs) = standard_lists();

    assert_eq!(
        prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt),
        Ok(())
    );

    assert!(psbt.outputs[0].proprietary.is_empty());
    assert_eq!(c.output_bundle(&psbt, 0), Ok(None));
    assert_eq!(c.output_proof(&psbt, 0), Ok(None));
}

#[test]
fn no_tree_for_output_index_errors() {
    let c = RustBitcoin::new();
    let w = wallet();
    let (inputs, outputs) = standard_lists();

    let mut psbt = common::spend_psbt(&w);
    let trees = [build_tree(&c, &w.descriptor, 0, 0).unwrap()];
    assert_eq!(
        prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt),
        Err(Error::NoTree(1))
    );
    assert!(psbt.inputs[0].proprietary.is_empty());
    for output in 0..psbt.outputs.len() {
        assert!(psbt.outputs[output].proprietary.is_empty());
    }

    let mut psbt = common::spend_psbt(&w);
    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let out_of_window = [Owned {
        psbt_index: 2,
        keychain: 0,
        index: 300,
    }];
    assert_eq!(
        prepare(
            &c,
            &w.descriptor,
            &trees,
            &inputs,
            &out_of_window,
            &mut psbt
        ),
        Err(Error::NoTree(2))
    );
    assert!(psbt.inputs[0].proprietary.is_empty());
    for output in 0..psbt.outputs.len() {
        assert!(psbt.outputs[output].proprietary.is_empty());
    }

    let mut psbt = common::spend_psbt(&w);
    let bad_keychain_inputs = [Owned {
        psbt_index: 0,
        keychain: 2,
        index: 5,
    }];
    assert_eq!(
        prepare(
            &c,
            &w.descriptor,
            &trees,
            &bad_keychain_inputs,
            &outputs,
            &mut psbt
        ),
        Err(Error::InvalidKeychain)
    );
    assert!(psbt.inputs[0].proprietary.is_empty());
    for output in 0..psbt.outputs.len() {
        assert!(psbt.outputs[output].proprietary.is_empty());
    }

    let mut psbt = common::spend_psbt(&w);
    let out_of_range_output = [Owned {
        psbt_index: 3,
        keychain: 0,
        index: 9,
    }];
    assert_eq!(
        prepare(
            &c,
            &w.descriptor,
            &trees,
            &inputs,
            &out_of_range_output,
            &mut psbt
        ),
        Err(Error::Psbt)
    );
    assert!(psbt.inputs[0].proprietary.is_empty());
    for output in 0..psbt.outputs.len() {
        assert!(psbt.outputs[output].proprietary.is_empty());
    }

    let mut psbt = common::spend_psbt(&w);
    let out_of_range_input = [Owned {
        psbt_index: 1,
        keychain: 0,
        index: 5,
    }];
    assert_eq!(
        prepare(
            &c,
            &w.descriptor,
            &trees,
            &out_of_range_input,
            &outputs,
            &mut psbt
        ),
        Err(Error::Psbt)
    );
    assert!(psbt.inputs[0].proprietary.is_empty());
    for output in 0..psbt.outputs.len() {
        assert!(psbt.outputs[output].proprietary.is_empty());
    }
}

#[test]
fn no_derivation_or_origin_fields_added() {
    let c = RustBitcoin::new();
    let w = wallet();
    let mut psbt = common::spend_psbt(&w);
    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (inputs, outputs) = standard_lists();

    assert_eq!(
        prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt),
        Ok(())
    );

    assert!(psbt.inputs[0].bip32_derivation.is_empty());
    assert!(psbt.inputs[0].tap_key_origins.is_empty());
    assert!(psbt.inputs[0].tap_scripts.is_empty());
    assert_eq!(psbt.inputs[0].tap_internal_key, None);
    assert_eq!(psbt.inputs[0].tap_merkle_root, None);

    for output in &psbt.outputs {
        assert!(output.bip32_derivation.is_empty());
        assert!(output.tap_key_origins.is_empty());
        assert_eq!(output.tap_internal_key, None);
    }
}
