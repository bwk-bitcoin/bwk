mod common;

use bwk_bip89::{
    accumulator::{
        record::{build_tree, sign_tree_root, tree_root, RootPolicy, RootRecord, RootSignature},
        tree::Proof,
    },
    bundle::derive_bundle,
    coordinator::prepare,
    delegator::{register, sign_spend, verify_spend, Registration},
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                self,
                hashes::Hash,
                secp256k1::{Keypair, Message, Scalar, SecretKey},
                sighash::{Prevouts, SighashCache},
                taproot, Amount, Psbt, TapLeafHash, TapSighashType, XOnlyPublicKey,
            },
            psbt::PsbtExt,
            Descriptor as MsDescriptor, DescriptorPublicKey,
        },
        RustBitcoin, SUBTYPE_PROOF, SUBTYPE_TWEAK,
    },
    tweak::tweak_key,
    BitcoinBackend, Error, Xpub,
};
use common::{
    delegate_to_rust_bitcoin, field_key, hex_arr, hex_vec, other_template, root_signature,
    signed_roots, spend_psbt, standard_lists, unsigned_roots, wallet, FixedRng, SortedMulti,
    VectorBackend, Wallet, DELEGATOR_KEY, DELEGATOR_SECRET, EXTERNAL_KEY, EXTERNAL_SECRET,
    OWNER1_KEY, OWNER1_SECRET, OWNER2_SECRET,
};

const LEAF_0_5: &str = "207c17af83390bb0de2146733fe837d30cd68b4c16a22f75edbc2b2fe8a580ee";
const SIGHASH_0_5: &str = "46d0f22f045bb6ef0ab388edbd95d8cb8a9a4dd23f6e6262d0890bd5e0607a16";

struct Setup {
    c: RustBitcoin,
    w: Wallet,
    psbt: Psbt,
    reg: Registration<RustBitcoin>,
}

fn setup() -> Setup {
    let c = RustBitcoin::new();
    let w = wallet();

    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (inputs, outputs) = standard_lists();

    let mut psbt = spend_psbt(&w);
    prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt).unwrap();

    let [receive, change] = signed_roots(&c, &w);
    let reg = register(
        &c,
        w.template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change,
    )
    .unwrap();

    Setup { c, w, psbt, reg }
}

fn tamper_proof(s: &mut Setup, f: impl FnOnce(&mut Proof)) {
    let mut proof = s.c.output_proof(&s.psbt, 1).unwrap().unwrap();
    f(&mut proof);
    s.c.set_output_proof(&mut s.psbt, 1, &proof).unwrap();
}

#[test]
fn honest_outflow_is_external_plus_fee() {
    let s = setup();
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Ok(31_000));
}

#[test]
fn output_without_bundle_counts_as_outflow() {
    let mut s = setup();
    s.psbt.outputs[2].proprietary.clear();
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Ok(50_000));
}

#[test]
fn input_script_mismatch_refused() {
    let mut s = setup();
    s.psbt.inputs[0]
        .proprietary
        .retain(|key, _| key.subtype != SUBTYPE_TWEAK);
    let bundle = derive_bundle(&s.c, &s.w.descriptor, 0, 6).unwrap();
    s.c.set_input_bundle(&mut s.psbt, 0, &bundle).unwrap();
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::InputMismatch(0))
    );
}

#[test]
fn missing_input_bundle_refused() {
    let mut s = setup();
    s.psbt.inputs[0].proprietary.clear();
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::MissingBundle(0))
    );
}

#[test]
fn input_maps_missing_refused() {
    let mut s = setup();
    s.psbt.inputs.clear();
    for output in &mut s.psbt.outputs {
        output
            .proprietary
            .retain(|key, _| key.subtype != SUBTYPE_TWEAK);
    }
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::MissingBundle(0))
    );
}

#[test]
fn missing_witness_utxo_refused() {
    let mut s = setup();
    s.psbt.inputs[0].witness_utxo = None;
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::MissingUtxo(0))
    );
}

#[test]
fn missing_proof_on_bundle_output_refused() {
    let mut s = setup();
    s.psbt.outputs[2]
        .proprietary
        .retain(|key, _| key.subtype != SUBTYPE_PROOF);
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::MissingProof(2))
    );
}

#[test]
fn output_script_mismatch_refused() {
    let mut s = setup();
    s.psbt.outputs[1]
        .proprietary
        .retain(|key, _| key.subtype != SUBTYPE_TWEAK);
    let bundle = derive_bundle(&s.c, &s.w.descriptor, 1, 4).unwrap();
    s.c.set_output_bundle(&mut s.psbt, 1, &bundle).unwrap();
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::OutputMismatch(1))
    );
}

#[test]
fn tampered_sibling_refused() {
    let mut s = setup();
    tamper_proof(&mut s, |p| p.siblings[3][0] ^= 1);
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::NotCommitted)
    );
}

#[test]
fn tampered_position_refused() {
    let mut s = setup();
    tamper_proof(&mut s, |p| p.position ^= 1);
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::NotCommitted)
    );
}

#[test]
fn root_signed_by_other_key_refused() {
    let s = setup();
    let [receive, owner1_change] = signed_roots(&s.c, &s.w);
    let change = sign_tree_root(&s.c, &s.w.descriptor, &OWNER2_SECRET, 1, 0).unwrap();
    let reg = register(
        &s.c,
        s.w.template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change,
    )
    .unwrap();
    assert_eq!(verify_spend(&s.c, &reg, &s.psbt), Ok(31_000));

    let owner1_signed = root_signature(&owner1_change);
    let forged_change = RootRecord {
        signature: Some(RootSignature {
            signature: root_signature(&change).signature,
            ..owner1_signed
        }),
        ..owner1_change
    };
    assert!(matches!(
        register(
            &s.c,
            s.w.template.clone(),
            RootPolicy::RequireSignature,
            &receive,
            &forged_change
        ),
        Err(Error::RootSignature)
    ));
}

#[test]
fn root_for_other_template_refused() {
    let s = setup();
    let [receive, change] = signed_roots(&s.c, &s.w);
    assert!(matches!(
        register(
            &s.c,
            other_template(),
            RootPolicy::RequireSignature,
            &receive,
            &change
        ),
        Err(Error::RootSignature)
    ));
}

#[test]
fn unsigned_roots_follow_the_registered_policy() {
    let s = setup();
    let [receive, change] = unsigned_roots(&s.c, &s.w);
    assert!(matches!(
        register(
            &s.c,
            s.w.template.clone(),
            RootPolicy::RequireSignature,
            &receive,
            &change
        ),
        Err(Error::MissingRootSignature)
    ));

    let reg = register(
        &s.c,
        s.w.template.clone(),
        RootPolicy::AllowUnsigned,
        &receive,
        &change,
    )
    .unwrap();
    assert_eq!(verify_spend(&s.c, &reg, &s.psbt), Ok(31_000));
}

#[test]
fn invalid_signature_refused_when_unsigned_roots_are_allowed() {
    let s = setup();
    let [receive, change] = signed_roots(&s.c, &s.w);
    let mut forged = change;
    // the first byte of the Schnorr signature, after the item count and its length
    forged.signature.as_mut().unwrap().signature[2] ^= 1;
    assert!(matches!(
        register(
            &s.c,
            s.w.template.clone(),
            RootPolicy::AllowUnsigned,
            &receive,
            &forged
        ),
        Err(Error::RootSignature)
    ));
}

#[test]
fn record_root_follows_the_registered_policy() {
    let s = setup();
    let [receive, change] = signed_roots(&s.c, &s.w);
    let next = tree_root(&s.c, &s.w.descriptor, 0, 256).unwrap();

    let mut strict = register(
        &s.c,
        s.w.template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change,
    )
    .unwrap();
    assert_eq!(
        strict.record_root(&s.c, &next),
        Err(Error::MissingRootSignature)
    );

    let mut lax = register(
        &s.c,
        s.w.template.clone(),
        RootPolicy::AllowUnsigned,
        &receive,
        &change,
    )
    .unwrap();
    assert_eq!(lax.record_root(&s.c, &next), Ok(()));
}

#[test]
fn root_recorded_after_registration_accepted() {
    let mut s = setup();
    let trees = [
        build_tree(&s.c, &s.w.descriptor, 0, 0).unwrap(),
        build_tree(&s.c, &s.w.descriptor, 1, 0).unwrap(),
        build_tree(&s.c, &s.w.descriptor, 0, 256).unwrap(),
    ];
    let (inputs, mut outputs) = standard_lists();
    outputs[1].index = 300;
    let mut psbt = spend_psbt(&s.w);
    psbt.unsigned_tx.output[2].script_pubkey = s.w.script_pubkey(0, 300);
    prepare(&s.c, &s.w.descriptor, &trees, &inputs, &outputs, &mut psbt).unwrap();
    assert_eq!(verify_spend(&s.c, &s.reg, &psbt), Err(Error::NotCommitted));

    let next = sign_tree_root(&s.c, &s.w.descriptor, &OWNER1_SECRET, 0, 256).unwrap();
    let mut forged = next.clone();
    forged.root = trees[0].root;
    assert_eq!(s.reg.record_root(&s.c, &forged), Err(Error::RootSignature));
    assert_eq!(verify_spend(&s.c, &s.reg, &psbt), Err(Error::NotCommitted));

    assert_eq!(s.reg.record_root(&s.c, &next), Ok(()));
    assert_eq!(verify_spend(&s.c, &s.reg, &psbt), Ok(31_000));
}

#[test]
fn extra_tweak_entry_refused() {
    let mut s = setup();
    assert_eq!(
        s.c.base_mul(&EXTERNAL_SECRET),
        Some(hex_arr::<33>(EXTERNAL_KEY))
    );
    s.psbt.outputs[1].proprietary.insert(
        field_key(SUBTYPE_TWEAK, hex_vec(EXTERNAL_KEY)),
        vec![0x01; 32],
    );
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Err(Error::ExtraTweak));
}

#[test]
fn missing_tweak_entry_refused() {
    let mut s = setup();
    let delegator_key = hex_vec(DELEGATOR_KEY);
    s.psbt.outputs[1]
        .proprietary
        .retain(|key, _| !(key.subtype == SUBTYPE_TWEAK && key.key == delegator_key));
    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::MissingTweak)
    );
}

#[test]
fn owned_above_inputs_refused() {
    let mut s = setup();
    s.psbt.unsigned_tx.output[1].value = Amount::from_sat(200_000);
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Err(Error::Amount));
}

#[test]
fn owned_sum_overflow_refused() {
    let mut s = setup();
    s.psbt.unsigned_tx.output[1].value = Amount::MAX;
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Err(Error::Amount));
}

#[test]
fn duplicate_proof_on_unowned_output_refused() {
    let mut s = setup();
    let value =
        s.c.output_proof(&s.psbt, 1)
            .unwrap()
            .unwrap()
            .to_bytes()
            .to_vec();
    s.psbt.outputs[0]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, vec![]), value.clone());
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Ok(31_000));
    s.psbt.outputs[0]
        .proprietary
        .insert(field_key(SUBTYPE_PROOF, vec![0x01]), value);
    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Err(Error::ProofLength));
}

/// `RustBitcoin` with a template that has no tapleaf for any key.
struct NoLeaves(RustBitcoin);

impl BitcoinBackend for NoLeaves {
    delegate_to_rust_bitcoin!();

    type Descriptor = MsDescriptor<DescriptorPublicKey>;
    type Template = MsDescriptor<bitcoin::PublicKey>;

    fn descriptor_policy(&self, d: &Self::Descriptor) -> Vec<u8> {
        self.0.descriptor_policy(d)
    }

    fn descriptor_template(&self, d: &Self::Descriptor) -> Result<Vec<u8>, Error> {
        self.0.descriptor_template(d)
    }

    fn descriptor_xpubs(&self, d: &Self::Descriptor) -> Result<Vec<Xpub>, Error> {
        self.0.descriptor_xpubs(d)
    }

    fn template_bytes(&self, t: &Self::Template) -> Vec<u8> {
        self.0.template_bytes(t)
    }

    fn template_base_keys(&self, t: &Self::Template) -> Vec<[u8; 33]> {
        self.0.template_base_keys(t)
    }

    fn template_script_pubkey(
        &self,
        t: &Self::Template,
        tweaked: &[([u8; 33], [u8; 33])],
    ) -> Result<Vec<u8>, Error> {
        self.0.template_script_pubkey(t, tweaked)
    }

    fn template_leaf_hashes(
        &self,
        _t: &Self::Template,
        _tweaked: &[([u8; 33], [u8; 33])],
        _key: &[u8; 33],
    ) -> Result<Vec<[u8; 32]>, Error> {
        Ok(Vec::new())
    }
}

#[test]
fn honest_spend_verifies_and_signs() {
    let mut s = setup();
    let mut rng = FixedRng::new(vec![0x22; 32]);

    let delegator_key = hex_arr::<33>(DELEGATOR_KEY);
    let leaf = hex_arr::<32>(LEAF_0_5);
    let sighash = hex_arr::<32>(SIGHASH_0_5);
    let leaf_hash = TapLeafHash::from_byte_array(leaf);

    let tweak = derive_bundle(&s.c, &s.w.descriptor, 0, 5)
        .unwrap()
        .tweak(&delegator_key)
        .unwrap();
    let tweaked = tweak_key(&s.c, &delegator_key, &tweak).unwrap();
    let xonly = XOnlyPublicKey::from_slice(&tweaked[1..]).unwrap();

    assert_eq!(
        sign_spend(&s.c, &mut rng, &s.reg, &DELEGATOR_SECRET, &mut s.psbt),
        Ok(31_000)
    );

    assert_eq!(s.psbt.inputs[0].tap_script_sigs.len(), 1);
    let sig = s.psbt.inputs[0]
        .tap_script_sigs
        .get(&(xonly, leaf_hash))
        .unwrap();
    assert_eq!(sig.sighash_type, TapSighashType::Default);

    let utxo = s.psbt.inputs[0].witness_utxo.clone().unwrap();
    let direct_sighash = SighashCache::new(&s.psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[utxo]),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    assert_eq!(direct_sighash.to_byte_array(), sighash);

    let msg = Message::from_digest(sighash);
    assert!(s
        .w
        .secp
        .verify_schnorr(&sig.signature, &msg, &xonly)
        .is_ok());

    let definite = s.w.descriptor.clone().into_single_descriptors().unwrap()[0]
        .at_derivation_index(5)
        .unwrap();
    let owner_tweak = derive_bundle(&s.c, &s.w.descriptor, 0, 5)
        .unwrap()
        .tweak(&hex_arr::<33>(OWNER1_KEY))
        .unwrap();
    let owner_secret = SecretKey::from_slice(&OWNER1_SECRET)
        .unwrap()
        .add_tweak(&Scalar::from_be_bytes(owner_tweak).unwrap())
        .unwrap();
    let keypair = Keypair::from_secret_key(&s.w.secp, &owner_secret);
    let owner_sig = s.w.secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    s.psbt.inputs[0].tap_script_sigs.insert(
        (keypair.x_only_public_key().0, leaf_hash),
        taproot::Signature {
            signature: owner_sig,
            sighash_type: TapSighashType::Default,
        },
    );
    s.psbt.update_input_with_descriptor(0, &definite).unwrap();
    s.psbt.finalize_mut(&s.w.secp).unwrap();
    let tx = s.psbt.clone().extract_tx().unwrap();
    assert_eq!(tx.input[0].witness.len(), 5);
    assert_eq!(tx.vsize(), 249);
}

#[test]
fn non_participant_secret_refused() {
    let mut s = setup();

    let mut rng = FixedRng::new(vec![0x22; 32]);
    assert_eq!(
        sign_spend(&s.c, &mut rng, &s.reg, &[0x05; 32], &mut s.psbt),
        Err(Error::NotParticipant)
    );
    assert!(s.psbt.inputs[0].tap_script_sigs.is_empty());

    let mut rng = FixedRng::new(vec![0x22; 32]);
    assert_eq!(
        sign_spend(&s.c, &mut rng, &s.reg, &[0u8; 32], &mut s.psbt),
        Err(Error::SecretKey)
    );
    assert!(s.psbt.inputs[0].tap_script_sigs.is_empty());
}

#[test]
fn verification_failure_writes_no_signature() {
    let mut s = setup();
    tamper_proof(&mut s, |p| p.siblings[0][0] ^= 1);

    let mut rng = FixedRng::new(vec![0x22; 32]);
    assert_eq!(
        sign_spend(&s.c, &mut rng, &s.reg, &DELEGATOR_SECRET, &mut s.psbt),
        Err(Error::NotCommitted)
    );
    assert!(s.psbt.inputs[0].tap_script_sigs.is_empty());

    let mut s = setup();
    s.psbt.inputs[0].proprietary.clear();

    let mut rng = FixedRng::new(vec![0x22; 32]);
    assert_eq!(
        sign_spend(&s.c, &mut rng, &s.reg, &DELEGATOR_SECRET, &mut s.psbt),
        Err(Error::MissingBundle(0))
    );
    assert!(s.psbt.inputs[0].tap_script_sigs.is_empty());
}

#[test]
fn nothing_to_sign_refused() {
    let s = setup();
    let no_leaves = NoLeaves(RustBitcoin::new());
    let [receive, change] = signed_roots(&s.c, &s.w);
    let reg = register(
        &no_leaves,
        s.w.template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change,
    )
    .unwrap();
    assert_eq!(verify_spend(&no_leaves, &reg, &s.psbt), Ok(31_000));

    let mut psbt = s.psbt;
    let mut rng = FixedRng::new(vec![0x22; 32]);
    assert_eq!(
        sign_spend(&no_leaves, &mut rng, &reg, &DELEGATOR_SECRET, &mut psbt),
        Err(Error::NothingToSign(0))
    );
    assert!(psbt.inputs[0].tap_script_sigs.is_empty());
}

#[test]
fn register_rejects_swapped_keychains_and_empty_template() {
    let s = setup();
    let [receive, change] = signed_roots(&s.c, &s.w);
    assert!(matches!(
        register(
            &s.c,
            s.w.template.clone(),
            RootPolicy::RequireSignature,
            &change,
            &receive
        ),
        Err(Error::InvalidKeychain)
    ));
    let empty = SortedMulti {
        threshold: 0,
        keys: Vec::new(),
    };
    assert!(matches!(
        register(
            &VectorBackend::default(),
            empty,
            RootPolicy::RequireSignature,
            &receive,
            &change
        ),
        Err(Error::Template)
    ));
    assert!(register(
        &s.c,
        s.w.template.clone(),
        RootPolicy::RequireSignature,
        &receive,
        &change
    )
    .is_ok());
}
