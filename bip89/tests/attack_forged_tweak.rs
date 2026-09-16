//! The forged change tweak attack against plain BIP89 verification: a
//! compromised coordinator sends genuine tweaks for the inputs and scalars of
//! its own choosing for the change output, unspendable and unfindable by any
//! scan. The tweak accumulator refuses it, while still accepting a genuine
//! bundle of another derivation index.

mod common;

use bwk_bip89::{
    accumulator::{
        branch_hash, leaf_hash,
        record::{build_tree, root_message, template_id, RootPolicy, RootRecord, RootSignature},
        root_hash,
        tree::{verify_proof, Proof, Tree, HEIGHT},
    },
    bundle::derive_bundle,
    coordinator::prepare,
    delegator::{register, verify_spend, Registration},
    rust_bitcoin::{
        miniscript::bitcoin::{Psbt, ScriptBuf},
        RustBitcoin, PREFIX, SUBTYPE_PROOF,
    },
    verify::{change_output_verification, tweaked_keys},
    BitcoinBackend, Bundle, Entry, Error,
};
use common::{signed_roots, spend_psbt, standard_lists, wallet, Wallet};

struct Setup {
    c: RustBitcoin,
    w: Wallet,
    tree1: Tree,
    psbt: Psbt,
    reg: Registration<RustBitcoin>,
}

fn honest() -> Setup {
    let c = RustBitcoin::new();
    let w = wallet();

    let tree1 = build_tree(&c, &w.descriptor, 1, 0).unwrap();
    let trees = [build_tree(&c, &w.descriptor, 0, 0).unwrap(), tree1.clone()];
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
    assert_eq!(verify_spend(&c, &reg, &psbt), Ok(31_000));

    Setup {
        c,
        w,
        tree1,
        psbt,
        reg,
    }
}

/// A bundle with the three lowest sorted base keys tweaked to attacker-chosen
/// scalars, and the highest keeping the genuine (1, 3) tweak, plus the script
/// it forges. Never the output of `ComputeBIP32Tweak` for any index.
fn forged_change(c: &RustBitcoin, w: &Wallet) -> (Bundle, Vec<u8>) {
    let template = &w.template;
    let base = c.template_base_keys(template);
    let genuine = derive_bundle(c, &w.descriptor, 1, 3).unwrap();

    let entries = vec![
        Entry {
            key: base[0],
            tweak: [0x41; 32],
        },
        Entry {
            key: base[1],
            tweak: [0x42; 32],
        },
        Entry {
            key: base[2],
            tweak: [0x43; 32],
        },
        Entry {
            key: base[3],
            tweak: genuine.tweak(&base[3]).unwrap(),
        },
    ];
    let forged = Bundle::new(entries).unwrap();
    let forged_script = c
        .template_script_pubkey(template, &tweaked_keys(c, &base, &forged).unwrap())
        .unwrap();

    let genuine_script = c
        .template_script_pubkey(template, &tweaked_keys(c, &base, &genuine).unwrap())
        .unwrap();
    assert_ne!(forged_script, genuine_script);

    (forged, forged_script)
}

/// Installs `script` and `bundle` on `output`: the subtype 0x00 entries are
/// keyed by base key, so writing `bundle` overwrites the genuine entries.
fn install(c: &RustBitcoin, psbt: &mut Psbt, output: usize, script: Vec<u8>, bundle: &Bundle) {
    psbt.unsigned_tx.output[output].script_pubkey = ScriptBuf::from_bytes(script);
    c.set_output_bundle(psbt, output, bundle).unwrap();
    assert_eq!(c.output_bundle(psbt, output), Ok(Some(bundle.clone())));
}

#[test]
fn forged_change_passes_plain_bip89_but_is_refused() {
    let mut s = honest();
    let (forged, forged_script) = forged_change(&s.c, &s.w);
    install(&s.c, &mut s.psbt, 1, forged_script.clone(), &forged);

    assert_eq!(
        change_output_verification(&s.c, &s.w.template, &forged_script, &forged),
        Ok(true)
    );

    let proof = s.tree1.proof(1, 4).unwrap();
    s.c.set_output_proof(&mut s.psbt, 1, &proof).unwrap();
    assert_eq!(s.c.output_proof(&s.psbt, 1), Ok(Some(proof)));

    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::NotCommitted)
    );

    let mut clone = s.psbt.clone();
    clone.outputs[1]
        .proprietary
        .retain(|key, _| !(key.prefix == PREFIX && key.subtype == SUBTYPE_PROOF));
    assert_eq!(s.c.output_proof(&clone, 1), Ok(None));
    assert_eq!(
        verify_spend(&s.c, &s.reg, &clone),
        Err(Error::MissingProof(1))
    );
}

#[test]
fn forged_change_with_self_made_tree_is_refused() {
    let mut s = honest();
    let (forged, forged_script) = forged_change(&s.c, &s.w);
    install(&s.c, &mut s.psbt, 1, forged_script, &forged);

    let nonce = [0x44; 32];
    let siblings = [[0x45; 32]; HEIGHT];
    let mut node = leaf_hash(&s.c, &forged, &nonce);
    for sibling in &siblings {
        node = branch_hash(&s.c, &node, sibling);
    }
    let root = root_hash(&s.c, &node);
    let proof = Proof {
        nonce,
        position: 0,
        siblings,
    };
    assert!(verify_proof(&s.c, &forged, &proof, &root));

    let attacker_secret = [0x46; 32];
    let tid = template_id(&s.c, &s.c.template_bytes(&s.w.template));
    let message = root_message(&s.c, &tid, &root);
    let record = RootRecord {
        keychain: 1,
        tree_start: 0,
        root,
        signature: Some(RootSignature {
            key: s.c.base_mul(&attacker_secret).unwrap(),
            branch_tweak: [0u8; 32],
            signature: s.c.bip322_sign(&attacker_secret, &message).unwrap(),
        }),
    };
    assert_eq!(s.reg.record_root(&s.c, &record), Err(Error::NotParticipant));

    s.c.set_output_proof(&mut s.psbt, 1, &proof).unwrap();
    assert_eq!(s.c.output_proof(&s.psbt, 1), Ok(Some(proof)));

    assert_eq!(
        verify_spend(&s.c, &s.reg, &s.psbt),
        Err(Error::NotCommitted)
    );
}

#[test]
fn genuine_bundle_of_other_index_is_accepted_and_recoverable() {
    let mut s = honest();
    let template = &s.w.template;
    let base = s.c.template_base_keys(template);
    let bundle = derive_bundle(&s.c, &s.w.descriptor, 1, 7).unwrap();
    let script =
        s.c.template_script_pubkey(template, &tweaked_keys(&s.c, &base, &bundle).unwrap())
            .unwrap();
    install(&s.c, &mut s.psbt, 1, script, &bundle);

    let proof = s.tree1.proof(1, 7).unwrap();
    s.c.set_output_proof(&mut s.psbt, 1, &proof).unwrap();

    assert_eq!(verify_spend(&s.c, &s.reg, &s.psbt), Ok(31_000));

    let target = s.psbt.unsigned_tx.output[1].script_pubkey.clone();
    let mut found = None;
    'scan: for keychain in 0..2u32 {
        for index in 0..16u32 {
            let candidate = derive_bundle(&s.c, &s.w.descriptor, keychain, index).unwrap();
            let candidate_script = s
                .c
                .template_script_pubkey(template, &tweaked_keys(&s.c, &base, &candidate).unwrap())
                .unwrap();
            if ScriptBuf::from_bytes(candidate_script) == target {
                found = Some((keychain, index));
                break 'scan;
            }
        }
    }
    assert_eq!(found, Some((1, 7)));
}
