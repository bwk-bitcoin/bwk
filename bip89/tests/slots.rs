//! Key slots end to end: a key used on two derivation paths, as in a Liana
//! recovery path that reuses a key.

mod common;

use std::str::FromStr;

use bwk_bip89::{
    accumulator::record::{build_tree, RootPolicy},
    bundle::derive_bundle,
    coordinator::prepare,
    delegator::{register, sign_spend, verify_spend},
    rust_bitcoin::{
        miniscript::{
            bitcoin::{hashes::Hash, secp256k1::Message, XOnlyPublicKey},
            Descriptor, DescriptorPublicKey,
        },
        RustBitcoin, PREFIX, SUBTYPE_TWEAK,
    },
    slot::Slot,
    tweak::tweak_key,
    verify::tweaked_keys,
    BitcoinBackend, Bundle, Entry, Error,
};
use common::{
    hex_arr, signed_roots, slot0, spend_psbt, standard_lists, template_of, two_slot_wallet,
    FixedRng, DELEGATOR_KEY, DELEGATOR_SECRET, NUMS_KEY, OWNER1_KEY,
};

/// A descriptor whose key `[e5a19e6c/48'/1'/0'/2']tpubDEJpp...` is used with
/// `/<2;3>/*` in the timelocked path and `/<0;1>/*` in the cosigned path.
const ISSUE_DESCRIPTOR: &str = "tr(tpubD6NzVbkrYhZ4Y3pt5ka92kaSpsJVs5uvuYEC9ysM45ArNCpujUK2VyUKfNyDX7CtQ1u6kokNZdFEFFoUXT8xkskNanvQTK5p6AwTSzBL3y7/<0;1>/*,{and_v(v:pk([e5a19e6c/48'/1'/0'/2']tpubDEJpp1WPRPJ1FsD5S7WuFqjPtw6DHtPvRtSZF1byjc6wF3DZbgjAbH1ycr2r8k46nkjwTkSTqdUHUh8rC1FwRTtZKrDqa5GYxrwtCqxbXH9/<2;3>/*),older(52596)),and_v(v:pk([e5a19e6c/48'/1'/0'/2']tpubDEJpp1WPRPJ1FsD5S7WuFqjPtw6DHtPvRtSZF1byjc6wF3DZbgjAbH1ycr2r8k46nkjwTkSTqdUHUh8rC1FwRTtZKrDqa5GYxrwtCqxbXH9/<0;1>/*),pk([e09a1136/89'/1'/0'/0']tpubDEu9iaqcArJqJa5YYkzowEBka9gxTZaScHrinXpWofkazUNBcQKNGCkUoKm972iq3hND1fTqnBw6zPprUK7cGaZRvaCpQichabUV3Krp4EM/<0;1>/*))})#ufefs3cc";
const ISSUE_TEMPLATE: &str = "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{and_v(v:pk(02702f5f7268e1e7cb2b3090e78d88b86aeefa2ceb901a4521f93801c72a828edf@1),older(52596)),and_v(v:pk(02702f5f7268e1e7cb2b3090e78d88b86aeefa2ceb901a4521f93801c72a828edf),pk(02e294448fc90549c94be7558b836b0bb5e262c2850a14c280e6dbe56e08e4c589))})#sk93u68q";
/// The key on two paths.
const ISSUE_USER_KEY: &str = "02702f5f7268e1e7cb2b3090e78d88b86aeefa2ceb901a4521f93801c72a828edf";
const ISSUE_COSIGNER_KEY: &str =
    "02e294448fc90549c94be7558b836b0bb5e262c2850a14c280e6dbe56e08e4c589";

fn slot(key: &str, number: u8) -> Slot {
    Slot {
        key: hex_arr(key),
        number,
    }
}

#[test]
fn issue_descriptor_is_accepted() {
    let c = RustBitcoin::new();
    let d = Descriptor::<DescriptorPublicKey>::from_str(ISSUE_DESCRIPTOR).unwrap();

    let xpubs = c.descriptor_xpubs(&d).unwrap();
    let keys: Vec<(String, [Vec<u32>; 2])> = xpubs
        .iter()
        .map(|x| (hex::encode(x.key), x.branches.clone()))
        .collect();
    assert_eq!(
        keys,
        vec![
            (NUMS_KEY.to_string(), [vec![0], vec![1]]),
            (ISSUE_USER_KEY.to_string(), [vec![0], vec![1]]),
            (ISSUE_USER_KEY.to_string(), [vec![2], vec![3]]),
            (ISSUE_COSIGNER_KEY.to_string(), [vec![0], vec![1]]),
        ]
    );
    assert_eq!(xpubs[1].chain_code, xpubs[2].chain_code);

    assert_eq!(
        c.descriptor_template(&d).unwrap(),
        ISSUE_TEMPLATE.as_bytes()
    );
    let t = template_of(&c, &d);
    assert_eq!(
        c.template_slots(&t),
        vec![
            slot(NUMS_KEY, 0),
            slot(ISSUE_USER_KEY, 0),
            slot(ISSUE_USER_KEY, 1),
            slot(ISSUE_COSIGNER_KEY, 0),
        ]
    );

    for (keychain, index) in [(0u32, 0u32), (0, 7), (1, 0), (1, 300)] {
        let bundle = derive_bundle(&c, &d, keychain, index).unwrap();
        let slots: Vec<Slot> = bundle.entries().iter().map(|e| e.slot).collect();
        assert_eq!(slots, c.template_slots(&t));
        assert_ne!(bundle.entries()[1].tweak, bundle.entries()[2].tweak);

        let tweaked = tweaked_keys(&c, &c.template_slots(&t), &bundle).unwrap();
        let expected = d.clone().into_single_descriptors().unwrap()[keychain as usize]
            .at_derivation_index(index)
            .unwrap()
            .script_pubkey();
        assert_eq!(
            c.template_script_pubkey(&t, &tweaked).unwrap(),
            expected.to_bytes()
        );
    }
}

#[test]
fn two_slot_spend_signs_once_per_slot() {
    let c = RustBitcoin::new();
    let w = two_slot_wallet();
    let trees = [
        build_tree(&c, &w.descriptor, 0, 0).unwrap(),
        build_tree(&c, &w.descriptor, 1, 0).unwrap(),
    ];
    let (inputs, outputs) = standard_lists();
    let mut psbt = spend_psbt(&w);
    prepare(&c, &w.descriptor, &trees, &inputs, &outputs, &mut psbt).unwrap();

    let input_bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    let mut keydata: Vec<Vec<u8>> = psbt.inputs[0]
        .proprietary
        .keys()
        .filter(|key| key.prefix == PREFIX && key.subtype == SUBTYPE_TWEAK)
        .map(|key| key.key.clone())
        .collect();
    keydata.sort();
    let delegator = hex_arr::<33>(DELEGATOR_KEY);
    let owner1 = hex_arr::<33>(OWNER1_KEY);
    let mut expected = vec![
        hex_arr::<33>(NUMS_KEY).to_vec(),
        delegator.to_vec(),
        [&delegator[..], &[0x01]].concat(),
        owner1.to_vec(),
        [&owner1[..], &[0x01]].concat(),
    ];
    expected.sort();
    assert_eq!(keydata, expected);
    assert_eq!(c.input_bundle(&psbt, 0), Ok(Some(input_bundle.clone())));

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

    let mut rng = FixedRng::new(vec![0x22; 64]);
    assert_eq!(
        sign_spend(&c, &mut rng, &reg, &DELEGATOR_SECRET, &mut psbt),
        Ok(31_000)
    );

    let sigs = &psbt.inputs[0].tap_script_sigs;
    assert_eq!(sigs.len(), 2);
    for number in [0u8, 1] {
        let tweak = input_bundle
            .tweak(&Slot {
                key: delegator,
                number,
            })
            .unwrap();
        let tweaked = tweak_key(&c, &delegator, &tweak).unwrap();
        let xonly = XOnlyPublicKey::from_slice(&tweaked[1..]).unwrap();
        let ((_, leaf), sig) = sigs.iter().find(|((key, _), _)| *key == xonly).unwrap();
        let sighash = c.tap_leaf_sighash(&psbt, 0, &leaf.to_byte_array());
        let msg = Message::from_digest(sighash.unwrap());
        assert!(w.secp.verify_schnorr(&sig.signature, &msg, &xonly).is_ok());
    }
}

#[test]
fn swapped_slot_tweaks_are_refused() {
    let c = RustBitcoin::new();
    let w = two_slot_wallet();
    let genuine = derive_bundle(&c, &w.descriptor, 1, 3).unwrap();
    let owner1 = hex_arr::<33>(OWNER1_KEY);
    let swapped = Bundle::new(
        genuine
            .entries()
            .iter()
            .map(|entry| match entry.slot {
                Slot { key, number } if key == owner1 => Entry {
                    slot: Slot {
                        key,
                        number: 1 - number,
                    },
                    tweak: entry.tweak,
                },
                _ => *entry,
            })
            .collect(),
    )
    .unwrap();
    assert_ne!(swapped, genuine);

    let slots = c.template_slots(&w.template);
    let script = |bundle: &Bundle| {
        c.template_script_pubkey(&w.template, &tweaked_keys(&c, &slots, bundle).unwrap())
            .unwrap()
    };
    assert_eq!(script(&genuine), w.script_pubkey(1, 3).to_bytes());
    assert_ne!(script(&swapped), script(&genuine));

    let mut missing = genuine.entries().to_vec();
    missing.retain(|entry| entry.slot != slot0(owner1));
    let missing = Bundle::new(missing);
    assert_eq!(missing, Err(Error::SlotGap));
}
