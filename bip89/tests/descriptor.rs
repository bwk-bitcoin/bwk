mod common;

use std::str::FromStr;

use bwk_bip89::{
    bundle::derive_bundle,
    rust_bitcoin::{
        miniscript::{
            bitcoin::{
                self,
                secp256k1::{All, PublicKey, Secp256k1, SecretKey},
            },
            Descriptor, DescriptorPublicKey,
        },
        RustBitcoin,
    },
    verify::tweaked_keys,
    BitcoinBackend, Error, Xpub,
};
use common::{
    hex_arr, hex_vec, template_of, tpub, DELEGATOR_CHAIN_CODE, DELEGATOR_KEY, DELEGATOR_SECRET,
    EXTERNAL_KEY, NUMS_CHAIN_CODE, NUMS_KEY, OWNER1_CHAIN_CODE, OWNER1_KEY, OWNER1_SECRET,
    OWNER2_CHAIN_CODE, OWNER2_KEY, OWNER2_SECRET, POLICY, TEMPLATE,
};

/// Parses `s` and validates it as a wallet descriptor.
fn xpubs(s: &str) -> Result<Vec<Xpub>, Error> {
    RustBitcoin::new().descriptor_xpubs(&Descriptor::from_str(s).unwrap())
}

fn nums_str() -> String {
    tpub(
        PublicKey::from_slice(&hex_vec(NUMS_KEY)).unwrap(),
        NUMS_CHAIN_CODE,
    )
    .to_string()
}

fn owner1_str(secp: &Secp256k1<All>) -> String {
    tpub(
        SecretKey::from_slice(&OWNER1_SECRET)
            .unwrap()
            .public_key(secp),
        OWNER1_CHAIN_CODE,
    )
    .to_string()
}

fn owner2_str(secp: &Secp256k1<All>) -> String {
    tpub(
        SecretKey::from_slice(&OWNER2_SECRET)
            .unwrap()
            .public_key(secp),
        OWNER2_CHAIN_CODE,
    )
    .to_string()
}

fn delegator_str(secp: &Secp256k1<All>) -> String {
    tpub(
        SecretKey::from_slice(&DELEGATOR_SECRET)
            .unwrap()
            .public_key(secp),
        DELEGATOR_CHAIN_CODE,
    )
    .to_string()
}

#[test]
fn fixture_literals() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let t = &w.template;

    assert_eq!(
        SecretKey::from_slice(&OWNER1_SECRET)
            .unwrap()
            .public_key(&w.secp)
            .serialize(),
        hex_arr::<33>(OWNER1_KEY)
    );
    assert_eq!(
        SecretKey::from_slice(&OWNER2_SECRET)
            .unwrap()
            .public_key(&w.secp)
            .serialize(),
        hex_arr::<33>(OWNER2_KEY)
    );
    assert_eq!(
        SecretKey::from_slice(&DELEGATOR_SECRET)
            .unwrap()
            .public_key(&w.secp)
            .serialize(),
        hex_arr::<33>(DELEGATOR_KEY)
    );

    assert_eq!(c.descriptor_policy(&w.descriptor), POLICY.as_bytes());
    assert_eq!(
        c.descriptor_template(&w.descriptor).unwrap(),
        TEMPLATE.as_bytes()
    );
    assert_eq!(c.template_bytes(t), TEMPLATE.as_bytes());

    assert_eq!(
        Descriptor::<DescriptorPublicKey>::from_str(POLICY).unwrap(),
        w.descriptor
    );
    assert_eq!(
        Descriptor::<bitcoin::PublicKey>::from_str(TEMPLATE).unwrap(),
        *t
    );
}

#[test]
fn xpubs_and_base_keys_are_sorted() {
    let c = RustBitcoin::new();
    let w = common::wallet();

    assert_eq!(
        c.template_base_keys(&w.template),
        vec![
            hex_arr::<33>(OWNER2_KEY),
            hex_arr::<33>(NUMS_KEY),
            hex_arr::<33>(DELEGATOR_KEY),
            hex_arr::<33>(OWNER1_KEY),
        ]
    );

    let xpubs = c.descriptor_xpubs(&w.descriptor).unwrap();
    assert_eq!(xpubs.len(), 4);
    let expected = [
        (OWNER2_KEY, [0x0c; 32]),
        (NUMS_KEY, [0x0e; 32]),
        (DELEGATOR_KEY, [0x0d; 32]),
        (OWNER1_KEY, [0x0b; 32]),
    ];
    for (xpub, (key, chain_code)) in xpubs.iter().zip(expected) {
        assert_eq!(xpub.key, hex_arr::<33>(key));
        assert_eq!(xpub.chain_code, chain_code);
        assert_eq!(xpub.branches, [vec![0], vec![1]]);
    }
}

#[test]
fn template_script_pubkey_matches_miniscript() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let t = &w.template;

    for keychain in [0u32, 1] {
        for index in [0u32, 5, 300] {
            let bundle = derive_bundle(&c, &w.descriptor, keychain, index).unwrap();
            let tweaked = tweaked_keys(&c, &c.template_base_keys(t), &bundle).unwrap();
            assert_eq!(
                c.template_script_pubkey(t, &tweaked).unwrap(),
                w.script_pubkey(keychain as usize, index).to_bytes()
            );
        }
    }

    let literal_cases = [
        (
            0u32,
            5u32,
            "51203e6b0f1e356824c411053f149a99075345130b773ab48a69b8a2b0392decdb7c",
        ),
        (
            1u32,
            3u32,
            "5120b7c91c73fa1b1b90f7b9f789b22265985a4ed894e32338d43b9cdbaa2896cbb6",
        ),
        (
            0u32,
            9u32,
            "512098577771c1f38d766d15f37f28832e7781e1162b9fdbe23aa012ccd287bc5128",
        ),
    ];
    for (keychain, index, expected) in literal_cases {
        let bundle = derive_bundle(&c, &w.descriptor, keychain, index).unwrap();
        let tweaked = tweaked_keys(&c, &c.template_base_keys(t), &bundle).unwrap();
        assert_eq!(
            c.template_script_pubkey(t, &tweaked).unwrap(),
            hex_vec(expected)
        );
    }

    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    let mut tweaked = tweaked_keys(&c, &c.template_base_keys(t), &bundle).unwrap();
    tweaked.retain(|(base, _)| *base != hex_arr::<33>(DELEGATOR_KEY));
    assert_eq!(
        c.template_script_pubkey(t, &tweaked),
        Err(Error::MissingTweak)
    );
}

#[test]
fn leaf_hashes_filter_by_tweaked_key() {
    let c = RustBitcoin::new();
    let w = common::wallet();
    let t = &w.template;

    let bundle = derive_bundle(&c, &w.descriptor, 0, 5).unwrap();
    let tweaked = tweaked_keys(&c, &c.template_base_keys(t), &bundle).unwrap();

    let delegator_tweaked = tweaked
        .iter()
        .find(|(base, _)| *base == hex_arr::<33>(DELEGATOR_KEY))
        .unwrap()
        .1;
    let nums_tweaked = tweaked
        .iter()
        .find(|(base, _)| *base == hex_arr::<33>(NUMS_KEY))
        .unwrap()
        .1;

    assert_eq!(
        c.template_leaf_hashes(t, &tweaked, &delegator_tweaked)
            .unwrap(),
        vec![hex_arr::<32>(
            "207c17af83390bb0de2146733fe837d30cd68b4c16a22f75edbc2b2fe8a580ee"
        )]
    );
    assert_eq!(
        c.template_leaf_hashes(t, &tweaked, &nums_tweaked).unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(
        c.template_leaf_hashes(t, &tweaked, &hex_arr::<33>(DELEGATOR_KEY))
            .unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(
        c.template_leaf_hashes(t, &tweaked, &hex_arr::<33>(EXTERNAL_KEY))
            .unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(
        c.template_leaf_hashes(t, &tweaked, &[0x04; 33]),
        Err(Error::InvalidPoint)
    );
}

#[test]
fn rejects_non_taproot() {
    let c = RustBitcoin::new();
    let secp = Secp256k1::new();
    let o1 = owner1_str(&secp);
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let wsh = format!("wsh(multi(2,{o1}/<0;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*))");
    assert!(matches!(xpubs(&wsh), Err(Error::NotTaproot)));

    let wpkh = format!("wpkh({o1}/<0;1>/*)");
    assert!(matches!(xpubs(&wpkh), Err(Error::NotTaproot)));

    let sh_wsh = format!("sh(wsh(multi(2,{o1}/<0;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*)))");
    assert!(matches!(xpubs(&sh_wsh), Err(Error::NotTaproot)));

    let wpkh_template =
        Descriptor::<bitcoin::PublicKey>::from_str(&format!("wpkh({OWNER1_KEY})")).unwrap();
    assert!(matches!(
        c.template_script_pubkey(&wpkh_template, &[]),
        Err(Error::NotTaproot)
    ));
}

#[test]
fn rejects_single_key() {
    let secp = Secp256k1::new();
    let o1 = owner1_str(&secp);
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let s = format!("tr({NUMS_KEY},multi_a(2,{o1}/<0;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*))");
    assert!(matches!(xpubs(&s), Err(Error::KeyType)));
}

#[test]
fn rejects_non_multipath() {
    let secp = Secp256k1::new();
    let nums = nums_str();
    let o1 = owner1_str(&secp);
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let single_path = format!("tr({nums}/0/*,multi_a(2,{o1}/0/*,{o2}/0/*,{d}/0/*))");
    assert!(matches!(xpubs(&single_path), Err(Error::KeyType)));

    let three_paths =
        format!("tr({nums}/<0;1;2>/*,multi_a(2,{o1}/<0;1;2>/*,{o2}/<0;1;2>/*,{d}/<0;1;2>/*))");
    assert!(matches!(xpubs(&three_paths), Err(Error::Multipath)));
}

#[test]
fn rejects_hardened_step() {
    let secp = Secp256k1::new();
    let nums = nums_str();
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let hardened_fixed = format!(
        "tr({nums}/<0;1>/*,multi_a(2,{}/0h/<0;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*))",
        owner1_str(&secp)
    );
    assert!(matches!(xpubs(&hardened_fixed), Err(Error::HardenedStep)));

    let hardened_multipath = format!(
        "tr({nums}/<0;1>/*,multi_a(2,{}/<0h;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*))",
        owner1_str(&secp)
    );
    assert!(matches!(
        xpubs(&hardened_multipath),
        Err(Error::HardenedStep)
    ));
}

#[test]
fn rejects_hardened_wildcard() {
    let secp = Secp256k1::new();
    let nums = nums_str();
    let o1 = owner1_str(&secp);
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let hardened_wildcard =
        format!("tr({nums}/<0;1>/*h,multi_a(2,{o1}/<0;1>/*h,{o2}/<0;1>/*h,{d}/<0;1>/*h))");
    assert!(matches!(xpubs(&hardened_wildcard), Err(Error::Wildcard)));

    let no_wildcard = format!("tr({nums}/<0;1>,multi_a(2,{o1}/<0;1>,{o2}/<0;1>,{d}/<0;1>))");
    assert!(matches!(xpubs(&no_wildcard), Err(Error::Wildcard)));
}

#[test]
fn rejects_conflicting_key() {
    let secp = Secp256k1::new();
    let nums = nums_str();
    let o1 = owner1_str(&secp);
    let d = delegator_str(&secp);

    let conflicting_chain_code = tpub(
        SecretKey::from_slice(&OWNER1_SECRET)
            .unwrap()
            .public_key(&secp),
        [0x0f; 32],
    )
    .to_string();
    let s = format!(
        "tr({nums}/<0;1>/*,multi_a(2,{o1}/<0;1>/*,{conflicting_chain_code}/<0;1>/*,{d}/<0;1>/*))"
    );
    assert!(matches!(xpubs(&s), Err(Error::ConflictingKey)));

    let s = format!("tr({nums}/<0;1>/*,multi_a(2,{o1}/<0;1>/*,{o1}/7/<0;1>/*,{d}/<0;1>/*))");
    assert!(matches!(xpubs(&s), Err(Error::ConflictingKey)));
}

#[test]
fn identical_key_is_deduplicated() {
    let secp = Secp256k1::new();
    let o1 = owner1_str(&secp);
    let o2 = owner2_str(&secp);
    let d = delegator_str(&secp);

    let s = format!("tr({o1}/<0;1>/*,multi_a(2,{o1}/<0;1>/*,{o2}/<0;1>/*,{d}/<0;1>/*))");
    let c = RustBitcoin::new();
    let descriptor = Descriptor::from_str(&s).unwrap();
    assert_eq!(c.descriptor_xpubs(&descriptor).unwrap().len(), 3);
    assert_eq!(c.template_base_keys(&template_of(&c, &descriptor)).len(), 3);
}
