mod common;

use std::collections::BTreeMap;

use bwk_bip89::{
    bip340, blind,
    rust_bitcoin::{
        miniscript::bitcoin::{
            hashes::{sha256, Hash},
            secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey},
        },
        RustBitcoin,
    },
    scalar::{point_neg, scalar_neg, scalar_reduce, tagged_hash256, xbytes, N},
    sign, tweak, verify, BitcoinBackend, Bundle, Entry, Error, Sha256Engine,
};
use common::{hex_arr, hex_vec, FixedRng, SortedMulti, VectorBackend};
use serde::{de::DeserializeOwned, Deserialize};

#[derive(Deserialize)]
struct TweakVectors {
    xpub: VectorXpub,
    valid_test_cases: Vec<TweakValid>,
    error_test_cases: Vec<TweakError>,
}

#[derive(Deserialize)]
struct VectorXpub {
    compressed: String,
    chain_code: String,
}

#[derive(Deserialize)]
struct TweakValid {
    comment: String,
    path: Vec<String>,
    expected: TweakExpected,
}

#[derive(Deserialize)]
struct TweakExpected {
    tweak: String,
    derived_xpub: VectorXpub,
}

#[derive(Deserialize)]
struct TweakError {
    comment: String,
    path: Vec<String>,
}

fn load<T: DeserializeOwned>(file: &str) -> T {
    let path = format!("{}/test_vectors/bip89/{file}", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn parse_path(path: &[String]) -> Vec<u32> {
    path.iter().map(|i| i.parse::<u32>().unwrap()).collect()
}

fn xpub_key() -> [u8; 33] {
    hex_arr("0296928602758150d2b4a8a253451b887625b94ab0a91f801f1408cb33b9cf0f83")
}

fn xpub_cc() -> [u8; 32] {
    hex_arr("433cf1154e61c4eb9793488880f8a795a3a72052ad14a7367852542425609640")
}

#[test]
fn compute_bip32_tweak_vectors() {
    let c = RustBitcoin::new();
    let vectors: TweakVectors = load("compute_bip32_tweak_vectors.json");

    assert_eq!(vectors.valid_test_cases.len(), 1);
    assert_eq!(vectors.error_test_cases.len(), 1);

    let key: [u8; 33] = hex_arr(&vectors.xpub.compressed);
    let chain_code: [u8; 32] = hex_arr(&vectors.xpub.chain_code);
    assert_eq!(key, xpub_key());
    assert_eq!(chain_code, xpub_cc());

    for case in &vectors.valid_test_cases {
        let path = parse_path(&case.path);
        let derived = tweak::compute_bip32_tweak(&c, &key, &chain_code, &path).unwrap();

        let expected_tweak: [u8; 32] = hex_arr(&case.expected.tweak);
        let expected_key: [u8; 33] = hex_arr(&case.expected.derived_xpub.compressed);
        let expected_cc: [u8; 32] = hex_arr(&case.expected.derived_xpub.chain_code);

        assert_eq!(derived.tweak, expected_tweak, "{}", case.comment);
        assert_eq!(derived.key, expected_key, "{}", case.comment);
        assert_eq!(derived.chain_code, expected_cc, "{}", case.comment);
    }

    let expected_tweak: [u8; 32] =
        hex_arr("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b");
    let expected_key: [u8; 33] =
        hex_arr("03636eb334a6ffdfc4b975a61dae12f49e7f94461690fa4688632db8eed5601b03");
    let expected_cc: [u8; 32] =
        hex_arr("299bc0ad44ab883a5be9601918badd2720c86c48a6d8b9d17e1ae1c3b0ad975d");
    let derived = tweak::compute_bip32_tweak(&c, &key, &chain_code, &[0, 1]).unwrap();
    assert_eq!(derived.tweak, expected_tweak);
    assert_eq!(derived.key, expected_key);
    assert_eq!(derived.chain_code, expected_cc);

    for case in &vectors.error_test_cases {
        let path = parse_path(&case.path);
        assert_eq!(
            tweak::compute_bip32_tweak(&c, &key, &chain_code, &path),
            Err(Error::HardenedIndex),
            "{}",
            case.comment
        );
    }
}

#[test]
fn compute_bip32_tweak_empty_path() {
    let c = RustBitcoin::new();
    let key = xpub_key();
    let chain_code = xpub_cc();
    let derived = tweak::compute_bip32_tweak(&c, &key, &chain_code, &[]).unwrap();
    assert_eq!(derived.tweak, [0u8; 32]);
    assert_eq!(derived.key, key);
    assert_eq!(derived.chain_code, chain_code);
}

#[test]
fn compute_bip32_tweak_rejects_invalid_key() {
    let c = RustBitcoin::new();
    let key = xpub_key();
    let mut bad_key = [0u8; 33];
    bad_key[0] = 0x04;
    bad_key[1..].copy_from_slice(&key[1..]);
    assert_eq!(
        tweak::compute_bip32_tweak(&c, &bad_key, &xpub_cc(), &[0]),
        Err(Error::InvalidPoint)
    );
}

#[test]
fn tweak_key_matches_derived_key() {
    let c = RustBitcoin::new();
    let key = xpub_key();
    let path_tweak: [u8; 32] =
        hex_arr("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b");
    let expected_key: [u8; 33] =
        hex_arr("03636eb334a6ffdfc4b975a61dae12f49e7f94461690fa4688632db8eed5601b03");
    assert_eq!(
        tweak::tweak_key(&c, &key, &path_tweak).unwrap(),
        expected_key
    );
    assert_eq!(tweak::tweak_key(&c, &key, &[0u8; 32]), Ok(key));
}

#[test]
fn tweak_key_errors() {
    let c = RustBitcoin::new();
    let key = xpub_key();
    let n: [u8; 32] = hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    assert_eq!(tweak::tweak_key(&c, &key, &n), Err(Error::ScalarRange));

    let mut bad_key = [0u8; 33];
    bad_key[0] = 0x04;
    bad_key[1..].copy_from_slice(&key[1..]);
    assert_eq!(
        tweak::tweak_key(&c, &bad_key, &[0u8; 32]),
        Err(Error::InvalidPoint)
    );

    let g: [u8; 33] = hex_arr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let n_minus_1: [u8; 32] =
        hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
    assert_eq!(tweak::tweak_key(&c, &g, &n_minus_1), Err(Error::Infinity));
}

#[test]
fn tweak_secret_matches_derived_key() {
    let c = RustBitcoin::new();
    let secret = delegator_sign_base_secret();
    let key = xpub_key();
    assert_eq!(c.base_mul(&secret), Some(key));

    let cases: [(&[u32], &str); 3] = [
        (
            &[0],
            "02b6a1f923bfe14a9bf1f11927cff0231e7ac9213a864324f3207ad0a44e836bc7",
        ),
        (
            &[1],
            "03e755baa14f139b02c09627e8e0e55abc0650397838233ba983ca78fe067f760d",
        ),
        (
            &[0, 1],
            "03636eb334a6ffdfc4b975a61dae12f49e7f94461690fa4688632db8eed5601b03",
        ),
    ];
    for (path, expected_key) in cases {
        let expected_key: [u8; 33] = hex_arr(expected_key);
        let derived = tweak::compute_bip32_tweak(&c, &key, &xpub_cc(), path).unwrap();
        assert_eq!(derived.key, expected_key);
        let child_secret = tweak::tweak_secret(&c, &secret, &derived.tweak).unwrap();
        assert_eq!(c.base_mul(&child_secret), Some(expected_key));
    }

    assert_eq!(tweak::tweak_secret(&c, &secret, &[0u8; 32]), Ok(secret));
}

#[test]
fn tweak_secret_errors() {
    let c = RustBitcoin::new();
    let secret = delegator_sign_base_secret();
    let n: [u8; 32] = hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

    assert_eq!(
        tweak::tweak_secret(&c, &[0u8; 32], &delegator_sign_tweak()),
        Err(Error::SecretKey)
    );
    assert_eq!(
        tweak::tweak_secret(&c, &n, &delegator_sign_tweak()),
        Err(Error::SecretKey)
    );
    assert_eq!(
        tweak::tweak_secret(&c, &secret, &n),
        Err(Error::ScalarRange)
    );
    assert_eq!(
        tweak::tweak_secret(&c, &secret, &delegator_sign_n_minus_base()),
        Err(Error::SecretKey)
    );
}

#[derive(Deserialize)]
struct VerificationVectors {
    test_cases: Vec<VerificationCase>,
}

#[derive(Deserialize)]
struct VerificationCase {
    comment: String,
    expected: bool,
    #[serde(alias = "tweaks")]
    tweak_map: BTreeMap<String, String>,
    witness_script: String,
}

fn k1() -> [u8; 33] {
    hex_arr("02a047233eec59cf06b9a5ee62d9088eeb8127201423f88637443ff7ee591923c9")
}

fn k2() -> [u8; 33] {
    hex_arr("0386623c88ed79ef5d9aacd24f227a0cd845f5840b861a25118c1200cccd046e0f")
}

fn k3() -> [u8; 33] {
    hex_arr("03c3c01af1d84ec032f7f8d6decd48d74cbbd62253e12691debd064e8b41cb0945")
}

fn sorted_multi_template() -> SortedMulti {
    SortedMulti {
        threshold: 2,
        keys: vec![k1(), k2(), k3()],
    }
}

fn input_bundle_entries() -> Vec<Entry> {
    vec![
        Entry {
            key: k1(),
            tweak: hex_arr("6e4dd29833f7b88751dad6ea6ff536959122f2d07074006657d0e2ef26af3ef6"),
        },
        Entry {
            key: k2(),
            tweak: hex_arr("b30d8530e3464dc71ed6e20897ef5c3c9d1149ecc11f332336520addab1454f3"),
        },
        Entry {
            key: k3(),
            tweak: hex_arr("c1efff9fb89227d09e54b403ae269f1991003e964f66f412e8302f8bb1c71644"),
        },
    ]
}

fn input_witness_script() -> Vec<u8> {
    hex_vec(
        "5221034ebf1d6b674fbf3d7ff09e4bc44b23e17745188b4aac3e2e101bd210cd8f3ed42103a0d8aed25b77\
         d286d7bf7a668b452f18def89f2e2285acd315fc00668fe0a70b2103bd4632ebd0de4573710722bf73b4bb\
         b76713734c4756b830302b8492f29a6aae53ae",
    )
}

/// Decodes a tweak map into bundle entries. Returns `None` on any malformed
/// hex string or wrong-length key or tweak, matching the vector runner rule
/// that a load failure counts as a verification failure.
fn decode_entries(map: &BTreeMap<String, String>) -> Option<Vec<Entry>> {
    map.iter()
        .map(|(key_hex, tweak_hex)| {
            let key: [u8; 33] = hex::decode(key_hex).ok()?.try_into().ok()?;
            let tweak: [u8; 32] = hex::decode(tweak_hex).ok()?.try_into().ok()?;
            Some(Entry { key, tweak })
        })
        .collect()
}

/// Runs one verification vector case through `verify_fn`. A malformed hex
/// entry, a bundle that fails to build, an `Err` result and an `Ok(false)`
/// result all count as `false`.
fn verification_result(
    case: &VerificationCase,
    template: &SortedMulti,
    verify_fn: fn(&VectorBackend, &SortedMulti, &[u8], &Bundle) -> Result<bool, Error>,
) -> bool {
    let c = VectorBackend::default();
    let Some(entries) = decode_entries(&case.tweak_map) else {
        return false;
    };
    let Ok(bundle) = Bundle::new(entries) else {
        return false;
    };
    let script = hex_vec(&case.witness_script);
    matches!(verify_fn(&c, template, &script, &bundle), Ok(true))
}

#[test]
fn input_verification_vectors() {
    let vectors: VerificationVectors = load("input_verification_vectors.json");
    assert_eq!(vectors.test_cases.len(), 4);
    let expected: Vec<bool> = vectors.test_cases.iter().map(|c| c.expected).collect();
    assert_eq!(expected, vec![true, false, false, false]);

    let template = sorted_multi_template();
    for case in &vectors.test_cases {
        let result = verification_result(case, &template, verify::input_verification);
        assert_eq!(result, case.expected, "{}", case.comment);
    }
}

#[test]
fn change_output_verification_vectors() {
    let vectors: VerificationVectors = load("change_output_verification_vectors.json");
    assert_eq!(vectors.test_cases.len(), 4);
    let expected: Vec<bool> = vectors.test_cases.iter().map(|c| c.expected).collect();
    assert_eq!(expected, vec![true, false, false, false]);

    let template = sorted_multi_template();
    for case in &vectors.test_cases {
        let result = verification_result(case, &template, verify::change_output_verification);
        assert_eq!(result, case.expected, "{}", case.comment);
    }
}

#[test]
fn verification_returns_ok_true_for_genuine_bundle() {
    let c = VectorBackend::default();
    let template = sorted_multi_template();
    let bundle = Bundle::new(input_bundle_entries()).unwrap();
    let script = input_witness_script();

    assert_eq!(
        verify::input_verification(&c, &template, &script, &bundle),
        Ok(true)
    );

    let mut mismatched = script.clone();
    *mismatched.last_mut().unwrap() = 0xaf;
    assert_eq!(
        verify::input_verification(&c, &template, &mismatched, &bundle),
        Ok(false)
    );
}

#[test]
fn tweaked_keys_missing_tweak() {
    let c = VectorBackend::default();
    let template = sorted_multi_template();
    let entries = input_bundle_entries()
        .into_iter()
        .filter(|entry| entry.key != k1())
        .collect();
    let bundle = Bundle::new(entries).unwrap();

    assert_eq!(
        verify::tweaked_keys(&c, &c.template_base_keys(&template), &bundle),
        Err(Error::MissingTweak)
    );
    assert_eq!(
        verify::input_verification(&c, &template, &input_witness_script(), &bundle),
        Err(Error::MissingTweak)
    );
}

#[test]
fn tweaked_keys_extra_tweak() {
    let c = VectorBackend::default();
    let template = sorted_multi_template();
    let mut entries = input_bundle_entries();
    entries.push(Entry {
        key: hex_arr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        tweak: [0x01; 32],
    });
    let bundle = Bundle::new(entries).unwrap();

    assert_eq!(
        verify::tweaked_keys(&c, &c.template_base_keys(&template), &bundle),
        Err(Error::ExtraTweak)
    );
    assert_eq!(
        verify::change_output_verification(&c, &template, &input_witness_script(), &bundle),
        Err(Error::ExtraTweak)
    );
}

#[test]
fn tweaked_keys_pairs_sorted_by_base() {
    let c = VectorBackend::default();
    let template = sorted_multi_template();
    let bundle = Bundle::new(input_bundle_entries()).unwrap();

    let pairs = verify::tweaked_keys(&c, &c.template_base_keys(&template), &bundle).unwrap();
    assert_eq!(pairs.len(), 3);

    let bases = [k1(), k2(), k3()];
    for (i, base) in bases.iter().enumerate() {
        assert_eq!(pairs[i].0, *base);
        let tweak = bundle.tweak(base).unwrap();
        assert_eq!(pairs[i].1, tweak::tweak_key(&c, base, &tweak).unwrap());
    }
}

#[derive(Deserialize)]
struct DelegatorSignVectors {
    test_cases: Vec<DelegatorSignCase>,
}

#[derive(Deserialize)]
struct DelegatorSignCase {
    comment: String,
    base_secret: String,
    tweak: String,
    message: String,
    expected: DelegatorSignExpected,
}

#[derive(Deserialize)]
struct DelegatorSignExpected {
    signature: String,
}

fn delegator_sign_base_secret() -> [u8; 32] {
    hex_arr("9303c68c414a6208dbc0329181dd640b135e669647ad7dcb2f09870c54b26ed9")
}

fn delegator_sign_tweak() -> [u8; 32] {
    hex_arr("d81d8e239630639ac24f3976257d9e4d905272b3da3a6507841c1ec80b04b91b")
}

fn delegator_sign_digest() -> [u8; 32] {
    hex_arr("ed952b43f26247e9b79c9170ee6c69eb911e59c4e78fd2e44c270bbd262ec80e")
}

fn delegator_sign_signature() -> [u8; 64] {
    hex_arr(
        "2f558d1519106f6cffdcfce09954c6ae328b98308718a0903e3efed103b457cd563c315fe6\
         c6b5ffe6f71f413ce68ba22ee793238ab73fd2cef9d5881ae80017",
    )
}

fn delegator_sign_base_key() -> [u8; 33] {
    hex_arr("0296928602758150d2b4a8a253451b887625b94ab0a91f801f1408cb33b9cf0f83")
}

fn delegator_sign_tweaked_key() -> [u8; 33] {
    hex_arr("03636eb334a6ffdfc4b975a61dae12f49e7f94461690fa4688632db8eed5601b03")
}

fn delegator_sign_n_minus_base() -> [u8; 32] {
    hex_arr("6cfc3973beb59df7243fcd6e7e229bf3a7507650679b227090c8d7807b83d268")
}

#[test]
fn delegator_sign_vectors() {
    let c = RustBitcoin::new();
    let vectors: DelegatorSignVectors = load("delegator_sign_vectors.json");
    assert_eq!(vectors.test_cases.len(), 1);

    for case in &vectors.test_cases {
        let digest = sha256::Hash::hash(case.message.as_bytes()).to_byte_array();
        assert_eq!(digest, delegator_sign_digest(), "{}", case.comment);

        let base_secret: [u8; 32] = hex_arr(&case.base_secret);
        let tweak: [u8; 32] = hex_arr(&case.tweak);
        let expected_signature: [u8; 64] = hex_arr(&case.expected.signature);

        assert_eq!(
            sign::delegator_sign(&c, &tweak, &base_secret, &digest, &[0u8; 32]),
            Ok(expected_signature),
            "{}",
            case.comment
        );
    }

    assert_eq!(
        sign::delegator_sign(
            &c,
            &delegator_sign_tweak(),
            &delegator_sign_base_secret(),
            &delegator_sign_digest(),
            &[0u8; 32],
        ),
        Ok(delegator_sign_signature())
    );
}

#[test]
fn delegator_signature_verifies_under_tweaked_key() {
    let c = RustBitcoin::new();
    let base = c.base_mul(&delegator_sign_base_secret()).unwrap();
    assert_eq!(base, delegator_sign_base_key());

    let tweaked = tweak::tweak_key(&c, &base, &delegator_sign_tweak()).unwrap();
    assert_eq!(tweaked, delegator_sign_tweaked_key());

    assert!(bip340::verify(
        &c,
        &xbytes(&tweaked),
        &delegator_sign_digest(),
        &delegator_sign_signature()
    ));
    assert!(!bip340::verify(
        &c,
        &xbytes(&base),
        &delegator_sign_digest(),
        &delegator_sign_signature()
    ));
}

#[test]
fn delegator_sign_rejects_cancelling_tweak() {
    let c = RustBitcoin::new();
    assert_eq!(
        scalar_neg(&delegator_sign_base_secret()),
        delegator_sign_n_minus_base()
    );

    assert_eq!(
        sign::delegator_sign(
            &c,
            &delegator_sign_n_minus_base(),
            &delegator_sign_base_secret(),
            &delegator_sign_digest(),
            &[0u8; 32],
        ),
        Err(Error::SecretKey)
    );
}

#[test]
fn delegator_sign_rejects_invalid_inputs() {
    let c = RustBitcoin::new();
    assert_eq!(
        sign::delegator_sign(
            &c,
            &delegator_sign_tweak(),
            &[0u8; 32],
            &delegator_sign_digest(),
            &[0u8; 32],
        ),
        Err(Error::SecretKey)
    );

    let n: [u8; 32] = hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    assert_eq!(
        sign::delegator_sign(
            &c,
            &n,
            &delegator_sign_base_secret(),
            &delegator_sign_digest(),
            &[0u8; 32],
        ),
        Err(Error::ScalarRange)
    );
}

fn secp_g() -> [u8; 33] {
    hex_arr("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
}

fn secp_neg_g() -> [u8; 33] {
    hex_arr("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
}

fn secp_g3() -> [u8; 33] {
    hex_arr("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
}

fn scalar_two() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 2;
    b
}

fn scalar_n_minus_1() -> [u8; 32] {
    hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
}

#[derive(Deserialize)]
struct NonceVectors {
    test_cases: Vec<NonceCase>,
}

#[derive(Deserialize)]
struct NonceCase {
    rand_: String,
    sk: Option<String>,
    pk: Option<String>,
    extra_in: Option<String>,
    expected_blindsecnonce: String,
    expected_blindpubnonce: String,
    comment: String,
}

#[test]
fn blind_nonce_gen() {
    let c = RustBitcoin::new();
    let vectors: NonceVectors = load("blind_nonce_gen_vectors.json");
    assert_eq!(vectors.test_cases.len(), 2);

    for (i, case) in vectors.test_cases.iter().enumerate() {
        let mut rng = FixedRng::new(hex_vec(&case.rand_));
        let sk: Option<[u8; 32]> = case.sk.as_deref().map(hex_arr);
        let pk: Option<[u8; 33]> = case.pk.as_deref().map(hex_arr);
        let extra: Option<Vec<u8>> = case.extra_in.as_deref().map(hex_vec);

        let (sec, pubnonce) =
            blind::blind_nonce_gen(&c, &mut rng, sk.as_ref(), pk.as_ref(), extra.as_deref())
                .unwrap();

        assert_eq!(
            sec.as_bytes(),
            hex_vec(&case.expected_blindsecnonce),
            "{}",
            case.comment
        );
        assert_eq!(
            pubnonce,
            hex_arr::<33>(&case.expected_blindpubnonce),
            "{}",
            case.comment
        );
        let expected_len = if pk.is_some() { 65 } else { 32 };
        assert_eq!(sec.as_bytes().len(), expected_len, "{}", case.comment);

        match i {
            0 => assert_eq!(
                pubnonce,
                hex_arr::<33>("0355a32c1b472ee1874924cd9a1bf2536d6a2b214413684fbdfc5b84870efdcef8")
            ),
            1 => {
                assert_eq!(
                    sec.as_bytes(),
                    hex_vec("78acdd864846bb5c18017a421e792cc771d63eda6b63a6cdc3825f298cac7788")
                );
                assert_eq!(
                    pubnonce,
                    hex_arr::<33>(
                        "025ca329f7676aeceac10c29566d9c7883a661db2574454ae491476eadee3cd430"
                    )
                );
            }
            _ => unreachable!("blind_nonce_gen_vectors.json has exactly 2 cases"),
        }
    }
}

#[test]
fn apply_tweak_plain_equals_tweak_key() {
    let c = RustBitcoin::new();
    let ctx = blind::apply_tweak(
        &c,
        &blind::tweak_ctx_init(&c, &secp_neg_g()).unwrap(),
        &scalar_two(),
        false,
    )
    .unwrap();

    assert_eq!(
        ctx.q,
        tweak::tweak_key(&c, &secp_neg_g(), &scalar_two()).unwrap()
    );
    assert_eq!(ctx.q, secp_g());
    assert!(!ctx.gacc_neg);
    assert_eq!(ctx.tacc, scalar_two());
}

#[test]
fn apply_tweak_xonly_negates_odd_key_first() {
    let c = RustBitcoin::new();
    let ctx = blind::apply_tweak(
        &c,
        &blind::tweak_ctx_init(&c, &secp_neg_g()).unwrap(),
        &scalar_two(),
        true,
    )
    .unwrap();

    assert_eq!(
        ctx.q,
        tweak::tweak_key(&c, &point_neg(&secp_neg_g()), &scalar_two()).unwrap()
    );
    assert_eq!(ctx.q, secp_g3());
    assert!(ctx.gacc_neg);
    assert_eq!(ctx.tacc, scalar_two());

    let even_ctx = blind::apply_tweak(
        &c,
        &blind::tweak_ctx_init(&c, &secp_g()).unwrap(),
        &scalar_two(),
        true,
    )
    .unwrap();
    assert_eq!(even_ctx.q, secp_g3());
    assert!(!even_ctx.gacc_neg);
}

#[test]
fn tweak_context_errors() {
    let c = RustBitcoin::new();

    let mut bad_key = [0u8; 33];
    bad_key[0] = 0x04;
    bad_key[1..].copy_from_slice(&xbytes(&secp_g()));
    assert_eq!(
        blind::tweak_ctx_init(&c, &bad_key),
        Err(Error::InvalidPoint)
    );

    let ctx = blind::tweak_ctx_init(&c, &secp_g()).unwrap();
    let n: [u8; 32] = hex_arr("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    assert_eq!(
        blind::apply_tweak(&c, &ctx, &n, false),
        Err(Error::ScalarRange)
    );

    assert_eq!(
        blind::apply_tweak(&c, &ctx, &scalar_n_minus_1(), false),
        Err(Error::Infinity)
    );
}

#[derive(Deserialize)]
struct ChallengeVectors {
    test_cases: Vec<ChallengeValid>,
    error_test_cases: Vec<ChallengeError>,
}

#[derive(Deserialize)]
struct ChallengeValid {
    rand: String,
    msg: String,
    blindpubnonce: String,
    pk: String,
    tweaks: Vec<String>,
    is_xonly: Vec<bool>,
    extra_in: Option<String>,
    expected_blindfactor: String,
    expected_challenge: String,
    expected_pubnonce: String,
    expected_blindchallenge: String,
    expected_pk_parity: bool,
    expected_nonce_parity: bool,
}

#[derive(Deserialize)]
struct ChallengeError {
    rand: String,
    msg: String,
    blindpubnonce: String,
    pk: String,
    tweaks: Vec<String>,
    is_xonly: Vec<bool>,
    extra_in: Option<String>,
    comment: String,
}

fn decode_tweaks(tweaks: &[String]) -> Vec<[u8; 32]> {
    tweaks.iter().map(|t| hex_arr(t)).collect()
}

#[test]
fn blind_challenge_gen() {
    let c = RustBitcoin::new();
    let vectors: ChallengeVectors = load("blind_challenge_gen_vectors.json");
    assert_eq!(vectors.test_cases.len(), 1);
    assert_eq!(vectors.error_test_cases.len(), 2);

    for case in &vectors.test_cases {
        let mut rng = FixedRng::new(hex_vec(&case.rand));
        let msg = hex_vec(&case.msg);
        let blindpubnonce: [u8; 33] = hex_arr(&case.blindpubnonce);
        let pk: [u8; 33] = hex_arr(&case.pk);
        let tweaks = decode_tweaks(&case.tweaks);
        let extra: Option<Vec<u8>> = case.extra_in.as_deref().map(hex_vec);

        let out = blind::blind_challenge_gen(
            &c,
            &mut rng,
            &msg,
            &blindpubnonce,
            &pk,
            &tweaks,
            &case.is_xonly,
            extra.as_deref(),
        )
        .unwrap();

        assert_eq!(
            out.blindchallenge,
            hex_arr::<32>(&case.expected_blindchallenge)
        );
        assert_eq!(
            out.blindchallenge,
            hex_arr::<32>("b5b3a3d63771818e930e55d3f91ebf11ed16bcdb11e0f1b5df06f636f870dfb5")
        );
        assert_eq!(out.pk_parity, case.expected_pk_parity);
        assert!(out.pk_parity);
        assert_eq!(out.nonce_parity, case.expected_nonce_parity);
        assert!(!out.nonce_parity);

        assert_eq!(out.session.pk, pk);
        assert_eq!(
            out.session.blindfactor,
            hex_arr::<32>(&case.expected_blindfactor)
        );
        assert_eq!(
            out.session.blindfactor,
            hex_arr::<32>("545ab2aab17406be3270d0dfb7b13568f9ed5fad5abc5e9acbafc8d17131cc37")
        );
        assert_eq!(
            out.session.challenge,
            hex_arr::<32>(&case.expected_challenge)
        );
        assert_eq!(
            out.session.challenge,
            hex_arr::<32>("ac03df1f1da05bfd6e01e11bd7b95e3a6a0752bbb0e31ea26251675cecce3a15")
        );
        assert_eq!(out.session.pubnonce, hex_arr::<33>(&case.expected_pubnonce));
        assert_eq!(
            out.session.pubnonce,
            hex_arr::<33>("0367e34dab4f1377cd8f3e7c5cd3e1e4a4d3b27beab9c0c0dc6717c9c52275d03b")
        );
        assert_eq!(out.session.tweaks, tweaks);
        assert_eq!(out.session.is_xonly, vec![true, true, false]);
    }

    for case in &vectors.error_test_cases {
        let mut rng = FixedRng::new(hex_vec(&case.rand));
        let msg = hex_vec(&case.msg);
        let blindpubnonce: [u8; 33] = hex_arr(&case.blindpubnonce);
        let pk: [u8; 33] = hex_arr(&case.pk);
        let tweaks = decode_tweaks(&case.tweaks);
        let extra: Option<Vec<u8>> = case.extra_in.as_deref().map(hex_vec);

        let result = blind::blind_challenge_gen(
            &c,
            &mut rng,
            &msg,
            &blindpubnonce,
            &pk,
            &tweaks,
            &case.is_xonly,
            extra.as_deref(),
        );

        match case.comment.as_str() {
            "mismatched arrays" => assert_eq!(result, Err(Error::TweakCount), "{}", case.comment),
            "invalid blindpubnonce encoding" => {
                assert_eq!(result, Err(Error::InvalidPoint), "{}", case.comment)
            }
            other => panic!("unknown error case: {other}"),
        }
    }
}

#[test]
fn blind_challenge_gen_session_recomputes_challenge() {
    let c = RustBitcoin::new();
    let vectors: ChallengeVectors = load("blind_challenge_gen_vectors.json");
    let case = &vectors.test_cases[0];

    let mut rng = FixedRng::new(hex_vec(&case.rand));
    let msg = hex_vec(&case.msg);
    let blindpubnonce: [u8; 33] = hex_arr(&case.blindpubnonce);
    let pk: [u8; 33] = hex_arr(&case.pk);
    let tweaks = decode_tweaks(&case.tweaks);
    let extra: Option<Vec<u8>> = case.extra_in.as_deref().map(hex_vec);

    let out = blind::blind_challenge_gen(
        &c,
        &mut rng,
        &msg,
        &blindpubnonce,
        &pk,
        &tweaks,
        &case.is_xonly,
        extra.as_deref(),
    )
    .unwrap();

    let mut ctx = blind::tweak_ctx_init(&c, &pk).unwrap();
    for (tweak, xonly) in tweaks.iter().zip(case.is_xonly.iter()) {
        ctx = blind::apply_tweak(&c, &ctx, tweak, *xonly).unwrap();
    }

    let mut engine = tagged_hash256(&c, b"BIP0340/challenge");
    engine.update(&xbytes(&out.session.pubnonce));
    engine.update(&xbytes(&ctx.q));
    engine.update(&msg);
    assert_eq!(engine.finalize(), out.session.challenge);
}

#[derive(Deserialize)]
struct BlindSignVectors {
    valid_test_cases: Vec<SignValid>,
    sign_error_test_cases: Vec<SignError>,
    verify_fail_test_cases: Vec<VerifyCase>,
    verify_error_test_cases: Vec<VerifyCase>,
}

#[derive(Deserialize)]
struct SignValid {
    sk: String,
    pk: String,
    blindsecnonce: String,
    blindpubnonce: String,
    blindchallenge: String,
    pk_parity: bool,
    nonce_parity: bool,
    expected: SignExpected,
    checks: SignChecks,
}

#[derive(Deserialize)]
struct SignExpected {
    blindsignature: String,
}

#[derive(Deserialize)]
struct SignChecks {
    verify_returns_true: bool,
    secnonce_prefix_zeroed_after_sign: bool,
    second_call_raises_valueerror: bool,
}

#[derive(Deserialize)]
struct SignError {
    sk: String,
    blindsecnonce: String,
    blindchallenge: String,
    pk_parity: bool,
    nonce_parity: bool,
    repeat: u32,
}

#[derive(Deserialize)]
struct VerifyCase {
    pk: String,
    blindpubnonce: String,
    blindchallenge: String,
    blindsignature: String,
    pk_parity: bool,
    nonce_parity: bool,
    comment: String,
}

#[test]
fn blind_sign_and_verify() {
    let c = RustBitcoin::new();
    let vectors: BlindSignVectors = load("blind_sign_and_verify_vectors.json");
    assert_eq!(vectors.valid_test_cases.len(), 1);
    assert_eq!(vectors.sign_error_test_cases.len(), 2);
    assert_eq!(vectors.verify_fail_test_cases.len(), 1);
    assert_eq!(vectors.verify_error_test_cases.len(), 1);

    let valid = &vectors.valid_test_cases[0];
    assert!(valid.sk.starts_with("E4E64DB3"));
    assert!(valid.pk_parity);
    assert!(!valid.nonce_parity);

    let sk: [u8; 32] = hex_arr(&valid.sk);
    let pk: [u8; 33] = hex_arr(&valid.pk);
    let blindsecnonce = hex_vec(&valid.blindsecnonce);
    let blindpubnonce: [u8; 33] = hex_arr(&valid.blindpubnonce);
    let e: [u8; 32] = hex_arr(&valid.blindchallenge);

    // R' consistency check: the reference cross-checks the base point multiple of k' against blindpubnonce.
    let k_prime: [u8; 32] = blindsecnonce[..32].try_into().unwrap();
    assert_eq!(c.base_mul(&k_prime), Some(blindpubnonce));

    let mut sec = blind::BlindSecNonce::from_bytes(&blindsecnonce).unwrap();
    let s = blind::blind_sign(&c, &sk, &e, &mut sec, valid.pk_parity, valid.nonce_parity).unwrap();
    assert_eq!(s, hex_arr::<32>(&valid.expected.blindsignature));
    assert_eq!(
        s,
        hex_arr::<32>("8632b771a6a923ff1561b3513c4841f2d88795b05d99bc581abca201eed86ec5")
    );

    assert!(valid.checks.secnonce_prefix_zeroed_after_sign);
    assert_eq!(&sec.as_bytes()[..64], [0u8; 64].as_slice());
    assert_eq!(sec.as_bytes()[64], 0xaa);

    assert!(valid.checks.verify_returns_true);
    assert_eq!(
        blind::verify_blind_signature(
            &c,
            &pk,
            &blindpubnonce,
            &e,
            &s,
            valid.pk_parity,
            valid.nonce_parity
        ),
        Ok(true)
    );

    assert!(valid.checks.second_call_raises_valueerror);
    assert_eq!(
        blind::blind_sign(&c, &sk, &e, &mut sec, valid.pk_parity, valid.nonce_parity),
        Err(Error::NonceReuse)
    );

    let expected_errors = [Error::ScalarRange, Error::NonceReuse];
    for (case, expected) in vectors.sign_error_test_cases.iter().zip(expected_errors) {
        let case_sk: [u8; 32] = hex_arr(&case.sk);
        let case_e: [u8; 32] = hex_arr(&case.blindchallenge);
        let original = hex_vec(&case.blindsecnonce);
        let mut case_sec = blind::BlindSecNonce::from_bytes(&original).unwrap();

        for i in 0..case.repeat {
            let result = blind::blind_sign(
                &c,
                &case_sk,
                &case_e,
                &mut case_sec,
                case.pk_parity,
                case.nonce_parity,
            );
            if i + 1 == case.repeat {
                assert_eq!(result, Err(expected));
            } else {
                assert!(result.is_ok());
            }
        }

        if expected == Error::ScalarRange {
            assert_eq!(case_sec.as_bytes(), original.as_slice());
        }
    }

    let fail = &vectors.verify_fail_test_cases[0];
    assert_eq!(fail.comment, "Verify should return False (no exception)");
    assert_eq!(
        blind::verify_blind_signature(
            &c,
            &hex_arr(&fail.pk),
            &hex_arr(&fail.blindpubnonce),
            &hex_arr(&fail.blindchallenge),
            &hex_arr(&fail.blindsignature),
            fail.pk_parity,
            fail.nonce_parity
        ),
        Ok(false)
    );

    let bad = &vectors.verify_error_test_cases[0];
    assert_eq!(bad.comment, "Bad blindpubnonce encoding");
    let bad_pubnonce: [u8; 33] = hex_arr(&bad.blindpubnonce);
    assert_eq!(bad_pubnonce[0], 0x04);
    assert_eq!(
        blind::verify_blind_signature(
            &c,
            &hex_arr(&bad.pk),
            &bad_pubnonce,
            &hex_arr(&bad.blindchallenge),
            &hex_arr(&bad.blindsignature),
            bad.pk_parity,
            bad.nonce_parity
        ),
        Err(Error::InvalidPoint)
    );

    assert_eq!(
        blind::verify_blind_signature(
            &c,
            &pk,
            &blindpubnonce,
            &e,
            &N,
            valid.pk_parity,
            valid.nonce_parity
        ),
        Err(Error::ScalarRange)
    );
    assert_eq!(
        blind::verify_blind_signature(
            &c,
            &pk,
            &blindpubnonce,
            &e,
            &s,
            !valid.pk_parity,
            valid.nonce_parity
        ),
        Ok(false)
    );
    let mut zero_sk_sec = blind::BlindSecNonce::from_bytes(&blindsecnonce).unwrap();
    assert_eq!(
        blind::blind_sign(
            &c,
            &[0u8; 32],
            &e,
            &mut zero_sk_sec,
            valid.pk_parity,
            valid.nonce_parity
        ),
        Err(Error::SecretKey)
    );
}

#[derive(Deserialize)]
struct UnblindVectors {
    valid_test_cases: Vec<UnblindCase>,
    error_test_cases: Vec<UnblindCase>,
}

#[derive(Deserialize)]
struct UnblindCase {
    session_ctx: SessionJson,
    msg: String,
    blindsignature: String,
    expected_bip340_sig: Option<String>,
    comment: Option<String>,
}

#[derive(Deserialize)]
struct SessionJson {
    pk: String,
    blindfactor: String,
    challenge: String,
    pubnonce: String,
    tweaks: Vec<String>,
    is_xonly: Vec<bool>,
}

fn build_session(json: &SessionJson) -> blind::SessionContext {
    blind::SessionContext {
        pk: hex_arr(&json.pk),
        blindfactor: hex_arr(&json.blindfactor),
        challenge: hex_arr(&json.challenge),
        pubnonce: hex_arr(&json.pubnonce),
        tweaks: json.tweaks.iter().map(|t| hex_arr(t)).collect(),
        is_xonly: json.is_xonly.clone(),
    }
}

#[test]
fn unblind_signature() {
    let c = RustBitcoin::new();
    let vectors: UnblindVectors = load("unblind_signature_vectors.json");
    assert_eq!(vectors.valid_test_cases.len(), 1);
    assert_eq!(vectors.error_test_cases.len(), 3);

    let valid = &vectors.valid_test_cases[0];
    let session = build_session(&valid.session_ctx);
    let msg: [u8; 32] = hex_arr(&valid.msg);
    let s: [u8; 32] = hex_arr(&valid.blindsignature);

    let sig = blind::unblind_signature(&c, &session, &s).unwrap();
    let expected: [u8; 64] = hex_arr(valid.expected_bip340_sig.as_deref().unwrap());
    assert_eq!(sig, expected);
    assert_eq!(
        sig,
        hex_arr::<64>(
            "ed7e7eb4e886f9a9df4e375f5f9321dcf5aa909b85a028b7ebb14f2ed80ae3bd1a606d2de092bd1a05b\
             82532bdea7f11493d00eb1109cf1ef30a8d8e2ff2721c"
        )
    );

    let mut ctx = blind::tweak_ctx_init(&c, &session.pk).unwrap();
    for (tweak, xonly) in session.tweaks.iter().zip(session.is_xonly.iter()) {
        ctx = blind::apply_tweak(&c, &ctx, tweak, *xonly).unwrap();
    }
    assert!(bip340::verify(&c, &xbytes(&ctx.q), &msg, &sig));

    for case in &vectors.error_test_cases {
        let case_session = build_session(&case.session_ctx);
        let case_s: [u8; 32] = hex_arr(&case.blindsignature);
        let comment = case.comment.as_deref().unwrap_or_default();
        let result = blind::unblind_signature(&c, &case_session, &case_s);
        match comment {
            "Bad pubnonce encoding" => assert_eq!(result, Err(Error::InvalidPoint), "{comment}"),
            "tweaks/is_xonly length mismatch" => {
                assert_eq!(result, Err(Error::TweakCount), "{comment}")
            }
            "challenge out of range" => assert_eq!(result, Err(Error::TweakCount), "{comment}"),
            other => panic!("unknown error case: {other}"),
        }
    }

    let mut challenge_n = session.clone();
    challenge_n.challenge = N;
    assert_eq!(
        blind::unblind_signature(&c, &challenge_n, &s),
        Err(Error::ScalarRange)
    );

    let mut blindfactor_n = session.clone();
    blindfactor_n.blindfactor = N;
    assert_eq!(
        blind::unblind_signature(&c, &blindfactor_n, &s),
        Err(Error::ScalarRange)
    );

    assert_eq!(
        blind::unblind_signature(&c, &session, &N),
        Err(Error::ScalarRange)
    );
}

#[test]
fn sign_and_verify_random() {
    let c = RustBitcoin::new();
    let h = |bytes: &[u8]| -> [u8; 32] { sha256::Hash::hash(bytes).to_byte_array() };

    for i in 0u8..6 {
        let sk = scalar_reduce(&h(&[b's', i]));
        assert_ne!(sk, [0u8; 32]);
        let pk = c.base_mul(&sk).unwrap();
        let msg = h(&[b'm', i]);

        let v = i % 4;
        let mut tweaks = Vec::new();
        let mut is_xonly = Vec::new();
        for j in 0..v {
            tweaks.push(scalar_reduce(&h(&[b't', i, j])));
            is_xonly.push((i + j) % 2 == 1);
        }

        let mut q_ctx = blind::tweak_ctx_init(&c, &pk).unwrap();
        for (tweak, xonly) in tweaks.iter().zip(is_xonly.iter()) {
            q_ctx = blind::apply_tweak(&c, &q_ctx, tweak, *xonly).unwrap();
        }

        let (mut sec, pubnonce) = blind::blind_nonce_gen(
            &c,
            &mut FixedRng::new(vec![0x10 + i; 32]),
            Some(&sk),
            Some(&pk),
            Some(&[i; 32]),
        )
        .unwrap();

        let ch = blind::blind_challenge_gen(
            &c,
            &mut FixedRng::new(vec![0x20 + i; 32]),
            &msg,
            &pubnonce,
            &pk,
            &tweaks,
            &is_xonly,
            Some(&[0x80 + i; 32]),
        )
        .unwrap();

        let s = blind::blind_sign(
            &c,
            &sk,
            &ch.blindchallenge,
            &mut sec,
            ch.pk_parity,
            ch.nonce_parity,
        )
        .unwrap();
        assert_eq!(
            blind::verify_blind_signature(
                &c,
                &pk,
                &pubnonce,
                &ch.blindchallenge,
                &s,
                ch.pk_parity,
                ch.nonce_parity
            ),
            Ok(true)
        );

        let sig = blind::unblind_signature(&c, &ch.session, &s).unwrap();
        assert_eq!(sig[..32], xbytes(&ch.session.pubnonce));
        assert!(bip340::verify(&c, &xbytes(&q_ctx.q), &msg, &sig));

        let secp = Secp256k1::verification_only();
        let sig_obj = schnorr::Signature::from_slice(&sig).unwrap();
        let message = Message::from_digest(msg);
        let xonly = XOnlyPublicKey::from_slice(&xbytes(&q_ctx.q)).unwrap();
        assert_eq!(secp.verify_schnorr(&sig_obj, &message, &xonly), Ok(()));

        assert_eq!(
            blind::blind_sign(
                &c,
                &sk,
                &ch.blindchallenge,
                &mut sec,
                ch.pk_parity,
                ch.nonce_parity
            ),
            Err(Error::NonceReuse)
        );
    }
}

#[test]
fn blind_sign_rejects_reused_nonce() {
    let c = RustBitcoin::new();
    let sk: [u8; 32] = hex_arr("E4E64DB308215A81F1F41969624B9A6265D50F479BA6789E40190027AC6C72A8");
    let e: [u8; 32] = hex_arr("64FD1082FA5E7C5BF1267A5AB5BC3F4BD41167427E4D4A4166876709857E92EB");

    let mut sec65 = blind::BlindSecNonce::from_bytes(&[0u8; 65]).unwrap();
    assert_eq!(
        blind::blind_sign(&c, &sk, &e, &mut sec65, true, false),
        Err(Error::NonceReuse)
    );

    let mut sec32 = blind::BlindSecNonce::from_bytes(&[0u8; 32]).unwrap();
    assert_eq!(
        blind::blind_sign(&c, &sk, &e, &mut sec32, true, false),
        Err(Error::NonceReuse)
    );
}
