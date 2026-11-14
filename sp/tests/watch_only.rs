//! An account built from an `sp(scan_priv, spend_pub)` descriptor alone, with
//! no mnemonic and no key material anywhere, can build a PSBT v2 that pays a
//! silent-payment address: building never needs the private key of an input.
//! These tests pin the observable consequences.

mod common;

use bitcoin::OutPoint;
use bwk_coin::CoinSpendInfo;
use bwk_psbt::sp;
use bwk_sp::account::recipient::TxBuilderSpExt;
use bwk_tx::tx_builder::TxBuilder;

use common::{test_mnemonic, test_mnemonic_2, watch_only_account, TestEnv};

const PLACEHOLDER_BLINDBIT_URL: &str = "https://blindbit.test.example.com";

#[test]
fn watch_only_account_has_no_mnemonic() {
    let account = watch_only_account(
        "watch-no-mnemonic",
        test_mnemonic(),
        PLACEHOLDER_BLINDBIT_URL,
    );

    assert!(account.get_config().mnemonic.is_none());
    let serialized = serde_json::to_string(&account.get_config()).unwrap();
    assert!(!serialized.contains(test_mnemonic()));
}

#[test]
fn watch_only_account_has_no_signers() {
    let account = watch_only_account(
        "watch-no-signers",
        test_mnemonic(),
        PLACEHOLDER_BLINDBIT_URL,
    );

    assert!(account.signing_manager_names().is_empty());
    assert!(account.signers().is_empty());
}

#[test]
fn watch_only_address_matches_hot_account() {
    let hot = common::test_account_named("hot", PLACEHOLDER_BLINDBIT_URL);
    let watch = watch_only_account(
        "watch-address-match",
        test_mnemonic(),
        PLACEHOLDER_BLINDBIT_URL,
    );

    assert_eq!(hot.sp_address(), watch.sp_address());
}

// The chain-touching tests below fund accounts via `TestEnv::fund_sp` rather
// than `seed_synthetic_owned_coin()`: that helper is `#[cfg(feature = "bench")]`
// only and seeds a single 1-sat coin, which can't cover the 100_000-sat sends
// exercised here.
#[test]
fn test_watch_only_build_path() {
    let mut env = TestEnv::new();

    test_watch_only_builds_sp_paying_psbt(&mut env);
    test_watch_only_builds_sp_change_without_script(&mut env);
    test_watch_only_v0_build_refuses_sp_output(&mut env);
    test_watch_only_builds_ordinary_payment(&mut env);
    test_watch_only_psbt_round_trips(&mut env);
}

/// Selects coins for `target`, adds them as inputs, and returns each SP
/// coin's `(outpoint, tweak)` so callers can check the tweak the builder
/// wrote against the one the coin actually carried.
fn add_sp_inputs(builder: &mut TxBuilder, target: u64) -> Vec<(OutPoint, [u8; 32])> {
    let coins = builder.select_coins(target, 1000);
    assert!(
        !coins.is_empty(),
        "coin selection must find the funded coin"
    );
    let tweaks = coins
        .iter()
        .map(|c| match &c.spend_info {
            CoinSpendInfo::Sp { tweak } => (c.outpoint, *tweak),
            CoinSpendInfo::Bip32 { .. } => {
                panic!("a watch-only account with no sub-account must only source SP coins")
            }
        })
        .collect();
    for coin in coins {
        builder.add_input(coin);
    }
    tweaks
}

fn test_watch_only_builds_sp_paying_psbt(env: &mut TestEnv) {
    let mut account = watch_only_account("watch-pay", test_mnemonic(), &env.url());
    env.fund_sp(&mut account, 0.5);

    let recipient_address = env
        .sp_account_with_mnemonic("recipient", test_mnemonic_2())
        .sp_address();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(recipient_address, 100_000);
    let expected_tweaks = add_sp_inputs(&mut builder, 100_000);

    let psbt = builder.generate_v2().unwrap();
    psbt.validate().unwrap();
    assert_eq!(psbt.tx_modifiable, None);

    let (recipient_output, info) = psbt
        .outputs
        .iter()
        .find_map(|output| {
            let info = sp::sp_v0_output(&output.psbt).unwrap()?;
            (info.spend_key == recipient_address.get_spend_key()).then_some((output, info))
        })
        .unwrap();
    assert_eq!(recipient_output.script_pubkey, None);
    assert_eq!(info.scan_key, recipient_address.get_scan_key());

    let spend_pk = account.sp_receiver().spend_pubkey();
    for (outpoint, tweak) in expected_tweaks {
        let input = psbt
            .inputs
            .iter()
            .find(|input| input.previous_output == outpoint)
            .unwrap();
        assert_eq!(sp::sp_input_tweak(&input.psbt).unwrap(), Some(tweak));
        assert_eq!(
            sp::sp_input_spend_bip32_derivation(&input.psbt, spend_pk).unwrap(),
            None,
            "a watch-only wallet knows no fingerprint, so it writes no derivation hint"
        );
    }
}

fn test_watch_only_builds_sp_change_without_script(env: &mut TestEnv) {
    let mut account = watch_only_account("watch-change", test_mnemonic(), &env.url());
    env.fund_sp(&mut account, 0.5);

    let recipient_address = env
        .sp_account_with_mnemonic("recipient", test_mnemonic_2())
        .sp_address();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(recipient_address, 100_000);
    add_sp_inputs(&mut builder, 100_000);
    let psbt = builder.generate_v2().unwrap();

    let change_address = account.sp_receiver().receiver.get_change_address();
    let (change_output, info) = psbt
        .outputs
        .iter()
        .find_map(|output| {
            let info = sp::sp_v0_output(&output.psbt).unwrap()?;
            (info.spend_key == change_address.get_spend_key()).then_some((output, info))
        })
        .unwrap();
    assert_eq!(change_output.script_pubkey, None);
    assert_eq!(info.scan_key, change_address.get_scan_key());
}

fn test_watch_only_v0_build_refuses_sp_output(env: &mut TestEnv) {
    let mut account = watch_only_account("watch-v0-refuses", test_mnemonic(), &env.url());
    env.fund_sp(&mut account, 0.5);

    let recipient_address = env
        .sp_account_with_mnemonic("recipient", test_mnemonic_2())
        .sp_address();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(recipient_address, 100_000);
    add_sp_inputs(&mut builder, 100_000);

    assert!(builder.generate().is_err());
}

fn test_watch_only_builds_ordinary_payment(env: &mut TestEnv) {
    let mut account = watch_only_account("watch-ordinary", test_mnemonic(), &env.url());
    env.fund_sp(&mut account, 0.5);

    let destination = env.taproot_addr(0);
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(destination.clone(), 100_000);
    add_sp_inputs(&mut builder, 100_000);

    let psbt = builder.generate_v2().unwrap();
    let output = psbt
        .outputs
        .iter()
        .find(|output| output.script_pubkey == Some(destination.script_pubkey()))
        .unwrap();
    assert_eq!(sp::sp_v0_output(&output.psbt).unwrap(), None);
}

fn test_watch_only_psbt_round_trips(env: &mut TestEnv) {
    let mut account = watch_only_account("watch-roundtrip", test_mnemonic(), &env.url());
    env.fund_sp(&mut account, 0.5);

    let recipient_address = env
        .sp_account_with_mnemonic("recipient", test_mnemonic_2())
        .sp_address();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(recipient_address, 100_000);
    add_sp_inputs(&mut builder, 100_000);
    let psbt = builder.generate_v2().unwrap();

    let bytes = psbt.serialize().unwrap();
    let round_tripped = bwk_psbt::PsbtV2::deserialize(&bytes).unwrap();
    assert_eq!(round_tripped, psbt);
}
