//! End-to-end regtest coverage of the external signer round trip: a
//! watch-only `bwk-sp` account builds a PSBT v2 paying a silent-payment
//! address, a mock remote manager backed by an `SpSigner` completes and signs
//! it, the account verifies the proofs, finalizes as a separate step,
//! broadcasts, and a receiver rediscovers the output by scanning.
//!
//! The only account that ever signs here is watch-only: it holds no key
//! material, only the mock signer does.

mod common;

use std::{sync::mpsc, time::Duration};

use bitcoin::Network;
use bwk::bwk_electrum::notification::{Notification, SpNotification};
use bwk_sign::{bwk_descriptor::descriptor::Descriptor, identity::SignerId};
use bwk_sp::{
    account::{config::Config, recipient::TxBuilderSpExt, Account, AccountError},
    core::utils::common::SilentPaymentAddress,
};

use common::{
    abort_after, mock_sp_manager, test_mnemonic, test_mnemonic_2, wait_for_signed_psbt,
    wait_for_signers, watch_only_account, watch_only_descriptor, TestEnv,
};

const SEND_AMOUNT: u64 = 100_000;

#[test]
fn test_signer_round_trip() {
    let mut env = TestEnv::new();

    test_external_signer_round_trip(&mut env);
    test_external_signer_round_trip_change_is_rediscovered(&mut env);
    test_external_signer_round_trip_broadcasts_over_electrum(&mut env);
    test_verification_notification_precedes_finalize(&mut env);
    test_account_holds_no_psbt_between_steps(&mut env);
    test_signer_id_is_not_the_fingerprint(&mut env);
}

/// Funds a hot account from `test_mnemonic()`, then builds and independently
/// scans a watch-only account for the same mnemonic over the funding block,
/// asserting the two see the same balance: the watch-only descriptor really
/// derives the same silent-payment address. `electrum` wires the watch-only
/// account to `env`'s embedded electrsd for the broadcast-through-electrum
/// test.
fn watch_only_synced(env: &mut TestEnv, name: &str, electrum: bool) -> Account {
    let mut sender = env.sp_account(name);
    let (_, funding_height) = env.fund_sp(&mut sender, 0.5);
    let sender_balance = sender.balance();
    assert!(sender_balance > 0);

    let mut account = if electrum {
        let (host, port) = env.electrum_endpoint();
        let mut config = Config::from_descriptor(
            format!("{name}-watch-only"),
            Network::Regtest,
            watch_only_descriptor(test_mnemonic(), Network::Regtest),
            env.url(),
            std::path::PathBuf::from("/unused"),
        )
        .with_persistence(None);
        config.set_electrum_endpoint(host, port);
        Account::new(config).unwrap()
    } else {
        watch_only_account(&format!("{name}-watch-only"), test_mnemonic(), &env.url())
    };
    account
        .scan_blocks(Some(funding_height), Some(env.height))
        .unwrap();
    assert_eq!(account.balance(), sender_balance);
    account
}

/// Builds the watch-only sending account, attaches the mock SP signer, and
/// waits for its single entry to reach the account's signer cache.
fn setup(env: &mut TestEnv, electrum: bool) -> (Account, SignerId, mpsc::Receiver<Notification>) {
    let mut account = watch_only_synced(env, "sender", electrum);
    let receiver = account.receiver().unwrap();
    account
        .attach_signing_manager("mock", mock_sp_manager(test_mnemonic(), Network::Regtest))
        .unwrap();
    let signers = wait_for_signers(&receiver, Duration::from_secs(10));
    assert_eq!(
        signers.len(),
        1,
        "the mock manager exposes exactly one signer"
    );
    let signer_id = signers[0].id.clone();
    (account, signer_id, receiver)
}

/// A silent-payment output with no `script_pubkey`: still waiting on a
/// signer to complete it.
fn is_unfinished_sp_output(output: &bwk_psbt::Output) -> bool {
    bwk_psbt::sp::sp_v0_output(&output.psbt).unwrap().is_some() && output.script_pubkey.is_none()
}

/// Asserts the shape of a PSBT `TxBuilder::generate_v2` just produced, before
/// any signer has touched it: at least one silent-payment output still
/// lacking a script, at least one input carrying the BIP375 tweak, and the
/// transaction still modifiable.
fn assert_presigned_shape(psbt: &bwk_psbt::PsbtV2) {
    assert!(
        psbt.tx_modifiable.is_none(),
        "an unsigned psbt must not be frozen yet"
    );
    assert!(
        psbt.outputs.iter().any(is_unfinished_sp_output),
        "expected at least one unfinished silent-payment output"
    );
    assert!(
        psbt.inputs
            .iter()
            .any(|input| bwk_psbt::sp::sp_input_tweak(&input.psbt).unwrap().is_some()),
        "expected at least one silent-payment input carrying PSBT_IN_SP_TWEAK"
    );
}

/// Asserts the shape of the bytes a signer handed back: every silent-payment
/// output now has a script, every scan key has a paired share and proof
/// (global or per-input), the transaction is frozen, and every
/// silent-payment input carries a signature.
fn assert_signed_shape(psbt: &bwk_psbt::PsbtV2) {
    assert_eq!(
        psbt.tx_modifiable,
        Some(bwk_psbt::TxModifiable::none()),
        "a completed psbt must freeze tx_modifiable"
    );
    assert!(
        !psbt.outputs.iter().any(is_unfinished_sp_output),
        "every silent-payment output must have a script after signing"
    );

    let scan_keys = bwk_sp::account::bip375::scan_keys(psbt).unwrap();
    assert!(!scan_keys.is_empty());
    for scan_key in &scan_keys {
        let has_global = bwk_psbt::sp::sp_global_ecdh_share_v2(psbt, *scan_key)
            .unwrap()
            .is_some()
            && bwk_psbt::sp::sp_global_dleq_v2(psbt, *scan_key)
                .unwrap()
                .is_some();
        let has_per_input = psbt.inputs.iter().any(|input| {
            bwk_psbt::sp::sp_input_ecdh_share(&input.psbt, *scan_key)
                .unwrap()
                .is_some()
                && bwk_psbt::sp::sp_input_dleq(&input.psbt, *scan_key)
                    .unwrap()
                    .is_some()
        });
        assert!(
            has_global || has_per_input,
            "scan key must have a paired share and proof, global or per-input"
        );
    }

    let sp_inputs_signed = psbt
        .inputs
        .iter()
        .filter(|input| bwk_psbt::sp::sp_input_tweak(&input.psbt).unwrap().is_some())
        .all(|input| input.psbt.tap_key_sig.is_some());
    assert!(
        sp_inputs_signed,
        "every silent-payment input must carry a signature"
    );
}

/// Builds a PSBT v2 sending `SEND_AMOUNT` to `destination`, asserts its
/// presigned shape, drives it through `sign`, waits for verification, and
/// asserts the signed shape. Returns the verified bytes.
fn build_sign_verify(
    account: &Account,
    signer_id: &SignerId,
    rx: &mpsc::Receiver<Notification>,
    destination: SilentPaymentAddress,
) -> Vec<u8> {
    let descriptor: Descriptor = account.get_config().descriptor.into();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(destination, SEND_AMOUNT);
    let coins = builder.select_coins(SEND_AMOUNT, 1000);
    assert!(!coins.is_empty());
    for coin in coins {
        builder.add_input(coin);
    }
    let unsigned = builder.generate_v2().unwrap();
    assert_presigned_shape(&unsigned);

    account
        .sign(signer_id, descriptor, unsigned.serialize().unwrap())
        .unwrap();

    let signed_bytes = wait_for_signed_psbt(rx, Duration::from_secs(30)).unwrap();
    let signed = bwk_psbt::PsbtV2::deserialize(&signed_bytes).unwrap();
    assert_signed_shape(&signed);
    signed_bytes
}

fn test_external_signer_round_trip(env: &mut TestEnv) {
    let _guard = abort_after("external_signer_round_trip", Duration::from_secs(180));

    let (account, signer_id, rx) = setup(env, false);
    let mut receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    let signed_bytes = build_sign_verify(&account, &signer_id, &rx, receiver_account.sp_address());
    let tx = account.finalize(&signed_bytes).unwrap();
    env.broadcast_and_mine(&tx);

    receiver_account
        .scan_blocks(Some(1), Some(env.height))
        .unwrap();
    let txid = tx.compute_txid();
    let new_coins: Vec<_> = receiver_account
        .coins()
        .into_iter()
        .filter(|(outpoint, _)| outpoint.txid == txid)
        .collect();
    assert_eq!(
        new_coins.len(),
        1,
        "receiver must find exactly one new coin"
    );
    assert!(receiver_account.balance() >= SEND_AMOUNT);
}

fn test_external_signer_round_trip_change_is_rediscovered(env: &mut TestEnv) {
    let _guard = abort_after(
        "external_signer_round_trip_change_is_rediscovered",
        Duration::from_secs(180),
    );

    let (mut account, signer_id, rx) = setup(env, false);
    let mut receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    let signed_bytes = build_sign_verify(&account, &signer_id, &rx, receiver_account.sp_address());
    let tx = account.finalize(&signed_bytes).unwrap();
    env.broadcast_and_mine(&tx);

    let txid = tx.compute_txid();
    account.scan_blocks(Some(1), Some(env.height)).unwrap();
    let change_coins: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(outpoint, _)| outpoint.txid == txid)
        .collect();
    assert_eq!(
        change_coins.len(),
        1,
        "the sending account must rediscover its own change output"
    );

    receiver_account
        .scan_blocks(Some(1), Some(env.height))
        .unwrap();
    assert!(receiver_account.balance() >= SEND_AMOUNT);
}

fn test_external_signer_round_trip_broadcasts_over_electrum(env: &mut TestEnv) {
    let _guard = abort_after(
        "external_signer_round_trip_broadcasts_over_electrum",
        Duration::from_secs(180),
    );

    let (mut account, signer_id, rx) = setup(env, true);
    let mut receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    let signed_bytes = build_sign_verify(&account, &signer_id, &rx, receiver_account.sp_address());
    let tx = account.finalize(&signed_bytes).unwrap();
    let txid = tx.compute_txid();

    account.broadcast(tx);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero(), "no broadcast outcome in time");
        match rx.recv_timeout(remaining) {
            Ok(Notification::Sp(SpNotification::Broadcasted { txid: got })) => {
                assert_eq!(got, txid);
                break;
            }
            Ok(Notification::Sp(SpNotification::FailBroadcast { message })) => {
                panic!("broadcast failed: {message}")
            }
            Ok(_) => continue,
            Err(e) => panic!("broadcast outcome never arrived: {e}"),
        }
    }
    env.mine(1);

    receiver_account
        .scan_blocks(Some(1), Some(env.height))
        .unwrap();
    assert!(receiver_account.balance() >= SEND_AMOUNT);
}

fn test_verification_notification_precedes_finalize(env: &mut TestEnv) {
    let _guard = abort_after(
        "verification_notification_precedes_finalize",
        Duration::from_secs(180),
    );

    let (account, signer_id, rx) = setup(env, false);
    let receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    // `build_sign_verify` blocks on `wait_for_signed_psbt`, which only
    // returns once `PsbtVerified` has been observed on the notification
    // channel. `finalize` below is a second, separate call the test makes
    // explicitly afterwards: verification and finalization are two steps.
    let signed_bytes = build_sign_verify(&account, &signer_id, &rx, receiver_account.sp_address());
    let tx = account.finalize(&signed_bytes).unwrap();
    assert!(!tx.input.is_empty());
}

fn test_account_holds_no_psbt_between_steps(env: &mut TestEnv) {
    let _guard = abort_after(
        "account_holds_no_psbt_between_steps",
        Duration::from_secs(180),
    );

    // The account is stateless across the sign/finalize boundary. There is no
    // `pending_psbt()` / `last_psbt()` getter to assert against, so this test
    // documents the invariant by driving the full round trip using only the
    // bytes `sign`'s notification carries: nothing here ever reads a psbt back
    // off `account` itself.
    let (account, signer_id, rx) = setup(env, false);
    let receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    let signed_bytes = build_sign_verify(&account, &signer_id, &rx, receiver_account.sp_address());
    account.finalize(&signed_bytes).unwrap();
}

fn test_signer_id_is_not_the_fingerprint(env: &mut TestEnv) {
    let _guard = abort_after("signer_id_is_not_the_fingerprint", Duration::from_secs(60));

    let (account, signer_id, _rx) = setup(env, false);
    let descriptor: Descriptor = account.get_config().descriptor.into();

    assert!(account.sign(&signer_id, descriptor.clone(), vec![]).is_ok());

    let fingerprint = account.signers().into_iter().next().unwrap().fingerprint;
    let fingerprint_id = SignerId::new(fingerprint.to_string());
    assert_ne!(
        fingerprint_id, signer_id,
        "the id must not equal its own fingerprint"
    );

    assert!(matches!(
        account.sign(&fingerprint_id, descriptor, vec![]),
        Err(AccountError::UnknownSigner)
    ));
}
