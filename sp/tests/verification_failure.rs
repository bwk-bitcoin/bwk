//! Proves the safety property the signing round trip rests on: a manager
//! that lies about a silent-payment output, or about the DLEQ proof backing
//! it, cannot get its transaction finalized. Verification fails at the
//! notification the account emits on receipt, and `finalize` fails too when
//! handed the same bytes directly, so there is no bypass for a consumer that
//! obtained a tampered PSBT some other way.

mod common;

use std::{sync::mpsc, time::Duration};

use bitcoin::Network;
use bwk::bwk_electrum::notification::{Notification, SignerNotification};
use bwk_sign::{bwk_descriptor::descriptor::Descriptor, manager::SigningManager};
use bwk_sp::account::{recipient::TxBuilderSpExt, Account, AccountError};
use bwk_utils::mock_manager::SpSignHook;

use common::{
    abort_after, mock_sp_manager_tampering, mock_sp_manager_with_hook, sign_and_tamper,
    test_mnemonic, test_mnemonic_2, wait_for_signers, watch_only_account, Tamper, TestEnv,
};

const SEND_AMOUNT: u64 = 100_000;

#[test]
fn test_verification_failure() {
    let mut env = TestEnv::new();

    test_tampered_output_script_fails_verification(&mut env);
    test_tampered_output_script_fails_finalize(&mut env);
    test_invalid_global_proof_fails_verification(&mut env);
    test_invalid_global_proof_fails_finalize(&mut env);
    test_invalid_input_proof_fails_verification(&mut env);
    test_mismatched_global_share_fails_verification(&mut env);
    test_dropped_shares_fails_verification(&mut env);
    test_dropped_shares_fails_finalize(&mut env);
    test_untouched_psbt_fails_verification(&mut env);
    test_undecodable_response_fails_verification(&mut env);
    test_failed_verification_broadcasts_nothing(&mut env);
    test_honest_signer_still_verifies(&mut env);
}

/// Builds the fixture shared by every test in this file: a funded hot
/// sender, a watch-only account for the same mnemonic seeing the same coin
/// (the account under test, holding no key material of its own), and a built
/// but unsigned v2 PSBT paying a foreign silent-payment address.
fn fixture(env: &mut TestEnv, name: &str) -> (Account, Vec<u8>) {
    let mut sender = env.sp_account(name);
    let (_, funding_height) = env.fund_sp(&mut sender, 0.5);
    assert!(sender.balance() > 0);

    let mut account =
        watch_only_account(&format!("{name}-watch-only"), test_mnemonic(), &env.url());
    account
        .scan_blocks(Some(funding_height), Some(env.height))
        .unwrap();
    assert_eq!(account.balance(), sender.balance());

    let receiver_account = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());
    let destination = receiver_account.sp_address();

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(destination, SEND_AMOUNT);
    let coins = builder.select_coins(SEND_AMOUNT, 1000);
    assert!(!coins.is_empty());
    for coin in coins {
        builder.add_input(coin);
    }
    let unsigned = builder.generate_v2().unwrap().serialize().unwrap();

    (account, unsigned)
}

fn sign(
    account: &mut Account,
    manager: Box<dyn SigningManager>,
    unsigned: Vec<u8>,
) -> mpsc::Receiver<Notification> {
    let receiver = account.receiver().unwrap();
    account.attach_signing_manager("mock", manager).unwrap();
    let signers = wait_for_signers(&receiver, Duration::from_secs(10));
    assert_eq!(signers.len(), 1);
    let signer_id = signers[0].id.clone();
    let descriptor: Descriptor = account.get_config().descriptor.into();
    account.sign(&signer_id, descriptor, unsigned).unwrap();
    receiver
}

fn recv_signer_notification(receiver: &mpsc::Receiver<Notification>) -> SignerNotification {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for signer notification"
        );
        match receiver.recv_timeout(remaining) {
            Ok(Notification::Signer(
                notification @ (SignerNotification::PsbtVerified { .. }
                | SignerNotification::PsbtVerificationFailed { .. }),
            )) => return notification,
            Ok(_) => continue,
            Err(e) => panic!("notification channel error while waiting for signed psbt: {e}"),
        }
    }
}

fn sign_expect_verified(
    account: &mut Account,
    manager: Box<dyn SigningManager>,
    unsigned: Vec<u8>,
) -> Vec<u8> {
    match recv_signer_notification(&sign(account, manager, unsigned)) {
        SignerNotification::PsbtVerified { psbt, .. } => psbt,
        other => panic!("expected PsbtVerified, got {other:?}"),
    }
}

fn sign_expect_verification_failed(
    account: &mut Account,
    manager: Box<dyn SigningManager>,
    unsigned: Vec<u8>,
) -> String {
    match recv_signer_notification(&sign(account, manager, unsigned)) {
        SignerNotification::PsbtVerificationFailed { reason, .. } => reason,
        other => panic!("expected PsbtVerificationFailed, got {other:?}"),
    }
}

/// A verification failure the account or `finalize` reported, distinguishable
/// from an ordinary satisfaction failure (`AccountError::Finalize`): the
/// signer lied, rather than an input that could not be satisfied.
fn is_verification_error(result: &Result<bitcoin::Transaction, AccountError>) -> bool {
    matches!(
        result,
        Err(AccountError::Bip375(_)) | Err(AccountError::PsbtV2)
    )
}

fn test_tampered_output_script_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "tampered_output_script_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let manager =
        mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::OutputScript);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);

    assert!(!reason.is_empty());
}

fn test_tampered_output_script_fails_finalize(env: &mut TestEnv) {
    let _guard = abort_after(
        "tampered_output_script_fails_finalize",
        Duration::from_secs(180),
    );
    let (account, unsigned) = fixture(env, "sender");

    let tampered = sign_and_tamper(
        test_mnemonic(),
        Network::Regtest,
        unsigned,
        &Tamper::OutputScript,
    )
    .unwrap();
    let result = account.finalize(&tampered);

    assert!(is_verification_error(&result));
}

fn test_invalid_global_proof_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "invalid_global_proof_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let manager = mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::GlobalProof);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);

    assert!(!reason.is_empty());
}

fn test_invalid_global_proof_fails_finalize(env: &mut TestEnv) {
    let _guard = abort_after(
        "invalid_global_proof_fails_finalize",
        Duration::from_secs(180),
    );
    let (account, unsigned) = fixture(env, "sender");

    let tampered = sign_and_tamper(
        test_mnemonic(),
        Network::Regtest,
        unsigned,
        &Tamper::GlobalProof,
    )
    .unwrap();
    let result = account.finalize(&tampered);

    assert!(is_verification_error(&result));
}

fn test_invalid_input_proof_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "invalid_input_proof_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let manager = mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::InputProof);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);

    assert!(!reason.is_empty());
}

fn test_mismatched_global_share_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "mismatched_global_share_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let manager = mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::GlobalShare);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);

    assert!(!reason.is_empty());
}

fn test_dropped_shares_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "dropped_shares_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let manager = mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::DropShares);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);

    assert!(!reason.is_empty());
}

fn test_dropped_shares_fails_finalize(env: &mut TestEnv) {
    let _guard = abort_after("dropped_shares_fails_finalize", Duration::from_secs(180));
    let (account, unsigned) = fixture(env, "sender");

    let tampered = sign_and_tamper(
        test_mnemonic(),
        Network::Regtest,
        unsigned,
        &Tamper::DropShares,
    )
    .unwrap();
    let result = account.finalize(&tampered);

    assert!(is_verification_error(&result));
}

fn test_untouched_psbt_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "untouched_psbt_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let hook: SpSignHook = Box::new(Ok);
    let manager = mock_sp_manager_with_hook(test_mnemonic(), Network::Regtest, hook);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned.clone());
    assert!(!reason.is_empty());

    // The plain BIP375 `validate` alone would pass an unstarted build; only
    // `verify_signed`'s completeness check catches a signer that did nothing.
    let finalize_result = account.finalize(&unsigned);
    assert!(is_verification_error(&finalize_result));
}

fn test_undecodable_response_fails_verification(env: &mut TestEnv) {
    let _guard = abort_after(
        "undecodable_response_fails_verification",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");

    let hook: SpSignHook = Box::new(|_bytes| Ok(vec![0xff; 8]));
    let manager = mock_sp_manager_with_hook(test_mnemonic(), Network::Regtest, hook);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);
    assert!(!reason.is_empty());

    let finalize_result = account.finalize(&[0xff; 8]);
    assert!(matches!(finalize_result, Err(AccountError::PsbtDecode)));
}

fn test_failed_verification_broadcasts_nothing(env: &mut TestEnv) {
    let _guard = abort_after(
        "failed_verification_broadcasts_nothing",
        Duration::from_secs(180),
    );
    let (mut account, unsigned) = fixture(env, "sender");
    let outpoints_before: Vec<_> = account.coins().into_keys().collect();
    let balance_before = account.balance();

    let manager =
        mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::OutputScript);
    let reason = sign_expect_verification_failed(&mut account, manager, unsigned);
    assert!(!reason.is_empty());

    let coins_after = account.coins();
    let outpoints_after: Vec<_> = coins_after.keys().copied().collect();
    assert_eq!(outpoints_after, outpoints_before);
    assert_eq!(account.balance(), balance_before);
    assert!(
        coins_after.values().all(|entry| entry.is_spendable()),
        "no unconfirmed spend must be recorded on a failed verification"
    );
    assert!(
        env.bitcoind.client.get_raw_mempool().unwrap().0.is_empty(),
        "a failed verification must never reach broadcast"
    );
}

fn test_honest_signer_still_verifies(env: &mut TestEnv) {
    let _guard = abort_after("honest_signer_still_verifies", Duration::from_secs(180));
    let (mut account, unsigned) = fixture(env, "sender");

    let manager = mock_sp_manager_tampering(test_mnemonic(), Network::Regtest, Tamper::None);
    let signed_bytes = sign_expect_verified(&mut account, manager, unsigned);

    let tx = account.finalize(&signed_bytes).unwrap();
    assert!(!tx.input.is_empty());
}
