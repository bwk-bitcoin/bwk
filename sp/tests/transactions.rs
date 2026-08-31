//! Transaction building and signing tests for bwk-sp.
//!
//! Covers 16 spending scenarios:
//! - SP-only inputs (to SP, taproot, segwit, and mixed outputs)
//! - Mixed SP + BIP32 inputs (to standard outputs)
//! - Mixed SP + BIP32 inputs (to SP outputs, regression for partial secret)

mod common;

use bitcoin::Network;
use bwk::bwk_electrum::coin_store::PaymentType;
use bwk_sign::HotSigner;
use bwk_sp::account::recipient::{SpRecipientAddress, TxBuilderSpExt};
use bwk_tx::{transaction::Amount, Recipient};

use common::{test_mnemonic, test_mnemonic_2, TestEnv};

#[test]
fn test_transactions() {
    let mut env = TestEnv::new();

    test_insufficient_funds(&env);
    test_bip32_only_sp_change_bookkeeping(&mut env);
    test_standard_output_ownership_is_counted_once(&mut env);
    test_drain(&mut env);
    test_sp_to_sp_self(&mut env);
    test_sp_to_sp_other(&mut env);
    test_sp_to_taproot(&mut env);
    test_sp_to_segwit(&mut env);
    test_sp_to_mixed_sp_taproot(&mut env);
    test_sp_to_mixed_sp_segwit(&mut env);
    test_multi_sp_to_mixed_sp_taproot(&mut env);
    test_multi_sp_to_taproot(&mut env);
    test_mixed_sp_taproot_to_taproot(&mut env);
    test_mixed_sp_taproot_to_segwit(&mut env);
    test_mixed_sp_segwit_to_taproot(&mut env);
    test_mixed_sp_segwit_to_segwit(&mut env);
    test_multi_sp_inputs_to_sp_and_taproot(&mut env);
    test_sp_to_three_sp_outputs_self(&mut env);
    test_multi_sp_inputs_to_three_sp_outputs(&mut env);
    test_sp_to_sp_other_and_self(&mut env);
    test_mixed_sp_taproot_to_sp(&mut env);
    test_mixed_sp_segwit_to_sp(&mut env);
}

/// Create a drain recipient for a standard address (Amount::Max, no change).
fn drain_to(addr: bitcoin::Address) -> Recipient {
    Recipient {
        address: addr.as_unchecked().clone(),
        amount: Amount::Max(None),
        label: None,
        origin: None,
        descriptor: None,
    }
}

/// Empty account cannot build a transaction.
fn test_insufficient_funds(env: &TestEnv) {
    let account = env.sp_account("test-insufficient");

    assert_eq!(account.balance(), 0);
    assert!(account.coins().is_empty());

    let sp_address = account.sp_address();
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(sp_address, 100_000);

    let coins = builder.select_coins(100_000, 1000);
    assert!(coins.is_empty());
    assert!(builder.generate().is_err());
}

/// BIP32-only inputs with automatic SP change retain the change metadata until
/// scanning records the SP coin and its spend tweak.
fn test_bip32_only_sp_change_bookkeeping(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test-bip32-only-sp-change");
    env.add_taproot_sub_account(&mut account);
    env.add_segwit_sub_account(&mut account);
    let coin = env.create_taproot_coin(0.1);
    let funding_tx = bwk_utils::test::get_tx(&mut env.bitcoind.client, coin.outpoint.txid).unwrap();
    account.sub_accounts()[0].record_unconfirmed_spend(&funding_tx);
    let input_value = coin.txout.value;

    let external_signer =
        HotSigner::new_taproot_from_mnemonics(Network::Regtest, test_mnemonic_2()).unwrap();
    let (external, _) = external_signer.taproot_receive_address_and_key(0);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(external.clone(), 100_000);
    builder.add_input(coin);

    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    let change: u64 = tx
        .output
        .iter()
        .find(|output| output.script_pubkey != external.script_pubkey())
        .unwrap()
        .value
        .to_sat();
    let txid = account.record_unconfirmed_spend(&tx).unwrap();

    let entry = account
        .tx_history()
        .into_iter()
        .find(|entry| entry.txid == txid)
        .unwrap();
    assert_eq!(entry.change, change);
    assert_eq!(entry.tx.unwrap(), tx);
    assert!(!account.sub_accounts()[1]
        .tx_history()
        .iter()
        .any(|entry| entry.txid() == txid));
    assert!(account.coins().is_empty());
    let payment = account
        .payment_history()
        .into_iter()
        .find(|payment| payment.txid == txid.to_string())
        .unwrap();
    assert!(matches!(payment.payment_type, PaymentType::Send));
    assert_eq!(payment.amount, input_value.to_sat() - change);

    env.broadcast_and_mine(&tx);
    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();

    let change_coins: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(outpoint, _)| outpoint.txid == txid)
        .collect();
    assert_eq!(change_coins.len(), 1);
    let (_, change_coin) = &change_coins[0];
    assert_eq!(change_coin.amount_sat(), change);
    assert!(change_coin.label().is_some());
    assert!(change_coin.is_spendable());
    let payment = account
        .payment_history()
        .into_iter()
        .find(|payment| payment.txid == txid.to_string())
        .unwrap();
    assert!(matches!(payment.payment_type, PaymentType::Send));
    assert_eq!(payment.amount, input_value.to_sat() - change);

    let mut spend_change = account.tx_builder().feerate(1000);
    spend_change.add_output(drain_to(env.taproot_addr(2)));
    let mut psbt = spend_change.generate().unwrap();
    account.sign_and_finalize(&mut psbt).unwrap();
}

fn test_standard_output_ownership_is_counted_once(env: &mut TestEnv) {
    let mut account = env.sp_account("test-standard-output-ownership");
    env.add_taproot_sub_account(&mut account);
    env.add_segwit_sub_account(&mut account);
    let coin = env.create_taproot_coin(0.1);
    let funding_tx = bwk_utils::test::get_tx(&mut env.bitcoind.client, coin.outpoint.txid).unwrap();
    account.sub_accounts()[0].record_unconfirmed_spend(&funding_tx);
    let input_value = coin.txout.value.to_sat();
    let standard_output = env.segwit_addr(0);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(standard_output.clone(), 100_000);
    builder.add_input(coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    let txid = account.record_unconfirmed_spend(&tx).unwrap();
    let output_value: u64 = tx.output.iter().map(|output| output.value.to_sat()).sum();
    let fee = input_value - output_value;
    let change: u64 = tx
        .output
        .iter()
        .filter(|output| output.script_pubkey != standard_output.script_pubkey())
        .map(|output| output.value.to_sat())
        .sum();

    let entry = account
        .tx_history()
        .into_iter()
        .find(|entry| entry.txid == txid)
        .unwrap();
    assert_eq!(entry.change, change);
    assert!(account.sub_accounts()[0]
        .tx_history()
        .iter()
        .any(|entry| entry.txid() == txid));
    assert!(account.sub_accounts()[1]
        .tx_history()
        .iter()
        .any(|entry| entry.txid() == txid));
    let payment = account
        .payment_history()
        .into_iter()
        .find(|payment| payment.txid == txid.to_string())
        .unwrap();
    assert!(matches!(payment.payment_type, PaymentType::Send));
    assert_eq!(payment.amount, fee);
}

/// Drain uses all UTXOs.
fn test_drain(env: &mut TestEnv) {
    let mut account = env.sp_account("test-drain");

    // Fund with 2 separate SP outputs
    env.fund_sp(&mut account, 0.1);
    env.fund_sp(&mut account, 0.1);
    assert_eq!(account.coins().len(), 2);

    let mut builder = account.tx_builder().feerate(1000);
    let mut drain_recip = SpRecipientAddress::from_sp(account.sp_address(), 0, Network::Regtest);
    drain_recip.amount = Amount::Max(None);
    builder.add_output(drain_recip);
    builder.drain_inputs();

    let psbt = builder.generate().unwrap();
    assert_eq!(psbt.unsigned_tx.input.len(), 2);
}

/// SP -> SP (self): send to own address, verify change.
fn test_sp_to_sp_self(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test-self");
    env.fund_sp(&mut account, 0.5);

    let original_balance = account.balance();
    assert!(original_balance > 0);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 100_000);
    let coins = builder.select_coins(100_000, 1000);
    assert!(!coins.is_empty());
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    // Rescan to detect change outputs
    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert_eq!(
        new_outputs.len(),
        2,
        "self-send must detect both receive and change outputs"
    );
}

/// SP -> SP (other wallet): verify recipient detects the output.
fn test_sp_to_sp_other(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut sender = env.sp_account_with_mnemonic("sender", test_mnemonic());
    let mut receiver = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    assert_ne!(
        sender.sp_address().to_string(),
        receiver.sp_address().to_string()
    );

    env.fund_sp(&mut sender, 0.5);

    let send_amount = 100_000u64;
    let mut builder = sender.tx_builder().feerate(1000);
    builder.send_to_sp(receiver.sp_address(), send_amount);
    let coins = builder.select_coins(send_amount, 1000);
    assert!(!coins.is_empty());
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = sender.sign_and_finalize(&mut psbt).unwrap();
    let txid = tx.compute_txid();
    env.broadcast_and_mine(&tx);

    // Receiver scans and finds the output
    receiver
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let receiver_coins = receiver.coins();
    assert_eq!(receiver_coins.len(), 1);
    let received_op = receiver_coins.keys().next().unwrap();
    assert_eq!(received_op.txid, txid);
    assert!(receiver.balance() >= send_amount);
}

/// SP -> taproot address.
fn test_sp_to_taproot(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.5);

    let tr_addr = env.taproot_addr(0);
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(tr_addr, 100_000);
    let coins = builder.select_coins(100_000, 1000);
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP -> segwit (P2WPKH) address.
fn test_sp_to_segwit(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.5);

    let sw_addr = env.segwit_addr(0);
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(sw_addr, 100_000);
    let coins = builder.select_coins(100_000, 1000);
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP -> SP + taproot (mixed outputs).
fn test_sp_to_mixed_sp_taproot(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.5);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to(env.taproot_addr(0), 50_000);
    let coins = builder.select_coins(100_000, 1000);
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert!(
        !new_outputs.is_empty(),
        "scanner must detect SP output from self-send"
    );
}

/// SP -> SP + segwit (mixed outputs).
fn test_sp_to_mixed_sp_segwit(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.5);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to(env.segwit_addr(0), 50_000);
    let coins = builder.select_coins(100_000, 1000);
    for c in coins {
        builder.add_input(c);
    }
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert!(
        !new_outputs.is_empty(),
        "scanner must detect SP output from self-send"
    );
}

/// 2 SP -> SP + taproot (multiple SP inputs, mixed outputs).
fn test_multi_sp_to_mixed_sp_taproot(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.fund_sp(&mut account, 0.1);
    assert_eq!(account.coins().len(), 2);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to(env.taproot_addr(0), 50_000);
    builder.drain_inputs();
    let mut psbt = builder.generate().unwrap();
    assert_eq!(psbt.unsigned_tx.input.len(), 2);

    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert!(
        !new_outputs.is_empty(),
        "scanner must detect SP output from self-send"
    );
}

/// 2 SP -> taproot (drain to standard output).
fn test_multi_sp_to_taproot(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.fund_sp(&mut account, 0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(env.taproot_addr(0), 50_000);
    builder.drain_inputs();
    let mut psbt = builder.generate().unwrap();
    assert_eq!(psbt.unsigned_tx.input.len(), 2);

    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP + taproot -> taproot (drain, no SP change).
fn test_mixed_sp_taproot_to_taproot(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_taproot_sub_account(&mut account);
    let tr_coin = env.create_taproot_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.add_output(drain_to(env.taproot_addr(1)));
    builder.drain_inputs();
    builder.add_input(tr_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP + taproot -> segwit (drain, no SP change).
fn test_mixed_sp_taproot_to_segwit(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_taproot_sub_account(&mut account);
    let tr_coin = env.create_taproot_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.add_output(drain_to(env.segwit_addr(0)));
    builder.drain_inputs();
    builder.add_input(tr_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP + segwit -> taproot (drain, no SP change).
fn test_mixed_sp_segwit_to_taproot(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_segwit_sub_account(&mut account);
    let sw_coin = env.create_segwit_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.add_output(drain_to(env.taproot_addr(0)));
    builder.drain_inputs();
    builder.add_input(sw_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// SP + segwit -> segwit (drain, no SP change).
fn test_mixed_sp_segwit_to_segwit(env: &mut TestEnv) {
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_segwit_sub_account(&mut account);
    let sw_coin = env.create_segwit_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.add_output(drain_to(env.segwit_addr(1)));
    builder.drain_inputs();
    builder.add_input(sw_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);
}

/// 3 SP inputs -> SP + taproot (drain multiple SP coins).
fn test_multi_sp_inputs_to_sp_and_taproot(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test-multi-in");

    // Fund with 3 separate SP outputs
    env.fund_sp(&mut account, 0.1);
    env.fund_sp(&mut account, 0.1);
    env.fund_sp(&mut account, 0.1);
    assert_eq!(account.coins().len(), 3);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to(env.taproot_addr(10), 50_000);
    builder.drain_inputs();

    let mut psbt = builder.generate().unwrap();
    assert_eq!(psbt.unsigned_tx.input.len(), 3);

    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    let txid = tx.compute_txid();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == txid)
        .collect();
    // 1 SP receive + 1 SP change (taproot output not ours)
    assert_eq!(
        new_outputs.len(),
        2,
        "3-input tx must detect both SP receive and change"
    );
}

/// SP -> 3 SP outputs to self (2 receive + 1 change, same scan key, k=0..2).
fn test_sp_to_three_sp_outputs_self(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test-3sp-self");
    env.fund_sp(&mut account, 0.5);

    let mut builder = account.tx_builder().feerate(1000);
    // 2 explicit outputs to receive address + auto change = 3 SP outputs
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to_sp(account.sp_address(), 60_000);
    let coins = builder.select_coins(110_000, 1000);
    assert!(!coins.is_empty());
    for c in coins {
        builder.add_input(c);
    }

    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    let txid = tx.compute_txid();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == txid)
        .collect();
    // 2 receive (no label) + 1 change (change label) = 3 SP outputs
    assert_eq!(
        new_outputs.len(),
        3,
        "self-send with 3 SP outputs (2 receive + 1 change) must all be detected"
    );
}

/// 2 SP inputs -> 3 SP outputs to self (multiple inputs, multiple outputs).
fn test_multi_sp_inputs_to_three_sp_outputs(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test-multi-3sp");
    env.fund_sp(&mut account, 0.3);
    env.fund_sp(&mut account, 0.3);
    assert_eq!(account.coins().len(), 2);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.send_to_sp(account.sp_address(), 60_000);
    builder.drain_inputs();

    let mut psbt = builder.generate().unwrap();
    assert_eq!(psbt.unsigned_tx.input.len(), 2);

    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    let txid = tx.compute_txid();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == txid)
        .collect();
    assert_eq!(
        new_outputs.len(),
        3,
        "2 SP inputs to 3 SP outputs (2 receive + 1 change) must all be detected"
    );
}

/// SP -> SP other + SP self + SP change (3 outputs, 2 scan-key groups).
fn test_sp_to_sp_other_and_self(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut sender = env.sp_account_with_mnemonic("sender", test_mnemonic());
    let mut receiver = env.sp_account_with_mnemonic("receiver", test_mnemonic_2());

    env.fund_sp(&mut sender, 0.5);

    let mut builder = sender.tx_builder().feerate(1000);
    builder.send_to_sp(receiver.sp_address(), 50_000);
    builder.send_to_sp(sender.sp_address(), 60_000);
    let coins = builder.select_coins(110_000, 1000);
    assert!(!coins.is_empty());
    for c in coins {
        builder.add_input(c);
    }

    let mut psbt = builder.generate().unwrap();
    let tx = sender.sign_and_finalize(&mut psbt).unwrap();
    let txid = tx.compute_txid();
    env.broadcast_and_mine(&tx);

    // Sender scans: should find self-receive + change
    sender
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let sender_new: Vec<_> = sender
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == txid)
        .collect();
    assert_eq!(
        sender_new.len(),
        2,
        "sender must detect self-receive and change outputs"
    );

    // Receiver scans: should find the output sent to them
    receiver
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let receiver_new: Vec<_> = receiver
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == txid)
        .collect();
    assert_eq!(
        receiver_new.len(),
        1,
        "receiver must detect exactly 1 output"
    );
    assert!(receiver.balance() >= 50_000);
}

/// SP + taproot -> SP address (drain, triggers partial secret with mixed inputs).
///
/// Regression test: before the fix, `compute_partial_secret()` failed with
/// `CoinNotFound` because it tried to look up BIP32 coins in the SP coin store.
fn test_mixed_sp_taproot_to_sp(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_taproot_sub_account(&mut account);
    let tr_coin = env.create_taproot_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.drain_inputs();
    builder.add_input(tr_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert!(
        !new_outputs.is_empty(),
        "scanner must detect SP output from mixed SP+taproot send"
    );
}

/// SP + segwit -> SP address (drain, triggers partial secret with mixed inputs).
///
/// Regression test: same as above but with segwit BIP32 coins.
fn test_mixed_sp_segwit_to_sp(env: &mut TestEnv) {
    let start_height = env.next_scan_height();
    let mut account = env.sp_account("test");
    env.fund_sp(&mut account, 0.1);
    env.add_segwit_sub_account(&mut account);
    let sw_coin = env.create_segwit_coin(0.1);

    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to_sp(account.sp_address(), 50_000);
    builder.drain_inputs();
    builder.add_input(sw_coin);
    let mut psbt = builder.generate().unwrap();
    let tx = account.sign_and_finalize(&mut psbt).unwrap();
    env.broadcast_and_mine(&tx);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let new_outputs: Vec<_> = account
        .coins()
        .into_iter()
        .filter(|(op, _)| op.txid == tx.compute_txid())
        .collect();
    assert!(
        !new_outputs.is_empty(),
        "scanner must detect SP output from mixed SP+segwit send"
    );
}
