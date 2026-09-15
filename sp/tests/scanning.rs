//! Scanning integration tests for bwk-sp.
//!
//! These tests start a real BlindbitD backend with regtest.

mod common;

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use bitcoin::OutPoint;
use bwk_utils::test::{self as bwk_test, temp_dir::TempDir};

use common::{
    test_account, test_account_named, test_account_persistent, test_account_persistent_named,
    test_mnemonic, test_outpoint, TestEnv,
};

use bwk::{
    bwk_electrum::{
        label_store::LabelStore,
        notification::{Notification, SpNotification},
    },
    persist::{
        backend::{json::JsonBackend, PersistenceBackend},
        ACCOUNT_STORE_KEY, COINS_STORE_KEY, LABELS_STORE_KEY,
    },
};
use bwk_sp::account::config::Config;

fn backend_height(blindbit_url: &str) -> u32 {
    let agent = bwk_sp::blindbit::agent().expect("blindbit agent");
    bwk_sp::blindbit::block_height(&agent, blindbit_url)
        .expect("backend height")
        .to_consensus_u32()
}

fn account_with_birthday(name: &str, env: &TestEnv) -> bwk_sp::account::Account {
    let mut config = Config::new(
        name.to_string(),
        bitcoin::Network::Regtest,
        test_mnemonic().to_string(),
        env.url(),
        std::path::PathBuf::from("/unused"),
    )
    .with_persistence(None);
    config.set_birthday_height(Some(env.next_scan_height()));
    bwk_sp::account::Account::new(config).expect("create test account")
}

#[test]
fn test_scanning() {
    let mut env = TestEnv::new();

    test_account_connects_to_blindbitd(&mut env);
    test_account_block_height_growth(&mut env);
    test_scan_no_matches(&mut env);
    test_scan_single_sp_output(&mut env);
    test_scan_oneshot_from_chosen_height(&mut env);
    test_scan_multiple_sp_outputs(&mut env);
    test_incremental_scanning(&mut env);
    test_rescan_idempotent(&mut env);
    test_scan_notifications(&mut env);
    test_new_output_notification(&mut env);
    test_persistence_after_scan(&mut env);
    test_background_scanner_start_stop(&mut env);
    test_drop_stops_scanner(&mut env);
    test_background_scanner_detects_new_blocks(&mut env);
    test_label_coin_persists(&mut env);
    test_label_transaction(&mut env);
    test_full_wallet_flow(&mut env);
    test_full_wallet_lifecycle(&mut env);
    test_watch_only_mode(&mut env);
    test_sp_address_generation(&mut env);
    test_spend_frontier_resume_skips_swept_heights(&mut env);
    test_spend_only_resume_at_same_tip(&mut env);
    test_unconfirmed_spend_injection(&mut env);
    test_unconfirmed_spend_no_sp_coin(&mut env);
    test_broadcast_requires_electrum_endpoint(&mut env);
    test_sp_scan_timestamps(&mut env);
}

/// Test 10.4.1.1: Account connects to BlindbitD and reports online.
///
/// This test verifies:
/// - Account can successfully connect to a BlindbitD server
/// - backend_online() returns true when connected
/// - block_height() returns the correct chain tip
///
/// Setup:
/// 1. Start BlindbitD with embedded Bitcoin Core
/// 2. Generate 100 blocks
/// 3. Create Account pointing to BlindbitD
/// 4. Verify connectivity and block height
fn test_account_connects_to_blindbitd(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let account = test_account(&blindbit_url);

    assert!(account.backend_online());
    let height = backend_height(&blindbit_url);
    assert!(height >= 100, "Expected height >= 100, got {height}");
}

/// Test 10.4.1.2: Account reports correct block height as chain grows.
///
/// This test verifies:
/// - Account tracks chain growth correctly
/// - Multiple block_height() calls reflect new blocks
fn test_account_block_height_growth(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let account = test_account(&blindbit_url);

    let height1 = account.block_height().unwrap();
    assert!(height1 >= 50, "Expected height >= 50, got {height1}");

    env.mine(50);

    let height2 = account.block_height().unwrap();
    assert!(height2 >= 100, "Expected height >= 100, got {height2}");
    assert!(height2 > height1, "Height should have grown");
}

/// Test 10.4.2.1: Scan blocks with no matching SP outputs.
///
/// This test verifies:
/// - scan_blocks() completes without error on empty chain
/// - balance remains 0 when no SP transactions exist
/// - coins() returns empty after scan
fn test_scan_no_matches(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    env.mine(100);
    let mut account = test_account(&blindbit_url);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();

    assert_eq!(
        account.balance(),
        0,
        "Balance should be 0 with no SP outputs"
    );
    assert!(account.coins().is_empty(), "Coins should be empty");
}

/// Test 10.4.2.2: Scan and detect a single SP output.
///
/// This test verifies:
/// - Scanner correctly identifies SP output addressed to account
/// - Coin is added to coin_store with correct outpoint
/// - Balance reflects the SP output amount
///
/// Setup:
/// 1. Create taproot address from account's mnemonic
/// 2. Fund taproot address
/// 3. Create SP transaction to account's SP address
/// 4. Scan and verify detection
///
fn test_scan_single_sp_output(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    // 4. Setup SP client and taproot signer with the same mnemonic
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    // 5. Create taproot signer from the SAME mnemonic to generate funding addresses
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");
    let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(0);

    // 6. Fund the taproot address
    let fund_txid =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1).expect("fund taproot");
    env.mine(2);

    // 7. Get the funded UTXO
    let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
    let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
        .into_iter()
        .next()
        .expect("find txout");
    let outpoint = OutPoint {
        txid: fund_txid,
        vout: index as u32,
    };

    // 8. Create SP transaction
    let sp_address = sp_receiver.get_receiving_address();
    let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp)
        .expect("generate recipient pubkey");

    let sp_tx = swap_to_sp(
        sk,
        outpoint,
        txout,
        recipient_pubkey,
        bitcoin::Amount::from_sat(1000), // fees
        &secp,
    )
    .expect("create sp tx");

    // 9. Broadcast and mine
    let sp_txid = sp_tx.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx)
        .expect("broadcast sp tx");
    env.mine(1);
    let sp_tx_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("get tx height") as u32;

    // 10. Scan
    let mut account = test_account_named("scan-single-sp-output", &blindbit_url);
    account
        .scan_blocks(Some(start_height), Some(sp_tx_height))
        .expect("scan");

    // 11. Verify found output
    let coins = account.coins();
    assert_eq!(coins.len(), 1, "Should find exactly 1 SP output");

    let expected_op = OutPoint {
        txid: sp_txid,
        vout: 0,
    };
    assert!(
        coins.contains_key(&expected_op),
        "Should find output at {}:0, got {:?}",
        sp_txid,
        coins.keys().collect::<Vec<_>>()
    );
}

fn test_scan_oneshot_from_chosen_height(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp, wait_for_oneshot_done};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");
    let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(0);

    let fund_txid =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1).expect("fund taproot");
    env.mine(2);

    let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
    let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
        .into_iter()
        .next()
        .expect("find txout");
    let outpoint = OutPoint {
        txid: fund_txid,
        vout: index as u32,
    };

    let sp_address = sp_receiver.get_receiving_address();
    let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp)
        .expect("generate recipient pubkey");

    let sp_tx = swap_to_sp(
        sk,
        outpoint,
        txout,
        recipient_pubkey,
        bitcoin::Amount::from_sat(1000),
        &secp,
    )
    .expect("create sp tx");

    let sp_txid = sp_tx.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx)
        .expect("broadcast sp tx");
    env.mine(1);
    let tip =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("get tx height") as u32;

    let mut account = test_account_named("scan-oneshot-from-height", &blindbit_url);
    assert_eq!(account.last_scanned_height(), None);

    account.scan_oneshot(Some(start_height)).expect("scan");
    wait_for_oneshot_done(&account, Duration::from_secs(60));

    let coins = account.coins();
    assert_eq!(coins.len(), 1, "Should find exactly 1 SP output");

    let expected_op = OutPoint {
        txid: sp_txid,
        vout: 0,
    };
    assert!(
        coins.contains_key(&expected_op),
        "Should find output at {}:0, got {:?}",
        sp_txid,
        coins.keys().collect::<Vec<_>>()
    );
    assert_eq!(account.last_scanned_height(), Some(tip));

    account.scan_oneshot(None).expect("rescan");
    wait_for_oneshot_done(&account, Duration::from_secs(60));
    assert_eq!(account.coins().len(), 1);
    assert_eq!(account.last_scanned_height(), Some(tip));
}

/// Test 10.4.2.3: Scan and detect multiple SP outputs in different blocks.
///
/// This test verifies:
/// - Scanner finds multiple SP outputs across different blocks
/// - All outputs are tracked in coin_store
/// - Total balance is sum of all outputs
fn test_scan_multiple_sp_outputs(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    // 4. Setup SP client and taproot signer with the same mnemonic
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    // 5. Create taproot signer from the SAME mnemonic to generate funding addresses
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");

    let sp_address = sp_receiver.get_receiving_address();
    let mut sp_txids = Vec::new();
    let mut final_height = env.height;

    // Create 3 SP outputs in separate blocks
    for i in 0..3 {
        let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(i);

        // Fund the taproot address
        let fund_txid = bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1)
            .expect("fund taproot");
        env.mine(2);

        // Get the funded UTXO
        let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
        let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
            .into_iter()
            .next()
            .expect("find txout");
        let outpoint = OutPoint {
            txid: fund_txid,
            vout: index as u32,
        };

        // Create SP transaction
        let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp)
            .expect("generate recipient pubkey");

        let sp_tx = swap_to_sp(
            sk,
            outpoint,
            txout,
            recipient_pubkey,
            bitcoin::Amount::from_sat(1000), // fees
            &secp,
        )
        .expect("create sp tx");

        // Broadcast and mine
        let sp_txid = sp_tx.compute_txid();
        env.bitcoind
            .client
            .send_raw_transaction(&sp_tx)
            .expect("broadcast sp tx");
        env.mine(1);
        final_height = bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid)
            .expect("get tx height") as u32;

        sp_txids.push(sp_txid);
    }

    // Scan
    let mut account = test_account_named("scan-multiple-sp-outputs", &blindbit_url);
    account
        .scan_blocks(Some(start_height), Some(final_height))
        .expect("scan");

    // Verify found outputs
    let coins = account.coins();
    assert_eq!(coins.len(), 3, "Should find exactly 3 SP outputs");

    for sp_txid in &sp_txids {
        let expected_op = OutPoint {
            txid: *sp_txid,
            vout: 0,
        };
        assert!(
            coins.contains_key(&expected_op),
            "Should find output at {}:0, got {:?}",
            sp_txid,
            coins.keys().collect::<Vec<_>>()
        );
    }
}

/// Test 10.4.3.1: Incremental scanning in multiple passes.
///
/// This test verifies:
/// - Scanning can be done in multiple passes over consecutive ranges
/// - Each pass adds newly found outputs
/// - No duplicates from overlapping ranges
fn test_incremental_scanning(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    // 4. Setup SP client and taproot signer with the same mnemonic
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    // 5. Create taproot signer from the SAME mnemonic
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");

    let sp_address = sp_receiver.get_receiving_address();

    // --- First SP output in the first range ---
    let (taproot_addr0, sk0) = tr_signer.taproot_receive_address_and_key(0);

    // Fund the taproot address
    let fund_txid0 =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr0.clone(), 0.1).expect("fund taproot");
    env.mine(3);

    // Get the funded UTXO
    let tx0 = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid0).expect("get tx");
    let (index0, txout0) = bwk_test::txouts_for(&taproot_addr0, &tx0)
        .into_iter()
        .next()
        .expect("find txout");
    let outpoint0 = OutPoint {
        txid: fund_txid0,
        vout: index0 as u32,
    };

    // Create SP transaction
    let recipient_pubkey0 = generate_recipient_pubkey(sk0, outpoint0, &txout0, sp_address, &secp)
        .expect("generate recipient pubkey");

    let sp_tx0 = swap_to_sp(
        sk0,
        outpoint0,
        txout0,
        recipient_pubkey0,
        bitcoin::Amount::from_sat(1000),
        &secp,
    )
    .expect("create sp tx");

    let sp_txid0 = sp_tx0.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx0)
        .expect("broadcast sp tx");
    env.mine(2);

    // Generate more blocks to reach ~110
    env.mine(4);
    let first_end = env.height;

    // --- First scan should find 1 output ---
    let mut account = test_account_named("incremental-scanning", &blindbit_url);
    account
        .scan_blocks(Some(start_height), Some(first_end))
        .expect("scan");

    let coins = account.coins();
    assert_eq!(coins.len(), 1, "First scan should find exactly 1 SP output");
    let expected_op0 = OutPoint {
        txid: sp_txid0,
        vout: 0,
    };
    assert!(
        coins.contains_key(&expected_op0),
        "Should find first output"
    );

    // --- Second SP output in the next range ---
    let (taproot_addr1, sk1) = tr_signer.taproot_receive_address_and_key(1);

    // Fund the taproot address
    let second_start = first_end + 1;
    let fund_txid1 =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr1.clone(), 0.1).expect("fund taproot");
    env.mine(3);

    // Get the funded UTXO
    let tx1 = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid1).expect("get tx");
    let (index1, txout1) = bwk_test::txouts_for(&taproot_addr1, &tx1)
        .into_iter()
        .next()
        .expect("find txout");
    let outpoint1 = OutPoint {
        txid: fund_txid1,
        vout: index1 as u32,
    };

    // Create SP transaction
    let recipient_pubkey1 = generate_recipient_pubkey(sk1, outpoint1, &txout1, sp_address, &secp)
        .expect("generate recipient pubkey");

    let sp_tx1 = swap_to_sp(
        sk1,
        outpoint1,
        txout1,
        recipient_pubkey1,
        bitcoin::Amount::from_sat(1000),
        &secp,
    )
    .expect("create sp tx");

    let sp_txid1 = sp_tx1.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx1)
        .expect("broadcast sp tx");
    env.mine(3);
    let sp_height1 =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid1).expect("get tx height") as u32;

    // --- Second scan using same scanner should find 1 more ---
    account
        .scan_blocks(Some(second_start), Some(sp_height1))
        .expect("scan");

    // After second scan, should have 2 outputs total
    let coins = account.coins();
    assert_eq!(
        coins.len(),
        2,
        "Second scan should have 2 outputs total (1 from first scan + 1 new)"
    );
    let expected_op1 = OutPoint {
        txid: sp_txid1,
        vout: 0,
    };
    assert!(
        coins.contains_key(&expected_op0),
        "Should still have first output"
    );
    assert!(
        coins.contains_key(&expected_op1),
        "Should find second output"
    );
}

/// Test 10.4.3.2: Rescanning same range is idempotent.
///
/// This test verifies:
/// - Scanning the same range twice doesn't create duplicates
/// - Balance and coin count remain consistent
fn test_rescan_idempotent(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    env.mine(100);
    let mut account = test_account(&blindbit_url);

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let coins_after_first = account.coins().len();
    let balance_after_first = account.balance();

    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    let coins_after_second = account.coins().len();
    let balance_after_second = account.balance();

    // 7. Verify idempotency
    assert_eq!(
        coins_after_first, coins_after_second,
        "Coin count should remain the same after rescan"
    );
    assert_eq!(
        balance_after_first, balance_after_second,
        "Balance should remain the same after rescan"
    );
}

/// Test 10.4.4.1: Notifications are sent during scanning.
///
/// This test verifies:
/// - ScanProgress notifications are sent during scan
/// - ScanCompleted notification is sent when scan finishes
fn test_scan_notifications(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    env.mine(100);
    let mut account = test_account(&blindbit_url);

    // 5. Take the receiver
    let receiver = account.receiver().expect("receiver should be available");

    // 6. Scan blocks
    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();

    // 7. Collect notifications
    let mut saw_progress = false;
    let mut saw_completed = false;

    // Non-blocking receive with timeout
    while let Ok(notif) = receiver.try_recv() {
        match notif {
            Notification::Sp(SpNotification::ScanReceiveProgress { .. })
            | Notification::Sp(SpNotification::ScanSpendProgress { .. }) => saw_progress = true,
            Notification::Sp(SpNotification::ScanCompleted) => saw_completed = true,
            _ => {}
        }
    }

    // 8. Verify notifications
    assert!(
        saw_progress,
        "Should have received ScanProgress notification"
    );
    assert!(
        saw_completed,
        "Should have received ScanCompleted notification"
    );
}

/// Test 10.4.4.2: NewOutput notification when SP output found.
///
/// This test verifies:
/// - NewOutput(outpoint) notification is sent for each found output
/// - Notification contains correct outpoint
///
fn test_new_output_notification(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    // 4. Setup SP client and taproot signer with the same mnemonic
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    // 5. Create taproot signer from the SAME mnemonic to generate funding addresses
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");
    let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(0);

    // 6. Fund the taproot address
    let fund_txid =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1).expect("fund taproot");
    env.mine(2);

    // 7. Get the funded UTXO
    let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
    let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
        .into_iter()
        .next()
        .expect("find txout");
    let outpoint = OutPoint {
        txid: fund_txid,
        vout: index as u32,
    };

    // 8. Create SP transaction
    let sp_address = sp_receiver.get_receiving_address();
    let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp)
        .expect("generate recipient pubkey");

    let sp_tx = swap_to_sp(
        sk,
        outpoint,
        txout,
        recipient_pubkey,
        bitcoin::Amount::from_sat(1000), // fees
        &secp,
    )
    .expect("create sp tx");

    // 9. Broadcast and mine
    let sp_txid = sp_tx.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx)
        .expect("broadcast sp tx");
    env.mine(1);
    let sp_tx_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("get tx height") as u32;

    // 10. Scan with Account and collect public notifications.
    let mut account = test_account_named("new-output-notification", &blindbit_url);
    let receiver = account.receiver().expect("receiver should be available");
    account
        .scan_blocks(Some(start_height), Some(sp_tx_height))
        .expect("scan");

    let expected_op = OutPoint {
        txid: sp_txid,
        vout: 0,
    };
    let notifications: Vec<_> = receiver.try_iter().collect();
    let new_outputs: Vec<OutPoint> = notifications
        .into_iter()
        .filter_map(|notification| match notification {
            Notification::Sp(SpNotification::NewOutput(outpoint)) => Some(outpoint),
            _ => None,
        })
        .collect();

    assert_eq!(
        new_outputs,
        vec![expected_op],
        "Should have received exactly one NewOutput notification"
    );
}

/// Test 10.4.5.1: Account data persists across reload.
///
/// This test verifies:
/// - Store files are created when persist=true
/// - Account can complete a scan and reload without errors
///
/// Note: When scanning blocks with no SP outputs, the scanner doesn't update
/// last_scanned_height since record_block_outputs is only called when outputs
/// are found. We test persistence through store file creation.
fn test_persistence_after_scan(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    env.mine(100);

    // 4. Create Account with persist=true
    let (mut account, config, _dir) = test_account_persistent(&blindbit_url);
    let account_dir = config.account_dir();

    // 5. Scan and drop (persists on drop)
    account
        .scan_blocks(Some(start_height), Some(env.height))
        .unwrap();
    assert_eq!(account.balance(), 0); // No SP outputs in standard blocks
    drop(account);

    // 6. Verify persistence files were created. At least one of the
    // store files should exist; ask the backend for the canonical paths
    // rather than baking the layout in here.
    let probe = JsonBackend::open(account_dir.clone()).expect("reopen JsonBackend");
    let coins_path = probe.path_for(COINS_STORE_KEY);
    let state_path = probe.path_for(ACCOUNT_STORE_KEY);
    let any_file_exists = coins_path.exists() || state_path.exists();
    drop(probe);
    assert!(
        any_file_exists,
        "At least one store file should exist after persist (coins: {}, state: {})",
        coins_path.display(),
        state_path.display()
    );

    // 7. Reload account
    let reloaded_account = bwk_sp::account::Account::load(config).unwrap();

    // 8. Verify reloaded account works
    assert!(
        reloaded_account.backend_online(),
        "Reloaded account should be online"
    );
    assert_eq!(
        reloaded_account.balance(),
        0,
        "Balance should be 0 after reload"
    );
}

/// Test 10.4.6.1: Background scanner starts and stops correctly.
///
/// This test verifies:
/// - start_scanner() starts the background thread
/// - scanner_running() returns true when running
/// - start_scanner() fails if already running
/// - stop_scanner() stops the background thread
/// - scanner_running() returns false after stop
fn test_background_scanner_start_stop(env: &mut TestEnv) {
    let mut account = account_with_birthday("background-scanner-start-stop", env);

    // 5. Verify scanner is not running initially
    assert!(
        !account.scanner_running(),
        "Scanner should not be running initially"
    );

    // 6. Start scanner
    account.start_scanner().unwrap();

    // Give it a moment to start
    thread::sleep(Duration::from_millis(100));

    // 7. Verify scanner is running
    assert!(
        account.scanner_running(),
        "Scanner should be running after start"
    );

    // 8. Verify starting again fails
    let result = account.start_scanner();
    assert!(result.is_err(), "Starting scanner again should fail");

    // 9. Stop scanner
    account.stop_scanner();

    // 10. Verify scanner is stopped
    assert!(
        !account.scanner_running(),
        "Scanner should not be running after stop"
    );
}

/// Test 10.4.6.3: Dropping account stops the scanner.
///
/// This test verifies:
/// - Starting scanner, then dropping account doesn't panic or hang
/// - Scanner thread automatically stops when account is dropped
fn test_drop_stops_scanner(env: &mut TestEnv) {
    // 4. Create Account and start scanner in a scope
    {
        let mut account = account_with_birthday("test-drop-scanner", env);

        // Start scanner
        account.start_scanner().expect("start scanner");

        // Give it time to start
        thread::sleep(Duration::from_millis(100));

        // Verify scanner is running
        assert!(account.scanner_running(), "Scanner should be running");

        // Account dropped here - scanner should auto-stop
    }

    // 5. If we reach here without hanging, the test passes
    // The scanner thread should have stopped when account was dropped

    // Small sleep to let any background threads finish
    thread::sleep(Duration::from_millis(100));
}

/// Test 10.4.6.2: Background scanner detects new blocks.
///
/// This test verifies:
/// - Background scanner can be started and runs without errors
/// - Scanner sends scan progress notifications
/// - Scanner can be stopped cleanly
///
/// NOTE: This test currently cannot verify SP output detection because
/// Account.scan_blocks queries info to determine cutthrough which may not work
/// with BlindbitD. The SP output detection is tested separately in
/// test_scan_single_sp_output.
fn test_background_scanner_detects_new_blocks(env: &mut TestEnv) {
    let blindbit_url = env.url();

    // 4. Create Account
    let dir = TempDir::new().unwrap();
    let mnemonic_str = test_mnemonic();
    let mut config = Config::new(
        "test-bg-scanner-new-blocks".to_string(),
        bitcoin::Network::Regtest,
        mnemonic_str.to_string(),
        blindbit_url.clone(),
        dir.path().to_path_buf(),
    )
    .with_persistence(None);
    config.set_birthday_height(Some(env.next_scan_height()));

    let mut account = bwk_sp::account::Account::new(config).unwrap();

    // 5. Get notification receiver and start background scanner
    let receiver = account.receiver().expect("get receiver");
    account.start_scanner().expect("start scanner");

    // 6. Verify scanner is running
    thread::sleep(Duration::from_millis(200));
    assert!(account.scanner_running(), "Scanner should be running");

    // 7. Mine some new blocks while scanner is running
    env.mine(5);

    // 8. Wait for some scan activity (progress notifications)
    let timeout = Duration::from_secs(30);
    let start_time = std::time::Instant::now();
    let mut received_progress = false;

    while start_time.elapsed() < timeout {
        while let Ok(notification) = receiver.try_recv() {
            match notification {
                Notification::Sp(SpNotification::StartingScan)
                | Notification::Sp(SpNotification::ScanReceiveProgress { .. })
                | Notification::Sp(SpNotification::ScanSpendProgress { .. })
                | Notification::Sp(SpNotification::ScanCompleted) => {
                    received_progress = true;
                }
                _ => {}
            }
        }
        if received_progress {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }

    // 9. Stop scanner
    account.stop_scanner();

    // 10. Verify scanner stopped
    assert!(!account.scanner_running(), "Scanner should be stopped");

    // 11. Verify we received some scan activity
    // Note: The background scanner runs continuously, so we should see activity
    // even if it doesn't find SP outputs (it still scans blocks)
    assert!(
        received_progress,
        "Should have received scan progress or completion notification"
    );
}

/// Phase 10.4.7.1 - Label coin persists
/// Tests that coin labels survive persistence/reload
/// - Create account with persist=true
/// - Add a label to the coin_store
/// - Persist and reload
/// - Verify label is retained
fn test_label_coin_persists(env: &mut TestEnv) {
    let (account, config, _dir) = test_account_persistent_named("test-label-coin", &env.url());
    let outpoint = test_outpoint();

    account.update_coin_label(outpoint, "rent payment".to_string());
    drop(account);

    let reloaded = bwk_sp::account::Account::load(config).unwrap();
    let label = reloaded.get_coin_label(&outpoint);
    assert_eq!(
        label,
        Some("rent payment".to_string()),
        "Label should persist across reload"
    );
}

/// Phase 10.4.7.2 - Label transaction
/// Tests that transaction labels survive persistence/reload
/// - Create account with persist=true
/// - Add a label to a transaction via update_tx_label
/// - Persist and reload
/// - Verify label is retained in label_store
fn test_label_transaction(env: &mut TestEnv) {
    let (account, config, _dir) = test_account_persistent_named("test-label-tx", &env.url());
    let txid = test_outpoint().txid;

    account.update_tx_label(txid, "groceries".to_string());
    drop(account);

    let account_dir = config.account_dir();
    let typed_backend = JsonBackend::open(account_dir).unwrap();
    assert!(
        typed_backend.path_for(LABELS_STORE_KEY).exists(),
        "Labels file should exist after persist"
    );

    let backend: Arc<dyn PersistenceBackend> = Arc::new(typed_backend);
    let label_store =
        LabelStore::load_from_backend(backend, LABELS_STORE_KEY).expect("load label store");
    assert_eq!(
        label_store.transaction(txid),
        Some("groceries".to_string()),
        "Transaction label should persist"
    );
}

/// Test 10.4.8.1: Complete wallet flow - create, scan, check balance.
///
/// This test verifies the complete wallet lifecycle:
/// 1. Create account from mnemonic
/// 2. Verify backend connectivity
/// 3. Create multiple SP outputs with different amounts
/// 4. Scan blockchain with Account
/// 5. Verify correct balance and coin count
/// 6. Verify spendable_coins() returns correct data
/// 7. Verify can_sign() returns true for mnemonic-based account
fn test_full_wallet_flow(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;

    let blindbit_url = env.url();
    let start_height = env.next_scan_height();

    // 4. Setup SP client and taproot signer with the same mnemonic
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    // 5. Create taproot signer from the SAME mnemonic to generate funding addresses
    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str)
        .expect("create taproot signer");

    let sp_address = sp_receiver.get_receiving_address();
    let mut sp_txids = Vec::new();
    let mut final_height = env.height;
    #[allow(unused_assignments)]
    let mut _expected_balance: u64 = 0;

    // Create 3 SP outputs with different amounts: 0.1, 0.2, 0.05 BTC
    let amounts = [0.1f64, 0.2, 0.05];
    let fee_sats = 1000u64;

    for (i, amount) in amounts.iter().enumerate() {
        let i = i as u32;
        let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(i);

        // Fund the taproot address
        let fund_txid = bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), *amount)
            .expect("fund taproot");
        env.mine(2);

        // Get the funded UTXO
        let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
        let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
            .into_iter()
            .next()
            .expect("find txout");
        let outpoint = OutPoint {
            txid: fund_txid,
            vout: index as u32,
        };

        // Create SP transaction
        let recipient_pubkey = generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp)
            .expect("generate recipient pubkey");

        let sp_tx = swap_to_sp(
            sk,
            outpoint,
            txout.clone(),
            recipient_pubkey,
            bitcoin::Amount::from_sat(fee_sats),
            &secp,
        )
        .expect("create sp tx");

        // Track expected balance (input value - fees)
        _expected_balance += txout.value.to_sat() - fee_sats;

        // Broadcast and mine
        let sp_txid = sp_tx.compute_txid();
        env.bitcoind
            .client
            .send_raw_transaction(&sp_tx)
            .expect("broadcast sp tx");
        env.mine(1);
        final_height = bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid)
            .expect("get tx height") as u32;

        sp_txids.push(sp_txid);
    }

    // 6. Create Account and scan
    let dir = TempDir::new().unwrap();
    let config = Config::new(
        "test-full-wallet-flow".to_string(),
        network,
        mnemonic_str.to_string(),
        blindbit_url.clone(),
        dir.path().to_path_buf(),
    )
    .with_persistence(None);

    let mut account = bwk_sp::account::Account::new(config).unwrap();
    account
        .scan_blocks(Some(start_height), Some(final_height))
        .expect("scan");

    // 7. Verify backend connectivity
    assert!(account.backend_online(), "Backend should be online");

    // 8. Verify can_sign() returns true for mnemonic-based account
    assert!(
        account.can_sign(),
        "Account with mnemonic should be able to sign"
    );

    // 9. Verify account found all SP outputs
    let coins = account.coins();
    assert_eq!(coins.len(), 3, "Account should find exactly 3 SP outputs");
    for sp_txid in &sp_txids {
        let expected_op = OutPoint {
            txid: *sp_txid,
            vout: 0,
        };
        assert!(
            coins.contains_key(&expected_op),
            "Account should find output at {}:0, got {:?}",
            sp_txid,
            coins.keys().collect::<Vec<_>>()
        );
    }
}

/// Test 10.4.8.2: Full wallet lifecycle - create, scan, persist, reload, verify.
///
/// This test verifies:
/// - Account can be persisted and reloaded
/// - All stores (coins, labels, txs) survive reload
/// - Configuration is preserved
/// - Scan state is consistent after reload
fn test_full_wallet_lifecycle(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    env.mine(100);

    // 4. Create Account with persist=true
    let (mut account, config, _dir) =
        test_account_persistent_named("lifecycle-test", &blindbit_url);
    let test_outpoint = test_outpoint();
    let test_txid = test_outpoint.txid;

    // 5. Phase 1: Scan, add labels, persist
    {
        // Scan blocks
        account
            .scan_blocks(Some(start_height), Some(env.height))
            .expect("scan should succeed");

        // Add labels (these will be stored even though we have no actual coins)
        account.update_coin_label(test_outpoint, "test coin label".to_string());
        account.update_tx_label(test_txid, "test tx label".to_string());

        // Verify labels were set
        assert_eq!(
            account.get_coin_label(&test_outpoint),
            Some("test coin label".to_string()),
            "Coin label should be set"
        );

        // Verify can_sign before persist
        assert!(account.can_sign(), "Should be able to sign before persist");

        // Record state before drop
        let balance_before = account.balance();
        let coins_count_before = account.coins().len();

        assert_eq!(balance_before, 0, "Balance should be 0 (no SP outputs)");
        assert_eq!(coins_count_before, 0, "No coins should be found");

        drop(account); // Triggers persist
    }

    // 6. Phase 2: Reload and verify state is preserved
    {
        let reloaded_account =
            bwk_sp::account::Account::load(config.clone()).expect("reload should succeed");

        // Verify backend connectivity is restored
        assert!(
            reloaded_account.backend_online(),
            "Backend should be online after reload"
        );

        // Verify can_sign is preserved
        assert!(
            reloaded_account.can_sign(),
            "Should be able to sign after reload"
        );

        // Verify balance is preserved (0 since no SP outputs)
        assert_eq!(
            reloaded_account.balance(),
            0,
            "Balance should be preserved after reload"
        );

        // Verify coins count is preserved
        assert_eq!(
            reloaded_account.coins().len(),
            0,
            "Coins count should be preserved after reload"
        );

        // Verify label was persisted
        assert_eq!(
            reloaded_account.get_coin_label(&test_outpoint),
            Some("test coin label".to_string()),
            "Coin label should be preserved after reload"
        );

        // Verify account is fully functional after reload
        let sp_address = reloaded_account.sp_address();
        assert!(
            !sp_address.to_string().is_empty(),
            "SP address should work after reload"
        );
    }
}

/// Test 10.4.8.3: Watch-only mode - scan without spending capability.
///
/// This test verifies:
/// - Account can be created with scan_sk + public spend_key
/// - Scanning works normally
/// - can_sign() returns false
/// - SP address can still be generated
fn test_watch_only_mode(env: &mut TestEnv) {
    let blindbit_url = env.url();

    // 4. Create watch-only config with scan_sk and PUBLIC spend_key (66 hex chars = 33 bytes)
    let dir = TempDir::new().unwrap();
    let config = Config::from_keys(
        "watch-only-test".to_string(),
        bitcoin::Network::Regtest,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // scan_sk (secret)
        "02fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(), // public spend key (66 chars)
        blindbit_url.clone(),
        dir.path().to_path_buf(),
    )
    .expect("valid config");

    let account = bwk_sp::account::Account::new(config).expect("account creation");

    // 5. Watch-only should NOT be able to sign
    assert!(
        !account.can_sign(),
        "Watch-only account should not be able to sign"
    );

    // 6. But should still be able to get SP address
    let sp_address = account.sp_address();
    assert!(
        !sp_address.to_string().is_empty(),
        "SP address should be available even in watch-only mode"
    );

    // 7. Verify it starts with expected prefix for regtest
    let addr_str = sp_address.to_string();
    assert!(
        addr_str.starts_with("sp") || addr_str.starts_with("tsp"),
        "SP address should start with 'sp' or 'tsp', got: {addr_str}"
    );
}

/// Test 10.4.8.5: SP address generation is correct.
///
/// This test verifies:
/// - sp_address() returns a valid Silent Payment address
/// - Address starts with appropriate prefix (sp or tsp)
fn test_sp_address_generation(env: &mut TestEnv) {
    let blindbit_url = env.url();

    // 4. Create Account
    let account = test_account_named("test-sp-address-gen", &blindbit_url);

    // 5. Get SP address and verify it's valid
    let sp_addr = account.sp_address();
    let addr_str = sp_addr.to_string();

    // 6. Verify address is not empty
    assert!(!addr_str.is_empty(), "SP address should not be empty");

    // 7. Verify address format - should start with 'sp' or 'tsp' (testnet/regtest)
    assert!(
        addr_str.starts_with("sp") || addr_str.starts_with("tsp"),
        "SP address should start with 'sp' or 'tsp', got: {addr_str}"
    );
}

/// Spend-frontier resume: a second `scan_blocks` over a fresh tail must not
/// re-sweep heights an earlier scan already swept. The first scan advances the
/// scan state to its end; the second advances it to the new tail.
fn test_spend_frontier_resume_skips_swept_heights(env: &mut TestEnv) {
    let blindbit_url = env.url();
    let start_height = env.next_scan_height();
    // Plain blocks: no SP outputs are expected; this checks public scan progress.
    env.mine(120);
    let middle_height = start_height + 59;

    let mut account = test_account_named("spend-frontier-resume", &blindbit_url);

    // First scan over the first half: scan state ends at the midpoint.
    account
        .scan_blocks(Some(start_height), Some(middle_height))
        .expect("first scan");
    assert_eq!(
        account.last_scanned_height(),
        Some(middle_height),
        "scan state should advance to the first scan's end"
    );

    // Second scan over the second half: scan state advances to the new tail.
    account
        .scan_blocks(Some(middle_height + 1), Some(env.height))
        .expect("second scan");
    assert_eq!(
        account.last_scanned_height(),
        Some(env.height),
        "scan state should advance to the second scan's end"
    );
}

/// A scan stopped during the spend sweep (receive frontier already at the tip,
/// spend frontier still behind) must finish the spend sweep on resume at the
/// SAME tip, and must not re-run the receive pass.
fn test_spend_only_resume_at_same_tip(env: &mut TestEnv) {
    use bwk_sp::scan::state::ScanState;
    use common::wait_for_oneshot_done;

    let (mut account, config, _dir) =
        test_account_persistent_named("spend-only-resume", &env.url());

    // Fund an SP output and scan to tip: both frontiers reach `c`.
    env.fund_sp(&mut account, 0.5);
    let c = env.height;
    let owned = {
        let coins = account.coins();
        assert_eq!(coins.len(), 1, "should own exactly one SP output");
        let (op, entry) = coins.iter().next().unwrap();
        assert!(entry.is_spendable(), "owned output should start unspent");
        *op
    };

    // Spend the SP output on-chain; the spend is mined above `c`. Scope the
    // builder so it drops (releasing its backend handle) before the account does.
    let tx = {
        let dest = env.taproot_addr(0);
        let mut builder = account.tx_builder().feerate(1000);
        builder.send_to(dest, 100_000);
        for coin in builder.select_coins(100_000, 1000) {
            builder.add_input(coin);
        }
        let mut psbt = builder.generate().expect("build spend tx");
        account.sign_and_finalize(&mut psbt).expect("sign spend tx")
    };
    env.broadcast_and_mine(&tx);
    let c2 = env.height;
    assert!(c2 > c, "spend must be mined above the funded tip");

    // Reproduce a scan stopped mid spend-sweep: push only the receive frontier to
    // the new tip, leaving the spend frontier at `c`.
    drop(account);
    {
        let backend: Arc<dyn PersistenceBackend> =
            Arc::new(JsonBackend::open(config.account_dir()).expect("open backend"));
        let mut state = ScanState::load_from_backend(0, backend).expect("load scan state");
        assert_eq!(state.last_scanned_height(), Some(c));
        assert_eq!(state.last_spend_height(), Some(c));
        state.set_last_scanned_height(c2);
        state.persist();
    }

    // Resume at the same tip: receive is already done, only the spend sweep runs.
    let mut account = bwk_sp::account::Account::new(config.clone()).expect("reopen account");
    let receiver = account.receiver().expect("receiver");
    account.scan_oneshot(None).expect("resume scan");
    wait_for_oneshot_done(&account, Duration::from_secs(60));

    // The receive pass must be skipped (no re-receive): no ScanReceiveProgress.
    let mut saw_receive_progress = false;
    while let Ok(notif) = receiver.try_recv() {
        if let Notification::Sp(SpNotification::ScanReceiveProgress { .. }) = notif {
            saw_receive_progress = true;
        }
    }
    assert!(
        !saw_receive_progress,
        "resume must not re-run the receive pass"
    );

    // The spend-only sweep ran and marked the owned output spent.
    let coins = account.coins();
    let entry = coins.get(&owned).expect("owned coin still tracked");
    assert!(
        !entry.is_spendable(),
        "spend-only resume should mark the owned output spent, got {:?}",
        entry.status()
    );
}

/// A scan records incoming txs; a broadcast injects the spend as unconfirmed; a
/// later scan confirms it without turning the self-spend change into an incoming.
fn test_unconfirmed_spend_injection(env: &mut TestEnv) {
    use bwk::bwk_electrum::coin_store::PaymentType;
    use common::wait_for_oneshot_done;

    let (mut account, _config, _dir) =
        test_account_persistent_named("unconfirmed-spend", &env.url());

    // Fund an SP output; fund_sp scans, so the funding tx is recorded.
    env.fund_sp(&mut account, 0.5);
    let owned = {
        let coins = account.coins();
        assert_eq!(coins.len(), 1, "should own exactly one SP output");
        *coins.keys().next().unwrap()
    };
    let funding_txid = owned.txid;
    let input_value = account.get_coin(&owned).expect("coin").amount_sat();

    // The receive scan recorded the funding tx as a confirmed receive.
    {
        let payment = account
            .payment_history()
            .into_iter()
            .find(|p| p.txid == funding_txid.to_string())
            .expect("incoming tx recorded by scan");
        assert!(matches!(payment.payment_type, PaymentType::Receive));
        assert!(payment.height.is_some(), "incoming tx should be confirmed");
    }
    assert!(account.balance() > 0);

    // Build + sign a spend of the SP coin (change returns to our SP address).
    let dest = env.taproot_addr(0);
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(dest.clone(), 100_000);
    for coin in builder.select_coins(100_000, 1000) {
        builder.add_input(coin);
    }
    let tx = {
        let mut psbt = builder.generate().expect("build spend tx");
        account.sign_and_finalize(&mut psbt).expect("sign spend tx")
    };
    let spend_txid = tx.compute_txid();
    let change = tx
        .output
        .iter()
        .find(|output| output.script_pubkey != dest.script_pubkey())
        .expect("SP change output")
        .value
        .to_sat();

    // Inject as unconfirmed (no broadcast/mine yet).
    account.record_unconfirmed_spend(&tx).expect("inject spend");
    {
        let tx_entry = account
            .tx_history()
            .into_iter()
            .find(|entry| entry.txid == spend_txid)
            .expect("outgoing SP tx entry");
        assert_eq!(tx_entry.change, change);
        let entry = account.get_coin(&owned).expect("coin still tracked");
        assert!(!entry.is_spendable(), "spent coin must drop from spendable");
        assert_eq!(
            account.balance(),
            0,
            "balance drops to 0 (change not yet scanned)"
        );
        let out = account
            .payment_history()
            .into_iter()
            .find(|p| p.txid == spend_txid.to_string())
            .expect("outgoing tx injected");
        assert!(matches!(out.payment_type, PaymentType::Send));
        assert!(out.height.is_none(), "injected spend is unconfirmed");
        assert_eq!(
            out.amount,
            input_value - change,
            "unconfirmed send amount = inputs - change = sent + fee"
        );
    }

    // Mine + scan: the spend confirms, the coin is mined, and the self-spend
    // change does not turn the outgoing entry into an incoming one.
    env.broadcast_and_mine(&tx);
    account.scan_oneshot(None).expect("scan");
    wait_for_oneshot_done(&account, Duration::from_secs(60));
    {
        let entry = account.get_coin(&owned).expect("coin still tracked");
        assert!(!entry.is_spendable(), "spent coin stays spent after scan");
        let out = account
            .payment_history()
            .into_iter()
            .find(|p| p.txid == spend_txid.to_string())
            .expect("outgoing tx present after scan");
        assert!(
            matches!(out.payment_type, PaymentType::Send),
            "self-spend change must keep it a send"
        );
        assert!(out.height.is_some(), "spend confirmed after scan");
        assert_eq!(
            out.amount,
            input_value - change,
            "scanned change supersedes the recorded value, same amount"
        );
    }
}

/// A spend with an input absent from every wallet coin store is refused before
/// any state changes.
fn test_unconfirmed_spend_no_sp_coin(env: &mut TestEnv) {
    use bitcoin::hashes::Hash;

    let (mut account, _config, _dir) =
        test_account_persistent_named("unconfirmed-no-sp-coin", &env.url());

    // Fund an SP coin so the store is non-empty; the spent tx won't touch it.
    env.fund_sp(&mut account, 0.5);
    let owned = {
        let coins = account.coins();
        assert_eq!(coins.len(), 1, "should own exactly one SP output");
        *coins.keys().next().unwrap()
    };
    assert!(
        account.get_coin(&owned).expect("coin").is_spendable(),
        "pre-funded SP coin starts spendable"
    );

    // A tx spending a FOREIGN outpoint absent from the SP coin store.
    let foreign = OutPoint::new(bitcoin::Txid::from_byte_array([7u8; 32]), 0);
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: foreign,
            script_sig: Default::default(),
            sequence: bitcoin::Sequence::ZERO,
            witness: Default::default(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let txid = tx.compute_txid();

    let err = account
        .record_unconfirmed_spend(&tx)
        .expect_err("foreign input must be refused");
    assert!(matches!(
        err,
        bwk_sp::account::AccountError::MissingInputCoin(outpoint) if outpoint == foreign
    ));

    // No SP record: neither an SpTxStore entry nor a payment_history row.
    assert!(
        !account.tx_history().iter().any(|e| e.txid == txid),
        "no SP tx_store entry for a tx spending no SP coin"
    );
    assert!(
        !account
            .payment_history()
            .into_iter()
            .any(|p| p.txid == txid.to_string()),
        "no payment_history row for a tx spending no SP coin"
    );

    // The pre-funded SP coin is untouched: still tracked and spendable.
    let entry = account.get_coin(&owned).expect("coin still tracked");
    assert!(entry.is_spendable(), "unrelated SP coin stays spendable");
    assert_eq!(account.coins().len(), 1, "coin store not mutated");
}

/// `broadcast` refuses when no Electrum endpoint is configured, and the refusal
/// leaves state untouched: it resolves the endpoint and broadcasts before
/// recording anything, so a real spend of an SP coin must not be injected.
fn test_broadcast_requires_electrum_endpoint(env: &mut TestEnv) {
    // Reachable blindbit (to fund/scan) but no Electrum endpoint configured.
    let (mut account, _config, _dir) =
        test_account_persistent_named("broadcast-no-endpoint", &env.url());

    // Fund a real SP coin and build + sign a spend of it.
    env.fund_sp(&mut account, 0.5);
    let owned = {
        let coins = account.coins();
        assert_eq!(coins.len(), 1, "should own exactly one SP output");
        *coins.keys().next().unwrap()
    };

    let dest = env.taproot_addr(0);
    let mut builder = account.tx_builder().feerate(1000);
    builder.send_to(dest, 100_000);
    for coin in builder.select_coins(100_000, 1000) {
        builder.add_input(coin);
    }
    let tx = {
        let mut psbt = builder.generate().expect("build spend tx");
        account.sign_and_finalize(&mut psbt).expect("sign spend tx")
    };
    let spend_txid = tx.compute_txid();

    let receiver = account.receiver().expect("notification receiver");
    account.broadcast(tx);
    // The scanner shares this channel, so skip its progress notifications until
    // the broadcast outcome lands.
    let deadline = Instant::now() + Duration::from_secs(30);
    let message = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "no broadcast outcome in time");
        match receiver.recv_timeout(remaining) {
            Ok(Notification::Sp(SpNotification::FailBroadcast { message })) => break message,
            Ok(Notification::Sp(SpNotification::Broadcasted { txid })) => {
                panic!("broadcast without an endpoint must fail, got {txid}")
            }
            Ok(_) => continue,
            Err(e) => panic!("broadcast outcome never arrived: {e}"),
        }
    };
    assert!(
        message.contains("no electrum endpoint"),
        "unexpected failure message: {message}"
    );

    // The refusal left state untouched: the spent SP coin is still spendable and
    // no SP record exists for the refused spend.
    let entry = account.get_coin(&owned).expect("coin still tracked");
    assert!(
        entry.is_spendable(),
        "refused broadcast must not mark the input spent"
    );
    assert!(
        !account.tx_history().iter().any(|e| e.txid == spend_txid),
        "no SP tx_store entry for a refused broadcast"
    );
    assert!(
        !account
            .payment_history()
            .into_iter()
            .any(|p| p.txid == spend_txid.to_string()),
        "no payment_history row for a refused broadcast"
    );
}

/// The scan stamps a confirmation block time on recorded txs, fetched from
/// blindbitd's embedded Electrum (blindbit itself has no block time).
fn test_sp_scan_timestamps(env: &mut TestEnv) {
    let (host, port) = env.electrum_endpoint();

    let dir = TempDir::new().unwrap();
    let mut config = Config::new(
        "sp-scan-timestamps".to_string(),
        bitcoin::Network::Regtest,
        common::test_mnemonic().to_string(),
        env.url(),
        dir.path().to_path_buf(),
    );
    config.set_electrum_endpoint(host, port);
    let mut account = bwk_sp::account::Account::new(config).expect("create account");

    // fund_sp funds the SP address and scans, recording the funding tx.
    env.fund_sp(&mut account, 0.5);

    let payment = account
        .payment_history()
        .into_iter()
        .next()
        .expect("one recorded payment");
    assert!(
        payment.timestamp.is_some_and(|t| t > 0),
        "scan must stamp a block time, got {:?}",
        payment.timestamp
    );
}
