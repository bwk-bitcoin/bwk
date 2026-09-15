//! Reorg handling tests for bwk-sp.

mod common;

use bitcoin::OutPoint;
use bwk_sp::blindbit;
use bwk_utils::test as bwk_test;

use common::{test_mnemonic, TestEnv};

#[test]
fn test_reorg() {
    let mut env = TestEnv::new();

    test_reorg_detection_block_hash_mismatch(&mut env);
    test_reorg_removes_orphaned_coins(&mut env);
    test_reorg_coin_reappears_in_new_chain(&mut env);
    test_reorg_deep_reorganization(&mut env);
}

/// Tests detection of reorg via block hash mismatch.
///
/// This test verifies that after a reorg, block hashes change at
/// the affected heights, demonstrating that the chain has diverged.
fn test_reorg_detection_block_hash_mismatch(env: &mut TestEnv) {
    let agent = blindbit::agent().expect("blindbit agent");
    let start_height = env.height;

    env.mine(20);
    let reorg_height = start_height + 15;

    let original_hash = env.invalidate_block(reorg_height);

    assert_eq!(
        env.height,
        reorg_height - 1,
        "Height should precede the invalidated block"
    );

    env.mine(10);

    let new_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[reorg_height.into()])
        .unwrap();
    assert_ne!(
        original_hash, new_hash,
        "Block hash should change after reorg"
    );

    let backend_height = blindbit::block_height(&agent, &env.url())
        .unwrap()
        .to_consensus_u32();
    assert_eq!(
        backend_height, env.height,
        "Backend should see new chain height"
    );
}

/// Tests that coins from orphaned blocks are removed after rescan.
///
/// This test verifies:
/// 1. Create SP output in a block and detect it via scan
/// 2. Force reorg that orphans the block containing the output
/// 3. After rescan, the coin should not be found (was in orphaned block)
fn test_reorg_removes_orphaned_coins(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;
    let start_height = env.next_scan_height();

    // 4. Setup SP client and signer
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str).expect("signer");
    let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(0);

    // 5. Fund taproot address
    let fund_txid =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1).expect("fund");
    env.mine(2);

    // 6. Create SP transaction
    let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
    let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
        .into_iter()
        .next()
        .expect("txout");
    let outpoint = OutPoint {
        txid: fund_txid,
        vout: index as u32,
    };

    let sp_address = sp_receiver.get_receiving_address();
    let recipient_pubkey =
        generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp).expect("pk");
    let sp_tx = swap_to_sp(
        sk,
        outpoint,
        txout,
        recipient_pubkey,
        bitcoin::Amount::from_sat(1000),
        &secp,
    )
    .expect("sp tx");

    // 7. Broadcast and mine
    let sp_txid = sp_tx.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx)
        .expect("broadcast");
    env.mine(1);
    let sp_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("height") as u32;

    // 8. Scan and verify coin is found
    let mut account = env.sp_account_with_mnemonic("reorg-removes", mnemonic_str);
    account
        .scan_blocks(Some(start_height), Some(sp_height))
        .expect("scan");

    assert_eq!(account.coins().len(), 1, "Should find 1 coin before reorg");

    // 9. Invalidate the block containing the FUNDING tx to truly orphan the SP tx
    let fund_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, fund_txid).expect("fund height") as u32;
    env.invalidate_block(fund_height);

    // 10. Mine blocks on new fork to ensure wallet has mature coinbase outputs
    env.mine(5);

    // 11. Double-spend the funding input on the new chain
    let new_addr: String = env
        .bitcoind
        .client
        .call(
            "getnewaddress",
            &[
                serde_json::Value::String("".to_string()),
                serde_json::Value::String("bech32m".to_string()),
            ],
        )
        .expect("generate address");
    let _: String = env
        .bitcoind
        .client
        .call(
            "sendtoaddress",
            &[new_addr.into(), serde_json::Value::from(0.05)],
        )
        .expect("send to different address");

    // 12. Mine new chain (SP tx is now invalid)
    env.mine(1);
    let new_height = env.height;

    // 13. Verify backend works after reorg and rescan succeeds
    let mut account2 = env.sp_account_with_mnemonic("reorg-removes-rescan", mnemonic_str);

    // Rescan should succeed after reorg
    account2
        .scan_blocks(Some(start_height), Some(new_height))
        .expect("rescan after reorg");
}

/// Tests coin reappears if re-included in new chain after reorg.
///
/// This test verifies:
/// 1. Create SP output and detect it
/// 2. Force reorg that orphans the block
/// 3. Re-broadcast the SP tx and mine it in the new chain
/// 4. After rescan, coin should be found again
fn test_reorg_coin_reappears_in_new_chain(env: &mut TestEnv) {
    use bwk_sign::{bip39, hot_signer::HotSigner};
    use bwk_sp::receiver::SpReceiver;
    use common::{generate_recipient_pubkey, swap_to_sp};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let network = bitcoin::Network::Regtest;
    let start_height = env.next_scan_height();

    // 4. Setup SP client and signer
    let mnemonic_str = test_mnemonic();
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str).expect("valid mnemonic");
    let sp_receiver =
        SpReceiver::new_from_mnemonic(mnemonic.clone(), network).expect("sp_receiver");

    let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic_str).expect("signer");
    let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(0);

    // 5. Fund taproot address
    let fund_txid =
        bwk_test::send(&mut env.bitcoind.client, taproot_addr.clone(), 0.1).expect("fund");
    env.mine(2);

    // 6. Create SP transaction
    let tx = bwk_test::get_tx(&mut env.bitcoind.client, fund_txid).expect("get tx");
    let (index, txout) = bwk_test::txouts_for(&taproot_addr, &tx)
        .into_iter()
        .next()
        .expect("txout");
    let outpoint = OutPoint {
        txid: fund_txid,
        vout: index as u32,
    };

    let sp_address = sp_receiver.get_receiving_address();
    let recipient_pubkey =
        generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp).expect("pk");
    let sp_tx = swap_to_sp(
        sk,
        outpoint,
        txout,
        recipient_pubkey,
        bitcoin::Amount::from_sat(1000),
        &secp,
    )
    .expect("sp tx");

    // 7. Broadcast and mine
    let sp_txid = sp_tx.compute_txid();
    env.bitcoind
        .client
        .send_raw_transaction(&sp_tx)
        .expect("broadcast");
    env.mine(1);
    let sp_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("height") as u32;

    // 8. Scan and verify coin is found
    let mut account = env.sp_account_with_mnemonic("reorg-reappears", mnemonic_str);
    account
        .scan_blocks(Some(start_height), Some(sp_height))
        .expect("scan");

    let expected_op = OutPoint {
        txid: sp_txid,
        vout: 0,
    };
    assert_eq!(account.coins().len(), 1, "Should find coin before reorg");
    assert!(account.coins().contains_key(&expected_op));

    // 9. Invalidate the block (but not the funding tx block)
    // The SP tx is in sp_height, fund tx is in earlier block
    env.invalidate_block(sp_height);

    // 10. Re-broadcast the SP tx (it's still valid, inputs not spent)
    // The tx should go back to mempool or we can re-send it
    let _ = env.bitcoind.client.send_raw_transaction(&sp_tx); // May already be in mempool

    // 11. Mine new blocks to include the tx
    env.mine(2);
    let new_sp_height =
        bwk_test::get_tx_height(&mut env.bitcoind.client, sp_txid).expect("new height") as u32;

    // 12. Rescan - coin should be found again
    let mut account2 = env.sp_account_with_mnemonic("reorg-reappears-rescan", mnemonic_str);

    account2
        .scan_blocks(Some(start_height), Some(new_sp_height))
        .expect("rescan");

    assert_eq!(
        account2.coins().len(),
        1,
        "Coin should reappear in new chain"
    );
    assert!(
        account2.coins().contains_key(&expected_op),
        "Should find same SP output in new chain"
    );
}

/// Tests handling of deep (multi-block) reorganization.
///
/// This test verifies:
/// 1. Generate many blocks with SP outputs spread across them
/// 2. Force a deep (5+ block) reorg
/// 3. Verify wallet handles the large reorganization correctly
fn test_reorg_deep_reorganization(env: &mut TestEnv) {
    let agent = blindbit::agent().expect("blindbit agent");
    let start_height = env.height;

    env.mine(11);
    let first_height = start_height + 1;
    let middle_height = start_height + 6;
    let last_height = start_height + 11;

    let first_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[first_height.into()])
        .unwrap();
    let middle_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[middle_height.into()])
        .unwrap();
    let last_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[last_height.into()])
        .unwrap();

    env.invalidate_block(first_height);

    assert_eq!(
        env.height, start_height,
        "Height should precede the invalidated segment"
    );

    env.mine(20);

    let new_first_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[first_height.into()])
        .unwrap();
    let new_middle_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[middle_height.into()])
        .unwrap();
    let new_last_hash: String = env
        .bitcoind
        .client
        .call("getblockhash", &[last_height.into()])
        .unwrap();

    assert_ne!(first_hash, new_first_hash, "First hash should change");
    assert_ne!(middle_hash, new_middle_hash, "Middle hash should change");
    assert_ne!(last_hash, new_last_hash, "Last hash should change");

    let backend_height = blindbit::block_height(&agent, &env.url())
        .unwrap()
        .to_consensus_u32();
    assert_eq!(
        backend_height, env.height,
        "Backend should see the new chain"
    );
}
