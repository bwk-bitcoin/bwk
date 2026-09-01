//! End-to-end integration tests for `HeaderStore`.
//!
//! Scenarios:
//!
//! 1. `multi_account_shared_header_store`: two Accounts sharing a single
//!    `Arc<HeaderStore>` each see their own funding tx reach
//!    `Inclusion::Verified` / `CoinStatus::Confirmed` via the same
//!    underlying header chain.
//! 2. `reorg_reconfirms_verified`: a Verified tx survives a reorg and is
//!    brought back to `Inclusion::Verified` at its new height by the
//!    scripthash subscription + history path once the tx is re-mined onto
//!    the new chain. Demotion is owned entirely by the history path
//!    (`CoinStore::insert_history` resets a reported-height change to
//!    `Unconfirmed`); `on_chain_update` is promote-only and never demotes,
//!    so the transient `Unconfirmed` window is best-effort and not
//!    asserted here. The deterministic "reported-height change ->
//!    Unconfirmed" demotion is covered by
//!    `account::tests::reported_height_change_demotes_verified_to_unconfirmed`.
//! 3. `restart_from_cache_skips_full_validation`: a freshly constructed
//!    file-backed store loads its tip from the binary cache before the
//!    worker has re-synced anything, and the persisted bytes match the
//!    in-memory state.
//! 4. `deep_reorg_below_anchor_resyncs`: a reorg rewriting history below
//!    the cache anchor converges via the walk-back reorg path (on regtest
//!    the backfill floor saturates to 0, so no wipe occurs; the
//!    `chunk_start <= min_stored` wipe branch is unit-covered by
//!    `reorg_with_no_ancestor_above_sparse_anchor_wipes_and_reanchors` in
//!    `header_store.rs`).
//! 5. `restart_requeues_stranded_merkle_fetch`: a `ConfirmedUnverified` tx
//!    whose merkle fetch is lost when electrs goes down still reaches
//!    `Verified` after the account reconnects to a freshly restarted
//!    electrs, proving the reconnect re-queue.
//! 6. `sparse_anchor_above_retarget_boundary_syncs_and_verifies`: with a
//!    birthday past two retarget intervals the store anchors sparsely at
//!    the previous boundary (height 2016) instead of genesis, and a
//!    funding tx still reaches `Verified` against that sparse chain.
//!
//! Adversarial coverage for malformed merkle proofs, future-dated headers
//! and the retarget boundary lives in deterministic unit tests in
//! `header_store.rs` / `header_validator.rs` (regtest cannot reproduce
//! those conditions through honest electrs). The C5 stale-pending-claims
//! sweep is covered by `account::tests::deep_reorg_clears_stale_pending_claims`.
#![cfg(feature = "test")]

use std::{sync::mpsc, thread::sleep, time::Duration};

use bip39::Mnemonic;
use bwk::{
    account::Notification,
    config::{maybe_create_dir, Config},
    header_store::HeaderStore,
    tx_store::Inclusion,
    Account,
};
use bwk_coin::CoinStatus;
use bwk_descriptor::descriptor::ScriptType;
use electrsd::bitcoind::{
    bitcoincore_rpc::{jsonrpc::serde_json::Value, RpcApi},
    BitcoinD,
};
use miniscript::bitcoin::{self, bip32::ChildNumber, Address, Amount, Network};
use temp_dir::TempDir;

mod common;
use common::{
    bootstrap_electrs, generate, get_block_hash_str, get_block_height, restart_electrs,
    wait_electrs_tip, wait_until,
};

fn send_to_address(bitcoind: &BitcoinD, addr: &Address, amount: Amount) {
    bitcoind
        .client
        .send_to_address(addr, amount, None, None, None, None, None, None)
        .unwrap();
}

fn invalidate_block(bitcoind: &BitcoinD, hash: String) {
    bitcoind
        .client
        .call::<Value>("invalidateblock", &[hash.into()])
        .unwrap();
}

/// Drain everything currently on `rx` without blocking.
fn drain_notifs(rx: &mpsc::Receiver<Notification>) -> Vec<Notification> {
    let mut out = Vec::new();
    while let Ok(n) = rx.try_recv() {
        out.push(n);
    }
    out
}

/// Build a fresh `Config` rooted at `dir` with its own fresh mnemonic.
fn fresh_config(dir: &TempDir, name: &str, url: &str, port: u16, look_ahead: u32) -> Config {
    let mut path = dir.path().to_path_buf();
    path.push(".bwk");
    maybe_create_dir(&path);
    let path = path.parent().unwrap().to_path_buf();

    let mnemonic = Mnemonic::generate(12).unwrap();
    let mut config = Config::new(
        Some(mnemonic.to_string()),
        name.to_string(),
        bitcoin::Network::Regtest,
        ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
        path,
        ".bwk".to_string(),
        true,
    )
    .unwrap();
    config.network = Network::Regtest;
    config.look_ahead = look_ahead;
    config.set_electrum_url(url.to_string());
    config.set_electrum_port(port.to_string());
    config.set_mnemonic(mnemonic.to_string());
    config
}

/// Wait until every entry in `account.tx_history()` reports an `inclusion`
/// for which `pred` returns true (and there is at least one entry).
fn wait_for_inclusion<F>(account: &Account, timeout: Duration, pred: F) -> bool
where
    F: Fn(&Inclusion) -> bool,
{
    wait_until(timeout, || {
        let txs = account.tx_history();
        !txs.is_empty() && txs.iter().all(|e| pred(e.inclusion()))
    })
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

/// End-to-end test for two Accounts sharing a single `HeaderStore`.
///
/// Exercises the full chain: Status push -> History -> pending-claims
/// resolution via CTA -> `GetTxMerkle` -> `Inclusion::Verified`. The
/// HeaderStore is pre-synced before the Accounts are constructed so
/// that the first notif observed by the listener is the post-funding
/// chain advance.
#[test]
fn multi_account_shared_header_store() {
    init_logger();
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs(false);

    let header_store = HeaderStore::start(url.clone(), port, Network::Regtest, None, None).unwrap();

    // Let the HeaderStore worker complete its initial sync against the
    // pre-mined regtest chain BEFORE constructing Accounts, so the first
    // tx the Accounts see lands on a HeaderStore that's already at the
    // chain tip. Without this, the very first incoming notif races the
    // backfill and triggers a long resolve_reorg detour.
    let chain_tip = get_block_height(&bitcoind);
    assert!(
        wait_until(Duration::from_secs(60), || header_store
            .tip()
            .is_some_and(|t| t >= chain_tip)),
        "HeaderStore did not catch up to chain_tip={chain_tip}; tip={:?}",
        header_store.tip()
    );

    // Two independent account directories + configs, sharing the same
    // `Arc<HeaderStore>`.
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let look_ahead = 5;
    let config_a = fresh_config(&dir_a, "alice", &url, port, look_ahead);
    let config_b = fresh_config(&dir_b, "bob", &url, port, look_ahead);

    let mut account_a =
        Account::try_new_with_header_store(config_a, header_store.clone()).expect("account A open");
    let mut account_b =
        Account::try_new_with_header_store(config_b, header_store.clone()).expect("account B open");
    let rx_a = account_a.receiver().expect("receiver A");
    let rx_b = account_b.receiver().expect("receiver B");
    sleep(Duration::from_millis(500));

    let addr_a = account_a.new_addr().address().assume_checked();
    let addr_b = account_b.new_addr().address().assume_checked();
    sleep(Duration::from_millis(500));

    // Fund one UTXO at each address and bury it under a handful of
    // confirmations so the merkle-proof path has a stable header to
    // validate against.
    send_to_address(&bitcoind, &addr_a, Amount::from_btc(0.1).unwrap());
    send_to_address(&bitcoind, &addr_b, Amount::from_btc(0.2).unwrap());
    generate(&bitcoind, 6);

    let timeout = Duration::from_secs(120);

    // Each Account independently progresses its tx to Verified.
    assert!(
        wait_for_inclusion(&account_a, timeout, |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "account A did not reach Inclusion::Verified; history={:?}",
        account_a
            .tx_history()
            .iter()
            .map(|e| e.inclusion().clone())
            .collect::<Vec<_>>(),
    );
    assert!(
        wait_for_inclusion(&account_b, timeout, |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "account B did not reach Inclusion::Verified; history={:?}",
        account_b
            .tx_history()
            .iter()
            .map(|e| e.inclusion().clone())
            .collect::<Vec<_>>(),
    );

    // Each Account should have observed at least one
    // `HeaderStoreUpdated` and one `CoinUpdate` across its lifetime.
    let notifs_a = drain_notifs(&rx_a);
    let notifs_b = drain_notifs(&rx_b);
    assert!(
        notifs_a
            .iter()
            .any(|n| matches!(n, Notification::HeaderStoreUpdated)),
        "account A never saw HeaderStoreUpdated; got {notifs_a:?}",
    );
    assert!(
        notifs_a
            .iter()
            .any(|n| matches!(n, Notification::CoinUpdate)),
        "account A never saw CoinUpdate; got {notifs_a:?}",
    );
    assert!(
        notifs_b
            .iter()
            .any(|n| matches!(n, Notification::HeaderStoreUpdated)),
        "account B never saw HeaderStoreUpdated; got {notifs_b:?}",
    );
    assert!(
        notifs_b
            .iter()
            .any(|n| matches!(n, Notification::CoinUpdate)),
        "account B never saw CoinUpdate; got {notifs_b:?}",
    );

    // Spendable coins are Confirmed (merkle-verified).
    let state_a = account_a.spendable_coins();
    let state_b = account_b.spendable_coins();
    assert_eq!(state_a.coins.len(), 1, "account A coin count");
    assert_eq!(state_b.coins.len(), 1, "account B coin count");
    let coin_a = state_a.coins.values().next().unwrap();
    let coin_b = state_b.coins.values().next().unwrap();
    assert_eq!(
        coin_a.status,
        CoinStatus::Confirmed,
        "account A coin not Confirmed",
    );
    assert_eq!(
        coin_b.status,
        CoinStatus::Confirmed,
        "account B coin not Confirmed",
    );
    assert_eq!(
        coin_a.value(),
        Amount::from_btc(0.1).unwrap(),
        "account A coin value",
    );
    assert_eq!(
        coin_b.value(),
        Amount::from_btc(0.2).unwrap(),
        "account B coin value",
    );

    // The shared HeaderStore tip matches bitcoind.
    let chain_tip = get_block_height(&bitcoind);
    assert!(
        wait_until(Duration::from_secs(60), || header_store.tip()
            == Some(chain_tip)),
        "shared HeaderStore tip did not reach chain_tip={chain_tip}; tip={:?}",
        header_store.tip()
    );
}

/// End-to-end test for `Verified` -> (reorg) -> `Verified` at a new height.
///
/// The tx is re-mined onto the new chain and the scripthash subscription
/// plus history path brings it back to `Verified`. A transient
/// `Unconfirmed` window may occur (when the wallet observes the reorged-out
/// tx before it is re-mined) but is not guaranteed under the promote-only
/// `on_chain_update`, so it is not asserted here.
#[test]
fn reorg_reconfirms_verified() {
    init_logger();
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs(false);

    let header_store = HeaderStore::start(url.clone(), port, Network::Regtest, None, None).unwrap();

    // Wait for the initial backfill before creating the Account.
    let chain_tip = get_block_height(&bitcoind);
    assert!(
        wait_until(Duration::from_secs(60), || header_store
            .tip()
            .is_some_and(|t| t >= chain_tip)),
        "HeaderStore did not catch up to chain_tip={chain_tip}; tip={:?}",
        header_store.tip()
    );

    let dir = TempDir::new().unwrap();
    let config = fresh_config(&dir, "alice", &url, port, 10);
    let mut account =
        Account::try_new_with_header_store(config, header_store.clone()).expect("account open");
    let _rx = account.receiver().expect("receiver");
    sleep(Duration::from_millis(500));

    let addr = account.new_addr().address().assume_checked();
    sleep(Duration::from_millis(500));

    // Fund and confirm.
    send_to_address(&bitcoind, &addr, Amount::from_btc(0.5).unwrap());
    // Mine M=5 blocks; the first one mines the funding tx; the rest
    // bury it so the verifier promotes Claimed -> Verified.
    let m_blocks: u32 = 5;
    generate(&bitcoind, m_blocks);

    let timeout = Duration::from_secs(120);
    assert!(
        wait_for_inclusion(&account, timeout, |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "tx never reached Verified before reorg",
    );

    // Snapshot the funding height + the header hash at that height.
    let entry = account.tx_history().pop().expect("at least one tx");
    let funding_height = match entry.inclusion() {
        Inclusion::Verified { height, .. } => *height,
        other => panic!("expected Verified, got {other:?}"),
    };
    let pre_reorg_hash = header_store
        .block_hash(funding_height)
        .expect("hash at funding height");

    // Reorg: invalidate the funding block and mine a longer chain on a
    // fresh address. The funding tx returns to bitcoind's mempool and
    // is re-mined into the new tip by the next generate.
    let hash_at_h = get_block_hash_str(&bitcoind, funding_height);
    invalidate_block(&bitcoind, hash_at_h);
    // Mine M+2 blocks on the new branch (strictly longer than the
    // discarded suffix).
    generate(&bitcoind, m_blocks + 2);

    // Wait for the HeaderStore to track the reorg.
    assert!(
        wait_until(Duration::from_secs(60), || {
            match header_store.block_hash(funding_height) {
                Some(h) => h != pre_reorg_hash,
                None => false,
            }
        }),
        "HeaderStore never tracked the reorg at h={funding_height}",
    );

    // The transient Unconfirmed window is racy under the promote-only CTA;
    // the deterministic demotion is unit-covered by
    // `account::tests::reported_height_change_demotes_verified_to_unconfirmed`.

    // Mine one more block to ensure the re-mined funding tx is buried
    // deeply enough for the verifier to re-promote.
    generate(&bitcoind, 3);

    // Re-confirmation via the scripthash subscription only; the CTA
    // path does not call `CoinRequest::History` proactively; the new
    // status push is what drives the re-claim and the verifier promotes it
    // back to Verified.
    assert!(
        wait_for_inclusion(&account, Duration::from_secs(120), |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "tx never returned to Verified after reorg; history={:?}",
        account
            .tx_history()
            .iter()
            .map(|e| e.inclusion().clone())
            .collect::<Vec<_>>(),
    );
    assert!(
        wait_until(Duration::from_secs(30), || {
            account
                .coins()
                .values()
                .all(|c| c.status() == CoinStatus::Confirmed)
        }),
        "coin never returned to CoinStatus::Confirmed after reorg",
    );
}

#[test]
fn restart_from_cache_skips_full_validation() {
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs(false);

    let persist_dir = TempDir::new().unwrap();
    let persist_path = persist_dir.path().join("headers.json");

    // First boot: sync headers from a relatively low `min_height` so the
    // backfill writes a meaningful range to disk.
    let initial_tip = get_block_height(&bitcoind);
    let expected_tip = {
        let store = HeaderStore::start(
            url.clone(),
            port,
            Network::Regtest,
            Some(persist_path.clone()),
            Some(0),
        )
        .unwrap();

        // Wait for the backfill to catch up to the chain tip.
        assert!(
            wait_until(Duration::from_secs(60), || store.tip() == Some(initial_tip)),
            "initial backfill did not reach tip={initial_tip}; got {:?}",
            store.tip()
        );

        // Mine a few extra blocks and let them land in the persisted file.
        generate(&bitcoind, 4);
        let new_tip = get_block_height(&bitcoind);
        assert!(
            wait_until(Duration::from_secs(60), || store.tip() == Some(new_tip)),
            "store did not follow tip after mining; got {:?}",
            store.tip()
        );

        // Drop ends the worker (last Arc handle goes here).
        drop(store);
        new_tip
    };

    // The persisted file must exist and be non-empty.
    let metadata = std::fs::metadata(&persist_path).expect("persisted file exists");
    assert!(metadata.len() > 0, "persisted headers file is empty");

    // Capture the persisted JSON for a structural comparison after the
    // in-memory load runs the sanity check.
    let before_bytes = std::fs::read(&persist_path).expect("read persisted headers");

    // Second boot: load from disk only. The sanity check parses the
    // file synchronously; tip() must return the persisted maximum
    // height immediately, before any electrum sync is allowed to run.
    //
    // To assert that without a race, we bring up the store wired to a
    // bogus port so the worker can't make progress. `HeaderStore::start`
    // already returns the file-backed store when the client succeeds,
    // and degrades to in-memory if the client errors out, so we can't
    // rely on that path for "tip already correct on return". Instead we
    // use `HeaderStore::from_file` directly: it runs the same sanity
    // pipeline and never spawns a worker, exposing the on-load state.
    let reloaded = HeaderStore::from_file(Network::Regtest, persist_path.clone()).unwrap();
    let persisted_tip = reloaded.tip().expect("persisted tip");
    assert_eq!(
        persisted_tip, expected_tip,
        "reloaded tip should match the persisted tip (no fresh sync ran)",
    );

    // On-disk file should still match what `from_file` loaded (sanity
    // pass is read-mostly: it only rewrites on shape mismatch / clear).
    let after_bytes = std::fs::read(&persist_path).expect("re-read persisted headers");
    assert_eq!(
        before_bytes, after_bytes,
        "persisted headers file should be byte-identical across a clean reload",
    );

    // Release the cache-file lock before reopening the same path below.
    // `from_file` spawns a background replay-validation thread that holds an
    // `Arc<HeaderStore>`, so the lock can outlive `drop(reloaded)` by a beat;
    // retry the reopen until that thread drops its handle and frees the lock.
    drop(reloaded);
    let store = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match HeaderStore::start(
                url.clone(),
                port,
                Network::Regtest,
                Some(persist_path.clone()),
                Some(0),
            ) {
                Ok(store) => break store,
                Err(e) if std::time::Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("warm start never acquired the cache lock: {e:?}"),
            }
        }
    };
    // The returned store may already report the persisted tip (from
    // disk) before the worker observes any new headers. Confirm at
    // minimum it is `>= persisted_tip`.
    let tip = store.tip();
    assert!(
        tip.is_some_and(|t| t >= persisted_tip),
        "warm-started store tip {tip:?} should be at least the persisted tip {persisted_tip}",
    );
    drop(store);
}

/// A reorg that rewrites history below the cache anchor converges via the
/// normal walk-back reorg path: on regtest the backfill floor saturates to
/// 0, so a common ancestor always exists and no wipe occurs. The
/// `chunk_start <= min_stored` wipe branch is unit-covered by
/// `reorg_with_no_ancestor_above_sparse_anchor_wipes_and_reanchors` in
/// `header_store.rs`.
#[test]
fn deep_reorg_below_anchor_resyncs() {
    init_logger();
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs(false);

    // Mine extra blocks so we can anchor the cache above genesis and then
    // reorg below that anchor.
    generate(&bitcoind, 20);
    let chain_tip = get_block_height(&bitcoind);
    let anchor = chain_tip - 2;

    let store =
        HeaderStore::start(url.clone(), port, Network::Regtest, None, Some(anchor)).unwrap();
    assert!(
        wait_until(Duration::from_secs(60), || store
            .tip()
            .is_some_and(|t| t >= chain_tip)),
        "store did not reach chain tip; got {:?}",
        store.tip()
    );
    let pre_hash_at_tip = store.tip_hash();

    // Reorg deep: invalidate a block below the anchor and mine a strictly
    // longer competing chain.
    let reorg_target = anchor.saturating_sub(1).max(1);
    let hash = get_block_hash_str(&bitcoind, reorg_target);
    invalidate_block(&bitcoind, hash);
    generate(&bitcoind, (chain_tip - reorg_target) + 4);
    let new_tip = get_block_height(&bitcoind);

    // The store must converge on the new chain (walk-back reorg; the
    // regtest floor saturates to 0 so no wipe is involved).
    assert!(
        wait_until(Duration::from_secs(90), || {
            store.tip() == Some(new_tip)
                && store.tip_hash().is_some()
                && store.tip_hash() != pre_hash_at_tip
        }),
        "store did not re-sync to the post-reorg chain; tip={:?} new_tip={new_tip}",
        store.tip()
    );
    drop(store);
}

/// Regression: a merkle fetch is single-attempt, so a `ConfirmedUnverified`
/// tx whose fetch response is lost when electrs goes down would otherwise
/// stay stranded (no header-hash change to re-trigger `on_chain_update`'s
/// reverify pass). Killing electrs right after the confirming block races
/// the merkle fetch its promotion queues, so the response never arrives.
/// Reconnecting to a freshly restarted electrs must re-queue that fetch and
/// bring the tx to `Verified`.
#[test]
fn restart_requeues_stranded_merkle_fetch() {
    init_logger();
    let (url, port, electrsd, bitcoind) = bootstrap_electrs(false);

    let header_store = HeaderStore::start(url.clone(), port, Network::Regtest, None, None).unwrap();
    let chain_tip = get_block_height(&bitcoind);
    assert!(
        wait_until(Duration::from_secs(60), || header_store
            .tip()
            .is_some_and(|t| t >= chain_tip)),
        "HeaderStore did not catch up to chain_tip={chain_tip}; tip={:?}",
        header_store.tip()
    );

    let dir = TempDir::new().unwrap();
    let config = fresh_config(&dir, "alice", &url, port, 10);
    let mut account =
        Account::try_new_with_header_store(config, header_store.clone()).expect("account open");
    let _rx = account.receiver().expect("receiver");
    sleep(Duration::from_millis(500));

    let addr = account.new_addr().address().assume_checked();
    sleep(Duration::from_millis(500));

    send_to_address(&bitcoind, &addr, Amount::from_btc(0.1).unwrap());
    generate(&bitcoind, 1);
    let (new_url, new_port, new_electrsd) = restart_electrs(electrsd, &bitcoind);
    wait_electrs_tip(&bitcoind, &new_electrsd);

    account.set_electrum_config(Some(new_url), Some(new_port));
    account.restart_electrum();

    // A few more confirmations so the verifier has a stable header to
    // validate the (re-queued) merkle proof against.
    generate(&bitcoind, 5);

    assert!(
        wait_for_inclusion(&account, Duration::from_secs(120), |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "tx never reached Verified after electrs restart; history={:?}",
        account
            .tx_history()
            .iter()
            .map(|e| e.inclusion().clone())
            .collect::<Vec<_>>(),
    );
}

/// Sparse-anchor sync across the retarget-interval floor: with a birthday
/// past two retarget intervals (2 * 2016), `backfill_floor` lands on the
/// previous boundary (height 2016) instead of saturating to genesis, so
/// the worker anchors the chain via `append_anchor` and merkle
/// verification runs against a sparse, non-genesis-anchored store.
#[test]
fn sparse_anchor_above_retarget_boundary_syncs_and_verifies() {
    init_logger();
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs(false);

    // Mine past 2 * 2016 blocks in chunks (single huge generatetoaddress
    // calls can hit the RPC timeout).
    for _ in 0..41 {
        generate(&bitcoind, 100);
    }
    let chain_tip = get_block_height(&bitcoind);
    assert!(chain_tip >= 4132, "chain too short: {chain_tip}");

    // min_height 4100 snaps to 4032 and pads one interval back to 2016.
    let header_store =
        HeaderStore::start(url.clone(), port, Network::Regtest, None, Some(4100)).unwrap();
    assert!(
        wait_until(Duration::from_secs(300), || header_store
            .tip()
            .is_some_and(|t| t >= chain_tip)),
        "HeaderStore did not reach chain_tip={chain_tip}; tip={:?}",
        header_store.tip()
    );
    // Anchored exactly at the previous retarget boundary, sparse below it.
    assert!(
        header_store.header(2016).is_some(),
        "anchor header missing at height 2016",
    );
    assert!(
        header_store.header(2015).is_none(),
        "store holds a header below the 2016 anchor",
    );

    let dir = TempDir::new().unwrap();
    let config = fresh_config(&dir, "alice", &url, port, 10);
    let mut account =
        Account::try_new_with_header_store(config, header_store.clone()).expect("account open");
    let _rx = account.receiver().expect("receiver");
    sleep(Duration::from_millis(500));

    let addr = account.new_addr().address().assume_checked();
    sleep(Duration::from_millis(500));

    // Fund and bury above the boundary; the merkle proof verifies against
    // a header of the sparse chain.
    send_to_address(&bitcoind, &addr, Amount::from_btc(0.3).unwrap());
    generate(&bitcoind, 6);

    assert!(
        wait_for_inclusion(&account, Duration::from_secs(120), |i| matches!(
            i,
            Inclusion::Verified { .. }
        )),
        "tx never reached Verified on the sparse-anchored store; history={:?}",
        account
            .tx_history()
            .iter()
            .map(|e| e.inclusion().clone())
            .collect::<Vec<_>>(),
    );

    // Steady-state appends keep following the chain.
    generate(&bitcoind, 3);
    let new_tip = get_block_height(&bitcoind);
    assert!(
        wait_until(Duration::from_secs(60), || header_store.tip()
            == Some(new_tip)),
        "tip did not advance to {new_tip}; got {:?}",
        header_store.tip()
    );
}
