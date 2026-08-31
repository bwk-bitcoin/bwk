//! End-to-end integration tests for `HeaderStore`.
//!
//! Scenarios:
//!
//! 1. `restart_from_cache_skips_full_validation`: a freshly constructed
//!    file-backed store loads its tip from the binary cache before the
//!    worker has re-synced anything, and the persisted bytes match the
//!    in-memory state.
//! 2. `deep_reorg_below_anchor_resyncs`: a reorg rewriting history below
//!    the cache anchor converges via the walk-back reorg path (on regtest
//!    the backfill floor saturates to 0, so no wipe occurs; the
//!    `chunk_start <= min_stored` wipe branch is unit-covered by
//!    `reorg_with_no_ancestor_above_sparse_anchor_wipes_and_reanchors` in
//!    `header_store.rs`).
//!
//! Adversarial coverage for malformed merkle proofs, future-dated headers
//! and the retarget boundary lives in deterministic unit tests in
//! `header_store.rs` / `header_validator.rs` (regtest cannot reproduce
//! those conditions through honest electrs).
#![cfg(feature = "test")]

use std::time::Duration;

use bwk_electrum::{config::HEADERS_FILENAME, header_store::HeaderStore};
use bwk_utils::test::regtest::{
    bootstrap_electrs, generate, get_block_hash_str, get_block_height, init_logger,
    invalidate_block, wait_until,
};
use miniscript::bitcoin::Network;
use temp_dir::TempDir;

#[test]
fn restart_from_cache_skips_full_validation() {
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs();

    let persist_dir = TempDir::new().unwrap();
    let persist_path = persist_dir.path().join(HEADERS_FILENAME);

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
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs();

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
