//! End-to-end test for `HeaderStore::start` against a regtest electrsd.
//!
//! Spins up bitcoind + electrs, starts a `HeaderStore`, mines a few blocks,
//! confirms the worker fans out tip notifications and updates the tip,
//! then triggers a reorg via `invalidateblock` + extra blocks and confirms
//! the store rewinds + re-extends to the new chain.
#![cfg(feature = "test")]

use std::{sync::mpsc, time::Duration};

use bwk_electrum::{
    config::HEADERS_FILENAME, header_store::HeaderStore, raw_client::CertificateCheck,
};
use bwk_utils::test::regtest::{
    bootstrap_electrs, generate, get_block_hash_str, get_block_height, invalidate_block, wait_until,
};
use miniscript::bitcoin::Network;
use temp_dir::TempDir;

/// Drain pending CTAs, waiting at most `timeout` for the first one.
fn drain(rx: &mpsc::Receiver<()>, timeout: Duration) -> usize {
    let mut n = 0;
    if rx.recv_timeout(timeout).is_ok() {
        n += 1;
        while rx.try_recv().is_ok() {
            n += 1;
        }
    }
    n
}

#[test]
fn header_store_follows_tip_and_resolves_reorg() {
    let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
    let base_height = get_block_height(&bitcoind);

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join(HEADERS_FILENAME);

    let store = HeaderStore::start(
        url,
        port,
        Network::Regtest,
        Some(path),
        Some(base_height),
        CertificateCheck::Validate,
    )
    .unwrap();
    let rx = store.register_chain_tick();

    // Wait for the worker to backfill up to the current tip.
    assert!(
        wait_until(Duration::from_secs(30), || store.tip() == Some(base_height)),
        "initial backfill did not reach base_height={base_height}; got tip={:?}",
        store.tip()
    );

    // Mine 5 blocks; expect notifications and tip advance.
    generate(&bitcoind, 5);
    let n = drain(&rx, Duration::from_secs(30));
    assert!(n >= 1, "expected at least one CTA after mining 5 blocks");

    assert!(
        wait_until(Duration::from_secs(30), || {
            store.tip() == Some(base_height + 5)
        }),
        "tip after 5 blocks = {:?}, expected {}",
        store.tip(),
        base_height + 5
    );

    let target = base_height + 3;
    let pre_reorg_hash = store.block_hash(target).expect("hash at target");

    // Invalidate the block at `target` and mine a longer fork.
    let hash_at_target = get_block_hash_str(&bitcoind, target);
    invalidate_block(&bitcoind, hash_at_target);
    generate(&bitcoind, 7);

    let new_tip = get_block_height(&bitcoind);
    assert!(
        new_tip > base_height + 5,
        "fork must be longer than original chain"
    );

    // Drain CTAs after the reorg+extend.
    let _ = drain(&rx, Duration::from_secs(30));

    // Electrs may push a single notif covering only an intermediate height
    // before the chain settles; wait for the store to converge to a tip
    // strictly above the original chain and confirm the reorg by checking
    // the hash at `target` changed.
    assert!(
        wait_until(Duration::from_secs(60), || {
            match (store.tip(), store.block_hash(target)) {
                (Some(t), Some(h)) => t > base_height + 5 && h != pre_reorg_hash,
                _ => false,
            }
        }),
        "post-reorg tip = {:?} (server new_tip {}), block_hash at {} = {:?} (pre-reorg {})",
        store.tip(),
        new_tip,
        target,
        store.block_hash(target),
        pre_reorg_hash
    );
}
