//! Reconciling a scan against the validated chain.
//!
//! An [`ElectrumScanner`] records what the server reported and never reads a
//! header, a [`HeaderStore`] validates the chain: [`Reconciler`] is the pass
//! between the two, and a wallet runs one per scanner it owns.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex, MutexGuard,
};

use bwk_backoff::Backoff;
use miniscript::bitcoin::{BlockHash, TxMerkleNode, Txid};

use crate::{
    coin_store::{ClaimAt, CoinStore},
    fanout::ListenerId,
    header_store::{verify_merkle_branch, HeaderStore, MerkleOutcome, MerkleProof},
    listener::ScanListeners,
    notification::{Notification, ValidationFailure},
    profile::ScanProfile,
    scanner::ElectrumScanner,
    tx_store::Inclusion,
    worker::{Worker, IDLE_BACKOFF_MS},
};

/// Promotes a scanner's state against a validated header chain, on its own
/// thread.
pub struct Reconciler<P: ScanProfile> {
    coin_store: Arc<Mutex<CoinStore<P>>>,
    /// Scan ticks of the scanner `coin_store` belongs to, taken once at
    /// [`spawn`](Reconciler::spawn) so no later call can wake this pass on
    /// another scanner's scan.
    scan_listeners: ScanListeners,
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    notification: mpsc::Sender<Notification>,
    /// Identifies this pass on the header store's merkle fan-out: the store
    /// routes back only the outcomes of the fetches issued under it.
    merkle_id: ListenerId,
    pass: Worker,
}

impl<P: ScanProfile> Reconciler<P> {
    /// Spawn the pass for `scanner`, against `header_store` for the proofs it
    /// needs.
    pub fn spawn(
        scanner: &ElectrumScanner<P>,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        notification: mpsc::Sender<Notification>,
    ) -> Self {
        let mut reconciler = Reconciler {
            coin_store: scanner.coin_store().clone(),
            scan_listeners: scanner.scan_listeners(),
            header_store,
            notification,
            merkle_id: ListenerId::next(),
            pass: Worker::default(),
        };
        reconciler.start();
        reconciler
    }

    /// Start the pass over the scanner it was spawned for. A no-op while one is
    /// already running.
    pub fn start(&mut self) {
        if self.pass.running() {
            return;
        }
        let chain_rx = self.header_store.register_chain_tick();
        let merkle_rx = self.header_store.register_merkle_outcome(self.merkle_id);
        let scan_rx = self.scan_listeners.register();
        let coin_store = self.coin_store.clone();
        let header_store = self.header_store.clone();
        let notification = self.notification.clone();
        let merkle_id = self.merkle_id;
        self.pass.start(move |stop_request| {
            reconcile(
                coin_store,
                header_store,
                notification,
                merkle_id,
                chain_rx,
                scan_rx,
                merkle_rx,
                stop_request,
            )
        });
    }

    /// Signal the pass to end without blocking. Its handle is kept for `Drop`
    /// to join.
    pub fn stop(&mut self) {
        self.pass.stop();
    }

    /// Re-queue a merkle fetch for every `ConfirmedUnverified` entry when the
    /// merkle client is (re)connected, covering entries stranded while it was
    /// down; it bypasses the in-flight guard, so a fetch that died with the old
    /// client is asked again.
    pub fn requeue_confirmed_unverified(&self) {
        requeue_confirmed_unverified(&self.coin_store, &self.header_store, self.merkle_id);
    }
}

impl<P: ScanProfile> std::fmt::Debug for Reconciler<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconciler").finish()
    }
}

impl<P: ScanProfile> Drop for Reconciler<P> {
    fn drop(&mut self) {
        // The pass holds an Arc clone of the coin store, and so of the
        // persistence backend; without the join the DirLock on the account
        // directory would stay acquired past Drop and refuse a subsequent
        // reopen.
        self.pass.join();
    }
}

/// Reconcile the scanner's stores against the validated chain until `stop`.
///
/// Wakes on a chain-tip advance or on freshly scanned state, never polls the
/// stores otherwise.
#[allow(clippy::too_many_arguments)]
fn reconcile<P: ScanProfile>(
    coin_store: Arc<Mutex<CoinStore<P>>>,
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    notification: mpsc::Sender<Notification>,
    merkle_id: ListenerId,
    chain_rx: mpsc::Receiver<()>,
    scan_rx: mpsc::Receiver<()>,
    merkle_rx: mpsc::Receiver<MerkleOutcome>,
    stop: Arc<AtomicBool>,
) {
    // Entries left ConfirmedUnverified by a previous run have no fetch in
    // flight any more; ask for their proofs again.
    requeue_confirmed_unverified(&coin_store, &header_store, merkle_id);
    stamp_confirmation_times(&coin_store, &header_store);

    let mut backoff = Backoff::new_ms(IDLE_BACKOFF_MS);
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let mut received = false;

        // Coalesce every pending tick into a single pass: both sources mean
        // "the resolved state may have moved", and the pass is idempotent.
        let chain_tick = drain_ticks(&chain_rx);
        let scan_tick = drain_ticks(&scan_rx);
        if chain_tick || scan_tick {
            received = true;
            on_chain_update(&coin_store, &header_store, &notification, merkle_id);
        }

        while let Ok(outcome) = merkle_rx.try_recv() {
            received = true;
            handle_merkle_outcome(
                &coin_store,
                &header_store,
                &notification,
                merkle_id,
                outcome,
            );
        }

        if received {
            // A promotion may have just given an entry a height whose header
            // has landed; stamp the whole store once, not once per proof.
            stamp_confirmation_times(&coin_store, &header_store);
            backoff.reset();
            continue;
        }
        backoff.snooze();
    }
}

/// Drain the pending ticks, true if at least one arrived. A gone sender reports
/// none: the stop flag is what ends the loop.
fn drain_ticks(rx: &mpsc::Receiver<()>) -> bool {
    let mut ticked = false;
    while let Ok(()) = rx.try_recv() {
        ticked = true;
    }
    ticked
}

/// Gate every claim-promotion pass on header validation: `true` when the
/// store is validated, otherwise notify `ValidationFailed(HeaderStore(_))`
/// (when the store rejected its own replay) and return `false` so the
/// caller refuses to promote against an unvalidated header.
fn header_store_ready<P: ScanProfile>(
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
) -> bool {
    if header_store.is_validated() {
        return true;
    }
    if let Some(reason) = header_store.validation_failed_reason() {
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::HeaderStore(reason),
        ));
    }
    false
}

/// Persist and regenerate what a pass changed, release the coin-store lock and
/// notify `HeaderStoreUpdated`. A pass with merkle fetches to issue dispatches
/// them after this, outside the lock.
fn commit_chain_update<P: ScanProfile>(
    mut store: MutexGuard<'_, CoinStore<P>>,
    notification: &mpsc::Sender<Notification>,
    changed: bool,
) {
    if changed {
        store.tx_store_mut().persist();
        store.generate();
    }
    drop(store);
    if changed {
        let _ = notification.send(Notification::HeaderStoreUpdated);
    }
}

/// Apply one resolved fetch: verify the proof it returned, or, when the fetch
/// failed, free its in-flight slot so the next chain-tick pass asks again.
fn handle_merkle_outcome<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
    merkle_id: ListenerId,
    outcome: MerkleOutcome,
) {
    match outcome {
        MerkleOutcome::Proof(proof) => {
            handle_tx_merkle(coin_store, header_store, notification, merkle_id, proof)
        }
        MerkleOutcome::Failed { txid, height } => {
            let claim = ClaimAt { txid, height };
            coin_store
                .lock()
                .expect("poisoned")
                .clear_merkle_in_flight(&claim);
            retry_reorged_merkle_claim(coin_store, header_store, notification, merkle_id, claim);
        }
    }
}

/// A fetch that ended without promoting the entry may have ended because a
/// same-height reorg replaced the block it was claimed in. Run a chain-update
/// pass in that case, so the entry is restamped against the replacement block
/// and its proof asked for again.
fn retry_reorged_merkle_claim<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
    merkle_id: ListenerId,
    claim: ClaimAt,
) {
    let stored_hash = coin_store
        .lock()
        .expect("poisoned")
        .tx_store_mut()
        .get(&claim.txid)
        .and_then(|entry| match entry.inclusion() {
            Inclusion::ConfirmedUnverified { height, block_hash } if *height == claim.height => {
                Some(*block_hash)
            }
            _ => None,
        });
    if stored_hash.is_some_and(|hash| {
        header_store
            .block_hash(claim.height)
            .is_some_and(|current| current != hash)
    }) {
        on_chain_update(coin_store, header_store, notification, merkle_id);
    }
}

/// Verify a fetched merkle proof and promote the entry to `Verified`, or mark
/// it terminally `VerifyFailed` on a hard proof mismatch.
fn handle_tx_merkle<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
    merkle_id: ListenerId,
    proof: MerkleProof,
) {
    let MerkleProof {
        txid,
        height,
        branch,
        pos,
    } = proof;
    let claim = ClaimAt { txid, height };
    // A proof response means the in-flight fetch resolved, whatever the
    // outcome; free the re-queue slot before anything else so a superseded
    // or dropped fetch can be re-issued by a later CTA pass.
    coin_store
        .lock()
        .expect("poisoned")
        .clear_merkle_in_flight(&claim);

    if !header_store_ready::<P>(header_store, notification) {
        return;
    }
    let Some(target) = resolve_tx_merkle_target(coin_store, header_store, txid, height) else {
        retry_reorged_merkle_claim(coin_store, header_store, notification, merkle_id, claim);
        return;
    };
    apply_tx_merkle(coin_store, notification, target, &branch, pos);
}

/// The verified target of a merkle proof: the entry is `ConfirmedUnverified`
/// at exactly `height`, its stored hash still matches the header there, and
/// `expected_root` is that header's merkle root.
struct MerkleTarget {
    txid: Txid,
    height: u32,
    block_hash: BlockHash,
    expected_root: TxMerkleNode,
}

/// Guard a merkle proof against stale or mismatched state and return the
/// target to verify, or `None` (with a debug log) when it must be skipped.
fn resolve_tx_merkle_target<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    txid: Txid,
    height: u32,
) -> Option<MerkleTarget> {
    // Read header data first (without holding the coin_store lock). If
    // headers were pruned by a recent reorg between request and response,
    // the CTA re-fetch pass (`reverify_remined_entries`) re-queues the
    // proof once a header is present at this height again.
    let (expected_root, block_hash) = match header_store.merkle_root_and_hash(height) {
        Some(v) => v,
        None => {
            log::debug!(
                "handle_tx_merkle(): proof for {txid}@{height} but no header in header_store; skipping"
            );
            return None;
        }
    };

    let mut store = coin_store.lock().expect("poisoned");
    let current = match store.tx_store_mut().get(&txid) {
        Some(entry) => entry.inclusion().clone(),
        None => {
            log::debug!("handle_tx_merkle(): proof for unknown txid {txid}; skipping");
            return None;
        }
    };
    let (entry_height, entry_hash) = match current {
        Inclusion::ConfirmedUnverified { height, block_hash } => (height, block_hash),
        _ => {
            log::debug!(
                "handle_tx_merkle(): proof for {txid} not in ConfirmedUnverified state ({current:?}); skipping"
            );
            return None;
        }
    };
    // Only verify the proof against the height the entry is actually
    // claimed at; a stale response for a different height must not promote.
    if entry_height != height {
        log::debug!(
            "handle_tx_merkle(): proof height {height} != entry height {entry_height} for {txid}; skipping"
        );
        return None;
    }
    // The entry's stored hash no longer matches the header at this height:
    // a reorg raced the merkle fetch. This is not a lying server, so stay
    // silent; the reorg re-queue (reverify_remined_entries) owns recovery.
    if entry_hash != block_hash {
        log::debug!(
            "handle_tx_merkle(): proof for {txid}@{height} stored hash {entry_hash} != current hash {block_hash}; reorg race, skipping"
        );
        return None;
    }
    Some(MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    })
}

/// Verify the branch against `target` and update the entry: `Verified` via the
/// shared CTA apply on a good proof, else terminal `VerifyFailed` with a
/// one-shot `ValidationFailed(MerkleProof)` notification.
fn apply_tx_merkle<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    notification: &mpsc::Sender<Notification>,
    target: MerkleTarget,
    branch: &[[u8; 32]],
    pos: u32,
) {
    let MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    } = target;
    let mut store = coin_store.lock().expect("poisoned");
    // The branch arrives in internal (little-endian) order from
    // `decode_tx_merkle_branch`, so it feeds `verify_merkle_branch` directly.
    if verify_merkle_branch(txid, branch, pos, expected_root) {
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::Verified { height, block_hash });
        commit_chain_update(store, notification, true);
    } else {
        // Hard proof mismatch: mark the entry terminally VerifyFailed so it is
        // not re-fetched every tick, and surface the failure exactly once.
        // reverify_remined_entries clears it only if the header hash changes.
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::VerifyFailed { height, block_hash });
        store.tx_store_mut().persist();
        store.generate();
        drop(store);
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::MerkleProof { txid, height },
        ));
    }
}

/// Stamp confirmed, un-timestamped txs with their block time, read from the
/// validated header chain. Entries whose header has not synced yet are left for
/// a later pass.
fn stamp_confirmation_times<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
) {
    let mut store = coin_store.lock().expect("poisoned");
    store.stamp_confirmation_times(|h| header_store.header(h as u32).map(|hdr| hdr.time as u64));
}

/// Chain-tip-advance pass: promote-only, resolves pending claims and queues merkle fetches against the validated chain.
fn on_chain_update<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
    merkle_id: ListenerId,
) {
    if !header_store_ready::<P>(header_store, notification) {
        return;
    }

    let mut store = coin_store.lock().expect("poisoned");

    let reverify = store.reverify_remined_entries(header_store);
    let promote = store.resolve_pending_claims(header_store);
    let changed = reverify.changed || promote.changed;
    let mut to_fetch = reverify.to_fetch;
    to_fetch.extend(promote.to_fetch);

    commit_chain_update(store, notification, changed);
    queue_merkle_fetches::<P>(header_store, merkle_id, to_fetch);
}

/// Dispatch the collected merkle-proof fetches, outside the CoinStore lock and
/// over the header store's own connection.
fn queue_merkle_fetches<P: ScanProfile>(
    header_store: &HeaderStore<P::HeaderStore>,
    merkle_id: ListenerId,
    to_fetch: Vec<ClaimAt>,
) {
    for ClaimAt { txid, height } in to_fetch {
        header_store.fetch_merkle(merkle_id, txid, height);
    }
}

/// Body of [`Reconciler::requeue_confirmed_unverified`], also run at thread
/// start where the two stores are held directly.
fn requeue_confirmed_unverified<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    merkle_id: ListenerId,
) {
    let to_fetch = coin_store
        .lock()
        .expect("poisoned")
        .confirmed_unverified_claims();
    queue_merkle_fetches::<P>(header_store, merkle_id, to_fetch);
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use bwk_descriptor::{derivator::SpkDerivator, descriptor::wpkh};
    use bwk_persist::NoopBackend;
    use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
    use bwk_utils::test::funding_tx;
    use miniscript::bitcoin::{self, bip32::DerivationPath, Network};
    use std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
        sync::{
            mpsc::{self, TryRecvError},
            Arc, Mutex,
        },
        time::Duration,
    };

    use crate::{
        client::CoinRequest,
        coin_store::{ClaimAt, CoinStore},
        fanout::ListenerId,
        header_store::{HeaderStore, MerkleOutcome, MerkleProof},
        label_store::LabelStore,
        notification::{Notification, ValidationFailure},
        reconcile::{
            drain_ticks, handle_merkle_outcome, handle_tx_merkle, on_chain_update, Reconciler,
        },
        scanner::ElectrumScanner,
        tx_store::{Inclusion, TxStore},
    };

    // Build a bare `CoinStore` (no listener thread) for testing the
    // CTA helpers directly.
    fn bare_coin_store() -> (Arc<Mutex<CoinStore>>, SpkDerivator) {
        let (notif_sender, _notif_recv) = mpsc::channel();
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer =
            HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let descriptor = wpkh(xpub);
        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        let label_store = Arc::new(Mutex::new(LabelStore::new()));
        let backend: Arc<dyn bwk_persist::PersistenceBackend> = Arc::new(NoopBackend);
        let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
            backend,
            bwk_persist::ACCOUNT_STORE_KEY,
            crate::profile::encode_account_key,
            crate::profile::encode_account_value,
        )));
        let coin_store = Arc::new(Mutex::new(CoinStore::new(
            bitcoin::Network::Regtest,
            descriptor,
            notif_sender,
            0,
            0,
            20,
            TxStore::new(),
            label_store,
            account_store,
        )));
        (coin_store, derivator)
    }

    /// Build a regtest header chain of `len` blocks (heights `0..len`),
    /// returning the (height -> raw) map and the tip block hash.
    fn build_header_map(len: u32) -> (BTreeMap<u32, [u8; 80]>, miniscript::bitcoin::BlockHash) {
        use miniscript::bitcoin::{
            block::{Header, Version},
            hashes::Hash,
            BlockHash, CompactTarget, TxMerkleNode,
        };
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut map = BTreeMap::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = prev;
        for h in 0..len {
            let hdr = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + h,
                bits,
                nonce: h,
            };
            prev = hdr.block_hash();
            tip = prev;
            let bytes = miniscript::bitcoin::consensus::serialize(&hdr);
            let mut arr = [0u8; 80];
            arr.copy_from_slice(&bytes);
            map.insert(h, arr);
        }
        (map, tip)
    }

    // Regression: after a deep reorg re-confirms a tx at a height
    // M different from the originally-claimed height N, the stale
    // `(N, txid)` entry must not linger in `pending_claims`.
    #[test]
    fn deep_reorg_clears_stale_pending_claims() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        // Seed a tx that is Verified at height M = 7.
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let m: u32 = 7;

        // Build a HeaderStore holding a header at M. `on_chain_update`
        // never demotes, so the Verified-at-M claim is left untouched; the
        // header is present so the seeded state is internally consistent.
        let (map, hash_at_m) = build_header_map(m + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: m,
                    block_hash: hash_at_m,
                },
            );
        }

        // Stale pending claim at the OLD height N = 4 (pre-reorg).
        let n: u32 = 4;
        coin_store
            .lock()
            .unwrap()
            .insert_pending_claim(ClaimAt { txid, height: n });

        let (notif_tx, _notif_rx) = mpsc::channel();

        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        // The stale (N, txid) entry must have been swept (tx is Verified
        // at M != N).
        let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
        assert!(
            snapshot.get(&n).map(|s| !s.contains(&txid)).unwrap_or(true),
            "stale pending claim at N={n} was not cleared: {snapshot:?}",
        );
    }

    // Regression: a claim whose tx is still in flight (History folded, Txs
    // response not yet) must survive a CTA pass. Dropping it as "removed
    // from the chain" wedges the tx Unconfirmed forever once it folds.
    #[test]
    fn pending_claim_survives_tx_fetch_in_flight() {
        use crate::header_store::HeaderStore;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, _notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        // History reports the confirmed tx before its bytes are known: the
        // update stays incomplete and the claim is queued, not promoted.
        {
            let mut store = coin_store.lock().unwrap();
            let mut hist = BTreeMap::new();
            hist.insert(spk, vec![(txid, Some(h as u64))]);
            let outcome = store.handle_history_response(hist);
            assert_eq!(outcome.missing_txs, vec![txid], "tx bytes must be missing");
            store.record_reported_heights(&outcome.reported);
        }
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "nothing to fetch yet"
        );

        // CTA fires while the Txs response is still in flight: the claim
        // must survive (the txid is referenced by an incomplete update).
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        {
            let store = coin_store.lock().unwrap();
            let snapshot = store.pending_claims_snapshot();
            assert!(
                snapshot.get(&h).map(|s| s.contains(&txid)).unwrap_or(false),
                "in-flight claim was dropped: {snapshot:?}",
            );
        }

        // The Txs response folds the tx, then the next CTA promotes it.
        coin_store.lock().unwrap().handle_txs_response(vec![tx]);
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert_eq!(
                entry.inclusion(),
                &Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
                "claim was not promoted after the tx folded",
            );
        }
        match req_rx.try_recv() {
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) => {
                assert_eq!(t, txid);
                assert_eq!(height, h);
            }
            other => panic!("expected GetTxMerkle, got {other:?}"),
        }
    }

    // Regression: history re-reports EVERY confirmed tx, not just the ones
    // whose height changed. An already-Verified tx re-reported at its SAME
    // height must stay Verified (the pass is promote-only); it must not be
    // demoted to ConfirmedUnverified nor trigger a fresh GetTxMerkle.
    #[test]
    fn re_report_does_not_demote_verified() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        // HeaderStore holds a real header at H, so the seeded Verified state
        // is internally consistent.
        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();
        header_store.set_merkle_sender_for_test(req_tx);

        // Server re-reports the same tx at the same height.
        coin_store
            .lock()
            .unwrap()
            .record_reported_heights(&[ClaimAt { txid, height: h }]);

        // The entry is STILL Verified at H (not demoted).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::Verified {
                    height, block_hash, ..
                } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, hash_at_h, "block_hash changed");
                }
                other => panic!("expected Verified{{H}}, got {other:?}"),
            }
        }

        // No GetTxMerkle was queued.
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a re-reported Verified tx",
        );
    }

    // A ConfirmedUnverified entry whose stored hash still matches the header
    // (its single-shot merkle fetch was dropped or errored) must be
    // re-queued by the CTA pass, without mutating state or notifying.
    #[test]
    fn stuck_confirmed_unverified_refetched_by_cta() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        // Exactly one re-queued fetch.
        assert!(matches!(
            req_rx.try_recv().unwrap(),
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // No state change: entry untouched, nothing notified.
        assert!(matches!(notif_rx.try_recv(), Err(TryRecvError::Empty)));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash }
                if *height == h && *block_hash == hash_at_h
        ));
    }

    // A fetch that fails, here because no merkle client is connected to take
    // it, must free the in-flight slot it took: the guard would otherwise
    // block every later re-queue and leave the entry ConfirmedUnverified for
    // good.
    #[test]
    fn a_failed_merkle_fetch_is_refetched_by_cta() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let merkle_id = ListenerId::next();
        let outcomes = header_store.register_merkle_outcome(merkle_id);
        let (notif_tx, _notif_rx) = mpsc::channel();

        // No merkle client: the fetch is marked in flight, then fails.
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        let outcome = outcomes.try_recv().expect("the failure must be reported");
        assert!(matches!(
            outcome,
            MerkleOutcome::Failed { txid: t, height } if t == txid && height == h
        ));

        // A client is back, but the slot is still taken: no re-queue yet.
        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // Handling the failure frees it, and the next pass asks again.
        handle_merkle_outcome(&coin_store, &header_store, &notif_tx, merkle_id, outcome);
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(
            req_rx.try_recv().unwrap(),
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
    }

    // A Verified entry whose stored hash matches the header must NOT be
    // re-fetched by the CTA pass.
    #[test]
    fn verified_with_matching_hash_not_refetched_by_cta() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, _notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a Verified entry with a matching hash",
        );
    }

    // Same-height reorg re-verification: a tx left `Verified` at height H
    // against a now-stale `block_hash` (the server re-mined it at the SAME
    // height in a DIFFERENT block, so the scripthash status is unchanged and
    // the history path never demotes it). `on_chain_update` must notice the
    // stored hash no longer matches the HeaderStore header at H, reset the
    // entry to `ConfirmedUnverified { H, B_new }`, and queue a fresh
    // `GetTxMerkle { H }`. It must NOT push the entry to `Unconfirmed`.
    #[test]
    fn same_height_reorg_reverifies_stale_block_hash() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // Build a HeaderStore whose header at H has block hash B_new,
        // distinct from the B_old we seed the tx with below.
        let (map, b_new) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // A clearly different (stale) block hash B_old, distinct from B_new.
        let b_old = miniscript::bitcoin::BlockHash::from_byte_array([0x7au8; 32]);
        assert_ne!(b_old, b_new);

        // Seed the tx Verified at H with the stale hash B_old.
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: b_old,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, _notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        // The entry was reset to ConfirmedUnverified at the SAME height with
        // the NEW block hash (re-verification, not demotion).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::ConfirmedUnverified { height, block_hash } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, b_new, "block_hash not updated to B_new");
                }
                other => panic!("expected ConfirmedUnverified{{H,B_new}}, got {other:?}"),
            }
        }

        // A GetTxMerkle for (txid, H) must have been queued.
        let mut saw_merkle = false;
        while let Ok(req) = req_rx.try_recv() {
            if let CoinRequest::GetTxMerkle { txid: t, height } = req {
                if t == txid && height == h {
                    saw_merkle = true;
                }
            }
        }
        assert!(saw_merkle, "GetTxMerkle{{H}} was not queued");
    }

    // The reported height is recorded as a claim whatever the header store's
    // state, replacing a stale claim at another height, but promotion waits
    // for the store to be validated.
    #[test]
    fn history_waits_for_header_validation_then_promotes_reported_claim() {
        use crate::header_store::{HeaderStore, HeaderValidationState};

        let (coin_store, derivator) = bare_coin_store();
        let spk = derivator.receive_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 4;

        let (map, block_hash) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store.set_validation_state_for_test(HeaderValidationState::Validating);

        coin_store.lock().unwrap().insert_pending_claim(ClaimAt {
            txid,
            height: h - 1,
        });

        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, _notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        // The scan folds the history and records the reported height, dropping
        // the stale claim; it never promotes, so nothing is fetched here.
        {
            let mut store = coin_store.lock().unwrap();
            let outcome = store
                .handle_history_response(BTreeMap::from([(spk, vec![(txid, Some(h as u64))])]));
            assert_eq!(outcome.missing_txs, vec![txid]);
            store.record_reported_heights(&outcome.reported);
            assert!(store.tx_store_mut().get(&txid).is_none());
            assert_eq!(
                store.pending_claims_snapshot(),
                BTreeMap::from([(h, BTreeSet::from([txid]))])
            );
        }
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // The bytes land, but the header store is still validating: the claim
        // stays queued and the entry stays Unconfirmed.
        coin_store.lock().unwrap().handle_txs_response(vec![tx]);
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "validation-gated update queued merkle proof too early"
        );
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert!(matches!(entry.inclusion(), Inclusion::Unconfirmed));
            assert_eq!(
                store.pending_claims_snapshot(),
                BTreeMap::from([(h, BTreeSet::from([txid]))])
            );
        }

        header_store.set_validation_state_for_test(HeaderValidationState::Valid);
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        let req = req_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("validation recovery should queue merkle proof");
        assert!(matches!(
            req,
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash: bh }
                if *height == h && *bh == block_hash
        ));
    }

    // A failure frees the fetch it names and no other: a stale failure at a
    // height the entry is no longer claimed at must leave the live fetch in
    // flight, or the entry is asked for twice.
    #[test]
    fn merkle_errors_release_only_their_in_flight_fetch() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 4;
        let (map, block_hash) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        {
            let mut store = coin_store.lock().unwrap();
            store.tx_store_mut().update(TxEntry::for_test(tx));
            store.tx_store_mut().update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash,
                },
            );
        }
        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, _notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // A failure naming another height frees nothing.
        handle_merkle_outcome(
            &coin_store,
            &header_store,
            &notif_tx,
            merkle_id,
            MerkleOutcome::Failed {
                txid,
                height: h - 1,
            },
        );
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // The failure of the live fetch frees it, and the next pass asks again.
        handle_merkle_outcome(
            &coin_store,
            &header_store,
            &notif_tx,
            merkle_id,
            MerkleOutcome::Failed { txid, height: h },
        );
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).unwrap();
        assert_eq!(
            entry.inclusion(),
            &Inclusion::ConfirmedUnverified {
                height: h,
                block_hash,
            }
        );
    }

    // Regression for the stale-pending-claim wedge: a tx queued at an OLD
    // height N_old (whose header IS present) must not be promoted to N_old
    // after a reorg re-reports it at N_new. `record_reported_heights` must
    // drop the stale `(N_old, txid)` claim before queueing `(N_new, txid)`,
    // so the subsequent `on_chain_update` cannot promote the tx to the
    // wrong (N_old) height and wedge it ConfirmedUnverified forever.
    #[test]
    fn re_report_purges_stale_pending_claim() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let n_old: u32 = 4;
        let n_new: u32 = 9;

        // HeaderStore holds headers 0..=n_old only. Height n_new has NO
        // header yet, so the re-report at n_new takes the queue branch
        // while n_old IS reachable (the dangerous case).
        let (map, _tip) = build_header_map(n_old + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // Seed the tx as Unconfirmed (post-reorg history reset state).
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
        }

        // Pre-existing stale pending claim at the OLD height N_old.
        coin_store.lock().unwrap().insert_pending_claim(ClaimAt {
            txid,
            height: n_old,
        });

        let (notif_tx, _notif_rx) = mpsc::channel();

        let merkle_id = ListenerId::next();

        // History re-reports the tx at N_new (its new post-reorg height).
        coin_store
            .lock()
            .unwrap()
            .record_reported_heights(&[ClaimAt {
                txid,
                height: n_new,
            }]);

        // The stale (N_old, txid) entry is gone; only (N_new, txid) remains.
        {
            let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
            assert!(
                snapshot
                    .get(&n_old)
                    .map(|s| !s.contains(&txid))
                    .unwrap_or(true),
                "stale pending claim at N_old={n_old} not purged: {snapshot:?}",
            );
            assert!(
                snapshot
                    .get(&n_new)
                    .map(|s| s.contains(&txid))
                    .unwrap_or(false),
                "new pending claim at N_new={n_new} not queued: {snapshot:?}",
            );
        }

        // A subsequent CTA must NOT promote the tx to N_old (its header is
        // reachable, but the stale claim is gone). The tx stays Unconfirmed.
        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "tx wrongly promoted to {:?} (expected Unconfirmed)",
            entry.inclusion(),
        );
    }

    // Deterministic demotion: a tx seeded as `Inclusion::Verified` at height H
    // is reset to `Inclusion::Unconfirmed` when the server re-reports it at a
    // DIFFERENT height. This is the history-owned path
    // (`update_spk_history` resets `diff.changed` txids), distinct from the
    // same-height hash-change case (`Verified -> ConfirmedUnverified`).
    #[test]
    fn reported_height_change_demotes_verified_to_unconfirmed() {
        use crate::tx_store::TxEntry;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_spk_at(0);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // A concrete block hash at height H so the seeded Verified state is
        // internally consistent.
        let (_map, hash_at_h) = build_header_map(h + 1);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        // Prime the spk history at the seeded height: the tx lands in
        // `diff.added`, which never resets inclusion, so Verified survives.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some(h as u64))]);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert!(
                matches!(
                    entry.inclusion(),
                    Inclusion::Verified { height, block_hash }
                        if *height == h && *block_hash == hash_at_h
                ),
                "priming report must not demote; got {:?}",
                entry.inclusion(),
            );
        }

        // Server re-reports the SAME tx at a DIFFERENT height: the txid lands
        // in `diff.changed`, which resets it to Unconfirmed.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some((h + 3) as u64))]);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert_eq!(
            *entry.inclusion(),
            Inclusion::Unconfirmed,
            "reported-height change must demote Verified -> Unconfirmed",
        );
    }

    // Refusal path: when the HeaderStore itself is Invalid, `on_chain_update`
    // must refuse to promote any pending claim and instead notify
    // `ValidationFailed(HeaderStore(_))`.
    #[test]
    fn invalid_header_store_blocks_promotion() {
        use crate::{
            header_store::{HeaderStore, HeaderValidationState, InvalidCause},
            tx_store::TxEntry,
        };

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        // Header at H is present, so a Valid store would promote the claim;
        // the Invalid state below is what must block it.
        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store
            .set_validation_state_for_test(HeaderValidationState::Invalid(InvalidCause::Sanity));

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
            store.insert_pending_claim(ClaimAt { txid, height: h });
        }

        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, notif_rx) = mpsc::channel();
        let merkle_id = ListenerId::next();

        on_chain_update(&coin_store, &header_store, &notif_tx, merkle_id);

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::HeaderStore(_))
            ),
            "expected ValidationFailed(HeaderStore(_)), got {notif:?}"
        );

        assert!(
            req_rx.try_recv().is_err(),
            "no merkle fetch should be queued while the header store is invalid"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "claim wrongly promoted to {:?} despite invalid header store",
            entry.inclusion(),
        );
    }

    // A pending claim whose txid was removed from the tx store (a reorg
    // dropped it) must be dropped by `resolve_pending_claims` rather than left
    // queued forever.
    #[test]
    fn resolve_pending_claims_drops_removed_txid() {
        let (coin_store, _deriv) = bare_coin_store();
        let (map, _tip) = build_header_map(5);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let txid = funding_tx(bitcoin::ScriptBuf::new(), 0.1).compute_txid();
        let h: u32 = 3;
        {
            let mut store = coin_store.lock().unwrap();
            store.insert_pending_claim(ClaimAt { txid, height: h });
            assert!(!store.pending_claims_snapshot().is_empty());
        }

        let mut store = coin_store.lock().unwrap();
        let outcome = store.resolve_pending_claims(&header_store);
        assert!(!outcome.changed, "no promotion for an absent txid");
        assert!(
            store.pending_claims_snapshot().is_empty(),
            "stale claim for a removed txid must be dropped"
        );
    }

    // Refusal path: a tampered merkle branch against a header whose hash
    // still matches the entry's stored hash must notify
    // `ValidationFailed(MerkleProof)` and move the entry to the terminal
    // `VerifyFailed` state so it is not re-fetched every tick.
    #[test]
    fn handle_tx_merkle_tampered_branch_notifies() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let block_hash = header_store.block_hash(h).expect("header at h present");

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash,
                },
            );
        }

        let (notif_tx, notif_rx) = mpsc::channel();
        // A sibling that does not fold to the header's (all-zero) merkle
        // root: the proof fails verification.
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &notif_tx,
            ListenerId::next(),
            MerkleProof {
                txid,
                height: h,
                branch: vec![[0x11u8; 32]],
                pos: 0,
            },
        );

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::MerkleProof { txid: t, height })
                    if t == txid && height == h
            ),
            "expected ValidationFailed(MerkleProof), got {notif:?}"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::VerifyFailed { height, block_hash: b }
                    if *height == h && *b == block_hash
            ),
            "entry not moved to VerifyFailed: {:?}",
            entry.inclusion(),
        );
    }

    // A stale proof response after a same-height reorg must requeue against
    // the replacement block instead of marking the transaction failed.
    #[test]
    fn handle_tx_merkle_hash_mismatch_requeues_replacement() {
        use crate::{header_store::HeaderStore, tx_store::TxEntry};
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let stale_hash = bitcoin::BlockHash::all_zeros();
        assert_ne!(
            header_store.block_hash(h).expect("header at h present"),
            stale_hash
        );

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: stale_hash,
                },
            );
        }

        let current_hash = header_store.block_hash(h).unwrap();
        let (req_tx, req_rx) = mpsc::channel();
        header_store.set_merkle_sender_for_test(req_tx);
        let (notif_tx, notif_rx) = mpsc::channel();
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &notif_tx,
            ListenerId::next(),
            MerkleProof {
                txid,
                height: h,
                branch: Vec::new(),
                pos: 0,
            },
        );

        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) if t == txid && height == h
        ));
        assert!(matches!(
            notif_rx.try_recv(),
            Ok(Notification::HeaderStoreUpdated)
        ));
        assert!(matches!(notif_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::ConfirmedUnverified { height, block_hash: b }
                    if *height == h && *b == current_hash
            ),
            "entry was not restamped after hash mismatch: {:?}",
            entry.inclusion(),
        );
    }

    // A scan tick from the scanner the pass was paired with must wake it: the
    // claim it promotes queues its merkle fetch, with no chain tick involved.
    #[test]
    fn a_scan_tick_wakes_the_reconciler() {
        let scanner = ElectrumScanner::offline_for_test();
        let spk = scanner.recv_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();
        header_store.set_merkle_sender_for_test(req_tx);

        // Fold the tx the way the listener does: history first, then its bytes.
        {
            let mut store = scanner.coin_store().lock().unwrap();
            let mut hist = BTreeMap::new();
            hist.insert(spk, vec![(txid, Some(h as u64))]);
            let outcome = store.handle_history_response(hist);
            store.record_reported_heights(&outcome.reported);
            store.handle_txs_response(vec![tx]);
        }

        let (notif_tx, _notif_rx) = mpsc::channel();
        let scan_listeners = scanner.scan_listeners();
        let _reconciler = Reconciler::spawn(&scanner, header_store, notif_tx);
        assert_eq!(scan_listeners.listener_count(), 1);
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "the claim must sit until a tick wakes the pass"
        );

        scan_listeners.notify(());

        match req_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(CoinRequest::GetTxMerkle {
                txid: fetched,
                height,
            }) => {
                assert_eq!(fetched, txid);
                assert_eq!(height, h);
            }
            other => panic!("expected GetTxMerkle for the promoted claim, got {other:?}"),
        }
    }

    // Every queued tick must collapse into a single pass, and neither an empty
    // nor a disconnected channel is a tick.
    #[test]
    fn drain_ticks_coalesces_the_queued_ticks() {
        let (tx, rx) = mpsc::channel::<()>();
        assert!(!drain_ticks(&rx), "an empty channel is not a tick");

        for _ in 0..3 {
            tx.send(()).unwrap();
        }
        assert!(drain_ticks(&rx), "three queued ticks are one pass");
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty), "none was left");
        assert!(!drain_ticks(&rx), "a drained tick is not replayed");

        drop(tx);
        assert!(!drain_ticks(&rx), "a gone sender is not a tick");
    }
}
