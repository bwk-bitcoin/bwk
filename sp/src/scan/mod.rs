//! Parts of the scan algorithms are adapted from cygnet3/spdk. The worker
//! pipeline, persistence, and native candidate-SPK path are BWK additions.
//! See `sp/NOTICE`.

#[cfg(feature = "scan-profile")]
pub mod profiling;
pub mod state;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroUsize,
    ops::RangeInclusive,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Instant,
};

use bitcoin::{
    absolute::Height,
    bip158::BlockFilter,
    hashes::{sha256, Hash},
    secp256k1::PublicKey,
    Amount, BlockHash, OutPoint, Txid, XOnlyPublicKey,
};

use bwk::bwk_electrum::notification::{Notification, SpNotification};
use crossbeam::channel;

use crate::{
    account::{coin_store::SpCoinStore, tx_store::SpTxEntry},
    blindbit,
    core::receiving::Label,
    profile::SpStorageProfile,
    receiver::{self, BlockData, FilterData, OutputSpendStatus, OwnedOutput, SpReceiver, UtxoData},
    scan::state::ScanState,
    thread_pool::ThreadPool,
};

/// Progress callbacks invoked during a scan: one per fetched block, and one per
/// height while sweeping spent filters.
pub type BlockDataObserver = Arc<dyn Fn(&BlockData) + Send + Sync>;
pub type HeightObserver = Arc<dyn Fn(Height) + Send + Sync>;

pub const DEFAULT_FETCH_CONCURRENCY_FACTOR: usize = 12;
pub const MAX_FETCH_CONCURRENCY_FACTOR: usize = 32;
const DEFAULT_PARALLELISM: usize = 8;
const BLOCK_CHANNEL_CAPACITY: usize = 64;
const MATCH_WINDOW_MAX: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanRuntimeConfig {
    fetch_concurrency_factor: NonZeroUsize,
    fetch_concurrency: NonZeroUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScanRuntimeConfigError {
    #[error("SP fetch concurrency factor must be between 1 and {MAX_FETCH_CONCURRENCY_FACTOR}")]
    InvalidFetchConcurrencyFactor,
}

impl ScanRuntimeConfig {
    pub fn from_fetch_concurrency_factor(
        fetch_concurrency_factor: usize,
    ) -> Result<Self, ScanRuntimeConfigError> {
        let fetch_concurrency_factor = factor(
            fetch_concurrency_factor,
            MAX_FETCH_CONCURRENCY_FACTOR,
            ScanRuntimeConfigError::InvalidFetchConcurrencyFactor,
        )?;
        let parallelism = available_parallelism();
        let fetch_concurrency = NonZeroUsize::new(parallelism * fetch_concurrency_factor.get())
            .expect("factor is non-zero");
        Ok(Self {
            fetch_concurrency_factor,
            fetch_concurrency,
        })
    }

    pub fn fetch_concurrency_factor(self) -> usize {
        self.fetch_concurrency_factor.get()
    }

    pub fn fetch_concurrency(self) -> usize {
        self.fetch_concurrency.get()
    }
}

impl Default for ScanRuntimeConfig {
    fn default() -> Self {
        Self::from_fetch_concurrency_factor(DEFAULT_FETCH_CONCURRENCY_FACTOR)
            .expect("default scan runtime config is valid")
    }
}

fn factor(
    value: usize,
    max: usize,
    error: ScanRuntimeConfigError,
) -> Result<NonZeroUsize, ScanRuntimeConfigError> {
    if value == 0 || value > max {
        return Err(error);
    }
    Ok(NonZeroUsize::new(value).expect("value checked above"))
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(DEFAULT_PARALLELISM)
}

pub(crate) fn fetch_concurrency() -> usize {
    ScanRuntimeConfig::default().fetch_concurrency()
}

fn match_window_cap() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        if let Some(n) = std::env::var("BWK_SP_MATCH_WINDOW")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
        {
            return n;
        }
        available_parallelism().min(MATCH_WINDOW_MAX)
    })
}

fn is_cancelled(stop: &AtomicBool, abort: &AtomicBool) -> bool {
    stop.load(Ordering::Relaxed) || abort.load(Ordering::Relaxed)
}

fn abort_once(abort: &AtomicBool) -> bool {
    abort
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

struct FetchWorkers {
    abort: Arc<AtomicBool>,
    pool: ThreadPool,
}

impl FetchWorkers {
    fn stop(self) {
        self.abort.store(true, Ordering::Relaxed);
        self.pool.shutdown();
    }
}

fn fetch_channel_cap() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("BWK_SP_FETCH_CHANNEL_CAP")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(BLOCK_CHANNEL_CAPACITY)
    })
}

/// Tweaks per batched native candidate-derivation call. Each chunk is one FFI
/// call; a block's tweaks split into chunks processed sequentially (the scan
/// parallelizes across blocks in the match window, not across a block's chunks).
/// Matches the native primitive's internal tweak-chunk size so each call is one
/// chunk.
const CANDIDATE_TWEAK_CHUNK: usize = 32;

/// Tweak-chunk size, overridable via `BWK_SP_CANDIDATE_CHUNK` for tuning the
/// batch granularity. Only changes how a block's tweaks split into batched
/// calls; the native primitive's internal chunk (`SP_BATCH_TWEAK_CHUNK`) is
/// compile-time. Defaults to the const above.
fn candidate_tweak_chunk() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::var("BWK_SP_CANDIDATE_CHUNK")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(CANDIDATE_TWEAK_CHUNK)
    })
}

pub(crate) fn script_to_secret_map(
    sp_receiver: &SpReceiver,
    tweak_data_vec: Vec<PublicKey>,
) -> Result<HashMap<[u8; 34], PublicKey>, receiver::error::Error> {
    let b_scan = &sp_receiver.get_scan_key();

    // ECDH per tweak, then SPK derivation. Only reached on a filter match;
    // sequential within the block, as the scan parallelizes across blocks.
    let shared_secrets: Vec<PublicKey> = tweak_data_vec
        .into_iter()
        .map(|tweak| crate::core::receiving::calculate_ecdh_shared_secret(&tweak, b_scan))
        .collect();

    let items: Result<Vec<_>, receiver::error::Error> = shared_secrets
        .into_iter()
        .map(|secret| {
            let spks = sp_receiver.receiver.get_spks_from_shared_secret(&secret)?;
            Ok((secret, spks.into_values()))
        })
        .collect();

    let mut res = HashMap::new();
    for (secret, spks) in items? {
        for spk in spks {
            res.insert(spk, secret);
        }
    }
    Ok(res)
}

/// The candidate output spks for a batch of tweaks, derived in one native
/// call per tweak (vartime ECDH plus `k = 0` candidate derivation, no FFI
/// round-trips). The spend points are constant across tweaks, so they are
/// computed once and reused. This is the GCS-filter membership set; on a
/// match the caller recovers the shared secrets via [`script_to_secret_map`].
pub(crate) fn candidate_spks(
    sp_receiver: &SpReceiver,
    tweaks: &[[u8; 33]],
) -> Result<Vec<[u8; 34]>, receiver::error::Error> {
    let scan_key = sp_receiver.get_scan_key();
    let spend_points = sp_receiver.receiver.candidate_spend_points()?;

    #[cfg(feature = "scan-profile")]
    let __t = std::time::Instant::now();
    // One batched native call per chunk of tweaks. Sequential within the
    // block; the scan parallelizes across blocks in the match window.
    let spks: Result<Vec<Vec<[u8; 34]>>, receiver::error::Error> = tweaks
        .chunks(candidate_tweak_chunk())
        .map(|chunk| {
            sp_receiver
                .receiver
                .candidate_output_spks_batch(chunk, &scan_key, &spend_points)
                .map_err(Into::into)
        })
        .collect();
    #[cfg(feature = "scan-profile")]
    profiling::add(&profiling::CANDIDATES_NS, __t.elapsed());

    Ok(spks?.into_iter().flatten().collect())
}

/// Fetch tweaks + new-utxo filter for every height in `range`, fanning out over
/// a bounded worker pool and streaming `BlockData` into `sender` in completion
/// order. Non-blocking: queues the heights, spawns the pool, and returns
/// immediately. The bounded channel applies backpressure, so fetching stays at
/// most `fetch_channel_cap()` blocks ahead of the consumer.
fn fetch_blocks<P: SpStorageProfile>(
    sender: channel::Sender<Result<BlockData, receiver::error::Error>>,
    backend: &BackendContext,
    scan: &ScanContext<P>,
) -> FetchWorkers {
    // Height 0 has no block to fetch; clamp the start to 1.
    let start = scan.start.to_consensus_u32().max(1);
    let end = scan.end.to_consensus_u32();
    spawn_block_fetchers(
        backend.agent.clone(),
        backend.url.clone(),
        start..=end,
        backend.dust_limit,
        backend.with_cutthrough,
        sender,
        scan.block_data_observer.clone(),
        Arc::clone(scan.stop),
        scan.runtime.fetch_concurrency(),
    )
}

#[allow(clippy::too_many_arguments)]
fn spawn_block_fetchers(
    agent: Arc<ureq::Agent>,
    url: String,
    range: RangeInclusive<u32>,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    sender: channel::Sender<Result<BlockData, receiver::error::Error>>,
    block_data_observer: Option<BlockDataObserver>,
    stop: Arc<AtomicBool>,
    fetch_concurrency: usize,
) -> FetchWorkers {
    let start = *range.start();
    let end = *range.end();
    let next = Arc::new(AtomicU32::new(start));
    let abort = Arc::new(AtomicBool::new(false));
    let pool = ThreadPool::new(fetch_concurrency);
    for _ in 0..fetch_concurrency {
        let agent = agent.clone();
        let url = url.clone();
        let sender = sender.clone();
        let block_data_observer = block_data_observer.clone();
        let next = Arc::clone(&next);
        let abort = Arc::clone(&abort);
        let stop = Arc::clone(&stop);
        pool.execute(move || loop {
            let height = next.fetch_add(1, Ordering::Relaxed);
            if height > end || is_cancelled(&stop, &abort) {
                break;
            }
            match fetch_block_data_for_height(
                &agent,
                &url,
                height,
                dust_limit,
                with_cutthrough,
                &stop,
                &abort,
            ) {
                Ok(Some(block_data)) => {
                    if is_cancelled(&stop, &abort) {
                        break;
                    }
                    if let Some(observer) = &block_data_observer {
                        observer(&block_data);
                    }
                    if sender.send(Ok(block_data)).is_err() {
                        abort.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    if abort_once(&abort) {
                        let _ = sender.send(Err(e));
                    }
                    break;
                }
            }
        });
    }
    FetchWorkers { abort, pool }
}

fn fetch_block_data_for_height(
    agent: &ureq::Agent,
    url: &str,
    height: u32,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    stop: &AtomicBool,
    abort: &AtomicBool,
) -> Result<Option<BlockData>, receiver::error::Error> {
    if is_cancelled(stop, abort) {
        return Ok(None);
    }
    let blkheight = Height::from_consensus(height).map_err(receiver::error::Error::from)?;
    let tweaks = match with_cutthrough {
        true => blindbit::tweaks(agent, url, blkheight, dust_limit),
        false => blindbit::tweak_index(agent, url, blkheight, dust_limit),
    };
    let tweaks = tweaks.map_err(receiver::error::Error::from)?;
    if is_cancelled(stop, abort) {
        return Ok(None);
    }
    let new_utxo_filter =
        blindbit::filter_new_utxos(agent, url, blkheight).map_err(receiver::error::Error::from)?;
    if is_cancelled(stop, abort) {
        return Ok(None);
    }
    let blkhash = new_utxo_filter.block_hash;
    Ok(Some(BlockData {
        blkheight,
        blkhash,
        tweaks,
        new_utxo_filter: new_utxo_filter.into(),
    }))
}

/// Concurrent spent-filter fetch for the spend sweep: one `filter/spent/{h}` GET
/// per height, fanned out across the fetch pool into a bounded channel, the same
/// pipeline `fetch_blocks` uses on the receive side. Input matching is ~free, so
/// the collector just drains and tests each filter as it arrives; the bound applies
/// backpressure. The pool is dropped here (workers keep draining the queue, then
/// exit), so this returns immediately after enqueuing.
/// In-order source of per-block spend detections for the sweep.
///
/// The production impl ([`BlindbitSpendScanner`]) fans spent-filter fetches over a
/// worker pool, keeping a window of `fetch_concurrency()` heights in flight ahead
/// of the cursor and matching each filter against the current watch set on the
/// calling thread. [`SpendScanner::jump_to`] lets the sweep skip a gap of heights
/// that have no watchable coin without ever fetching them.
struct SpendsAt {
    height: u32,
    block_hash: BlockHash,
    spent: HashSet<OutPoint>,
}

trait SpendScanner {
    /// Detect spends at the current cursor height against `watch`, then advance the
    /// cursor by one.
    fn next(&mut self, watch: &HashSet<OutPoint>) -> Result<SpendsAt, receiver::error::Error>;

    /// Resume the next [`SpendScanner::next`] at `to`, discarding work below it.
    /// Heights between the old position and `to` are never fetched.
    fn jump_to(&mut self, to: u32);
}

/// Spent-filter scanner over the blindbit backend. Keeps up to
/// `fetch_concurrency()` heights in flight in a sliding window ahead of the
/// cursor; filters arriving ahead of the cursor are buffered, stale ones (below
/// the cursor, e.g. after a jump) are dropped.
struct BlindbitSpendScanner {
    agent: Arc<ureq::Agent>,
    url: String,
    pool: ThreadPool,
    abort: Arc<AtomicBool>,
    tx: channel::Sender<(u32, Result<FilterData, receiver::error::Error>)>,
    rx: channel::Receiver<(u32, Result<FilterData, receiver::error::Error>)>,
    cursor: u32,
    next_to_fetch: u32,
    end: u32,
    window: u32,
    buf: BTreeMap<u32, FilterData>,
}

impl BlindbitSpendScanner {
    fn new(backend: &BackendContext, cursor: u32, end: u32) -> Self {
        let (tx, rx) = channel::unbounded();
        let abort = Arc::new(AtomicBool::new(false));
        let fetch_concurrency = backend.runtime.fetch_concurrency();
        let mut scanner = Self {
            agent: backend.agent.clone(),
            url: backend.url.clone(),
            pool: ThreadPool::new(fetch_concurrency),
            abort,
            tx,
            rx,
            cursor,
            next_to_fetch: cursor,
            end,
            window: fetch_concurrency as u32,
            buf: BTreeMap::new(),
        };
        scanner.refill();
        scanner
    }

    /// Submit fetches so the window `[cursor, cursor + window)` (clamped to `end`)
    /// is in flight or buffered. Gap heights below `next_to_fetch` are never
    /// submitted.
    fn refill(&mut self) {
        if self.abort.load(Ordering::Relaxed) {
            return;
        }
        let limit = self
            .cursor
            .saturating_add(self.window)
            .min(self.end.saturating_add(1));
        while self.next_to_fetch < limit {
            let height = self.next_to_fetch;
            let agent = self.agent.clone();
            let url = self.url.clone();
            let tx = self.tx.clone();
            let abort = Arc::clone(&self.abort);
            self.pool.execute(move || {
                if abort.load(Ordering::Relaxed) {
                    return;
                }
                let res = Height::from_consensus(height)
                    .map_err(receiver::error::Error::from)
                    .and_then(|bh| {
                        blindbit::spent_filter(&agent, &url, bh, None)
                            .map_err(receiver::error::Error::from)
                    });
                if abort.load(Ordering::Relaxed) {
                    return;
                }
                if res.is_err() {
                    if abort_once(&abort) {
                        let _ = tx.send((height, res));
                    }
                    return;
                }
                if tx.send((height, res)).is_err() {
                    abort.store(true, Ordering::Relaxed);
                }
            });
            self.next_to_fetch += 1;
        }
    }
}

impl Drop for BlindbitSpendScanner {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Relaxed);
        self.pool.join();
    }
}

impl SpendScanner for BlindbitSpendScanner {
    fn next(&mut self, watch: &HashSet<OutPoint>) -> Result<SpendsAt, receiver::error::Error> {
        self.refill();
        let filter = loop {
            if let Some(f) = self.buf.remove(&self.cursor) {
                break f;
            }
            // We hold `tx`, so the channel never disconnects while we are alive.
            let (height, res) = self.rx.recv().expect("spend-filter fetchers dropped");
            if height < self.cursor {
                continue; // stale (jumped past), discard
            }
            let f = res?;
            if height == self.cursor {
                break f;
            }
            self.buf.insert(height, f);
        };
        let blkheight = Height::from_consensus(self.cursor)?;
        let blkhash = filter.block_hash;
        let spent = match_inputs_for(&self.agent, &self.url, blkheight, filter, watch)?;
        let height = self.cursor;
        self.cursor += 1;
        self.refill();
        Ok(SpendsAt {
            height,
            block_hash: blkhash,
            spent,
        })
    }

    fn jump_to(&mut self, to: u32) {
        self.cursor = to;
        self.next_to_fetch = self.next_to_fetch.max(to);
        self.buf.retain(|&h, _| h >= to);
        self.refill();
    }
}

pub struct ScanStores<P: SpStorageProfile> {
    pub coin_store: Arc<Mutex<SpCoinStore<P>>>,
    pub tx_store: Arc<Mutex<crate::account::tx_store::SpTxStore<P>>>,
    pub scan_state: Arc<Mutex<ScanState>>,
    pub sender: mpsc::Sender<Notification>,
    pub header_store: Arc<bwk::bwk_electrum::header_store::HeaderStore>,
}

/// Resolve a block's time for `height` from the shared HeaderStore, whose worker
/// follows the chain and stores every header (with its nTime). Non-blocking: a
/// height the worker has not synced yet returns `None` and is stamped on a later
/// scan by [`restamp_missing_timestamps`], so a scan never stalls waiting for a
/// header (which never arrives at all when no endpoint worker is running).
fn block_time<P: SpStorageProfile>(stores: &ScanStores<P>, height: u32) -> Option<u64> {
    stores.header_store.header(height).map(|h| h.time as u64)
}

/// Fill in confirmation timestamps left `None` by an earlier scan (the header
/// was not synced yet when the tx confirmed). Runs at the start of every scan so
/// stragglers heal as the header worker catches up.
fn restamp_missing_timestamps<P: SpStorageProfile>(stores: &ScanStores<P>) {
    let mut tx_store = stores.tx_store.lock().expect("poisoned");
    let mut stamped = false;
    for entry in tx_store.transactions() {
        if entry.timestamp.is_some() {
            continue;
        }
        if let Some(height) = entry.height {
            if let Some(time) = block_time(stores, height) {
                tx_store.update_timestamp(&entry.txid, time);
                stamped = true;
            }
        }
    }
    if stamped {
        tx_store.persist();
    }
}

/// Connection + fetch config for the blindbit backend. Grouped so the scan
/// pipeline takes one backend handle; later this can be made generic over the
/// transport.
struct BackendContext {
    agent: Arc<ureq::Agent>,
    url: String,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    runtime: ScanRuntimeConfig,
}

/// Wallet-side handles and the height range for a scan.
struct ScanContext<'a, P: SpStorageProfile> {
    sp_receiver: &'a SpReceiver,
    stores: &'a ScanStores<P>,
    stop: &'a Arc<AtomicBool>,
    start: Height,
    end: Height,
    runtime: ScanRuntimeConfig,
    block_data_observer: Option<BlockDataObserver>,
}

#[allow(clippy::too_many_arguments)]
pub fn scan_blocks<P: SpStorageProfile>(
    agent: Arc<ureq::Agent>,
    blindbit_url: &str,
    sp_receiver: &SpReceiver,
    stores: &ScanStores<P>,
    stop: &Arc<AtomicBool>,
    start: Height,
    end: Height,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    runtime: ScanRuntimeConfig,
) -> Result<(), receiver::error::Error> {
    scan_blocks_with_observer(
        agent,
        blindbit_url,
        sp_receiver,
        stores,
        stop,
        start,
        end,
        dust_limit,
        with_cutthrough,
        runtime,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scan_blocks_with_observer<P: SpStorageProfile>(
    agent: Arc<ureq::Agent>,
    blindbit_url: &str,
    sp_receiver: &SpReceiver,
    stores: &ScanStores<P>,
    stop: &Arc<AtomicBool>,
    start: Height,
    end: Height,
    dust_limit: Option<Amount>,
    with_cutthrough: bool,
    runtime: ScanRuntimeConfig,
    block_data_observer: Option<BlockDataObserver>,
) -> Result<(), receiver::error::Error> {
    // `start > end` is allowed: it means the receive pass is already at the tip
    // and only the trailing spend sweep needs to run. `process_scan` decides
    // per phase and errors if neither phase has work.
    log::info!("start: {start} end: {end}");
    let start_time = Instant::now();
    let backend = BackendContext {
        agent,
        url: blindbit_url.to_string(),
        dust_limit,
        with_cutthrough,
        runtime,
    };
    let mut scan = ScanContext {
        sp_receiver,
        stores,
        stop,
        start,
        end,
        runtime,
        block_data_observer,
    };
    process_scan(&backend, &mut scan)?;
    log::info!(
        "Blindbit scan completed in {} seconds",
        start_time.elapsed().as_secs()
    );
    Ok(())
}

fn should_interrupt(stop: &Arc<AtomicBool>) -> bool {
    stop.load(Ordering::Relaxed)
}

fn save_state<P: SpStorageProfile>(stores: &ScanStores<P>) -> Result<(), receiver::error::Error> {
    stores.coin_store.lock().expect("poisoned").persist();
    stores.tx_store.lock().expect("poisoned").persist();
    stores.scan_state.lock().expect("poisoned").persist();
    Ok(())
}

fn record_outputs<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    outputs: HashMap<OutPoint, OwnedOutput>,
) -> Result<(), receiver::error::Error> {
    // One entry per funding tx, recording the block height it confirmed at.
    let mut by_tx: HashMap<Txid, u32> = HashMap::new();
    {
        let mut store = stores.coin_store.lock().expect("poisoned");
        for (outpoint, mut output) in outputs {
            by_tx
                .entry(outpoint.txid)
                .or_insert(output.blockheight.to_consensus_u32());
            if let Some(existing) = store.get(&outpoint) {
                if !matches!(existing.status(), OutputSpendStatus::Unspent) {
                    output.spend_status = existing.status().clone();
                }
            }
            store.insert(outpoint, output);
            let _ = stores
                .sender
                .send(Notification::Sp(SpNotification::NewOutput(outpoint)));
        }
        store.persist();
    }

    // Resolve block times before taking the tx_store lock (network fetch).
    let times: HashMap<Txid, Option<u64>> = by_tx
        .iter()
        .map(|(txid, h)| (*txid, block_time(stores, *h)))
        .collect();

    let mut tx_store = stores.tx_store.lock().expect("poisoned");
    for (txid, height) in by_tx {
        // Do not clobber an existing entry (e.g. our own outgoing spend whose
        // change lands back here); only confirm its height.
        if tx_store.get(&txid).is_some() {
            tx_store.update_height(&txid, Some(height));
        } else {
            let mut entry = SpTxEntry::new(txid);
            entry.height = Some(height);
            tx_store.insert(entry);
        }
        if let Some(ts) = times.get(&txid).copied().flatten() {
            tx_store.update_timestamp(&txid, ts);
        }
    }
    tx_store.persist();
    Ok(())
}

fn record_inputs<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    block_hash: BlockHash,
    height: Height,
    inputs: HashSet<OutPoint>,
) -> Result<(), receiver::error::Error> {
    // A coin already marked `Spent { txid, .. }` came from our own broadcast
    // inject; the txid lets us confirm that outgoing tx now that its spend is
    // mined. Read it before `confirm_spend` records the block hash.
    let mut confirmed_txids = Vec::new();
    {
        let mut store = stores.coin_store.lock().expect("poisoned");
        for outpoint in inputs {
            if let Some(entry) = store.get(&outpoint) {
                if let OutputSpendStatus::Spent { txid, .. } = entry.status() {
                    confirmed_txids.push(Txid::from_byte_array(*txid));
                }
            }
            store.confirm_spend(&outpoint, *block_hash.as_byte_array());
            let _ = stores
                .sender
                .send(Notification::Sp(SpNotification::OutputSpent(outpoint)));
        }
        store.persist();
    }

    if !confirmed_txids.is_empty() {
        let h = height.to_consensus_u32();
        // Resolve the block time before taking the tx_store lock (network fetch).
        let ts = block_time(stores, h);
        let mut tx_store = stores.tx_store.lock().expect("poisoned");
        for txid in confirmed_txids {
            tx_store.update_height(&txid, Some(h));
            if let Some(ts) = ts {
                tx_store.update_timestamp(&txid, ts);
            }
        }
        tx_store.persist();
    }
    Ok(())
}

fn record_receive_progress<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    current: Height,
    end: Height,
) -> Result<(), receiver::error::Error> {
    let _ = stores
        .sender
        .send(Notification::Sp(SpNotification::ScanReceiveProgress {
            current: current.to_consensus_u32(),
            end: end.to_consensus_u32(),
        }));
    Ok(())
}

fn record_spend_progress<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    current: Height,
    end: Height,
) -> Result<(), receiver::error::Error> {
    let _ = stores
        .sender
        .send(Notification::Sp(SpNotification::ScanSpendProgress {
            current: current.to_consensus_u32(),
            end: end.to_consensus_u32(),
        }));
    Ok(())
}

fn record_scan_frontier<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    height: Height,
    block_hash: BlockHash,
) -> Result<(), receiver::error::Error> {
    let mut state = stores.scan_state.lock().expect("poisoned");
    state.advance_frontier(height.to_consensus_u32(), *block_hash.as_byte_array());
    state.persist();
    Ok(())
}

fn record_spend_frontier<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    height: Height,
) -> Result<(), receiver::error::Error> {
    let mut state = stores.scan_state.lock().expect("poisoned");
    state.advance_spend_frontier(height.to_consensus_u32());
    state.persist();
    Ok(())
}

fn spend_frontier<P: SpStorageProfile>(
    stores: &ScanStores<P>,
) -> Result<Option<u32>, receiver::error::Error> {
    Ok(stores
        .scan_state
        .lock()
        .expect("poisoned")
        .last_spend_height())
}

/// Where the spend sweep starts for a scan beginning at `start_u32`.
///
/// A normal resume (`start_u32` past the spend frontier) resumes at frontier + 1
/// so already-swept heights are skipped. An explicit override at or below the
/// frontier (`start_u32 <= f`) re-sweeps from the override. With no frontier yet,
/// it starts at `start_u32`.
fn effective_spend_start<P: SpStorageProfile>(
    stores: &ScanStores<P>,
    start_u32: u32,
) -> Result<u32, receiver::error::Error> {
    Ok(spend_frontier(stores)?
        .map(|f| if start_u32 <= f { start_u32 } else { f + 1 })
        .unwrap_or(start_u32))
}

fn scan_utxos(
    agent: &ureq::Agent,
    url: &str,
    sp_receiver: &SpReceiver,
    blkheight: Height,
    secrets_map: HashMap<[u8; 34], bitcoin::secp256k1::PublicKey>,
) -> Result<Vec<(Option<Label>, UtxoData, bitcoin::secp256k1::Scalar)>, receiver::error::Error> {
    let utxos = blindbit::utxos(agent, url, blkheight)?;
    let mut txmap: HashMap<Txid, Vec<UtxoData>> = HashMap::new();
    for utxo in utxos {
        txmap.entry(utxo.txid).or_default().push(utxo);
    }

    let mut result = Vec::new();
    for utxos in txmap.into_values() {
        let mut secret = None;
        for utxo in utxos.iter() {
            let spk = utxo.scriptpubkey.as_bytes();
            if let Some(s) = secrets_map.get(spk) {
                secret = Some(s);
                break;
            }
        }
        let secret = match secret {
            Some(secret) => secret,
            None => continue,
        };

        let output_keys: Result<Vec<XOnlyPublicKey>, receiver::error::Error> = utxos
            .iter()
            .filter_map(|x| {
                if x.scriptpubkey.is_p2tr() {
                    Some(
                        XOnlyPublicKey::from_slice(&x.scriptpubkey.as_bytes()[2..])
                            .map_err(receiver::error::Error::from),
                    )
                } else {
                    None
                }
            })
            .collect();

        let ours = sp_receiver
            .receiver
            .scan_transaction(secret, output_keys?)?;

        for utxo in utxos {
            if !utxo.scriptpubkey.is_p2tr() || utxo.spent {
                continue;
            }
            let xonly = XOnlyPublicKey::from_slice(&utxo.scriptpubkey.as_bytes()[2..])?;
            for (label, map) in ours.iter() {
                if let Some(scalar) = map.get(&xonly) {
                    result.push((label.clone(), utxo, *scalar));
                    break;
                }
            }
        }
    }
    Ok(result)
}

fn check_block_outputs(
    created_utxo_filter: BlockFilter,
    blkhash: BlockHash,
    candidate_spks: Vec<&[u8; 34]>,
) -> Result<bool, receiver::error::Error> {
    let output_keys: Vec<_> = candidate_spks
        .into_iter()
        .map(|spk| spk[2..].as_ref())
        .collect();
    if !output_keys.is_empty() {
        Ok(created_utxo_filter.match_any(&blkhash, &mut output_keys.into_iter())?)
    } else {
        Ok(false)
    }
}

/// Backend-agnostic crypto: derive the candidate output spks for the block's tweaks
/// and test them against its new-utxo GCS filter. `true` if the block may pay us
/// (confirmed and expanded by [`derive_owned`] on the collector).
fn candidate_match(
    sp_receiver: &SpReceiver,
    blockdata: &BlockData,
) -> Result<bool, receiver::error::Error> {
    if blockdata.tweaks.is_empty() {
        return Ok(false);
    }
    let candidate_spks = candidate_spks(sp_receiver, &blockdata.tweaks)?;
    let candidate_spks: Vec<&[u8; 34]> = candidate_spks.iter().collect();

    #[cfg(feature = "scan-profile")]
    let __t = std::time::Instant::now();
    let blkfilter = BlockFilter::new(&blockdata.new_utxo_filter.data);
    let matched = check_block_outputs(
        blkfilter,
        blockdata.new_utxo_filter.block_hash,
        candidate_spks,
    )?;
    #[cfg(feature = "scan-profile")]
    profiling::add(&profiling::OUTPUT_FILTER_NS, __t.elapsed());

    Ok(matched)
}

/// Deferred, on-match-only: re-derive the shared secrets for the block's tweaks,
/// fetch its UTXOs from the backend, and build the owned-output map.
fn derive_owned(
    agent: &ureq::Agent,
    url: &str,
    sp_receiver: &SpReceiver,
    blkheight: Height,
    tweaks: &[[u8; 33]],
) -> Result<HashMap<OutPoint, OwnedOutput>, receiver::error::Error> {
    let tweaks: Vec<bitcoin::secp256k1::PublicKey> = tweaks
        .iter()
        .map(|t| bitcoin::secp256k1::PublicKey::from_slice(t))
        .collect::<Result<_, _>>()?;
    let secrets_map = script_to_secret_map(sp_receiver, tweaks)?;
    #[cfg(feature = "scan-profile")]
    let __t = std::time::Instant::now();
    let found = scan_utxos(agent, url, sp_receiver, blkheight, secrets_map)?;
    #[cfg(feature = "scan-profile")]
    profiling::add(&profiling::SCAN_UTXOS_NS, __t.elapsed());

    let mut res = HashMap::new();
    for (label, utxo, tweak) in found {
        let outpoint = OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        };
        let out = OwnedOutput {
            blockheight: blkheight,
            tweak: tweak.to_be_bytes(),
            amount: utxo.value,
            script: utxo.scriptpubkey,
            label,
            spend_status: OutputSpendStatus::Unspent,
        };
        res.insert(outpoint, out);
    }
    Ok(res)
}

fn input_hashes_for(
    blkhash: BlockHash,
    owned: &HashSet<OutPoint>,
) -> Result<HashMap<[u8; 8], OutPoint>, receiver::error::Error> {
    let mut map = HashMap::new();
    for outpoint in owned {
        let mut arr = [0u8; 68];
        arr[..32].copy_from_slice(outpoint.txid.to_raw_hash().as_byte_array());
        arr[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
        arr[36..].copy_from_slice(&blkhash.to_byte_array());
        let hash = sha256::Hash::hash(&arr);
        let mut res = [0u8; 8];
        res.copy_from_slice(&hash[..8]);
        map.insert(res, *outpoint);
    }
    Ok(map)
}

fn check_block_inputs(
    spent_filter: BlockFilter,
    blkhash: BlockHash,
    input_hashes: Vec<[u8; 8]>,
) -> Result<bool, receiver::error::Error> {
    if !input_hashes.is_empty() {
        Ok(spent_filter.match_any(&blkhash, &mut input_hashes.into_iter())?)
    } else {
        Ok(false)
    }
}

fn match_inputs_for(
    agent: &ureq::Agent,
    url: &str,
    blkheight: Height,
    spent_filter: FilterData,
    owned: &HashSet<OutPoint>,
) -> Result<HashSet<OutPoint>, receiver::error::Error> {
    let mut res = HashSet::new();
    let blkhash = spent_filter.block_hash;
    let input_hashes_map = input_hashes_for(blkhash, owned)?;

    let blkfilter = BlockFilter::new(&spent_filter.data);
    let matched_inputs = check_block_inputs(
        blkfilter,
        blkhash,
        input_hashes_map.keys().cloned().collect(),
    )?;
    if matched_inputs {
        let spent = blindbit::spent_index(agent, url, blkheight)?.data;
        for spent in spent {
            let hex: &[u8] = spent.as_ref();
            if let Some(outpoint) = input_hashes_map.get(hex) {
                res.insert(*outpoint);
            }
        }
    }
    Ok(res)
}

#[allow(clippy::too_many_arguments)]
fn commit_block<P: SpStorageProfile>(
    scan: &mut ScanContext<P>,
    start_u32: u32,
    end_u32: u32,
    blkheight: Height,
    blkhash: BlockHash,
    outs: HashMap<OutPoint, OwnedOutput>,
    done: &mut [bool],
    hashes: &mut [Option<BlockHash>],
    recv_tip: &mut Option<u32>,
    last_progress: &mut u32,
    notified_any: &mut bool,
    last_checkpoint: &mut std::time::Instant,
) -> Result<(), receiver::error::Error> {
    let idx = (blkheight.to_consensus_u32() - start_u32) as usize;
    done[idx] = true;
    hashes[idx] = Some(blkhash);
    if !outs.is_empty() {
        record_outputs(scan.stores, outs)?;
    }

    let mut next = recv_tip.map(|h| h + 1).unwrap_or(start_u32);
    while next <= end_u32 && done[(next - start_u32) as usize] {
        *recv_tip = Some(next);
        next += 1;
    }

    if let Some(tip) = *recv_tip {
        if !*notified_any || tip.saturating_sub(*last_progress) >= 100 {
            record_receive_progress(scan.stores, Height::from_consensus(tip)?, scan.end)?;
            *last_progress = tip;
            *notified_any = true;
        }
    }

    if last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL {
        if let Some(tip) = *recv_tip {
            let i = (tip - start_u32) as usize;
            let hash = hashes[i].ok_or(receiver::error::Error::MissingBlockHash(tip))?;
            record_scan_frontier(scan.stores, Height::from_consensus(tip)?, hash)?;
            save_state(scan.stores)?;
        }
        *last_checkpoint = std::time::Instant::now();
    }
    let _ = scan.start;
    Ok(())
}

const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Blocks between spend-sweep progress reports.
const SPEND_PROGRESS_INTERVAL: u32 = 1000;

/// The crypto stage's per-block verdict for the collector. A no-match (the common
/// case) carries only progress; a match additionally carries the tweaks the
/// collector needs to derive the owned outputs.
enum BlockOutcome {
    NoMatch {
        height: Height,
        hash: BlockHash,
    },
    Matched {
        height: Height,
        hash: BlockHash,
        tweaks: Vec<[u8; 33]>,
    },
}

/// Consume `BlockData` from `receiver` (produced by [`fetch_blocks`]), derive the
/// owned outputs of each block, and commit them in height order. Returns `true`
/// if the scan was interrupted via `stop` (state already persisted); on normal
/// completion it records the receive-scan frontier and returns `false`.
fn process_blocks<P: SpStorageProfile>(
    backend: &BackendContext,
    scan: &mut ScanContext<P>,
    receiver: channel::Receiver<Result<BlockData, receiver::error::Error>>,
) -> Result<bool, receiver::error::Error> {
    let start_u32 = scan.start.to_consensus_u32();
    let end_u32 = scan.end.to_consensus_u32();
    let len = (end_u32 - start_u32 + 1) as usize;

    let mut done = vec![false; len];
    let mut hashes: Vec<Option<BlockHash>> = vec![None; len];
    let mut recv_tip: Option<u32> = None;
    let mut last_progress = start_u32.saturating_sub(1);
    let mut notified_any = false;
    let mut last_checkpoint = Instant::now();

    let n = match_window_cap();
    let (tx, rx) = mpsc::sync_channel::<Result<BlockOutcome, receiver::error::Error>>(n * 2);

    // Backend-agnostic crypto workers: each clones the input receiver, pulls blocks,
    // runs the candidate/filter check, and ships a minimal outcome. The bounded
    // input channel applies backpressure; the only per-worker state is a cloned
    // `SpReceiver`.
    let pool = ThreadPool::new(n);
    for _ in 0..n {
        let input = receiver.clone();
        let sp_receiver = scan.sp_receiver.clone();
        let tx = tx.clone();
        pool.execute(move || {
            while let Ok(msg) = input.recv() {
                let bd = match msg {
                    Ok(bd) => bd,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                };
                let outcome = match candidate_match(&sp_receiver, &bd) {
                    Ok(true) => Ok(BlockOutcome::Matched {
                        height: bd.blkheight,
                        hash: bd.blkhash,
                        tweaks: bd.tweaks,
                    }),
                    Ok(false) => Ok(BlockOutcome::NoMatch {
                        height: bd.blkheight,
                        hash: bd.blkhash,
                    }),
                    Err(e) => Err(e),
                };
                let failed = outcome.is_err();
                if tx.send(outcome).is_err() || failed {
                    break;
                }
            }
        });
    }
    drop(tx);

    // Collector = this thread: derive owned outputs for the rare matches (with the
    // backend), commit every block in arrival order.
    for msg in rx {
        let (blkheight, blkhash, outs) = match msg? {
            BlockOutcome::NoMatch { height, hash } => (height, hash, HashMap::new()),
            BlockOutcome::Matched {
                height,
                hash,
                tweaks,
            } => {
                let outs = derive_owned(
                    &backend.agent,
                    &backend.url,
                    scan.sp_receiver,
                    height,
                    &tweaks,
                )?;
                (height, hash, outs)
            }
        };
        commit_block(
            scan,
            start_u32,
            end_u32,
            blkheight,
            blkhash,
            outs,
            &mut done,
            &mut hashes,
            &mut recv_tip,
            &mut last_progress,
            &mut notified_any,
            &mut last_checkpoint,
        )?;
        if should_interrupt(scan.stop) {
            if let Some(tip) = recv_tip {
                let i = (tip - start_u32) as usize;
                let hash = hashes[i].ok_or(receiver::error::Error::MissingBlockHash(tip))?;
                record_scan_frontier(scan.stores, Height::from_consensus(tip)?, hash)?;
            }
            save_state(scan.stores)?;
            return Ok(true);
        }
    }

    if recv_tip != Some(end_u32) {
        if should_interrupt(scan.stop) {
            if let Some(tip) = recv_tip {
                let i = (tip - start_u32) as usize;
                let hash = hashes[i].ok_or(receiver::error::Error::MissingBlockHash(tip))?;
                record_scan_frontier(scan.stores, Height::from_consensus(tip)?, hash)?;
            }
            save_state(scan.stores)?;
            return Ok(true);
        }
        return Err(receiver::error::Error::MissingBlockHash(end_u32));
    }
    let end_hash = hashes[len - 1].ok_or(receiver::error::Error::MissingBlockHash(end_u32))?;
    record_scan_frontier(scan.stores, scan.end, end_hash)?;
    record_receive_progress(scan.stores, scan.end, scan.end)?;
    save_state(scan.stores)?;
    Ok(false)
}

/// Sweep `[spend_frontier+1, end]` for inputs spending any still-owned output:
/// remove those outputs, record the spends, and advance the spend frontier
/// (checkpointing periodically), persisting it at `end` on completion. Returns
/// early with state persisted if interrupted via `stop`.
///
/// Spent filters are fetched concurrently through the same pool the receive scan
/// uses (`fetch_spent_filters`), so the sweep is fetch-pipelined rather than one
/// blocking request per block; the input match is ~free, so the collector just
/// tests each filter as it arrives, advancing the frontier over the contiguous
/// prefix that has been swept.
/// The still-watchable SP coins during a spend sweep: the outpoints tested
/// against each spent filter, plus their creation heights so the sweep can raise
/// its floor (the lowest watchable coin height) and skip blocks below it.
struct WatchableSet {
    outpoints: HashSet<OutPoint>,
    height_of: HashMap<OutPoint, u32>,
    by_height: BTreeMap<u32, usize>,
}

impl WatchableSet {
    fn new(coins: impl IntoIterator<Item = (OutPoint, u32)>) -> Self {
        let mut set = Self {
            outpoints: HashSet::new(),
            height_of: HashMap::new(),
            by_height: BTreeMap::new(),
        };
        for (outpoint, height) in coins {
            if set.outpoints.insert(outpoint) {
                set.height_of.insert(outpoint, height);
                *set.by_height.entry(height).or_insert(0) += 1;
            }
        }
        set
    }

    /// The lowest watchable coin height, or `None` when empty. A watchable coin at
    /// height H can only be spent above H, so blocks at or below `floor` need not
    /// be examined.
    fn floor(&self) -> Option<u32> {
        self.by_height.keys().next().copied()
    }

    fn outpoints(&self) -> &HashSet<OutPoint> {
        &self.outpoints
    }

    /// Drop a coin detected as spent, which may raise the floor.
    fn remove(&mut self, outpoint: &OutPoint) {
        if !self.outpoints.remove(outpoint) {
            return;
        }
        if let Some(height) = self.height_of.remove(outpoint) {
            if let Some(count) = self.by_height.get_mut(&height) {
                *count -= 1;
                if *count == 0 {
                    self.by_height.remove(&height);
                }
            }
        }
    }
}

/// Drive a spend sweep to `end` using `scanner` as the in-order source of spend
/// detections, jumping over height ranges that have no watchable coin. The
/// frontier is `cursor - 1` (processed in order); a jumped gap is recorded swept
/// so a resume never re-fetches it.
fn run_sweep<P: SpStorageProfile, S: SpendScanner>(
    stores: &ScanStores<P>,
    stop: &Arc<AtomicBool>,
    scanner: &mut S,
    mut watch: WatchableSet,
    mut cursor: u32,
    end: Height,
) -> Result<(), receiver::error::Error> {
    let end_u32 = end.to_consensus_u32();
    let mut last_progress = cursor.saturating_sub(1);
    let mut last_checkpoint = Instant::now();

    while cursor <= end_u32 {
        if should_interrupt(stop) {
            record_spend_frontier(stores, Height::from_consensus(cursor - 1)?)?;
            save_state(stores)?;
            return Ok(());
        }

        let SpendsAt {
            height,
            block_hash: blkhash,
            spent,
        } = scanner.next(watch.outpoints())?;
        if !spent.is_empty() {
            for outpoint in &spent {
                watch.remove(outpoint);
            }
            record_inputs(stores, blkhash, Height::from_consensus(height)?, spent)?;
        }
        cursor = height + 1;

        if (cursor - 1).saturating_sub(last_progress) >= SPEND_PROGRESS_INTERVAL {
            record_spend_progress(stores, Height::from_consensus(cursor - 1)?, end)?;
            last_progress = cursor - 1;
        }
        if last_checkpoint.elapsed() >= CHECKPOINT_INTERVAL {
            record_spend_frontier(stores, Height::from_consensus(cursor - 1)?)?;
            save_state(stores)?;
            last_checkpoint = Instant::now();
        }

        // Each iteration, check the lowest still-watchable coin. If it sits
        // strictly above the cursor, the gap up to it has nothing to watch, so
        // record that gap swept and jump the scanner to the floor block itself.
        // The floor block is scanned, not skipped: a coin can be spent in the
        // same block it was created in.
        match watch.floor() {
            None => {
                record_spend_frontier(stores, end)?;
                save_state(stores)?;
                return Ok(());
            }
            Some(floor) if floor > cursor => {
                record_spend_frontier(stores, Height::from_consensus(floor - 1)?)?;
                save_state(stores)?;
                cursor = floor;
                scanner.jump_to(cursor);
            }
            _ => {}
        }
    }

    record_spend_frontier(stores, end)?;
    save_state(stores)?;
    Ok(())
}

fn process_spends<P: SpStorageProfile>(
    backend: &BackendContext,
    scan: &ScanContext<P>,
) -> Result<(), receiver::error::Error> {
    let end_u32 = scan.end.to_consensus_u32();
    let watch = WatchableSet::new(scan.stores.coin_store.lock().expect("poisoned").watchable());

    // Nothing watchable -> no coin can be spent in this range; jump the frontier
    // straight to the tip.
    let Some(floor) = watch.floor() else {
        record_spend_frontier(scan.stores, scan.end)?;
        save_state(scan.stores)?;
        return Ok(());
    };

    let resume = effective_spend_start(scan.stores, scan.start.to_consensus_u32())?;
    // Start at the floor block itself, not one past it: a coin can be spent in
    // the same block it was created in.
    let cursor = resume.max(floor);
    if cursor > end_u32 {
        record_spend_frontier(scan.stores, scan.end)?;
        save_state(scan.stores)?;
        return Ok(());
    }

    let mut scanner = BlindbitSpendScanner::new(backend, cursor, end_u32);
    run_sweep(
        scan.stores,
        scan.stop,
        &mut scanner,
        watch,
        cursor,
        scan.end,
    )
}

fn process_scan<P: SpStorageProfile>(
    backend: &BackendContext,
    scan: &mut ScanContext<P>,
) -> Result<(), receiver::error::Error> {
    let start_u32 = scan.start.to_consensus_u32();
    let end_u32 = scan.end.to_consensus_u32();

    // Heal any confirmation timestamps a prior scan could not resolve yet.
    restamp_missing_timestamps(scan.stores);

    if spend_frontier(scan.stores)?.is_none() {
        if let Some(floor) = start_u32.checked_sub(1) {
            record_spend_frontier(scan.stores, Height::from_consensus(floor)?)?;
            save_state(scan.stores)?;
        }
    }

    // The two passes resume from their own frontiers, so a stop during the spend
    // sweep can be resumed at the same tip (receive done, spend still trailing).
    let receive_has_work = start_u32 <= end_u32;
    let spend_has_work = effective_spend_start(scan.stores, start_u32)? <= end_u32;
    if !receive_has_work && !spend_has_work {
        return Err(receiver::error::Error::InvalidRange(start_u32, end_u32));
    }

    if receive_has_work {
        #[cfg(feature = "scan-profile")]
        let recv_t = Instant::now();
        let (sender, receiver) = channel::bounded(fetch_channel_cap());
        let fetchers = fetch_blocks(sender, backend, scan);
        let result = process_blocks(backend, scan, receiver);
        fetchers.stop();
        let interrupted = result?;
        #[cfg(feature = "scan-profile")]
        profiling::add(&profiling::RECEIVE_WALL_NS, recv_t.elapsed());
        if interrupted {
            // Interrupted mid-scan; process_blocks already persisted state.
            return Ok(());
        }
    }

    #[cfg(feature = "scan-profile")]
    let spend_t = Instant::now();
    process_spends(backend, scan)?;
    #[cfg(feature = "scan-profile")]
    profiling::add(&profiling::SPEND_WALL_NS, spend_t.elapsed());
    Ok(())
}

// Account scan-orchestration methods.
//
// These stay methods on [`Account`] (public API unchanged); only their
// source location lives here, next to the free scanning functions they
// drive. Gated on `mnemonic` alongside the `account` module that defines
// [`Account`].
#[cfg(feature = "mnemonic")]
use {
    crate::account::{AccountError, ScanMode},
    std::{thread, time::Duration},
};

#[cfg(feature = "mnemonic")]
impl<P: SpStorageProfile> crate::account::Account<P> {
    /// Start a scan with the specified mode.
    ///
    /// # Arguments
    /// * `mode` - The scanning mode (OneShot or Continuous)
    /// * `start` - overrides where the scan begins; `None` resumes from the last
    ///   scanned position; for Continuous it only applies to the first pass.
    ///
    /// # Modes
    /// - `OneShot`: Spawns a background thread that scans from the last position
    ///   to the current chain tip, then ends. Returns immediately after spawning.
    /// - `Continuous`: Spawns a background thread that scans to tip, then watches for new blocks.
    ///   Returns immediately after spawning. Use `stop_scan()` to stop.
    ///
    /// # Errors
    /// - `AccountError::ScannerAlreadyRunning` if a scan is already running
    pub fn start_scan(&mut self, mode: ScanMode, start: Option<u32>) -> Result<(), AccountError> {
        match mode {
            ScanMode::OneShot => self.scan_oneshot(start),
            ScanMode::Continuous => self.start_continuous_scan(start),
        }
    }

    /// Execute a one-shot scan to the current chain tip on a background thread.
    ///
    /// `start` overrides where the scan begins. `None` uses
    /// `ScanState::next_scan_start()` (resume from last scanned, or birthday).
    ///
    /// Returns immediately after spawning the scanner thread; progress is
    /// reported through the notification channel (`ScanStarted`,
    /// `ScanReceiveProgress`, `ScanSpendProgress`, `ScanCompleted`,
    /// `FailStartScanning`, `FailScan`). Use `is_scanning()` to poll for
    /// completion and `stop_scan()` to cancel.
    pub fn scan_oneshot(&mut self, start: Option<u32>) -> Result<(), AccountError> {
        if self
            .scanner_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
        {
            return Err(AccountError::ScannerAlreadyRunning);
        }

        // Clear any stale cancel signal from a previous run before we hand
        // the flag down to the scanner. Without this, a caller that flipped
        // the flag via `cancel_flag()` for a prior scan would cause the next
        // OneShot to bail at the first block (spdk-core's `process_blocks`
        // returns Ok early when `should_interrupt()` is true).
        self.scanner_stop.store(false, Ordering::Relaxed);

        let sp_receiver = self.sp_receiver.clone();
        let agent = self.agent.clone();
        let blindbit_url = self.config.blindbit_url.clone();
        let dust_limit = self.config.dust_limit.map(Amount::from_sat);
        let coin_store = self.coin_store.clone();
        let tx_store = self.tx_store.clone();
        let scan_state = self.scan_state.clone();
        let sender = self.sender.clone();
        let stop = self.scanner_stop.clone();
        let min_birthday = self.config.min_birthday_height();
        let header_store = self.header_store.clone();
        let runtime = self.scan_runtime;

        let handle = thread::spawn(move || {
            let with_cutthrough = blindbit::info(&agent, &blindbit_url)
                .map(|info| info.tweaks_cut_through_with_dust_filter)
                .unwrap_or(false);

            let chain_height = match blindbit::block_height(&agent, &blindbit_url) {
                Ok(h) => h.to_consensus_u32(),
                Err(e) => {
                    let _ = sender.send(Notification::Sp(SpNotification::FailStartScanning {
                        message: e.to_string(),
                    }));
                    return;
                }
            };

            let (resume_start, spend_resume) = {
                let st = scan_state.lock().expect("poisoned");
                (st.next_scan_start(), st.next_spend_start())
            };
            let start_height = start.unwrap_or(resume_start).max(min_birthday);

            // Caught up only when BOTH passes have reached the tip; an explicit
            // override always forces a run.
            if start.is_none() && start_height > chain_height && spend_resume > chain_height {
                let _ = sender.send(Notification::Sp(SpNotification::ScanCompleted));
                return;
            }

            let (start, end) = match (
                Height::from_consensus(start_height),
                Height::from_consensus(chain_height),
            ) {
                (Ok(start), Ok(end)) => (start, end),
                _ => {
                    let _ = sender.send(Notification::Sp(SpNotification::FailScan {
                        message: format!("invalid height range {start_height}..{chain_height}"),
                    }));
                    return;
                }
            };

            let stores = ScanStores {
                coin_store,
                tx_store,
                scan_state,
                sender: sender.clone(),
                header_store,
            };

            // Clamp so a spend-only pass (start_height == tip + 1) does not report
            // a backwards range.
            let _ = sender.send(Notification::Sp(SpNotification::ScanStarted {
                start: start_height.min(chain_height),
                end: chain_height,
            }));

            match scan_blocks(
                agent.clone(),
                &blindbit_url,
                &sp_receiver,
                &stores,
                &stop,
                start,
                end,
                dust_limit,
                with_cutthrough,
                runtime,
            ) {
                Ok(()) => {
                    let _ = sender.send(Notification::Sp(SpNotification::ScanCompleted));
                }
                Err(e) => {
                    let _ = sender.send(Notification::Sp(SpNotification::FailScan {
                        message: e.to_string(),
                    }));
                }
            }
        });

        self.scanner_handle = Some(handle);
        Ok(())
    }

    /// Start continuous scan in background thread.
    ///
    /// `start` overrides where the first pass begins; later passes resume from
    /// the last scanned position.
    fn start_continuous_scan(&mut self, start: Option<u32>) -> Result<(), AccountError> {
        if self.scanner_handle.is_some() {
            return Err(AccountError::ScannerAlreadyRunning);
        }

        self.scanner_stop.store(false, Ordering::Relaxed);
        let _ = self
            .sender
            .send(Notification::Sp(SpNotification::StartingScan));

        let sp_receiver = self.sp_receiver.clone();
        let agent = self.agent.clone();
        let blindbit_url = self.config.blindbit_url.clone();
        let dust_limit = self.config.dust_limit.map(Amount::from_sat);
        let coin_store = self.coin_store.clone();
        let tx_store = self.tx_store.clone();
        let scan_state = self.scan_state.clone();
        let sender = self.sender.clone();
        let stop = self.scanner_stop.clone();
        let mut first_start = start.map(|h| h.max(self.config.min_birthday_height()));
        let header_store = self.header_store.clone();
        let runtime = self.scan_runtime;

        let handle = thread::spawn(move || {
            let mut last_notified_tip: Option<u32> = None;
            let mut waiting = false;

            let with_cutthrough = blindbit::info(&agent, &blindbit_url)
                .map(|info| info.tweaks_cut_through_with_dust_filter)
                .unwrap_or(false);

            let stores = ScanStores {
                coin_store: coin_store.clone(),
                tx_store: tx_store.clone(),
                scan_state: scan_state.clone(),
                sender: sender.clone(),
                header_store,
            };

            while !stop.load(Ordering::Relaxed) {
                let chain_height = match blindbit::block_height(&agent, &blindbit_url) {
                    Ok(h) => h.to_consensus_u32(),
                    Err(e) => {
                        log::warn!("scanner: failed to get block height: {e}");
                        let _ = sender.send(Notification::Sp(SpNotification::FailStartScanning {
                            message: e.to_string(),
                        }));
                        break;
                    }
                };

                let override_start = first_start.take();
                let (resume_start, spend_resume) = {
                    let st = scan_state.lock().expect("poisoned");
                    (st.next_scan_start(), st.next_spend_start())
                };
                let start_height = override_start.unwrap_or(resume_start);

                // Caught up only when BOTH passes have reached the tip; an
                // override forces a run.
                if override_start.is_none()
                    && start_height > chain_height
                    && spend_resume > chain_height
                {
                    if !waiting {
                        let _ = sender.send(Notification::Sp(SpNotification::WaitingForBlocks {
                            tip_height: chain_height,
                        }));
                        waiting = true;
                    }
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }

                waiting = false;

                // New blocks detected - notify if we were previously waiting
                if let Some(prev_tip) = last_notified_tip {
                    if chain_height > prev_tip {
                        let _ = sender.send(Notification::Sp(SpNotification::NewBlocksDetected {
                            from_height: prev_tip,
                            to_height: chain_height,
                        }));
                    }
                }

                let start = match Height::from_consensus(start_height) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let end = match Height::from_consensus(chain_height) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                let _ = sender.send(Notification::Sp(SpNotification::ScanStarted {
                    start: start_height.min(chain_height),
                    end: end.to_consensus_u32(),
                }));

                match scan_blocks(
                    agent.clone(),
                    &blindbit_url,
                    &sp_receiver,
                    &stores,
                    &stop,
                    start,
                    end,
                    dust_limit,
                    with_cutthrough,
                    runtime,
                ) {
                    Ok(()) => {
                        let _ = sender.send(Notification::Sp(SpNotification::ScanCompleted));
                        last_notified_tip = Some(chain_height);
                    }
                    Err(e) => {
                        let _ = sender.send(Notification::Sp(SpNotification::FailScan {
                            message: e.to_string(),
                        }));
                        break;
                    }
                }

                // Brief pause before checking for new blocks
                thread::sleep(Duration::from_millis(500));
            }

            let _ = sender.send(Notification::Sp(SpNotification::ScanStopped));
        });

        self.scanner_handle = Some(handle);
        Ok(())
    }

    /// Stop the continuous scan.
    ///
    /// No-op if not running in continuous mode.
    pub fn stop_scan(&mut self) {
        let _ = self
            .sender
            .send(Notification::Sp(SpNotification::StoppingScan));
        self.scanner_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.scanner_handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if a continuous scan is currently running.
    pub fn is_scanning(&self) -> bool {
        self.scanner_handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    pub fn clear_scan_state(&mut self) -> Result<(), AccountError> {
        if self.is_scanning() {
            return Err(AccountError::ScannerAlreadyRunning);
        }
        let mut state = self.scan_state.lock().expect("poisoned");
        state.clear_progress();
        state.try_persist()?;
        Ok(())
    }

    /// Returns a clone of the scanner cancellation flag.
    ///
    /// Setting this `AtomicBool` to `true` causes any in-flight OneShot or
    /// Continuous scan to bail at the next per-block checkpoint inside
    /// spdk-core's `process_blocks` (which calls `should_interrupt()` before
    /// every block). The scan call returns `Ok(())` after persisting state
    /// , i.e. cancellation is graceful, not an error.
    ///
    /// `scan_oneshot` resets this flag to `false` at the start of each run,
    /// so leaving the flag in `true` between runs is harmless.
    ///
    /// Intended for consumers that hold an `Account` behind a `Mutex` and
    /// need to interrupt a scan without first re-acquiring the mutex (which
    /// the in-flight scan call still holds via `&mut self`).
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.scanner_stop.clone()
    }

    /// Scan a range of blocks for silent payment outputs.
    pub fn scan_blocks(
        &mut self,
        start: Option<u32>,
        end: Option<u32>,
    ) -> Result<(), AccountError> {
        // If both are None, use the new one-shot scan
        if start.is_none() && end.is_none() {
            return self.start_scan(ScanMode::OneShot, None);
        }

        // Custom range scan (legacy behavior)
        let (resume_start, spend_resume) = {
            let st = self.scan_state.lock().expect("poisoned");
            (st.next_scan_start(), st.next_spend_start())
        };
        let start_height = start.unwrap_or(resume_start);
        let end_height = match end {
            Some(h) => h,
            None => self.block_height()?,
        };

        // Nothing to do only when both passes have reached the end; otherwise fall
        // through so a trailing spend sweep still runs.
        if start_height > end_height && spend_resume > end_height {
            return Ok(());
        }

        let start =
            Height::from_consensus(start_height).map_err(|e| AccountError::Scan(e.into()))?;
        let end = Height::from_consensus(end_height).map_err(|e| AccountError::Scan(e.into()))?;

        let dust_limit = self.config.dust_limit.map(Amount::from_sat);

        let with_cutthrough = blindbit::info(&self.agent, &self.config.blindbit_url)
            .map(|info| info.tweaks_cut_through_with_dust_filter)
            .unwrap_or(false);

        let stores = ScanStores {
            coin_store: self.coin_store.clone(),
            tx_store: self.tx_store.clone(),
            scan_state: self.scan_state.clone(),
            sender: self.sender.clone(),
            header_store: self.header_store.clone(),
        };

        scan_blocks(
            self.agent.clone(),
            &self.config.blindbit_url,
            &self.sp_receiver,
            &stores,
            &self.scanner_stop,
            start,
            end,
            dust_limit,
            with_cutthrough,
            self.scan_runtime,
        )
        .map_err(AccountError::Scan)?;

        let _ = self
            .sender
            .send(Notification::Sp(SpNotification::ScanCompleted));
        Ok(())
    }

    /// Start a background scanner thread.
    pub fn start_scanner(&mut self) -> Result<(), AccountError> {
        self.start_scan(ScanMode::Continuous, None)
    }

    /// Stop the background scanner thread.
    pub fn stop_scanner(&mut self) {
        self.stop_scan()
    }

    /// Check if the scanner is currently running.
    pub fn scanner_running(&self) -> bool {
        self.is_scanning()
    }

    /// Returns the last scanned block height.
    pub fn last_scanned_height(&self) -> Option<u32> {
        self.scan_state
            .lock()
            .expect("poisoned")
            .last_scanned_height()
    }

    pub fn min_birthday_height(&self) -> u32 {
        self.config.min_birthday_height()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A malformed (non-curve-point) tweak must surface as an `Err`, never a
    // panic on the worker thread. The byte-FFI kernel rejects the point and the
    // binding returns `MalformedPubkey`, mapped to `Error::MalformedTweak`. This
    // pins the panic->Result conversion: integration scans only ever feed valid
    // tweaks, so this graceful-failure path has no other coverage.
    #[test]
    fn candidate_spks_rejects_malformed_tweak() {
        let sp_receiver = SpReceiver::default();
        // Invalid compressed-point prefix (must be 0x02/0x03), so the C
        // `ec_pubkey_parse` rejects it outright.
        let bad = [0x01u8; 33];
        let err = candidate_spks(&sp_receiver, &[bad]);
        assert!(
            matches!(
                err,
                Err(receiver::error::Error::SilentPayments(
                    crate::core::error::Error::MalformedTweak
                ))
            ),
            "expected MalformedTweak Err, got {err:?}"
        );
    }

    #[test]
    fn scan_runtime_config_defaults_are_current_mobile_baseline() {
        let config = ScanRuntimeConfig::default();

        assert_eq!(config.fetch_concurrency_factor(), 12);
        assert!(config.fetch_concurrency() >= 16);
    }

    #[test]
    fn scan_runtime_config_rejects_invalid_fetch_concurrency_factor() {
        assert!(matches!(
            ScanRuntimeConfig::from_fetch_concurrency_factor(0),
            Err(ScanRuntimeConfigError::InvalidFetchConcurrencyFactor)
        ));
        assert!(matches!(
            ScanRuntimeConfig::from_fetch_concurrency_factor(MAX_FETCH_CONCURRENCY_FACTOR + 1),
            Err(ScanRuntimeConfigError::InvalidFetchConcurrencyFactor)
        ));
    }

    use bitcoin::ScriptBuf;

    fn op(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    fn owned_unspent(height: u32) -> OwnedOutput {
        OwnedOutput {
            blockheight: Height::from_consensus(height).unwrap(),
            tweak: [0u8; 32],
            amount: Amount::from_sat(1000),
            script: ScriptBuf::new(),
            label: None,
            spend_status: OutputSpendStatus::Unspent,
        }
    }

    fn test_stores(
        coins: &[(OutPoint, u32)],
    ) -> (
        ScanStores<crate::profile::SpRamProfile<bwk::bwk_electrum::profile::DefaultBackend>>,
        mpsc::Receiver<Notification>,
    ) {
        use crate::account::tx_store::SpTxStore;
        let mut cs = SpCoinStore::new();
        for &(o, h) in coins {
            cs.insert(o, owned_unspent(h));
        }
        let (tx, rx) = mpsc::channel();
        let stores = ScanStores {
            coin_store: Arc::new(Mutex::new(cs)),
            tx_store: Arc::new(Mutex::new(SpTxStore::new())),
            scan_state: Arc::new(Mutex::new(ScanState::new(0))),
            sender: tx,
            header_store: bwk::bwk_electrum::header_store::HeaderStore::new_in_memory(
                bitcoin::Network::Regtest,
            ),
        };
        (stores, rx)
    }

    /// In-order fake recording which heights were asked for, reporting a spend set
    /// per height. `jump_to` resyncs the cursor with `run_sweep`.
    struct FakeScanner {
        spends: HashMap<u32, Vec<OutPoint>>,
        requested: Vec<u32>,
        cursor: u32,
    }

    impl SpendScanner for FakeScanner {
        fn next(&mut self, _watch: &HashSet<OutPoint>) -> Result<SpendsAt, receiver::error::Error> {
            let h = self.cursor;
            self.requested.push(h);
            let spent: HashSet<OutPoint> = self
                .spends
                .get(&h)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            self.cursor += 1;
            Ok(SpendsAt {
                height: h,
                block_hash: BlockHash::all_zeros(),
                spent,
            })
        }

        fn jump_to(&mut self, to: u32) {
            self.cursor = to;
        }
    }

    #[test]
    fn record_outputs_preserves_spent_status_on_rediscovery() {
        let outpoint = op(1);
        let (stores, _rx) = test_stores(&[(outpoint, 100)]);
        stores
            .coin_store
            .lock()
            .unwrap()
            .mark_spent(&outpoint, [2; 32]);

        record_outputs(&stores, HashMap::from([(outpoint, owned_unspent(100))])).unwrap();

        assert!(
            !stores
                .coin_store
                .lock()
                .unwrap()
                .get(&outpoint)
                .unwrap()
                .is_spendable(),
            "rediscovery must not resurrect a spent output"
        );
    }

    #[test]
    fn watchable_set_floor_and_remove() {
        let mut w = WatchableSet::new([(op(1), 100), (op(2), 100), (op(3), 5000)]);
        assert_eq!(w.floor(), Some(100));
        w.remove(&op(1));
        assert_eq!(w.floor(), Some(100)); // op(2) still at 100
        w.remove(&op(2));
        assert_eq!(w.floor(), Some(5000)); // floor raised
        w.remove(&op(3));
        assert_eq!(w.floor(), None);
    }

    #[test]
    fn run_sweep_jumps_gap_after_spend() {
        let coins = [(op(1), 100), (op(2), 5000)];
        let (stores, _rx) = test_stores(&coins);
        let watch = WatchableSet::new(coins.iter().copied());
        let mut scanner = FakeScanner {
            spends: HashMap::from([(200u32, vec![op(1)])]),
            requested: Vec::new(),
            cursor: 101,
        };
        let stop = Arc::new(AtomicBool::new(false));
        run_sweep(
            &stores,
            &stop,
            &mut scanner,
            watch,
            101,
            Height::from_consensus(10000).unwrap(),
        )
        .unwrap();

        // The gap 201..=4999 (no watchable coin active) is never fetched, but
        // block 5000, op(2)'s creation block, is swept: a same-block spend there
        // must not be skipped.
        assert!(!scanner.requested.iter().any(|&h| (201..=4999).contains(&h)));
        assert!(scanner.requested.contains(&101));
        assert!(scanner.requested.contains(&200));
        assert!(scanner.requested.contains(&5000));
        assert!(scanner.requested.contains(&10000));
        assert_eq!(
            stores.scan_state.lock().unwrap().last_spend_height(),
            Some(10000)
        );
    }

    #[test]
    fn run_sweep_catches_same_block_spend() {
        // op(2) is created at 5000 and spent in that same block. After op(1) is
        // spent at 200 the sweep jumps to 5000 (not 5001), so the same-block
        // spend is found rather than skipped forever.
        let coins = [(op(1), 100), (op(2), 5000)];
        let (stores, _rx) = test_stores(&coins);
        let watch = WatchableSet::new(coins.iter().copied());
        let mut scanner = FakeScanner {
            spends: HashMap::from([(200u32, vec![op(1)]), (5000u32, vec![op(2)])]),
            requested: Vec::new(),
            cursor: 101,
        };
        let stop = Arc::new(AtomicBool::new(false));
        run_sweep(
            &stores,
            &stop,
            &mut scanner,
            watch,
            101,
            Height::from_consensus(10000).unwrap(),
        )
        .unwrap();

        // Block 5000 is scanned and op(2)'s spend is caught; once it is removed
        // nothing above 5000 is watchable, so no height above it is fetched.
        assert!(scanner.requested.contains(&5000));
        assert!(!scanner.requested.iter().any(|&h| h > 5000));
        assert!(
            !stores
                .coin_store
                .lock()
                .unwrap()
                .get(&op(2))
                .unwrap()
                .is_spendable(),
            "op(2) must be marked spent after the same-block sweep"
        );
    }

    #[test]
    fn run_sweep_continuous_when_low_coin_unspent() {
        let coins = [(op(1), 100), (op(2), 5000)];
        let (stores, _rx) = test_stores(&coins);
        let watch = WatchableSet::new(coins.iter().copied());
        let mut scanner = FakeScanner {
            spends: HashMap::new(),
            requested: Vec::new(),
            cursor: 101,
        };
        let stop = Arc::new(AtomicBool::new(false));
        run_sweep(
            &stores,
            &stop,
            &mut scanner,
            watch,
            101,
            Height::from_consensus(10000).unwrap(),
        )
        .unwrap();

        // The low coin stays unspent, so every height is swept (no wrong jump).
        assert_eq!(scanner.requested.len(), 10000 - 101 + 1);
        assert!(scanner.requested.contains(&5000));
        assert_eq!(
            stores.scan_state.lock().unwrap().last_spend_height(),
            Some(10000)
        );
    }

    #[test]
    fn run_sweep_jumps_to_end_when_watch_empties() {
        let coins = [(op(1), 100)];
        let (stores, _rx) = test_stores(&coins);
        let watch = WatchableSet::new(coins.iter().copied());
        let mut scanner = FakeScanner {
            spends: HashMap::from([(150u32, vec![op(1)])]),
            requested: Vec::new(),
            cursor: 101,
        };
        let stop = Arc::new(AtomicBool::new(false));
        run_sweep(
            &stores,
            &stop,
            &mut scanner,
            watch,
            101,
            Height::from_consensus(10000).unwrap(),
        )
        .unwrap();

        // After the only coin is spent at 150, nothing is watchable -> no fetch above.
        assert!(!scanner.requested.iter().any(|&h| h > 150));
        assert_eq!(
            stores.scan_state.lock().unwrap().last_spend_height(),
            Some(10000)
        );
    }
}
