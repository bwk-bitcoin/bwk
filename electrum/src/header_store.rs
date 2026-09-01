//! Validated header chain shared across `bwk` Accounts.
//!
//! This module owns a contiguous range of validated 80-byte block headers
//! keyed by height and exposes a small read API plus a background worker
//! that drives initial sync and reorg resolution against the electrum
//! server.
//!
//! `HeaderStore` follows the same domain-store pattern as `TxStore` and
//! `LabelStore`: it wraps a typed [`Store`](bwk_persist::Store), keeps
//! encoding in explicit helpers, and leaves persistence layout details to a
//! backend. The default file-backed backend is
//! [`HeaderBackend`](bwk_persist::HeaderBackend), which stores the chain as
//! `magic || min_stored || raw headers`. Sparse caches that start at a
//! 2016-block boundary above genesis are therefore represented without
//! fabricating lower-height rows. The chain is always binary-backed through
//! `HeaderBackend`, even when the account's other stores use the JSON or
//! SQLite backend.
//!
//! The store is promote-only with respect to wallet tx state: it never
//! demotes a tx. Tx demotion (e.g. on a reorg) is owned by the
//! scripthash-subscription + history path, which resets a reported-height
//! change back to `Inclusion::Unconfirmed` and re-claims it at the new
//! height.

use crate::{
    client::{
        Client, CoinError, CoinRequest, CoinResponse, Error as ClientError, HeaderError,
        HeaderRequest, HeaderResponse, MERKLE_HASH_BYTES,
    },
    fanout::{Fanout, ListenerId},
    header_validator::{self, expected_genesis, Error as ValidatorError},
    notification::Notification,
    raw_client::CertificateCheck,
    worker::Worker,
};
use bwk_persist::{
    HeaderBackend, NoopBackend, PersistError, PersistenceBackend, RamStore, Store,
    HEADERS_STORE_KEY,
};
use miniscript::bitcoin::{
    block::Header,
    consensus::deserialize,
    hashes::{sha256d, Hash, HashEngine},
    params::Params,
    BlockHash, Network, TxMerkleNode, Txid, Work,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, Weak,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Blocks between difficulty retargets on `network`, per the validator's own
/// derivation (the single source of truth for this value).
fn retarget_interval(network: Network) -> usize {
    header_validator::retarget_interval(&Params::new(network))
}

/// Current unix time in seconds, 0 if the clock is before the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub const STORE_KEY: &str = HEADERS_STORE_KEY;

pub fn encode_height(k: &u32) -> String {
    k.to_string()
}

pub fn decode_height(s: &str) -> Result<u32, PersistError> {
    s.parse::<u32>()
        .map_err(|e| PersistError::Io(format!("bad header height {s:?}: {e}")))
}

pub fn encode_header(v: &[u8; Header::SIZE]) -> Result<Vec<u8>, PersistError> {
    Ok(v.to_vec())
}

pub fn decode_header(bytes: &[u8]) -> Result<[u8; Header::SIZE], PersistError> {
    bytes
        .try_into()
        .map_err(|_| PersistError::Io(format!("bad header length {}", bytes.len())))
}

/// Process-wide validated header chain.
///
/// `S` is a deliberate extension point: production always uses the default
/// `HeaderBackend`-backed `RamStore`, but the generic lets a consumer or a
/// future store plug in its own `Store` implementation.
#[derive(Debug)]
pub struct HeaderStore<S = RamStore<Arc<dyn PersistenceBackend>, u32, [u8; Header::SIZE]>>
where
    S: Store<Key = u32, Value = [u8; Header::SIZE]>,
{
    network: Network,
    inner: Mutex<Inner<S>>,
    listeners: Fanout<()>,
    progress_listeners: Mutex<ProgressListeners>,
    /// Authoritative writer token. Only the worker holding the current token
    /// may mutate the store, enforced by checking it under the inner lock in
    /// [`with_writer`](HeaderStore::with_writer). `restart` bumps it so a
    /// superseded worker's in-flight mutations become no-ops and it self-exits,
    /// leaving the replacement worker the sole writer.
    writer_token: AtomicU64,
    /// Set by `stop` to idle the worker without spawning a replacement. The
    /// worker checks it alongside the token and self-exits when true.
    stopped: AtomicBool,
    /// Backfill floor remembered at `start`, reused by `restart`. `None`
    /// until a worker is spawned.
    worker: Mutex<Option<BackfillFloor>>,
    /// Request side of the header worker's client, kept so `stop` can close
    /// the connection instead of waiting out the worker's receive timeout.
    header_req: Mutex<Option<mpsc::Sender<HeaderRequest>>>,
    /// Request side of the dedicated merkle-proof client, `None` until a
    /// worker is spawned and replaced on every `restart`. The scan side never
    /// sees it: proof fetching rides the validator's own connection.
    merkle_req: Mutex<Option<mpsc::Sender<CoinRequest>>>,
    /// The fetches this store issues, and who is waiting for each of them.
    merkle: Arc<MerkleRouter>,
    /// Where this store reports its own events. A store shared by several
    /// consumers reports to each of them, one registration per consumer.
    notifications: Fanout<Notification>,
    /// The header worker and the merkle forwarder. `stop` signals them and
    /// leaves them parked rather than blocking, and `Drop` joins them: they
    /// hold the electrum connections open until they exit. The
    /// replay-validation thread is deliberately not here: it holds an `Arc` to
    /// this store, so it can be the last owner and run this `Drop` itself,
    /// where joining it would be a self-join.
    header_worker: Mutex<Worker>,
    merkle_worker: Mutex<Worker>,
}

/// How a fetch issued through [`HeaderStore::fetch_merkle`] resolved. A
/// failure is fanned out like a proof, so a requester that reserved a slot for
/// this fetch frees it and asks again on a later pass instead of waiting for an
/// answer that never comes.
#[derive(Debug, Clone)]
pub enum MerkleOutcome {
    Proof(MerkleProof),
    Failed { txid: Txid, height: u32 },
}

impl MerkleOutcome {
    /// The fetch this outcome ends, as the `(txid, height)` it was issued for.
    pub fn claim(&self) -> (Txid, u32) {
        match self {
            Self::Proof(proof) => (proof.txid, proof.height),
            Self::Failed { txid, height } => (*txid, *height),
        }
    }
}

/// The merkle fan-out plus the table that routes an outcome back to whoever
/// asked for that transaction, so a store shared by several reconcilers wakes
/// only the one the answer belongs to.
#[derive(Debug, Default)]
struct MerkleRouter {
    listeners: Fanout<MerkleOutcome>,
    /// Requesters of the fetches still waiting for an answer. Two reconcilers
    /// can want the same fetch, so a `(txid, height)` maps to a set of them. An
    /// entry a superseded client left behind is consumed by the next answer
    /// for that fetch.
    pending: Mutex<HashMap<(Txid, u32), BTreeSet<ListenerId>>>,
}

impl MerkleRouter {
    fn record(&self, txid: Txid, height: u32, requester: ListenerId) {
        self.pending
            .lock()
            .expect("poisoned")
            .entry((txid, height))
            .or_default()
            .insert(requester);
    }

    /// Hand `outcome` to whoever asked for that fetch. With nobody recorded (a
    /// fetch issued before a restart, or an answer the server repeated) it goes
    /// to every listener rather than being dropped: an outcome the requester
    /// never sees leaves it holding an in-flight slot.
    fn deliver(&self, outcome: MerkleOutcome) {
        let requesters = self
            .pending
            .lock()
            .expect("poisoned")
            .remove(&outcome.claim());
        match requesters {
            Some(ids) => {
                for id in ids {
                    self.listeners.notify_one(id, outcome.clone());
                }
            }
            None => self.listeners.notify(outcome),
        }
    }

    /// End every fetch still waiting for an answer, for when the client that
    /// would have answered them is gone.
    fn fail_pending(&self) {
        let pending = std::mem::take(&mut *self.pending.lock().expect("poisoned"));
        for ((txid, height), ids) in pending {
            for id in ids {
                self.listeners
                    .notify_one(id, MerkleOutcome::Failed { txid, height });
            }
        }
    }
}

/// A merkle branch the server returned for a fetch issued through
/// [`HeaderStore::fetch_merkle`].
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub txid: Txid,
    pub height: u32,
    /// Siblings in internal (little-endian) order, ready to feed
    /// [`verify_merkle_branch`].
    pub branch: Vec<[u8; MERKLE_HASH_BYTES]>,
    pub pos: u32,
}

#[derive(Debug)]
struct BackfillFloor {
    min_height: Option<u32>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("failed to connect to electrum: {0}")]
    Connect(#[from] ClientError),
    #[error("failed to open header backend: {0}")]
    Open(#[from] PersistError),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCause {
    #[error("{0}")]
    Validator(ValidatorError),
    #[error("header store read failed: {0}")]
    StoreRead(PersistError),
    #[error("header sanity check failed")]
    Sanity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderValidationState {
    Unchecked,
    Validating,
    Valid,
    Invalid(InvalidCause),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderProgressPhase {
    Replay,
    InitialSync,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderProgressEvent {
    Started {
        phase: HeaderProgressPhase,
        start: u32,
        end: u32,
    },
    Progress {
        phase: HeaderProgressPhase,
        current: u32,
        end: u32,
    },
    Completed {
        phase: HeaderProgressPhase,
    },
    Failed {
        phase: HeaderProgressPhase,
    },
}

/// Failure from a chain mutator: either the incoming header failed
/// validation, or persisting the change failed. Persist failures must
/// surface so the in-memory chain and the on-disk file cannot silently
/// diverge.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MutateError {
    #[error("header validation failed: {0}")]
    Validate(#[from] ValidatorError),
    #[error("header persistence failed: {0}")]
    Persist(#[from] PersistError),
    #[error("anchor must be on an empty store at a retarget boundary")]
    BadAnchor,
}

#[derive(Debug)]
struct Inner<S> {
    store: S,
    validation_state: HeaderValidationState,
}

#[derive(Debug, Default)]
struct ProgressListeners {
    latest: Option<HeaderProgressEvent>,
    listeners: Vec<mpsc::Sender<HeaderProgressEvent>>,
}

impl HeaderStore<RamStore<Arc<dyn PersistenceBackend>, u32, [u8; Header::SIZE]>> {
    pub fn new_in_memory(network: Network) -> Arc<Self> {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        Self::from_store(
            network,
            RamStore::empty(backend, STORE_KEY, encode_height, encode_header),
        )
    }

    /// Backend-backed store. Loads rows through the typed store layer and
    /// starts empty if the stored chain fails to decode.
    pub fn from_backend(network: Network, backend: Arc<dyn PersistenceBackend>) -> Arc<Self> {
        let store = match RamStore::open(
            backend.clone(),
            STORE_KEY,
            encode_height,
            decode_height,
            encode_header,
            decode_header,
        ) {
            Ok(store) => store,
            Err(e) => {
                // Header data failed to decode. The chain is cheap to refetch
                // from the server, so start empty and let the worker resync.
                // Keep the real backend (not a NoopBackend) so the resynced
                // chain re-persists rather than silently dropping every write.
                // Unlike wallet stores, where corrupt data must propagate as
                // an error (never silently discarded), headers are a pure
                // refetchable cache: wipe + resync is the correct recovery.
                log::warn!(
                    "HeaderStore::from_backend: load failed: {e}; starting empty, will resync"
                );
                RamStore::empty(backend, STORE_KEY, encode_height, encode_header)
            }
        };
        Self::from_store(network, store)
    }

    /// File-backed store. An open failure is a real environment error (not
    /// data corruption, which `from_backend` recovers from by resyncing),
    /// so it propagates rather than silently dropping persistence.
    pub fn from_file(network: Network, path: PathBuf) -> Result<Arc<Self>, PersistError> {
        let backend = HeaderBackend::open(path, Header::SIZE)?;
        Ok(Self::from_backend(network, Arc::new(backend)))
    }

    /// Test-only constructor that injects a prebuilt map without running
    /// sanity checks. Used by unit tests that build synthetic chains.
    #[cfg(any(test, feature = "test"))]
    pub fn from_map(network: Network, map: BTreeMap<u32, [u8; Header::SIZE]>) -> Arc<Self> {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        let mut store = RamStore::empty(backend, STORE_KEY, encode_height, encode_header);
        for (h, raw) in map {
            if let Err(e) = store.insert(h, raw) {
                log::error!("HeaderStore::from_map insert {h}: {e}");
            }
        }
        Arc::new(Self {
            network,
            inner: Mutex::new(Inner {
                store,
                validation_state: HeaderValidationState::Valid,
            }),
            listeners: Fanout::default(),
            progress_listeners: Mutex::new(ProgressListeners::default()),
            writer_token: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            worker: Mutex::new(None),
            header_req: Mutex::new(None),
            merkle_req: Mutex::new(None),
            merkle: Arc::default(),
            notifications: Fanout::default(),
            header_worker: Mutex::default(),
            merkle_worker: Mutex::default(),
        })
    }

    /// Construct a file-backed (or in-memory) `HeaderStore` wired to a
    /// dedicated background worker that drives initial sync, applies
    /// incoming tip notifications, and resolves reorgs.
    ///
    /// `path == None` yields an in-memory store. `min_height == Some(h)`
    /// snaps the initial backfill down to the nearest 2016-block boundary
    /// at or below `h`; `None` starts from the server-reported tip.
    ///
    /// The worker thread holds a `Weak<HeaderStore>` so it exits cleanly
    /// once the last public `Arc` is dropped.
    pub fn start(
        electrum_url: String,
        electrum_port: u16,
        network: Network,
        path: Option<PathBuf>,
        min_height: Option<u32>,
        certificate_check: CertificateCheck,
    ) -> Result<Arc<Self>, StartError> {
        let store = match path {
            Some(p) => Self::from_file(network, p)?,
            None => Self::new_in_memory(network),
        };

        // A failure to connect is surfaced to the caller rather than
        // silently returning a worker-less store: header-sync progress
        // gates wallet `Verified` state, so the caller must know the store
        // is degraded and can re-attempt.
        store.spawn_worker(&electrum_url, electrum_port, min_height, certificate_check)?;
        Ok(store)
    }

    /// Start online against `url`/`port` when both are given, or open
    /// file-backed/in-memory (idle) when no endpoint is configured. Shared
    /// try-start-else-open branching for callers (e.g. `bwk::Account`,
    /// `bwk_sp::Account`) that build one `HeaderStore` per config; whether an
    /// endpoint is even attempted (e.g. an "offline" config flag) is the
    /// caller's call, expressed by passing `None`.
    ///
    /// A missing endpoint is not an error: it opens idle. A failed connect
    /// against a *given* endpoint is surfaced as [`StartError`] rather than
    /// silently degrading to an idle store, matching [`start`](Self::start).
    pub fn start_or_open(
        url: Option<String>,
        port: Option<u16>,
        network: Network,
        path: Option<PathBuf>,
        min_height: Option<u32>,
        certificate_check: CertificateCheck,
    ) -> Result<Arc<Self>, StartError> {
        if let (Some(url), Some(port)) = (url, port) {
            return Self::start(url, port, network, path, min_height, certificate_check);
        }
        Ok(match path {
            Some(p) => Self::from_file(network, p)?,
            None => Self::new_in_memory(network),
        })
    }

    /// Reconnect the background worker to `url:port` after the previous
    /// connection died. Clears the stop flag and bumps the writer token so the
    /// superseded worker self-exits and its in-flight mutations become no-ops,
    /// then spawns a fresh worker (the sole writer under the new token) reusing
    /// the backfill floor remembered at [`start`](Self::start).
    ///
    /// `certificate_check` is the caller's, not remembered: a store that opened
    /// idle never held one, and reconnecting under the default would strand a
    /// consumer who configured a self-signed server.
    pub fn restart(
        self: &Arc<Self>,
        url: String,
        port: u16,
        certificate_check: CertificateCheck,
    ) -> Result<(), StartError> {
        let min_height = self.remembered_min_height();
        // Close the previous pair rather than leaving its sockets open until
        // the superseded worker times out and drops its request sender.
        self.stop();
        self.stopped.store(false, Ordering::SeqCst);
        self.writer_token.fetch_add(1, Ordering::SeqCst);
        self.spawn_worker(&url, port, min_height, certificate_check)
    }

    /// Connect a fresh worker pair to `url:port` and record the backfill floor
    /// with the writer token it was spawned under: the header worker that
    /// drives sync and reorg resolution, plus the merkle client the validator
    /// fetches inclusion proofs over.
    fn spawn_worker(
        self: &Arc<Self>,
        url: &str,
        port: u16,
        min_height: Option<u32>,
        certificate_check: CertificateCheck,
    ) -> Result<(), StartError> {
        let client = connect(url, port, certificate_check)?;
        // A second connection on purpose: the header worker's loop is a strict
        // sequence of header fetches that blocks on each answer, so proof
        // traffic multiplexed into it would stall sync behind every proof.
        let merkle = connect(url, port, certificate_check)?;
        let (req_tx, resp_rx) = client.listen_headers::<HeaderRequest, HeaderResponse>();
        let token = self.writer_token.load(Ordering::SeqCst);
        *self.worker.lock().expect("poisoned") = Some(BackfillFloor { min_height });
        *self.header_req.lock().expect("poisoned") = Some(req_tx.clone());
        self.spawn_merkle_client(merkle, token);
        let weak = Arc::downgrade(self);
        let network = self.network;
        self.header_worker
            .lock()
            .expect("poisoned")
            .start(move |_| run_worker(weak, network, min_height, token, req_tx, resp_rx));
        Ok(())
    }

    /// Wire `client` as the merkle-proof fetcher: its request sender replaces
    /// the previous one, and a forwarding thread routes every answer back to
    /// the listener that asked for it. The thread ends when the client's
    /// response channel closes, which [`stop`](Self::stop) and `Drop` trigger
    /// by asking the client to close.
    fn spawn_merkle_client(self: &Arc<Self>, client: Client, token: u64) {
        let (req_tx, resp_rx) = client.listen_txs::<CoinRequest, CoinResponse>();
        *self.merkle_req.lock().expect("poisoned") = Some(req_tx);
        let merkle = self.merkle.clone();
        let weak = Arc::downgrade(self);
        self.merkle_worker
            .lock()
            .expect("poisoned")
            .start(move |_| forward_merkle_proofs(resp_rx, merkle, weak, token));
    }
}

/// Route every answer the merkle client returns back to the listener that
/// asked for it, until the client's response channel closes. Split out of
/// [`HeaderStore::spawn_merkle_client`] so the exit path can be driven directly.
fn forward_merkle_proofs<S>(
    resp_rx: mpsc::Receiver<CoinResponse>,
    merkle: Arc<MerkleRouter>,
    weak: Weak<HeaderStore<S>>,
    token: u64,
) where
    S: Store<Key = u32, Value = [u8; Header::SIZE]> + Send + 'static,
{
    for resp in resp_rx {
        let outcome = match resp {
            CoinResponse::TxMerkle {
                txid,
                height,
                branch,
                pos,
            } => MerkleOutcome::Proof(MerkleProof {
                txid,
                height,
                branch,
                pos,
            }),
            CoinResponse::Stopped => break,
            CoinResponse::Error(e) => {
                log::warn!("HeaderStore merkle client: {e}");
                match e {
                    // A stale height across a reorg, or transient server
                    // trouble: both name the fetch they end, so report it and
                    // let the requester ask again on a later pass.
                    CoinError::MerkleFetch { txid, height, .. }
                    | CoinError::MerkleDecode { txid, height, .. } => {
                        MerkleOutcome::Failed { txid, height }
                    }
                    _ => continue,
                }
            }
            other => {
                log::warn!("HeaderStore merkle client: unexpected {}", other.summary());
                continue;
            }
        };
        merkle.deliver(outcome);
    }
    if let Some(store) = weak.upgrade() {
        store.merkle_client_ended(token);
    }
}

/// Open an electrum connection, tagging a failure as [`StartError::Connect`].
fn connect(
    url: &str,
    port: u16,
    certificate_check: CertificateCheck,
) -> Result<Client, StartError> {
    Client::new(url, port, certificate_check).map_err(|e| {
        log::warn!("HeaderStore: fail to create electrum client {url}:{port}: {e}");
        StartError::Connect(e)
    })
}

impl<S> HeaderStore<S>
where
    S: Store<Key = u32, Value = [u8; Header::SIZE]> + Send + 'static,
{
    pub fn from_store(network: Network, store: S) -> Arc<Self> {
        let store = Arc::new(Self {
            network,
            inner: Mutex::new(Inner {
                store,
                validation_state: HeaderValidationState::Unchecked,
            }),
            listeners: Fanout::default(),
            progress_listeners: Mutex::new(ProgressListeners::default()),
            writer_token: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            worker: Mutex::new(None),
            header_req: Mutex::new(None),
            merkle_req: Mutex::new(None),
            merkle: Arc::default(),
            notifications: Fanout::default(),
            header_worker: Mutex::default(),
            merkle_worker: Mutex::default(),
        });
        store.start_replay_validation();
        store
    }

    fn start_replay_validation(self: &Arc<Self>) {
        let snapshot = match self.raw_map() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                // A read failure here is not an empty chain; treating it as
                // empty would mark the store Valid and mask the lost data.
                self.set_validation_state(HeaderValidationState::Invalid(InvalidCause::StoreRead(
                    e,
                )));
                return;
            }
        };
        if snapshot.is_empty() {
            self.set_validation_state(HeaderValidationState::Valid);
            return;
        }
        if !sanity_check(self.network, &snapshot) {
            // Wipe before publishing Invalid: `wait_for_replay` unparks the
            // worker the moment state leaves `Validating`, so the store must
            // already be empty when the Invalid state (and notification)
            // becomes visible, or the worker could append onto a chain about to
            // be cleared. A clear failure is only surfaced, not acted on.
            if let Err(e) = self.clear_store() {
                log::error!("HeaderStore::start_replay_validation: clear after sanity fail: {e}");
            }
            self.set_validation_state(HeaderValidationState::Invalid(InvalidCause::Sanity));
            self.publish_progress(HeaderProgressEvent::Failed {
                phase: HeaderProgressPhase::Replay,
            });
            self.notify_listeners();
            return;
        }

        self.set_validation_state(HeaderValidationState::Validating);
        let start = *snapshot.keys().next().expect("non-empty");
        let end = *snapshot.keys().last().expect("non-empty");
        self.publish_progress(HeaderProgressEvent::Started {
            phase: HeaderProgressPhase::Replay,
            start,
            end,
        });
        let store = self.clone();
        let network = self.network;
        thread::spawn(move || {
            match replay_validate(network, &snapshot, |current, end| {
                store.publish_progress(HeaderProgressEvent::Progress {
                    phase: HeaderProgressPhase::Replay,
                    current,
                    end,
                });
            }) {
                Ok(()) => store.finish_replay_validation_success(),
                Err(e) => {
                    // Wipe before publishing Invalid (see start_replay_validation):
                    // the parked worker unparks as soon as state leaves
                    // `Validating`, so the store must be empty first.
                    if let Err(clear_err) = store.clear_store() {
                        log::error!(
                            "HeaderStore::replay_validate: clear after invalid chain: {clear_err}"
                        );
                    }
                    store.set_validation_state(HeaderValidationState::Invalid(
                        InvalidCause::Validator(e),
                    ));
                    store.publish_progress(HeaderProgressEvent::Failed {
                        phase: HeaderProgressPhase::Replay,
                    });
                    store.notify_listeners();
                }
            }
        });
    }

    fn raw_map(&self) -> Result<BTreeMap<u32, [u8; Header::SIZE]>, PersistError> {
        Ok(self.inner.lock().expect("poisoned").store.iter()?.collect())
    }

    /// Run `f` against the inner store, but only if `token` is still the
    /// authoritative writer token (checked WHILE holding the inner lock, so
    /// the check and the mutation cannot be split by a concurrent `restart`).
    /// Returns `None` when this worker has been superseded, in which case the
    /// caller treats the mutation as a no-op and exits.
    fn with_writer<R>(&self, token: u64, f: impl FnOnce(&mut Inner<S>) -> R) -> Option<R> {
        let mut inner = self.inner.lock().expect("poisoned");
        if self.writer_token.load(Ordering::SeqCst) != token {
            return None;
        }
        Some(f(&mut inner))
    }

    fn clear_store(&self) -> Result<(), MutateError> {
        let mut inner = self.inner.lock().expect("poisoned");
        clear_inner(&mut inner)?;
        Ok(())
    }

    fn set_validation_state(&self, state: HeaderValidationState) {
        self.inner.lock().expect("poisoned").validation_state = state;
    }

    fn finish_replay_validation_success(&self) {
        let notify = {
            let mut inner = self.inner.lock().expect("poisoned");
            let notify = matches!(inner.validation_state, HeaderValidationState::Validating);
            inner.validation_state = HeaderValidationState::Valid;
            notify
        };
        if notify {
            self.publish_progress(HeaderProgressEvent::Completed {
                phase: HeaderProgressPhase::Replay,
            });
            self.notify_listeners();
        }
    }

    #[cfg(any(test, feature = "test"))]
    #[allow(dead_code)]
    pub fn set_validation_state_for_test(&self, state: HeaderValidationState) {
        self.set_validation_state(state);
    }

    pub fn validation_state(&self) -> HeaderValidationState {
        self.inner
            .lock()
            .expect("poisoned")
            .validation_state
            .clone()
    }

    pub fn is_validated(&self) -> bool {
        matches!(self.validation_state(), HeaderValidationState::Valid)
    }

    pub fn validation_failed_reason(&self) -> Option<InvalidCause> {
        match self.validation_state() {
            HeaderValidationState::Invalid(cause) => Some(cause),
            _ => None,
        }
    }

    pub(crate) fn append(
        &self,
        token: u64,
        h: u32,
        raw: [u8; Header::SIZE],
    ) -> Result<(), MutateError> {
        let incoming: Header = deserialize(&raw).map_err(|_| ValidatorError::MalformedHeader)?;
        let network = self.network;
        // Read ancestors, validate, insert and flush all under the one lock
        // hold, so no concurrent mutation can slip between the ancestor read
        // and the insert (the old two-acquisition path had that TOCTOU).
        let res = self.with_writer(token, |inner| -> Result<(), MutateError> {
            let ancestors = collect_ancestors(h, retarget_interval(network), |k| {
                inner.store.get(&k).ok().flatten()
            });
            header_validator::validate_append(network, &ancestors, h, &incoming, now_secs())?;
            let was_empty = inner.store.keys()?.next().is_none();
            inner.store.insert(h, raw)?;
            inner.store.flush()?;
            match inner.validation_state {
                HeaderValidationState::Validating => {}
                // A non-empty chain already flagged Invalid stays Invalid: one
                // valid append does not re-validate the headers before it, so
                // only full replay validation may promote it back to Valid.
                HeaderValidationState::Invalid(_) if !was_empty => {}
                _ => inner.validation_state = HeaderValidationState::Valid,
            }
            Ok(())
        });
        match res {
            Some(Ok(())) => {
                self.notify_listeners();
                Ok(())
            }
            Some(Err(e)) => Err(e),
            // Superseded: the worker is exiting, so a skipped append is not an
            // error.
            None => Ok(()),
        }
    }

    /// Store `raw` at `h` trusting it on proof-of-work alone, consistent
    /// with the reload (`replay_validate`) path: the lowest header of a
    /// sparse chain has no ancestors to link against, so it is anchored by
    /// PoW only rather than by full `validate_append`.
    ///
    /// Trust model: a sparse anchor is not connected to any pinned
    /// checkpoint, so a malicious server could serve a fabricated
    /// low-difficulty chain from the anchor upward. Sparse-start operation
    /// assumes an honest server for the anchor's chain context; only a
    /// genesis-anchored chain is fully self-validating.
    #[cfg(test)]
    pub(crate) fn append_anchor(
        &self,
        token: u64,
        h: u32,
        raw: [u8; Header::SIZE],
    ) -> Result<(), MutateError> {
        let header: Header = deserialize(&raw).map_err(|_| ValidatorError::MalformedHeader)?;
        let params = Params::new(self.network);
        header_validator::check_pow(&params, &header)?;
        let network = self.network;

        let res = self.with_writer(token, |inner| -> Result<(), MutateError> {
            // The reload `sanity_check` requires exactly these two invariants
            // of a sparse anchor: the store is empty and the anchor sits on a
            // retarget boundary. Enforce them here rather than trusting the
            // caller, so an anchor can never leave the store in a shape a
            // later reload would wipe.
            let empty = inner.store.keys()?.next().is_none();
            if !empty || h % retarget_interval(network) as u32 != 0 {
                return Err(MutateError::BadAnchor);
            }
            inner.store.insert(h, raw)?;
            inner.store.flush()?;
            inner.validation_state = HeaderValidationState::Valid;
            Ok(())
        });
        match res {
            Some(Ok(())) => {
                self.notify_listeners();
                Ok(())
            }
            Some(Err(e)) => Err(e),
            None => Ok(()),
        }
    }

    fn append_batch(
        &self,
        token: u64,
        start: u32,
        raws: &[[u8; Header::SIZE]],
    ) -> Result<(), MutateError> {
        if raws.is_empty() {
            return Ok(());
        }
        let network = self.network;
        let res = self.with_writer(token, |inner| -> Result<(), MutateError> {
            let was_empty = inner.store.keys()?.next().is_none();
            let mut ancestors = if was_empty {
                VecDeque::new()
            } else {
                collect_ancestors(start, retarget_interval(network), |k| {
                    inner.store.get(&k).ok().flatten()
                })
                .into()
            };
            let params = Params::new(network);

            for (i, raw) in raws.iter().enumerate() {
                let h = start + i as u32;
                let header: Header =
                    deserialize(raw).map_err(|_| ValidatorError::MalformedHeader)?;
                if was_empty && i == 0 && h > 0 {
                    if h % retarget_interval(network) as u32 != 0 {
                        return Err(MutateError::BadAnchor);
                    }
                    header_validator::check_pow(&params, &header)?;
                } else {
                    header_validator::validate_append(
                        network,
                        ancestors.make_contiguous(),
                        h,
                        &header,
                        now_secs(),
                    )?;
                }
                inner.store.insert(h, *raw)?;
                ancestors.push_back(header);
                if ancestors.len() > retarget_interval(network) {
                    ancestors.pop_front();
                }
            }

            inner.store.flush()?;
            inner.validation_state = HeaderValidationState::Valid;
            Ok(())
        });
        match res {
            Some(Ok(())) => {
                self.notify_listeners();
                Ok(())
            }
            Some(Err(e)) => Err(e),
            None => Ok(()),
        }
    }

    /// Decode the contiguous run of stored headers ending at `h - 1`, oldest
    /// first (the immediate parent `h - 1` is last), bounded to at most `max`
    /// entries. Reads under a single lock and shares `collect_ancestors`'s
    /// downward-scan gap semantics with `decode_ancestors`. For a sparse cache
    /// anchored at `min_stored > 0` this yields exactly `[min_stored, h)`.
    /// Empty if `h == 0`.
    ///
    /// Test-only: `append` reads ancestors inline under its own lock hold (to
    /// close the read-validate-insert TOCTOU), so the only remaining callers
    /// are the ancestor-window regression tests.
    #[cfg(test)]
    fn ancestors_for(&self, h: u32, max: usize) -> Vec<Header> {
        let inner = self.inner.lock().expect("poisoned");
        collect_ancestors(h, max, |k| inner.store.get(&k).ok().flatten())
    }

    fn replace_branch(
        &self,
        token: u64,
        fork_h: u32,
        branch: &BTreeMap<u32, [u8; Header::SIZE]>,
    ) -> Result<(), MutateError> {
        let res = self.with_writer(token, |inner| -> Result<(), MutateError> {
            let keys: Vec<u32> = inner.store.keys()?.filter(|k| *k > fork_h).collect();
            for key in keys {
                inner.store.remove(&key)?;
            }
            for (h, raw) in branch {
                inner.store.insert(*h, *raw)?;
            }
            inner.store.flush()?;
            inner.validation_state = HeaderValidationState::Valid;
            Ok(())
        });
        match res {
            Some(Ok(())) => {
                self.notify_listeners();
                Ok(())
            }
            Some(Err(e)) => Err(e),
            None => Ok(()),
        }
    }

    fn notify_listeners(&self) {
        self.listeners.notify(());
    }

    fn publish_progress(&self, event: HeaderProgressEvent) {
        let mut progress = self.progress_listeners.lock().expect("poisoned");
        progress.latest = Some(event.clone());
        progress
            .listeners
            .retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// Wipe the in-memory chain (and persisted file if applicable). Used by
    /// the worker on unrecoverable inconsistencies (genesis mismatch, etc.).
    /// Token-gated like the other worker mutations: a superseded worker's wipe
    /// is a no-op so it cannot clear a chain the replacement worker owns.
    fn wipe(&self, token: u64) {
        // Every wipe call site bails out (returns) right after, so a clear
        // failure here cannot be acted on and is only surfaced via the log.
        if let Some(Err(e)) = self.with_writer(token, |inner| clear_inner(inner)) {
            log::error!("HeaderStore::wipe: clear failed: {e}");
        }
    }

    /// Backfill floor remembered when the worker was spawned, reused by
    /// `restart` and by the below-floor re-sync in `resolve_reorg`.
    fn remembered_min_height(&self) -> Option<u32> {
        self.worker
            .lock()
            .expect("poisoned")
            .as_ref()
            .and_then(|w| w.min_height)
    }

    /// Lowest stored height (used by the worker to bound reorg walk-back).
    fn min_height(&self) -> Option<u32> {
        self.inner
            .lock()
            .expect("poisoned")
            .store
            .keys()
            .ok()?
            .next()
    }

    pub fn tip(&self) -> Option<u32> {
        self.inner
            .lock()
            .expect("poisoned")
            .store
            .keys()
            .ok()?
            .last()
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        let tip = self.tip()?;
        self.block_hash(tip)
    }

    /// Tip height and its block hash, read under a single lock so the two
    /// cannot race against a concurrent append/prune between calls.
    pub fn tip_with_hash(&self) -> Option<(u32, BlockHash)> {
        let inner = self.inner.lock().expect("poisoned");
        let tip = inner.store.keys().ok()?.last()?;
        let raw = inner.store.get(&tip).ok().flatten()?;
        let hash = deserialize::<Header>(&raw).ok()?.block_hash();
        Some((tip, hash))
    }

    pub fn header(&self, h: u32) -> Option<Header> {
        let raw = self
            .inner
            .lock()
            .expect("poisoned")
            .store
            .get(&h)
            .ok()
            .flatten()?;
        deserialize::<Header>(&raw).ok()
    }

    pub fn block_hash(&self, h: u32) -> Option<BlockHash> {
        self.header(h).map(|hdr| hdr.block_hash())
    }

    pub fn merkle_root(&self, h: u32) -> Option<TxMerkleNode> {
        self.header(h).map(|hdr| hdr.merkle_root)
    }

    /// Merkle root and block hash at `h`, read under a single lock so the
    /// two cannot tear against a concurrent append/prune between calls.
    pub fn merkle_root_and_hash(&self, h: u32) -> Option<(TxMerkleNode, BlockHash)> {
        let inner = self.inner.lock().expect("poisoned");
        let raw = inner.store.get(&h).ok().flatten()?;
        let hdr = deserialize::<Header>(&raw).ok()?;
        Some((hdr.merkle_root, hdr.block_hash()))
    }

    /// Register a listener notified (via an empty `()`) on every chain
    /// update. Drop the returned receiver to deregister.
    pub fn register_chain_tick(&self) -> mpsc::Receiver<()> {
        self.listeners.register()
    }

    /// Register `id` as a listener for how the fetches it issues resolve:
    /// [`fetch_merkle`](Self::fetch_merkle) routes an outcome back by that id.
    /// A listener restarting on a fresh channel registers under the same id,
    /// so the store does not keep the one it left behind.
    pub fn register_merkle_outcome(&self, id: ListenerId) -> mpsc::Receiver<MerkleOutcome> {
        self.merkle.listeners.register_as(id)
    }

    /// Route this store's own events to `sender`. Registered once per consumer
    /// by whoever owns the store: a store shared by several consumers reports
    /// to each of them exactly once.
    pub fn register_notifications(&self, sender: mpsc::Sender<Notification>) {
        self.notifications.register_sender(sender);
    }

    fn notify_merkle_fetch_stopped(&self) {
        self.notifications
            .notify_with(|| Notification::MerkleFetchStopped);
    }

    /// True while this store has a live worker pair: `false` when it was
    /// opened with no endpoint, when `stop` idled it, or once both its threads
    /// have exited.
    pub fn running(&self) -> bool {
        !self.stopped.load(Ordering::SeqCst)
            && (self.header_worker.lock().expect("poisoned").running()
                || self.merkle_worker.lock().expect("poisoned").running())
    }

    /// The merkle forwarder spawned under `token` exited: clear the request
    /// side it owned and report that no proof is being fetched any more. A
    /// `restart` (which bumps the token) already installed a newer client, and
    /// a `stop` already took the sender, so neither has anything to report.
    fn merkle_client_ended(&self, token: u64) {
        if self.writer_token.load(Ordering::SeqCst) != token {
            return;
        }
        // Nothing is left to answer the fetches this client was holding.
        self.merkle.fail_pending();
        let mut slot = self.merkle_req.lock().expect("poisoned");
        if slot.take().is_none() {
            return;
        }
        drop(slot);
        self.notify_merkle_fetch_stopped();
    }

    /// Ask the server to prove `txid` is included in the block at `height`, on
    /// behalf of `requester`: the answer goes back to that listener alone. With
    /// no client to ask, the fetch resolves right away as
    /// [`MerkleOutcome::Failed`] rather than being dropped in silence: a
    /// requester holding a slot for it must learn it is over.
    pub fn fetch_merkle(&self, requester: ListenerId, txid: Txid, height: u32) {
        self.merkle.record(txid, height, requester);
        let sent = match self.merkle_req.lock().expect("poisoned").as_ref() {
            Some(req) => req.send(CoinRequest::GetTxMerkle { txid, height }).is_ok(),
            None => false,
        };
        if !sent {
            self.merkle.deliver(MerkleOutcome::Failed { txid, height });
        }
    }

    /// Route merkle fetches to `req` instead of an electrum client, so a test
    /// can observe them against a store built with no worker.
    #[cfg(any(test, feature = "test"))]
    pub fn set_merkle_sender_for_test(&self, req: mpsc::Sender<CoinRequest>) {
        *self.merkle_req.lock().expect("poisoned") = Some(req);
    }

    /// Register a listener for header validation progress. If a lifecycle event
    /// already happened, the receiver gets it before any future events.
    pub fn register_progress(&self) -> mpsc::Receiver<HeaderProgressEvent> {
        let (tx, rx) = mpsc::channel();
        let mut progress = self.progress_listeners.lock().expect("poisoned");
        if let Some(event) = progress.latest.clone() {
            let _ = tx.send(event);
        }
        progress.listeners.push(tx);
        rx
    }

    #[cfg(test)]
    fn insert_unchecked(&self, h: u32, raw: [u8; Header::SIZE]) {
        let mut inner = self.inner.lock().expect("poisoned");
        if let Err(e) = inner.store.insert(h, raw) {
            log::error!("HeaderStore::insert_unchecked insert {h}: {e}");
        }
        if let Err(e) = inner.store.flush() {
            log::error!("HeaderStore::insert_unchecked flush: {e}");
        }
    }
}

// Bounded exactly like the struct: `Drop` may not add bounds, so `stop` cannot
// live in the `Send + 'static` block above.
impl<S> HeaderStore<S>
where
    S: Store<Key = u32, Value = [u8; Header::SIZE]>,
{
    /// Idle both connections without spawning a replacement, leaving the store
    /// worker-less until a later `restart` reconnects it. The header worker
    /// returns on `Stopped` instead of waiting out its receive timeout, and the
    /// merkle forwarder ends when its response channel closes. Does not block:
    /// the threads are left parked for `Drop` to join.
    ///
    /// Every fetch still waiting ends as [`MerkleOutcome::Failed`] here rather
    /// than on the forwarder's own exit: a `restart` bumps the writer token
    /// before that exit lands, which makes it a no-op, and a requester that
    /// never hears back holds its in-flight slot forever.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.merkle.fail_pending();
        if let Some(req) = self.header_req.lock().expect("poisoned").take() {
            let _ = req.send(HeaderRequest::Stop);
        }
        if let Some(req) = self.merkle_req.lock().expect("poisoned").take() {
            let _ = req.send(CoinRequest::Stop);
        }
        self.header_worker.lock().expect("poisoned").stop();
        self.merkle_worker.lock().expect("poisoned").stop();
    }
}

impl<S> Drop for HeaderStore<S>
where
    S: Store<Key = u32, Value = [u8; Header::SIZE]>,
{
    fn drop(&mut self) {
        // The worker threads hold the electrum connections open; signal them
        // first so the joins do not wait out the worker's receive timeout.
        self.stop();
        self.header_worker.lock().expect("poisoned").join();
        self.merkle_worker.lock().expect("poisoned").join();
    }
}

/// Verify a merkle branch against an expected root.
///
/// Folds `txid` upward through `branch`: at each level, if the current
/// position bit is 0 the running node is hashed as `sha256d(node ||
/// sibling)`, else as `sha256d(sibling || node)`. The final node is
/// compared against `expected_root`.
///
/// Rejects proofs whose `branch` is too short to address `pos`: each extra
/// branch level doubles the number of leaves the proof can reach, so a
/// branch of a given length covers only that many leaves and any position
/// at or beyond that count is impossible and must be rejected (a too-short
/// branch with a large position would otherwise fold to a bogus root).
pub fn verify_merkle_branch(
    txid: Txid,
    branch: &[[u8; 32]],
    pos: u32,
    expected_root: TxMerkleNode,
) -> bool {
    // `1 << len` for len >= 32 cannot be addressed by a u32 position, so
    // any such proof trivially covers every reachable `pos`; only guard
    // when the shift stays in range.
    if branch.len() < 32 && (1u64 << branch.len()) <= pos as u64 {
        return false;
    }
    let mut node: [u8; 32] = txid.to_byte_array();
    let mut idx = pos;
    for sibling in branch {
        let mut engine = sha256d::Hash::engine();
        if idx & 1 == 0 {
            engine.input(&node);
            engine.input(sibling);
        } else {
            engine.input(sibling);
            engine.input(&node);
        }
        node = sha256d::Hash::from_engine(engine).to_byte_array();
        idx >>= 1;
    }
    node == expected_root.to_byte_array()
}

/// Remove every row and flush. Shared by `clear_store` (its own lock) and the
/// token-gated `wipe` (inside `with_writer`'s lock), so it takes the already
/// locked inner rather than locking itself.
fn clear_inner<S>(inner: &mut Inner<S>) -> Result<(), PersistError>
where
    S: Store<Key = u32, Value = [u8; Header::SIZE]>,
{
    let keys: Vec<u32> = inner.store.keys()?.collect();
    for key in keys {
        inner.store.remove(&key)?;
    }
    inner.store.flush()
}

/// Collect the contiguous run of headers ending at `h - 1`, reading each
/// height through `get`. Scans downward from `h - 1` and stops at the first
/// gap (a height `get` cannot supply or decode) or once `h - max` is reached,
/// so a cache anchored at `min_stored > 0` yields exactly `[min_stored, h)`.
/// Returned oldest-first: the immediate parent `h - 1` is the last element,
/// which is what `validate_append` and its retarget/mtp/linkage checks expect.
/// Empty if `h == 0`.
fn collect_ancestors<F>(h: u32, max: usize, get: F) -> Vec<Header>
where
    F: Fn(u32) -> Option<[u8; Header::SIZE]>,
{
    if h == 0 {
        return Vec::new();
    }
    let lo = h.saturating_sub(max as u32);
    let mut out = Vec::new();
    let mut k = h - 1;
    while let Some(hdr) = get(k).and_then(|raw| deserialize::<Header>(&raw).ok()) {
        out.push(hdr);
        if k == lo {
            break;
        }
        k -= 1;
    }
    out.reverse();
    out
}

fn decode_ancestors(
    headers: &BTreeMap<u32, [u8; Header::SIZE]>,
    incoming_height: u32,
    max: usize,
) -> Vec<Header> {
    collect_ancestors(incoming_height, max, |k| headers.get(&k).copied())
}

fn sanity_check(network: Network, headers: &BTreeMap<u32, [u8; Header::SIZE]>) -> bool {
    if headers.is_empty() {
        return true;
    }
    let min = *headers.keys().next().expect("non-empty");
    let max = *headers.keys().next_back().expect("non-empty");
    let span = (max - min) as usize + 1;
    if span != headers.len() {
        return false;
    }
    // A sparse-anchored cache (min > 0) sits exactly on a retarget boundary
    // (the previous boundary below the account's min_height), matching
    // `backfill_floor`: this is what guarantees every retarget boundary at or
    // above the anchor has a full ancestor window. A violation fails loud
    // rather than silently validating with a partial window.
    if min != 0 && min % backfill_chunk(network) != 0 {
        return false;
    }
    if let Some(genesis) = expected_genesis(network) {
        // The genesis row is optional: a cache may legitimately start above
        // height 0 (snapped to a 2016 boundary). When height 0 *is* present
        // it must be the network genesis; the worker rebuilds the rest of
        // the chain via `GetHeaders` anchored at `min_stored`.
        if let Some(raw) = headers.get(&0) {
            match deserialize::<Header>(raw) {
                Ok(hdr) if hdr.block_hash() == genesis => {}
                _ => return false,
            }
        }
    }
    true
}

fn replay_validate(
    network: Network,
    headers: &BTreeMap<u32, [u8; Header::SIZE]>,
    mut progress: impl FnMut(u32, u32),
) -> Result<(), ValidatorError> {
    if headers.is_empty() {
        return Ok(());
    }
    let now_secs = now_secs();
    let min = *headers.keys().next().expect("non-empty");
    let max = *headers.keys().last().expect("non-empty");
    let max_ancestors = retarget_interval(network);
    let mut ancestors = VecDeque::new();
    let mut checked = 0usize;

    for (h, raw) in headers {
        let header: Header = deserialize(raw).map_err(|_| ValidatorError::MalformedHeader)?;
        if *h == 0 {
            header_validator::validate_append(network, &[], *h, &header, now_secs)?;
        } else if *h > min {
            header_validator::validate_append(
                network,
                ancestors.make_contiguous(),
                *h,
                &header,
                now_secs,
            )?;
        } else {
            let params = Params::new(network);
            header_validator::check_pow(&params, &header)?;
        }
        ancestors.push_back(header);
        if ancestors.len() > max_ancestors {
            ancestors.pop_front();
        }
        checked += 1;
        if checked % max_ancestors == 0 || *h == max {
            progress(*h, max);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct HeaderBranch {
    headers: BTreeMap<u32, [u8; Header::SIZE]>,
    chainwork: Work,
}

impl HeaderBranch {
    fn validate(
        network: Network,
        active: &BTreeMap<u32, [u8; Header::SIZE]>,
        fork_h: u32,
        incoming_h: u32,
        buffer: &BTreeMap<u32, [u8; Header::SIZE]>,
    ) -> Result<Self, ValidatorError> {
        let now_secs = now_secs();
        let mut combined = active.clone();
        combined.retain(|h, _| *h <= fork_h);
        let mut headers = BTreeMap::new();
        let mut chainwork = Work::from_be_bytes([0; 32]);

        for h in fork_h.saturating_add(1)..=incoming_h {
            let raw = *buffer.get(&h).ok_or(ValidatorError::MissingAncestor)?;
            let header: Header = deserialize(&raw).map_err(|_| ValidatorError::MalformedHeader)?;
            let ancestors = decode_ancestors(&combined, h, retarget_interval(network));
            header_validator::validate_append(network, &ancestors, h, &header, now_secs)?;
            chainwork = chainwork + header.work();
            combined.insert(h, raw);
            headers.insert(h, raw);
        }

        Ok(Self { headers, chainwork })
    }

    fn has_more_work_than_active(
        &self,
        active: &BTreeMap<u32, [u8; Header::SIZE]>,
        fork_h: u32,
    ) -> Result<bool, ValidatorError> {
        let mut active_work = Work::from_be_bytes([0; 32]);
        for raw in active.range(fork_h.saturating_add(1)..).map(|(_, raw)| raw) {
            // Fail loud like the candidate side (validate): an undecodable active
            // header must not be silently counted as zero work, which would bias
            // the comparison toward reorging away from a chain we cannot read.
            let header = deserialize::<Header>(raw).map_err(|_| ValidatorError::MalformedHeader)?;
            active_work = active_work + header.work();
        }
        Ok(self.chainwork > active_work)
    }
}

#[cfg(test)]
fn store_from_file(path: &std::path::Path) -> BTreeMap<u32, [u8; Header::SIZE]> {
    let backend = HeaderBackend::open(path.to_path_buf(), Header::SIZE).unwrap();
    backend
        .get_rows(STORE_KEY)
        .unwrap()
        .into_iter()
        .filter_map(|(k, v)| Some((decode_height(&k).ok()?, decode_header(&v).ok()?)))
        .collect()
}

#[cfg(test)]
fn write_to_disk(path: &std::path::Path, headers: &BTreeMap<u32, [u8; Header::SIZE]>) {
    let backend = HeaderBackend::open(path.to_path_buf(), Header::SIZE).unwrap();
    let inserts: Vec<(String, Vec<u8>)> = headers
        .iter()
        .map(|(h, raw)| (encode_height(h), encode_header(raw).unwrap()))
        .collect();
    let removed: Vec<String> = backend
        .get_rows(STORE_KEY)
        .unwrap()
        .into_iter()
        .filter_map(|(k, _)| {
            let h = decode_height(&k).ok()?;
            (!headers.contains_key(&h)).then_some(k)
        })
        .collect();
    backend.flush_batch(STORE_KEY, &inserts, &removed).unwrap();
}

#[cfg(test)]
fn append_to_disk(
    path: &std::path::Path,
    height: u32,
    raw: &[u8; Header::SIZE],
    full: &BTreeMap<u32, [u8; Header::SIZE]>,
) {
    // Scope the positional open so its advisory lock releases before
    // `write_to_disk` reopens the same file.
    {
        let backend = HeaderBackend::open(path.to_path_buf(), Header::SIZE).unwrap();
        let _ = backend.put_row(STORE_KEY, &encode_height(&height), raw);
    }
    write_to_disk(path, full);
}

// Worker driving initial sync and tip-following for `HeaderStore::start`.

/// Block height step used when issuing initial-sync `GetHeaders` batches.
/// One retarget period per batch so a backfilled window always carries the
/// ancestors a boundary retarget check needs.
fn backfill_chunk(network: Network) -> u32 {
    retarget_interval(network) as u32
}

/// `h` snapped down to the nearest backfill-chunk (retarget-interval)
/// boundary at or below it.
fn snap(h: u32, network: Network) -> u32 {
    let chunk = backfill_chunk(network);
    h - h % chunk
}

/// Backfill floor: `min_height` (or the server tip when absent) snapped down
/// to a retarget boundary, then padded down by a full retarget interval so the
/// anchor lands on the previous retarget boundary. Every retarget boundary at
/// or above the snapped boundary then has a complete ancestor window for its
/// difficulty check. The anchor itself is stored PoW-only (`append_anchor`),
/// so its own retarget is skipped; the handful of headers just above the
/// anchor keep the anchor-relative MTP relaxation, but they all sit below the
/// account's `min_height` and are never account relevant. Saturates at zero
/// near genesis.
fn backfill_floor(min_height: Option<u32>, tip_h: u32, network: Network) -> u32 {
    let snapped = snap(min_height.unwrap_or(tip_h), network);
    snapped.saturating_sub(backfill_chunk(network))
}

/// True when the stored range cannot be contiguously extended down to `low`
/// (the wanted floor is below the stored floor, after a lowered birthday)
/// or up to it (a gap separates the stored tip from `low`).
fn needs_reanchor(min_stored: Option<u32>, stored_tip: Option<u32>, low: u32) -> bool {
    match (min_stored, stored_tip) {
        (Some(min), Some(tip)) => low < min || tip.saturating_add(1) < low,
        _ => false,
    }
}

const REORG_WALK_CHUNK: u32 = 20;
#[cfg(not(test))]
const RECV_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const RECV_TIMEOUT: Duration = Duration::from_millis(200);
const INITIAL_SYNC_RETRY_DELAY: Duration = Duration::from_millis(300);
/// Upper bound on the deferred tip/notif queue. A chatty (or malicious)
/// server could otherwise flood notifications during a `GetHeaders`
/// round-trip and grow this queue without limit.
const MAX_DEFERRED: usize = 4096;

/// Push a parked tip/notif onto the bounded deferred queue, dropping the
/// incoming item (and logging) on overflow. Dropping the oldest instead
/// would leave the surviving queue non-contiguous, sending every survivor
/// through the reorg path; a dropped newer tip is simply re-announced by
/// the subscription on the next block.
fn push_deferred(
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
    item: (u32, [u8; Header::SIZE]),
) {
    if deferred.len() >= MAX_DEFERRED {
        log::warn!("HeaderStore: deferred notif queue full ({MAX_DEFERRED}); dropping incoming");
        return;
    }
    deferred.push_back(item);
}

/// True when the store is gone, `stop` was called, or `restart` bumped the
/// writer token past `token`, signalling this worker to exit.
fn is_stale(weak: &Weak<HeaderStore>, token: u64) -> bool {
    match weak.upgrade() {
        Some(store) => {
            store.stopped.load(Ordering::SeqCst)
                || store.writer_token.load(Ordering::SeqCst) != token
        }
        None => true,
    }
}

/// Park a freshly spawned worker until replay validation settles, so its
/// appends cannot race the replay thread's wipe-on-invalid. Returns false
/// when the worker should exit (store gone, stopped, or superseded).
fn wait_for_replay(weak: &Weak<HeaderStore>, token: u64) -> bool {
    loop {
        let store = match weak.upgrade() {
            Some(s) => s,
            None => return false,
        };
        if store.stopped.load(Ordering::SeqCst)
            || store.writer_token.load(Ordering::SeqCst) != token
        {
            return false;
        }
        if !matches!(store.validation_state(), HeaderValidationState::Validating) {
            return true;
        }
        drop(store);
        thread::sleep(Duration::from_millis(20));
    }
}

fn run_worker(
    weak: Weak<HeaderStore>,
    network: Network,
    min_height: Option<u32>,
    token: u64,
    req_tx: mpsc::Sender<HeaderRequest>,
    resp_rx: mpsc::Receiver<HeaderResponse>,
) {
    log::debug!("HeaderStore::run_worker: starting");

    // A failed replay wipes the whole store; appending before it settles
    // would let that wipe erase freshly synced rows.
    if !wait_for_replay(&weak, token) {
        return;
    }

    if req_tx.send(HeaderRequest::Subscribe).is_err() {
        log::warn!("HeaderStore::run_worker: failed to send Subscribe (worker exiting)");
        return;
    }

    // Wait for the initial Tip and run initial sync.
    let server_tip = loop {
        let resp = match resp_rx.recv() {
            Ok(r) => r,
            Err(_) => {
                log::warn!("HeaderStore::run_worker: response channel closed before Tip");
                return;
            }
        };
        if is_stale(&weak, token) {
            return;
        }
        match resp {
            HeaderResponse::Tip { height, raw } => break (height, raw),
            HeaderResponse::Stopped => return,
            HeaderResponse::Error(e) => {
                log::warn!("HeaderStore::run_worker: pre-Tip error: {e}");
            }
            other => {
                log::debug!("HeaderStore::run_worker: ignoring pre-Tip response: {other:?}");
            }
        }
    };

    // Notifications received while a fetch is outstanding are parked
    // here and processed by the steady-state loop after each fetch.
    let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

    match weak.upgrade() {
        Some(store)
            if !store.stopped.load(Ordering::SeqCst)
                && store.writer_token.load(Ordering::SeqCst) == token =>
        {
            if !initial_sync(
                &store,
                network,
                min_height,
                token,
                server_tip,
                &req_tx,
                &resp_rx,
                &mut deferred,
            ) {
                return;
            }
            // Apply the tip header itself if it isn't already part of the
            // backfilled range (initial_sync may have stopped before tip).
            let (tip_h, tip_raw) = server_tip;
            if store.tip().map(|t| t < tip_h).unwrap_or(true) {
                apply_one(
                    &store,
                    token,
                    tip_h,
                    tip_raw,
                    &req_tx,
                    &resp_rx,
                    &mut deferred,
                );
            }
        }
        _ => return,
    }

    // Steady-state loop: prefer deferred queue, then block on `resp_rx`.
    // `recv_timeout` doubles as a periodic wake so a worker superseded by
    // `restart` self-exits even on a silent dead socket.
    loop {
        // Drain any deferred notifications first.
        while let Some((h, raw)) = deferred.pop_front() {
            if is_stale(&weak, token) {
                return;
            }
            let store = match weak.upgrade() {
                Some(s) => s,
                None => return,
            };
            apply_one(&store, token, h, raw, &req_tx, &resp_rx, &mut deferred);
        }

        let resp = match resp_rx.recv_timeout(RECV_TIMEOUT) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if is_stale(&weak, token) {
                    return;
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                log::debug!("HeaderStore::run_worker: response channel closed; exiting");
                return;
            }
        };
        if is_stale(&weak, token) {
            return;
        }
        let store = match weak.upgrade() {
            Some(s) => s,
            None => return,
        };
        match resp {
            HeaderResponse::Tip { height, raw } | HeaderResponse::Header { height, raw } => {
                apply_one(&store, token, height, raw, &req_tx, &resp_rx, &mut deferred);
            }
            HeaderResponse::Batch { start, raws } => {
                for (i, raw) in raws.into_iter().enumerate() {
                    apply_one(
                        &store,
                        token,
                        start + i as u32,
                        raw,
                        &req_tx,
                        &resp_rx,
                        &mut deferred,
                    );
                }
            }
            HeaderResponse::Stopped => return,
            HeaderResponse::Error(e) => {
                log::warn!("HeaderStore::run_worker: server error: {e}");
            }
        }
    }
}

/// Fetch the server's height-0 header and verify it matches `expected`.
/// Returns the raw genesis bytes on success. On a hash/decode mismatch the
/// store is wiped (an inconsistent cache must not survive); on no response
/// the store is left untouched since it may simply be a transient hiccup.
fn fetch_and_verify_genesis(
    store: &Arc<HeaderStore>,
    token: u64,
    expected: BlockHash,
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> Option<[u8; Header::SIZE]> {
    match request_initial_headers(store, token, req_tx, resp_rx, 0, 1, deferred) {
        Some(raws) => match deserialize::<Header>(&raws[0]) {
            Ok(hdr) if hdr.block_hash() == expected => Some(raws[0]),
            Ok(hdr) => {
                log::warn!(
                    "HeaderStore::initial_sync: server genesis {} != expected {}",
                    hdr.block_hash(),
                    expected
                );
                store.wipe(token);
                None
            }
            Err(e) => {
                log::warn!("HeaderStore::initial_sync: decode genesis: {e}");
                store.wipe(token);
                None
            }
        },
        _ => {
            log::warn!("HeaderStore::initial_sync: no response for genesis fetch");
            None
        }
    }
}

/// Genesis pin + retarget-boundary-snapped backfill up to `server_tip.0 - 1`.
///
/// Returns `false` on unrecoverable error (worker should exit).
#[allow(clippy::too_many_arguments)]
fn initial_sync(
    store: &Arc<HeaderStore>,
    network: Network,
    min_height: Option<u32>,
    token: u64,
    server_tip: (u32, [u8; Header::SIZE]),
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> bool {
    let (tip_h, _) = server_tip;

    let low = backfill_floor(min_height, tip_h, network);

    // A persisted range that cannot extend down to the wanted floor (lowered
    // birthday) or up from its tip to it (floor above the stored tip) is
    // wiped so the first-boot anchor logic below re-anchors at `low`;
    // headers are a refetchable cache.
    if needs_reanchor(store.min_height(), store.tip(), low) {
        log::warn!(
            "HeaderStore::initial_sync: stored range cannot reach floor {low}; wiping and re-anchoring"
        );
        store.wipe(token);
    }

    // Genesis handling (non-regtest only).
    if let Some(expected) = expected_genesis(network) {
        if low == 0 && store.header(0).is_none() {
            // Full sync: pin and store genesis as the chain's first row.
            let raw =
                match fetch_and_verify_genesis(store, token, expected, req_tx, resp_rx, deferred) {
                    Some(raw) => raw,
                    None => return false,
                };
            if let Err(e) = store.append(token, 0, raw) {
                log::warn!("HeaderStore::initial_sync: append genesis failed: {e:?}");
                store.wipe(token);
                return false;
            }
        } else if low > 0 && store.tip().is_none() {
            // Sparse start: verify the server genesis matches but do not
            // store it, so the cache stays contiguous from `low`.
            if fetch_and_verify_genesis(store, token, expected, req_tx, resp_rx, deferred).is_none()
            {
                return false;
            }
        }
    }

    let mut start = store
        .tip()
        .map(|t| t.saturating_add(1))
        .unwrap_or(low)
        .max(low);
    let progress_end = tip_h.saturating_sub(1);
    let mut progress_started = false;
    if start < tip_h {
        progress_started = true;
        store.publish_progress(HeaderProgressEvent::Started {
            phase: HeaderProgressPhase::InitialSync,
            start,
            end: progress_end,
        });
    }

    while start < tip_h {
        let remaining = tip_h - start;
        let count = remaining.min(backfill_chunk(network));
        let raws =
            match request_initial_headers(store, token, req_tx, resp_rx, start, count, deferred) {
                Some(r) => r,
                None => {
                    log::warn!("HeaderStore::initial_sync: no response at start={start}");
                    store.publish_progress(HeaderProgressEvent::Failed {
                        phase: HeaderProgressPhase::InitialSync,
                    });
                    return false;
                }
            };
        if let Err(e) = store.append_batch(token, start, &raws) {
            log::warn!("HeaderStore::initial_sync: append batch at {start}: {e:?}");
            store.publish_progress(HeaderProgressEvent::Failed {
                phase: HeaderProgressPhase::InitialSync,
            });
            return false;
        }
        start += raws.len() as u32;
        store.publish_progress(HeaderProgressEvent::Progress {
            phase: HeaderProgressPhase::InitialSync,
            current: start.saturating_sub(1),
            end: progress_end,
        });
    }
    if progress_started {
        store.publish_progress(HeaderProgressEvent::Completed {
            phase: HeaderProgressPhase::InitialSync,
        });
    }

    true
}

/// Apply a single incoming header at height `h`. Fast-path on contiguous
/// append; otherwise enter reorg resolution.
fn apply_one(
    store: &Arc<HeaderStore>,
    token: u64,
    h: u32,
    raw: [u8; Header::SIZE],
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) {
    let header: Header = match deserialize(&raw) {
        Ok(hdr) => hdr,
        Err(e) => {
            log::warn!("HeaderStore::apply_one: decode {h}: {e}");
            return;
        }
    };

    // Fast path: contiguous append against current tip, or fresh-start
    // append at the snapped low boundary. Read tip height + hash under a
    // single lock so they cannot disagree across a concurrent mutation.
    let contiguous = match store.tip_with_hash() {
        Some((t, tip_hash)) => h == t + 1 && header.prev_blockhash == tip_hash,
        None => true,
    };
    if contiguous {
        if let Err(e) = store.append(token, h, raw) {
            log::warn!("HeaderStore::apply_one: append {h}: {e:?}; falling back to reorg path");
            resolve_reorg(store, token, h, raw, req_tx, resp_rx, deferred);
        }
        return;
    }

    // A header that fails its own PoW must never cost a walk-back + cache
    // wipe, so gate the reorg path on a cheap PoW check first.
    if let Err(e) = header_validator::check_pow(&Params::new(store.network), &header) {
        log::warn!("HeaderStore::apply_one: PoW check failed for {h}: {e}; dropping header");
        return;
    }

    // Above the tip but not contiguous, or below the tip: treat as reorg.
    resolve_reorg(store, token, h, raw, req_tx, resp_rx, deferred);
}

/// Walk back from `incoming_h - 1` in `REORG_WALK_CHUNK`-sized batches,
/// filling `buffer` as it goes, until a stored height's hash matches the
/// server's. Returns the matching (fork) height.
///
/// Returns `None` if a fetch failed, or if the walk exhausted the stored
/// range without a match; the latter case wipes and re-syncs the store from
/// scratch instead of leaving it dormant.
#[allow(clippy::too_many_arguments)]
fn find_fork_point(
    store: &Arc<HeaderStore>,
    token: u64,
    incoming_h: u32,
    incoming_raw: [u8; Header::SIZE],
    min_stored: u32,
    buffer: &mut BTreeMap<u32, [u8; Header::SIZE]>,
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> Option<u32> {
    let mut walk_h = incoming_h - 1;

    loop {
        let chunk_start = walk_h.saturating_sub(REORG_WALK_CHUNK - 1).max(min_stored);
        let count = walk_h - chunk_start + 1;
        let raws = match request_headers(req_tx, resp_rx, chunk_start, count, deferred) {
            Some(r) if !r.is_empty() => r,
            _ => {
                log::warn!("HeaderStore::resolve_reorg: no headers for walk_h={walk_h}");
                return None;
            }
        };

        // Scan top-down within the chunk for the first matching height.
        let mut fork_h = None;
        for i in (0..raws.len()).rev() {
            let wh = chunk_start + i as u32;
            buffer.insert(wh, raws[i]);
            let server_hash = match deserialize::<Header>(&raws[i]) {
                Ok(hdr) => hdr.block_hash(),
                Err(e) => {
                    log::warn!("HeaderStore::resolve_reorg: decode walk {wh}: {e}");
                    return None;
                }
            };
            if store.block_hash(wh) == Some(server_hash) {
                fork_h = Some(wh);
                break;
            }
        }

        if let Some(fork_h) = fork_h {
            return Some(fork_h);
        }

        if chunk_start <= min_stored {
            log::warn!(
                "HeaderStore::resolve_reorg: walked below min stored {min_stored} without match; wiping and re-syncing"
            );
            store.wipe(token);
            // Re-anchor from scratch so the worker self-heals instead of
            // staying dormant until the next restart. Reuse the backfill
            // floor remembered at start.
            let min_height = store.remembered_min_height();
            if initial_sync(
                store,
                store.network,
                min_height,
                token,
                (incoming_h, incoming_raw),
                req_tx,
                resp_rx,
                deferred,
            ) {
                apply_one(
                    store,
                    token,
                    incoming_h,
                    incoming_raw,
                    req_tx,
                    resp_rx,
                    deferred,
                );
            }
            return None;
        }
        walk_h = chunk_start - 1;
    }
}

/// Re-fetch any heights in `(fork_h, incoming_h]` missing from `buffer`.
/// Most are already there from `find_fork_point`'s walk-back; this fills any
/// gaps it didn't cover. Returns `false` on a fetch failure.
fn fetch_branch(
    network: Network,
    fork_h: u32,
    incoming_h: u32,
    buffer: &mut BTreeMap<u32, [u8; Header::SIZE]>,
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> bool {
    let mut h = fork_h + 1;
    while h <= incoming_h {
        if buffer.contains_key(&h) {
            h += 1;
            continue;
        }
        let need = incoming_h - h + 1;
        let count = need.min(backfill_chunk(network));
        let raws = match request_headers(req_tx, resp_rx, h, count, deferred) {
            Some(r) if !r.is_empty() => r,
            _ => {
                log::warn!("HeaderStore::resolve_reorg: no headers for refetch h={h}");
                return false;
            }
        };
        for (i, raw) in raws.iter().enumerate() {
            buffer.insert(h + i as u32, *raw);
        }
        h += raws.len() as u32;
    }
    true
}

/// Walk back to the fork point and switch only to a strictly stronger branch.
fn resolve_reorg(
    store: &Arc<HeaderStore>,
    token: u64,
    incoming_h: u32,
    incoming_raw: [u8; Header::SIZE],
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) {
    log::debug!("HeaderStore::resolve_reorg at h={incoming_h}");

    // Buffer of fetched headers indexed by height. Used to avoid re-fetching
    // the new branch after we find the fork point.
    let mut buffer: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
    buffer.insert(incoming_h, incoming_raw);

    let min_stored = match store.min_height() {
        Some(m) => m,
        None => {
            // Empty store: there is nothing to reconcile against, so we
            // must not blindly anchor on an unverifiable header. On a
            // network with a pinned genesis, only a height-0 header
            // (validated against the genesis pin by `append`) may bootstrap
            // an empty store here; any higher height must be brought in by
            // the genesis-pinned `initial_sync` backfill instead, where
            // linkage back to a 2016 boundary can be established.
            if incoming_h != 0 && expected_genesis(store.network).is_some() {
                log::warn!(
                    "HeaderStore::resolve_reorg: refusing to anchor empty store on unverifiable h={incoming_h}; deferring to initial_sync"
                );
                return;
            }
            if let Err(e) = store.append(token, incoming_h, incoming_raw) {
                log::warn!("HeaderStore::resolve_reorg: empty-store append {incoming_h}: {e:?}");
            }
            return;
        }
    };

    if incoming_h == 0 {
        log::warn!("HeaderStore::resolve_reorg: incoming h=0 cannot reorg");
        return;
    }

    if incoming_h <= min_stored {
        log::warn!("HeaderStore::resolve_reorg: incoming h={incoming_h} <= min_stored {min_stored}; cannot reconcile below floor");
        return;
    }

    let fork_h = match find_fork_point(
        store,
        token,
        incoming_h,
        incoming_raw,
        min_stored,
        &mut buffer,
        req_tx,
        resp_rx,
        deferred,
    ) {
        Some(fork_h) => fork_h,
        None => return,
    };

    if !fetch_branch(
        store.network,
        fork_h,
        incoming_h,
        &mut buffer,
        req_tx,
        resp_rx,
        deferred,
    ) {
        return;
    }

    let active = match store.raw_map() {
        Ok(active) => active,
        Err(e) => {
            log::error!("HeaderStore::resolve_reorg: failed to read active chain: {e}");
            return;
        }
    };
    let branch = match HeaderBranch::validate(store.network, &active, fork_h, incoming_h, &buffer) {
        Ok(branch) => branch,
        Err(e) => {
            log::warn!("HeaderStore::resolve_reorg: candidate branch failed validation: {e:?}");
            return;
        }
    };
    match branch.has_more_work_than_active(&active, fork_h) {
        Ok(true) => {}
        Ok(false) => {
            log::debug!(
                "HeaderStore::resolve_reorg: rejecting candidate at h={incoming_h}; work is not greater than active suffix"
            );
            return;
        }
        Err(e) => {
            log::warn!("HeaderStore::resolve_reorg: cannot compare work, active suffix has a malformed header: {e:?}");
            return;
        }
    }
    if let Err(e) = store.replace_branch(token, fork_h, &branch.headers) {
        log::warn!("HeaderStore::resolve_reorg: replace_branch at fork_h={fork_h}: {e:?}");
    }
}

enum RequestHeadersOutcome {
    Batch(Vec<[u8; Header::SIZE]>),
    Failed,
    Timeout,
    Cancelled,
}

fn receive_headers(
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    start: u32,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> RequestHeadersOutcome {
    loop {
        let resp = match resp_rx.recv_timeout(RECV_TIMEOUT) {
            Ok(resp) => resp,
            Err(mpsc::RecvTimeoutError::Timeout) => return RequestHeadersOutcome::Timeout,
            Err(mpsc::RecvTimeoutError::Disconnected) => return RequestHeadersOutcome::Cancelled,
        };
        match resp {
            HeaderResponse::Batch { start: s, raws } if s == start => {
                return RequestHeadersOutcome::Batch(raws)
            }
            HeaderResponse::Batch { start: s, raws } => {
                log::debug!(
                    "HeaderStore::request_headers: ignoring unrelated batch start={s} len={}",
                    raws.len()
                );
            }
            HeaderResponse::Tip { height, raw } | HeaderResponse::Header { height, raw } => {
                // Park tip/notif arriving mid-fetch onto the deferred
                // queue so the steady-state loop processes them after
                // the current fetch completes.
                push_deferred(deferred, (height, raw));
            }
            HeaderResponse::Error(HeaderError::GetHeaders { start: s, error }) if s == start => {
                // Tagged for this call's own request: fail promptly instead
                // of stalling until `RECV_TIMEOUT` for an answer that will
                // never arrive.
                log::warn!(
                    "HeaderStore::request_headers: get_headers at start={start} failed: {error}"
                );
                return RequestHeadersOutcome::Failed;
            }
            HeaderResponse::Error(HeaderError::GetHeadersDecode { start: s, source })
                if s == start =>
            {
                log::warn!(
                    "HeaderStore::request_headers: decode get_headers at start={start}: {source}"
                );
                return RequestHeadersOutcome::Failed;
            }
            HeaderResponse::Error(e) => {
                log::warn!("HeaderStore::request_headers: server error: {e}");
            }
            HeaderResponse::Stopped => return RequestHeadersOutcome::Cancelled,
        }
    }
}

/// Send a `GetHeaders` request and block-recv until the matching `Batch`
/// arrives. Returns `None` if the request fails, times out, or is cancelled.
fn request_headers(
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    start: u32,
    count: u32,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> Option<Vec<[u8; Header::SIZE]>> {
    req_tx
        .send(HeaderRequest::GetHeaders { start, count })
        .ok()?;
    match receive_headers(resp_rx, start, deferred) {
        RequestHeadersOutcome::Batch(raws) => Some(raws),
        _ => None,
    }
}

fn request_initial_headers(
    store: &Arc<HeaderStore>,
    token: u64,
    req_tx: &mpsc::Sender<HeaderRequest>,
    resp_rx: &mpsc::Receiver<HeaderResponse>,
    start: u32,
    count: u32,
    deferred: &mut VecDeque<(u32, [u8; Header::SIZE])>,
) -> Option<Vec<[u8; Header::SIZE]>> {
    let mut send = true;
    loop {
        if store.stopped.load(Ordering::SeqCst)
            || store.writer_token.load(Ordering::SeqCst) != token
        {
            return None;
        }
        if send {
            req_tx
                .send(HeaderRequest::GetHeaders { start, count })
                .ok()?;
            send = false;
        }

        let outcome = receive_headers(resp_rx, start, deferred);
        if store.stopped.load(Ordering::SeqCst)
            || store.writer_token.load(Ordering::SeqCst) != token
        {
            return None;
        }
        let retry = match outcome {
            RequestHeadersOutcome::Batch(raws) if raws.is_empty() => {
                log::warn!("HeaderStore::initial_sync: empty batch at start={start}; retrying");
                true
            }
            RequestHeadersOutcome::Batch(raws) => return Some(raws),
            RequestHeadersOutcome::Failed => true,
            RequestHeadersOutcome::Timeout => false,
            RequestHeadersOutcome::Cancelled => return None,
        };
        if retry {
            thread::sleep(INITIAL_SYNC_RETRY_DELAY);
            send = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::response::{ErrorResponse, ErrorResult};
    use miniscript::bitcoin::{
        block::{Header, Version},
        consensus::serialize,
        constants::genesis_block,
        hashes::Hash,
        params::Params,
        BlockHash, CompactTarget, TxMerkleNode,
    };
    use std::fs;
    use temp_dir::TempDir;

    fn raw_header(h: &Header) -> [u8; Header::SIZE] {
        let bytes = serialize(h);
        let mut arr = [0u8; Header::SIZE];
        arr.copy_from_slice(&bytes);
        arr
    }

    fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cond()
    }

    fn mine_regtest_header(mut h: Header) -> Header {
        let params = Params::new(Network::Regtest);
        let target = h.target().min(params.max_attainable_target);
        while h.validate_pow(target).is_err() {
            h.nonce = h.nonce.wrapping_add(1);
        }
        h
    }

    /// Encode a contiguous (height -> raw) map into the binary cache format.
    fn write_binary(path: &std::path::Path, map: &BTreeMap<u32, [u8; Header::SIZE]>) {
        write_to_disk(path, map);
    }

    fn build_chain(len: u32) -> Vec<Header> {
        // Build a chain on Regtest (no PoW retargeting, MTP skipped).
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut chain = Vec::with_capacity(len as usize);
        let mut prev = BlockHash::all_zeros();
        for i in 0..len {
            let h = mine_regtest_header(Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([(i as u8); 32]),
                time: 1_700_000_000 + i,
                bits,
                nonce: i,
            });
            prev = h.block_hash();
            chain.push(h);
        }
        chain
    }

    fn build_branch(prev: Header, start_height: u32, len: u32, marker: u8) -> Vec<Header> {
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut chain = Vec::with_capacity(len as usize);
        let mut prev_hash = prev.block_hash();
        for i in 0..len {
            let h = mine_regtest_header(Header {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::from_byte_array([marker.wrapping_add(i as u8); 32]),
                time: 1_700_010_000 + start_height + i,
                bits,
                nonce: i,
            });
            prev_hash = h.block_hash();
            chain.push(h);
        }
        chain
    }

    fn store_with_chain(chain: &[Header]) -> Arc<HeaderStore> {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        for (i, h) in chain.iter().enumerate() {
            store.insert_unchecked(i as u32, raw_header(h));
        }
        store
    }

    fn recv_get_headers(rx: &mpsc::Receiver<HeaderRequest>, start: u32, count: u32) {
        match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            HeaderRequest::GetHeaders {
                start: request_start,
                count: request_count,
            } => {
                assert_eq!(request_start, start);
                assert_eq!(request_count, count);
            }
            other => panic!("expected GetHeaders, got {other:?}"),
        }
    }

    #[test]
    fn resolve_reorg_below_floor_does_not_panic() {
        // Build a store whose lowest stored height is > 0 (a floor), then
        // drive `resolve_reorg` with an incoming height at/below that floor.
        // This used to underflow (`walk_h - chunk_start`) and panic; the
        // floor guard must now make it return early without panicking.
        let chain = build_chain(20);
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let floor = 10u32;
        for (i, h) in chain.iter().enumerate().skip(floor as usize) {
            store.insert_unchecked(i as u32, raw_header(h));
        }
        assert_eq!(store.min_height(), Some(floor));

        // Dummy channels: the guard returns before any request is sent.
        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (_resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        // incoming_h == min_stored (boundary) and incoming_h < min_stored.
        for incoming_h in [floor, floor - 1, 1] {
            let raw = raw_header(&chain[incoming_h as usize]);
            resolve_reorg(&store, 0, incoming_h, raw, &req_tx, &resp_rx, &mut deferred);
        }
        // Store unchanged; reached here without panicking.
        assert_eq!(store.min_height(), Some(floor));
    }

    #[test]
    fn pow_invalid_non_contiguous_header_does_not_wipe() {
        // A non-connecting header that fails its own PoW must be dropped
        // before any walk-back: tip and floor unchanged, no resync request.
        let chain = build_chain(20);
        let store = store_with_chain(&chain);
        let tip_before = store.tip();
        let min_before = store.min_height();

        // Non-contiguous height, well above tip+1, advertising a target so
        // small its hash cannot meet it (unmined), so `check_pow` rejects it.
        let bad = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0xAB; 32]),
            time: 1_700_000_500,
            bits: CompactTarget::from_consensus(0x03000001),
            nonce: 0,
        };
        let raw = raw_header(&bad);

        // Dummy channels: the PoW guard must return before any request.
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (_resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        apply_one(&store, 0, 100, raw, &req_tx, &resp_rx, &mut deferred);

        assert_eq!(store.tip(), tip_before);
        assert_eq!(store.min_height(), min_before);
        assert!(req_rx.try_recv().is_err());
    }

    #[test]
    fn needs_reanchor_detects_lowered_floor_and_gap() {
        // Lowered floor: wanted low below the stored floor.
        assert!(needs_reanchor(Some(4032), Some(4035), 0));
        // Gap: stored tip cannot extend contiguously up to low.
        assert!(needs_reanchor(Some(0), Some(3), 2016));
        // Contiguous resume cases.
        assert!(!needs_reanchor(Some(0), Some(3), 0));
        assert!(!needs_reanchor(Some(2016), Some(4031), 2016));
        assert!(!needs_reanchor(Some(0), Some(3), 4));
        // Empty store: first-boot anchor logic handles it, no wipe needed.
        assert!(!needs_reanchor(None, None, 2016));
    }

    #[test]
    fn worker_waits_for_replay_validation() {
        let chain = build_chain(3);
        let store = store_with_chain(&chain);
        store.set_validation_state_for_test(HeaderValidationState::Validating);

        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let weak = Arc::downgrade(&store);
        let worker =
            thread::spawn(move || run_worker(weak, Network::Regtest, None, 0, req_tx, resp_rx));

        // Parked: no Subscribe while replay validation is pending.
        assert!(req_rx.recv_timeout(Duration::from_millis(200)).is_err());

        store.set_validation_state_for_test(HeaderValidationState::Valid);
        assert!(matches!(
            req_rx.recv_timeout(Duration::from_secs(5)),
            Ok(HeaderRequest::Subscribe)
        ));

        // Closing the response channel makes the worker exit.
        drop(resp_tx);
        worker.join().unwrap();
    }

    #[test]
    fn worker_self_exits_when_stopped() {
        // `stop` sets the flag before the worker even subscribes: it must
        // exit at the first check (in `wait_for_replay`) and touch nothing.
        let chain = build_chain(3);
        let store = store_with_chain(&chain);
        store.set_validation_state_for_test(HeaderValidationState::Valid);
        let tip_before = store.tip();
        store.stopped.store(true, Ordering::SeqCst);

        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (_resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let token = store.writer_token.load(Ordering::SeqCst);
        let weak = Arc::downgrade(&store);
        let worker =
            thread::spawn(move || run_worker(weak, Network::Regtest, None, token, req_tx, resp_rx));

        worker.join().unwrap();
        assert!(
            req_rx.try_recv().is_err(),
            "stopped worker must not subscribe"
        );
        assert_eq!(store.tip(), tip_before, "stopped worker must not write");
    }

    #[test]
    fn worker_self_exits_when_token_superseded() {
        // A `restart` bumps the writer token; a worker still parked under the
        // old token must self-exit rather than ever subscribe or write.
        let store = HeaderStore::new_in_memory(Network::Regtest);
        store.set_validation_state_for_test(HeaderValidationState::Validating);

        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (_resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let weak = Arc::downgrade(&store);
        // Spawned under token 0.
        let worker =
            thread::spawn(move || run_worker(weak, Network::Regtest, None, 0, req_tx, resp_rx));

        // Supersede it (as `restart` does) while it is parked on Validating.
        store.writer_token.fetch_add(1, Ordering::SeqCst);
        assert!(wait_until(Duration::from_secs(5), || {
            worker.is_finished()
        }));
        worker.join().unwrap();
        assert!(
            req_rx.try_recv().is_err(),
            "superseded worker must not subscribe"
        );
    }

    #[test]
    fn push_deferred_drops_incoming_on_overflow() {
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();
        let raw = [0u8; Header::SIZE];
        for h in 0..MAX_DEFERRED as u32 {
            push_deferred(&mut deferred, (h, raw));
        }
        assert_eq!(deferred.len(), MAX_DEFERRED);

        // At capacity the incoming item is dropped, not enqueued, and the
        // existing queue is left untouched (front and back unchanged).
        push_deferred(&mut deferred, (99_999, raw));
        assert_eq!(deferred.len(), MAX_DEFERRED);
        assert_eq!(deferred.front().map(|(h, _)| *h), Some(0));
        assert_eq!(
            deferred.back().map(|(h, _)| *h),
            Some(MAX_DEFERRED as u32 - 1)
        );
    }

    #[test]
    fn initial_headers_retries_error_then_accepts_batch() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let raw = [1u8; Header::SIZE];
        let responder = thread::spawn(move || {
            recv_get_headers(&req_rx, 10, 20);
            resp_tx
                .send(HeaderResponse::Error(HeaderError::GetHeaders {
                    start: 10,
                    error: ErrorResponse {
                        id: 1,
                        error: ErrorResult {
                            code: 1,
                            message: "temporary".to_string(),
                        },
                    },
                }))
                .unwrap();
            recv_get_headers(&req_rx, 10, 20);
            resp_tx
                .send(HeaderResponse::Batch {
                    start: 10,
                    raws: vec![raw],
                })
                .unwrap();
        });
        let mut deferred = VecDeque::new();

        assert_eq!(
            request_initial_headers(&store, 0, &req_tx, &resp_rx, 10, 20, &mut deferred),
            Some(vec![raw])
        );
        responder.join().unwrap();
    }

    #[test]
    fn initial_headers_retries_empty_then_accepts_batch() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let raw = [2u8; Header::SIZE];
        let responder = thread::spawn(move || {
            recv_get_headers(&req_rx, 30, 40);
            resp_tx
                .send(HeaderResponse::Batch {
                    start: 30,
                    raws: Vec::new(),
                })
                .unwrap();
            recv_get_headers(&req_rx, 30, 40);
            resp_tx
                .send(HeaderResponse::Batch {
                    start: 30,
                    raws: vec![raw],
                })
                .unwrap();
        });
        let mut deferred = VecDeque::new();

        assert_eq!(
            request_initial_headers(&store, 0, &req_tx, &resp_rx, 30, 40, &mut deferred),
            Some(vec![raw])
        );
        responder.join().unwrap();
    }

    #[test]
    fn initial_headers_retries_decode_error_then_accepts_batch() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let raw = [3u8; Header::SIZE];
        let responder = thread::spawn(move || {
            recv_get_headers(&req_rx, 70, 80);
            resp_tx
                .send(HeaderResponse::Error(HeaderError::GetHeadersDecode {
                    start: 70,
                    source: crate::client::DecodeError::HeadersAlignment(1),
                }))
                .unwrap();
            recv_get_headers(&req_rx, 70, 80);
            resp_tx
                .send(HeaderResponse::Batch {
                    start: 70,
                    raws: vec![raw],
                })
                .unwrap();
        });
        let mut deferred = VecDeque::new();

        assert_eq!(
            request_initial_headers(&store, 0, &req_tx, &resp_rx, 70, 80, &mut deferred),
            Some(vec![raw])
        );
        responder.join().unwrap();
    }

    #[test]
    fn initial_headers_timeout_waits_for_original_request() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let raw = [4u8; Header::SIZE];
        let responder = thread::spawn(move || {
            recv_get_headers(&req_rx, 90, 100);
            thread::sleep(RECV_TIMEOUT + Duration::from_millis(50));
            assert!(req_rx.try_recv().is_err());
            resp_tx
                .send(HeaderResponse::Batch {
                    start: 90,
                    raws: vec![raw],
                })
                .unwrap();
        });
        let mut deferred = VecDeque::new();

        assert_eq!(
            request_initial_headers(&store, 0, &req_tx, &resp_rx, 90, 100, &mut deferred),
            Some(vec![raw])
        );
        responder.join().unwrap();
    }

    #[test]
    fn initial_headers_stops_on_cancellation() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        let responder = thread::spawn(move || {
            recv_get_headers(&req_rx, 50, 60);
            resp_tx.send(HeaderResponse::Stopped).unwrap();
            assert!(req_rx.recv_timeout(Duration::from_millis(100)).is_err());
        });
        let mut deferred = VecDeque::new();

        assert_eq!(
            request_initial_headers(&store, 0, &req_tx, &resp_rx, 50, 60, &mut deferred),
            None
        );
        responder.join().unwrap();
    }

    #[test]
    fn initial_sync_reanchors_below_stored_floor() {
        // Persisted rows at 4032..=4035, but the wanted floor drops to 0
        // (no min_height, low server tip): the stale range must be wiped
        // and the sync re-anchored at 0.
        let chain = build_chain(11);
        let store = HeaderStore::new_in_memory(Network::Regtest);
        for (i, h) in chain.iter().enumerate().take(4) {
            store.insert_unchecked(4032 + i as u32, raw_header(h));
        }
        assert_eq!(store.min_height(), Some(4032));

        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        resp_tx
            .send(HeaderResponse::Batch {
                start: 0,
                raws: chain[0..10].iter().map(raw_header).collect(),
            })
            .unwrap();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        let ok = initial_sync(
            &store,
            Network::Regtest,
            None,
            0,
            (10, raw_header(&chain[10])),
            &req_tx,
            &resp_rx,
            &mut deferred,
        );

        assert!(ok);
        assert_eq!(store.min_height(), Some(0));
        assert_eq!(store.tip(), Some(9));
        assert_eq!(store.block_hash(0), Some(chain[0].block_hash()));
        assert!(store.block_hash(4032).is_none(), "stale rows must be wiped");
    }

    #[test]
    fn initial_sync_reanchors_over_gap() {
        // Persisted rows at 0..=3, but min_height jumped to 4040 (floor
        // 2016): the gap cannot be extended contiguously, so the store is
        // wiped and a sparse anchor lands at 2016 via `append_anchor`.
        let old = build_chain(4);
        let store = store_with_chain(&old);

        let fresh = build_chain(6);
        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        resp_tx
            .send(HeaderResponse::Batch {
                start: 2016,
                raws: fresh[0..5].iter().map(raw_header).collect(),
            })
            .unwrap();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        let ok = initial_sync(
            &store,
            Network::Regtest,
            Some(4040),
            0,
            (2021, raw_header(&fresh[5])),
            &req_tx,
            &resp_rx,
            &mut deferred,
        );

        assert!(ok);
        assert_eq!(store.min_height(), Some(2016), "sparse anchor at the floor");
        assert_eq!(store.tip(), Some(2020));
        assert_eq!(store.block_hash(2016), Some(fresh[0].block_hash()));
        assert!(store.block_hash(0).is_none(), "old rows must be wiped");
    }

    // The `chunk_start <= min_stored` wipe branch of `find_fork_point`: a
    // reorg with NO common ancestor at or above a sparse anchor must wipe
    // the store and re-anchor on the new chain instead of staying dormant.
    #[test]
    fn reorg_with_no_ancestor_above_sparse_anchor_wipes_and_reanchors() {
        let old = build_chain(11);
        let store = HeaderStore::new_in_memory(Network::Regtest);
        for (i, h) in old.iter().enumerate() {
            store.insert_unchecked(1000 + i as u32, raw_header(h));
        }
        assert_eq!(store.min_height(), Some(1000));

        // A fully disjoint chain (different seed header, so no height
        // matches the stored range anywhere).
        let seed = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0xAA; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let new_chain = build_branch(seed, 0, 1006, 0x40);

        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        // The fork walk from 1004 clamps to min_stored = 1000 and misses.
        resp_tx
            .send(HeaderResponse::Batch {
                start: 1000,
                raws: new_chain[1000..=1004].iter().map(raw_header).collect(),
            })
            .unwrap();
        // The post-wipe initial_sync backfill from 0 (regtest floor).
        resp_tx
            .send(HeaderResponse::Batch {
                start: 0,
                raws: new_chain[0..=1004].iter().map(raw_header).collect(),
            })
            .unwrap();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        resolve_reorg(
            &store,
            0,
            1005,
            raw_header(&new_chain[1005]),
            &req_tx,
            &resp_rx,
            &mut deferred,
        );

        assert_eq!(store.min_height(), Some(0), "store must re-anchor at 0");
        assert_eq!(store.tip(), Some(1005));
        assert_eq!(store.block_hash(1000), Some(new_chain[1000].block_hash()));
        assert_eq!(store.block_hash(1005), Some(new_chain[1005].block_hash()));
    }

    #[test]
    fn persisted_invalid_chain_is_wiped_by_replay_validation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.json");

        let mut chain = build_chain(4);
        chain[2].prev_blockhash = BlockHash::all_zeros();
        chain[2] = mine_regtest_header(chain[2]);
        {
            let store = HeaderStore::from_file(Network::Regtest, path.clone()).unwrap();
            for (i, h) in chain.iter().enumerate() {
                store.insert_unchecked(i as u32, raw_header(h));
            }
        }

        let reloaded = HeaderStore::from_file(Network::Regtest, path).unwrap();
        assert!(wait_until(Duration::from_secs(5), || {
            matches!(
                reloaded.validation_state(),
                HeaderValidationState::Invalid(_)
            )
        }));
        assert_eq!(reloaded.tip(), None);
    }

    #[test]
    fn from_store_wraps_typed_store() {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        let mut typed = RamStore::empty(backend, STORE_KEY, encode_height, encode_header);
        let chain = build_chain(2);
        typed.insert(0, raw_header(&chain[0])).unwrap();
        typed.insert(1, raw_header(&chain[1])).unwrap();

        let store = HeaderStore::from_store(Network::Regtest, typed);

        assert_eq!(store.tip(), Some(1));
        assert_eq!(store.block_hash(1), Some(chain[1].block_hash()));
    }

    #[test]
    fn candidate_branch_must_have_more_work() {
        let active_chain = build_chain(4);
        let active: BTreeMap<u32, [u8; Header::SIZE]> = active_chain
            .iter()
            .enumerate()
            .map(|(h, hdr)| (h as u32, raw_header(hdr)))
            .collect();
        let fork_h = 1;

        let stronger = build_branch(active_chain[fork_h as usize], 2, 4, 0x80);
        let stronger_buffer: BTreeMap<u32, [u8; Header::SIZE]> = stronger
            .iter()
            .enumerate()
            .map(|(i, hdr)| (fork_h + 1 + i as u32, raw_header(hdr)))
            .collect();
        let stronger =
            HeaderBranch::validate(Network::Regtest, &active, fork_h, 5, &stronger_buffer).unwrap();
        assert!(stronger.has_more_work_than_active(&active, fork_h).unwrap());

        let weaker = build_branch(active_chain[fork_h as usize], 2, 1, 0x90);
        let weaker_buffer: BTreeMap<u32, [u8; Header::SIZE]> = weaker
            .iter()
            .enumerate()
            .map(|(i, hdr)| (fork_h + 1 + i as u32, raw_header(hdr)))
            .collect();
        let weaker =
            HeaderBranch::validate(Network::Regtest, &active, fork_h, 2, &weaker_buffer).unwrap();
        assert!(!weaker.has_more_work_than_active(&active, fork_h).unwrap());
    }

    #[test]
    fn rejected_candidate_branch_does_not_mutate_active_or_notify() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let active_chain = build_chain(4);
        let store = HeaderStore::from_file(Network::Regtest, path.clone()).unwrap();
        for (i, header) in active_chain.iter().enumerate() {
            store.insert_unchecked(i as u32, raw_header(header));
        }
        let before = store.raw_map().expect("raw_map");
        // Read the raw file bytes rather than reopening a HeaderBackend: the
        // live store still holds the cache file's advisory lock, so a second
        // open would return AlreadyOpen.
        let persisted_before = fs::read(&path).unwrap();
        let rx = store.register_chain_tick();

        let fork_h = 1;
        let candidate = build_branch(active_chain[fork_h as usize], 2, 2, 0x80);
        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        resp_tx
            .send(HeaderResponse::Batch {
                start: 0,
                raws: vec![
                    raw_header(&active_chain[0]),
                    raw_header(&active_chain[1]),
                    raw_header(&candidate[0]),
                ],
            })
            .unwrap();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        resolve_reorg(
            &store,
            0,
            3,
            raw_header(&candidate[1]),
            &req_tx,
            &resp_rx,
            &mut deferred,
        );

        assert_eq!(store.raw_map().expect("raw_map"), before);
        assert_eq!(fs::read(&path).unwrap(), persisted_before);
        assert!(rx.try_recv().is_err(), "rejected branch notified listeners");
    }

    #[test]
    fn accepted_higher_work_candidate_replaces_branch_once() {
        let active_chain = build_chain(4);
        let store = store_with_chain(&active_chain);
        let rx = store.register_chain_tick();

        let fork_h = 1;
        let candidate = build_branch(active_chain[fork_h as usize], 2, 3, 0x90);
        let (req_tx, _req_rx) = mpsc::channel::<HeaderRequest>();
        let (resp_tx, resp_rx) = mpsc::channel::<HeaderResponse>();
        resp_tx
            .send(HeaderResponse::Batch {
                start: 0,
                raws: vec![
                    raw_header(&active_chain[0]),
                    raw_header(&active_chain[1]),
                    raw_header(&candidate[0]),
                    raw_header(&candidate[1]),
                ],
            })
            .unwrap();
        let mut deferred: VecDeque<(u32, [u8; Header::SIZE])> = VecDeque::new();

        resolve_reorg(
            &store,
            0,
            4,
            raw_header(&candidate[2]),
            &req_tx,
            &resp_rx,
            &mut deferred,
        );

        assert_eq!(store.tip(), Some(4));
        assert_eq!(store.block_hash(0), Some(active_chain[0].block_hash()));
        assert_eq!(store.block_hash(1), Some(active_chain[1].block_hash()));
        assert_eq!(store.block_hash(2), Some(candidate[0].block_hash()));
        assert_eq!(store.block_hash(3), Some(candidate[1].block_hash()));
        assert_eq!(store.block_hash(4), Some(candidate[2].block_hash()));
        rx.recv_timeout(Duration::from_secs(1))
            .expect("accepted branch should notify once");
        assert!(
            rx.try_recv().is_err(),
            "accepted branch should produce one notification"
        );
    }

    #[test]
    fn invalid_persisted_cache_wipes_then_live_append_recovers_to_valid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");

        let mut invalid = build_chain(4);
        invalid[2].prev_blockhash = BlockHash::all_zeros();
        invalid[2] = mine_regtest_header(invalid[2]);
        {
            let store = HeaderStore::from_file(Network::Regtest, path.clone()).unwrap();
            for (i, h) in invalid.iter().enumerate() {
                store.insert_unchecked(i as u32, raw_header(h));
            }
        }

        let store = HeaderStore::from_file(Network::Regtest, path).unwrap();
        assert!(wait_until(Duration::from_secs(5), || {
            matches!(store.validation_state(), HeaderValidationState::Invalid(_))
                && store.tip().is_none()
        }));

        let valid = build_chain(3);
        for (i, h) in valid.iter().enumerate() {
            store.append(0, i as u32, raw_header(h)).unwrap();
        }
        assert_eq!(store.validation_state(), HeaderValidationState::Valid);
        assert_eq!(store.tip(), Some(2));
    }

    #[test]
    fn replay_validating_to_valid_notifies_listener() {
        let backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
        let typed = RamStore::empty(backend, STORE_KEY, encode_height, encode_header);
        let store = Arc::new(HeaderStore {
            network: Network::Regtest,
            inner: Mutex::new(Inner {
                store: typed,
                validation_state: HeaderValidationState::Validating,
            }),
            listeners: Fanout::default(),
            progress_listeners: Mutex::new(ProgressListeners::default()),
            writer_token: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            worker: Mutex::new(None),
            header_req: Mutex::new(None),
            merkle_req: Mutex::new(None),
            merkle: Arc::default(),
            notifications: Fanout::default(),
            header_worker: Mutex::default(),
            merkle_worker: Mutex::default(),
        });
        let rx = store.register_chain_tick();

        store.finish_replay_validation_success();

        assert_eq!(store.validation_state(), HeaderValidationState::Valid);
        rx.recv_timeout(Duration::from_secs(1))
            .expect("validation success should notify listeners");
    }

    #[test]
    fn binary_round_trip_above_genesis() {
        // A cache that starts above height 0 (min_stored > 0) must round
        // trip with the right heights.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let chain = build_chain(10);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate().skip(4) {
            map.insert(i as u32, raw_header(h));
        }
        write_binary(&path, &map);

        let reloaded = store_from_file(&path);
        assert_eq!(reloaded.keys().next().copied(), Some(4));
        assert_eq!(reloaded.keys().next_back().copied(), Some(9));
        for (i, h) in chain.iter().enumerate().skip(4) {
            let raw = reloaded.get(&(i as u32)).unwrap();
            assert_eq!(
                deserialize::<Header>(raw).unwrap().block_hash(),
                h.block_hash()
            );
        }
    }

    #[test]
    fn positional_append_matches_full_rewrite() {
        // Drive `append_to_disk` one header at a time and confirm the
        // resulting bytes match a single full rewrite. Uses the raw
        // persistence helpers (not the PoW-validating `append`) so the
        // synthetic regtest chain doesn't need real proof-of-work.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let chain = build_chain(6);

        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            let raw = raw_header(h);
            map.insert(i as u32, raw);
            append_to_disk(&path, i as u32, &raw, &map);
        }
        let appended = fs::read(&path).unwrap();

        let other = dir.path().join("full.bin");
        write_binary(&other, &map);
        let full = fs::read(&other).unwrap();
        assert_eq!(appended, full);
    }

    #[test]
    fn positional_append_truncates_stale_tail() {
        // A shorter chain written via `append_to_disk` (same `min_stored`,
        // fewer records) must truncate the deprecated trailing records left
        // by a previous longer chain; otherwise `store_from_file` would read
        // them back as a bogus longer chain.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let chain = build_chain(6);

        // Start with a full 6-record chain on disk.
        let mut long: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            long.insert(i as u32, raw_header(h));
        }
        write_binary(&path, &long);
        assert_eq!(store_from_file(&path).len(), 6);

        // Reorg to a shorter 3-record chain (same min_stored = 0) and write
        // its tip through the positional path.
        let mut short: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate().take(3) {
            short.insert(i as u32, raw_header(h));
        }
        append_to_disk(&path, 2, &raw_header(&chain[2]), &short);

        // The stale records (heights 3..=5) must be gone.
        let reloaded = store_from_file(&path);
        assert_eq!(reloaded.len(), 3);
        assert_eq!(reloaded.keys().next_back().copied(), Some(2));
    }

    #[test]
    fn sanity_check_rejects_gap() {
        // The binary cache format is inherently contiguous, so a gap can
        // only arise in memory. Exercise the sanity_check span guard
        // directly: heights 0,1,3,4 (gap at 2) must be rejected.
        let chain = build_chain(5);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            if i == 2 {
                continue;
            }
            map.insert(i as u32, raw_header(h));
        }
        assert!(!sanity_check(Network::Regtest, &map));
    }

    #[test]
    fn sanity_check_rejects_non_boundary_sparse_anchor() {
        // A sparse-anchored cache (min > 0) must sit exactly on a retarget
        // boundary, matching `backfill_floor`. min=5 satisfies neither
        // "genesis-anchored" (min == 0) nor boundary alignment, so it must be
        // rejected even though the span is contiguous.
        let chain = build_chain(5);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            map.insert(5 + i as u32, raw_header(h));
        }
        assert!(!sanity_check(Network::Regtest, &map));
    }

    #[test]
    fn sanity_check_accepts_boundary_aligned_sparse_anchor() {
        // The new backfill floor is a retarget-boundary multiple; a cache
        // whose min is that floor must be accepted. Under the old `+
        // MTP_WINDOW` margin this boundary-aligned min was rejected and the
        // cache wiped on every reload.
        let floor = backfill_chunk(Network::Regtest);
        let chain = build_chain(header_validator::MTP_WINDOW as u32);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            map.insert(floor + i as u32, raw_header(h));
        }
        assert!(sanity_check(Network::Regtest, &map));
    }

    #[test]
    fn mtp_enforced_at_full_window_above_sparse_anchor() {
        // Seed a store whose lowest stored height is exactly the backfill
        // floor `initial_sync` now produces for a sparse start: the retarget
        // boundary one interval below the account's snapped min_height. Every
        // height at or above `floor + MTP_WINDOW` has a full MTP window; a
        // header whose timestamp does not beat that window's median must be
        // rejected. On the old upward scan `ancestors_for` returned no
        // ancestors above the anchor, failing the length assertion below.
        let network = Network::Bitcoin;
        let chunk = backfill_chunk(network);
        let floor = backfill_floor(Some(chunk * 2), 0, network);
        assert_eq!(floor, chunk);
        let span = header_validator::MTP_WINDOW as u32 + 10;

        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        let mut prev_hash = BlockHash::all_zeros();
        for i in 0..span {
            let h = Header {
                version: Version::ONE,
                prev_blockhash: prev_hash,
                merkle_root: TxMerkleNode::from_byte_array([(i as u8); 32]),
                time: 1_700_000_000 + i * 600,
                bits,
                nonce: 0,
            };
            prev_hash = h.block_hash();
            map.insert(floor + i, raw_header(&h));
        }
        let store = HeaderStore::from_map(network, map);

        let full_window_lo = floor + header_validator::MTP_WINDOW as u32;
        for h in full_window_lo..(floor + span) {
            let ancestors = store.ancestors_for(h, header_validator::MTP_WINDOW);
            assert_eq!(
                ancestors.len(),
                header_validator::MTP_WINDOW,
                "height {h} lacks a full MTP window; the backfill margin regressed"
            );
            let mut times: Vec<u32> = ancestors.iter().map(|a| a.time).collect();
            times.sort_unstable();
            let median = times[times.len() / 2];
            let violating = Header {
                version: Version::ONE,
                prev_blockhash: ancestors.last().unwrap().block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: median,
                bits,
                nonce: 0,
            };
            assert_eq!(
                header_validator::check_mtp(network, &ancestors, &violating),
                Err(ValidatorError::MtpViolation),
                "height {h} did not reject a violating header"
            );
        }
    }

    #[test]
    fn load_wipes_on_short_trailing_record() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");

        let chain = build_chain(3);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            map.insert(i as u32, raw_header(h));
        }
        write_binary(&path, &map);
        // Truncate the file mid-record (drop the last 10 bytes).
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 10]).unwrap();

        // The corrupt file is wiped on load; the store comes up empty.
        // (`from_file` re-persists an empty cache, so the path may exist
        // again, but it no longer carries the truncated chain.)
        let store = HeaderStore::from_file(Network::Regtest, path.clone()).unwrap();
        assert_eq!(store.tip(), None);
        // Drop the store first: it holds the cache file's advisory lock, and
        // `store_from_file` reopens the same file.
        drop(store);
        assert!(store_from_file(&path).is_empty());
    }

    #[test]
    fn load_wipes_legacy_json_cache() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.json");

        // A leftover legacy JSON cache (starts with '{') must be deleted.
        fs::write(&path, b"{\"0\":\"deadbeef\"}").unwrap();
        let store = HeaderStore::from_file(Network::Regtest, path.clone()).unwrap();
        assert_eq!(store.tip(), None);
        // Drop the store first: it holds the cache file's advisory lock, and
        // `store_from_file` reopens the same file.
        drop(store);
        // The legacy JSON content is gone (replaced by an empty binary
        // cache or no file).
        assert!(store_from_file(&path).is_empty());
    }

    #[test]
    fn sanity_load_wipes_on_swapped_genesis() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.json");

        // Build a synthetic mainnet-flagged file whose height-0 header is
        // NOT the real Bitcoin genesis.
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let bogus_genesis = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_231_006_505,
            bits,
            nonce: 0,
        };
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        map.insert(0, raw_header(&bogus_genesis));
        write_binary(&path, &map);

        let store = HeaderStore::from_file(Network::Bitcoin, path).unwrap();
        assert_eq!(store.tip(), None);
    }

    #[test]
    fn sanity_load_accepts_canonical_mainnet_genesis() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.json");

        let g = genesis_block(Params::new(Network::Bitcoin)).header;
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        map.insert(0, raw_header(&g));
        write_binary(&path, &map);

        let store = HeaderStore::from_file(Network::Bitcoin, path).unwrap();
        assert_eq!(store.tip(), Some(0));
        assert_eq!(store.block_hash(0), Some(g.block_hash()));
    }

    #[test]
    fn block_hash_and_merkle_root_return_correct_values() {
        let chain = build_chain(3);
        let store = store_with_chain(&chain);
        for (i, h) in chain.iter().enumerate() {
            assert_eq!(store.block_hash(i as u32), Some(h.block_hash()));
            assert_eq!(store.merkle_root(i as u32), Some(h.merkle_root));
        }
        assert!(store.block_hash(99).is_none());
        assert!(store.merkle_root(99).is_none());
    }

    #[test]
    fn missing_file_yields_empty_store() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");
        let store = HeaderStore::from_file(Network::Regtest, path).unwrap();
        assert_eq!(store.tip(), None);
    }

    /// A merkle client that dies leaves no live request sender behind and says
    /// so, otherwise every later fetch is dropped in silence and the entries it
    /// would have proved stay `ConfirmedUnverified` for good.
    #[test]
    fn a_dead_merkle_client_clears_its_sender_and_reports() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (notif_tx, notif_rx) = mpsc::channel();
        store.register_notifications(notif_tx);
        let (req_tx, _req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let token = store.writer_token.load(Ordering::SeqCst);

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, token)
        });
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(store.merkle_req.lock().expect("poisoned").is_none());
        assert!(matches!(
            notif_rx.try_recv(),
            Ok(Notification::MerkleFetchStopped)
        ));
    }

    /// A superseded forwarder must stay quiet: `restart` bumps the token and
    /// installs a newer client, so the old one clearing or reporting would
    /// wrongly say no proof is being fetched.
    #[test]
    fn a_superseded_merkle_forwarder_reports_nothing() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (notif_tx, notif_rx) = mpsc::channel();
        store.register_notifications(notif_tx);
        let (req_tx, _req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let stale = store.writer_token.load(Ordering::SeqCst);
        store.writer_token.fetch_add(1, Ordering::SeqCst);

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, stale)
        });
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(store.merkle_req.lock().expect("poisoned").is_some());
        assert!(notif_rx.try_recv().is_err());
    }

    /// A merkle failure names the fetch it ends, so it must reach the
    /// listeners: dropped, the requester keeps a slot for an answer that never
    /// comes and never asks again.
    #[test]
    fn a_failed_merkle_fetch_reaches_the_listeners() {
        use crate::client::DecodeError;

        let store = HeaderStore::new_in_memory(Network::Regtest);
        let outcomes = store.register_merkle_outcome(ListenerId::next());
        let token = store.writer_token.load(Ordering::SeqCst);

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, token)
        });
        let txid = Txid::from_byte_array([0x42; 32]);
        resp_tx
            .send(CoinResponse::Error(CoinError::MerkleDecode {
                txid,
                height: 7,
                source: DecodeError::MerkleHashLength { index: 0, got: 31 },
            }))
            .unwrap();
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(matches!(
            outcomes.try_recv(),
            Ok(MerkleOutcome::Failed { txid: t, height: 7 }) if t == txid
        ));
    }

    /// One outcome must reach the reconciler that asked for it and nobody
    /// else: on a store shared by several reconcilers, every other one would
    /// otherwise wake and take its coin-store lock to look up a txid that
    /// belongs to a different sub-account.
    #[test]
    fn a_merkle_outcome_reaches_only_its_requester() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (req_tx, req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let requester = ListenerId::next();
        let mine = store.register_merkle_outcome(requester);
        let theirs = store.register_merkle_outcome(ListenerId::next());
        let token = store.writer_token.load(Ordering::SeqCst);
        let txid = Txid::from_byte_array([0x11; 32]);

        store.fetch_merkle(requester, txid, 7);
        assert!(matches!(
            req_rx.try_recv(),
            Ok(CoinRequest::GetTxMerkle { txid: t, height: 7 }) if t == txid
        ));

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, token)
        });
        resp_tx
            .send(CoinResponse::TxMerkle {
                txid,
                height: 7,
                branch: Vec::new(),
                pos: 0,
            })
            .unwrap();
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(matches!(
            mine.try_recv(),
            Ok(MerkleOutcome::Proof(proof)) if proof.txid == txid
        ));
        assert!(matches!(theirs.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    /// An outcome nobody is recorded against (a fetch issued before a restart,
    /// or an answer the server repeated) goes to every listener: dropping it
    /// would leave a requester holding a slot for an answer it never hears.
    #[test]
    fn an_unrequested_merkle_outcome_reaches_every_listener() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let first = store.register_merkle_outcome(ListenerId::next());
        let second = store.register_merkle_outcome(ListenerId::next());
        let txid = Txid::from_byte_array([0x22; 32]);

        store
            .merkle
            .deliver(MerkleOutcome::Failed { txid, height: 5 });

        assert!(matches!(
            first.try_recv(),
            Ok(MerkleOutcome::Failed { txid: t, height: 5 }) if t == txid
        ));
        assert!(matches!(
            second.try_recv(),
            Ok(MerkleOutcome::Failed { txid: t, height: 5 }) if t == txid
        ));
    }

    /// Nothing answers a fetch its client did not outlive, so the fetch must be
    /// failed when the client goes: the requester frees its slot and asks again
    /// over the next connection.
    #[test]
    fn a_dead_merkle_client_fails_its_pending_fetches() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let requester = ListenerId::next();
        let outcomes = store.register_merkle_outcome(requester);
        let (req_tx, _req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let token = store.writer_token.load(Ordering::SeqCst);
        let txid = Txid::from_byte_array([0x33; 32]);
        store.fetch_merkle(requester, txid, 9);

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, token)
        });
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(matches!(
            outcomes.try_recv(),
            Ok(MerkleOutcome::Failed { txid: t, height: 9 }) if t == txid
        ));
    }

    /// A `restart` bumps the writer token before the superseded forwarder
    /// exits, which makes its own `merkle_client_ended` a no-op: idling must
    /// therefore fail the pending fetches itself, or the reconciler of a wallet
    /// sharing the store never asks for its proofs again.
    #[test]
    fn an_idled_store_fails_its_pending_fetches() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let requester = ListenerId::next();
        let outcomes = store.register_merkle_outcome(requester);
        let (req_tx, _req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let txid = Txid::from_byte_array([0x44; 32]);
        store.fetch_merkle(requester, txid, 9);

        store.stop();

        assert!(matches!(
            outcomes.try_recv(),
            Ok(MerkleOutcome::Failed { txid: t, height: 9 }) if t == txid
        ));
    }

    /// The notification sender is registered once by whoever owns the store,
    /// not once per reconciler, so a store several reconcilers share reports
    /// each of its events to that channel exactly once.
    #[test]
    fn a_notification_sender_registered_once_hears_an_event_once() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let (notif_tx, notif_rx) = mpsc::channel();
        store.register_notifications(notif_tx);
        let _first = store.register_merkle_outcome(ListenerId::next());
        let _second = store.register_merkle_outcome(ListenerId::next());
        let (req_tx, _req_rx) = mpsc::channel();
        store.set_merkle_sender_for_test(req_tx);
        let token = store.writer_token.load(Ordering::SeqCst);

        let (resp_tx, resp_rx) = mpsc::channel();
        let merkle = store.merkle.clone();
        let forwarder = thread::spawn({
            let weak = Arc::downgrade(&store);
            move || forward_merkle_proofs(resp_rx, merkle, weak, token)
        });
        drop(resp_tx);
        forwarder.join().expect("forwarder panicked");

        assert!(matches!(
            notif_rx.try_recv(),
            Ok(Notification::MerkleFetchStopped)
        ));
        assert!(matches!(
            notif_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn register_returns_a_live_receiver() {
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let _rx = store.register_chain_tick();
        assert_eq!(store.listeners.listener_count(), 1);
    }

    // Verify the merkle helper using hand-rolled vectors.

    fn sha256d_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut engine = sha256d::Hash::engine();
        engine.input(left);
        engine.input(right);
        sha256d::Hash::from_engine(engine).to_byte_array()
    }

    #[test]
    fn verify_merkle_branch_pos_zero_one_level_accepts() {
        let txid = Txid::from_byte_array([0x11; 32]);
        let sibling = [0x22u8; 32];
        let root_bytes = sha256d_pair(&txid.to_byte_array(), &sibling);
        let root = TxMerkleNode::from_byte_array(root_bytes);
        assert!(verify_merkle_branch(txid, &[sibling], 0, root));
    }

    #[test]
    fn verify_merkle_branch_pos_one_one_level_accepts() {
        let txid = Txid::from_byte_array([0x33; 32]);
        let sibling = [0x44u8; 32];
        let root_bytes = sha256d_pair(&sibling, &txid.to_byte_array());
        let root = TxMerkleNode::from_byte_array(root_bytes);
        assert!(verify_merkle_branch(txid, &[sibling], 1, root));
    }

    #[test]
    fn verify_merkle_branch_tampered_sibling_rejects() {
        let txid = Txid::from_byte_array([0x55; 32]);
        let sibling = [0x66u8; 32];
        let root_bytes = sha256d_pair(&txid.to_byte_array(), &sibling);
        let root = TxMerkleNode::from_byte_array(root_bytes);
        let bad_sibling = [0x67u8; 32];
        assert!(!verify_merkle_branch(txid, &[bad_sibling], 0, root));
    }

    #[test]
    fn verify_merkle_branch_three_levels_accepts() {
        // Three-level branch. At each level the position bit selects
        // whether the running node is on the left or right side of the
        // concatenation. pos = 0b101 = 5:
        //   level 0: pos bit 1 -> sibling || node
        //   level 1: pos bit 0 -> node    || sibling
        //   level 2: pos bit 1 -> sibling || node
        let txid = Txid::from_byte_array([0xAA; 32]);
        let s0 = [0xB0u8; 32];
        let s1 = [0xB1u8; 32];
        let s2 = [0xB2u8; 32];

        let n0 = sha256d_pair(&s0, &txid.to_byte_array());
        let n1 = sha256d_pair(&n0, &s1);
        let n2 = sha256d_pair(&s2, &n1);
        let root = TxMerkleNode::from_byte_array(n2);

        assert!(verify_merkle_branch(txid, &[s0, s1, s2], 5, root));

        // Negative: wrong position yields a mismatch.
        assert!(!verify_merkle_branch(txid, &[s0, s1, s2], 4, root));
    }

    // Mirrors the `Claimed -> Verified` promotion path's verification
    // step: a merkle proof that does not fold to the block's merkle root
    // returns false, which is exactly the condition under which the
    // listener emits `Notification::ValidationFailed` and makes no state
    // change. The notification emission itself is covered by
    // `account::tests::handle_tx_merkle_tampered_branch_notifies`.
    #[test]
    fn malformed_merkle_proof_fails_verification() {
        let txid = Txid::from_byte_array([0x42; 32]);
        let sibling = [0x99u8; 32];
        // Correct root for pos 0 with this single sibling.
        let root = TxMerkleNode::from_byte_array(sha256d_pair(&txid.to_byte_array(), &sibling));
        // A wrong sibling fails verification against the real root.
        let bad_sibling = [0x9au8; 32];
        assert!(!verify_merkle_branch(txid, &[bad_sibling], 0, root));
        // A proof claiming the wrong root also fails.
        let wrong_root = TxMerkleNode::from_byte_array([0u8; 32]);
        assert!(!verify_merkle_branch(txid, &[sibling], 0, wrong_root));
    }

    // The store's `append` rejects a header timestamped far in the future
    // (the worker relies on this to leave its tip unchanged when a server
    // advertises a bogus future header). Mirrors the worker-level
    // `future_block_rejected_by_worker` scenario without needing electrs.
    #[test]
    fn append_rejects_future_timestamp() {
        use miniscript::bitcoin::CompactTarget;
        let bits = CompactTarget::from_consensus(0x207fffff);
        // Genesis-anchored regtest chain of length 1 (height 0).
        let g = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits,
            nonce: 0,
        };
        let store = HeaderStore::new_in_memory(Network::Regtest);
        store.insert_unchecked(0, raw_header(&g));

        // Header at height 1 dated ~3h in the future.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let future = Header {
            version: Version::ONE,
            prev_blockhash: g.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: (now + 3 * 3600) as u32,
            bits,
            nonce: 0,
        };
        let res = store.append(0, 1, raw_header(&future));
        assert!(matches!(
            res,
            Err(MutateError::Validate(
                ValidatorError::TimestampTooFarInFuture
            ))
        ));
        // Tip is unchanged (still genesis).
        assert_eq!(store.tip(), Some(0));
    }

    // The sparse-start anchor: `append_anchor` trusts a header on
    // proof-of-work alone (no ancestors), promotes the store to Valid, and
    // is what lets the first live backfilled header land. The anchor must sit
    // on a retarget boundary on an empty store (enforced by `append_anchor`),
    // so use the first boundary above genesis.
    #[test]
    fn append_anchor_accepts_pow_only_and_sets_valid() {
        let anchor = backfill_chunk(Network::Regtest);
        let header = mine_regtest_header(Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0x11; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        });
        let store = HeaderStore::new_in_memory(Network::Regtest);
        store.append_anchor(0, anchor, raw_header(&header)).unwrap();
        assert_eq!(store.tip(), Some(anchor));
        assert_eq!(store.block_hash(anchor), Some(header.block_hash()));
        assert_eq!(store.validation_state(), HeaderValidationState::Valid);
    }

    // `append_anchor` enforces its two invariants (empty store, retarget
    // boundary) that the reload `sanity_check` relies on. A non-boundary
    // height and a non-empty store must each be rejected with `BadAnchor`,
    // never written.
    #[test]
    fn append_anchor_rejects_non_boundary_and_non_empty() {
        let anchor = backfill_chunk(Network::Regtest);
        let raw_at = |merkle: u8| {
            raw_header(&mine_regtest_header(Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::from_byte_array([merkle; 32]),
                time: 1_700_000_000,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            }))
        };

        // Non-boundary height on an empty store.
        let store = HeaderStore::new_in_memory(Network::Regtest);
        assert!(matches!(
            store.append_anchor(0, anchor + 1, raw_at(0x22)),
            Err(MutateError::BadAnchor)
        ));
        assert_eq!(store.tip(), None);

        // Boundary height but the store is not empty.
        let store = HeaderStore::new_in_memory(Network::Regtest);
        store.append_anchor(0, anchor, raw_at(0x33)).unwrap();
        assert!(matches!(
            store.append_anchor(0, anchor * 2, raw_at(0x44)),
            Err(MutateError::BadAnchor)
        ));
        assert_eq!(store.tip(), Some(anchor));
    }

    // A header whose target does not satisfy proof-of-work is rejected even
    // by the relaxed anchor path. A mainnet-hard `bits` with nonce 0 cannot
    // satisfy the regtest-clamped target.
    #[test]
    fn append_anchor_rejects_bad_pow() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let header = Header {
            version: Version::ONE,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits,
            nonce: 0,
        };
        let store = HeaderStore::new_in_memory(Network::Regtest);
        let res = store.append_anchor(0, 5, raw_header(&header));
        assert!(matches!(
            res,
            Err(MutateError::Validate(ValidatorError::Pow))
        ));
        assert_eq!(store.tip(), None);
    }

    #[test]
    fn backfill_floor_saturates_near_genesis() {
        // A min_height inside the first retarget period snaps to 0, and the
        // retarget-interval padding must saturate rather than underflow.
        let network = Network::Bitcoin;
        assert_eq!(backfill_floor(Some(5), 0, network), 0);
        assert_eq!(backfill_floor(None, 0, network), 0);
    }

    #[test]
    fn backfill_floor_anchors_on_previous_retarget_boundary() {
        // The floor pads the snapped boundary down by a full retarget interval
        // so the anchor lands on the previous boundary, giving the boundary at
        // the snap a complete ancestor window. The old floor subtracted only
        // MTP_WINDOW.
        let network = Network::Bitcoin;
        let chunk = backfill_chunk(network);
        let boundary = chunk * 2;
        assert_eq!(
            backfill_floor(Some(boundary + 5), 0, network),
            boundary - chunk
        );
    }

    #[test]
    fn ancestors_for_returns_contiguous_suffix_above_sparse_anchor() {
        // A cache anchored at min_stored > 0: `ancestors_for(h, max)` with
        // `h - max < min_stored` must return the full contiguous run
        // [min_stored, h), oldest-first, not an empty vec. The old upward scan
        // probed `h - max` first, missed, and returned empty, stalling sync
        // one block above the anchor.
        let network = Network::Bitcoin;
        let min_stored = backfill_chunk(network);
        let span = 30u32;
        let chain = build_chain(span);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            map.insert(min_stored + i as u32, raw_header(h));
        }
        let store = HeaderStore::from_map(network, map);

        let h = min_stored + span - 1;
        let ancestors = store.ancestors_for(h, retarget_interval(network));
        assert_eq!(ancestors.len() as u32, h - min_stored);
        assert_eq!(
            ancestors.first().unwrap().block_hash(),
            chain[0].block_hash()
        );
        assert_eq!(
            ancestors.last().unwrap().block_hash(),
            chain[(h - 1 - min_stored) as usize].block_hash()
        );
    }

    #[test]
    fn persisted_sparse_cache_at_new_floor_survives_reload() {
        // A sparse cache anchored on a retarget boundary (min is a
        // 2016-multiple, matching the new `backfill_floor`) passes both
        // `sanity_check` and full `replay_validate`, so a reload keeps it. The
        // old `+ MTP_WINDOW` sanity margin required `min == boundary -
        // MTP_WINDOW` and would have wiped this cache on every reload.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.bin");
        let anchor = backfill_chunk(Network::Regtest);
        let chain = build_chain(20);
        let mut map: BTreeMap<u32, [u8; Header::SIZE]> = BTreeMap::new();
        for (i, h) in chain.iter().enumerate() {
            map.insert(anchor + i as u32, raw_header(h));
        }
        assert!(sanity_check(Network::Regtest, &map));
        write_binary(&path, &map);

        let store = HeaderStore::from_file(Network::Regtest, path).unwrap();
        assert!(wait_until(Duration::from_secs(5), || {
            store.validation_state() == HeaderValidationState::Valid
        }));
        assert_eq!(store.min_height(), Some(anchor));
        assert_eq!(store.tip(), Some(anchor + 19));
    }

    // Regression for S7: a position that an empty (or too-short) branch
    // cannot address must be rejected outright, never folded to a bogus
    // root.
    #[test]
    fn verify_merkle_branch_rejects_pos_beyond_branch_length() {
        let txid = Txid::from_byte_array([0x11; 32]);
        let root = TxMerkleNode::from_byte_array(txid.to_byte_array());
        // Empty branch can only cover a single-leaf tree (pos 0). pos=7 is
        // unaddressable and must be rejected even though, with an empty
        // branch, the fold would otherwise return `node == root`.
        assert!(!verify_merkle_branch(txid, &[], 7, root));
        // pos 0 with an empty branch is the degenerate single-tx block.
        assert!(verify_merkle_branch(txid, &[], 0, root));
        // A two-level branch covers positions 0..=3; pos 4 is rejected.
        let s0 = [0xB0u8; 32];
        let s1 = [0xB1u8; 32];
        assert!(!verify_merkle_branch(txid, &[s0, s1], 4, root));
    }
}
