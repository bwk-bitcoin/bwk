use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use serde::{Deserialize, Serialize};

pub type ConnId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Wallet to server.
    Up,
    /// Server to wallet.
    Down,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct MethodStats {
    pub calls: u64,
    pub responses: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub ttfb: TtfbStats,
}

impl MethodStats {
    fn merge_from(&mut self, other: &MethodStats) {
        self.calls += other.calls;
        self.responses += other.responses;
        self.bytes_up += other.bytes_up;
        self.bytes_down += other.bytes_down;
        self.ttfb.merge_from(&other.ttfb);
    }
}

/// Time-to-first-byte aggregate for a method: count, min, max and running sum
/// (mean is derived from the sum). Individual samples are never retained.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct TtfbStats {
    pub count: u64,
    pub min_secs: f64,
    pub max_secs: f64,
    pub sum_secs: f64,
}

impl TtfbStats {
    pub fn mean_secs(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_secs / self.count as f64
        }
    }

    fn record(&mut self, secs: f64) {
        if self.count == 0 || secs < self.min_secs {
            self.min_secs = secs;
        }
        if self.count == 0 || secs > self.max_secs {
            self.max_secs = secs;
        }
        self.sum_secs += secs;
        self.count += 1;
    }

    fn merge_from(&mut self, other: &TtfbStats) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            *self = other.clone();
            return;
        }
        self.min_secs = self.min_secs.min(other.min_secs);
        self.max_secs = self.max_secs.max(other.max_secs);
        self.sum_secs += other.sum_secs;
        self.count += other.count;
    }
}

/// Which side of a connection closed it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloseInfo {
    pub closed_by: Side,
    pub clean: bool,
    pub error: Option<String>,
    pub idle_before_close: Option<f64>,
}

/// One bucket of JSON-RPC error responses sharing a `(method, code)` pair.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ErrorBucket {
    pub method: String,
    pub code: i64,
    pub count: u64,
    pub sample: String,
}

/// Response ordering relative to the order requests were sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct OrderStats {
    pub out_of_order: u64,
    pub max_displacement: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Discovery,
    TxFetch,
    Proofs,
    Headers,
    Other,
}

impl Phase {
    pub fn of(method: &str) -> Self {
        match method {
            "blockchain.scripthash.subscribe" | "blockchain.scripthash.get_history" => {
                Phase::Discovery
            }
            "blockchain.transaction.get" => Phase::TxFetch,
            "blockchain.transaction.get_merkle" | "blockchain.block.header" => Phase::Proofs,
            "blockchain.headers.subscribe" | "blockchain.block.headers" => Phase::Headers,
            _ => Phase::Other,
        }
    }
}

/// The JSON-RPC error carried by a response element.
pub struct ResponseError {
    pub code: i64,
    pub message: String,
}

/// A response element matched to an outstanding request.
pub struct MatchedResponse {
    pub method: String,
    pub bytes: u64,
    /// Distance from the front of the outstanding queue, 0 when in order.
    pub displacement: u64,
    pub ttfb_secs: f64,
    pub error: Option<ResponseError>,
}

/// One element of a line: the whole line, or one item of a JSON array batch.
pub enum ElementUpdate {
    /// A request or a notification, attributed to its own method.
    Attributed {
        method: String,
        bytes: u64,
    },
    Matched(MatchedResponse),
    Unattributed {
        bytes: u64,
    },
}

/// Every effect one wire line has on the metrics of one connection, gathered
/// so [`Metrics::apply_line`] can apply them all under a single lock. A
/// reader can then never catch a line half accounted, which would make the
/// per-method bytes and the framing bytes disagree with the wire.
pub struct LineUpdate {
    pub dir: Direction,
    pub line_size: u64,
    pub framing_bytes: u64,
    pub elements: Vec<ElementUpdate>,
}

impl LineUpdate {
    pub fn new(dir: Direction, line_size: u64) -> Self {
        Self {
            dir,
            line_size,
            framing_bytes: 0,
            elements: Vec::new(),
        }
    }
}

struct ConnMetrics {
    opened_at: Instant,
    closed_at: Option<Instant>,
    close: Option<CloseInfo>,
    round_trips: u64,
    methods: HashMap<String, MethodStats>,
    unattributed: MethodStats,
    last_dir: Option<Direction>,
    framing_bytes_up: u64,
    framing_bytes_down: u64,
    last_activity: Option<Instant>,
    max_idle_gap_secs: f64,
    largest_request_line: u64,
    largest_response_line: u64,
    errors: HashMap<String, ErrorBucket>,
    order: OrderStats,
}

impl ConnMetrics {
    fn new() -> Self {
        Self {
            opened_at: Instant::now(),
            closed_at: None,
            close: None,
            round_trips: 0,
            methods: HashMap::new(),
            unattributed: MethodStats::default(),
            last_dir: None,
            framing_bytes_up: 0,
            framing_bytes_down: 0,
            last_activity: None,
            max_idle_gap_secs: 0.0,
            largest_request_line: 0,
            largest_response_line: 0,
            errors: HashMap::new(),
            order: OrderStats::default(),
        }
    }

    fn count_round_trip(&mut self, dir: Direction) {
        if dir == Direction::Up && !matches!(self.last_dir, Some(Direction::Up)) {
            self.round_trips += 1;
        }
        self.last_dir = Some(dir);
    }

    fn record_activity(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_activity {
            let gap = now.duration_since(last).as_secs_f64();
            if gap > self.max_idle_gap_secs {
                self.max_idle_gap_secs = gap;
            }
        }
        self.last_activity = Some(now);
    }

    fn record_line_size(&mut self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Up => {
                if bytes > self.largest_request_line {
                    self.largest_request_line = bytes;
                }
            }
            Direction::Down => {
                if bytes > self.largest_response_line {
                    self.largest_response_line = bytes;
                }
            }
        }
    }

    fn record_ttfb(&mut self, method: &str, secs: f64) {
        self.methods
            .entry(method.to_string())
            .or_default()
            .ttfb
            .record(secs);
    }

    fn record_error(&mut self, method: &str, code: i64, message: &str) {
        let key = format!("{method}:{code}");
        let bucket = self.errors.entry(key).or_insert_with(|| ErrorBucket {
            method: method.to_string(),
            code,
            count: 0,
            sample: message.to_string(),
        });
        bucket.count += 1;
    }

    fn record_order(&mut self, displacement: u64) {
        if displacement == 0 {
            return;
        }
        self.order.out_of_order += 1;
        if displacement > self.order.max_displacement {
            self.order.max_displacement = displacement;
        }
    }

    fn record(&mut self, dir: Direction, method: &str, bytes: u64) {
        let stats = self.methods.entry(method.to_string()).or_default();
        match dir {
            Direction::Up => {
                stats.calls += 1;
                stats.bytes_up += bytes;
            }
            Direction::Down => {
                stats.responses += 1;
                stats.bytes_down += bytes;
            }
        }
        self.count_round_trip(dir);
    }

    fn record_framing(&mut self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Up => self.framing_bytes_up += bytes,
            Direction::Down => self.framing_bytes_down += bytes,
        }
    }

    fn record_unattributed(&mut self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Up => {
                self.unattributed.calls += 1;
                self.unattributed.bytes_up += bytes;
            }
            Direction::Down => {
                self.unattributed.responses += 1;
                self.unattributed.bytes_down += bytes;
            }
        }
        self.count_round_trip(dir);
    }

    fn apply_element(&mut self, dir: Direction, element: &ElementUpdate) {
        match element {
            ElementUpdate::Attributed { method, bytes } => self.record(dir, method, *bytes),
            ElementUpdate::Matched(response) => {
                self.record_order(response.displacement);
                self.record_ttfb(&response.method, response.ttfb_secs);
                self.record(dir, &response.method, response.bytes);
                if let Some(error) = &response.error {
                    self.record_error(&response.method, error.code, &error.message);
                }
            }
            ElementUpdate::Unattributed { bytes } => self.record_unattributed(dir, *bytes),
        }
    }

    fn snapshot(&self, id: ConnId, start: Instant) -> ConnSnapshot {
        ConnSnapshot {
            id,
            opened_at: self.opened_at.duration_since(start).as_secs_f64(),
            closed_at: self
                .closed_at
                .map(|instant| instant.duration_since(start).as_secs_f64()),
            close: self.close.clone(),
            round_trips: self.round_trips,
            methods: self.methods.clone(),
            unattributed: self.unattributed.clone(),
            framing_bytes_up: self.framing_bytes_up,
            framing_bytes_down: self.framing_bytes_down,
            max_idle_gap_secs: self.max_idle_gap_secs,
            largest_request_line: self.largest_request_line,
            largest_response_line: self.largest_response_line,
            errors: self.errors.clone(),
            order: self.order,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnSnapshot {
    pub id: ConnId,
    pub opened_at: f64,
    pub closed_at: Option<f64>,
    pub close: Option<CloseInfo>,
    pub round_trips: u64,
    pub methods: HashMap<String, MethodStats>,
    pub unattributed: MethodStats,
    pub framing_bytes_up: u64,
    pub framing_bytes_down: u64,
    pub max_idle_gap_secs: f64,
    pub largest_request_line: u64,
    pub largest_response_line: u64,
    pub errors: HashMap<String, ErrorBucket>,
    pub order: OrderStats,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub methods: BTreeMap<String, MethodStats>,
    pub phases: BTreeMap<Phase, MethodStats>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub wall_secs: f64,
    pub connections: Vec<ConnSnapshot>,
    pub totals: Totals,
}

pub struct Metrics {
    start: Instant,
    conns: Mutex<BTreeMap<ConnId, ConnMetrics>>,
    next_id: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            conns: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(0),
        })
    }

    pub fn open_conn(&self) -> ConnId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns
            .lock()
            .expect("poisoned")
            .insert(id, ConnMetrics::new());
        id
    }

    pub fn close_conn(&self, id: ConnId, side: Side, clean: bool, error: Option<String>) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            let now = Instant::now();
            conn.closed_at = Some(now);
            let idle_before_close = conn
                .last_activity
                .map(|last| now.duration_since(last).as_secs_f64());
            conn.close = Some(CloseInfo {
                closed_by: side,
                clean,
                error,
                idle_before_close,
            });
        }
    }

    /// Records that bytes flowed on `id`, updating the longest observed gap
    /// between consecutive bytes in either direction.
    pub fn record_activity(&self, id: ConnId) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_activity();
        }
    }

    /// Records the size of a wire line, updating the largest seen so far for
    /// its direction.
    pub fn record_line_size(&self, id: ConnId, dir: Direction, bytes: u64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_line_size(dir, bytes);
        }
    }

    /// Records the elapsed time between a request and its matching response.
    pub fn record_ttfb(&self, id: ConnId, method: &str, secs: f64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_ttfb(method, secs);
        }
    }

    /// Buckets a JSON-RPC error response by `(method, code)`, keeping a
    /// count and a single sample message.
    pub fn record_error(&self, id: ConnId, method: &str, code: i64, message: &str) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_error(method, code, message);
        }
    }

    /// Records the displacement of a response from its send order. A
    /// displacement of 0 means the response arrived in order and is not
    /// counted; this is a reported statistic, never an error condition.
    pub fn record_order(&self, id: ConnId, displacement: u64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_order(displacement);
        }
    }

    pub fn record(&self, id: ConnId, dir: Direction, method: &str, bytes: u64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record(dir, method, bytes);
        }
    }

    pub fn record_framing(&self, id: ConnId, dir: Direction, bytes: u64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_framing(dir, bytes);
        }
    }

    pub fn record_unattributed(&self, id: ConnId, dir: Direction, bytes: u64) {
        if let Some(conn) = self.conns.lock().expect("poisoned").get_mut(&id) {
            conn.record_unattributed(dir, bytes);
        }
    }

    /// Applies every effect of one wire line at once, in the order the line
    /// was read: line size, then each element, then the framing bytes.
    pub fn apply_line(&self, id: ConnId, update: &LineUpdate) {
        let mut conns = self.conns.lock().expect("poisoned");
        let Some(conn) = conns.get_mut(&id) else {
            return;
        };
        conn.record_line_size(update.dir, update.line_size);
        for element in &update.elements {
            conn.apply_element(update.dir, element);
        }
        conn.record_framing(update.dir, update.framing_bytes);
    }

    pub fn snapshot(&self) -> Snapshot {
        let conns = self.conns.lock().expect("poisoned");
        let mut totals = Totals::default();
        let connections = conns
            .iter()
            .map(|(id, conn)| {
                for (method, stats) in &conn.methods {
                    totals
                        .methods
                        .entry(method.clone())
                        .or_default()
                        .merge_from(stats);
                    totals
                        .phases
                        .entry(Phase::of(method))
                        .or_default()
                        .merge_from(stats);
                }
                totals
                    .phases
                    .entry(Phase::Other)
                    .or_default()
                    .merge_from(&conn.unattributed);
                conn.snapshot(*id, self.start)
            })
            .collect();

        Snapshot {
            wall_secs: self.start.elapsed().as_secs_f64(),
            connections,
            totals,
        }
    }

    pub fn reset(&self) {
        self.conns.lock().expect("poisoned").clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::metrics::{Direction, Metrics, Phase, Side};

    #[test]
    fn open_conn_increasing_ids() {
        let metrics = Metrics::new();
        let a = metrics.open_conn();
        let b = metrics.open_conn();
        let c = metrics.open_conn();
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn record_accumulates_stats() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        metrics.record(conn, Direction::Up, "blockchain.transaction.get", 10);
        metrics.record(conn, Direction::Up, "blockchain.transaction.get", 20);
        metrics.record(conn, Direction::Down, "blockchain.transaction.get", 5);

        let snapshot = metrics.snapshot();
        let stats = &snapshot.connections[0].methods["blockchain.transaction.get"];
        assert_eq!(stats.calls, 2);
        assert_eq!(stats.bytes_up, 30);
        assert_eq!(stats.responses, 1);
        assert_eq!(stats.bytes_down, 5);
    }

    #[test]
    fn round_trips_counted_on_burst_start() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        for dir in [
            Direction::Up,
            Direction::Up,
            Direction::Down,
            Direction::Up,
            Direction::Down,
        ] {
            metrics.record(conn, dir, "server.ping", 1);
        }
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections[0].round_trips, 2);
    }

    #[test]
    fn round_trips_are_per_connection() {
        let metrics = Metrics::new();
        let a = metrics.open_conn();
        let b = metrics.open_conn();

        metrics.record(a, Direction::Up, "server.ping", 1);
        metrics.record(b, Direction::Down, "server.ping", 1);
        metrics.record(a, Direction::Down, "server.ping", 1);
        metrics.record(b, Direction::Up, "server.ping", 1);
        metrics.record(a, Direction::Up, "server.ping", 1);

        let snapshot = metrics.snapshot();
        let a_rt = snapshot
            .connections
            .iter()
            .find(|c| c.id == a)
            .unwrap()
            .round_trips;
        let b_rt = snapshot
            .connections
            .iter()
            .find(|c| c.id == b)
            .unwrap()
            .round_trips;
        assert_eq!(a_rt, 2);
        assert_eq!(b_rt, 1);
    }

    #[test]
    fn close_conn_marks_closed_and_stays_in_snapshot() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        metrics.close_conn(conn, Side::Client, true, None);
        let snapshot = metrics.snapshot();
        let snap = snapshot.connections.iter().find(|c| c.id == conn).unwrap();
        assert!(snap.closed_at.is_some());
        assert_eq!(snap.close.as_ref().unwrap().closed_by, Side::Client);
        assert!(snap.close.as_ref().unwrap().clean);
    }

    #[test]
    fn reset_clears_counters() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        metrics.record(conn, Direction::Up, "server.ping", 10);
        metrics.reset();
        let snapshot = metrics.snapshot();
        assert!(snapshot.connections.is_empty());
        assert!(snapshot.totals.methods.is_empty());
    }

    #[test]
    fn phase_of_maps_known_methods() {
        assert_eq!(
            Phase::of("blockchain.scripthash.subscribe"),
            Phase::Discovery
        );
        assert_eq!(
            Phase::of("blockchain.scripthash.get_history"),
            Phase::Discovery
        );
        assert_eq!(Phase::of("blockchain.transaction.get"), Phase::TxFetch);
        assert_eq!(
            Phase::of("blockchain.transaction.get_merkle"),
            Phase::Proofs
        );
        assert_eq!(Phase::of("blockchain.block.header"), Phase::Proofs);
        assert_eq!(Phase::of("blockchain.headers.subscribe"), Phase::Headers);
        assert_eq!(Phase::of("blockchain.block.headers"), Phase::Headers);
        assert_eq!(Phase::of("server.ping"), Phase::Other);
    }
}
