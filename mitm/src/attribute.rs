//! Reassembles newline-delimited JSON-RPC lines from arbitrary byte chunks
//! and attributes each request/response/notification to a method, folding
//! byte and call counts into `Metrics`.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};

use serde_json::value::RawValue;

use crate::{
    metrics::{
        ConnId, Direction, ElementUpdate, LineUpdate, MatchedResponse, Metrics, ResponseError,
    },
    trace::{TraceEvent, Tracer},
};

/// Bound on the number of outstanding request ids tracked for out-of-order
/// detection, so a long-lived connection with unanswered requests cannot
/// grow this bookkeeping without limit.
const MAX_OUTSTANDING: usize = 1024;

/// Buffers bytes for one direction of one connection until full lines
/// (delimited by `\n`) can be split off. Operates on bytes, never `str`: a
/// chunk boundary can fall in the middle of a multi-byte UTF-8 sequence, and
/// converting early would panic or lose data.
#[derive(Default)]
struct LineReassembler {
    buf: Vec<u8>,
}

impl LineReassembler {
    fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    fn take_line(&mut self) -> Option<Vec<u8>> {
        let pos = self.buf.iter().position(|b| *b == b'\n')?;
        let rest = self.buf.split_off(pos + 1);
        let mut line = std::mem::replace(&mut self.buf, rest);
        line.pop();
        Some(line)
    }
}

// Deliberately not a `serde_json::Value` tree: responses can be hundreds of
// kilobytes (a 2016-header batch), and a full value tree would allocate for
// all of it. This struct discards everything but what attribution needs.
#[derive(serde::Deserialize)]
struct RpcError {
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(serde::Deserialize)]
struct Envelope {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

/// Normalizes an id to a map key so numeric and string ids cannot collide
/// (`1` and `"1"` serialize to different strings).
fn id_key(id: &serde_json::Value) -> String {
    id.to_string()
}

struct PendingRequest {
    method: String,
    sent_at: Instant,
}

/// Attributes bytes on the wire to JSON-RPC methods for a single connection.
///
/// The id-to-method map is per connection, never shared: JSON-RPC ids are
/// scoped to a socket and collide across sockets, so a shared map would
/// mis-attribute responses.
pub struct Attributor {
    pending: HashMap<String, PendingRequest>,
    /// Ids in the order their requests were sent, bounded to
    /// `MAX_OUTSTANDING`, used to detect out-of-order responses.
    sent_order: VecDeque<String>,
    up: LineReassembler,
    down: LineReassembler,
    tracer: Option<Arc<Tracer>>,
}

impl Default for Attributor {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Attributor {
    pub fn new(tracer: Option<Arc<Tracer>>) -> Self {
        Self {
            pending: HashMap::new(),
            sent_order: VecDeque::new(),
            up: LineReassembler::default(),
            down: LineReassembler::default(),
            tracer,
        }
    }

    /// Emits one trace event, a no-op when no `--trace` path was given. `id`
    /// is set for an up-going request and a matched down-going response;
    /// `None` for notifications and unattributed traffic.
    fn trace(
        &self,
        conn: ConnId,
        dir: Direction,
        method: Option<&str>,
        id: Option<&str>,
        bytes: u64,
    ) {
        let Some(tracer) = &self.tracer else {
            return;
        };
        tracer.write(TraceEvent {
            elapsed_secs: tracer.elapsed_secs(),
            conn,
            dir,
            method: method.map(str::to_string),
            id: id.map(str::to_string),
            bytes,
        });
    }

    fn push_sent_order(&mut self, key: String) {
        self.sent_order.push_back(key);
        if self.sent_order.len() > MAX_OUTSTANDING {
            self.sent_order.pop_front();
        }
    }

    /// Removes `key` from the send-order queue and returns its displacement
    /// from the front (0 means it was the oldest outstanding request, i.e.
    /// in order). A key evicted by the bound is treated as in order, since
    /// its position can no longer be known.
    fn resolve_order(&mut self, key: &str) -> u64 {
        match self.sent_order.iter().position(|k| k == key) {
            Some(pos) => {
                self.sent_order.remove(pos);
                pos as u64
            }
            None => 0,
        }
    }

    /// Feeds a chunk of bytes for the given direction, attributing every
    /// complete line it yields.
    pub fn feed(&mut self, dir: Direction, chunk: &[u8], metrics: &Metrics, conn: ConnId) {
        let reassembler = match dir {
            Direction::Up => &mut self.up,
            Direction::Down => &mut self.down,
        };
        reassembler.feed(chunk);
        let mut lines = Vec::new();
        while let Some(line) = reassembler.take_line() {
            lines.push(line);
        }
        for line in lines {
            self.on_line(dir, &line, metrics, conn);
        }
    }

    /// Gathers every metrics effect of one line into a single `LineUpdate`,
    /// applied at the end in one shot: a concurrent `snapshot()` never sees a
    /// line half accounted.
    fn on_line(&mut self, dir: Direction, line: &[u8], metrics: &Metrics, conn: ConnId) {
        let mut update = LineUpdate::new(dir, line.len() as u64);
        if let Ok(elems) = serde_json::from_slice::<Vec<&RawValue>>(line) {
            let mut sum = 0u64;
            for raw in &elems {
                let bytes = raw.get().len() as u64;
                sum += bytes;
                self.attribute(raw.get().as_bytes(), bytes, conn, &mut update);
            }
            // +1 for the trailing '\n' that take_line() stripped before this
            // line reached attribution; it is framing overhead, not data.
            update.framing_bytes = (line.len() as u64).saturating_sub(sum) + 1;
        } else {
            self.attribute(line, line.len() as u64, conn, &mut update);
            // The trailing '\n' stripped by take_line() is framing overhead.
            update.framing_bytes = 1;
        }
        metrics.apply_line(conn, &update);
    }

    fn attribute(&mut self, raw: &[u8], bytes: u64, conn: ConnId, update: &mut LineUpdate) {
        match update.dir {
            Direction::Up => match serde_json::from_slice::<Envelope>(raw) {
                Ok(Envelope {
                    method: Some(method),
                    id,
                    ..
                }) => {
                    let id_str = id.as_ref().map(|id| {
                        let key = id_key(id);
                        self.pending.insert(
                            key.clone(),
                            PendingRequest {
                                method: method.clone(),
                                sent_at: Instant::now(),
                            },
                        );
                        self.push_sent_order(key.clone());
                        key
                    });
                    self.trace(conn, Direction::Up, Some(&method), id_str.as_deref(), bytes);
                    update
                        .elements
                        .push(ElementUpdate::Attributed { method, bytes });
                }
                _ => {
                    update.elements.push(ElementUpdate::Unattributed { bytes });
                    self.trace(conn, Direction::Up, None, None, bytes);
                }
            },
            Direction::Down => match serde_json::from_slice::<Envelope>(raw) {
                Ok(Envelope {
                    method: Some(method),
                    id: None,
                    ..
                }) => {
                    self.trace(conn, Direction::Down, Some(&method), None, bytes);
                    update
                        .elements
                        .push(ElementUpdate::Attributed { method, bytes });
                }
                Ok(Envelope {
                    id: Some(id),
                    error,
                    ..
                }) => {
                    let key = id_key(&id);
                    match self.pending.remove(&key) {
                        Some(pending) => {
                            let displacement = self.resolve_order(&key);
                            let ttfb_secs = pending.sent_at.elapsed().as_secs_f64();
                            self.trace(
                                conn,
                                Direction::Down,
                                Some(&pending.method),
                                Some(&key),
                                bytes,
                            );
                            update
                                .elements
                                .push(ElementUpdate::Matched(MatchedResponse {
                                    method: pending.method,
                                    bytes,
                                    displacement,
                                    ttfb_secs,
                                    error: error.map(|err| ResponseError {
                                        code: err.code,
                                        message: err.message,
                                    }),
                                }));
                        }
                        None => {
                            update.elements.push(ElementUpdate::Unattributed { bytes });
                            self.trace(conn, Direction::Down, None, None, bytes);
                        }
                    }
                }
                _ => {
                    update.elements.push(ElementUpdate::Unattributed { bytes });
                    self.trace(conn, Direction::Down, None, None, bytes);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Instant};

    use serde_json::value::RawValue;

    use crate::{
        attribute::Attributor,
        metrics::{ConnId, Direction, Metrics},
        trace::Tracer,
    };

    fn assert_zero_unattributed(metrics: &Metrics, conn: ConnId) {
        let snapshot = metrics.snapshot();
        let snap = snapshot.connections.iter().find(|c| c.id == conn).unwrap();
        assert_eq!(snap.unattributed.calls, 0);
        assert_eq!(snap.unattributed.responses, 0);
    }

    #[test]
    fn request_then_response_attributes_to_method() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        attributor.feed(
            Direction::Up,
            br#"{"id":1,"method":"server.ping","params":[]}
"#,
            &metrics,
            conn,
        );
        attributor.feed(
            Direction::Down,
            b"{\"id\":1,\"result\":null}\n",
            &metrics,
            conn,
        );

        let snapshot = metrics.snapshot();
        let stats = &snapshot.connections[0].methods["server.ping"];
        assert_eq!(stats.calls, 1);
        assert_eq!(stats.responses, 1);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn array_batch_counts_each_element() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        let line = br#"[{"id":1,"method":"a.one","params":[]},{"id":2,"method":"a.two","params":[]},{"id":3,"method":"a.three","params":[]}]
"#;
        attributor.feed(Direction::Up, line, &metrics, conn);

        let snapshot = metrics.snapshot();
        let conn_snap = &snapshot.connections[0];
        assert_eq!(conn_snap.methods["a.one"].calls, 1);
        assert_eq!(conn_snap.methods["a.two"].calls, 1);
        assert_eq!(conn_snap.methods["a.three"].calls, 1);

        // Each method's recorded bytes equal its own element's exact length.
        let elems: Vec<&RawValue> = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(
            conn_snap.methods["a.one"].bytes_up,
            elems[0].get().len() as u64
        );
        assert_eq!(
            conn_snap.methods["a.two"].bytes_up,
            elems[1].get().len() as u64
        );
        assert_eq!(
            conn_snap.methods["a.three"].bytes_up,
            elems[2].get().len() as u64
        );
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn newline_pipelined_batch_counts_each_line() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        let chunk = b"{\"id\":1,\"method\":\"a.one\",\"params\":[]}\n\
                       {\"id\":2,\"method\":\"a.two\",\"params\":[]}\n\
                       {\"id\":3,\"method\":\"a.three\",\"params\":[]}\n";
        attributor.feed(Direction::Up, chunk, &metrics, conn);

        let snapshot = metrics.snapshot();
        let conn_snap = &snapshot.connections[0];
        assert_eq!(conn_snap.methods["a.one"].calls, 1);
        assert_eq!(conn_snap.methods["a.two"].calls, 1);
        assert_eq!(conn_snap.methods["a.three"].calls, 1);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn notification_without_id_attributes_directly() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        attributor.feed(
            Direction::Down,
            br#"{"method":"blockchain.scripthash.subscribe","params":["abcd","status"]}
"#,
            &metrics,
            conn,
        );

        let snapshot = metrics.snapshot();
        let stats = &snapshot.connections[0].methods["blockchain.scripthash.subscribe"];
        assert_eq!(stats.responses, 1);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn line_split_across_feeds_is_reassembled() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        // "café" has a 2-byte UTF-8 sequence for 'é'; split right in the
        // middle of it.
        let line = "{\"id\":1,\"method\":\"server.ping\",\"params\":[\"café\"]}\n";
        let bytes = line.as_bytes();
        let split_at = bytes.len() - 2; // inside the 2-byte 'é' sequence
        attributor.feed(Direction::Up, &bytes[..split_at], &metrics, conn);
        attributor.feed(Direction::Up, &bytes[split_at..], &metrics, conn);

        let snapshot = metrics.snapshot();
        let stats = &snapshot.connections[0].methods["server.ping"];
        assert_eq!(stats.calls, 1);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn two_lines_in_one_feed_both_attribute() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        let chunk = b"{\"id\":1,\"method\":\"a.one\",\"params\":[]}\n{\"id\":2,\"method\":\"a.two\",\"params\":[]}\n";
        attributor.feed(Direction::Up, chunk, &metrics, conn);

        let snapshot = metrics.snapshot();
        let conn_snap = &snapshot.connections[0];
        assert_eq!(conn_snap.methods["a.one"].calls, 1);
        assert_eq!(conn_snap.methods["a.two"].calls, 1);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn colliding_ids_across_connections_do_not_cross_attribute() {
        let metrics = Metrics::new();
        let conn_a = metrics.open_conn();
        let conn_b = metrics.open_conn();
        let mut attributor_a = Attributor::new(None);
        let mut attributor_b = Attributor::new(None);

        attributor_a.feed(
            Direction::Up,
            b"{\"id\":1,\"method\":\"a.method\",\"params\":[]}\n",
            &metrics,
            conn_a,
        );
        attributor_b.feed(
            Direction::Up,
            b"{\"id\":1,\"method\":\"b.method\",\"params\":[]}\n",
            &metrics,
            conn_b,
        );

        attributor_a.feed(
            Direction::Down,
            b"{\"id\":1,\"result\":null}\n",
            &metrics,
            conn_a,
        );
        attributor_b.feed(
            Direction::Down,
            b"{\"id\":1,\"result\":null}\n",
            &metrics,
            conn_b,
        );

        let snapshot = metrics.snapshot();
        let a_snap = snapshot
            .connections
            .iter()
            .find(|c| c.id == conn_a)
            .unwrap();
        let b_snap = snapshot
            .connections
            .iter()
            .find(|c| c.id == conn_b)
            .unwrap();
        assert_eq!(a_snap.methods["a.method"].responses, 1);
        assert_eq!(b_snap.methods["b.method"].responses, 1);
        assert!(!a_snap.methods.contains_key("b.method"));
        assert!(!b_snap.methods.contains_key("a.method"));
        assert_zero_unattributed(&metrics, conn_a);
        assert_zero_unattributed(&metrics, conn_b);
    }

    #[test]
    fn unknown_response_id_is_unattributed() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        attributor.feed(
            Direction::Down,
            b"{\"id\":42,\"result\":null}\n",
            &metrics,
            conn,
        );

        let snapshot = metrics.snapshot();
        let snap = &snapshot.connections[0];
        assert_eq!(snap.unattributed.responses, 1);
    }

    #[test]
    fn array_batch_framing_plus_method_bytes_equals_line_length() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        let line =
            br#"[{"id":1,"method":"a.one","params":[]},{"id":2,"method":"a.two","params":[]}]
"#;
        attributor.feed(Direction::Up, line, &metrics, conn);

        let snapshot = metrics.snapshot();
        let conn_snap = &snapshot.connections[0];
        let method_bytes: u64 = conn_snap.methods.values().map(|m| m.bytes_up).sum();
        assert_eq!(method_bytes + conn_snap.framing_bytes_up, line.len() as u64);
        assert_zero_unattributed(&metrics, conn);
    }

    #[test]
    fn malformed_line_is_unattributed_not_panic() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        attributor.feed(Direction::Up, b"not json at all\n", &metrics, conn);
        attributor.feed(Direction::Down, b"not json at all\n", &metrics, conn);

        let snapshot = metrics.snapshot();
        let snap = &snapshot.connections[0];
        assert_eq!(snap.unattributed.calls, 1);
        assert_eq!(snap.unattributed.responses, 1);
    }

    #[test]
    fn array_of_bare_numbers_is_unattributed_not_panic() {
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(None);

        attributor.feed(Direction::Up, b"[1,2,3]\n", &metrics, conn);
        attributor.feed(Direction::Down, b"[1,2,3]\n", &metrics, conn);

        let snapshot = metrics.snapshot();
        let snap = &snapshot.connections[0];
        assert_eq!(snap.unattributed.calls, 3);
        assert_eq!(snap.unattributed.responses, 3);
    }

    fn temp_trace_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "bwk-mitm-attribute-trace-test-{name}-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ))
    }

    #[test]
    fn trace_emits_one_event_per_attributed_element_in_wire_order() {
        let path = temp_trace_path("order");
        let tracer = Arc::new(Tracer::new(&path).unwrap());
        let metrics = Metrics::new();
        let conn = metrics.open_conn();
        let mut attributor = Attributor::new(Some(tracer.clone()));

        attributor.feed(
            Direction::Up,
            b"{\"id\":1,\"method\":\"server.ping\",\"params\":[]}\n",
            &metrics,
            conn,
        );
        attributor.feed(
            Direction::Down,
            b"{\"id\":1,\"result\":null}\n",
            &metrics,
            conn,
        );
        attributor.feed(
            Direction::Down,
            b"{\"id\":99,\"result\":null}\n",
            &metrics,
            conn,
        );
        tracer.flush();

        let content = std::fs::read_to_string(&path).unwrap();
        let events: Vec<serde_json::Value> = content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events.len(), 3);

        assert_eq!(events[0]["dir"], "up");
        assert_eq!(events[0]["method"], "server.ping");
        assert_eq!(events[0]["id"], "1");
        assert_eq!(events[0]["bytes"], 43);

        assert_eq!(events[1]["dir"], "down");
        assert_eq!(events[1]["method"], "server.ping");
        assert_eq!(events[1]["id"], "1");

        assert_eq!(events[2]["dir"], "down");
        assert!(events[2]["method"].is_null());
        assert!(events[2]["id"].is_null());

        std::fs::remove_file(&path).unwrap();
    }
}
