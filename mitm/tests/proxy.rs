use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use bwk_mitm::{
    metrics::{Side, Snapshot},
    proxy::Mitm,
    trace::Tracer,
    Upstream,
};
use native_tls::{Identity, TlsAcceptor, TlsStream};

/// A fake Electrum server: reads newline-delimited lines and looks each one
/// up in a script to decide what to write back. Runs until the client
/// disconnects.
fn spawn_fake_upstream(script: Vec<(String, String)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let script = script.clone();
            thread::spawn(move || serve_fake_upstream(stream, script));
        }
    });
    addr
}

fn serve_fake_upstream(mut stream: TcpStream, script: Vec<(String, String)>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let rest = buf.split_off(pos + 1);
            let mut line = std::mem::replace(&mut buf, rest);
            line.pop();
            let line = String::from_utf8(line).unwrap();
            if let Some((_, resp)) = script.iter().find(|(req, _)| *req == line) {
                if stream.write_all(resp.as_bytes()).is_err() {
                    return;
                }
            }
        }
    }
}

/// A fake upstream that runs an arbitrary handler per accepted connection,
/// for scenarios the script-based fake upstream can't express (custom
/// close behaviour, reordered responses, delayed responses).
fn spawn_custom_upstream<F>(handler: F) -> SocketAddr
where
    F: Fn(TcpStream) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = handler.clone();
            thread::spawn(move || handler(stream));
        }
    });
    addr
}

/// Reads exactly `responses.len()` newline-delimited request lines, then
/// writes back `responses` in reverse order, to exercise out-of-order
/// response detection.
fn serve_reordered(mut stream: TcpStream, responses: Vec<String>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut lines_seen = 0;
    while lines_seen < responses.len() {
        let n = match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let rest = buf.split_off(pos + 1);
            buf = rest;
            lines_seen += 1;
        }
    }
    for resp in responses.iter().rev() {
        if stream.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

fn connect_proxy(upstream_addr: SocketAddr) -> (Mitm, TcpStream) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(listen, Upstream::Plain(upstream_addr.to_string()), None).unwrap();
    let client = TcpStream::connect(mitm.local_addr()).unwrap();
    (mitm, client)
}

fn read_exact_len(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).unwrap();
    buf
}

/// Busy-polls the metrics snapshot until `pred` holds, with a timeout so a
/// regression fails the test instead of hanging it.
fn wait_for_snapshot(mitm: &Mitm, pred: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = mitm.metrics().snapshot();
        if pred(&snapshot) {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "timed out waiting for snapshot");
        thread::yield_now();
    }
}

#[test]
fn byte_identical_passthrough() {
    let request = "{\"id\":1,\"method\":\"server.ping\",\"params\":[]}";
    let response = "{\"id\":1,\"result\":null}\n";
    let upstream_addr = spawn_fake_upstream(vec![(request.to_string(), response.to_string())]);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let got = read_exact_len(&mut client, response.len());
    assert_eq!(got, response.as_bytes());

    mitm.shutdown();
}

#[test]
fn accounting_matches_wire_bytes() {
    let request = "{\"id\":1,\"method\":\"server.ping\",\"params\":[]}";
    let response = "{\"id\":1,\"result\":null}\n";
    let upstream_addr = spawn_fake_upstream(vec![(request.to_string(), response.to_string())]);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let _ = read_exact_len(&mut client, response.len());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections.first().is_some_and(|c| {
            c.methods
                .get("server.ping")
                .is_some_and(|m| m.responses >= 1)
        })
    });
    let conn = &snapshot.connections[0];

    let bytes_up: u64 = conn.methods.values().map(|m| m.bytes_up).sum();
    let bytes_down: u64 = conn.methods.values().map(|m| m.bytes_down).sum();
    assert_eq!(bytes_up + conn.framing_bytes_up, request.len() as u64 + 1);
    assert_eq!(bytes_down + conn.framing_bytes_down, response.len() as u64);

    drop(client);
    mitm.shutdown();
}

/// One request line: a JSON array batch of three calls with the given ids.
fn batch_request(ids: [u64; 3]) -> String {
    format!(
        "[{{\"id\":{},\"method\":\"batch.one\",\"params\":[]}},\
         {{\"id\":{},\"method\":\"batch.two\",\"params\":[]}},\
         {{\"id\":{},\"method\":\"batch.three\",\"params\":[]}}]",
        ids[0], ids[1], ids[2]
    )
}

/// The matching response line, one array element per request id.
fn batch_response(ids: [u64; 3]) -> String {
    format!(
        "[{{\"id\":{},\"result\":\"one\"}},\
         {{\"id\":{},\"result\":\"two\"}},\
         {{\"id\":{},\"result\":\"three\"}}]\n",
        ids[0], ids[1], ids[2]
    )
}

/// Every line of a direction has the same length here, so the bytes accounted
/// for a direction (per method, unattributed and framing) must always be a
/// whole number of lines. Returns a description of the first total that is
/// not, meaning the snapshot caught a line half accounted.
fn partial_line(snapshot: &Snapshot, up_line: u64, down_line: u64) -> Option<String> {
    for conn in &snapshot.connections {
        let up: u64 = conn.methods.values().map(|m| m.bytes_up).sum::<u64>()
            + conn.unattributed.bytes_up
            + conn.framing_bytes_up;
        if up % up_line != 0 {
            return Some(format!(
                "conn {}: {up} bytes up is not a whole number of {up_line} byte request lines",
                conn.id
            ));
        }
        let down: u64 = conn.methods.values().map(|m| m.bytes_down).sum::<u64>()
            + conn.unattributed.bytes_down
            + conn.framing_bytes_down;
        if down % down_line != 0 {
            return Some(format!(
                "conn {}: {down} bytes down is not a whole number of {down_line} byte response lines",
                conn.id
            ));
        }
    }
    None
}

#[test]
fn concurrent_snapshots_never_see_a_partly_accounted_line() {
    const ROUNDS: u64 = 200;

    let rounds: Vec<[u64; 3]> = (0..ROUNDS)
        .map(|round| {
            let base = 100 + round * 3;
            [base, base + 1, base + 2]
        })
        .collect();
    let script: Vec<(String, String)> = rounds
        .iter()
        .map(|ids| (batch_request(*ids), batch_response(*ids)))
        .collect();
    let up_line = batch_request(rounds[0]).len() as u64 + 1;
    let down_line = batch_response(rounds[0]).len() as u64;

    let upstream_addr = spawn_fake_upstream(script.clone());
    let (mitm, mut client) = connect_proxy(upstream_addr);

    let done = Arc::new(AtomicBool::new(false));
    let checker = {
        let metrics = mitm.metrics();
        let done = done.clone();
        thread::spawn(move || {
            let mut violation = None;
            while violation.is_none() && !done.load(Ordering::Relaxed) {
                violation = partial_line(&metrics.snapshot(), up_line, down_line);
            }
            violation
        })
    };

    let writer = {
        let mut sink = client.try_clone().unwrap();
        let requests: String = script.iter().map(|(req, _)| format!("{req}\n")).collect();
        thread::spawn(move || sink.write_all(requests.as_bytes()).unwrap())
    };
    let response_bytes: usize = script.iter().map(|(_, resp)| resp.len()).sum();
    let _ = read_exact_len(&mut client, response_bytes);
    writer.join().unwrap();

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.methods.values().map(|m| m.responses).sum::<u64>() >= 3 * ROUNDS)
    });
    done.store(true, Ordering::Relaxed);
    if let Some(violation) = checker.join().unwrap() {
        panic!("{violation}");
    }

    let conn = &snapshot.connections[0];
    let bytes_up: u64 = conn.methods.values().map(|m| m.bytes_up).sum();
    let bytes_down: u64 = conn.methods.values().map(|m| m.bytes_down).sum();
    assert_eq!(bytes_up + conn.framing_bytes_up, ROUNDS * up_line);
    assert_eq!(bytes_down + conn.framing_bytes_down, ROUNDS * down_line);
    assert_eq!(conn.unattributed.calls, 0);
    assert_eq!(conn.unattributed.responses, 0);

    mitm.shutdown();
}

#[test]
fn two_connections_with_colliding_ids_attribute_independently() {
    let request_a = "{\"id\":1,\"method\":\"a.method\",\"params\":[]}";
    let response_a = "{\"id\":1,\"result\":\"a\"}\n";
    let request_b = "{\"id\":1,\"method\":\"b.method\",\"params\":[]}";
    let response_b = "{\"id\":1,\"result\":\"b\"}\n";
    let upstream_addr = spawn_fake_upstream(vec![
        (request_a.to_string(), response_a.to_string()),
        (request_b.to_string(), response_b.to_string()),
    ]);

    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(listen, Upstream::Plain(upstream_addr.to_string()), None).unwrap();
    let mut client_a = TcpStream::connect(mitm.local_addr()).unwrap();
    let mut client_b = TcpStream::connect(mitm.local_addr()).unwrap();

    client_a
        .write_all(format!("{request_a}\n").as_bytes())
        .unwrap();
    client_b
        .write_all(format!("{request_b}\n").as_bytes())
        .unwrap();
    assert_eq!(
        read_exact_len(&mut client_a, response_a.len()),
        response_a.as_bytes()
    );
    assert_eq!(
        read_exact_len(&mut client_b, response_b.len()),
        response_b.as_bytes()
    );

    let snapshot = wait_for_snapshot(&mitm, |snap| snap.connections.len() >= 2);
    assert_eq!(snapshot.connections.len(), 2);
    assert!(snapshot
        .connections
        .iter()
        .any(|c| c.methods.contains_key("a.method")));
    assert!(snapshot
        .connections
        .iter()
        .any(|c| c.methods.contains_key("b.method")));

    mitm.shutdown();
}

#[test]
fn large_response_arrives_intact_and_attributed_once() {
    let request = "{\"id\":1,\"method\":\"big.get\",\"params\":[]}";
    let payload = "x".repeat(200_000);
    let response = format!("{{\"id\":1,\"result\":\"{payload}\"}}\n");
    let upstream_addr = spawn_fake_upstream(vec![(request.to_string(), response.clone())]);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let got = read_exact_len(&mut client, response.len());
    assert_eq!(got, response.as_bytes());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.methods.get("big.get").is_some_and(|m| m.responses >= 1))
    });
    let stats = &snapshot.connections[0].methods["big.get"];
    assert_eq!(stats.responses, 1);
    assert_eq!(stats.bytes_down, response.len() as u64 - 1);

    mitm.shutdown();
}

#[test]
fn reconnect_appears_as_distinct_connections() {
    let upstream_addr = spawn_fake_upstream(vec![]);
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(listen, Upstream::Plain(upstream_addr.to_string()), None).unwrap();

    let first = TcpStream::connect(mitm.local_addr()).unwrap();
    let snapshot = wait_for_snapshot(&mitm, |snap| !snap.connections.is_empty());
    let first_id = snapshot.connections[0].id;
    drop(first);
    let _ = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .iter()
            .any(|c| c.id == first_id && c.closed_at.is_some())
    });

    let second = TcpStream::connect(mitm.local_addr()).unwrap();
    let snapshot = wait_for_snapshot(&mitm, |snap| snap.connections.len() >= 2);
    drop(second);

    assert_eq!(snapshot.connections.len(), 2);
    let first_snap = snapshot
        .connections
        .iter()
        .find(|c| c.id == first_id)
        .unwrap();
    assert!(first_snap.closed_at.is_some());
    assert!(snapshot.connections.iter().any(|c| c.id != first_id));

    mitm.shutdown();
}

#[test]
fn shutdown_with_no_connections_returns_promptly() {
    let upstream_addr = spawn_fake_upstream(vec![]);
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(listen, Upstream::Plain(upstream_addr.to_string()), None).unwrap();
    mitm.shutdown();
}

#[test]
fn shutdown_with_live_connections_joins_cleanly() {
    let upstream_addr = spawn_fake_upstream(vec![]);
    let (mitm, _client) = connect_proxy(upstream_addr);
    let _ = wait_for_snapshot(&mitm, |snap| !snap.connections.is_empty());
    mitm.shutdown();
}

#[test]
fn failed_upstream_dial_does_not_kill_acceptor() {
    let dead_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(listen, Upstream::Plain(dead_addr.to_string()), None).unwrap();

    let first = TcpStream::connect(mitm.local_addr()).unwrap();
    drop(first);
    let second = TcpStream::connect(mitm.local_addr()).unwrap();
    drop(second);

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections.len() >= 2 && snap.connections.iter().all(|c| c.closed_at.is_some())
    });
    assert_eq!(snapshot.connections.len(), 2);

    mitm.shutdown();
}

#[test]
fn error_response_is_bucketed_by_method_and_code() {
    let request = "{\"id\":1,\"method\":\"blockchain.transaction.get\",\"params\":[]}";
    let response = "{\"id\":1,\"error\":{\"code\":-32601,\"message\":\"boom\"}}\n";
    let upstream_addr = spawn_fake_upstream(vec![(request.to_string(), response.to_string())]);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let _ = read_exact_len(&mut client, response.len());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| !c.errors.is_empty())
    });
    let conn = &snapshot.connections[0];
    let bucket = conn
        .errors
        .values()
        .find(|b| b.method == "blockchain.transaction.get" && b.code == -32601)
        .unwrap();
    assert_eq!(bucket.count, 1);
    assert_eq!(bucket.sample, "boom");
    let stats = &conn.methods["blockchain.transaction.get"];
    assert_eq!(stats.responses, 1);

    mitm.shutdown();
}

#[test]
fn pipelined_requests_answered_in_reverse_order_are_detected() {
    let requests = [
        "{\"id\":1,\"method\":\"a.one\",\"params\":[]}",
        "{\"id\":2,\"method\":\"a.two\",\"params\":[]}",
        "{\"id\":3,\"method\":\"a.three\",\"params\":[]}",
    ];
    let responses: Vec<String> = (1..=3)
        .map(|id| format!("{{\"id\":{id},\"result\":null}}\n"))
        .collect();
    let upstream_addr = {
        let responses = responses.clone();
        spawn_custom_upstream(move |stream| serve_reordered(stream, responses.clone()))
    };
    let (mitm, mut client) = connect_proxy(upstream_addr);

    let mut pipeline = String::new();
    for req in requests {
        pipeline.push_str(req);
        pipeline.push('\n');
    }
    client.write_all(pipeline.as_bytes()).unwrap();
    let total_len: usize = responses.iter().map(|r| r.len()).sum();
    let _ = read_exact_len(&mut client, total_len);

    // Forwarding to the client happens before accounting (see the `worker`
    // doc comment in proxy.rs), so reading all response bytes back doesn't
    // guarantee attribution for all of them has completed yet: wait for the
    // full response count too, not just any nonzero out-of-order count.
    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.methods.values().map(|m| m.responses).sum::<u64>() >= 3)
    });
    let order = snapshot.connections[0].order;
    assert_eq!(order.out_of_order, 2);
    assert_eq!(order.max_displacement, 2);

    mitm.shutdown();
}

#[test]
fn pipelined_requests_answered_in_order_have_zero_out_of_order() {
    let requests = [
        "{\"id\":1,\"method\":\"a.one\",\"params\":[]}",
        "{\"id\":2,\"method\":\"a.two\",\"params\":[]}",
        "{\"id\":3,\"method\":\"a.three\",\"params\":[]}",
    ];
    let responses = [
        "{\"id\":1,\"result\":null}\n",
        "{\"id\":2,\"result\":null}\n",
        "{\"id\":3,\"result\":null}\n",
    ];
    let script = requests
        .iter()
        .zip(responses.iter())
        .map(|(req, resp)| (req.to_string(), resp.to_string()))
        .collect();
    let upstream_addr = spawn_fake_upstream(script);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    let mut pipeline = String::new();
    for req in requests {
        pipeline.push_str(req);
        pipeline.push('\n');
    }
    client.write_all(pipeline.as_bytes()).unwrap();
    let total_len: usize = responses.iter().map(|r| r.len()).sum();
    let _ = read_exact_len(&mut client, total_len);

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.methods.values().map(|m| m.responses).sum::<u64>() >= 3)
    });
    let order = snapshot.connections[0].order;
    assert_eq!(order.out_of_order, 0);
    assert_eq!(order.max_displacement, 0);

    mitm.shutdown();
}

#[test]
fn server_closing_first_is_attributed_to_server() {
    let upstream_addr = spawn_custom_upstream(drop);
    let (mitm, client) = connect_proxy(upstream_addr);

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections.first().is_some_and(|c| c.close.is_some())
    });
    let close = snapshot.connections[0].close.clone().unwrap();
    assert_eq!(close.closed_by, Side::Server);
    assert!(close.clean);

    drop(client);
    mitm.shutdown();
}

#[test]
fn client_closing_first_is_attributed_to_client() {
    let upstream_addr = spawn_fake_upstream(vec![]);
    let (mitm, client) = connect_proxy(upstream_addr);
    let _ = wait_for_snapshot(&mitm, |snap| !snap.connections.is_empty());
    drop(client);

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections.first().is_some_and(|c| c.close.is_some())
    });
    let close = snapshot.connections[0].close.clone().unwrap();
    assert_eq!(close.closed_by, Side::Client);
    assert!(close.clean);

    mitm.shutdown();
}

#[test]
fn largest_request_and_response_lines_are_tracked() {
    let small_req = "{\"id\":1,\"method\":\"a.one\",\"params\":[]}";
    let small_resp = "{\"id\":1,\"result\":null}\n";
    let big_req = format!(
        "{{\"id\":2,\"method\":\"a.two\",\"params\":[\"{}\"]}}",
        "x".repeat(500)
    );
    let big_resp = format!("{{\"id\":2,\"result\":\"{}\"}}\n", "y".repeat(800));
    let upstream_addr = spawn_fake_upstream(vec![
        (small_req.to_string(), small_resp.to_string()),
        (big_req.clone(), big_resp.clone()),
    ]);
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client
        .write_all(format!("{small_req}\n").as_bytes())
        .unwrap();
    let _ = read_exact_len(&mut client, small_resp.len());
    client.write_all(format!("{big_req}\n").as_bytes()).unwrap();
    let _ = read_exact_len(&mut client, big_resp.len());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.largest_response_line as usize >= big_resp.len() - 1)
    });
    let conn = &snapshot.connections[0];
    assert_eq!(conn.largest_request_line, big_req.len() as u64);
    assert_eq!(conn.largest_response_line, big_resp.len() as u64 - 1);

    mitm.shutdown();
}

#[test]
fn ttfb_is_recorded_for_method() {
    let request = "{\"id\":1,\"method\":\"server.ping\",\"params\":[]}";
    let response = "{\"id\":1,\"result\":null}\n";
    let upstream_addr = spawn_custom_upstream(move |mut stream| {
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        thread::sleep(Duration::from_millis(20));
        let _ = stream.write_all(response.as_bytes());
    });
    let (mitm, mut client) = connect_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let _ = read_exact_len(&mut client, response.len());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections.first().is_some_and(|c| {
            c.methods
                .get("server.ping")
                .is_some_and(|m| m.ttfb.count > 0)
        })
    });
    let ttfb = &snapshot.connections[0].methods["server.ping"].ttfb;
    assert_eq!(ttfb.count, 1);
    assert!(ttfb.min_secs > 0.0);
    assert!(ttfb.max_secs >= ttfb.min_secs);
    assert!(ttfb.mean_secs() > 0.0);

    mitm.shutdown();
}

/// A unique temp path per test, so tests using `--trace` can run in
/// parallel without colliding on the same file.
fn temp_trace_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "bwk-mitm-proxy-trace-{name}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ))
}

#[test]
fn trace_produces_one_valid_json_line_per_attributed_element() {
    let request = "{\"id\":1,\"method\":\"server.ping\",\"params\":[]}";
    let response = "{\"id\":1,\"result\":null}\n";
    let upstream_addr = spawn_fake_upstream(vec![(request.to_string(), response.to_string())]);

    let path = temp_trace_path("basic");
    let tracer = Arc::new(Tracer::new(&path).unwrap());
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mitm = bwk_mitm::bind(
        listen,
        Upstream::Plain(upstream_addr.to_string()),
        Some(tracer),
    )
    .unwrap();
    let mut client = TcpStream::connect(mitm.local_addr()).unwrap();

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let _ = read_exact_len(&mut client, response.len());

    let _ = wait_for_snapshot(&mitm, |snap| {
        snap.connections.first().is_some_and(|c| {
            c.methods
                .get("server.ping")
                .is_some_and(|m| m.responses >= 1)
        })
    });

    mitm.shutdown();

    let content = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    let mut last_elapsed = 0.0;
    for line in &lines {
        assert!(!line.contains("server.ping\",\"params"));
        assert!(!line.contains("\"result\""));
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        let elapsed = value["elapsed_secs"].as_f64().unwrap();
        assert!(elapsed >= last_elapsed);
        last_elapsed = elapsed;
    }

    let up: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect();
    assert_eq!(up[0]["dir"], "up");
    assert_eq!(up[0]["method"], "server.ping");
    assert_eq!(up[0]["id"], "1");
    assert_eq!(up[1]["dir"], "down");
    assert_eq!(up[1]["method"], "server.ping");
    assert_eq!(up[1]["id"], "1");

    fs::remove_file(&path).unwrap();
}

#[test]
fn trace_omitted_when_no_path_given() {
    let upstream_addr = spawn_fake_upstream(vec![]);
    let (mitm, client) = connect_proxy(upstream_addr);
    let _ = wait_for_snapshot(&mitm, |snap| !snap.connections.is_empty());
    drop(client);
    mitm.shutdown();
}

#[test]
fn bad_trace_path_fails_loudly() {
    let path = std::path::PathBuf::from("/nonexistent-dir/does-not-exist/trace.jsonl");
    let err = Tracer::new(&path).unwrap_err();
    assert!(err.to_string().contains("trace"));
}

/// PKCS#12 identity for the fake TLS upstream, and its password. CN=localhost
/// with SAN DNS:localhost and IP:127.0.0.1.
const TLS_IDENTITY: &[u8] = include_bytes!("fixtures/localhost.p12");
const TLS_IDENTITY_PASSWORD: &str = "test";

/// A fake TLS upstream that runs `handler` per accepted connection, once the
/// handshake has completed.
fn spawn_tls_upstream<F>(handler: F) -> SocketAddr
where
    F: Fn(TlsStream<TcpStream>) + Send + Sync + 'static,
{
    let identity = Identity::from_pkcs12(TLS_IDENTITY, TLS_IDENTITY_PASSWORD).unwrap();
    let acceptor = Arc::new(TlsAcceptor::new(identity).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let acceptor = acceptor.clone();
            let handler = handler.clone();
            thread::spawn(move || {
                if let Ok(tls) = acceptor.accept(stream) {
                    handler(tls);
                }
            });
        }
    });
    addr
}

/// The fixture certificate is self-signed, so the proxy dials with
/// verification off; the client socket gets a read timeout so a starved
/// worker fails the test instead of hanging it.
fn connect_tls_proxy(upstream_addr: SocketAddr) -> (Mitm, TcpStream) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let upstream = Upstream::Tls {
        target: upstream_addr.to_string(),
        verify_cert: false,
    };
    let mitm = bwk_mitm::bind(listen, upstream, None).unwrap();
    let client = TcpStream::connect(mitm.local_addr()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (mitm, client)
}

/// Answers one response line per received request line, waiting `think_time`
/// before each answer. That wait is what makes the down worker sit on the
/// shared TLS stream while the up worker needs it to send the next request.
fn serve_tls_lines(mut tls: TlsStream<TcpStream>, think_time: Duration, responses: Vec<String>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut served = 0;
    while served < responses.len() {
        match tls.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        while served < responses.len() {
            let Some(pos) = buf.iter().position(|b| *b == b'\n') else {
                break;
            };
            buf = buf.split_off(pos + 1);
            thread::sleep(think_time);
            if tls.write_all(responses[served].as_bytes()).is_err() {
                return;
            }
            served += 1;
        }
    }
}

#[test]
fn tls_upstream_answers_every_request_of_a_slow_conversation() {
    const ROUNDS: usize = 5;
    const THINK_TIME: Duration = Duration::from_millis(200);

    let responses: Vec<String> = (1..=ROUNDS)
        .map(|id| format!("{{\"id\":{id},\"result\":null}}\n"))
        .collect();
    let upstream_addr = {
        let responses = responses.clone();
        spawn_tls_upstream(move |tls| serve_tls_lines(tls, THINK_TIME, responses.clone()))
    };
    let (mitm, mut client) = connect_tls_proxy(upstream_addr);

    let started = Instant::now();
    for (round, response) in responses.iter().enumerate() {
        let request = format!(
            "{{\"id\":{},\"method\":\"server.ping\",\"params\":[]}}\n",
            round + 1
        );
        client.write_all(request.as_bytes()).unwrap();
        let got = read_exact_len(&mut client, response.len());
        assert_eq!(got, response.as_bytes());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "{ROUNDS} round trips of {THINK_TIME:?} took {elapsed:?}"
    );

    mitm.shutdown();
}

#[test]
fn tls_forwards_bytes_unchanged_in_both_directions() {
    let request = format!(
        "{{\"id\":1,\"method\":\"big.get\",\"params\":[\"{}\"]}}",
        "q".repeat(5_000)
    );
    let response = format!("{{\"id\":1,\"result\":\"{}\"}}\n", "x".repeat(100_000));

    let (sender, received) = mpsc::channel();
    let upstream_addr = {
        let sender = Mutex::new(sender);
        let response = response.clone();
        spawn_tls_upstream(move |mut tls| {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            while !buf.contains(&b'\n') {
                match tls.read(&mut tmp) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let _ = sender.lock().unwrap().send(buf);
            let _ = tls.write_all(response.as_bytes());
        })
    };
    let (mitm, mut client) = connect_tls_proxy(upstream_addr);

    client.write_all(format!("{request}\n").as_bytes()).unwrap();
    let got = read_exact_len(&mut client, response.len());
    assert_eq!(got, response.as_bytes());
    let seen = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(seen, format!("{request}\n").into_bytes());

    let snapshot = wait_for_snapshot(&mitm, |snap| {
        snap.connections
            .first()
            .is_some_and(|c| c.methods.get("big.get").is_some_and(|m| m.responses >= 1))
    });
    let stats = &snapshot.connections[0].methods["big.get"];
    assert_eq!(stats.calls, 1);
    assert_eq!(stats.responses, 1);
    assert_eq!(stats.bytes_up, request.len() as u64);
    assert_eq!(stats.bytes_down, response.len() as u64 - 1);

    mitm.shutdown();
}
