//! Acceptor, per-direction workers, forwarding and teardown.
//!
//! One acceptor thread. Each accepted client connection dials its own
//! dedicated upstream connection and gets two worker threads, one per
//! direction. The client side and a `Plain` upstream do plain blocking
//! reads; a `Tls` upstream is polled non-blocking instead, since the
//! `TlsStream` is shared with the up worker (see [`UpstreamStream`]). Chunks
//! are forwarded verbatim and immediately; accounting happens on a parallel
//! copy fed to the connection's `Attributor`, so the proxy never delays a
//! byte or alters framing.

use std::{
    collections::HashMap,
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use bwk_backoff::Backoff;

use crate::{
    attribute::Attributor,
    error::Error,
    metrics::{ConnId, Direction, Metrics, Side},
    trace::Tracer,
    Upstream,
};

const BUF_SIZE: usize = 16 * 1024;

// Backoff ceiling for the shared TLS stream. Each attempt starts a fresh
// backoff in its `yield_now()` tier, so data already waiting is picked up
// without sleeping and only an idle connection reaches the ceiling. The
// ceiling caps how long a byte arriving mid-snooze sits unseen, which biases
// the reported time-to-first-byte, and measuring that is why this crate
// exists: one millisecond keeps the bias below the resolution anyone reads
// off a report, at the cost of waking an idle connection that often.
const TLS_SNOOZE_CAP_MS: u64 = 1;

/// The upstream (server-facing) half of a proxied connection. The
/// client-facing half is always a plain `TcpStream`; only this side can be
/// TLS-wrapped.
///
/// A `TlsStream` cannot be cloned or split, so the up (write) and down (read)
/// workers share one behind an `Arc<Mutex<_>>`. Its socket is non-blocking
/// (set once, after the handshake, in [`dial`]), so every read and write is a
/// syscall that returns at once: the mutex is held for one attempt only and
/// released before the backoff snoozes, and neither worker can starve the
/// other.
enum UpstreamStream {
    Plain(TcpStream),
    Tls(Arc<Mutex<native_tls::TlsStream<TcpStream>>>),
}

impl UpstreamStream {
    /// A handle to the same upstream connection for the other worker: an
    /// independent fd for `Plain`, a shared handle for `Tls`.
    fn dup(&self) -> io::Result<Self> {
        match self {
            Self::Plain(s) => Ok(Self::Plain(s.try_clone()?)),
            Self::Tls(stream) => Ok(Self::Tls(stream.clone())),
        }
    }

    /// A clone of the raw TCP layer, kept in the connection registry so
    /// [`Mitm::shutdown`] can end a worker's read loop without going through
    /// the TLS session.
    fn raw_clone(&self) -> io::Result<TcpStream> {
        match self {
            Self::Plain(s) => s.try_clone(),
            Self::Tls(stream) => stream.lock().expect("poisoned").get_ref().try_clone(),
        }
    }

    fn shutdown(&self) {
        match self {
            Self::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            Self::Tls(stream) => {
                let _ = stream
                    .lock()
                    .expect("poisoned")
                    .get_ref()
                    .shutdown(Shutdown::Both);
            }
        }
    }
}

/// Runs one `op` on the shared TLS stream, retrying while the non-blocking
/// socket is not ready. The lock is taken for the attempt and dropped at the
/// end of that statement, so `snooze` never runs holding it. A shut down
/// socket reports end of file or an error rather than `WouldBlock`, which is
/// what ends a worker's loop.
fn retry_while_not_ready<T>(
    stream: &Mutex<native_tls::TlsStream<TcpStream>>,
    mut op: impl FnMut(&mut native_tls::TlsStream<TcpStream>) -> io::Result<T>,
) -> io::Result<T> {
    let mut backoff = Backoff::new_ms(TLS_SNOOZE_CAP_MS);
    loop {
        let result = op(&mut stream.lock().expect("poisoned"));
        match result {
            Err(e) if e.kind() == ErrorKind::WouldBlock => backoff.snooze(),
            result => return result,
        }
    }
}

impl Read for UpstreamStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(stream) => retry_while_not_ready(stream, |tls| tls.read(buf)),
        }
    }
}

impl Write for UpstreamStream {
    /// Never reports `WouldBlock`: it retries until the TLS layer accepts
    /// some of `buf`, so the `write_all` above it keeps its blocking
    /// semantics and its own loop drains whatever is left unwritten.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(stream) => retry_while_not_ready(stream, |tls| tls.write(buf)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(stream) => retry_while_not_ready(stream, |tls| tls.flush()),
        }
    }
}

/// A worker's stream half: forwards bytes and unblocks its peer's blocking
/// read on teardown. Implemented by `TcpStream` (the client side, and the
/// `Plain` upstream path) and by `UpstreamStream` (the `Tls` upstream path).
trait Endpoint: Read + Write {
    fn shutdown_both(&self);
}

impl Endpoint for TcpStream {
    fn shutdown_both(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

impl Endpoint for UpstreamStream {
    fn shutdown_both(&self) {
        self.shutdown();
    }
}

struct ConnStreams {
    client: TcpStream,
    upstream: TcpStream,
}

type Registry = Arc<Mutex<HashMap<ConnId, ConnStreams>>>;

/// The per-connection state both direction workers share: the id they account
/// under, and the handles they account and tear down through.
#[derive(Clone)]
struct ConnContext {
    id: ConnId,
    metrics: Arc<Metrics>,
    attributor: Arc<Mutex<Attributor>>,
    closed: Arc<AtomicBool>,
    registry: Registry,
}

/// A running proxy instance. Dropping it leaves the acceptor and worker
/// threads running; call [`Mitm::shutdown`] to stop them.
pub struct Mitm {
    local_addr: SocketAddr,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    registry: Registry,
    acceptor: JoinHandle<()>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    tracer: Option<Arc<Tracer>>,
}

impl Mitm {
    pub(crate) fn bind(
        listen: SocketAddr,
        upstream: Upstream,
        tracer: Option<Arc<Tracer>>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(listen).map_err(|source| Error::Bind {
            addr: listen,
            source,
        })?;
        let local_addr = listener.local_addr().map_err(|source| Error::Bind {
            addr: listen,
            source,
        })?;

        let metrics = Metrics::new();
        let stop = Arc::new(AtomicBool::new(false));
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let workers = Arc::new(Mutex::new(Vec::new()));

        let acceptor = {
            let metrics = metrics.clone();
            let stop = stop.clone();
            let registry = registry.clone();
            let workers = workers.clone();
            let tracer = tracer.clone();
            thread::spawn(move || {
                accept_loop(listener, upstream, metrics, stop, registry, workers, tracer)
            })
        };

        Ok(Self {
            local_addr,
            metrics,
            stop,
            registry,
            acceptor,
            workers,
            tracer,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Stops the acceptor and every live worker, then joins all threads.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock the acceptor's blocking `accept()` with a throwaway dial.
        let _ = TcpStream::connect(self.local_addr);
        let _ = self.acceptor.join();

        let streams = std::mem::take(&mut *self.registry.lock().expect("poisoned"));
        for conn in streams.values() {
            let _ = conn.client.shutdown(Shutdown::Both);
            let _ = conn.upstream.shutdown(Shutdown::Both);
        }

        let workers = std::mem::take(&mut *self.workers.lock().expect("poisoned"));
        for worker in workers {
            let _ = worker.join();
        }

        if let Some(tracer) = &self.tracer {
            tracer.flush();
        }
    }
}

/// The hostname part of a `host:port` string, for SNI and certificate
/// hostname validation (the resolved IP must never be passed there).
fn host_of(target: &str) -> &str {
    match target.rfind(':') {
        Some(idx) => &target[..idx],
        None => target,
    }
}

fn dial(upstream: &Upstream) -> Result<UpstreamStream, Error> {
    match upstream {
        Upstream::Plain(addr) => {
            let stream = TcpStream::connect(addr).map_err(|source| Error::Dial {
                addr: addr.clone(),
                source,
            })?;
            Ok(UpstreamStream::Plain(stream))
        }
        Upstream::Tls {
            target,
            verify_cert,
        } => {
            let tcp = TcpStream::connect(target).map_err(|source| Error::Dial {
                addr: target.clone(),
                source,
            })?;
            let mut builder = native_tls::TlsConnector::builder();
            if !verify_cert {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            let connector = builder.build()?;
            // Handshake first, on the still-blocking socket, so it needs no
            // retry loop of its own; the socket goes non-blocking once, here,
            // and stays that way for both workers.
            let tls =
                connector
                    .connect(host_of(target), tcp)
                    .map_err(|source| Error::TlsHandshake {
                        addr: target.clone(),
                        source,
                    })?;
            tls.get_ref().set_nonblocking(true)?;
            Ok(UpstreamStream::Tls(Arc::new(Mutex::new(tls))))
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    upstream: Upstream,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    registry: Registry,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    tracer: Option<Arc<Tracer>>,
) {
    loop {
        let client = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                log::error!("bwk-mitm: accept failed: {e}");
                continue;
            }
        };
        // A stopped proxy's throwaway unblocking dial lands here too.
        if stop.load(Ordering::SeqCst) {
            return;
        }

        let id = metrics.open_conn();
        if let Some((up, down)) =
            spawn_connection(client, id, &upstream, &metrics, &registry, tracer.clone())
        {
            let mut workers = workers.lock().expect("poisoned");
            workers.push(up);
            workers.push(down);
        }
    }
}

/// Clones `stream`, logging and returning `None` on failure so the caller can
/// tear the connection down instead of panicking on a resource exhaustion
/// edge case.
fn try_clone(stream: &TcpStream, what: &str, id: ConnId) -> Option<TcpStream> {
    match stream.try_clone() {
        Ok(s) => Some(s),
        Err(e) => {
            log::error!("bwk-mitm: failed to clone {what} stream for conn {id}: {e}");
            None
        }
    }
}

fn spawn_connection(
    client: TcpStream,
    id: ConnId,
    upstream: &Upstream,
    metrics: &Arc<Metrics>,
    registry: &Registry,
    tracer: Option<Arc<Tracer>>,
) -> Option<(JoinHandle<()>, JoinHandle<()>)> {
    let upstream_stream = match dial(upstream) {
        Ok(s) => s,
        Err(e) => {
            log::error!("bwk-mitm: {e}");
            let _ = client.shutdown(Shutdown::Both);
            metrics.close_conn(id, Side::Server, false, Some(e.to_string()));
            return None;
        }
    };

    let client_clones = (
        try_clone(&client, "client", id),
        try_clone(&client, "client", id),
    );
    let upstream_clones = (upstream_stream.dup().ok(), upstream_stream.raw_clone().ok());
    let ((client_src, client_reg), (upstream_dst, upstream_reg)) =
        match (client_clones, upstream_clones) {
            ((Some(a), Some(b)), (Some(c), Some(d))) => ((a, b), (c, d)),
            _ => {
                log::error!("bwk-mitm: failed to clone stream for conn {id}");
                let _ = client.shutdown(Shutdown::Both);
                upstream_stream.shutdown();
                metrics.close_conn(
                    id,
                    Side::Server,
                    false,
                    Some("failed to clone stream".to_string()),
                );
                return None;
            }
        };

    registry.lock().expect("poisoned").insert(
        id,
        ConnStreams {
            client: client_reg,
            upstream: upstream_reg,
        },
    );

    let ctx = ConnContext {
        id,
        metrics: metrics.clone(),
        attributor: Arc::new(Mutex::new(Attributor::new(tracer))),
        closed: Arc::new(AtomicBool::new(false)),
        registry: registry.clone(),
    };

    let up = {
        let ctx = ctx.clone();
        thread::spawn(move || worker(ctx, Direction::Up, client_src, upstream_dst))
    };

    let down = thread::spawn(move || worker(ctx, Direction::Down, upstream_stream, client));

    Some((up, down))
}

/// One direction of one connection. `up` (wallet to server) accounts before
/// forwarding, so the id-to-method map is populated before the request can
/// reach the server and a response can race it back. `down` forwards before
/// accounting, since responses carry the bulk of the bytes and nothing
/// downstream depends on that accounting being done first.
fn worker<S: Endpoint, D: Endpoint>(ctx: ConnContext, dir: Direction, mut src: S, mut dst: D) {
    let mut buf = [0u8; BUF_SIZE];
    let (side, clean, error) = loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break (read_close_side(dir), true, None),
            Err(e) => break (read_close_side(dir), false, Some(e.to_string())),
            Ok(n) => n,
        };
        ctx.metrics.record_activity(ctx.id);
        match dir {
            Direction::Up => {
                ctx.attributor.lock().expect("poisoned").feed(
                    Direction::Up,
                    &buf[..n],
                    &ctx.metrics,
                    ctx.id,
                );
                if let Err(e) = dst.write_all(&buf[..n]).and_then(|_| dst.flush()) {
                    break (write_close_side(dir), false, Some(e.to_string()));
                }
            }
            Direction::Down => {
                if let Err(e) = dst.write_all(&buf[..n]).and_then(|_| dst.flush()) {
                    break (write_close_side(dir), false, Some(e.to_string()));
                }
                ctx.attributor.lock().expect("poisoned").feed(
                    Direction::Down,
                    &buf[..n],
                    &ctx.metrics,
                    ctx.id,
                );
            }
        }
    };
    src.shutdown_both();
    dst.shutdown_both();
    if !ctx.closed.swap(true, Ordering::SeqCst) {
        ctx.metrics.close_conn(ctx.id, side, clean, error);
        ctx.registry.lock().expect("poisoned").remove(&ctx.id);
    }
}

/// The side whose `read()` ending the loop (EOF or error) closed the
/// connection: `up` reads from the client, `down` reads from the server.
fn read_close_side(dir: Direction) -> Side {
    match dir {
        Direction::Up => Side::Client,
        Direction::Down => Side::Server,
    }
}

/// The side whose forwarding write failing closed the connection: a failed
/// write means the *other* end of that direction is already gone.
fn write_close_side(dir: Direction) -> Side {
    match dir {
        Direction::Up => Side::Server,
        Direction::Down => Side::Client,
    }
}
