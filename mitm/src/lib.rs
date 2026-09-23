//! Counting MITM proxy for the Electrum protocol.

pub mod attribute;
pub mod error;
pub mod metrics;
pub mod proxy;
pub mod trace;

use std::{net::SocketAddr, sync::Arc};

/// Where the proxy forwards traffic to. The wallet-facing (client) side is
/// always plaintext; only the upstream connection can be wrapped in TLS.
#[derive(Debug, Clone)]
pub enum Upstream {
    Plain(String),
    Tls { target: String, verify_cert: bool },
}

/// Binds `listen` and spawns the acceptor thread forwarding to `upstream`.
/// `tracer`, when set, receives one event per attributed wire element.
pub fn bind(
    listen: SocketAddr,
    upstream: Upstream,
    tracer: Option<Arc<trace::Tracer>>,
) -> Result<proxy::Mitm, error::Error> {
    proxy::Mitm::bind(listen, upstream, tracer)
}
