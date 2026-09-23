use std::{
    io,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("failed to open trace file {}: {source}", path.display())]
    TraceOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to dial upstream {addr}: {source}")]
    Dial {
        addr: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to configure TLS connector: {0}")]
    TlsConfig(#[from] native_tls::Error),
    #[error("TLS handshake with {addr} failed: {source}")]
    TlsHandshake {
        addr: String,
        #[source]
        source: native_tls::HandshakeError<TcpStream>,
    },
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("failed to serialize snapshot: {0}")]
    Json(#[from] serde_json::Error),
}
