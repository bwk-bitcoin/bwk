pub(crate) mod ssl_client;
pub(crate) mod tcp_client;

use std::{
    collections::HashMap,
    fmt::Display,
    io::{ErrorKind, Read},
    net, thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::electrum::{
    self,
    request::Request,
    response::{parse_str_response, Response},
};

use self::{ssl_client::SslClient, tcp_client::TcpClient};

// Using a 1 byte seek buffer
pub const PEEK_BUFFER_SIZE: usize = 10;
const TCP_READ_BUFFER_SIZE: usize = 8192;
const TLS_READ_BUFFER_SIZE: usize = 1024;

pub trait ElectrumRead: Read {
    const BUFFER_SIZE: usize;

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), Error>;
}

impl ElectrumRead for net::TcpStream {
    const BUFFER_SIZE: usize = TCP_READ_BUFFER_SIZE;

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), Error> {
        net::TcpStream::set_nonblocking(self, nonblocking).map_err(|_| match nonblocking {
            true => Error::SetNonBlocking,
            false => Error::SetBlocking,
        })
    }
}

impl ElectrumRead for native_tls::TlsStream<net::TcpStream> {
    const BUFFER_SIZE: usize = TLS_READ_BUFFER_SIZE;

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), Error> {
        self.get_mut()
            .set_nonblocking(nonblocking)
            .map_err(|_| match nonblocking {
                true => Error::SetNonBlocking,
                false => Error::SetBlocking,
            })
    }
}

fn take_line(buf: &mut Vec<u8>) -> Option<String> {
    let pos = buf.iter().position(|b| *b == b'\n')?;
    let rest = buf.split_off(pos + 1);
    let line = std::mem::replace(buf, rest);
    Some(String::from_utf8_lossy(&line).into_owned())
}

pub fn try_read_line<R: ElectrumRead>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<String>, Error> {
    if let Some(line) = take_line(buf) {
        return Ok(Some(line));
    }
    stream.set_nonblocking(true)?;
    let mut tmp = vec![0u8; R::BUFFER_SIZE];
    let result = loop {
        match stream.read(&mut tmp) {
            Ok(0) => break Err(Error::Disconnected),
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(line) = take_line(buf) {
                    break Ok(Some(line));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(None),
            Err(e) => break Err(Error::TcpStream(e)),
        }
    };
    stream.set_nonblocking(false)?;
    result
}

pub fn read_line<R: ElectrumRead>(stream: &mut R, buf: &mut Vec<u8>) -> Result<String, Error> {
    stream.set_nonblocking(false)?;
    let mut tmp = vec![0u8; R::BUFFER_SIZE];
    loop {
        if let Some(line) = take_line(buf) {
            return Ok(line);
        }
        match stream.read(&mut tmp) {
            Ok(0) if !buf.is_empty() => {
                let line = std::mem::take(buf);
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
            Ok(0) => return Err(Error::Disconnected),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(Error::TcpStream(e)),
        }
    }
}

/// Whether the TLS certificate a server presents is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateCheck {
    /// Check the chain of trust, the expiry and the hostname.
    #[default]
    Validate,
    /// Accept any certificate: the chain of trust, the expiry and the hostname
    /// are all skipped, so any party on the network path can impersonate the
    /// server. It exists to reach a self-signed or onion server, and is unsafe
    /// against anything else.
    DangerAcceptInvalid,
}

#[derive(Debug)]
pub enum Error {
    TcpStream(std::io::Error),
    SocketAddr,
    Tls(native_tls::Error),
    TlsHandshake(native_tls::HandshakeError<std::net::TcpStream>),
    Io(std::io::Error),
    Electrum(electrum::Error),
    Mutex,
    AlreadyConnected,
    NotConnected,
    Disconnected,
    NotConfigured,
    ShutDown,
    SetNonBlocking,
    SetBlocking,
    SerializeRequest,
    Batch,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

impl From<electrum::Error> for Error {
    fn from(value: electrum::Error) -> Self {
        Error::Electrum(value)
    }
}

#[derive(Debug, Default, Clone)]
pub enum Client {
    #[default]
    None,
    Tcp(TcpClient),
    Ssl(SslClient),
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tcp(self, url: &str, port: u16) -> Self {
        Self::new_tcp(url, port)
    }

    pub fn new_tcp(url: &str, port: u16) -> Self {
        Self::Tcp(TcpClient::default().url(url).port(port))
    }

    pub fn ssl(self, url: &str, port: u16) -> Self {
        Self::new_ssl(url, port)
    }

    pub fn new_ssl(url: &str, port: u16) -> Self {
        Self::Ssl(SslClient::default().url(url).port(port))
    }

    pub fn new_ssl_maybe(url: &str, port: u16, ssl: bool) -> Self {
        match ssl {
            true => Self::new_ssl(url, port),
            false => Self::new_tcp(url, port),
        }
    }

    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.read_timeout = timeout,
            Client::Ssl(c) => c.read_timeout = timeout,
        }
        self
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_read_timeout(timeout),
            Client::Ssl(c) => c.set_read_timeout(timeout),
        }
    }

    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.write_timeout = timeout,
            Client::Ssl(c) => c.write_timeout = timeout,
        }
        self
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_write_timeout(timeout),
            Client::Ssl(c) => c.set_write_timeout(timeout),
        }
    }

    /// Set the certificate policy the next connection handshakes under.
    ///
    /// Errors on a connected client: the handshake is already behind us, so
    /// keeping the old policy would leave the caller believing they had
    /// reached their self-signed server, and on an unconfigured one, which has
    /// no endpoint to apply it to. A plain TCP endpoint presents no certificate
    /// at all, so there the policy is dropped without complaint.
    pub fn certificate_check(mut self, check: CertificateCheck) -> Result<Self, Error> {
        if self.is_connected() {
            return Err(Error::AlreadyConnected);
        }
        match &mut self {
            Client::None => return Err(Error::NotConfigured),
            Client::Tcp(_) => {}
            Client::Ssl(c) => c.certificate_check = check,
        }
        Ok(self)
    }

    pub fn is_connected(&self) -> bool {
        match self {
            Client::None => false,
            Client::Tcp(c) => c.is_connected(),
            Client::Ssl(c) => c.is_connected(),
        }
    }

    pub fn try_connect(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.try_connect(timeout),
            Client::Ssl(c) => c.try_connect(timeout),
        }
    }

    pub fn try_connect_retry(
        &mut self,
        retry: usize,
        delay: Duration,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut result = self.try_connect(Some(timeout));
        let mut count = 0;
        loop {
            match result {
                e @ Err(Error::NotConfigured) => return e,
                e @ Err(_) => {
                    thread::sleep(delay);
                    count += 1;
                    if count > retry {
                        return e;
                    }
                    result = self.try_connect(Some(timeout));
                }
                ok => return ok,
            }
        }
    }

    pub fn send(&mut self, request: &Request) {
        self.try_send(request).unwrap();
    }

    pub fn send_str(&mut self, request: &str) {
        self.try_send_str(request).unwrap();
    }

    pub fn try_send_batch(&mut self, requests: Vec<&Request>) -> Result<(), Error> {
        let batch = serde_json::to_string(&requests).map_err(|_| Error::Batch)?;
        self.try_send_str(&batch)
    }

    pub fn try_send(&mut self, request: &Request) -> Result<(), Error> {
        let s = serde_json::to_string(request).map_err(|_| Error::SerializeRequest)?;
        self.try_send_str(&s)
    }

    pub fn try_send_str(&mut self, request: &str) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn recv(&mut self, index: &HashMap<usize, Request>) -> Result<Vec<Response>, Error> {
        let raw = self.recv_str()?;
        Ok(parse_str_response(&raw, index)?)
    }

    pub fn recv_str(&mut self) -> Result<String, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn try_recv(
        &mut self,
        index: &HashMap<usize, Request>,
    ) -> Result<Option<Vec<Response>>, Error> {
        let raw = self.try_recv_str()?;
        if let Some(rr) = raw {
            Ok(Some(parse_str_response(&rr, index)?))
        } else {
            Ok(None)
        }
    }

    pub fn try_recv_str(&mut self) -> Result<Option<String>, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn close(&mut self) -> Result<(), Error> {
        match self {
            Client::None => Ok(()),
            Client::Tcp(c) => c.close(),
            Client::Ssl(c) => c.close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        sync::mpsc,
    };

    /// Accept one connection, write `greeting`, then close. Returns the port
    /// and a channel that yields the accepted stream so the test controls when
    /// the peer goes away.
    fn closing_server(greeting: &'static str) -> (u16, mpsc::Receiver<TcpStream>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            if !greeting.is_empty() {
                stream.write_all(greeting.as_bytes()).expect("write");
                stream.flush().expect("flush");
            }
            let _ = tx.send(stream);
        });
        (port, rx)
    }

    fn connected(port: u16) -> Client {
        let mut client = Client::new().tcp("127.0.0.1", port);
        client.try_connect(None).expect("connect");
        client
    }

    /// A peer that closed must not read as "no data yet": the listener loop
    /// treats `Ok(None)` as an idle tick and would spin on a dead socket.
    #[test]
    fn a_closed_peer_is_reported_rather_than_read_as_no_data() {
        let (port, accepted) = closing_server("");
        let mut client = connected(port);
        drop(accepted.recv().expect("accepted"));

        let mut last = Ok(None);
        for _ in 0..100 {
            last = client.try_recv_str();
            if last.is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            matches!(last, Err(Error::Disconnected)),
            "expected Disconnected, got {last:?}"
        );
    }

    /// The blocking read must report the close too, instead of handing back an
    /// empty line for every subsequent call.
    #[test]
    fn a_blocking_read_on_a_closed_peer_reports_the_close() {
        let (port, accepted) = closing_server("");
        let mut client = connected(port);
        drop(accepted.recv().expect("accepted"));

        let read = client.recv_str();
        assert!(
            matches!(read, Err(Error::Disconnected)),
            "expected Disconnected, got {read:?}"
        );
    }

    /// Whatever the peer sent before closing is still handed back, and only
    /// the read after it reports the close.
    #[test]
    fn a_partial_line_is_flushed_before_the_close_is_reported() {
        let (port, accepted) = closing_server("no trailing newline");
        let mut client = connected(port);
        drop(accepted.recv().expect("accepted"));

        assert_eq!(client.recv_str().expect("tail"), "no trailing newline");
        assert!(matches!(client.recv_str(), Err(Error::Disconnected)));
    }
}
