use crate::raw_client::{read_line, try_read_line, CertificateCheck, Error};
use std::{
    io::Write,
    net::{self, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(target_os = "android")]
use {bwk_utils::android_root_certs, native_tls::Certificate};

/// A connected TLS stream plus the bytes already read past the last delimiter.
/// native-tls has no peek, so we keep a residual buffer across read calls to
/// implement a non-blocking `try_read`.
pub struct TlsState {
    tls: native_tls::TlsStream<net::TcpStream>,
    buf: Vec<u8>,
}

impl std::fmt::Debug for TlsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsState").finish()
    }
}

type SslStream = Arc<Mutex<TlsState>>;

#[derive(Debug)]
pub struct SslClient {
    url: String,
    port: u16,
    pub(crate) stream: Option<SslStream>,
    pub(crate) read_timeout: Option<Duration>,
    pub(crate) write_timeout: Option<Duration>,
    pub certificate_check: CertificateCheck,
}

impl Clone for SslClient {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            port: self.port,
            stream: self.stream.clone(),
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            certificate_check: self.certificate_check,
        }
    }
}

impl Drop for SslClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Default for SslClient {
    fn default() -> Self {
        Self {
            url: Default::default(),
            port: 50002,
            stream: None,
            read_timeout: None,
            write_timeout: None,
            certificate_check: CertificateCheck::default(),
        }
    }
}

impl SslClient {
    pub fn url(mut self, url: &str) -> Self {
        if !self.is_connected() {
            self.url = url.into();
        } else {
            log::error!("Cannot change url of a connected SslClient!")
        }
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        if !self.is_connected() {
            self.port = port;
        } else {
            log::error!("Cannot change port of a connected TcpClient!")
        }
        self
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn try_connect(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        let url = format!("{}:{}", self.url, self.port);
        let mut builder = native_tls::TlsConnector::builder();

        #[cfg(target_os = "android")]
        {
            for cert in android_root_certs().map_err(Error::Io)? {
                let cert = Certificate::from_pem(&cert)
                    .or_else(|_| Certificate::from_der(&cert))
                    .map_err(Error::Tls)?;
                builder.add_root_certificate(cert);
            }
        }

        if self.certificate_check == CertificateCheck::DangerAcceptInvalid {
            log::warn!(
                "certificate verification is disabled for {}, this connection can be impersonated",
                self.url
            );
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        let connector = builder.build().map_err(Error::Tls)?;
        let tcp = if let Some(timeout) = timeout {
            let addr = url
                .to_socket_addrs()
                .map_err(Error::Io)?
                .next()
                .ok_or(Error::SocketAddr)?;
            net::TcpStream::connect_timeout(&addr, timeout).map_err(Error::TcpStream)?
        } else {
            net::TcpStream::connect(url).map_err(Error::TcpStream)?
        };
        tcp.set_read_timeout(self.read_timeout)
            .map_err(Error::TcpStream)?;
        tcp.set_write_timeout(self.write_timeout)
            .map_err(Error::TcpStream)?;
        let tls = connector
            .connect(&self.url, tcp)
            .map_err(Error::TlsHandshake)?;
        let state = Arc::new(Mutex::new(TlsState {
            tls,
            buf: Vec::new(),
        }));

        if self.stream.is_none() {
            self.stream = Some(state);
            Ok(())
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        if let Some(stream) = self.stream.as_mut() {
            let stream = stream.lock().map_err(|_| Error::Mutex)?;
            stream
                .tls
                .get_ref()
                .set_read_timeout(timeout)
                .map_err(Error::TcpStream)?;
        }
        self.read_timeout = timeout;
        Ok(())
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        if let Some(stream) = self.stream.as_mut() {
            let stream = stream.lock().map_err(|_| Error::Mutex)?;
            stream
                .tls
                .get_ref()
                .set_write_timeout(timeout)
                .map_err(Error::TcpStream)?;
        }
        self.write_timeout = timeout;
        Ok(())
    }

    pub fn send(state: &mut TlsState, request: &str) -> Result<(), Error> {
        state
            .tls
            .write_all(request.as_bytes())
            .map_err(Error::TcpStream)?;
        // add a \n char for EOL
        state.tls.write_all(&[10]).map_err(Error::TcpStream)?;
        state.tls.flush().map_err(Error::TcpStream)?;
        Ok(())
    }

    pub fn try_read(state: &mut TlsState) -> Result<Option<String>, Error> {
        try_read_line(&mut state.tls, &mut state.buf)
    }

    pub fn read(state: &mut TlsState) -> Result<String, Error> {
        read_line(&mut state.tls, &mut state.buf)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(stream) = self.stream.take() {
            stream
                .try_lock()
                .map_err(|_| Error::Mutex)?
                .tls
                .shutdown()
                .map_err(|_| Error::ShutDown)?;
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }
}
