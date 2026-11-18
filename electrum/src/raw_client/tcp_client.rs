use super::{read_line, try_read_line, Error};
use std::{
    io::Write,
    net::{self, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

/// A connected TCP stream plus the bytes already read past the last delimiter.
/// We keep a residual buffer across read calls so chunked reads never drop the
/// tail of a burst: leftover bytes after a `\n` survive to the next read.
pub struct TcpState {
    stream: net::TcpStream,
    buf: Vec<u8>,
}

impl std::fmt::Debug for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpState").finish()
    }
}

type TcpStream = Arc<Mutex<TcpState>>;

#[derive(Debug)]
pub struct TcpClient {
    url: String,
    port: u16,
    pub(crate) stream: Option<TcpStream>,
    pub(crate) read_timeout: Option<Duration>,
    pub(crate) write_timeout: Option<Duration>,
}

impl Clone for TcpClient {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            port: self.port,
            stream: self.stream.clone(),
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for TcpClient {
    fn default() -> Self {
        Self {
            url: Default::default(),
            port: 50002,
            stream: None,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl TcpClient {
    pub fn url(mut self, url: &str) -> Self {
        if !self.is_connected() {
            self.url = url.into();
        } else {
            log::error!("Cannot change url of a connected TcpClient!")
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
        let stream = if let Some(timeout) = timeout {
            crate::raw_client::connect_timeout(url.to_socket_addrs().map_err(Error::Io)?, timeout)?
        } else {
            net::TcpStream::connect(url).map_err(Error::TcpStream)?
        };
        stream
            .set_read_timeout(self.read_timeout)
            .map_err(Error::TcpStream)?;
        stream
            .set_write_timeout(self.write_timeout)
            .map_err(Error::TcpStream)?;
        if self.stream.is_none() {
            self.stream = Some(Arc::new(Mutex::new(TcpState {
                stream,
                buf: Vec::new(),
            })));
            Ok(())
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    pub fn send(state: &mut TcpState, request: &str) -> Result<(), Error> {
        state
            .stream
            .write_all(request.as_bytes())
            .map_err(Error::TcpStream)?;
        // add a \n char for EOL
        state.stream.write_all(&[10]).map_err(Error::TcpStream)?;
        state.stream.flush().map_err(Error::TcpStream)?;
        Ok(())
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        if let Some(stream) = self.stream.as_mut() {
            let stream = stream.lock().map_err(|_| Error::Mutex)?;
            stream
                .stream
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
                .stream
                .set_write_timeout(timeout)
                .map_err(Error::TcpStream)?;
        }
        self.write_timeout = timeout;
        Ok(())
    }

    pub fn try_read(state: &mut TcpState) -> Result<Option<String>, Error> {
        try_read_line(&mut state.stream, &mut state.buf)
    }

    pub fn read(state: &mut TcpState) -> Result<String, Error> {
        read_line(&mut state.stream, &mut state.buf)
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(stream) = self.stream.take() {
            stream
                .try_lock()
                .map_err(|_| Error::Mutex)?
                .stream
                .shutdown(net::Shutdown::Both)
                .map_err(|_| Error::ShutDown)?;
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }
}
