//! Links a Coldcard is reached over: USB HID, or the simulator's Unix datagram socket.

#[cfg(unix)]
use std::{
    io::ErrorKind,
    os::unix::net::UnixDatagram,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::Error;

/// Socket of a simulator started without `--segregate`.
pub const DEFAULT_SIMULATOR_SOCKET: &str = "/tmp/ckcc-simulator.sock";
/// Serial number the simulator reports (ckcc-protocol's `'F1' * 6`).
pub const SIMULATOR_SERIAL: &str = "F1F1F1F1F1F1";

#[cfg(unix)]
const SIMULATOR_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// ckcc-protocol picks a read timeout per call (1 ms to none); the `Transport` API has
/// no per-call timeout for blocking reads, so one generous bound covers them all.
#[cfg(unix)]
const SIMULATOR_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Client socket names tried, as ckcc-protocol's `UnixSimulatorPipe`.
#[cfg(unix)]
const SIMULATOR_CLIENT_INSTANCES: u32 = 5;

/// A link carrying the Coldcard's 64-byte HID packets.
pub trait Transport: Send {
    /// One 65-byte HID report: report number 0, framing byte, 63 payload bytes.
    fn write(&mut self, report: &[u8; 65]) -> Result<(), Error>;
    /// One 64-byte packet; blocks up to the transport's own timeout.
    fn read(&mut self, packet: &mut [u8; 64]) -> Result<usize, Error>;
    /// Ok(0) when nothing arrives within `timeout_ms`.
    fn read_timeout(&mut self, packet: &mut [u8; 64], timeout_ms: i32) -> Result<usize, Error>;
}

/// A Coldcard plugged over USB.
pub struct HidTransport(pub hidapi::HidDevice);

impl Transport for HidTransport {
    fn write(&mut self, report: &[u8; 65]) -> Result<(), Error> {
        self.0.write(&report[..])?;
        Ok(())
    }

    fn read(&mut self, packet: &mut [u8; 64]) -> Result<usize, Error> {
        Ok(self.0.read(packet)?)
    }

    fn read_timeout(&mut self, packet: &mut [u8; 64], timeout_ms: i32) -> Result<usize, Error> {
        Ok(self.0.read_timeout(packet, timeout_ms)?)
    }
}

/// The simulator's Unix datagram socket, as ckcc-protocol's `UnixSimulatorPipe`: the
/// client binds to a named socket (the simulator refuses unbound writers and answers
/// to the last sender) and sends each report without its report number.
#[cfg(unix)]
pub struct UnixSimulatorTransport {
    socket: UnixDatagram,
    client_path: PathBuf,
}

#[cfg(unix)]
impl UnixSimulatorTransport {
    /// Binds the first free client name of [`client_socket_path`] and connects to the
    /// simulator at `socket`. A name left by a dead client is removed and skipped, as
    /// ckcc-protocol does; unlike ckcc-protocol, a name a live client is bound to is
    /// only skipped, so two links of one process can share a simulator.
    pub fn connect(socket: &Path) -> Result<Self, Error> {
        let pid = std::process::id();
        let mut instance = 0;
        loop {
            let client_path = client_socket_path(socket, pid, instance);
            match UnixDatagram::bind(&client_path) {
                Ok(datagram) => {
                    let transport = Self {
                        socket: datagram,
                        client_path,
                    };
                    transport.socket.connect(socket)?;
                    return Ok(transport);
                }
                Err(e) => {
                    if is_stale_socket(&client_path) {
                        let _ = std::fs::remove_file(&client_path);
                    }
                    instance += 1;
                    if instance == SIMULATOR_CLIENT_INSTANCES {
                        return Err(e.into());
                    }
                }
            }
        }
    }
}

/// True when `path` exists but nothing is bound to it any more.
#[cfg(unix)]
fn is_stale_socket(path: &Path) -> bool {
    path.exists()
        && UnixDatagram::unbound()
            .and_then(|probe| probe.connect(path))
            .is_err_and(|e| e.kind() == ErrorKind::ConnectionRefused)
}

#[cfg(unix)]
impl Transport for UnixSimulatorTransport {
    fn write(&mut self, report: &[u8; 65]) -> Result<(), Error> {
        self.socket
            .set_write_timeout(Some(SIMULATOR_WRITE_TIMEOUT))?;
        let packet = &report[1..];
        if self.socket.send(packet)? == packet.len() {
            Ok(())
        } else {
            Err(Error::TransmissionFailed)
        }
    }

    fn read(&mut self, packet: &mut [u8; 64]) -> Result<usize, Error> {
        self.socket.set_read_timeout(Some(SIMULATOR_READ_TIMEOUT))?;
        Ok(self.socket.recv(packet)?)
    }

    /// A timeout of 0 or less blocks, as ckcc-protocol's `read(timeout_ms=0)`.
    fn read_timeout(&mut self, packet: &mut [u8; 64], timeout_ms: i32) -> Result<usize, Error> {
        let timeout = u64::try_from(timeout_ms)
            .ok()
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis);
        self.socket.set_read_timeout(timeout)?;
        match self.socket.recv(packet) {
            Ok(read) => Ok(read),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(unix)]
impl Drop for UnixSimulatorTransport {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.client_path);
    }
}

/// Client socket name of ckcc-protocol's `UnixSimulatorPipe`:
/// `/tmp/ckcc-client<sim>-<pid>-<instance>.sock`, where `<sim>` is empty for
/// [`DEFAULT_SIMULATOR_SOCKET`], else `-` and the last `-` field of the socket path
/// cut at its first `.`.
#[cfg(unix)]
pub fn client_socket_path(simulator_socket: &Path, pid: u32, instance: u32) -> PathBuf {
    let sim_pid = if simulator_socket.as_os_str() == DEFAULT_SIMULATOR_SOCKET {
        String::new()
    } else {
        let path = simulator_socket.to_string_lossy();
        let head = path.split_once('.').map_or(&*path, |(head, _)| head);
        let last = head.rsplit_once('-').map_or(head, |(_, last)| last);
        format!("-{last}")
    };
    PathBuf::from(format!("/tmp/ckcc-client{sim_pid}-{pid}-{instance}.sock"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;

    #[cfg(unix)]
    use std::{
        fs,
        os::unix::net::UnixDatagram,
        path::{Path, PathBuf},
    };

    #[cfg(unix)]
    use crate::transport::{UnixSimulatorTransport, client_socket_path};
    use crate::{Error, transport::Transport};

    /// Records the reports written and replays queued packets.
    #[derive(Default)]
    pub(crate) struct MockTransport {
        pub(crate) written: Vec<[u8; 65]>,
        pub(crate) to_read: VecDeque<[u8; 64]>,
    }

    impl Transport for MockTransport {
        fn write(&mut self, report: &[u8; 65]) -> Result<(), Error> {
            self.written.push(*report);
            Ok(())
        }

        fn read(&mut self, packet: &mut [u8; 64]) -> Result<usize, Error> {
            let next = self.to_read.pop_front().ok_or(Error::TransmissionFailed)?;
            *packet = next;
            Ok(packet.len())
        }

        fn read_timeout(&mut self, packet: &mut [u8; 64], _: i32) -> Result<usize, Error> {
            match self.to_read.pop_front() {
                Some(next) => {
                    *packet = next;
                    Ok(packet.len())
                }
                None => Ok(0),
            }
        }
    }

    /// A socket standing in for the simulator, in a fresh directory. The last `-` field
    /// of its file name is `<tag><pid>`, so each test gets its own client names.
    #[cfg(unix)]
    pub(crate) struct FakeSimulator {
        pub(crate) socket: UnixDatagram,
        pub(crate) path: PathBuf,
        dir: PathBuf,
    }

    #[cfg(unix)]
    impl FakeSimulator {
        pub(crate) fn bind(tag: &str) -> Self {
            let pid = std::process::id();
            let dir = PathBuf::from(format!("/tmp/bwk-cc-test-{pid}-{tag}"));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir(&dir).unwrap();
            let path = dir.join(format!("sim-{tag}{pid}.sock"));
            let socket = UnixDatagram::bind(&path).unwrap();
            Self { socket, path, dir }
        }
    }

    #[cfg(unix)]
    impl Drop for FakeSimulator {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn client_socket_path_follows_ckcc() {
        assert_eq!(
            client_socket_path(Path::new("/tmp/ckcc-simulator.sock"), 42, 0),
            PathBuf::from("/tmp/ckcc-client-42-0.sock")
        );
        assert_eq!(
            client_socket_path(Path::new("/tmp/ckcc-simulator-1234.sock"), 42, 0),
            PathBuf::from("/tmp/ckcc-client-1234-42-0.sock")
        );
        assert_eq!(
            client_socket_path(Path::new("/tmp/ckcc-simulator-1234.sock"), 42, 3),
            PathBuf::from("/tmp/ckcc-client-1234-42-3.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_transport_round_trip() {
        let sim = FakeSimulator::bind("roundtrip");
        let mut client = UnixSimulatorTransport::connect(&sim.path).unwrap();
        let client_path = client.client_path.clone();
        assert!(client_path.exists());

        let mut report = [0_u8; 65];
        for (i, byte) in report.iter_mut().enumerate() {
            *byte = i as u8;
        }
        client.write(&report).unwrap();

        let mut received = [0_u8; 128];
        let (len, from) = sim.socket.recv_from(&mut received).unwrap();
        assert_eq!(len, 64);
        assert_eq!(&received[..64], &report[1..]);
        assert_eq!(from.as_pathname(), Some(client_path.as_path()));

        let answer = [0xa5_u8; 64];
        sim.socket
            .send_to(&answer, from.as_pathname().unwrap())
            .unwrap();
        let mut packet = [0_u8; 64];
        assert_eq!(client.read(&mut packet).unwrap(), 64);
        assert_eq!(packet, answer);

        assert_eq!(client.read_timeout(&mut packet, 1).unwrap(), 0);

        drop(client);
        assert!(!client_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_transport_skips_a_live_client_name() {
        let sim = FakeSimulator::bind("twoclients");
        let first = UnixSimulatorTransport::connect(&sim.path).unwrap();
        let second = UnixSimulatorTransport::connect(&sim.path).unwrap();
        assert_ne!(first.client_path, second.client_path);
        assert!(first.client_path.exists());
        assert!(second.client_path.exists());
    }
}
