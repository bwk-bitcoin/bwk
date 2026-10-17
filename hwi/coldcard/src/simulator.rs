//! The simulator's test-only commands (`shared/usb_test_commands.py` in the firmware).

use std::path::Path;

use crate::{Error, constants, protocol::Response, recv, send, transport::UnixSimulatorTransport};

/// A second, unencrypted connection to the simulator for its test-only commands.
/// Never resyncs and only sends single-packet messages, so it can run next to
/// the encrypted connection of the device under test (shared/usb.py:221-300).
pub struct SimulatorLink {
    transport: UnixSimulatorTransport,
}

impl SimulatorLink {
    pub fn connect(socket: &Path) -> Result<Self, Error> {
        Ok(Self {
            transport: UnixSimulatorTransport::connect(socket)?,
        })
    }

    /// `XKEY<keys>`: presses `keys` (for example "y", "x").
    pub fn keypress(&mut self, keys: &str) -> Result<(), Error> {
        self.command(b"XKEY", keys)?.into_ok().map_err(Error::from)
    }

    /// `EXEC<code>`: the bytes the code wrote to `RV`.
    pub fn exec(&mut self, code: &str) -> Result<Vec<u8>, Error> {
        self.command(b"EXEC", code)?
            .into_binary()
            .map_err(Error::from)
    }

    fn command(&mut self, command: &[u8; 4], args: &str) -> Result<Response, Error> {
        let mut message = command.to_vec();
        message.extend_from_slice(args.as_bytes());
        if message.len() > constants::CHUNK_SIZE {
            return Err(Error::SimulatorMessageTooLong(message.len()));
        }
        let mut send_buf = [0_u8; 2 + constants::CHUNK_SIZE];
        let mut read_buf = [0_u8; 64];
        send(message, &mut self.transport, None, &mut send_buf)?;
        recv(&mut self.transport, None, &mut read_buf)
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use crate::{Error, simulator::SimulatorLink, transport::tests::FakeSimulator};

    #[test]
    fn exec_refuses_a_multi_packet_message() {
        let sim = FakeSimulator::bind("toolong");
        let mut link = SimulatorLink::connect(&sim.path).unwrap();
        let code = "x".repeat(60);
        assert!(matches!(
            link.exec(&code),
            Err(Error::SimulatorMessageTooLong(64))
        ));
        assert!(matches!(
            link.keypress(&code),
            Err(Error::SimulatorMessageTooLong(64))
        ));

        sim.socket.set_nonblocking(true).unwrap();
        let mut buf = [0_u8; 64];
        let err = sim.socket.recv(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }
}
