use std::{
    io::{BufReader, Write},
    net::{SocketAddr, TcpStream},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bitcoin::p2p::{
    address,
    message::{self, NetworkMessage},
    message_network::VersionMessage,
    Magic, ServiceFlags,
};
use bitcoin::{
    consensus::{encode, Decodable},
    Network,
};

use crate::error::Error;

const USER_AGENT: &str = "/bwk-p2p:0.0.1/";
const PROTOCOL_VERSION: u32 = 70_016;

pub fn network_to_magic(network: Network) -> Magic {
    match network {
        Network::Bitcoin => Magic::BITCOIN,
        Network::Testnet => Magic::TESTNET3,
        Network::Testnet4 => Magic::TESTNET4,
        Network::Signet => Magic::SIGNET,
        Network::Regtest => Magic::REGTEST,
    }
}

pub(crate) fn connect(
    addr: &str,
    network: Network,
    timeout: Duration,
) -> Result<(TcpStream, BufReader<TcpStream>, i32), Error> {
    let address = SocketAddr::from_str(addr).map_err(|_| Error::InvalidAddress)?;
    let magic = network_to_magic(network);

    log::debug!("connecting to {address} (timeout: {timeout:?})");
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    let own_ip = stream.local_addr().map_err(|_| Error::LocalAddress)?;
    log::debug!("connected to {address} from {own_ip}");

    let version_message = version_msg(own_ip, address);
    let version_message = message::RawNetworkMessage::new(magic, version_message);

    let _ = stream.write_all(encode::serialize(&version_message).as_slice());
    log::debug!("sent version message to {address}");

    let mut reader = BufReader::new(stream.try_clone().map_err(|_| Error::StreamClone)?);

    let mut verack = false;
    let mut version = false;
    let mut start_height = 0;

    let handshake_start = SystemTime::now();

    loop {
        let elapsed = SystemTime::now()
            .duration_since(handshake_start)
            .expect("valid time");
        if elapsed > timeout {
            log::debug!("handshake timed out with {address}");
            return Err(Error::Timeout);
        }

        let reply =
            message::RawNetworkMessage::consensus_decode(&mut reader).map_err(|_| Error::Decode)?;
        match reply.payload() {
            NetworkMessage::Version(v) => {
                start_height = v.start_height;
                version = true;
                log::debug!("received version from {address} (start_height: {start_height})");
            }
            NetworkMessage::Verack => {
                verack = true;
                log::debug!("received verack from {address}");
            }
            _ => {}
        }
        if version && verack {
            let verack_msg = message::RawNetworkMessage::new(magic, NetworkMessage::Verack);
            let _ = stream.write_all(encode::serialize(&verack_msg).as_slice());
            log::debug!("handshake complete with {address}");
            break;
        }
    }

    Ok((stream, reader, start_height))
}

fn version_msg(own_ip: SocketAddr, peer_ip: SocketAddr) -> NetworkMessage {
    let services = ServiceFlags::NONE;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs();

    let addr_recv = address::Address::new(&peer_ip, ServiceFlags::NONE);
    let addr_from = address::Address::new(&own_ip, ServiceFlags::NONE);

    let nonce: u64 = rand::random();
    let start_height: i32 = 0;

    let mut version = VersionMessage::new(
        services,
        timestamp as i64,
        addr_recv,
        addr_from,
        nonce,
        USER_AGENT.to_string(),
        start_height,
    );
    version.version = PROTOCOL_VERSION;

    NetworkMessage::Version(version)
}
