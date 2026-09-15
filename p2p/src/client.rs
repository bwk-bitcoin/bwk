use std::{
    io::{BufReader, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

use bitcoin::consensus::{encode, Decodable};
use bitcoin::p2p::{
    message::{self, NetworkMessage},
    message_blockdata::Inventory,
    Magic,
};
use bitcoin::{Block, BlockHash, Network, Transaction};

use crate::{connection::network_to_magic, error::Error};

#[derive(Debug)]
pub struct Client {
    address: SocketAddr,
    network: Network,
    timeout: Duration,
    stream: Option<Arc<Mutex<TcpStream>>>,
    receiver: Option<mpsc::Receiver<NetworkMessage>>,
    stop: Arc<AtomicBool>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            network: self.network,
            timeout: self.timeout,
            stream: None,
            receiver: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Client {
    pub fn new(address: SocketAddr, network: Network) -> Self {
        Self {
            address,
            network,
            timeout: Duration::from_millis(1000),
            stream: None,
            receiver: None,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect(mut self) -> Result<Self, Error> {
        self.stop.store(false, Ordering::Relaxed);
        let (stream, reader, _height) =
            crate::connection::connect(&self.address.to_string(), self.network, self.timeout)?;
        let stream = Arc::new(Mutex::new(stream));
        self.stream = Some(stream.clone());
        self.start_listen(reader, stream)?;
        Ok(self)
    }

    fn start_listen(
        &mut self,
        reader: BufReader<TcpStream>,
        stream: Arc<Mutex<TcpStream>>,
    ) -> Result<(), Error> {
        if !self.is_connected() {
            return Err(Error::NotConnected);
        }

        let (thread_sender, client_receiver) = mpsc::channel();
        self.receiver = Some(client_receiver);

        let magic = network_to_magic(self.network);
        let stop = self.stop.clone();

        std::thread::spawn(move || {
            Self::listen(stream, reader, thread_sender, magic, stop);
        });

        Ok(())
    }

    fn listen(
        stream: Arc<Mutex<TcpStream>>,
        mut reader: BufReader<TcpStream>,
        sender: mpsc::Sender<NetworkMessage>,
        magic: Magic,
        stop: Arc<AtomicBool>,
    ) {
        let mut fail = 0;
        loop {
            match message::RawNetworkMessage::consensus_decode(&mut reader) {
                Ok(msg) => match msg.into_payload() {
                    NetworkMessage::Ping(nonce) => {
                        let pong_msg = NetworkMessage::Pong(nonce);
                        let msg = message::RawNetworkMessage::new(magic, pong_msg);
                        stream
                            .lock()
                            .expect("poisoned")
                            .write_all(encode::serialize(&msg).as_slice())
                            .unwrap();
                    }
                    m @ NetworkMessage::Block(_) => {
                        let _ = sender.send(m);
                    }
                    NetworkMessage::Addr(a) => {
                        let _ = sender.send(NetworkMessage::Addr(a.clone()));
                    }
                    m @ NetworkMessage::GetData(_) => {
                        let _ = sender.send(m);
                    }
                    _ => {}
                },
                Err(e) => {
                    fail += 1;
                    if fail > 3 {
                        log::warn!("P2P decode error: {e:?}");
                    }
                    stop.store(true, Ordering::Relaxed);
                }
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
        }
    }

    pub fn stop(&mut self) {
        self.stream = None;
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn is_started(&self) -> bool {
        self.receiver.is_some()
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some() || self.is_started()
    }

    pub fn get_block(&mut self, block_hash: BlockHash) -> Result<Option<Block>, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnected);
        }
        let stream = if let Some(stream) = &self.stream {
            stream.clone()
        } else {
            return Err(Error::NotConnected);
        };
        let timeout = self.timeout;
        let mut back_off = bwk_backoff::Backoff::new_ms(20);
        if let Some(receiver) = self.receiver.as_mut() {
            let block = Inventory::Block(block_hash);
            let getdata_msg = message::NetworkMessage::GetData(vec![block]);
            let magic = network_to_magic(self.network);
            let get_block = message::RawNetworkMessage::new(magic, getdata_msg);
            let _ = stream
                .lock()
                .expect("poisoned")
                .write_all(encode::serialize(&get_block).as_slice());
            let send = SystemTime::now();

            loop {
                if let Ok(NetworkMessage::Block(block)) = receiver.try_recv() {
                    return Ok(Some(block));
                } else {
                    let elapsed = SystemTime::now().duration_since(send).expect("valid time");
                    if elapsed > timeout {
                        return Ok(None);
                    } else {
                        back_off.snooze();
                    }
                }
                if self.stop.load(Ordering::Relaxed) {
                    return Err(Error::Stopped);
                }
            }
        } else {
            Err(Error::NotConnected)
        }
    }

    pub fn get_addr(&mut self) -> Result<Option<Vec<SocketAddr>>, Error> {
        if !self.is_connected() {
            return Err(Error::NotConnected);
        }
        let stream = if let Some(stream) = &self.stream {
            stream.clone()
        } else {
            return Err(Error::NotConnected);
        };
        let timeout = self.timeout;
        let mut back_off = bwk_backoff::Backoff::new_ms(20);
        if let Some(receiver) = self.receiver.as_mut() {
            let getdata_msg = message::NetworkMessage::GetAddr;
            let magic = network_to_magic(self.network);
            let get_addr = message::RawNetworkMessage::new(magic, getdata_msg);
            let _ = stream
                .lock()
                .expect("poisoned")
                .write_all(encode::serialize(&get_addr).as_slice());
            let send = SystemTime::now();

            loop {
                if let Ok(NetworkMessage::Addr(vec)) = receiver.try_recv() {
                    let addresses = vec
                        .into_iter()
                        .filter_map(|(_, a)| a.socket_addr().ok())
                        .collect();
                    return Ok(Some(addresses));
                } else {
                    let elapsed = SystemTime::now().duration_since(send).expect("valid time");
                    if elapsed > timeout {
                        return Ok(None);
                    } else {
                        back_off.snooze();
                    }
                }
                if self.stop.load(Ordering::Relaxed) {
                    return Err(Error::Stopped);
                }
            }
        } else {
            Err(Error::NotConnected)
        }
    }

    /// Broadcast a transaction to the connected peer using the standard
    /// `inv` -> `getdata` -> `tx` relay protocol.
    ///
    /// Returns `Ok(())` once the peer has requested and received the full
    /// transaction. This is the strongest confirmation available over P2P:
    /// Bitcoin Core will not serve a transaction back to the peer that sent
    /// it, so mempool acceptance cannot be verified from the same connection.
    pub fn broadcast_tx(&mut self, tx: Transaction) -> Result<(), Error> {
        if !self.is_connected() {
            return Err(Error::NotConnected);
        }
        let stream = if let Some(stream) = &self.stream {
            stream.clone()
        } else {
            return Err(Error::NotConnected);
        };
        let receiver = self.receiver.as_mut().ok_or(Error::NotConnected)?;
        let timeout = self.timeout;
        let stop = &self.stop;

        let txid = tx.compute_txid();
        let magic = network_to_magic(self.network);

        // Send inv announcing the txid
        let inv_msg = NetworkMessage::Inv(vec![Inventory::Transaction(txid)]);
        let raw = message::RawNetworkMessage::new(magic, inv_msg);
        stream
            .lock()
            .expect("poisoned")
            .write_all(encode::serialize(&raw).as_slice())?;

        // Wait for GetData requesting our txid, then send the full tx
        let mut back_off = bwk_backoff::Backoff::new_ms(20);
        let start = SystemTime::now();
        loop {
            if let Ok(NetworkMessage::GetData(inv_list)) = receiver.try_recv() {
                let found = inv_list.iter().any(|i| match i {
                    Inventory::Transaction(id) | Inventory::WitnessTransaction(id) => *id == txid,
                    _ => false,
                });
                if found {
                    let tx_msg = NetworkMessage::Tx(tx);
                    let raw = message::RawNetworkMessage::new(magic, tx_msg);
                    stream
                        .lock()
                        .expect("poisoned")
                        .write_all(encode::serialize(&raw).as_slice())?;
                    return Ok(());
                }
            }
            let elapsed = SystemTime::now().duration_since(start).expect("valid time");
            if elapsed > timeout {
                return Err(Error::Timeout);
            }
            back_off.snooze();
            if stop.load(Ordering::Relaxed) {
                return Err(Error::Stopped);
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(all(test, feature = "ci-p2p"))]
mod tests {
    use bitcoin::{BlockHash, Network};
    use corepc_node::{Client as RpcClient, Conf, P2P};
    use std::{net::SocketAddr, str::FromStr, time::Duration};
    use temp_dir::TempDir;

    use crate::dns::fetch_peers;

    use super::Client;

    fn get_height(client: &mut RpcClient) -> u64 {
        client.get_block_count().unwrap().0
    }

    fn generate_blocks(client: &mut RpcClient, blocks: usize) {
        let height = get_height(client);
        for _ in 0..blocks {
            let addr = client.new_address().unwrap();
            client.generate_to_address(1, &addr).unwrap();
        }
        let new_height = get_height(client);
        assert_eq!(new_height, height + blocks as u64);
    }

    fn use_tmpdir(conf: &mut Conf) -> TempDir {
        let tmp = TempDir::with_prefix("bwk-p2p-bitcoind").unwrap();
        conf.staticdir = Some(tmp.path().to_path_buf());
        tmp
    }

    #[test]
    fn test_get_block() {
        let mut conf = Conf::default();
        conf.p2p = P2P::Yes;
        let _tmp = use_tmpdir(&mut conf);
        let mut node = corepc_node::Node::from_downloaded_with_conf(&conf).unwrap();
        let p2p_addr = match node.p2p_connect(true).unwrap() {
            P2P::Connect(addr, _) => SocketAddr::V4(addr),
            _ => panic!(),
        };

        let bitcoind = &mut node.client;

        generate_blocks(bitcoind, 200);

        let bh = bitcoind.get_block_hash(125).unwrap().block_hash().unwrap();

        let mut p2p_client = Client::new(p2p_addr, Network::Regtest)
            .timeout(Duration::from_millis(500))
            .connect()
            .unwrap();
        assert!(p2p_client.is_connected());
        assert!(p2p_client.is_started());

        let block = p2p_client.get_block(bh).unwrap().unwrap();
        assert_eq!(bh, block.block_hash());

        let fake_hash =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert!(p2p_client.get_block(fake_hash).unwrap().is_none());
    }

    #[test]
    fn test_seed_peers() {
        use std::net::ToSocketAddrs;

        // Check internet connectivity with a reliable DNS
        if "dns.google:443".to_socket_addrs().is_err() {
            eprintln!("Skipping test_seed_peers: no internet connection");
            return;
        }

        const MAX_RETRIES: usize = 3;
        const SUCCESS_THRESHOLD_PERCENT: usize = 40;

        for attempt in 1..=MAX_RETRIES {
            println!("Attempt {attempt}/{MAX_RETRIES}");

            let peers = fetch_peers("seed.bitcoin.sipa.be").unwrap();

            let mut failed = 0;
            let len = peers.len();
            for (index, peer) in peers.into_iter().enumerate() {
                println!("{}/{}", index + 1, len);
                let client = Client::new(peer, Network::Bitcoin)
                    .timeout(Duration::from_secs(5))
                    .connect();
                let mut client = match client {
                    Ok(c) => c,
                    Err(_) => {
                        failed += 1;
                        continue;
                    }
                };
                let addrs = match client.get_addr() {
                    Ok(Some(a)) => a,
                    Err(_) => {
                        failed += 1;
                        continue;
                    }
                    _ => continue,
                };

                println!("received {} peers addresses", addrs.len());
            }

            let success = len - failed;
            println!("Success: {success}/{len}");

            if success * 100 >= len * SUCCESS_THRESHOLD_PERCENT {
                return;
            }

            if attempt < MAX_RETRIES {
                eprintln!("Only {}% succeeded, retrying...", success * 100 / len);
            } else {
                panic!(
                    "Only {}% succeeded after {} attempts!",
                    success * 100 / len,
                    MAX_RETRIES
                );
            }
        }
    }

    #[test]
    fn test_broadcast_tx() {
        use bitcoin::{psbt::Psbt, Amount};
        use std::collections::BTreeMap;
        let _ = env_logger::try_init();

        // Node A: has wallet, creates the TX
        let mut conf_a = Conf::default();
        conf_a.p2p = P2P::Yes;
        let _tmp_a = use_tmpdir(&mut conf_a);
        let mut node_a = corepc_node::Node::from_downloaded_with_conf(&conf_a).unwrap();

        // Node B: connected to Node A, receives the broadcast
        let mut conf_b = Conf::default();
        conf_b.p2p = node_a.p2p_connect(true).unwrap();
        let _tmp_b = use_tmpdir(&mut conf_b);
        let mut node_b = corepc_node::Node::from_downloaded_with_conf(&conf_b).unwrap();
        let node_b_p2p = match node_b.p2p_connect(true).unwrap() {
            P2P::Connect(addr, _) => SocketAddr::V4(addr),
            _ => panic!(),
        };

        // Generate blocks on Node A
        generate_blocks(&mut node_a.client, 101);

        // Wait for Node B to sync
        for _ in 0..50 {
            if get_height(&mut node_b.client) >= 101 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(get_height(&mut node_b.client), 101, "Node B did not sync");

        // Create and sign a TX on Node A (don't broadcast via RPC)
        let addr = node_a.client.new_address().unwrap();
        let mut outputs = BTreeMap::new();
        outputs.insert(addr, Amount::from_sat(50_000));

        let funded = node_a
            .client
            .wallet_create_funded_psbt(vec![], vec![outputs])
            .unwrap();
        let funded_psbt: Psbt = funded.psbt.parse().expect("valid psbt");

        let signed = node_a.client.wallet_process_psbt(&funded_psbt).unwrap();
        let signed_psbt: Psbt = signed.psbt.parse().expect("valid psbt");

        let finalized = node_a.client.finalize_psbt(&signed_psbt).unwrap();
        assert!(finalized.complete, "PSBT not complete");

        let finalized_psbt: Psbt = finalized
            .psbt
            .expect("psbt present")
            .parse()
            .expect("valid psbt");
        let tx = finalized_psbt.extract_tx().expect("extractable tx");
        let broadcast_txid = tx.compute_txid();

        // Verify TX is NOT yet in Node B's mempool
        let mempool = node_b.client.get_raw_mempool().unwrap().0;
        assert!(
            mempool.is_empty(),
            "Node B mempool should be empty before broadcast"
        );

        // Connect our P2P client to Node B and broadcast
        let mut p2p_client = Client::new(node_b_p2p, Network::Regtest)
            .timeout(Duration::from_millis(5000))
            .connect()
            .unwrap();

        p2p_client.broadcast_tx(tx).unwrap();

        for _ in 0..50 {
            let mempool = node_b.client.get_raw_mempool().unwrap().0;
            let mempool_txids: Vec<bitcoin::Txid> =
                mempool.iter().map(|s| s.parse().unwrap()).collect();
            if mempool_txids.contains(&broadcast_txid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "Transaction {broadcast_txid} not found in Node B's mempool after confirmed P2P broadcast"
        );
    }
}
