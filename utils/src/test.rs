pub mod regtest;

use std::{
    env,
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
    sync::Once,
};

pub use corepc_node::{self, Client, Node};
pub use electrsd;
pub use miniscript;
pub use temp_dir::TempDir;

use miniscript::bitcoin::{
    self, hashes::serde_macros::serde_details::SerdeHash, key::rand::random, Address, Amount,
    BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use rand::Rng;

static INIT: Once = Once::new();

pub fn setup_logger() {
    INIT.call_once(|| {
        env_logger::builder()
            // Ensures output is only printed in test mode
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .init();
    });
}

// generate a dummy txid
pub fn txid() -> bitcoin::Txid {
    let raw: [u8; 32] = random();
    bitcoin::Txid::from_slice_delegated(&raw).expect("Invalid Txid")
}

/// Generates a random Bitcoin transaction input.
#[allow(deprecated)]
pub fn random_input() -> TxIn {
    let mut rng = rand::thread_rng();
    let txid = txid();
    let vout = rng.gen_range(0..10);
    TxIn {
        previous_output: OutPoint::new(txid, vout),
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        witness: bitcoin::Witness::new(),
    }
}

/// Generates a random Bitcoin transaction output.
#[allow(deprecated)]
pub fn random_output() -> TxOut {
    let mut rng = rand::thread_rng();
    let value = rng.gen_range(1..100_000);
    let script_pubkey = ScriptBuf::new();
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey,
    }
}

/// Generates a funding transaction paying to a given spk with additional
/// random inputs and outputs.
#[allow(deprecated)]
pub fn funding_tx(spk: ScriptBuf, amount: f64) -> bitcoin::Transaction {
    let num_inputs = rand::thread_rng().gen_range(1..10);
    let num_outputs = rand::thread_rng().gen_range(1..5);

    let mut input = vec![];
    let mut output = vec![];

    for _ in 0..num_inputs {
        input.push(random_input());
    }

    for _ in 0..num_outputs {
        output.push(random_output());
    }

    output.push(TxOut {
        value: Amount::from_btc(amount).unwrap(),
        script_pubkey: spk,
    });

    bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::Blocks(bitcoin::absolute::Height::ZERO),
        input,
        output,
    }
}

/// Generates a spending transaction, spending a given outpoint with additional
/// random inputs and outputs.
#[allow(deprecated)]
pub fn spending_tx(outpoint: bitcoin::OutPoint) -> bitcoin::Transaction {
    let num_inputs = rand::thread_rng().gen_range(1..=10);
    let num_outputs = rand::thread_rng().gen_range(0..=5);

    let mut input = vec![TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence(0xFFFFFFFF),
        witness: bitcoin::Witness::new(),
    }];

    for _ in 0..(num_inputs - 1) {
        input.push(random_input());
    }

    let mut output = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        output.push(random_output());
    }

    bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::Blocks(bitcoin::absolute::Height::ZERO),
        input,
        output,
    }
}

pub fn generate_blocks(bitcoind: &mut Client, blocks: usize) {
    let addr = bitcoind.new_address().unwrap();
    bitcoind.generate_to_address(blocks, &addr).unwrap();
}

pub fn send(bitcoind: &mut Client, addr: Address, btc: f64) -> Option<Txid> {
    bitcoind
        .send_to_address(&addr, Amount::from_btc(btc).unwrap())
        .unwrap()
        .txid()
        .ok()
}

pub fn send_sats(bitcoind: &mut Client, addr: Address, sats: u64) -> Option<Txid> {
    bitcoind
        .send_to_address(&addr, Amount::from_sat(sats))
        .unwrap()
        .txid()
        .ok()
}

pub struct TestNode {
    node: corepc_node::Node,
    _tmp: TempDir,
}

pub struct TestBitcoinD {
    bitcoind: electrsd::bitcoind::BitcoinD,
    _tmp: TempDir,
}

impl Deref for TestBitcoinD {
    type Target = electrsd::bitcoind::BitcoinD;

    fn deref(&self) -> &Self::Target {
        &self.bitcoind
    }
}

impl DerefMut for TestBitcoinD {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bitcoind
    }
}

pub fn bootstrap_electrs(txindex: bool) -> (String, u16, electrsd::ElectrsD, TestBitcoinD) {
    let mut cwd: PathBuf = env::current_dir().expect("current_dir");
    cwd.push("tests");

    let mut bitcoind_path = cwd;
    bitcoind_path.push("bin");
    bitcoind_path.push("bitcoind_25_2");

    let mut conf = electrsd::bitcoind::Conf::default();
    conf.p2p = electrsd::bitcoind::P2P::Yes;
    if txindex {
        conf.args.push("-txindex");
    }
    let tmp = TempDir::with_prefix("bwk-bitcoind").unwrap();
    conf.staticdir = Some(tmp.path().to_path_buf());
    let bitcoind = TestBitcoinD {
        bitcoind: electrsd::bitcoind::BitcoinD::with_conf(&bitcoind_path, &conf)
            .unwrap_or_else(|e| panic!("failed to start bitcoind: {e:?}")),
        _tmp: tmp,
    };

    let (url, port, electrsd) = start_electrs(&bitcoind);

    (url, port, electrsd, bitcoind)
}

pub fn start_electrs(bitcoind: &electrsd::bitcoind::BitcoinD) -> (String, u16, electrsd::ElectrsD) {
    let mut electrs_path: PathBuf = env::current_dir().expect("current_dir");
    electrs_path.push("tests");
    electrs_path.push("bin");
    electrs_path.push("electrs_0_9_11");

    let mut electrsd_conf = electrsd::Conf::default();
    electrsd_conf.args = vec!["--skip-default-conf-files", "--log-filters", "DEBUG"];
    electrsd_conf.buffered_logs = true;
    let electrsd = electrsd::ElectrsD::with_conf(electrs_path, bitcoind, &electrsd_conf).unwrap();
    let (url, port) = electrsd.electrum_url.split_once(':').unwrap();
    let port = port.parse::<u16>().unwrap();

    (url.into(), port, electrsd)
}

pub fn wait_electrs_tip(bitcoind: &electrsd::bitcoind::BitcoinD, electrsd: &electrsd::ElectrsD) {
    use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
    use electrsd::electrum_client::ElectrumApi;

    let target: u64 = bitcoind.client.call("getblockcount", &[]).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if let Ok(header) = electrsd.client.block_headers_subscribe() {
            if header.height as u64 >= target {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("electrs did not catch up to height {target}");
}

impl Deref for TestNode {
    type Target = corepc_node::Node;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl DerefMut for TestNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

pub fn bitcoind_with_txindex() -> TestNode {
    let mut conf = corepc_node::Conf::default();
    let tmp = TempDir::with_prefix("bwk-utils-bitcoind").unwrap();
    conf.staticdir = Some(tmp.path().to_path_buf());
    conf.args.push("-txindex");
    let node = corepc_node::Node::from_downloaded_with_conf(&conf)
        .unwrap_or_else(|e| panic!("failed to start bitcoind: {e:?}"));
    let mut node = TestNode { node, _tmp: tmp };
    generate_blocks(&mut node.client, 110);
    node
}

pub fn get_tx(bitcoind: &mut Client, txid: Txid) -> Option<Transaction> {
    bitcoind
        .get_raw_transaction(txid)
        .unwrap()
        .transaction()
        .ok()
}

pub fn get_height(bitcoind: &mut Client) -> u64 {
    bitcoind.get_block_count().unwrap().0
}

pub fn get_tx_height(bitcoind: &mut Client, txid: Txid) -> Option<u64> {
    let hash = bitcoind
        .get_raw_transaction_verbose(txid)
        .unwrap()
        .block_hash?;
    let hash = BlockHash::from_str(&hash).unwrap();
    bitcoind.get_block(hash).unwrap().bip34_block_height().ok()
}

pub fn txouts_for(addr: &Address, tx: &Transaction) -> Vec<(usize /* index */, TxOut)> {
    let mut txouts = vec![];
    for (index, txout) in tx.output.iter().enumerate() {
        if txout.script_pubkey == addr.script_pubkey() {
            txouts.push((index, txout.clone()));
        }
    }
    txouts
}

#[test]
fn gen_txid() {
    setup_logger();
    let tx = txid();
    log::debug!("{tx:?}");
    let tx = txid();
    log::debug!("{tx:?}");
}
