//! Regtest harness: a bitcoind + electrs pair and the block helpers that
//! drive them.
//!
//! The node binaries are looked up under `tests/bin` of the crate running the
//! test, so each consumer ships its own pair.

use std::{
    thread::sleep,
    time::{Duration, Instant},
};

use crate::test::{
    electrsd::{
        bitcoind::{
            bitcoincore_rpc::{jsonrpc::serde_json::Value, RpcApi},
            BitcoinD,
        },
        ElectrsD,
    },
    start_electrs, wait_electrs_tip, TestBitcoinD,
};

/// Spin up bitcoind + electrs and pre-mine 101 blocks so coins to fresh
/// addresses can be confirmed immediately.
pub fn bootstrap_electrs() -> (String, u16, ElectrsD, TestBitcoinD) {
    bootstrap_electrs_with_args(&[])
}

/// [`bootstrap_electrs`] with extra `bitcoind` command line arguments, for a
/// test that needs the node configured differently (`-txindex` and such).
pub fn bootstrap_electrs_with_args(
    bitcoind_args: &[&str],
) -> (String, u16, ElectrsD, TestBitcoinD) {
    let txindex = bitcoind_args.contains(&"-txindex");
    let (url, port, electrsd, bitcoind) = crate::test::bootstrap_electrs(txindex);
    generate(&bitcoind, 101);
    wait_electrs_synced(&bitcoind, &electrsd);
    (url, port, electrsd, bitcoind)
}

/// Wait until electrs has indexed up to bitcoind's tip, so a test does not
/// start querying it while it is still ingesting the pre-mined blocks.
fn wait_electrs_synced(bitcoind: &BitcoinD, electrsd: &ElectrsD) {
    wait_electrs_tip(bitcoind, electrsd);
}

/// Kill `electrsd` and spin up a fresh electrs process against the same
/// `bitcoind`, simulating a server restart (the new process gets its own
/// port; callers must repoint their client at the returned url/port).
pub fn restart_electrs(mut electrsd: ElectrsD, bitcoind: &BitcoinD) -> (String, u16, ElectrsD) {
    electrsd.kill().expect("kill electrs");
    start_electrs(bitcoind)
}

pub fn generate(bitcoind: &BitcoinD, blocks: u32) {
    let node_address = bitcoind.client.call::<Value>("getnewaddress", &[]).unwrap();
    bitcoind
        .client
        .call::<Value>("generatetoaddress", &[blocks.into(), node_address])
        .unwrap();
}

pub fn get_block_height(bitcoind: &BitcoinD) -> u32 {
    bitcoind.client.call("getblockcount", &[]).unwrap()
}

pub fn get_block_hash_str(bitcoind: &BitcoinD, height: u32) -> String {
    bitcoind
        .client
        .call("getblockhash", &[height.into()])
        .unwrap()
}

pub fn invalidate_block(bitcoind: &BitcoinD, hash: String) {
    bitcoind
        .client
        .call::<Value>("invalidateblock", &[hash.into()])
        .unwrap();
}

/// Poll `cond` for up to `timeout`. Returns true if it ever held.
pub fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut cond: F) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        sleep(Duration::from_millis(100));
    }
    cond()
}

/// Logger for the regtest tests. Unlike [`crate::test::setup_logger`] it keeps the
/// `RUST_LOG` default, so bitcoind and electrs do not flood the output.
pub fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}
