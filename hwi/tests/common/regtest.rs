//! A Bitcoin Core v31 regtest node with a miner wallet. Port of the `Core` wrapper of
//! sign/tests/musig_core_interop.rs:98-224 (af5bc48), without the musig wallet.

use std::{env, str::FromStr};

use bitcoin::{Address, Amount, Transaction, Txid};
use bwk_utils::test::{corepc_node, generate_blocks};
use serde_json::{json, Value};

pub const BITCOIND_V31_EXE: &str = "BITCOIND_V31_EXE";

/// A v31 regtest node with `-txindex` and its miner wallet (110 blocks).
pub struct Core {
    node: corepc_node::Node,
}

impl Core {
    pub fn start() -> Self {
        let exe = env::var(BITCOIND_V31_EXE).unwrap_or_else(|_| {
            panic!(
                "set {BITCOIND_V31_EXE} to a Bitcoin Core v31 bitcoind (hwi/tests/devices/run.sh)"
            )
        });
        let mut conf = corepc_node::Conf::default();
        conf.args.push("-txindex");
        conf.wallet = Some("miner".into());
        let mut node = corepc_node::Node::with_conf(exe, &conf).unwrap();
        let version = node.client.call::<Value>("getnetworkinfo", &[]).unwrap()["version"]
            .as_u64()
            .unwrap();
        assert!(version >= 310_000, "bitcoind {version} is older than v31");
        generate_blocks(&mut node.client, 110);
        Self { node }
    }

    pub fn miner(&self, method: &str, args: &[Value]) -> Value {
        self.node.client.call(method, args).unwrap()
    }

    pub fn mine(&self, blocks: u64) {
        let address = self.miner("getnewaddress", &[]);
        self.miner("generatetoaddress", &[json!(blocks), address]);
    }

    pub fn new_address(&self) -> Address {
        let address = self.miner("getnewaddress", &[]);
        Address::from_str(address.as_str().unwrap())
            .unwrap()
            .assume_checked()
    }

    /// Receive address `index` of the multipath `descriptor`.
    pub fn derive_address(&self, descriptor: &str, index: u32) -> String {
        let addresses = self.miner(
            "deriveaddresses",
            &[json!(descriptor), json!([index, index])],
        );
        // A multipath descriptor gives one list per path, receive first.
        addresses[0][0].as_str().unwrap().to_string()
    }

    /// Sends `amount` to `address` and mines it; the funding transaction and the vout
    /// paying `address`.
    pub fn fund(&self, address: &Address, amount: Amount) -> (Transaction, u32) {
        let txid = self.miner(
            "sendtoaddress",
            &[json!(address.to_string()), json!(amount.to_btc())],
        );
        self.mine(1);
        let hex = self.miner("getrawtransaction", &[txid]);
        let tx: Transaction =
            bitcoin::consensus::encode::deserialize_hex(hex.as_str().unwrap()).unwrap();
        let script = address.script_pubkey();
        let vout = tx
            .output
            .iter()
            .position(|output| output.script_pubkey == script)
            .unwrap();
        (tx, vout as u32)
    }

    /// Broadcasts `hex`, mines a block, asserts the transaction has one
    /// confirmation; its txid.
    pub fn broadcast(&self, hex: &str) -> Txid {
        let txid = self.miner("sendrawtransaction", &[json!(hex)]);
        self.mine(1);
        let tx = self.miner("getrawtransaction", &[txid.clone(), json!(true)]);
        assert_eq!(tx["confirmations"], json!(1), "{tx}");
        Txid::from_str(txid.as_str().unwrap()).unwrap()
    }
}
