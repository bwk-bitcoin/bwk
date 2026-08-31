use bwk_electrum::client::Client;
use bwk_utils::test::{regtest::bootstrap_electrs_with_args, wait_electrs_tip, TestBitcoinD};
use electrsd::{
    bitcoind::bitcoincore_rpc::{self, RpcApi},
    ElectrsD,
};
use miniscript::bitcoin::{
    self, absolute, transaction, Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

/// `-txindex`, so the node hands back any raw tx by txid and not only the ones
/// its own wallet holds.
fn bootstrap_electrs() -> (String, u16, ElectrsD, TestBitcoinD) {
    bootstrap_electrs_with_args(&["-txindex"])
}

fn rpc_address(rpc: &bitcoincore_rpc::Client) -> Address {
    let raw: String = rpc.call("getnewaddress", &[]).unwrap();
    let unchecked: Address<bitcoin::address::NetworkUnchecked> = raw.parse().unwrap();
    unchecked.require_network(Network::Regtest).unwrap()
}

fn mine_to_address(rpc: &bitcoincore_rpc::Client, n: u64, addr: &Address) {
    let _: Vec<bitcoin::BlockHash> = rpc
        .call("generatetoaddress", &[n.into(), addr.to_string().into()])
        .unwrap();
}

#[test]
fn validate_psbt_reports_reused_output() {
    let (url, port, electrs, bitcoind) = bootstrap_electrs();
    let rpc = &bitcoind.client;

    let addr = rpc_address(rpc);
    mine_to_address(rpc, 110, &addr);
    wait_electrs_tip(&bitcoind, &electrs);

    let mut client = Client::new(&url, port).expect("connect");

    let unsigned = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: addr.script_pubkey(),
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned).expect("psbt");

    let report = client.validate_psbt(&psbt).expect("validate");
    assert_eq!(
        report.reused_outputs.len(),
        1,
        "expected reused output, got {report:?}",
    );
    assert_eq!(report.reused_outputs[0].index, 0);
    assert_eq!(report.reused_outputs[0].script_pubkey, addr.script_pubkey());
    assert!(report.spent_inputs.is_empty());
}

#[test]
fn validate_psbt_clean_when_no_history() {
    let (url, port, electrs, bitcoind) = bootstrap_electrs();
    let rpc = &bitcoind.client;

    let addr = rpc_address(rpc);
    mine_to_address(rpc, 110, &addr);
    wait_electrs_tip(&bitcoind, &electrs);

    let mut client = Client::new(&url, port).expect("connect");

    // Fresh address: getnewaddress returns one that has never received funds.
    let fresh = rpc_address(rpc);

    let unsigned = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: fresh.script_pubkey(),
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned).expect("psbt");

    let report = client.validate_psbt(&psbt).expect("validate");
    assert!(report.is_clean(), "expected clean, got {report:?}");
}

#[test]
fn validate_psbt_skips_op_return() {
    let (url, port, _electrs, _bitcoind) = bootstrap_electrs();
    let mut client = Client::new(&url, port).expect("connect");

    use bitcoin::script::PushBytesBuf;
    let op_return = ScriptBuf::new_op_return(PushBytesBuf::try_from(b"hello".to_vec()).unwrap());
    let unsigned = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
        input: vec![],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: op_return,
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned).expect("psbt");
    let report = client.validate_psbt(&psbt).expect("validate");
    assert!(report.is_clean(), "expected clean, got {report:?}");
}

#[test]
fn validate_psbt_reports_spent_input() {
    use bitcoin::consensus::encode::deserialize as consensus_deserialize;
    use hex_conservative::FromHex;

    let (url, port, electrs, bitcoind) = bootstrap_electrs();
    let rpc = &bitcoind.client;

    let mining_addr = rpc_address(rpc);
    mine_to_address(rpc, 110, &mining_addr);
    wait_electrs_tip(&bitcoind, &electrs);

    // Send to a known address, creating a UTXO owned by pay_addr.
    let pay_addr = rpc_address(rpc);
    let funding_txid_hex: String = rpc
        .call(
            "sendtoaddress",
            &[pay_addr.to_string().into(), "1.0".into()],
        )
        .unwrap();
    let funding_txid: bitcoin::Txid = funding_txid_hex.parse().unwrap();
    mine_to_address(rpc, 1, &mining_addr);
    wait_electrs_tip(&bitcoind, &electrs);

    let raw_hex: String = rpc
        .call("getrawtransaction", &[funding_txid_hex.clone().into()])
        .unwrap();
    let bytes = Vec::<u8>::from_hex(&raw_hex).unwrap();
    let funding_tx: Transaction = consensus_deserialize(&bytes).unwrap();
    let (vout_idx, funding_txout) = funding_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == pay_addr.script_pubkey())
        .map(|(i, o)| (i as u32, o.clone()))
        .expect("pay_addr output");

    let outpoint = OutPoint::new(funding_txid, vout_idx);

    // Spend the UTXO into another address; outpoint is now consumed.
    let spend_dest = rpc_address(rpc);
    let raw_inputs = serde_json::json!([
        {"txid": funding_txid_hex, "vout": vout_idx}
    ]);
    let raw_outputs = serde_json::json!([
        {spend_dest.to_string(): "0.999"}
    ]);
    let spend_hex: String = rpc
        .call("createrawtransaction", &[raw_inputs, raw_outputs])
        .unwrap();
    let signed: serde_json::Value = rpc
        .call("signrawtransactionwithwallet", &[spend_hex.into()])
        .unwrap();
    let signed_hex = signed["hex"].as_str().expect("signed hex").to_string();
    let _: String = rpc
        .call("sendrawtransaction", &[signed_hex.into()])
        .unwrap();
    mine_to_address(rpc, 1, &mining_addr);
    wait_electrs_tip(&bitcoind, &electrs);

    let mut client = Client::new(&url, port).expect("connect");
    let unsigned = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: mining_addr.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(funding_txout);

    let report = client.validate_psbt(&psbt).expect("validate");
    assert_eq!(
        report.spent_inputs.len(),
        1,
        "expected spent input, got {report:?}",
    );
    assert_eq!(report.spent_inputs[0].outpoint, outpoint);
}
