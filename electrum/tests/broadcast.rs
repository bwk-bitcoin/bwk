use bwk_electrum::client::{Client, Error};
use bwk_utils::test::regtest::bootstrap_electrs;
use miniscript::bitcoin::{
    self, absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// A tx referencing a non-existent UTXO triggers `Response::Error` from electrs;
/// the new `broadcast_tx` must map that to `Error::Rejected` rather than the
/// opaque `Error::WrongResponse` returned by `broadcast`.
#[test]
fn broadcast_tx_rejection_is_typed() {
    let (url, port, _electrs, _bitcoind) = bootstrap_electrs();
    let mut client = Client::new(&url, port).expect("connect");

    // Random outpoint guaranteed not to exist on regtest.
    let bogus = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::Blocks(absolute::Height::ZERO),
        input: vec![TxIn {
            previous_output: OutPoint::new(
                bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
                0,
            ),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFF),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    match client.broadcast_tx(&bogus) {
        Err(Error::Rejected(msg)) => {
            assert!(!msg.is_empty(), "rejection message should be non-empty");
        }
        Err(other) => panic!("expected Rejected, got {other:?}"),
        Ok(txid) => panic!("expected rejection, server accepted tx {txid}"),
    }
}
