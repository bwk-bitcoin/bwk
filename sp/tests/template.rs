//! Tests for the [`bwk_tx::template::TxRequest`]-driven `Account` helpers.
//!
//! These cover the request-validation paths that don't need actual UTXOs:
//! address parsing, the multiple-`max` rule, manual-outpoint lookups
//! against an empty wallet, and the auto-select / insufficient-funds path.
//! Coin-aware paths (drain, spendable filtering, happy-path PSBT generation)
//! are exercised by the existing `BlindbitD`-gated integration suite.

mod common;

use bitcoin::{hashes::Hash, OutPoint};
use bwk_tx::template::{TxOutputSpec, TxRequest, TxRequestError};
use common::test_account_named;

fn account() -> bwk_sp::account::Account {
    test_account_named("template-tests", "http://127.0.0.1:1")
}

fn valid_address() -> &'static str {
    // A real bech32 P2WPKH address. `RecipientAddress::try_from` only checks
    // syntactic validity, so the network doesn't matter for these tests.
    "bc1qkl8ms75cq6ajxtny7e88z3u9hkpkvktt5jwh6u"
}

#[test]
fn multiple_max_outputs_rejected() {
    let acc = account();
    let request = TxRequest {
        outputs: vec![
            TxOutputSpec {
                address: valid_address().into(),
                amount: 0,
                label: None,
                max: true,
            },
            TxOutputSpec {
                address: valid_address().into(),
                amount: 0,
                label: None,
                max: true,
            },
        ],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
    };
    match acc.tx_builder_from_request(&request) {
        Err(TxRequestError::MultipleMaxOutputs) => {}
        Err(other) => panic!("expected MultipleMaxOutputs, got {other:?}"),
        Ok(_) => panic!("expected MultipleMaxOutputs, got Ok"),
    }
}

#[test]
fn invalid_address_is_typed() {
    let acc = account();
    let request = TxRequest {
        outputs: vec![TxOutputSpec {
            address: "this-is-not-an-address".into(),
            amount: 1_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
    };
    match acc.tx_builder_from_request(&request) {
        Err(TxRequestError::InvalidAddress { address, .. }) => {
            assert_eq!(address, "this-is-not-an-address");
        }
        Err(other) => panic!("expected InvalidAddress, got {other:?}"),
        Ok(_) => panic!("expected InvalidAddress, got Ok"),
    }
}

#[test]
fn manual_outpoint_not_in_wallet_is_coin_not_found() {
    let acc = account();
    let outpoint = OutPoint {
        txid: bitcoin::Txid::from_byte_array([7u8; 32]),
        vout: 0,
    };
    let request = TxRequest {
        outputs: vec![TxOutputSpec {
            address: valid_address().into(),
            amount: 1_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![outpoint],
    };
    match acc.tx_builder_from_request(&request) {
        Err(TxRequestError::CoinNotFound(op)) => assert_eq!(op, outpoint),
        Err(other) => panic!("expected CoinNotFound, got {other:?}"),
        Ok(_) => panic!("expected CoinNotFound, got Ok"),
    }
}

#[test]
fn auto_select_on_empty_wallet_is_insufficient_funds() {
    let acc = account();
    let request = TxRequest {
        outputs: vec![TxOutputSpec {
            address: valid_address().into(),
            amount: 100_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
    };
    match acc.simulate(&request) {
        Err(TxRequestError::InsufficientFunds) => {}
        Err(other) => panic!("expected InsufficientFunds, got {other:?}"),
        Ok(_) => panic!("expected InsufficientFunds, got Ok"),
    }
}
