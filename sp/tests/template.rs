//! Tests for the [`bwk_tx::template::TxRequest`]-driven `Account` helpers.
//!
//! These cover the request-validation paths that don't need actual UTXOs:
//! address parsing, the multiple-`max` rule, manual-outpoint lookups
//! against an empty wallet, and the auto-select / insufficient-funds path.
//! Coin-aware paths (drain, spendable filtering, happy-path PSBT generation)
//! are exercised by the existing `BlindbitD`-gated integration suite.

mod common;

use bitcoin::{hashes::Hash, Address, Network, OutPoint, ScriptBuf};
use bwk_sp::{
    core::utils::common::{Network as SpNetwork, SilentPaymentAddress},
    receiver::error::Error as ReceiverError,
};
use bwk_tx::template::{TxOutputSpec, TxRequest, TxRequestError};
use common::test_account_named;

fn account() -> bwk_sp::account::Account {
    test_account_named("template-tests", "http://127.0.0.1:1")
}

fn address(network: Network) -> String {
    Address::p2wsh(&ScriptBuf::new(), network).to_string()
}

fn valid_address() -> String {
    address(Network::Regtest)
}

#[test]
fn multiple_max_outputs_rejected() {
    let acc = account();
    let request = TxRequest {
        outputs: vec![
            TxOutputSpec {
                address: valid_address(),
                amount: 0,
                label: None,
                max: true,
            },
            TxOutputSpec {
                address: valid_address(),
                amount: 0,
                label: None,
                max: true,
            },
        ],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
        dust_threshold: None,
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
        dust_threshold: None,
    };
    match acc.tx_builder_from_request(&request) {
        Err(TxRequestError::InvalidAddress { address, .. }) => {
            assert_eq!(address, "this-is-not-an-address");
        }
        Err(other) => panic!("expected InvalidAddress, got {other:?}"),
        Ok(_) => panic!("expected InvalidAddress, got Ok"),
    }
}

fn send_to(address: &str) -> TxRequest {
    TxRequest {
        outputs: vec![TxOutputSpec {
            address: address.into(),
            amount: 1_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
        dust_threshold: None,
    }
}

fn invalid_address_source(acc: &bwk_sp::account::Account, address: &str) -> ReceiverError {
    match acc.tx_builder_from_request(&send_to(address)) {
        Err(TxRequestError::InvalidAddress {
            address: rejected,
            source,
        }) => {
            assert_eq!(rejected, address);
            *source.downcast::<ReceiverError>().unwrap()
        }
        Err(other) => panic!("expected InvalidAddress, got {other:?}"),
        Ok(_) => panic!("expected InvalidAddress, got Ok"),
    }
}

fn sp_address(acc: &bwk_sp::account::Account, network: SpNetwork) -> String {
    let own = acc.sp_address();
    SilentPaymentAddress::new(own.get_scan_key(), own.get_spend_key(), network, 0)
        .unwrap()
        .to_string()
}

#[test]
fn legacy_address_on_other_network_is_rejected() {
    let acc = account();
    for network in [Network::Bitcoin, Network::Testnet, Network::Signet] {
        let addr = address(network);
        match invalid_address_source(&acc, &addr) {
            ReceiverError::Address(_) => {}
            other => panic!("expected Address, got {other:?}"),
        }
    }
}

#[test]
fn sp_address_on_other_network_is_rejected() {
    let acc = account();
    for network in [SpNetwork::Mainnet, SpNetwork::Testnet] {
        let addr = sp_address(&acc, network);
        match invalid_address_source(&acc, &addr) {
            ReceiverError::SpNetworkMismatch { address, account } => {
                assert_eq!(address, network);
                assert_eq!(account, SpNetwork::Regtest);
            }
            other => panic!("expected SpNetworkMismatch, got {other:?}"),
        }
    }
}

#[test]
fn address_on_account_network_is_accepted() {
    let acc = account();
    for addr in [valid_address(), sp_address(&acc, SpNetwork::Regtest)] {
        assert!(acc.tx_builder_from_request(&send_to(&addr)).is_ok());
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
            address: valid_address(),
            amount: 1_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![outpoint],
        dust_threshold: None,
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
            address: valid_address(),
            amount: 100_000,
            label: None,
            max: false,
        }],
        fee_rate: 1.0,
        fee: 0,
        input_outpoints: vec![],
        dust_threshold: None,
    };
    match acc.simulate(&request) {
        Err(TxRequestError::InsufficientFunds) => {}
        Err(other) => panic!("expected InsufficientFunds, got {other:?}"),
        Ok(_) => panic!("expected InsufficientFunds, got Ok"),
    }
}
