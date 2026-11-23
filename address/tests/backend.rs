#![cfg(feature = "bitcoin_0_32")]

use bitcoin_0_32::{
    self as bitcoin,
    address::{self, NetworkUnchecked},
};
use bwk_address::{
    backend::{
        rust_bitcoin::{Address, Error, RustBitcoin, SilentPaymentAddress},
        Backend,
    },
    sp::{Network, SilentPaymentAddressError},
    uri::UriError,
};

const ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const OFF_CURVE_SPEND_KEY: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgp2uexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc56r4em";

#[test]
fn an_address_round_trips() {
    let address = SilentPaymentAddress::try_from(ADDRESS).unwrap();
    assert_eq!(address.get_network(), Network::Mainnet);
    assert_eq!(
        address.get_scan_key().to_string(),
        "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4"
    );
    assert_eq!(address.to_string(), ADDRESS);
    assert_eq!(String::from(address), ADDRESS);
}

#[test]
fn a_key_off_the_curve_is_refused() {
    assert!(matches!(
        SilentPaymentAddress::try_from(OFF_CURVE_SPEND_KEY),
        Err(Error::PublicKey(_))
    ));
}

#[test]
fn an_invalid_address_is_refused() {
    assert!(matches!(
        SilentPaymentAddress::try_from("sp1qqqqqqqqq"),
        Err(Error::SilentPaymentAddress(_))
    ));
}

#[test]
fn a_version_other_than_0_is_refused() {
    let address = SilentPaymentAddress::try_from(ADDRESS).unwrap();
    assert_eq!(
        SilentPaymentAddress::new(
            address.get_scan_key(),
            address.get_spend_key(),
            Network::Mainnet,
            1
        ),
        Err(Error::SilentPaymentAddress(
            SilentPaymentAddressError::UnsupportedVersion(1)
        ))
    );
}

#[test]
fn a_bitcoin_network_maps_to_its_silent_payment_network() {
    for (network, expected) in [
        (bitcoin::Network::Bitcoin, Network::Mainnet),
        (bitcoin::Network::Testnet, Network::Testnet),
        (bitcoin::Network::Signet, Network::Testnet),
        (bitcoin::Network::Regtest, Network::Regtest),
    ] {
        assert_eq!(Network::from(network), expected);
    }
}

const BITCOIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const BAD_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
const TESTNET_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

fn bitcoin_address(text: &str) -> Address {
    Address::Bitcoin(text.parse::<address::Address<NetworkUnchecked>>().unwrap())
}

#[test]
fn a_bitcoin_address_of_any_network_converts() {
    for (uri, expected) in [
        (
            format!("bitcoin:{BITCOIN_ADDRESS}?label=main"),
            BITCOIN_ADDRESS,
        ),
        (
            format!("BITCOIN:{}", BITCOIN_ADDRESS.to_uppercase()),
            BITCOIN_ADDRESS,
        ),
        (format!("bitcoin:{TESTNET_ADDRESS}"), TESTNET_ADDRESS),
    ] {
        assert_eq!(
            RustBitcoin::parse_uri(&uri).unwrap(),
            bitcoin_address(expected),
            "{uri}"
        );
    }
}

#[test]
fn a_silent_payment_address_converts() {
    assert_eq!(
        RustBitcoin::parse_uri(&format!("bitcoin:?sp={ADDRESS}")).unwrap(),
        Address::SilentPayment(SilentPaymentAddress::try_from(ADDRESS).unwrap())
    );
}

#[test]
fn an_invalid_bitcoin_address_is_refused() {
    assert!(matches!(
        RustBitcoin::parse_uri(&format!("bitcoin:{BAD_ADDRESS}")),
        Err(Error::Address(_))
    ));
}

#[test]
fn a_refused_uri_is_a_uri_error() {
    assert_eq!(
        RustBitcoin::parse_uri("bitcoin:"),
        Err(Error::Uri(UriError::NoAddress))
    );
}

#[test]
fn a_bitcoin_amount_is_accepted() {
    for query in [
        "amount=0.1",
        "amount=21000000",
        "amount=0.00000001",
        "label=main",
    ] {
        assert_eq!(
            RustBitcoin::parse_uri(&format!("bitcoin:{BITCOIN_ADDRESS}?{query}")).unwrap(),
            bitcoin_address(BITCOIN_ADDRESS),
            "{query}"
        );
    }
}

#[test]
fn an_amount_that_does_not_parse_is_refused() {
    for amount in ["1,5", "1.123456789", "184467440737.09551616"] {
        assert!(
            matches!(
                RustBitcoin::parse_uri(&format!("bitcoin:{BITCOIN_ADDRESS}?amount={amount}")),
                Err(Error::Amount(_))
            ),
            "{amount}"
        );
    }
}

#[test]
fn a_zero_amount_is_refused() {
    for amount in ["0", "0.00000000"] {
        assert_eq!(
            RustBitcoin::parse_uri(&format!("bitcoin:{BITCOIN_ADDRESS}?amount={amount}")),
            Err(Error::AmountZero),
            "{amount}"
        );
    }
}
