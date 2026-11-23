use core::fmt;

use bwk_address::{
    backend::Backend,
    sp::{Network, SilentPaymentAddressError, PUBLIC_KEY_LEN},
    uri::UriError,
};

const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TESTNET_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

#[derive(Debug, PartialEq)]
enum MockAddress {
    Bitcoin(String),
    SilentPayment(Network),
}

impl From<String> for MockAddress {
    fn from(address: String) -> Self {
        Self::Bitcoin(address)
    }
}

impl From<Network> for MockAddress {
    fn from(network: Network) -> Self {
        Self::SilentPayment(network)
    }
}

#[derive(Debug, PartialEq)]
enum MockError {
    SilentPaymentAddress(SilentPaymentAddressError),
    Uri(UriError),
    Amount(String),
}

impl fmt::Display for MockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<SilentPaymentAddressError> for MockError {
    fn from(error: SilentPaymentAddressError) -> Self {
        Self::SilentPaymentAddress(error)
    }
}

impl From<UriError> for MockError {
    fn from(error: UriError) -> Self {
        Self::Uri(error)
    }
}

enum Mock {}

impl Backend for Mock {
    type SilentPaymentAddress = Network;
    type BitcoinAddress = String;
    type Address = MockAddress;
    type Error = MockError;

    fn silent_payment_address(
        network: Network,
        _scan_key: &[u8; PUBLIC_KEY_LEN],
        _spend_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Network, MockError> {
        Ok(network)
    }

    fn bitcoin_address(address: &str) -> Result<String, MockError> {
        Ok(address.to_string())
    }

    fn check_amount(amount: &str) -> Result<(), MockError> {
        match amount {
            "refused" => Err(MockError::Amount(amount.to_string())),
            _ => Ok(()),
        }
    }
}

fn bitcoin_address(text: &str) -> MockAddress {
    MockAddress::Bitcoin(text.to_string())
}

fn parsed(uri: &str) -> MockAddress {
    Mock::parse_uri(uri).unwrap()
}

fn uri_error(uri: &str) -> UriError {
    match Mock::parse_uri(uri) {
        Err(MockError::Uri(error)) => error,
        other => panic!("{uri}: {other:?}"),
    }
}

#[test]
fn a_bitcoin_address_uri_parses() {
    for uri in [
        format!("bitcoin:{ADDRESS}"),
        format!("bitcoin:{ADDRESS}?label=main&amount=0.1&message=hi%20there"),
        format!("bitcoin:{ADDRESS}?foo=bar&lightning=lnbc1&&pop=wallet%3A"),
        format!("  bitcoin:{ADDRESS}?req-pop=wallet%3A  "),
    ] {
        assert_eq!(parsed(&uri), bitcoin_address(ADDRESS), "{uri}");
    }
}

#[test]
fn an_uppercase_uri_keeps_the_address_case() {
    let upper = ADDRESS.to_uppercase();
    assert_eq!(
        parsed(&format!("BITCOIN:{upper}?LABEL=MAIN&Amount=1")),
        bitcoin_address(&upper)
    );
}

#[test]
fn an_address_of_any_network_parses() {
    assert_eq!(
        parsed(&format!("bitcoin:{TESTNET_ADDRESS}")),
        bitcoin_address(TESTNET_ADDRESS)
    );
}

#[test]
fn a_silent_payment_uri_parses() {
    for uri in [
        format!("bitcoin:?sp={SP_ADDRESS}"),
        format!("BITCOIN:?SP={SP_ADDRESS}"),
        format!("BITCOIN:?SP={}", SP_ADDRESS.to_uppercase()),
        format!("bitcoin:?req-sp={SP_ADDRESS}"),
        format!("bitcoin:?lightning=lnbc1&label=main&sp={SP_ADDRESS}&"),
        format!("bitcoin:?bc={ADDRESS}&sp={SP_ADDRESS}"),
    ] {
        assert_eq!(
            parsed(&uri),
            MockAddress::SilentPayment(Network::Mainnet),
            "{uri}"
        );
    }
}

#[test]
fn an_invalid_silent_payment_address_is_refused() {
    let broken = format!("{}q", &SP_ADDRESS[..SP_ADDRESS.len() - 1]);
    for address in [broken.as_str(), "sp1qqqqqqqqq", ADDRESS] {
        assert!(
            matches!(
                Mock::parse_uri(&format!("bitcoin:?sp={address}")),
                Err(MockError::SilentPaymentAddress(_))
            ),
            "{address}"
        );
    }
}

#[test]
fn the_amount_goes_to_the_backend() {
    assert_eq!(
        Mock::parse_uri(&format!("bitcoin:{ADDRESS}?amount=refused")),
        Err(MockError::Amount("refused".to_string()))
    );
}

#[test]
fn a_uri_of_another_scheme_is_refused() {
    for uri in [
        "litecoin:x",
        "bitcoin",
        "",
        "bitcoi\u{20ac}:x",
        "bitcoin2:x",
    ] {
        assert_eq!(uri_error(uri), UriError::InvalidScheme, "{uri}");
    }
}

#[test]
fn an_address_outside_the_uri_grammar_is_refused() {
    for (uri, address) in [
        ("bitcoin:bc1q-w508".to_string(), "bc1q-w508"),
        (format!("bitcoin:?bc=bc1q%20x&sp={SP_ADDRESS}"), "bc1q%20x"),
    ] {
        assert_eq!(
            uri_error(&uri),
            UriError::InvalidAddress(address.to_string()),
            "{uri}"
        );
    }
}

#[test]
fn a_parameter_without_a_value_is_refused() {
    assert_eq!(
        uri_error(&format!("bitcoin:{ADDRESS}?label")),
        UriError::MalformedParam("label".to_string())
    );
}

#[test]
fn a_duplicate_parameter_is_refused() {
    for key in ["amount", "label", "message", "pop"] {
        assert_eq!(
            uri_error(&format!(
                "bitcoin:{ADDRESS}?{key}=1&req-{}=2",
                key.to_uppercase()
            )),
            UriError::DuplicateParam(key.to_string())
        );
    }
}

#[test]
fn discarded_values_are_not_checked() {
    for query in [
        "message=%ff",
        "label=%c3",
        "foo=%ff",
        "req-pop=https%3A%2F%2Fexample.com",
    ] {
        assert_eq!(
            parsed(&format!("bitcoin:{ADDRESS}?{query}")),
            bitcoin_address(ADDRESS),
            "{query}"
        );
    }
}

#[test]
fn an_unknown_required_parameter_is_refused() {
    assert_eq!(
        uri_error(&format!("bitcoin:{ADDRESS}?REQ-Foo=1")),
        UriError::UnsupportedRequiredParam("foo".to_string())
    );
}

#[test]
fn a_uri_without_an_address_is_refused() {
    for uri in [
        "bitcoin:",
        "bitcoin:?label=main",
        "bitcoin:?sp=",
        "bitcoin:?lightning=lnbc1",
        "bitcoin:?bc=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ] {
        assert_eq!(uri_error(uri), UriError::NoAddress, "{uri}");
    }
}

#[test]
fn a_uri_with_more_than_one_address_is_refused() {
    for uri in [
        format!("bitcoin:{ADDRESS}?sp={SP_ADDRESS}"),
        format!("bitcoin:?sp={SP_ADDRESS}&sp={SP_ADDRESS}"),
        format!("bitcoin:?sp={SP_ADDRESS}&sp="),
    ] {
        assert_eq!(uri_error(&uri), UriError::MultipleAddresses, "{uri}");
    }
}
