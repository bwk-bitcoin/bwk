use core::fmt;

use crate::{
    sp::{Network, RawSilentPaymentAddress, SilentPaymentAddressError, PUBLIC_KEY_LEN},
    uri::{self, UriAddress, UriError},
};

#[cfg(feature = "bitcoin_0_32")]
pub mod rust_bitcoin;

pub trait Backend {
    type SilentPaymentAddress;
    type BitcoinAddress;
    type Address: From<Self::BitcoinAddress> + From<Self::SilentPaymentAddress>;
    type Error: fmt::Debug + fmt::Display + From<SilentPaymentAddressError> + From<UriError>;

    fn silent_payment_address(
        network: Network,
        scan_key: &[u8; PUBLIC_KEY_LEN],
        spend_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<Self::SilentPaymentAddress, Self::Error>;

    fn bitcoin_address(address: &str) -> Result<Self::BitcoinAddress, Self::Error>;

    fn check_amount(amount: &str) -> Result<(), Self::Error>;

    fn parse_silent_payment_address(
        address: &str,
    ) -> Result<Self::SilentPaymentAddress, Self::Error> {
        let raw = RawSilentPaymentAddress::decode(address)?;
        Self::silent_payment_address(raw.network, &raw.scan_key, &raw.spend_key)
    }

    fn parse_uri(uri: &str) -> Result<Self::Address, Self::Error> {
        let uri = uri::parse(uri)?;
        if let Some(amount) = uri.amount {
            Self::check_amount(amount)?;
        }
        match uri.address {
            UriAddress::Bitcoin(address) => Ok(Self::bitcoin_address(address)?.into()),
            UriAddress::SilentPayment(address) => {
                Ok(Self::parse_silent_payment_address(address)?.into())
            }
        }
    }
}
