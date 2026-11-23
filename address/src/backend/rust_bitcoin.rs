use alloc::string::{String, ToString};
use core::fmt;

#[cfg(feature = "serde")]
use serde::{ser::Serializer, Deserialize, Deserializer, Serialize};

use bitcoin_0_32::{
    self as bitcoin,
    address::{self, NetworkUnchecked},
    amount,
    secp256k1::{self, PublicKey},
    Amount, Denomination,
};

use crate::{
    backend::Backend,
    sp::{Network, RawSilentPaymentAddress, SilentPaymentAddressError, PUBLIC_KEY_LEN},
    uri::UriError,
};

pub enum RustBitcoin {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    SilentPaymentAddress(SilentPaymentAddressError),
    PublicKey(secp256k1::Error),
    Uri(UriError),
    Address(address::ParseError),
    Amount(amount::ParseAmountError),
    AmountZero,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SilentPaymentAddress(e) => write!(f, "invalid silent payment address: {e}"),
            Self::PublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::Uri(e) => write!(f, "invalid URI: {e}"),
            Self::Address(e) => write!(f, "invalid address: {e}"),
            Self::Amount(e) => write!(f, "invalid amount: {e}"),
            Self::AmountZero => f.write_str("amount must not be zero"),
        }
    }
}

impl core::error::Error for Error {}

impl From<SilentPaymentAddressError> for Error {
    fn from(error: SilentPaymentAddressError) -> Self {
        Self::SilentPaymentAddress(error)
    }
}

impl From<UriError> for Error {
    fn from(error: UriError) -> Self {
        Self::Uri(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Bitcoin(bitcoin::Address<NetworkUnchecked>),
    SilentPayment(SilentPaymentAddress),
}

impl From<bitcoin::Address<NetworkUnchecked>> for Address {
    fn from(address: bitcoin::Address<NetworkUnchecked>) -> Self {
        Self::Bitcoin(address)
    }
}

impl From<SilentPaymentAddress> for Address {
    fn from(address: SilentPaymentAddress) -> Self {
        Self::SilentPayment(address)
    }
}

impl Backend for RustBitcoin {
    type SilentPaymentAddress = SilentPaymentAddress;
    type BitcoinAddress = bitcoin::Address<NetworkUnchecked>;
    type Address = Address;
    type Error = Error;

    fn silent_payment_address(
        network: Network,
        scan_key: &[u8; PUBLIC_KEY_LEN],
        spend_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<SilentPaymentAddress, Error> {
        SilentPaymentAddress::new(public_key(scan_key)?, public_key(spend_key)?, network, 0)
    }

    fn bitcoin_address(address: &str) -> Result<bitcoin::Address<NetworkUnchecked>, Error> {
        address.parse().map_err(Error::Address)
    }

    fn check_amount(amount: &str) -> Result<(), Error> {
        match Amount::from_str_in(amount, Denomination::Bitcoin).map_err(Error::Amount)? {
            Amount::ZERO => Err(Error::AmountZero),
            _ => Ok(()),
        }
    }
}

fn public_key(key: &[u8; PUBLIC_KEY_LEN]) -> Result<PublicKey, Error> {
    PublicKey::from_slice(key).map_err(Error::PublicKey)
}

impl From<bitcoin::Network> for Network {
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => Network::Mainnet,
            bitcoin::Network::Regtest => Network::Regtest,
            _ => Network::Testnet,
        }
    }
}

/// A silent payment address struct that can be used to deserialize a silent payment address string.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

#[cfg(feature = "serde")]
impl Serialize for SilentPaymentAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = (*self).into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SilentPaymentAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addr_str: String = Deserialize::deserialize(deserializer)?;

        SilentPaymentAddress::try_from(addr_str.as_str()).map_err(serde::de::Error::custom)
    }
}

impl SilentPaymentAddress {
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: u8,
    ) -> Result<Self, Error> {
        if version != 0 {
            return Err(SilentPaymentAddressError::UnsupportedVersion(version).into());
        }

        Ok(SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            network,
            version,
        })
    }

    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    pub fn get_network(&self) -> Network {
        self.network
    }
}

impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        RawSilentPaymentAddress {
            network: self.network,
            scan_key: self.scan_pubkey.serialize(),
            spend_key: self.m_pubkey.serialize(),
        }
        .fmt(f)
    }
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self, Self::Error> {
        RustBitcoin::parse_silent_payment_address(addr)
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self, Self::Error> {
        addr.as_str().try_into()
    }
}

impl From<SilentPaymentAddress> for String {
    fn from(val: SilentPaymentAddress) -> Self {
        val.to_string()
    }
}
