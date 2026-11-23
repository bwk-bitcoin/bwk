//! Source: derived from cygnet3/rust-silentpayments (MIT). See `NOTICE`.

use alloc::string::{String, ToString};
use core::fmt;

use bech32::{
    primitives::{
        decode::{CheckedHrpstring, CheckedHrpstringError},
        iter::{ByteIterExt, Fe32IterExt},
    },
    Bech32m, Fe32, Hrp,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub const PUBLIC_KEY_LEN: usize = 33;
const VERSION: u8 = 0;
const DATA_LEN: usize = 107;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SilentPaymentAddressError {
    UnsupportedVersion(u8),
    WrongAddressLength(usize),
    InvalidAddress(CheckedHrpstringError),
    InvalidPadding,
    WrongHrp(String),
    InvalidNetwork(String),
}

impl fmt::Display for SilentPaymentAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported version {version}, only version 0 is supported"
                )
            }
            Self::WrongAddressLength(len) => write!(f, "address length is wrong: {len}"),
            Self::InvalidAddress(e) => e.fmt(f),
            Self::InvalidPadding => f.write_str("address padding bits are not zero"),
            Self::WrongHrp(hrp) => write!(
                f,
                "wrong address prefix, expected \"sp\", \"tsp\", or \"sprt\", got {hrp:?}"
            ),
            Self::InvalidNetwork(network) => write!(f, "invalid network: {network}"),
        }
    }
}

impl core::error::Error for SilentPaymentAddressError {}

/// The network format used for this silent payment address.
///
/// There are three network types: Mainnet (`sp1..`), Testnet (`tsp1..`), and Regtest (`sprt1..`).
/// Signet uses the same network type as Testnet.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    fn hrp(self) -> Hrp {
        match self {
            Self::Mainnet => Hrp::parse_unchecked("sp"),
            Self::Testnet => Hrp::parse_unchecked("tsp"),
            Self::Regtest => Hrp::parse_unchecked("sprt"),
        }
    }
}

impl From<Network> for &str {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "bitcoin", // we use the same string as rust-bitcoin for compatibility
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = SilentPaymentAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let res = match value {
            "bitcoin" | "main" => Self::Mainnet, // We also take the core style argument
            "regtest" => Self::Regtest,
            "testnet" | "signet" | "test" => Self::Testnet, // core arg
            _ => return Err(SilentPaymentAddressError::InvalidNetwork(value.to_string())),
        };
        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSilentPaymentAddress {
    pub network: Network,
    pub scan_key: [u8; PUBLIC_KEY_LEN],
    pub spend_key: [u8; PUBLIC_KEY_LEN],
}

impl RawSilentPaymentAddress {
    pub fn decode(address: &str) -> Result<Self, SilentPaymentAddressError> {
        let checked = CheckedHrpstring::new::<Bech32m>(address)
            .map_err(SilentPaymentAddressError::InvalidAddress)?;
        let data = checked.data_part_ascii_no_checksum();
        if data.len() != DATA_LEN {
            return Err(SilentPaymentAddressError::WrongAddressLength(data.len()));
        }
        let version = Fe32::from_char_unchecked(data[0]).to_u8();
        if version != VERSION {
            return Err(SilentPaymentAddressError::UnsupportedVersion(version));
        }
        let network = match checked.hrp().to_lowercase().as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            "sprt" => Network::Regtest,
            hrp => return Err(SilentPaymentAddressError::WrongHrp(hrp.to_string())),
        };
        if Fe32::from_char_unchecked(data[DATA_LEN - 1]).to_u8() & 0b11 != 0 {
            return Err(SilentPaymentAddressError::InvalidPadding);
        }
        let mut bytes = data[1..]
            .iter()
            .map(|&c| Fe32::from_char_unchecked(c))
            .fes_to_bytes();
        let mut key = || {
            let mut key = [0; PUBLIC_KEY_LEN];
            key.iter_mut().zip(&mut bytes).for_each(|(k, b)| *k = b);
            key
        };
        let scan_key = key();
        let spend_key = key();
        Ok(Self {
            network,
            scan_key,
            spend_key,
        })
    }
}

impl fmt::Display for RawSilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hrp = self.network.hrp();
        let chars = self
            .scan_key
            .iter()
            .chain(&self.spend_key)
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars();
        for c in chars {
            fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use bech32::{Bech32m, Hrp};

    use crate::sp::{Network, RawSilentPaymentAddress, SilentPaymentAddressError, PUBLIC_KEY_LEN};

    const ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const SCAN_KEY: &str = "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4";
    const SPEND_KEY: &str = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";

    fn key(hex: &str) -> [u8; PUBLIC_KEY_LEN] {
        let mut key = [0; PUBLIC_KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        key
    }

    #[test]
    fn an_address_decodes_to_its_keys_and_back() {
        let raw = RawSilentPaymentAddress::decode(ADDRESS).unwrap();
        assert_eq!(
            raw,
            RawSilentPaymentAddress {
                network: Network::Mainnet,
                scan_key: key(SCAN_KEY),
                spend_key: key(SPEND_KEY),
            }
        );
        assert_eq!(raw.to_string(), ADDRESS);
    }

    #[test]
    fn each_network_round_trips() {
        for (network, prefix) in [
            (Network::Mainnet, "sp1q"),
            (Network::Testnet, "tsp1q"),
            (Network::Regtest, "sprt1q"),
        ] {
            let raw = RawSilentPaymentAddress {
                network,
                scan_key: key(SCAN_KEY),
                spend_key: key(SPEND_KEY),
            };
            let text = raw.to_string();
            assert!(text.starts_with(prefix), "{text}");
            assert_eq!(RawSilentPaymentAddress::decode(&text).unwrap(), raw);
        }
    }

    #[test]
    fn an_uppercase_address_decodes() {
        let raw = RawSilentPaymentAddress::decode(&ADDRESS.to_uppercase()).unwrap();
        assert_eq!(raw.to_string(), ADDRESS);
    }

    #[test]
    fn a_broken_checksum_is_refused() {
        let broken = ADDRESS.replace("qwv", "qwq");
        assert!(matches!(
            RawSilentPaymentAddress::decode(&broken),
            Err(SilentPaymentAddressError::InvalidAddress(_))
        ));
    }

    #[test]
    fn a_segwit_address_is_refused() {
        assert!(matches!(
            RawSilentPaymentAddress::decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(SilentPaymentAddressError::InvalidAddress(_))
        ));
    }

    #[test]
    fn a_wrong_length_is_refused() {
        let short = bech32::encode::<Bech32m>(Hrp::parse_unchecked("sp"), &[0]).unwrap();
        assert_eq!(
            RawSilentPaymentAddress::decode(&short),
            Err(SilentPaymentAddressError::WrongAddressLength(2))
        );
    }
}
