use std::{fmt, str::FromStr};

use miniscript::bitcoin::{
    bech32::{primitives::decode::CheckedHrpstring, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp},
    secp256k1::{All, PublicKey, Secp256k1, SecretKey},
    NetworkKind,
};

const SPSCAN_MAINNET_HRP: &str = "spscan";
const SPSCAN_TESTNET_HRP: &str = "tspscan";
const SPSPEND_MAINNET_HRP: &str = "spspend";
const SPSPEND_TESTNET_HRP: &str = "tspspend";

const SPSCAN_PAYLOAD_LEN: usize = 65;
const SPSPEND_PAYLOAD_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("bech32: {0}")]
    Bech32(String),
    #[error("missing silent payment version character")]
    MissingVersion,
    #[error("unsupported silent payment version {0}, expected 0")]
    InvalidVersion(u8),
    #[error("unknown human readable part {0:?}")]
    InvalidHrp(String),
    #[error("payload is {actual} bytes, expected {expected}")]
    InvalidPayloadLength { expected: usize, actual: usize },
    #[error("payload does not decode to a valid secret key")]
    Scalar,
    #[error("payload does not decode to a valid public key")]
    Point,
    #[error("non canonical encoding")]
    NonCanonical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpScanKey {
    pub scan_key: SecretKey,
    pub spend_key: PublicKey,
    pub network: NetworkKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpSpendKey {
    pub scan_key: SecretKey,
    pub spend_key: SecretKey,
    pub network: NetworkKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpKey {
    Scan(SpScanKey),
    Spend(SpSpendKey),
}

impl SpKey {
    pub fn scan_secret_key(&self) -> SecretKey {
        match self {
            SpKey::Scan(key) => key.scan_key,
            SpKey::Spend(key) => key.scan_key,
        }
    }

    pub fn spend_public_key(&self, secp: &Secp256k1<All>) -> PublicKey {
        match self {
            SpKey::Scan(key) => key.spend_key,
            SpKey::Spend(key) => PublicKey::from_secret_key(secp, &key.spend_key),
        }
    }

    pub fn spend_secret_key(&self) -> Option<SecretKey> {
        match self {
            SpKey::Scan(_) => None,
            SpKey::Spend(key) => Some(key.spend_key),
        }
    }

    pub fn network(&self) -> NetworkKind {
        match self {
            SpKey::Scan(key) => key.network,
            SpKey::Spend(key) => key.network,
        }
    }
}

fn encode(hrp: &str, payload: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("hardcoded hrp");
    payload
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::Q)
        .chars()
        .collect()
}

impl fmt::Display for SpScanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = match self.network {
            NetworkKind::Main => SPSCAN_MAINNET_HRP,
            NetworkKind::Test => SPSCAN_TESTNET_HRP,
        };
        let payload: Vec<u8> = self
            .scan_key
            .secret_bytes()
            .into_iter()
            .chain(self.spend_key.serialize())
            .collect();
        write!(f, "{}", encode(hrp, &payload))
    }
}

impl fmt::Display for SpSpendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = match self.network {
            NetworkKind::Main => SPSPEND_MAINNET_HRP,
            NetworkKind::Test => SPSPEND_TESTNET_HRP,
        };
        let payload: Vec<u8> = self
            .scan_key
            .secret_bytes()
            .into_iter()
            .chain(self.spend_key.secret_bytes())
            .collect();
        write!(f, "{}", encode(hrp, &payload))
    }
}

impl fmt::Display for SpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpKey::Scan(key) => key.fmt(f),
            SpKey::Spend(key) => key.fmt(f),
        }
    }
}

impl FromStr for SpKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parsed =
            CheckedHrpstring::new::<Bech32m>(s).map_err(|e| Error::Bech32(e.to_string()))?;
        let hrp = parsed.hrp().to_string().to_ascii_lowercase();

        let version = parsed
            .remove_witness_version()
            .ok_or(Error::MissingVersion)?;
        if version != Fe32::Q {
            return Err(Error::InvalidVersion(version.to_u8()));
        }

        let payload: Vec<u8> = parsed.byte_iter().collect();

        let key = match hrp.as_str() {
            SPSCAN_MAINNET_HRP | SPSCAN_TESTNET_HRP => {
                if payload.len() != SPSCAN_PAYLOAD_LEN {
                    return Err(Error::InvalidPayloadLength {
                        expected: SPSCAN_PAYLOAD_LEN,
                        actual: payload.len(),
                    });
                }
                let network = if hrp == SPSCAN_MAINNET_HRP {
                    NetworkKind::Main
                } else {
                    NetworkKind::Test
                };
                let scan_key = SecretKey::from_slice(&payload[..32]).map_err(|_| Error::Scalar)?;
                let spend_key = PublicKey::from_slice(&payload[32..]).map_err(|_| Error::Point)?;
                SpKey::Scan(SpScanKey {
                    scan_key,
                    spend_key,
                    network,
                })
            }
            SPSPEND_MAINNET_HRP | SPSPEND_TESTNET_HRP => {
                if payload.len() != SPSPEND_PAYLOAD_LEN {
                    return Err(Error::InvalidPayloadLength {
                        expected: SPSPEND_PAYLOAD_LEN,
                        actual: payload.len(),
                    });
                }
                let network = if hrp == SPSPEND_MAINNET_HRP {
                    NetworkKind::Main
                } else {
                    NetworkKind::Test
                };
                let scan_key = SecretKey::from_slice(&payload[..32]).map_err(|_| Error::Scalar)?;
                let spend_key = SecretKey::from_slice(&payload[32..]).map_err(|_| Error::Scalar)?;
                SpKey::Spend(SpSpendKey {
                    scan_key,
                    spend_key,
                    network,
                })
            }
            other => return Err(Error::InvalidHrp(other.to_string())),
        };

        if key.to_string() != s.to_ascii_lowercase() {
            return Err(Error::NonCanonical);
        }

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::bitcoin::{
        bech32::{
            primitives::decode::CheckedHrpstring, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp,
        },
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        NetworkKind,
    };

    use crate::sp_key::{
        encode, Error, SpKey, SpScanKey, SpSpendKey, SPSCAN_MAINNET_HRP, SPSCAN_PAYLOAD_LEN,
        SPSPEND_MAINNET_HRP,
    };

    fn scan_key_fixture(network: NetworkKind) -> SpScanKey {
        let secp = Secp256k1::new();
        let scan_key = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0xcd; 32]).unwrap());
        SpScanKey {
            scan_key,
            spend_key,
            network,
        }
    }

    fn spend_key_fixture(network: NetworkKind) -> SpSpendKey {
        let scan_key = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let spend_key = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        SpSpendKey {
            scan_key,
            spend_key,
            network,
        }
    }

    #[test]
    fn spscan_mainnet_roundtrip() {
        let key = scan_key_fixture(NetworkKind::Main);
        let encoded = key.to_string();
        assert!(encoded.starts_with("spscan1q"));

        let parsed = SpKey::from_str(&encoded).unwrap();
        match parsed {
            SpKey::Scan(parsed) => assert_eq!(parsed, key),
            SpKey::Spend(_) => panic!("expected SpKey::Scan"),
        }
    }

    #[test]
    fn spscan_testnet_roundtrip() {
        let key = scan_key_fixture(NetworkKind::Test);
        let encoded = key.to_string();
        assert!(encoded.starts_with("tspscan1q"));

        let parsed = SpKey::from_str(&encoded).unwrap();
        match parsed {
            SpKey::Scan(parsed) => assert_eq!(parsed, key),
            SpKey::Spend(_) => panic!("expected SpKey::Scan"),
        }
    }

    #[test]
    fn spspend_mainnet_roundtrip() {
        let key = spend_key_fixture(NetworkKind::Main);
        let encoded = key.to_string();
        assert!(encoded.starts_with("spspend1q"));

        let parsed = SpKey::from_str(&encoded).unwrap();
        match parsed {
            SpKey::Spend(parsed) => assert_eq!(parsed, key),
            SpKey::Scan(_) => panic!("expected SpKey::Spend"),
        }
    }

    #[test]
    fn spspend_testnet_roundtrip() {
        let key = spend_key_fixture(NetworkKind::Test);
        let encoded = key.to_string();
        assert!(encoded.starts_with("tspspend1q"));

        let parsed = SpKey::from_str(&encoded).unwrap();
        match parsed {
            SpKey::Spend(parsed) => assert_eq!(parsed, key),
            SpKey::Scan(_) => panic!("expected SpKey::Spend"),
        }
    }

    #[test]
    fn version_character_is_separate() {
        let scan = scan_key_fixture(NetworkKind::Main).to_string();
        assert_eq!(scan.chars().nth("spscan1".len()), Some('q'));
        assert_eq!(scan.len(), "spscan1".len() + 111);

        let tscan = scan_key_fixture(NetworkKind::Test).to_string();
        assert_eq!(tscan.chars().nth("tspscan1".len()), Some('q'));

        let spend = spend_key_fixture(NetworkKind::Main).to_string();
        assert_eq!(spend.chars().nth("spspend1".len()), Some('q'));
        assert_eq!(spend.len(), "spspend1".len() + 110);

        let tspend = spend_key_fixture(NetworkKind::Test).to_string();
        assert_eq!(tspend.chars().nth("tspspend1".len()), Some('q'));
    }

    #[test]
    fn unknown_hrp_rejected() {
        let key = scan_key_fixture(NetworkKind::Main).to_string();
        let bad = key.replacen("spscan", "badhrp", 1);
        match SpKey::from_str(&bad) {
            Err(Error::InvalidHrp(_)) | Err(Error::Bech32(_)) => {}
            other => panic!("expected InvalidHrp or Bech32 error, got {other:?}"),
        }
    }

    #[test]
    fn wrong_version_rejected() {
        let key = scan_key_fixture(NetworkKind::Main).to_string();
        let mut bad = key.clone();
        let idx = "spscan1".len();
        bad.replace_range(idx..idx + 1, "p");
        assert!(matches!(SpKey::from_str(&bad), Err(Error::Bech32(_))));

        let hrp = Hrp::parse(SPSCAN_MAINNET_HRP).unwrap();
        let payload = [0u8; SPSCAN_PAYLOAD_LEN];
        let bad_version: String = payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::P)
            .chars()
            .collect();
        assert_eq!(SpKey::from_str(&bad_version), Err(Error::InvalidVersion(1)));
    }

    #[test]
    fn wrong_payload_length_rejected() {
        let bad = encode(SPSCAN_MAINNET_HRP, &[0xab; 40]);
        match SpKey::from_str(&bad) {
            Err(Error::InvalidPayloadLength { expected: 65, .. }) => {}
            other => panic!("expected InvalidPayloadLength, got {other:?}"),
        }
    }

    #[test]
    fn invalid_scalar_rejected() {
        let mut payload = [0xffu8; SPSCAN_PAYLOAD_LEN];
        payload[..32].fill(0x00);
        let bad = encode(SPSCAN_MAINNET_HRP, &payload);
        assert_eq!(SpKey::from_str(&bad), Err(Error::Scalar));
    }

    #[test]
    fn non_canonical_padding_rejected() {
        let key = spend_key_fixture(NetworkKind::Main).to_string();
        let hrp = Hrp::parse(SPSPEND_MAINNET_HRP).unwrap();
        let checked = CheckedHrpstring::new::<Bech32m>(&key).unwrap();
        let mut fes: Vec<Fe32> = checked.fe32_iter::<std::iter::Empty<u8>>().collect();
        let last = *fes.last().unwrap();
        *fes.last_mut().unwrap() = Fe32::try_from(last.to_u8() ^ 1).unwrap();

        let bad: String = fes
            .into_iter()
            .with_checksum::<Bech32m>(&hrp)
            .chars()
            .collect();

        assert_eq!(SpKey::from_str(&bad), Err(Error::NonCanonical));
    }
}
