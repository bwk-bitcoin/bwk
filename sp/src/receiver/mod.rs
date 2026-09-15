//! The silent-payment receiver: BIP352 key material plus address/output
//! derivation and scan-matching. No network I/O, that is the blindbit module.
//!
//! Source: adapted from cygnet3/spdk. See `sp/NOTICE`.

pub mod error;

use error::Error;
// Re-export commonly used external types.
#[cfg(feature = "mnemonic")]
pub use bip39;
pub use bitcoin;

use std::str::FromStr;

#[cfg(feature = "mnemonic")]
use bitcoin::bip32;
use bitcoin::{
    absolute::Height,
    address::NetworkUnchecked,
    hex::{DisplayHex, FromHex},
    secp256k1::{All, PublicKey, Secp256k1, SecretKey},
    Address, Amount, BlockHash, Network, ScriptBuf, Txid,
};
use serde::{Deserialize, Serialize};

use crate::core::{
    receiving::{Label, Receiver},
    utils::common::{Network as SpNetwork, SilentPaymentAddress},
};

// Blockchain data fetched via the blindbit transport.

pub struct BlockData {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    // Raw 33-byte compressed tweak points, NOT parsed to `PublicKey` here: point
    // validation is crypto and is deferred to the bounded compute threads (see
    // `process_block_outputs`), so the many fetch workers stay pure I/O and never
    // oversubscribe the cores.
    pub tweaks: Vec<[u8; 33]>,
    pub new_utxo_filter: FilterData,
}

#[derive(Clone)]
pub struct UtxoData {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
    pub scriptpubkey: ScriptBuf,
    pub spent: bool,
}

pub struct SpentIndexData {
    pub data: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct FilterData {
    pub block_hash: BlockHash,
    pub data: Vec<u8>,
}

// Owned outputs, recipient addresses, and spend keys.

type SpendingTxId = [u8; 32];
type MinedInBlock = [u8; 32];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum OutputSpendStatus {
    Unspent,
    /// Spent by a known transaction (our own broadcast). `block_hash` is set
    /// once the spend confirms; the spending txid is retained through
    /// confirmation so the spend can be attributed to its transaction.
    Spent {
        txid: SpendingTxId,
        block_hash: Option<MinedInBlock>,
    },
    /// A spend discovered by a scan with an unknown spending txid, already mined.
    Mined(MinedInBlock),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct OwnedOutput {
    pub blockheight: Height,
    pub tweak: [u8; 32], // scalar in big endian format
    pub amount: Amount,
    pub script: ScriptBuf,
    pub label: Option<Label>,
    pub spend_status: OutputSpendStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum RecipientAddress {
    LegacyAddress(Address<NetworkUnchecked>),
    SpAddress(SilentPaymentAddress),
    Data(Vec<u8>), // OpReturn output
}

impl TryFrom<String> for RecipientAddress {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp_address) = SilentPaymentAddress::try_from(value.as_str()) {
            Ok(Self::SpAddress(sp_address))
        } else if let Ok(legacy_address) = Address::from_str(&value) {
            Ok(Self::LegacyAddress(legacy_address))
        } else if let Ok(data) = Vec::from_hex(&value) {
            Ok(Self::Data(data))
        } else {
            Err(Error::UnknownAddressType)
        }
    }
}

impl From<RecipientAddress> for String {
    fn from(value: RecipientAddress) -> Self {
        match value {
            RecipientAddress::LegacyAddress(address) => address.assume_checked().to_string(),
            RecipientAddress::SpAddress(sp_address) => sp_address.to_string(),
            RecipientAddress::Data(data) => data.to_lower_hex_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum SpendKey {
    Secret(SecretKey),
    Public(PublicKey),
}

impl TryInto<SecretKey> for SpendKey {
    type Error = Error;
    fn try_into(self) -> Result<SecretKey, Error> {
        match self {
            Self::Secret(k) => Ok(k),
            Self::Public(_) => Err(Error::MissingSecretKey),
        }
    }
}

impl From<&SpendKey> for PublicKey {
    fn from(value: &SpendKey) -> Self {
        match value {
            SpendKey::Secret(k) => {
                let secp = Secp256k1::signing_only();
                k.public_key(&secp)
            }
            SpendKey::Public(p) => *p,
        }
    }
}

impl From<SpendKey> for PublicKey {
    fn from(value: SpendKey) -> Self {
        (&value).into()
    }
}

impl From<SecretKey> for SpendKey {
    fn from(value: SecretKey) -> Self {
        Self::Secret(value)
    }
}

// The receiver: key material + address/output derivation.

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpReceiver {
    scan_sk: SecretKey,
    spend_key: SpendKey,
    pub receiver: Receiver,
    network: Network,
}

#[cfg(test)]
use bitcoin::{key::constants::ONE, secp256k1::Scalar, XOnlyPublicKey};

#[cfg(test)]
impl Default for SpReceiver {
    fn default() -> Self {
        let default_sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let default_pubkey = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap()
        .public_key(bitcoin::key::Parity::Even);
        Self {
            scan_sk: default_sk,
            spend_key: SpendKey::Secret(default_sk),
            receiver: Receiver::new(
                0,
                default_pubkey,
                default_pubkey,
                Scalar::from_be_bytes(ONE).unwrap().into(),
                SpNetwork::Regtest,
            )
            .unwrap(),
            network: Network::Regtest,
        }
    }
}

impl SpReceiver {
    pub fn new(scan_sk: SecretKey, spend_key: SpendKey, network: Network) -> Result<Self, Error> {
        let secp = Secp256k1::new();
        Self::new_inner(scan_sk, spend_key, network, secp)
    }
    fn new_inner(
        scan_sk: SecretKey,
        spend_key: SpendKey,
        network: Network,
        secp: Secp256k1<All>,
    ) -> Result<Self, Error> {
        let scan_pubkey = scan_sk.public_key(&secp);
        let change_label = Label::new(scan_sk, 0);

        let sp_network = match network {
            Network::Bitcoin => SpNetwork::Mainnet,
            Network::Regtest => SpNetwork::Regtest,
            Network::Testnet | Network::Signet => SpNetwork::Testnet,
            _ => unreachable!(),
        };

        let receiver = Receiver::new(
            0,
            scan_pubkey,
            (&spend_key).into(),
            change_label,
            sp_network,
        )?;

        Ok(Self {
            scan_sk,
            spend_key,
            receiver,
            network,
        })
    }
    #[cfg(feature = "mnemonic")]
    pub fn new_from_mnemonic(mnemonic: bip39::Mnemonic, network: Network) -> Result<Self, Error> {
        use bitcoin::bip32::ChildNumber;

        Self::new_from_mnemonic_with_passphrase_and_account(
            mnemonic,
            "",
            network,
            ChildNumber::from_hardened_idx(0).expect("zero"),
        )
    }

    #[cfg(feature = "mnemonic")]
    pub fn new_from_mnemonic_with_passphrase_and_account(
        mnemonic: bip39::Mnemonic,
        pp: &str,
        network: Network,
        account: bip32::ChildNumber,
    ) -> Result<Self, Error> {
        use bitcoin::bip32;

        let secp = Secp256k1::new();
        let seed = mnemonic.to_seed(pp);
        let master_xpriv =
            bip32::Xpriv::new_master(network, &seed).map_err(|_| Error::SeedDerivation)?;
        let network_idx = match network {
            Network::Bitcoin => 0u32,
            _ => 1,
        };
        let base_deriv = vec![
            bip32::ChildNumber::from_hardened_idx(352).expect("352"),
            bip32::ChildNumber::from_hardened_idx(network_idx).expect("0 or 1"),
            account,
        ];

        let mut scan_deriv = base_deriv.clone();
        scan_deriv.push(bip32::ChildNumber::from_hardened_idx(1).expect("1"));
        scan_deriv.push(bip32::ChildNumber::from_normal_idx(0).expect("0"));

        let mut spend_deriv = base_deriv;
        spend_deriv.push(bip32::ChildNumber::from_hardened_idx(0).expect("0"));
        spend_deriv.push(bip32::ChildNumber::from_normal_idx(0).expect("0"));

        let scan = master_xpriv
            .derive_priv(&secp, &scan_deriv)
            .map_err(|_| Error::KeyDerivation("scan"))?
            .private_key;

        let spend = master_xpriv
            .derive_priv(&secp, &spend_deriv)
            .map_err(|_| Error::KeyDerivation("spend"))?
            .private_key;

        Self::new_inner(scan, spend.into(), network, secp)
    }

    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
        self.receiver.get_receiving_address()
    }

    pub fn get_scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn try_get_secret_spend_key(&self) -> Result<SecretKey, Error> {
        match self.spend_key {
            SpendKey::Public(_) => Err(Error::MissingSecretKey),
            SpendKey::Secret(sk) => Ok(sk),
        }
    }
}
