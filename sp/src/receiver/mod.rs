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

use bitcoin::{
    absolute::Height,
    address::NetworkUnchecked,
    bip32,
    hex::{DisplayHex, FromHex},
    secp256k1::{All, PublicKey, Secp256k1, SecretKey},
    Address, Amount, BlockHash, Network, ScriptBuf, Txid,
};
use serde::{Deserialize, Serialize};

use crate::core::{
    receiving::{Label, Receiver},
    utils::common::{Network as SpNetwork, SilentPaymentAddress},
    SpVersion,
};

const SP_PURPOSE: u32 = 352;
const SP_SPEND_KEY: u32 = 0;
const SP_SCAN_KEY: u32 = 1;
const SP_KEY_INDEX: u32 = 0;

/// The BIP352 `purpose'/coin_type'/account'` prefix shared by the scan and
/// spend derivation paths.
pub fn bip352_base_derivation(
    network: Network,
    account: bip32::ChildNumber,
) -> Vec<bip32::ChildNumber> {
    let network_idx = match network {
        Network::Bitcoin => 0u32,
        _ => 1,
    };
    vec![
        bip32::ChildNumber::from_hardened_idx(SP_PURPOSE).expect("valid purpose"),
        bip32::ChildNumber::from_hardened_idx(network_idx).expect("0 or 1"),
        account,
    ]
}

/// The BIP352 scan derivation path, `m/352'/{0,1}'/account'/1'/0`. Shared by
/// [`SpReceiver`]'s mnemonic constructors and a later BIP376 updater.
pub fn scan_path(network: Network, account: bip32::ChildNumber) -> bip32::DerivationPath {
    let mut path = bip352_base_derivation(network, account);
    path.push(bip32::ChildNumber::from_hardened_idx(SP_SCAN_KEY).expect("valid scan key"));
    path.push(bip32::ChildNumber::from_normal_idx(SP_KEY_INDEX).expect("valid key index"));
    path.into()
}

/// The BIP352 spend derivation path, `m/352'/{0,1}'/account'/0'/0`. Shared by
/// [`SpReceiver`], `bwk_sp::signer::SpSigner`, and a later BIP376 updater.
pub fn spend_path(network: Network, account: bip32::ChildNumber) -> bip32::DerivationPath {
    let mut path = bip352_base_derivation(network, account);
    path.push(bip32::ChildNumber::from_hardened_idx(SP_SPEND_KEY).expect("valid spend key"));
    path.push(bip32::ChildNumber::from_normal_idx(SP_KEY_INDEX).expect("valid key index"));
    path.into()
}

/// Derive the BIP352 spend secret key (`b_spend`) at [`spend_path`]. Shared by
/// [`SpReceiver`] and `bwk_sp::signer::SpSigner`, the only two owners of this
/// key.
pub fn derive_spend_key(
    master_xpriv: &bip32::Xpriv,
    secp: &Secp256k1<All>,
    network: Network,
    account: bip32::ChildNumber,
) -> Result<SecretKey, Error> {
    master_xpriv
        .derive_priv(secp, &spend_path(network, account))
        .map_err(|_| Error::KeyDerivation("spend"))
        .map(|k| k.private_key)
}

/// Derives the BIP32 master fingerprint from `mnemonic`, without handing back
/// any private key material. Lets a consumer cache a [`bip32::Fingerprint`]
/// for BIP376 key-origin metadata without ever holding a master xpriv.
#[cfg(feature = "mnemonic")]
pub fn mnemonic_fingerprint(mnemonic: &str, network: Network) -> Option<bip32::Fingerprint> {
    let mnemonic = bip39::Mnemonic::from_str(mnemonic).ok()?;
    let seed = mnemonic.to_seed("");
    let master = bip32::Xpriv::new_master(network, &seed).ok()?;
    Some(master.fingerprint(&Secp256k1::new()))
}

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

// The receiver: key material + address/output derivation.

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct SpReceiver {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
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
            spend_pk: default_sk.public_key(&Secp256k1::new()),
            receiver: Receiver::new(
                SpVersion::V0,
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
    pub fn new(scan_sk: SecretKey, spend_pk: PublicKey, network: Network) -> Result<Self, Error> {
        let secp = Secp256k1::new();
        Self::new_inner(scan_sk, spend_pk, network, secp)
    }
    fn new_inner(
        scan_sk: SecretKey,
        spend_pk: PublicKey,
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
            SpVersion::V0,
            scan_pubkey,
            spend_pk,
            change_label,
            sp_network,
        )?;

        Ok(Self {
            scan_sk,
            spend_pk,
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

        let scan = master_xpriv
            .derive_priv(&secp, &scan_path(network, account))
            .map_err(|_| Error::KeyDerivation("scan"))?
            .private_key;

        let spend = derive_spend_key(&master_xpriv, &secp, network, account)?;

        Self::new_inner(scan, spend.public_key(&secp), network, secp)
    }

    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
        self.receiver.get_receiving_address()
    }

    pub fn get_scan_key(&self) -> SecretKey {
        self.scan_sk
    }

    pub fn spend_pubkey(&self) -> PublicKey {
        self.spend_pk
    }
}

#[cfg(all(test, feature = "mnemonic"))]
mod tests {
    use bitcoin::{bip32, secp256k1::Secp256k1, Network};

    use crate::receiver::{derive_spend_key, scan_path, spend_path, SpReceiver};

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon about";

    fn test_mnemonic() -> bip39::Mnemonic {
        bip39::Mnemonic::parse(TEST_MNEMONIC).unwrap()
    }

    #[test]
    fn mnemonic_receiver_holds_no_secret_spend_key() {
        let secp = Secp256k1::new();
        let network = Network::Signet;
        let account = bip32::ChildNumber::from_hardened_idx(0).unwrap();

        let receiver = SpReceiver::new_from_mnemonic(test_mnemonic(), network).unwrap();

        let seed = test_mnemonic().to_seed("");
        let master_xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();
        let expected_spend_pk = derive_spend_key(&master_xpriv, &secp, network, account)
            .unwrap()
            .public_key(&secp);

        assert_eq!(receiver.spend_pubkey(), expected_spend_pk);
    }

    #[test]
    fn watch_only_and_mnemonic_receivers_match() {
        let secp = Secp256k1::new();
        let network = Network::Signet;
        let account = bip32::ChildNumber::from_hardened_idx(0).unwrap();

        let mnemonic_receiver = SpReceiver::new_from_mnemonic(test_mnemonic(), network).unwrap();

        let seed = test_mnemonic().to_seed("");
        let master_xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();
        let scan_sk = master_xpriv
            .derive_priv(&secp, &scan_path(network, account))
            .unwrap()
            .private_key;
        let spend_pk = derive_spend_key(&master_xpriv, &secp, network, account)
            .unwrap()
            .public_key(&secp);

        let watch_only_receiver = SpReceiver::new(scan_sk, spend_pk, network).unwrap();

        assert_eq!(
            mnemonic_receiver.get_receiving_address(),
            watch_only_receiver.get_receiving_address()
        );
    }

    #[test]
    fn bip352_paths_match_bip352() {
        let account = bip32::ChildNumber::from_hardened_idx(0).unwrap();

        assert_eq!(
            scan_path(Network::Bitcoin, account).to_string(),
            "352'/0'/0'/1'/0"
        );
        assert_eq!(
            spend_path(Network::Bitcoin, account).to_string(),
            "352'/0'/0'/0'/0"
        );
        assert_eq!(
            scan_path(Network::Signet, account).to_string(),
            "352'/1'/0'/1'/0"
        );
        assert_eq!(
            spend_path(Network::Signet, account).to_string(),
            "352'/1'/0'/0'/0"
        );
    }
}
