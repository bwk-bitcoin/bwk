//! Coin domain types.
//!
//! These describe what scanning finds and what spending consumes, so they sit
//! below both `bwk-electrum` and `bwk-tx` rather than inside either.

use miniscript::{
    bitcoin::{
        self, absolute, bip32::DerivationPath, key::rand, psbt, Psbt, ScriptBuf, TxIn, Witness,
    },
    psbt::PsbtExt,
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};

/// Errors constructing or converting a [`Coin`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to derive the descriptor")]
    Derivation,
    #[error("unknown keychain")]
    KeyChain,
    #[error("expected a single-path descriptor")]
    MultiDescriptor,
    #[error("failed to update the psbt input")]
    Update,
}

/// Witness satisfaction weight (WU) of a single taproot key-spend input:
/// Schnorr sig 64 + sighash byte 1 + witness-stack length byte 1 = 66.
pub const TAPROOT_KEYSPEND_SATISFACTION_WU: u64 = 66;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyChain {
    Receive,
    Change,
    Custom(u32),
}

impl From<KeyChain> for u32 {
    fn from(value: KeyChain) -> Self {
        match value {
            KeyChain::Receive => 0,
            KeyChain::Change => 0,
            KeyChain::Custom(c) => c,
        }
    }
}

impl From<u32> for KeyChain {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Receive,
            1 => Self::Change,
            c => Self::Custom(c),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum CoinStatus {
    Unconfirmed,
    /// Server claims this coin's tx is confirmed at some height, but we
    /// haven't yet proved inclusion via a merkle branch verified
    /// against a stored header. Spendable, but consumers that gate on
    /// "fully verified confirmed" should not treat it as `Confirmed`.
    ConfirmedUnverified,
    Confirmed,
    BeingSpend,
    Spent,
}

type Label = String;

/// Signing-specific information for a coin.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoinSpendInfo {
    /// Descriptor-based coin (standard wallets)
    Bip32 {
        coin_path: (KeyChain, u32),
        descriptor: Descriptor<DescriptorPublicKey>,
        /// Ephemeral secret key for SP partial secret computation.
        /// Never persisted, only populated at tx-building time.
        #[serde(skip)]
        secret_key: Option<bitcoin::secp256k1::SecretKey>,
    },
    /// Silent Payment coin (BIP352)
    Sp {
        derivation: DerivationPath,
        tweak: [u8; 32],
    },
}

/// High-level source/classification for a wallet coin.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoinSourceKind {
    SilentPayment,
    Segwit,
    Taproot,
    Other,
}

/// A spendable coin (UTXO) with all information needed for transaction building and signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coin {
    pub txout: bitcoin::TxOut,
    pub outpoint: bitcoin::OutPoint,
    pub height: Option<u64>,
    pub sequence: bitcoin::Sequence,
    pub status: CoinStatus,
    pub label: Option<Label>,
    pub satisfaction_size: u64,
    pub spend_info: CoinSpendInfo,
}

impl From<Coin> for bitcoin::TxIn {
    fn from(value: Coin) -> Self {
        TxIn {
            previous_output: value.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: value.sequence,
            witness: Witness::new(),
        }
    }
}

impl TryFrom<Coin> for bitcoin::psbt::Input {
    type Error = Error;

    fn try_from(coin: Coin) -> Result<Self, Self::Error> {
        coin.to_psbt_input()
    }
}

impl Coin {
    pub fn spk(&self) -> ScriptBuf {
        self.txout.script_pubkey.clone()
    }

    pub fn value(&self) -> bitcoin::Amount {
        self.txout.value
    }

    pub fn is_bip32(&self) -> bool {
        matches!(self.spend_info, CoinSpendInfo::Bip32 { .. })
    }

    pub fn is_sp(&self) -> bool {
        matches!(self.spend_info, CoinSpendInfo::Sp { .. })
    }

    pub fn source(&self) -> CoinSourceKind {
        match &self.spend_info {
            CoinSpendInfo::Sp { .. } => CoinSourceKind::SilentPayment,
            CoinSpendInfo::Bip32 { .. } if self.txout.script_pubkey.is_p2wpkh() => {
                CoinSourceKind::Segwit
            }
            CoinSpendInfo::Bip32 { .. } if self.txout.script_pubkey.is_p2tr() => {
                CoinSourceKind::Taproot
            }
            CoinSpendInfo::Bip32 { .. } => CoinSourceKind::Other,
        }
    }

    pub fn to_psbt_input(&self) -> Result<psbt::Input, Error> {
        match &self.spend_info {
            CoinSpendInfo::Bip32 {
                coin_path,
                descriptor,
                ..
            } => self.spk_to_psbt_input(*coin_path, descriptor),
            CoinSpendInfo::Sp { .. } => self.sp_to_psbt_input(),
        }
    }

    fn spk_to_psbt_input(
        &self,
        coin_path: (KeyChain, u32),
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> Result<psbt::Input, Error> {
        let inp = psbt::Input {
            witness_utxo: Some(self.txout.clone()),
            ..Default::default()
        };

        let (kc, index) = coin_path;
        let descr = derive_descriptor(descriptor, kc, index)?;

        let dummy_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![self.clone().into()],
            output: vec![],
        };

        let mut dummy_psbt = Psbt {
            unsigned_tx: dummy_tx,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![inp],
            outputs: vec![],
        };
        PsbtExt::update_input_with_descriptor(&mut dummy_psbt, 0, &descr)
            .map_err(|_| Error::Update)?;

        Ok(dummy_psbt.inputs[0].clone())
    }

    fn sp_to_psbt_input(&self) -> Result<psbt::Input, Error> {
        // For SP coins, we create a basic PSBT input with witness_utxo
        // The actual signing will be handled by the SP signer which uses the tweak
        Ok(psbt::Input {
            witness_utxo: Some(self.txout.clone()),
            ..Default::default()
        })
    }
}

/// Derive the definite descriptor of a keychain at an index, out of a two-path
/// multipath descriptor.
pub fn derive_descriptor(
    descriptor: &Descriptor<DescriptorPublicKey>,
    keychain: KeyChain,
    index: u32,
) -> Result<Descriptor<DefiniteDescriptorKey>, Error> {
    let mut descriptors = descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|_| Error::MultiDescriptor)?
        .into_iter();
    let recv = descriptors.next().ok_or(Error::MultiDescriptor)?;
    let change = descriptors.next().ok_or(Error::MultiDescriptor)?;

    let single = match keychain {
        KeyChain::Receive => recv,
        KeyChain::Change => change,
        KeyChain::Custom(_) => return Err(Error::KeyChain),
    };

    single
        .at_derivation_index(index)
        .map_err(|_| Error::Derivation)
}

pub fn shuffle_coins(mut vec: Vec<Coin>) -> Vec<Coin> {
    use rand::seq::SliceRandom;
    vec.shuffle(&mut rand::thread_rng());
    vec
}

/// Trait for managing change address index tip.
/// Implemented by wallet types that need to track the next change index.
/// Called by RecipientProvider implementations when deriving new change addresses.
pub trait ChangeTip {
    fn next_index(&mut self) -> u32;
}

pub trait CoinSource {
    fn spendable_coins(&self) -> Vec<Coin>;
    #[cfg(feature = "test")]
    fn add_coin(&mut self, _coin: Coin) {}
    #[cfg(feature = "test")]
    fn remove_coin(&mut self, _coin: &Coin) {}
}

#[cfg(feature = "test")]
impl CoinSource for std::collections::BTreeMap<miniscript::bitcoin::OutPoint, Coin> {
    fn spendable_coins(&self) -> Vec<Coin> {
        self.values().cloned().collect()
    }

    fn add_coin(&mut self, coin: Coin) {
        self.insert(coin.outpoint, coin);
    }

    fn remove_coin(&mut self, coin: &Coin) {
        self.remove(&coin.outpoint);
    }
}

/// Estimate the satisfaction size for an input, returning the result
/// in weight units (WU).
/// Note: The output of this function represent the worst case scenario.
pub fn max_input_satisfaction_size(descriptor: &Descriptor<DescriptorPublicKey>) -> usize {
    descriptor
        .clone()
        .into_single_descriptors()
        .expect("multikey")
        .first()
        .expect("multikey")
        .clone()
        .max_weight_to_satisfy()
        .expect("invalid descriptor")
        .to_wu() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::str::FromStr;

    fn bip32_descriptor() -> Descriptor<DescriptorPublicKey> {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(bitcoin::Network::Regtest, &[3u8; 32]).unwrap();
        let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &xpriv);
        Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({xpub}/<0;1>/*)")).unwrap()
    }

    fn bip32_coin(script_pubkey: ScriptBuf) -> Coin {
        Coin {
            txout: bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey,
            },
            outpoint: bitcoin::OutPoint::null(),
            height: Some(1),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: 0,
            spend_info: CoinSpendInfo::Bip32 {
                coin_path: (KeyChain::Receive, 0),
                descriptor: bip32_descriptor(),
                secret_key: None,
            },
        }
    }

    #[test]
    fn source_classifies_silent_payment() {
        let coin = Coin {
            txout: bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            outpoint: bitcoin::OutPoint::null(),
            height: Some(1),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: 0,
            spend_info: CoinSpendInfo::Sp {
                derivation: DerivationPath::default(),
                tweak: [0u8; 32],
            },
        };

        assert_eq!(coin.source(), CoinSourceKind::SilentPayment);
    }

    #[test]
    fn source_classifies_segwit_taproot_and_other_bip32() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let public_key: bitcoin::CompressedPublicKey =
            bitcoin::PublicKey::new(secret_key.public_key(&secp))
                .try_into()
                .unwrap();
        let p2wpkh =
            bitcoin::Address::p2wpkh(&public_key, bitcoin::Network::Regtest).script_pubkey();
        let (xonly, _parity) = secret_key.public_key(&secp).x_only_public_key();
        let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly);
        let p2tr =
            bitcoin::Address::p2tr_tweaked(tweaked, bitcoin::Network::Regtest).script_pubkey();

        assert_eq!(bip32_coin(p2wpkh).source(), CoinSourceKind::Segwit);
        assert_eq!(bip32_coin(p2tr).source(), CoinSourceKind::Taproot);
        assert_eq!(bip32_coin(ScriptBuf::new()).source(), CoinSourceKind::Other);
    }
}
