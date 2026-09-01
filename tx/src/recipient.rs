use miniscript::{
    bitcoin::{
        self, absolute,
        address::NetworkUnchecked,
        secp256k1::{PublicKey, SecretKey},
        Address, Network, ScriptBuf, TxOut, Weight,
    },
    psbt::PsbtExt,
    Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};

use bwk_coin::{ChangeTip, Coin, KeyChain};

use crate::{transaction::Amount, Error};

/// Context passed during transaction finalization.
/// Contains all information needed to create output scripts.
pub struct FinalizationContext<'a> {
    /// Selected input coins
    pub inputs: &'a [Coin],
    /// Partial secret for SP outputs (computed by SpPartialSecretProvider if any SP outputs exist)
    pub partial_secret: Option<SecretKey>,
    /// Bitcoin network
    pub network: Network,
}

/// Trait for computing SP partial secret from inputs.
/// Implemented by SpReceiver/Account in bwk-sp.
pub trait SpPartialSecretProvider {
    /// Compute the partial secret needed for SP output derivation.
    /// This combines the spend key with tweaks from all selected inputs.
    fn compute_partial_secret(&self, inputs: &[Coin]) -> Result<SecretKey, Error>;

    /// Batch-derive scripts for all Silent Payment outputs in a transaction.
    ///
    /// BIP352 requires all SP outputs sharing the same scan key to be derived
    /// together with incrementing `k` values. This method is called during
    /// `finalize()` after computing `partial_secret` but before `build_psbt()`.
    fn derive_sp_scripts(
        &self,
        _outputs: &mut [Box<dyn RecipientProvider>],
        _partial_secret: SecretKey,
    ) {
    }
}

/// Trait for types that can provide recipient output information.
/// Implemented by Address, SilentPaymentAddress, and Account types.
pub trait RecipientProvider: RecipientProviderClone {
    /// Weight of this output for fee estimation
    fn output_weight(&self) -> Weight;

    /// Create output script using finalization context.
    /// - For regular addresses: ignores context
    /// - For SP: uses partial_secret from context to derive output key
    fn create_script(&mut self, ctx: &FinalizationContext) -> ScriptBuf;

    /// PSBT output metadata for signers (BIP32 derivation or BIP375 SP info)
    fn psbt_output_info(&self) -> PsbtOutputInfo;

    /// Whether this recipient is a Silent Payment address.
    fn is_silent_payment(&self) -> bool {
        false
    }

    /// Whether this is a change output (KeyChain::Change in origin)
    fn is_change(&self) -> bool {
        false
    }

    /// The amount for this output
    fn amount(&self) -> Amount;

    /// Set the amount (used for Max output resolution)
    fn set_amount(&mut self, amount: Amount);

    /// Store a pre-computed output script (used by SP batch derivation).
    fn set_precomputed_script(&mut self, _script: ScriptBuf) {}

    /// Convert to PSBT output metadata
    fn to_psbt_output(&self) -> Result<bitcoin::psbt::Output, Error> {
        Ok(bitcoin::psbt::Output::default())
    }

    /// Network for this recipient
    fn network(&self) -> Network;
}

/// Helper trait for cloning boxed RecipientProvider
pub trait RecipientProviderClone {
    fn clone_box(&self) -> Box<dyn RecipientProvider>;
}

impl<T> RecipientProviderClone for T
where
    T: RecipientProvider + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn RecipientProvider> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn RecipientProvider> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// PSBT output metadata - needed by signers
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PsbtOutputInfo {
    /// Descriptor-based wallets (BIP32 derivation paths)
    Bip32 {
        origin: (KeyChain, u32),
        descriptor: Descriptor<DescriptorPublicKey>,
    },
    /// Silent Payment outputs (BIP375)
    /// Contains PSBT_OUT_SP_V0_INFO (scan + spend pubkeys) and optional PSBT_OUT_SP_V0_LABEL
    SilentPayment {
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        label: Option<u32>,
    },
    /// External address with no special metadata
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Recipient {
    pub address: Address<NetworkUnchecked>,
    pub amount: Amount,
    pub label: Option<String>,
    pub origin: Option<(KeyChain, u32 /* index */)>,
    pub descriptor: Option<Descriptor<DescriptorPublicKey>>,
}

impl From<&Recipient> for TxOut {
    fn from(recip: &Recipient) -> Self {
        let value = match recip.amount {
            Amount::Value(v) => bitcoin::Amount::from_sat(v),
            Amount::Max(value) => {
                match value {
                    Some(v) => bitcoin::Amount::from_sat(v),
                    // NOTE: if value is None, that's mean simulation do
                    // NOT success, thus we put a dummy MAX_MONEY amount
                    // in order to be sure the transaction is not realistically
                    // spendable, but can be used for weight estimation
                    None => bitcoin::Amount::MAX_MONEY,
                }
            }
            Amount::Anchor => bitcoin::Amount::ZERO,
        };
        TxOut {
            value,
            script_pubkey: recip.address.clone().assume_checked().script_pubkey(),
        }
    }
}

impl From<Recipient> for TxOut {
    fn from(value: Recipient) -> Self {
        (&value).into()
    }
}

impl TryFrom<Recipient> for bitcoin::psbt::Output {
    type Error = Error;

    fn try_from(recip: Recipient) -> Result<Self, Self::Error> {
        recip.to_psbt_output()
    }
}

impl Recipient {
    pub fn to_psbt_output(&self) -> Result<bitcoin::psbt::Output, Error> {
        if let (Some(descr), Some((kc, index))) = (&self.descriptor, &self.origin) {
            let descriptors = descr
                .clone()
                .into_single_descriptors()
                .map_err(|_| Error::MultiDescriptor)?;
            let recv = descriptors.first().ok_or(Error::MultiDescriptor)?;
            let change = descriptors.get(1).ok_or(Error::MultiDescriptor)?;

            let descr = match kc {
                KeyChain::Receive => recv
                    .at_derivation_index(*index)
                    .map_err(|_| Error::Derivation)?,
                KeyChain::Change => change
                    .at_derivation_index(*index)
                    .map_err(|_| Error::Derivation)?,

                KeyChain::Custom(_) => return Err(Error::KeyChain),
            };

            let dummy_tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![self.clone().into()],
            };

            let mut dummy_psbt = bitcoin::Psbt {
                unsigned_tx: dummy_tx,
                version: 0,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
                inputs: Default::default(),
                outputs: vec![bitcoin::psbt::Output::default()],
            };

            PsbtExt::update_output_with_descriptor(&mut dummy_psbt, 0, &descr)
                .map_err(|_| Error::Update)?;

            Ok(dummy_psbt.outputs[0].clone())
        } else {
            Ok(bitcoin::psbt::Output::default())
        }
    }
}

impl RecipientProvider for Recipient {
    fn output_weight(&self) -> Weight {
        let script = self.address.clone().assume_checked().script_pubkey();
        TxOut {
            value: bitcoin::Amount::MAX_MONEY,
            script_pubkey: script,
        }
        .weight()
    }

    fn create_script(&mut self, _ctx: &FinalizationContext) -> ScriptBuf {
        self.address.clone().assume_checked().script_pubkey()
    }

    fn psbt_output_info(&self) -> PsbtOutputInfo {
        match (&self.origin, &self.descriptor) {
            (Some(origin), Some(descriptor)) => PsbtOutputInfo::Bip32 {
                origin: *origin,
                descriptor: descriptor.clone(),
            },
            _ => PsbtOutputInfo::None,
        }
    }

    fn amount(&self) -> Amount {
        self.amount.clone()
    }

    fn set_amount(&mut self, amount: Amount) {
        self.amount = amount;
    }

    fn is_change(&self) -> bool {
        matches!(self.origin, Some((KeyChain::Change, _)))
    }

    fn to_psbt_output(&self) -> Result<bitcoin::psbt::Output, Error> {
        if let (Some(descr), Some((kc, index))) = (&self.descriptor, &self.origin) {
            let descriptors = descr
                .clone()
                .into_single_descriptors()
                .map_err(|_| Error::MultiDescriptor)?;
            let recv = descriptors.first().ok_or(Error::MultiDescriptor)?;
            let change = descriptors.get(1).ok_or(Error::MultiDescriptor)?;

            let descr = match kc {
                KeyChain::Receive => recv
                    .at_derivation_index(*index)
                    .map_err(|_| Error::Derivation)?,
                KeyChain::Change => change
                    .at_derivation_index(*index)
                    .map_err(|_| Error::Derivation)?,
                KeyChain::Custom(_) => return Err(Error::KeyChain),
            };

            let dummy_tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![self.clone().into()],
            };

            let mut dummy_psbt = bitcoin::Psbt {
                unsigned_tx: dummy_tx,
                version: 0,
                xpub: Default::default(),
                proprietary: Default::default(),
                unknown: Default::default(),
                inputs: Default::default(),
                outputs: vec![bitcoin::psbt::Output::default()],
            };

            PsbtExt::update_output_with_descriptor(&mut dummy_psbt, 0, &descr)
                .map_err(|_| Error::Update)?;

            Ok(dummy_psbt.outputs[0].clone())
        } else {
            Ok(bitcoin::psbt::Output::default())
        }
    }

    fn network(&self) -> Network {
        use miniscript::ForEachKey;

        if let Some(descriptor) = &self.descriptor {
            let is_mainnet = descriptor
                .clone()
                .into_single_descriptors()
                .ok()
                .and_then(|d| d.first().cloned())
                .map(|d| {
                    d.for_any_key(|k| match k {
                        DescriptorPublicKey::XPub(k) => k.xkey.network.is_mainnet(),
                        _ => false,
                    })
                })
                .unwrap_or(false);
            if is_mainnet {
                Network::Bitcoin
            } else {
                Network::Signet
            }
        } else {
            Network::Signet
        }
    }
}

#[derive(Clone)]
pub struct LocalTipUpdater(u32);

impl LocalTipUpdater {
    pub fn new(tip: u32) -> Self {
        Self(tip)
    }
}

impl ChangeTip for LocalTipUpdater {
    fn next_index(&mut self) -> u32 {
        self.0 += 1;
        self.0
    }
}

/// RecipientProvider for change outputs in descriptor-based wallets.
///
/// Generic over `T: ChangeTip` to decouple from concrete wallet implementations.
/// The type parameter is erased when boxed into `Box<dyn RecipientProvider>`.
pub struct ChangeRecipientProvider<T: ChangeTip> {
    tip_updater: T,
    descriptor: Descriptor<DescriptorPublicKey>,
    network: Network,
    amount: Amount,
    current_index: Option<u32>,
}

impl ChangeRecipientProvider<LocalTipUpdater> {
    pub fn new(descriptor: Descriptor<DescriptorPublicKey>, network: Network) -> Self {
        Self {
            tip_updater: LocalTipUpdater::new(0),
            descriptor,
            network,
            amount: Amount::Value(0),
            current_index: None,
        }
    }

    pub fn tip(mut self, tip: u32) -> Self {
        self.tip_updater = LocalTipUpdater::new(tip);
        self
    }
}

impl<T: ChangeTip> ChangeRecipientProvider<T> {
    pub fn new_with_updater(
        tip_updater: T,
        descriptor: Descriptor<DescriptorPublicKey>,
        network: Network,
    ) -> Self {
        Self {
            tip_updater,
            descriptor,
            network,
            amount: Amount::Value(0),
            current_index: None,
        }
    }
}

impl<T: ChangeTip + Clone> Clone for ChangeRecipientProvider<T> {
    fn clone(&self) -> Self {
        Self {
            tip_updater: self.tip_updater.clone(),
            descriptor: self.descriptor.clone(),
            network: self.network,
            amount: self.amount.clone(),
            current_index: self.current_index,
        }
    }
}

impl<T: ChangeTip + Clone + 'static> RecipientProvider for ChangeRecipientProvider<T> {
    fn output_weight(&self) -> Weight {
        let script = self
            .descriptor
            .clone()
            .into_single_descriptors()
            .expect("multipath")
            .get(1)
            .expect("change descriptor")
            .at_derivation_index(0)
            .expect("derivation")
            .address(self.network)
            .expect("address")
            .script_pubkey();
        TxOut {
            value: bitcoin::Amount::MAX_MONEY,
            script_pubkey: script,
        }
        .weight()
    }

    fn create_script(&mut self, _ctx: &FinalizationContext) -> ScriptBuf {
        let index = self.tip_updater.next_index();
        self.current_index = Some(index);

        self.descriptor
            .clone()
            .into_single_descriptors()
            .expect("multipath")
            .get(1)
            .expect("change descriptor")
            .at_derivation_index(index)
            .expect("derivation")
            .address(self.network)
            .expect("address")
            .script_pubkey()
    }

    fn psbt_output_info(&self) -> PsbtOutputInfo {
        let index = self
            .current_index
            .expect("psbt_output_info() called before create_script()");
        PsbtOutputInfo::Bip32 {
            origin: (KeyChain::Change, index),
            descriptor: self.descriptor.clone(),
        }
    }

    fn is_change(&self) -> bool {
        true
    }

    fn amount(&self) -> Amount {
        self.amount.clone()
    }

    fn set_amount(&mut self, amount: Amount) {
        self.amount = amount;
    }

    fn network(&self) -> Network {
        self.network
    }
}
