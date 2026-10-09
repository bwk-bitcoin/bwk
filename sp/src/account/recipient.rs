//! RecipientProvider implementations for Silent Payment types.
//!
//! This module implements bwk-tx's RecipientProvider trait for SP types.
//! Uses newtype wrappers to satisfy the orphan rule.

use crate::{
    core::{receiving::NUMS_H, utils::common::SilentPaymentAddress},
    receiver::{
        bitcoin::{
            bip32::{Fingerprint, Xpriv},
            key::TapTweak,
            script::PushBytesBuf,
            secp256k1::{All, Keypair, Secp256k1, SecretKey},
            Network, ScriptBuf, TxOut, Weight,
        },
        RecipientAddress, SpReceiver,
    },
};

use bwk_coin::{derive_descriptor, Coin, CoinSpendInfo};
use bwk_tx::{
    error::Error as TxError,
    recipient::{FinalizationContext, PsbtOutputInfo, RecipientProvider, SpPartialSecretProvider},
    transaction::Amount,
};
use miniscript::{
    descriptor::{ShInner, Tr},
    DefiniteDescriptorKey, Descriptor, ToPublicKey,
};

const TR_OUTPUT_WEIGHT: u64 = 172;

#[derive(Debug, Clone)]
pub struct SpRecipient {
    /// The silent payment address
    pub address: SilentPaymentAddress,
    /// Amount to send
    pub amount: Amount,
    /// Optional label index for BIP375
    pub label: Option<u32>,
    /// Network
    pub network: Network,
    /// Pre-computed output script (set by batch derivation)
    precomputed_script: Option<ScriptBuf>,
}

impl SpRecipient {
    /// Create a new SpRecipient from a SilentPaymentAddress
    pub fn new(address: SilentPaymentAddress, amount: u64, network: Network) -> Self {
        Self {
            address,
            amount: Amount::Value(amount),
            label: None,
            network,
            precomputed_script: None,
        }
    }

    /// Create a new SpRecipient with a label
    pub fn with_label(
        address: SilentPaymentAddress,
        amount: u64,
        label: u32,
        network: Network,
    ) -> Self {
        Self {
            address,
            amount: Amount::Value(amount),
            label: Some(label),
            network,
            precomputed_script: None,
        }
    }
}

impl RecipientProvider for SpRecipient {
    fn output_weight(&self) -> Weight {
        // SP outputs are always P2TR
        Weight::from_wu(TR_OUTPUT_WEIGHT)
    }

    fn create_script(&mut self, ctx: &FinalizationContext) -> ScriptBuf {
        if let Some(ref script) = self.precomputed_script {
            return script.clone();
        }

        let partial_secret = ctx
            .partial_secret
            .expect("SP output requires partial_secret in FinalizationContext");

        // Fallback: single-output independent derivation (k=0).
        // For multi-output transactions, derive_sp_scripts() should have
        // already set precomputed_script with the correct k value.
        let pubkeys =
            crate::core::sending::generate_recipient_pubkeys(vec![self.address], partial_secret)
                .expect("failed to generate SP recipient pubkeys");

        let output_pubkeys = pubkeys
            .get(&self.address)
            .expect("missing pubkey for SP address");

        let pubkey = output_pubkeys[0];
        ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked())
    }

    fn set_precomputed_script(&mut self, script: ScriptBuf) {
        self.precomputed_script = Some(script);
    }

    fn psbt_output_info(&self) -> PsbtOutputInfo {
        PsbtOutputInfo::SilentPayment {
            scan_pubkey: self.address.get_scan_key(),
            spend_pubkey: self.address.get_spend_key(),
            label: self.label,
        }
    }

    fn is_silent_payment(&self) -> bool {
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

#[derive(Debug, Clone)]
pub struct SpRecipientAddress {
    pub inner: RecipientAddress,
    pub amount: Amount,
    pub network: Network,
    /// Pre-computed output script (set by batch derivation)
    precomputed_script: Option<ScriptBuf>,
}

impl SpRecipientAddress {
    /// Create a new SpRecipientAddress with an amount
    pub fn new(addr: RecipientAddress, amount: u64, network: Network) -> Self {
        Self {
            inner: addr,
            amount: Amount::Value(amount),
            network,
            precomputed_script: None,
        }
    }

    /// Create from a SilentPaymentAddress
    pub fn from_sp(addr: SilentPaymentAddress, amount: u64, network: Network) -> Self {
        Self {
            inner: RecipientAddress::SpAddress(addr),
            amount: Amount::Value(amount),
            network,
            precomputed_script: None,
        }
    }
}

impl RecipientProvider for SpRecipientAddress {
    fn output_weight(&self) -> Weight {
        match &self.inner {
            RecipientAddress::SpAddress(_) => Weight::from_wu(TR_OUTPUT_WEIGHT),
            RecipientAddress::LegacyAddress(addr) => {
                let script = addr.script_pubkey();
                TxOut {
                    value: crate::receiver::bitcoin::Amount::MAX_MONEY,
                    script_pubkey: script,
                }
                .weight()
            }
            RecipientAddress::Data(data) => {
                // OP_RETURN: OP_RETURN (1) + push (1-2) + data
                let script_len = 1 + 1 + data.len().min(80);
                // output = 8 (value) + 1 (varint) + script_len
                let output_size = 8 + 1 + script_len;
                Weight::from_wu((output_size * 4) as u64)
            }
        }
    }

    fn create_script(&mut self, ctx: &FinalizationContext) -> ScriptBuf {
        match &self.inner {
            RecipientAddress::SpAddress(sp) => {
                if let Some(ref script) = self.precomputed_script {
                    return script.clone();
                }

                let partial_secret = ctx
                    .partial_secret
                    .expect("SP output requires partial_secret");

                let pubkeys =
                    crate::core::sending::generate_recipient_pubkeys(vec![*sp], partial_secret)
                        .expect("failed to generate SP recipient pubkeys");

                let output_pubkeys = pubkeys.get(sp).expect("missing pubkey for SP address");

                let pubkey = output_pubkeys[0];
                ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked())
            }
            RecipientAddress::LegacyAddress(addr) => addr.script_pubkey(),
            RecipientAddress::Data(data) => {
                let mut op_return = PushBytesBuf::with_capacity(data.len());
                op_return
                    .extend_from_slice(data)
                    .expect("data too large for OP_RETURN");
                ScriptBuf::new_op_return(op_return)
            }
        }
    }

    fn set_precomputed_script(&mut self, script: ScriptBuf) {
        self.precomputed_script = Some(script);
    }

    fn psbt_output_info(&self) -> PsbtOutputInfo {
        match &self.inner {
            RecipientAddress::SpAddress(sp) => PsbtOutputInfo::SilentPayment {
                scan_pubkey: sp.get_scan_key(),
                spend_pubkey: sp.get_spend_key(),
                label: None,
            },
            _ => PsbtOutputInfo::None,
        }
    }

    fn is_silent_payment(&self) -> bool {
        matches!(self.inner, RecipientAddress::SpAddress(_))
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

// TxBuilderSpExt

/// Error returned when adding a Silent Payment recipient fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpRecipientError {
    /// The SP address network is not the builder's network (e.g. a testnet
    /// `tsp1...` address on a regtest wallet).
    NetworkMismatch {
        address: crate::core::utils::common::Network,
        builder: Network,
    },
}

impl std::fmt::Display for SpRecipientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpRecipientError::NetworkMismatch { address, builder } => write!(
                f,
                "silent payment address network ({address:?}) does not match wallet network ({builder:?})"
            ),
        }
    }
}

impl std::error::Error for SpRecipientError {}

pub trait TxBuilderSpExt {
    fn send_to_sp(&mut self, address: SilentPaymentAddress, amount: u64);

    /// Validate the SP `address` network against the builder's configured
    /// `bitcoin::Network` and add it as an output. Returns
    /// [`SpRecipientError::NetworkMismatch`] without mutating the builder when
    /// the address is not for that exact network.
    fn try_send_to_sp(
        &mut self,
        address: SilentPaymentAddress,
        amount: u64,
    ) -> Result<(), SpRecipientError>;
}

impl TxBuilderSpExt for bwk_tx::tx_builder::TxBuilder {
    fn send_to_sp(&mut self, address: SilentPaymentAddress, amount: u64) {
        let network = self.network();
        self.add_output(SpRecipientAddress::from_sp(address, amount, network));
    }

    fn try_send_to_sp(
        &mut self,
        address: SilentPaymentAddress,
        amount: u64,
    ) -> Result<(), SpRecipientError> {
        let network = self.network();
        if address.get_network() != network.into() {
            return Err(SpRecipientError::NetworkMismatch {
                address: address.get_network(),
                builder: network,
            });
        }
        self.add_output(SpRecipientAddress::from_sp(address, amount, network));
        Ok(())
    }
}

/// Change output provider for Silent Payment wallets.
///
/// Wraps an [`SpRecipient`] for the wallet's change address, adding
/// `is_change() = true` so that [`TxBuilder`](bwk_tx::tx_builder::TxBuilder)
/// handles it correctly during fee estimation and finalization.
#[derive(Debug, Clone)]
pub struct SpChangeRecipientProvider(SpRecipient);

impl SpChangeRecipientProvider {
    pub fn new(address: SilentPaymentAddress, network: Network) -> Self {
        Self(SpRecipient::new(address, 0, network))
    }
}

impl RecipientProvider for SpChangeRecipientProvider {
    fn output_weight(&self) -> Weight {
        self.0.output_weight()
    }

    fn create_script(&mut self, ctx: &FinalizationContext) -> ScriptBuf {
        self.0.create_script(ctx)
    }

    fn set_precomputed_script(&mut self, script: ScriptBuf) {
        self.0.set_precomputed_script(script);
    }

    fn psbt_output_info(&self) -> PsbtOutputInfo {
        self.0.psbt_output_info()
    }

    fn is_silent_payment(&self) -> bool {
        true
    }

    fn is_change(&self) -> bool {
        true
    }

    fn amount(&self) -> Amount {
        self.0.amount()
    }

    fn set_amount(&mut self, amount: Amount) {
        self.0.set_amount(amount);
    }

    fn network(&self) -> Network {
        self.0.network()
    }
}

// Batch SP script derivation

use std::collections::{BTreeMap, HashMap};

/// Batch-derive output scripts for all SP outputs in a transaction.
///
/// Per BIP352, outputs sharing the same scan key must be derived together
/// with incrementing `k` values. This function:
/// 1. Collects all SP addresses from outputs via `psbt_output_info()`
/// 2. Calls `generate_recipient_pubkeys()` once with all SP addresses
/// 3. Uses per-address counters to assign the correct pubkey to each output
/// 4. Stores the pre-computed script on each SP output
///
/// Source: adapted from cygnet3/spdk's silent-payment transaction finalization.
/// See `sp/NOTICE`.
fn batch_derive_sp_scripts(
    outputs: &mut [Box<dyn RecipientProvider>],
    partial_secret: crate::receiver::bitcoin::secp256k1::SecretKey,
) {
    // Collect SP output indices and reconstruct their addresses
    let mut sp_indices = Vec::new();
    let mut sp_addresses = Vec::new();

    for (i, output) in outputs.iter().enumerate() {
        if !output.is_silent_payment() {
            continue;
        }
        if let PsbtOutputInfo::SilentPayment {
            scan_pubkey,
            spend_pubkey,
            ..
        } = output.psbt_output_info()
        {
            let addr =
                SilentPaymentAddress::new(scan_pubkey, spend_pubkey, output.network().into(), 0)
                    .expect("valid SP address from psbt_output_info");
            sp_addresses.push(addr);
            sp_indices.push(i);
        }
    }

    if sp_addresses.is_empty() {
        return;
    }

    // Single call with all addresses: BIP352 k-counter increments per scan-key group
    let pubkey_map =
        crate::core::sending::generate_recipient_pubkeys(sp_addresses.clone(), partial_secret)
            .expect("failed to generate SP recipient pubkeys");

    // Assign the correct pubkey to each output using per-address counters
    let mut counters: HashMap<SilentPaymentAddress, usize> = HashMap::new();

    for (sp_idx, &output_idx) in sp_indices.iter().enumerate() {
        let addr = &sp_addresses[sp_idx];
        let pubkeys = pubkey_map.get(addr).expect("missing pubkey for SP address");
        let k = counters.entry(*addr).or_insert(0);
        let pubkey = pubkeys[*k];
        *k += 1;

        let script = ScriptBuf::new_p2tr_tweaked(pubkey.dangerous_assume_tweaked());
        outputs[output_idx].set_precomputed_script(script);
    }
}

// BIP352 input keys

/// Sum the BIP352 input keys of `inputs` into the partial secret. The input
/// hash still covers every outpoint, eligible or not.
///
/// Source: adapted from cygnet3/spdk's selected-input partial-secret logic.
/// See `sp/NOTICE`.
fn partial_secret(
    inputs: &[Coin],
    b_spend: &SecretKey,
    xprivs: &BTreeMap<Fingerprint, Xpriv>,
    secp: &Secp256k1<All>,
) -> Result<SecretKey, TxError> {
    let mut input_keys = Vec::with_capacity(inputs.len());
    let mut outpoints = Vec::with_capacity(inputs.len());

    for coin in inputs {
        outpoints.push((coin.outpoint.txid.to_string(), coin.outpoint.vout));
        if let Some(key) = bip352_input_key(coin, b_spend, xprivs, secp)? {
            input_keys.push(key);
        }
    }

    crate::core::sending::calculate_partial_secret(&input_keys, &outpoints)
        .map_err(|_| TxError::SpPartialSecret)
}

/// The secret key `coin` adds to the BIP352 input sum, and whether it is a
/// taproot key.
///
/// `None` for an input BIP352 receivers leave out of the sum. An error when
/// the input counts but we cannot produce its key: the SP outputs would then
/// pay to a key the receiver never finds. A descriptor we cannot derive at the
/// coin's path errors with [`TxError::Coin`].
fn bip352_input_key(
    coin: &Coin,
    b_spend: &SecretKey,
    xprivs: &BTreeMap<Fingerprint, Xpriv>,
    secp: &Secp256k1<All>,
) -> Result<Option<(SecretKey, bool)>, TxError> {
    match &coin.spend_info {
        CoinSpendInfo::Sp { tweak, .. } => sp_input_key(b_spend, tweak).map(Some),
        CoinSpendInfo::Bip32 {
            coin_path: (keychain, index),
            descriptor,
            ..
        } => {
            let descriptor = derive_descriptor(descriptor, *keychain, *index)?;
            if descriptor.script_pubkey() != coin.txout.script_pubkey {
                return Err(TxError::SpPartialSecret);
            }
            match &descriptor {
                Descriptor::Pkh(pkh) => single_key_input_key(pkh.as_inner(), xprivs, secp),
                Descriptor::Wpkh(wpkh) => single_key_input_key(wpkh.as_inner(), xprivs, secp),
                Descriptor::Sh(sh) => match sh.as_inner() {
                    ShInner::Wpkh(wpkh) => single_key_input_key(wpkh.as_inner(), xprivs, secp),
                    ShInner::Wsh(_) | ShInner::SortedMulti(_) | ShInner::Ms(_) => Ok(None),
                },
                Descriptor::Tr(tr) => taproot_input_key(tr, xprivs, secp),
                Descriptor::Bare(_) | Descriptor::Wsh(_) => Ok(None),
            }
        }
    }
}

fn sp_input_key(b_spend: &SecretKey, tweak: &[u8; 32]) -> Result<(SecretKey, bool), TxError> {
    let tweak = SecretKey::from_slice(tweak).map_err(|_| TxError::SpPartialSecret)?;
    let key = b_spend
        .add_tweak(&tweak.into())
        .map_err(|_| TxError::SpPartialSecret)?;
    Ok((key, true))
}

/// BIP352 skips an uncompressed key.
fn single_key_input_key(
    key: &DefiniteDescriptorKey,
    xprivs: &BTreeMap<Fingerprint, Xpriv>,
    secp: &Secp256k1<All>,
) -> Result<Option<(SecretKey, bool)>, TxError> {
    let pubkey = key.to_public_key();
    if !pubkey.compressed {
        return Ok(None);
    }
    let secret = held_secret(key, xprivs, secp)?;
    if secret.public_key(secp) != pubkey.inner {
        return Err(TxError::SpPartialSecret);
    }
    Ok(Some((secret, false)))
}

/// The output key is the internal key tweaked with the tap tree, whatever
/// path the input will be spent with.
fn taproot_input_key(
    tr: &Tr<DefiniteDescriptorKey>,
    xprivs: &BTreeMap<Fingerprint, Xpriv>,
    secp: &Secp256k1<All>,
) -> Result<Option<(SecretKey, bool)>, TxError> {
    let internal_key = tr.internal_key();
    if internal_key.to_x_only_pubkey().serialize() == NUMS_H {
        return Ok(None);
    }
    let secret = held_secret(internal_key, xprivs, secp)?;
    let spend_info = tr.spend_info();
    let tweaked = Keypair::from_secret_key(secp, &secret)
        .tap_tweak(secp, spend_info.merkle_root())
        .to_keypair();
    if tweaked.x_only_public_key().0 != spend_info.output_key().to_x_only_public_key() {
        return Err(TxError::SpPartialSecret);
    }
    Ok(Some((tweaked.secret_key(), true)))
}

fn held_secret(
    key: &DefiniteDescriptorKey,
    xprivs: &BTreeMap<Fingerprint, Xpriv>,
    secp: &Secp256k1<All>,
) -> Result<SecretKey, TxError> {
    let xpriv = xprivs
        .get(&key.master_fingerprint())
        .ok_or(TxError::SpPartialSecret)?;
    let path = key.full_derivation_path().ok_or(TxError::SpPartialSecret)?;
    xpriv
        .derive_priv(secp, &path)
        .map(|xpriv| xpriv.private_key)
        .map_err(|_| TxError::SpPartialSecret)
}

// SpSecretProvider

/// Standalone [`SpPartialSecretProvider`] that can be boxed into a
/// [`TxBuilder`](bwk_tx::tx_builder::TxBuilder).
///
/// Holds a cloned [`SpReceiver`] for the spend key, and the master xprivs of
/// the sub-accounts to derive the BIP32 input keys.
pub struct SpSecretProvider {
    client: SpReceiver,
    xprivs: std::collections::BTreeMap<
        crate::receiver::bitcoin::bip32::Fingerprint,
        crate::receiver::bitcoin::bip32::Xpriv,
    >,
    secp: crate::receiver::bitcoin::secp256k1::Secp256k1<crate::receiver::bitcoin::secp256k1::All>,
}

impl SpSecretProvider {
    pub fn new(
        client: SpReceiver,
        xprivs: std::collections::BTreeMap<
            crate::receiver::bitcoin::bip32::Fingerprint,
            crate::receiver::bitcoin::bip32::Xpriv,
        >,
    ) -> Self {
        Self {
            client,
            xprivs,
            secp: crate::receiver::bitcoin::secp256k1::Secp256k1::new(),
        }
    }
}

impl SpPartialSecretProvider for SpSecretProvider {
    fn compute_partial_secret(&self, inputs: &[Coin]) -> Result<SecretKey, TxError> {
        let b_spend = self
            .client
            .try_get_secret_spend_key()
            .map_err(|_| TxError::SpPartialSecret)?;

        partial_secret(inputs, &b_spend, &self.xprivs, &self.secp)
    }

    fn derive_sp_scripts(
        &self,
        outputs: &mut [Box<dyn RecipientProvider>],
        partial_secret: crate::receiver::bitcoin::secp256k1::SecretKey,
    ) {
        batch_derive_sp_scripts(outputs, partial_secret);
    }
}

// SpPartialSecretProvider for Account.

#[cfg(feature = "mnemonic")]
use crate::account::Account;

#[cfg(feature = "mnemonic")]
impl SpPartialSecretProvider for Account {
    fn compute_partial_secret(&self, inputs: &[Coin]) -> Result<SecretKey, TxError> {
        let b_spend = self
            .sp_receiver()
            .try_get_secret_spend_key()
            .map_err(|_| TxError::SpPartialSecret)?;

        partial_secret(inputs, &b_spend, &self.master_xprivs(), &Secp256k1::new())
    }

    fn derive_sp_scripts(
        &self,
        outputs: &mut [Box<dyn RecipientProvider>],
        partial_secret: crate::receiver::bitcoin::secp256k1::SecretKey,
    ) {
        batch_derive_sp_scripts(outputs, partial_secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::utils::common::Network as SpNetwork,
        receiver::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey},
    };

    /// Build a SilentPaymentAddress for `network` from deterministic keys.
    fn sp_address(network: SpNetwork) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        let scan = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
        SilentPaymentAddress::new(scan, spend, network, 0).unwrap()
    }

    /// A minimal TxBuilder bound to `network` (SP change provider only).
    fn builder(network: Network) -> bwk_tx::tx_builder::TxBuilder {
        let change = SpChangeRecipientProvider::new(sp_address(network.into()), network);
        bwk_tx::tx_builder::TxBuilder::new(Box::new(change))
    }

    #[test]
    fn try_send_to_sp_rejects_mainnet_address_on_non_mainnet_builder() {
        let mut b = builder(Network::Regtest);
        let addr = sp_address(SpNetwork::Mainnet);
        let res = b.try_send_to_sp(addr, 10_000);
        assert!(matches!(res, Err(SpRecipientError::NetworkMismatch { .. })));
        assert!(b.tx_template.outputs.is_empty());
    }

    #[test]
    fn try_send_to_sp_rejects_testnet_address_on_mainnet_builder() {
        let mut b = builder(Network::Bitcoin);
        let addr = sp_address(SpNetwork::Testnet);
        let res = b.try_send_to_sp(addr, 10_000);
        assert!(matches!(res, Err(SpRecipientError::NetworkMismatch { .. })));
        assert!(b.tx_template.outputs.is_empty());
    }

    #[test]
    fn try_send_to_sp_rejects_testnet_address_on_regtest_builder() {
        let mut b = builder(Network::Regtest);
        let addr = sp_address(SpNetwork::Testnet);
        let res = b.try_send_to_sp(addr, 10_000);
        assert!(matches!(res, Err(SpRecipientError::NetworkMismatch { .. })));
        assert!(b.tx_template.outputs.is_empty());
    }

    #[test]
    fn try_send_to_sp_accepts_matching_mainnet() {
        let mut b = builder(Network::Bitcoin);
        let addr = sp_address(SpNetwork::Mainnet);
        assert!(b.try_send_to_sp(addr, 10_000).is_ok());
        assert_eq!(b.tx_template.outputs.len(), 1);
    }

    #[test]
    fn try_send_to_sp_accepts_matching_regtest() {
        let mut b = builder(Network::Regtest);
        let addr = sp_address(SpNetwork::Regtest);
        assert!(b.try_send_to_sp(addr, 10_000).is_ok());
        assert_eq!(b.tx_template.outputs.len(), 1);
    }
}
