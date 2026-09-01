//! RecipientProvider implementations for Silent Payment types.
//!
//! This module implements bwk-tx's RecipientProvider trait for SP types.
//! Uses newtype wrappers to satisfy the orphan rule.

use crate::{
    core::utils::common::SilentPaymentAddress,
    receiver::{
        bitcoin::{key::TapTweak, script::PushBytesBuf, ScriptBuf, TxOut, Weight},
        RecipientAddress,
    },
};

use bwk_coin::{Coin, CoinSpendInfo};
use bwk_tx::{
    transaction::Amount, Error as TxError, FinalizationContext, PsbtOutputInfo, RecipientProvider,
    SpPartialSecretProvider,
};

const TR_OUTPUT_WEIGHT: u64 = 172;

use crate::receiver::bitcoin::Network;

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
                let script = addr.clone().assume_checked().script_pubkey();
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
            RecipientAddress::LegacyAddress(addr) => addr.clone().assume_checked().script_pubkey(),
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
    /// The SP address network is incompatible with the builder's network
    /// (e.g. a mainnet `sp1...` address on a non-mainnet wallet).
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

/// Returns `true` if the SP `address` network is compatible with `builder`
/// (the wallet's `bitcoin::Network`).
///
/// A mainnet SP address (`sp1...`) is only valid on `Network::Bitcoin`; a
/// non-mainnet SP address is only valid on a non-mainnet wallet. This mirrors
/// the guard wallet wrappers previously applied caller-side.
fn sp_network_matches(address: crate::core::utils::common::Network, builder: Network) -> bool {
    let address_is_mainnet = matches!(address, crate::core::utils::common::Network::Mainnet);
    let builder_is_mainnet = matches!(builder, Network::Bitcoin);
    address_is_mainnet == builder_is_mainnet
}

pub trait TxBuilderSpExt {
    fn send_to_sp(&mut self, address: SilentPaymentAddress, amount: u64);

    /// Validate the SP `address` network against the builder's configured
    /// `bitcoin::Network` and add it as an output. Returns
    /// [`SpRecipientError::NetworkMismatch`] without mutating the builder when
    /// the networks are incompatible.
    fn try_send_to_sp(
        &mut self,
        address: SilentPaymentAddress,
        amount: u64,
    ) -> Result<(), SpRecipientError>;
}

impl TxBuilderSpExt for bwk_tx::TxBuilder {
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
        if !sp_network_matches(address.get_network(), network) {
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
/// `is_change() = true` so that [`TxBuilder`](bwk_tx::TxBuilder) handles it
/// correctly during fee estimation and finalization.
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

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::receiver::SpReceiver;

use crate::account::coin_store::SpCoinStore;

/// Convert bitcoin::Network to crate::core::utils::common::Network.
fn to_sp_network(network: Network) -> crate::core::utils::common::Network {
    use crate::core::utils::common::Network as SpNetwork;
    match network {
        Network::Bitcoin => SpNetwork::Mainnet,
        Network::Testnet | Network::Signet => SpNetwork::Testnet,
        Network::Regtest => SpNetwork::Regtest,
        _ => SpNetwork::Testnet,
    }
}

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
            let sp_network = to_sp_network(output.network());
            let addr = SilentPaymentAddress::new(scan_pubkey, spend_pubkey, sp_network, 0)
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

// SpSecretProvider

/// Standalone [`SpPartialSecretProvider`] that can be boxed into a
/// [`TxBuilder`](bwk_tx::TxBuilder).
///
/// Holds a cloned [`SpReceiver`] and a shared coin store reference to look up
/// `OwnedOutput` tweaks for selected inputs. Also stores master xprivs from
/// BIP32 sub-accounts so it can derive secret keys for mixed-input transactions.
pub struct SpSecretProvider<
    P: crate::profile::SpStorageProfile = crate::profile::SpRamProfile<
        bwk::bwk_electrum::profile::DefaultBackend,
    >,
> {
    coin_store: Arc<Mutex<SpCoinStore<P>>>,
    client: SpReceiver,
    xprivs: std::collections::BTreeMap<
        crate::receiver::bitcoin::bip32::Fingerprint,
        crate::receiver::bitcoin::bip32::Xpriv,
    >,
    secp: crate::receiver::bitcoin::secp256k1::Secp256k1<crate::receiver::bitcoin::secp256k1::All>,
}

impl<P: crate::profile::SpStorageProfile> SpSecretProvider<P> {
    pub fn new(
        coin_store: Arc<Mutex<SpCoinStore<P>>>,
        client: SpReceiver,
        xprivs: std::collections::BTreeMap<
            crate::receiver::bitcoin::bip32::Fingerprint,
            crate::receiver::bitcoin::bip32::Xpriv,
        >,
    ) -> Self {
        Self {
            coin_store,
            client,
            xprivs,
            secp: crate::receiver::bitcoin::secp256k1::Secp256k1::new(),
        }
    }

    /// Derive the secret key for a BIP32 coin if not already set.
    fn derive_bip32_secret_key(
        &self,
        coin: &Coin,
    ) -> Option<crate::receiver::bitcoin::secp256k1::SecretKey> {
        let psbt_input = coin.to_psbt_input().ok()?;

        if !psbt_input.bip32_derivation.is_empty() {
            psbt_input.bip32_derivation.values().find_map(|(fg, path)| {
                let xpriv = self.xprivs.get(fg)?;
                xpriv
                    .derive_priv(&self.secp, path)
                    .ok()
                    .map(|k| k.private_key)
            })
        } else if !psbt_input.tap_key_origins.is_empty() {
            psbt_input
                .tap_key_origins
                .values()
                .find_map(|(_, (fg, path))| {
                    let xpriv = self.xprivs.get(fg)?;
                    xpriv
                        .derive_priv(&self.secp, path)
                        .ok()
                        .map(|k| k.private_key)
                })
        } else {
            None
        }
    }
}

impl<P: crate::profile::SpStorageProfile + Send + Sync + 'static> SpPartialSecretProvider
    for SpSecretProvider<P>
{
    // Source: adapted from cygnet3/spdk's selected-input partial-secret logic.
    // See `sp/NOTICE`.
    fn compute_partial_secret(
        &self,
        inputs: &[Coin],
    ) -> Result<crate::receiver::bitcoin::secp256k1::SecretKey, TxError> {
        use crate::receiver::bitcoin::secp256k1::SecretKey;

        let b_spend = self
            .client
            .try_get_secret_spend_key()
            .map_err(|_| TxError::SpPartialSecret)?;

        let store = self.coin_store.lock().expect("poisoned");
        let mut input_keys = Vec::with_capacity(inputs.len());
        let mut outpoints = Vec::with_capacity(inputs.len());

        for coin in inputs {
            outpoints.push((coin.outpoint.txid.to_string(), coin.outpoint.vout));

            match &coin.spend_info {
                CoinSpendInfo::Sp { tweak, .. } => {
                    let sk = SecretKey::from_slice(tweak).map_err(|_| TxError::SpPartialSecret)?;
                    let signing_key = b_spend
                        .add_tweak(&sk.into())
                        .map_err(|_| TxError::SpPartialSecret)?;
                    input_keys.push((signing_key, true));
                }
                CoinSpendInfo::Bip32 { secret_key, .. } => {
                    let sk = secret_key
                        .or_else(|| self.derive_bip32_secret_key(coin))
                        .ok_or(TxError::CoinNotFound)?;
                    let is_taproot = coin.txout.script_pubkey.is_p2tr();
                    if is_taproot {
                        // BIP32 P2TR outputs have a standard BIP341 taproot tweak.
                        // The scanner extracts the tweaked output key from scriptPubKey,
                        // so we must use the tweaked private key for partial secret.
                        let kp = crate::receiver::bitcoin::secp256k1::Keypair::from_secret_key(
                            &self.secp, &sk,
                        );
                        let tweaked = kp.tap_tweak(&self.secp, None).to_keypair();
                        input_keys.push((tweaked.secret_key(), true));
                    } else {
                        input_keys.push((sk, false));
                    }
                }
            }
        }

        drop(store);
        crate::core::sending::calculate_partial_secret(&input_keys, &outpoints)
            .map_err(|_| TxError::SpPartialSecret)
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

/// Derive a BIP32 coin's secret key from the SP account's and sub-accounts' master xprivs.
#[cfg(feature = "mnemonic")]
fn derive_bip32_key(
    coin: &Coin,
    account: &Account,
) -> Option<crate::receiver::bitcoin::secp256k1::SecretKey> {
    let secp = crate::receiver::bitcoin::secp256k1::Secp256k1::new();
    let psbt_input = coin.to_psbt_input().ok()?;

    let xprivs = account.master_xprivs();

    if !psbt_input.bip32_derivation.is_empty() {
        psbt_input.bip32_derivation.values().find_map(|(fg, path)| {
            let xpriv = xprivs.get(fg)?;
            xpriv.derive_priv(&secp, path).ok().map(|k| k.private_key)
        })
    } else if !psbt_input.tap_key_origins.is_empty() {
        psbt_input
            .tap_key_origins
            .values()
            .find_map(|(_, (fg, path))| {
                let xpriv = xprivs.get(fg)?;
                xpriv.derive_priv(&secp, path).ok().map(|k| k.private_key)
            })
    } else {
        None
    }
}

#[cfg(feature = "mnemonic")]
impl SpPartialSecretProvider for Account {
    // Source: adapted from cygnet3/spdk's selected-input partial-secret logic.
    // See `sp/NOTICE`.
    fn compute_partial_secret(
        &self,
        inputs: &[Coin],
    ) -> Result<crate::receiver::bitcoin::secp256k1::SecretKey, TxError> {
        use crate::receiver::bitcoin::secp256k1::SecretKey;

        let b_spend = self
            .sp_receiver()
            .try_get_secret_spend_key()
            .map_err(|_| TxError::SpPartialSecret)?;

        let mut input_keys = Vec::with_capacity(inputs.len());
        let mut outpoints = Vec::with_capacity(inputs.len());

        for coin in inputs {
            outpoints.push((coin.outpoint.txid.to_string(), coin.outpoint.vout));

            match &coin.spend_info {
                CoinSpendInfo::Sp { tweak, .. } => {
                    let sk = SecretKey::from_slice(tweak).map_err(|_| TxError::SpPartialSecret)?;
                    let signing_key = b_spend
                        .add_tweak(&sk.into())
                        .map_err(|_| TxError::SpPartialSecret)?;
                    input_keys.push((signing_key, true));
                }
                CoinSpendInfo::Bip32 { secret_key, .. } => {
                    let sk = secret_key
                        .or_else(|| derive_bip32_key(coin, self))
                        .ok_or(TxError::CoinNotFound)?;
                    let is_taproot = coin.txout.script_pubkey.is_p2tr();
                    if is_taproot {
                        let secp = crate::receiver::bitcoin::secp256k1::Secp256k1::new();
                        let kp = crate::receiver::bitcoin::secp256k1::Keypair::from_secret_key(
                            &secp, &sk,
                        );
                        let tweaked = kp.tap_tweak(&secp, None).to_keypair();
                        input_keys.push((tweaked.secret_key(), true));
                    } else {
                        input_keys.push((sk, false));
                    }
                }
            }
        }

        crate::core::sending::calculate_partial_secret(&input_keys, &outpoints)
            .map_err(|_| TxError::SpPartialSecret)
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

    fn sp_net(n: Network) -> SpNetwork {
        if matches!(n, Network::Bitcoin) {
            SpNetwork::Mainnet
        } else {
            SpNetwork::Testnet
        }
    }

    /// Build a SilentPaymentAddress for `network` from deterministic keys.
    fn sp_address(network: SpNetwork) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        let scan = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
        SilentPaymentAddress::new(scan, spend, network, 0).unwrap()
    }

    /// A minimal TxBuilder bound to `network` (SP change provider only).
    fn builder(network: Network) -> bwk_tx::TxBuilder {
        let change = SpChangeRecipientProvider::new(sp_address(sp_net(network)), network);
        bwk_tx::TxBuilder::new(Box::new(change))
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
    fn try_send_to_sp_accepts_matching_mainnet() {
        let mut b = builder(Network::Bitcoin);
        let addr = sp_address(SpNetwork::Mainnet);
        assert!(b.try_send_to_sp(addr, 10_000).is_ok());
        assert_eq!(b.tx_template.outputs.len(), 1);
    }

    #[test]
    fn try_send_to_sp_accepts_matching_non_mainnet() {
        let mut b = builder(Network::Regtest);
        let addr = sp_address(SpNetwork::Testnet);
        assert!(b.try_send_to_sp(addr, 10_000).is_ok());
        assert_eq!(b.tx_template.outputs.len(), 1);
    }
}
