//! RecipientProvider implementations for Silent Payment types.
//!
//! This module implements bwk-tx's RecipientProvider trait for SP types.
//! Uses newtype wrappers to satisfy the orphan rule. Silent-payment outputs
//! never get a script here: that derivation needs `b_spend` and every
//! selected input's tweak, so it happens later, in `bwk_sp::signer::SpSigner`.

use crate::{
    core::utils::common::SilentPaymentAddress,
    receiver::{
        bitcoin::{script::PushBytesBuf, ScriptBuf, TxOut, Weight},
        RecipientAddress,
    },
};

use bwk_tx::{
    recipient::{FinalizationContext, PsbtOutputInfo, RecipientProvider},
    transaction::Amount,
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
}

impl SpRecipient {
    /// Create a new SpRecipient from a SilentPaymentAddress
    pub fn new(address: SilentPaymentAddress, amount: u64, network: Network) -> Self {
        Self {
            address,
            amount: Amount::Value(amount),
            label: None,
            network,
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
        }
    }
}

impl RecipientProvider for SpRecipient {
    fn output_weight(&self) -> Weight {
        // SP outputs are always P2TR
        Weight::from_wu(TR_OUTPUT_WEIGHT)
    }

    fn create_script(&mut self, _ctx: &FinalizationContext) -> ScriptBuf {
        // Left empty: a signer derives this from the input hash and writes it
        // into the PSBTv2 output once it has both b_spend and the tx's inputs.
        ScriptBuf::new()
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
}

impl SpRecipientAddress {
    /// Create a new SpRecipientAddress with an amount
    pub fn new(addr: RecipientAddress, amount: u64, network: Network) -> Self {
        Self {
            inner: addr,
            amount: Amount::Value(amount),
            network,
        }
    }

    /// Create from a SilentPaymentAddress
    pub fn from_sp(addr: SilentPaymentAddress, amount: u64, network: Network) -> Self {
        Self {
            inner: RecipientAddress::SpAddress(addr),
            amount: Amount::Value(amount),
            network,
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

    fn create_script(&mut self, _ctx: &FinalizationContext) -> ScriptBuf {
        match &self.inner {
            // Left empty: a signer derives this later, see `SpRecipient::create_script`.
            RecipientAddress::SpAddress(_) => ScriptBuf::new(),
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

/// Convert bitcoin::Network to crate::core::utils::common::Network.
pub fn to_sp_network(network: Network) -> crate::core::utils::common::Network {
    use crate::core::utils::common::Network as SpNetwork;
    match network {
        Network::Bitcoin => SpNetwork::Mainnet,
        Network::Testnet | Network::Signet => SpNetwork::Testnet,
        Network::Regtest => SpNetwork::Regtest,
        _ => SpNetwork::Testnet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{utils::common::Network as SpNetwork, SpVersion},
        receiver::bitcoin::secp256k1::PublicKey,
    };

    /// Compressed encoding of the secp256k1 generator point `G`.
    const SCAN_PUBKEY_BYTES: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    /// Compressed encoding of `2G`.
    const SPEND_PUBKEY_BYTES: [u8; 33] = [
        0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
        0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c,
        0x70, 0x9e, 0xe5,
    ];

    fn sp_net(n: Network) -> SpNetwork {
        if matches!(n, Network::Bitcoin) {
            SpNetwork::Mainnet
        } else {
            SpNetwork::Testnet
        }
    }

    /// Build a SilentPaymentAddress for `network` from fixed dummy keys.
    fn sp_address(network: SpNetwork) -> SilentPaymentAddress {
        let scan = PublicKey::from_slice(&SCAN_PUBKEY_BYTES).unwrap();
        let spend = PublicKey::from_slice(&SPEND_PUBKEY_BYTES).unwrap();
        SilentPaymentAddress::new(scan, spend, network, SpVersion::V0).unwrap()
    }

    /// A minimal TxBuilder bound to `network` (SP change provider only).
    fn builder(network: Network) -> bwk_tx::tx_builder::TxBuilder {
        let change = SpChangeRecipientProvider::new(sp_address(sp_net(network)), network);
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
