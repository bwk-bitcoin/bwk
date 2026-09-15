//! Serializable transaction request used by [`bwk_sp::account::Account`]
//! orchestration helpers.
//!
//! A [`TxRequest`] is a binding-friendly description of a transaction to
//! build: outputs (address strings, amounts, optional labels, optional
//! drain), fee spec, and either a manual input set or no inputs (auto-select
//! / drain). Account-level helpers turn it into a configured `TxBuilder`, a
//! [`TxSimulation`], or an unsigned PSBT.

use serde::{Deserialize, Serialize};

/// One output specified in a [`TxRequest`].
///
/// `amount` is ignored when `max` is true. Address parsing is deferred to the
/// account-level helper (it knows the relevant networks and SP context).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputSpec {
    /// The destination address: a Bitcoin address or a Silent Payment address.
    pub address: String,
    /// Amount in satoshis. Ignored when `max == true`.
    pub amount: u64,
    /// Optional user label attached to this output.
    pub label: Option<String>,
    /// If true, this output drains the wallet (minus fees). At most one output may set this.
    pub max: bool,
}

/// A serializable transaction request to be turned into a `TxBuilder`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRequest {
    /// Outputs of the transaction.
    pub outputs: Vec<TxOutputSpec>,
    /// Fee rate in sat/vbyte. Used when `fee == 0`. Internally clamped to `>= 1.0`.
    pub fee_rate: f64,
    /// Absolute fee in satoshis. When `> 0` it takes precedence over `fee_rate`.
    pub fee: u64,
    /// Outpoints to spend. Empty means auto-select (or drain, if any output has `max`).
    pub input_outpoints: Vec<bitcoin::OutPoint>,
}

/// Result of [`bwk_sp::account::Account::simulate`]: fee, weight, and the
/// selected input set.
#[derive(Debug, Clone)]
pub struct TxSimulation {
    /// Estimated fee.
    pub fee: bitcoin::Amount,
    /// Estimated transaction weight.
    pub weight: bitcoin::Weight,
    /// Sum of selected input values.
    pub input_total: bitcoin::Amount,
    /// Sum of output values (excluding the fee).
    pub output_total: bitcoin::Amount,
    /// Outpoints actually selected by the builder.
    pub selected_outpoints: Vec<bitcoin::OutPoint>,
}

/// Error returned by the [`TxRequest`]-driven account helpers.
#[derive(Debug, thiserror::Error)]
pub enum TxRequestError {
    #[error("invalid address '{address}': {source}")]
    InvalidAddress {
        address: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("only one output can have max=true")]
    MultipleMaxOutputs,
    #[error("coin {0} not found in wallet")]
    CoinNotFound(bitcoin::OutPoint),
    #[error("coin {0} is not spendable")]
    CoinNotSpendable(bitcoin::OutPoint),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("builder error: {0}")]
    Builder(#[source] crate::transaction::Error),
}

impl From<crate::transaction::Error> for TxRequestError {
    /// A failed auto-selection (`CoinSelection`) means there weren't enough
    /// spendable coins, so it surfaces as `InsufficientFunds`; other errors
    /// are reported verbatim via `Builder`.
    fn from(err: crate::transaction::Error) -> Self {
        match err {
            crate::transaction::Error::CoinSelection => TxRequestError::InsufficientFunds,
            other => TxRequestError::Builder(other),
        }
    }
}
