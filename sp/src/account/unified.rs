//! Unified views of coins and spendable totals across the SP account and its
//! BIP32 sub-accounts.
//!
//! The SP [`Account`](crate::account::Account) embeds zero or more scanner
//! sub-accounts (segwit, taproot, ...). These helpers fold all
//! of them into one structure keyed by outpoint so callers (including FFI
//! bindings) do not have to stitch them together themselves.

use bitcoin::{Amount, OutPoint};
use bwk::bwk_electrum::notification::CoinOrigin;

/// A coin from anywhere in the composite SP
/// [`Account`](crate::account::Account).
///
/// Spent / being-spent coins are included; filter by [`UnifiedCoin::spendable`]
/// to keep only live UTXOs.
#[derive(Debug, Clone)]
pub struct UnifiedCoin {
    /// Where the coin came from.
    pub origin: CoinOrigin,
    /// The coin's outpoint.
    pub outpoint: OutPoint,
    /// The coin's value.
    pub amount: Amount,
    /// The block height at which the coin was confirmed; `None` if unconfirmed.
    pub height: Option<u32>,
    /// True if the coin is currently spendable (not spent and not in-flight).
    pub spendable: bool,
    /// Optional user-supplied label, looked up via the SP account's label store.
    pub label: Option<String>,
}

/// Aggregated spendable totals across the SP account and every sub-account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpendableSummary {
    /// Number of confirmed spendable coins.
    pub confirmed_count: u64,
    /// Total value of confirmed spendable coins.
    pub confirmed_balance: Amount,
    /// Number of unconfirmed (mempool) spendable coins.
    pub unconfirmed_count: u64,
    /// Total value of unconfirmed (mempool) spendable coins.
    pub unconfirmed_balance: Amount,
}
