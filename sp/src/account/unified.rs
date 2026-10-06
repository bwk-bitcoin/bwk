//! Unified views of coins and spendable totals across the SP account and its
//! BIP32 sub-accounts.
//!
//! The SP [`Account`](crate::account::Account) embeds zero or more scanner
//! sub-accounts (segwit, taproot, ...). These helpers fold all
//! of them into one structure keyed by outpoint so callers (including FFI
//! bindings) do not have to stitch them together themselves.

use bitcoin::{Amount, OutPoint};
use miniscript::{Descriptor, MiniscriptKey};

/// The script type of a BIP32 sub-account, read from its descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountKind {
    /// A `wpkh(..)` descriptor.
    Segwit,
    /// A `tr(..)` descriptor.
    Taproot,
    /// Any other descriptor.
    Other,
}

impl<Pk: MiniscriptKey> From<&Descriptor<Pk>> for SubAccountKind {
    fn from(descriptor: &Descriptor<Pk>) -> Self {
        match descriptor {
            Descriptor::Wpkh(_) => Self::Segwit,
            Descriptor::Tr(_) => Self::Taproot,
            _ => Self::Other,
        }
    }
}

/// Where a coin lives inside a composite SP
/// [`Account`](crate::account::Account).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinOrigin {
    /// The Silent Payments main account.
    Sp,
    /// An embedded BIP32 sub-account.
    SubAccount {
        /// Its position in
        /// [`Account::scanners`](crate::account::Account::scanners).
        index: usize,
        kind: SubAccountKind,
    },
}

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use miniscript::{Descriptor, DescriptorPublicKey};

    use crate::account::unified::SubAccountKind;

    const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn kind_of(descriptor: &str) -> SubAccountKind {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor).unwrap();
        SubAccountKind::from(&descriptor)
    }

    #[test]
    fn sub_account_kind_from_descriptor() {
        assert_eq!(kind_of(&format!("wpkh({KEY})")), SubAccountKind::Segwit);
        assert_eq!(kind_of(&format!("tr({KEY})")), SubAccountKind::Taproot);
        assert_eq!(kind_of(&format!("pkh({KEY})")), SubAccountKind::Other);
        assert_eq!(kind_of(&format!("sh(wpkh({KEY}))")), SubAccountKind::Other);
    }
}
