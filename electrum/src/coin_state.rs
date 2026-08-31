//! The aggregate view of what the scanner has found.

use std::collections::BTreeMap;

use bwk_coin::Coin;
use miniscript::bitcoin::OutPoint;

#[derive(Debug, Clone, PartialEq, Eq)]
/// `confirmed_*` includes `ConfirmedUnverified` coins: confirmed on-chain,
/// SPV proof still pending.
pub struct CoinState {
    pub coins: BTreeMap<OutPoint, Coin>,
    pub confirmed_coins: usize,
    pub confirmed_balance: u64,
    pub unconfirmed_coins: usize,
    pub unconfirmed_balance: u64,
}
