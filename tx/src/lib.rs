pub mod coin_selection;
pub mod descr_fingerprint;
pub mod error;
mod psbt_sp;
pub mod recipient;
pub mod template;
pub mod transaction;
pub mod tx_builder;

pub const DUST_AMOUNT: u64 = 5_000;
