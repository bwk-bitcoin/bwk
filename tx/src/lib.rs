pub mod coin_selection;
pub mod descr_fingerprint;
pub mod error;
pub mod recipient;
pub mod template;
pub mod transaction;
pub mod tx_builder;

pub use bwk_psbt;

pub const DUST_AMOUNT: u64 = 5_000;
