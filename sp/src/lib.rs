// bwk-sp: Silent Payment Account Wrapper
//
// A modular Rust library for building Bitcoin wallets with Silent Payments.
// Experimental, not production-ready.

// Account uses the blindbit transport directly.
pub mod account;
pub mod blindbit;
pub mod core;
pub mod profile;
pub mod receiver;
pub mod scan;
mod thread_pool;

pub use bwk;

// Re-export external types for convenience
pub use bitcoin;
pub use bwk_sign;
pub use bwk_tx::{
    self, Fees, FinalizationContext, PsbtOutputInfo, RecipientProvider, SpPartialSecretProvider,
};
