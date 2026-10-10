//! BIP89 chain code delegation with the tweak accumulator. All protocol code
//! is generic over one `BitcoinBackend` trait and builds no_std with `alloc`;
//! the `rust-bitcoin` feature adds `RustBitcoin`, the backend on
//! rust-miniscript.

#![cfg_attr(not(feature = "rust-bitcoin"), no_std)]

extern crate alloc;

pub mod accumulator;
pub mod backend;
pub mod bip340;
pub mod blind;
pub mod bundle;
pub mod coordinator;
pub mod delegator;
mod error;
#[cfg(feature = "rust-bitcoin")]
pub mod rust_bitcoin;
pub mod scalar;
pub mod sign;
pub mod tweak;
pub mod verify;

pub use backend::{BitcoinBackend, Output, Rng, Sha256Engine, Sha512Engine, Xpub};
pub use bundle::{Bundle, Entry};
pub use error::Error;
