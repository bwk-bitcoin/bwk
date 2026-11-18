//! MuSig2 (BIP-327) over one `MusigBackend` trait, no_std with `alloc`; the
//! `rust-bitcoin` feature adds `RustBitcoin`, the backend on rust-secp256k1 0.33.

#![cfg_attr(not(feature = "rust-bitcoin"), no_std)]

extern crate alloc;

pub mod backend;
mod error;
pub mod keyagg;
pub mod nonce;
#[cfg(feature = "rust-bitcoin")]
pub mod rust_bitcoin;
pub mod sign;

pub use backend::{MusigBackend, Rng};
pub use error::Error;
pub use keyagg::{key_sort, synthetic_xpub, KeyAgg, SyntheticXpub, Tweak, BIP328_CHAIN_CODE};
pub use nonce::{nonce_agg, nonce_gen, nonce_gen_with_rand, SecNonce};
pub use sign::{partial_agg, partial_sign, partial_verify};

pub const PUBKEY_LEN: usize = 33;
pub const SCALAR_LEN: usize = 32;
pub const PUB_NONCE_LEN: usize = 66;
pub const PARTIAL_SIG_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
