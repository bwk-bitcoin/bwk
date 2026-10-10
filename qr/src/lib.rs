//! QR generation, scanning, and signing-flow message transport.
//!
//! The crate keeps QR primitives internal. Callers use [`encoder::Encoder`] and
//! [`decoder::Decoder`] for plain text QR codes or, with the `protocol` feature, the
//! signing-flow messages in [`protocol`].

pub mod config;
pub mod error;
pub mod image;

#[cfg(feature = "scan")]
pub mod decoder;
#[cfg(feature = "gen")]
pub mod encoder;
#[cfg(feature = "gen")]
mod gen;
#[cfg(feature = "scan")]
mod scan;

#[cfg(feature = "protocol")]
pub use bwk_qr_protocol as protocol;
