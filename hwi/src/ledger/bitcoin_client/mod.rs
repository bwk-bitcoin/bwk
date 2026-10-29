//! Fork of ledger_bitcoin_client (https://github.com/LedgerHQ/app-bitcoin-new, Apache-2.0) with
//! async removed.

// Vendored from upstream ledger_bitcoin_client; keep clippy stance aligned
// with the upstream crate rather than the bwk workspace.
#![allow(clippy::uninlined_format_args, clippy::while_let_loop)]

mod bip327;
mod command;
mod interpreter;
mod merkle;

pub mod apdu;
pub mod client;
pub mod error;
pub mod protocol;
pub mod psbt;
pub mod wallet;
