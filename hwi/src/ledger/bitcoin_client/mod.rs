//! Fork of ledger_bitcoin_client (https://github.com/LedgerHQ/app-bitcoin-new, Apache-2.0) with
//! async removed.

mod command;
mod interpreter;
mod merkle;

pub mod apdu;
pub mod client;
pub mod error;
pub mod psbt;
pub mod wallet;
