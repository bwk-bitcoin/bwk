//! C ABI shim: builds the `bwk-bip89-ll` C binding as a `staticlib` and a `cdylib`.
//! `bwk-bip89-ll` stays an rlib that cannot supply a global allocator or a panic handler;
//! on hosted targets `std` supplies both here, a bare-metal consumer supplies its own.
//! Re-exporting the `extern "C"` entry points keeps their symbols in the libraries.

pub use bwk_bip89_ll::*;
