# bwk-musig

**Experimental. Do not use in production or with real coins. API will break.**

MuSig2 (BIP-327) key aggregation, nonce generation and aggregation, partial
signatures and their aggregation, written once over the `MusigBackend` trait so
the protocol code does not depend on a given secp256k1 library.

The default `rust-bitcoin` feature adds `RustBitcoin`, the backend on
rust-secp256k1 0.33 and its musig module. Without it the crate is `no_std` and
only needs `alloc`: bring your own backend.
