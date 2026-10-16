# bwk-musig

**Experimental. Do not use in production or with real coins. API will break.**

MuSig2 (BIP-327) written once over the `MusigBackend` trait, so the protocol code
does not depend on a given secp256k1 library. The default `rust-bitcoin` feature
adds `RustBitcoin`, the backend on rust-secp256k1 0.33 and its musig module (no
context object, it runs on the library's internal one). Without it the crate is
`no_std` and only needs `alloc`: bring your own backend.

Covered:

- KeySort (`key_sort`, a lexicographic sort of the encodings) and KeyAgg
  (`KeyAgg::new` in the given order, `KeyAgg::sorted` for KeySort then KeyAgg, as
  BIP-390 `musig()` requires).
- Plain and x-only tweaks on the aggregate (`KeyAgg::apply_tweak`,
  `KeyAgg::with_tweaks`): a failed tweak leaves the `KeyAgg` unchanged.
- The BIP-328 synthetic xpub of an aggregate (`synthetic_xpub`,
  `BIP328_CHAIN_CODE`).

Nonce generation and aggregation, partial signatures and their aggregation land
next. DeterministicSign is not provided.

Byte formats: points are 33-byte compressed encodings, scalars and partial
signatures 32-byte big-endian, public nonces 66 bytes, signatures 64-byte BIP-340.

Tests run the BIP-327 KeySort, KeyAgg and tweak vectors and the BIP-328 vectors
(`test_vectors/`), and cross-check the BIP-32 and BIP-341 tweaks against
rust-bitcoin on the BIP-373 test aggregate.
