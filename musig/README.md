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
- The two signing rounds:
  1. each signer calls `nonce_gen` and sends its 66-byte public nonce;
  2. anyone aggregates them with `nonce_agg`;
  3. each signer calls `partial_sign` with its secret nonce and the aggregate nonce;
  4. `partial_verify` checks a share against its signer's key and public nonce;
  5. `partial_agg` sums one share per participant into the BIP-340 signature. It
     is not verified: check it against `KeyAgg::output_key`.

Nonce rules:

- `nonce_gen` draws fresh randomness from the caller's `Rng` on every call: it must
  be a cryptographically secure RNG, and each signing session needs its own call.
- Bind the message (the sighash) with `msg` when it is known.
- A `SecNonce` is not `Clone` and has no serialization: `partial_sign` consumes it,
  also on error, so it signs once. Never store it.
- `partial_sign` rejects a nonce of a signer that is not a participant
  (`NotParticipant`), of another key (`NonceKeyMismatch`), and an already used or
  out-of-range one (`InvalidSecNonce`), with an error instead of libsecp's abort.
- A `SecNonce` dropped without signing (or refused with `NotParticipant`) is not
  wiped: the upstream type has no `Drop`. It never leaves memory, but sign promptly.
- `nonce_gen_with_rand` supports vectors and root-backed sessions such as
  bwk-sign's hot cache API. Regenerate only for one signing call per session;
  reusing nonces across signing calls leaks the secret key.
- Never `Debug` the backend's nonce (`RustBitcoin::nonce_gen` output): the upstream
  type prints its secret bytes.

DeterministicSign is not provided.

Byte formats: points are 33-byte compressed encodings, scalars and partial
signatures 32-byte big-endian, public nonces 66 bytes, signatures 64-byte BIP-340.

Tests run the BIP-327 KeySort, KeyAgg, tweak, NonceGen, NonceAgg, sign/verify and
signature aggregation vectors and the BIP-328 vectors (`test_vectors/`), cross-check
the BIP-32 and BIP-341 tweaks against rust-bitcoin on the BIP-373 test aggregate,
and verify full signing rounds with rust-bitcoin. Vectors libsecp cannot express
are skipped:

- NonceGen cases 0 to 2: libsecp hashes the aggregate key of a KeyAgg cache, not a
  raw `aggpk` value, and takes 32-byte messages only (case 1 is empty, case 2 is 38
  bytes).
- Sign cases with the empty and the 38-byte message, for the same reason.
- The sign error case of a signer outside the key list runs through `partial_sign`
  rather than the backend, which has no key list.
