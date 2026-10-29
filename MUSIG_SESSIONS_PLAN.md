# Persisted hot MuSig sessions

- Add an opaque, non-cloneable session value with a fresh random root, caller ID,
  canonical policy hash, owner fingerprint, and one to eight absolute input slots.
  Export consumes the value into wipe-on-drop bytes; decode consumes those bytes
  and validates the fixed binary format and expected owner and descriptor.
- Share descriptor expression occurrence indexes in the existing slot resolver.
  Count the internal key first, then every key in DFS leaf order, including plain
  and foreign expressions. Expose all-expression derivation for prefetch and the
  selected PSBT slot metadata for both hot and hardware consumers.
- Derive nonce randomness from the root, input position, and expression index.
  BIP-327 NonceGen receives the participant public key but no secret key,
  aggregate key, or message. This permits publication without an unlocked signer
  and supports arbitrary public derivation indexes within the bound policy.
- Create checks the ordinary signer's two-path wildcard descriptor support and
  actual signer ownership across all descriptor paths. Restored unsupported
  policies fail consuming signing without panicking. Publish
  resolves the real PSBT with the shared resolver. Consuming signing verifies
  ownership, regenerates and checks published nonces, and reuses the existing
  partial-signature and guarded ordinary-signing paths. Commit PSBT changes only
  after success. The application burns durable state before signing and owns
  atomic replacement and allocation invalidation.
- Test key and script paths, all expressions, one/two/eight inputs, reopening,
  same-ID fresh roots, wrong owners and policies, malformed encodings, coverage,
  nonce mismatch, signing failures, and existing transaction-bound signing.
  Run focused bwk-sign and bwk-musig tests, formatting, and targeted clippy.
- Preserve existing slot eligibility: partial leaf data does not disable an
  internal aggregate whose 0x1a is present. Use distinct role keys in selected
  leaf tests and separately verify stable indexes for shared aggregate occurrences.
