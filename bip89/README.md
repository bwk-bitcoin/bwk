# bwk-bip89

Rust implementation of BIP89 Chain Code Delegation and of the tweak accumulator
specified in [`bip-tweak-accumulator.md`](bip-tweak-accumulator.md), which lets a
delegator refuse owned outputs, receive or change, built from forged tweaks.
Taproot only.

All protocol code is generic over one trait, `BitcoinBackend`, and builds no_std
with `alloc`. The default `rust-bitcoin` feature adds `RustBitcoin`, a backend on
rust-miniscript and the `bip322` crate.

## Crates

```
+----------------+-------------------------------------------------------------+
| Crate          | Description                                                 |
+----------------+-------------------------------------------------------------+
| bwk-bip89      | `bip89`, the protocol generic over `BitcoinBackend`, and    |
|                | the `RustBitcoin` backend behind `rust-bitcoin`.            |
| bwk-bip89-ll   | `bip89/ll`, no_std C ABI: `VtableBackend` implements        |
|                | `BitcoinBackend` over C vtables.                            |
| bwk-bip89-cabi | `bip89/cabi`, `staticlib` and `cdylib` named `bip89`, not   |
|                | published.                                                  |
+----------------+-------------------------------------------------------------+
```

## Features

```
+--------------+---------+-----------------------------------------------------+
| Feature      | Default | Description                                         |
+--------------+---------+-----------------------------------------------------+
| rust-bitcoin | yes     | The `rust_bitcoin` module: `RustBitcoin` over       |
|              |         | rust-miniscript, its `bitcoin`/`secp256k1`          |
|              |         | re-exports and `bip322`. Without it the crate is    |
|              |         | no_std.                                             |
+--------------+---------+-----------------------------------------------------+
```

## The BitcoinBackend trait

`backend::BitcoinBackend` is everything the protocol takes from a bitcoin
library. Keys cross it as raw bytes: 33-byte compressed points, 32-byte big-endian
canonical scalars and 32-byte x-only keys. Its associated types:

```
+------------+-----------------------------------------------------------------+
| Type       | Role                                                            |
+------------+-----------------------------------------------------------------+
| Sha256     | Streaming `Sha256Engine`.                                       |
| Sha512     | Streaming `Sha512Engine`.                                       |
| Descriptor | The full wallet descriptor, held by the signing key holder and  |
|            | the coordinator: every key carries its chain code and fixed     |
|            | steps.                                                          |
| Template   | What the delegator holds: the descriptor reduced to its base    |
|            | keys.                                                           |
| Psbt       | The PSBT the coordinator prepares and the delegator signs.      |
+------------+-----------------------------------------------------------------+
```

Its methods, by group:

```
+-------------+----------------------------------------------------------------+
| Group       | Methods                                                        |
+-------------+----------------------------------------------------------------+
| Hashing     | sha256, sha512                                                 |
| Curve       | point_is_valid, point_add, point_mul, base_mul, scalar_add,    |
|             | scalar_mul                                                     |
| BIP322      | bip322_sign, bip322_verify                                     |
| Descriptor  | descriptor_policy, descriptor_template, descriptor_xpubs       |
| Template    | template_bytes, template_base_keys, template_script_pubkey,    |
|             | template_leaf_hashes                                           |
| PSBT getter | input_count, output_count, spent_output, output, input_bundle, |
|             | output_bundle, output_proof, tap_leaf_sighash                  |
| PSBT setter | set_input_bundle, set_output_bundle, set_output_proof,         |
|             | add_tap_script_sig                                             |
+-------------+----------------------------------------------------------------+
```

Curve inputs are valid points and canonical scalars; `None` means the point at
infinity. Secret scalar arithmetic goes through the backend, so a constant-time
backend keeps the whole crate constant time.

The BIP322 methods sign and verify a BIP322 simple signature of a 32-byte message
for the single-key taproot address (no script tree) of a key, the signature being
the consensus-serialized witness. They are how a key of the descriptor signs an
accumulator root and how the delegator checks it.

The PSBT methods get and set protocol values (`Output`, `Bundle`, `Proof`), not
PSBT fields. How a bundle or a proof is stored in the PSBT is the backend's
business: the protocol code never builds a PSBT key, so it does not depend on any
PSBT library. `RustBitcoin` stores them in the proprietary fields of the spec; a C
consumer stores them however its own PSBT code does.

Randomness is not part of the backend. `sign_spend`, `blind_nonce_gen` and
`blind_challenge_gen` take a caller `R: Rng` per call.
Nothing is bundled, and no OS randomness is assumed.

## RustBitcoin

`rust_bitcoin::RustBitcoin` implements the trait on rust-miniscript, rust-bitcoin's
`bitcoin_hashes`, libsecp256k1 and the `bip322` crate. The module re-exports
`miniscript`.

```
+------------+-----------------------------------------------------------------+
| Type       | RustBitcoin                                                     |
+------------+-----------------------------------------------------------------+
| Descriptor | `miniscript::Descriptor<DescriptorPublicKey>`                   |
| Template   | `miniscript::Descriptor<bitcoin::PublicKey>`                    |
| Psbt       | `bitcoin::Psbt`                                                 |
+------------+-----------------------------------------------------------------+
```

- **Descriptor.** Only `tr()` over multipath extended keys (`<a;b>/*`) with
  unhardened steps. `descriptor_xpubs` rejects any other shape with `NotTaproot`,
  `KeyType`, `Multipath`, `Wildcard`, `HardenedStep`, `ConflictingKey` or
  `NoKeys`.
- **Template.** The same `tr()` with every key reduced to its base key. The
  delegator gets it as the string `descriptor_template` returns, parsed as a
  `Descriptor<bitcoin::PublicKey>`.
- **BIP322.** `bip322_sign` and `bip322_verify` call `bip322::sign_simple` and
  `bip322::verify_simple` for `Address::p2tr` of the key with no script tree. The
  address network is fixed, since BIP322 only reads its script. Signing uses no
  auxiliary randomness, so a signature is deterministic.
- **PSBT.** Bundles and proofs use the spec's fields, identifier `PREFIX`
  (`BIPXXX`), subtype `SUBTYPE_TWEAK` (0x00, one field per bundle entry) and
  `SUBTYPE_PROOF` (0x01, 289 bytes), with strict lengths. The unsigned
  transaction is the truth: an index outside its inputs or outputs is `Psbt`.

## Implementing another backend

Implement `BitcoinBackend` on your own type and pick the associated types that fit
your bitcoin library; nothing requires rust-bitcoin. The protocol code relies on
this contract:

- `descriptor_xpubs` validates the descriptor shape and returns its keys sorted by
  key.
- `template_base_keys` returns the base keys sorted and deduplicated.
- `template_script_pubkey` and `template_leaf_hashes` receive `tweaked` as
  `(base, tweaked)` pairs sorted by base key.
- A PSBT getter returns `Ok(None)` when the field is absent, and an error when the
  stored value does not decode.
- `tap_leaf_sighash` is the BIP341 script path sighash over every spent output
  with the default sighash type.

`tests/common/mod.rs` has a small example: `VectorBackend` wraps `RustBitcoin`,
delegates hashing, curve and PSBT to it, and swaps in a `wsh(sortedmulti)`
template to run the BIP89 verification vectors.

## Roles

- **Signing key holder.** `accumulator::record::sign_tree_root(b, d, secret,
  keychain, tree_start)` builds the tree itself and signs its root with BIP322
  under the branch key of `secret` for `keychain`. The `RootRecord` it returns
  carries the keychain, tree start and root, with a `RootSignature` holding the
  base key, the branch tweak and the signature. A secret that is not a key of `d`
  is `NotParticipant`. `accumulator::record::tree_root(b, d, keychain,
  tree_start)` builds the same tree and returns its root with no signature.
- **Coordinator.** `accumulator::record::build_tree` builds the proof trees, and
  `coordinator::prepare(b, d, trees, inputs, outputs, psbt)` writes bundles, and
  for each owned output the proof from the first tree that covers it (`NoTree`
  otherwise), into the PSBT through the backend setters.
- **Delegator.** `delegator::register(b, template, receive, change)` checks the
  receive (keychain 0) and change (keychain 1) root records with
  `accumulator::record::verify_root` and records the template and both roots in a
  `Registration`. `Registration::record_root` records the root of a keychain's
  next tree the same way. Any base key of the template is accepted as signer:
  which keys a delegator requires is its policy with its users, left to the
  consumer. `delegator::verify_spend` checks each owned output's proof against
  any recorded root and returns the outflow including the fee;
  `delegator::sign_spend` verifies, then adds BIP340 script path signatures.

This verification flow applies to the non-blinded signing mode; blinded signing is
available in `blind`.

## Example

[`example/`](example/README.md) runs the roles end to end with `RustBitcoin`: a
`Wallet` that is delegatee, coordinator and root signing key holder at once, and a
`SigningServer` delegator with a spending limit. It registers, signs an honest spend,
refuses a spend above the limit and a forged change, and records the root of a next
tree.

```sh
cargo run -p bwk-bip89-example
```

## C bindings

`bwk-bip89-ll` is the C ABI over this crate: `VtableBackend` implements
`BitcoinBackend` over caller vtables. See [`ll/README.md`](ll/README.md),
[`ll/include/bip89.h`](ll/include/bip89.h) and
[`ll/examples/consumer.c`](ll/examples/consumer.c).

## no_std

Without its default feature the crate builds without `std` for embedded targets:

```sh
rustup target add thumbv7em-none-eabihf
cargo build -p bwk-bip89 --no-default-features --target thumbv7em-none-eabihf
```

## Tests and vectors

The tests in `tests/` build with the default features:

```sh
cargo test -p bwk-bip89
```

`test_vectors/bip89/` are the BIP89 vector files. `test_vectors/accumulator/` are
generated by the `#[ignore]` test `regenerate_vectors` in
`tests/accumulator_vectors.rs`, which rewrites them:

```sh
cargo test -p bwk-bip89 --test accumulator_vectors regenerate_vectors -- --ignored
```

They are never edited by hand: inspect `git diff bip89/test_vectors/` after
regenerating and commit only intentional changes.

## Out of scope

- Non-taproot descriptors and ECDSA.
- Other bundled backends.
- Key-path signing with a delegated internal key.
- The concurrently secure blinded variant.
- Bundled OS randomness.
- Writing or stripping PSBT key origin fields.

## Building from source

This repository ships no prebuilt binaries. Build the libraries and the crypto
backend you plug in yourself, from reviewed sources, and verify them.
