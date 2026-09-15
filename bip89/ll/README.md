# bwk-bip89-ll

The C ABI of [`bwk-bip89`](../README.md). `VtableBackend` implements
`BitcoinBackend` over vtables of C function pointers, and every `bip89_*` entry
point runs the generic protocol code of `bwk-bip89` on it. The crate is no_std
with `alloc` and depends only on `bwk-bip89` without its default features, so it
never pulls rust-miniscript and builds for `thumbv7em-none-eabihf`:

```sh
cargo build -p bwk-bip89-ll --target thumbv7em-none-eabihf
```

The header [`include/bip89.h`](include/bip89.h) is kept in sync by hand with
`src/lib.rs`; [`tests/layout.rs`](tests/layout.rs) pins the size, alignment and
field offset of every struct, so a Rust-side change fails the tests until the
header follows.

## Vtables

Four vtables carry what `BitcoinBackend` needs. Each one maps onto a group of
trait methods:

```
+-------------------------+--------------------+-------------------------------+
| C vtable                | Rust adapter       | BitcoinBackend methods        |
+-------------------------+--------------------+-------------------------------+
| bip89_crypto_vtable     | VtableBackend      | hashing, curve, BIP322, plus  |
|                         |                    | fill_random for `Rng`         |
| bip89_descriptor_vtable | VtableDescriptor   | descriptor_*                  |
| bip89_template_vtable   | VtableTemplate     | template_*                    |
| bip89_psbt_vtable       | VtablePsbt         | PSBT getters and setters      |
+-------------------------+--------------------+-------------------------------+
```

`VtableBackend` sets `type Descriptor = VtableDescriptor`,
`type Template = VtableTemplate` and `type Psbt = VtablePsbt`.

- **Crypto.** SHA-256 and SHA-512 init/update/final over a library-owned state
  buffer, point and scalar arithmetic, `bip322_sign`, `bip322_verify` and
  `fill_random`. `point_add`, `point_mul` and `base_mul` return nonzero for the
  point at infinity.
  - `bip322_sign(ctx, secret, msg, out, cap, out_len)` writes the BIP322 simple
    signature of the 32-byte `msg` for the single-key taproot address (no script
    tree) of the public key of the 32-byte `secret`, as consensus-serialized
    witness bytes. It follows the callback buffer rule below; a nonzero return
    gives `BIP89_ERR_SECRET_KEY`.
  - `bip322_verify(ctx, key, msg, sig, sig_len)` returns 1 when `sig` is a valid
    BIP322 simple signature of `msg` for the single-key taproot address of the
    33-byte `key`. Any other value is an invalid signature.
- **Descriptor.** `policy_bytes`, `template_bytes` and `xpubs`, read once per
  entry point. The branch pointers of each `bip89_xpub` must stay valid
  until the entry point returns.
- **Template.** `bytes` and `base_keys` (strictly ascending, read once), then
  `script_pubkey` and `leaf_hashes` over `BIP89_TWEAKED_PAIR_LEN`-byte
  `base || tweaked` records sorted by base key.
- **PSBT.** `input_count`, `output_count`, `spent_output`, `output`,
  `input_bundle`/`set_input_bundle`, `output_bundle`/`set_output_bundle`,
  `output_proof`/`set_output_proof`, `tap_leaf_sighash` and `add_tap_script_sig`.

## PSBT callbacks

The PSBT callbacks are semantic: they get and set protocol values, never raw PSBT
fields, and how the values are stored in the PSBT is up to the consumer.

- The bundle and proof getters write a present flag: 1 when the field is set, 0
  when it is absent. An absent field is distinct from an empty one. Any
  other flag value is `BIP89_ERR_PSBT`.
- A bundle crosses as `ser(bundle)`, its canonical serialization of
  `BIP89_ENTRY_LEN` bytes per entry, and is decoded strictly on read.
- An accumulator proof crosses as exactly `BIP89_PROOF_LEN` (289) bytes, so its
  callbacks take no length.
- `spent_output` and `output` write the scriptPubKey through the buffer
  convention below and the value in satoshis.

## Buffers and retries

- **Callback buffers.** A callback writing variable-length data gets `out`, `cap`
  and `out_len`. It writes the full length to `*out_len`, writes the bytes only
  when they fit in `cap`, and returns 0 in both cases. When the data did not fit,
  the library calls again once with a buffer of exactly the reported length, and
  the second report must match. Array callbacks (`xpubs`, `base_keys`,
  `leaf_hashes`) follow the same rule with `cap` and `*out_count` counted in
  records.
- **Entry point buffers.** `bip89_derive_bundle`, `bip89_blind_challenge_gen` and
  `bip89_sign_tree_root` take `out_cap` (or `session_cap`, `signature_cap`) and a
  length out-parameter. When the buffer is too small they return
  `BIP89_ERR_BUFFER_TOO_SMALL` with the needed length written back; the output
  pointer may be null when the capacity is 0.
- **Hash state.** The buffer passed to `sha256_init` and `sha512_init` is
  `BIP89_HASH_STATE_LEN` (256) bytes, 8-byte aligned, owned by the library, and
  may move between calls. A callback stores only relocatable data in it, never a
  pointer into the buffer itself.

## Handles and ownership

Two opaque handles cross the boundary:

```
+--------------------+---------------------+-----------------------------------+
| Handle             | Returned by         | Released by                       |
+--------------------+---------------------+-----------------------------------+
| bip89_tree         | bip89_build_tree    | bip89_tree_free                   |
| bip89_registration | bip89_register      | bip89_registration_free           |
+--------------------+---------------------+-----------------------------------+
```

- A handle is written to `*out` on success only; freeing a null handle is a
  no-op.
- `bip89_coordinator_prepare` borrows its trees and clones them internally.
- A registration keeps a copy of the template vtable, so its `ctx` must stay
  valid until `bip89_registration_free`.
- Rust never frees caller memory, and the caller frees library memory only
  through the two release functions.

Blinded signing writes a session in `bip89_blind_challenge_gen`, laid out as
`pk (33) || blindfactor (32) || challenge (32) || pubnonce (33)`, then
`tweak (32) || is_xonly (1)` per tweak; `bip89_blind_sign` zeroes the caller
secret nonce.

## Signed roots

`bip89_sign_tree_root` builds the tree of the descriptor for a keychain and tree
start and signs its root with BIP322 under the branch key of the caller `secret`.
It writes the 32-byte root, the 33-byte base key of `secret`, its 32-byte branch
tweak, and the signature to `signature_out` with its length in `*signature_len`,
following the entry point buffer rule above. A secret that is not a key of the
descriptor gives `BIP89_ERR_NOT_PARTICIPANT`. A retry with a larger buffer
builds the tree and signs again.

A signed root crosses back as `bip89_signed_root`:

```
+---------------+----------------+---------------------------------------------+
| Field         | Type           | Content                                     |
+---------------+----------------+---------------------------------------------+
| keychain      | uint32_t       | 0 receive, 1 change                         |
| tree_start    | uint32_t       | First derivation index of the tree          |
| root          | uint8_t[32]    | Accumulator root                            |
| key           | uint8_t[33]    | Base key of the signer                      |
| branch_tweak  | uint8_t[32]    | Tweak from `key` to its branch key          |
| signature     | const uint8_t* | BIP322 signature, borrowed for the call     |
| signature_len | size_t         | Signature length; `signature` may be null   |
|               |                | when it is 0                                |
+---------------+----------------+---------------------------------------------+
```

- `bip89_register(crypto, tmpl, receive, change, out)` checks the `receive`
  (keychain 0) and `change` (keychain 1) signed roots and writes a registration
  handle. A key that is not a base key of the template gives
  `BIP89_ERR_NOT_PARTICIPANT`, a failing signature `BIP89_ERR_ROOT_SIGNATURE`,
  and a root on another keychain `BIP89_ERR_INVALID_KEYCHAIN`.
- `bip89_registration_record_root(crypto, registration, signed_root)` records
  the root of a keychain's next tree, checked the same way.

## Errors

Every entry point returns an `int32_t`. `BIP89_OK` is 0. The last parameter,
`const char **err` (nullable), receives a static NUL-terminated message, never
freed by the caller. The coordinator and spend entry points also take a nullable
`size_t *index_out` that receives the input or output index of an indexed error.

```
+------------+-----------------------------------------------------------------+
| Codes      | Meaning                                                         |
+------------+-----------------------------------------------------------------+
| 100 to 134 | Protocol errors, one to one with `bwk_bip89::Error`. Codes 120  |
|            | and 123 are retired and never reused. 129 is                    |
|            | `BIP89_ERR_MISSING_PROOF`, an owned output without a proof.     |
| 135 to 141 | Descriptor validation variants of `bwk_bip89::Error`:           |
|            | NotTaproot, KeyType, Multipath, Wildcard, HardenedStep,         |
|            | ConflictingKey, NoKeys.                                         |
| 500        | Null pointer.                                                   |
| 501        | Vtable with a null callback.                                    |
| 502        | Output buffer too small; the needed length is written back.     |
| 503        | Index out of bounds.                                            |
+------------+-----------------------------------------------------------------+
```

Every vtable callback must be non-null: a null callback fails with
`BIP89_ERR_BAD_VTABLE`. A nonzero return from a descriptor or template callback
gives `BIP89_ERR_TEMPLATE`; from a PSBT callback, `BIP89_ERR_PSBT`.
`VtableBackend` passes the xpubs the descriptor callback reports through
unvalidated, so no C entry point returns codes 135 to 141.

## Linking

`bwk-bip89-ll` stays a plain `rlib`: a `staticlib` needs a global allocator and a
panic handler, which a library cannot supply. [`bip89/cabi`](../cabi)
(`bwk-bip89-cabi`) is the hosted shim that provides both and re-exports
`bwk_bip89_ll::*`, producing `libbip89.a` and `libbip89.so`.

[`examples/consumer.c`](examples/consumer.c) computes a BIP89 tweak and a
delegator signature through the C ABI, with libsecp256k1 and libsodium behind the
crypto vtable. It signs no root, so its `bip322_sign` and `bip322_verify`
callbacks are stubs that always fail. Build and run it from the workspace root:

```sh
cargo build --release -p bwk-bip89-cabi
cc -Wall -Wextra -Werror -I bip89/ll/include bip89/ll/examples/consumer.c \
   target/release/libbip89.a -lsecp256k1 -lsodium -lpthread -ldl -lm -o target/consumer
./target/consumer
```

On a bare-metal target, keep the crate no_std and write a shim that provides
`#[global_allocator]` and `#[panic_handler]` itself and re-exports
`bwk_bip89_ll::*`.

## Tests

`tests/layout.rs` pins the struct layouts against the header.
`tests/ffi_roundtrip.rs` drives every entry point through `extern "C"` callbacks
backed by `RustBitcoin` and compares each result with the Rust API.

```sh
cargo test -p bwk-bip89-ll
```

## Building from source

This repository ships no prebuilt binaries. Build the libraries and the crypto
backend you plug in yourself, from reviewed sources, and verify them.
