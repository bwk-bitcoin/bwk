# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in
this repository.

## What this crate is

`bwk-bup` (lib `bwk_bup`, "Bitcoin user policy") is a member of the bwk workspace
that models Bitcoin spending policies on top of `rust-miniscript`. The miniscript
version is the workspace pin (12.2), with the `serde` and `compiler` features added by
this crate. It is descriptor-agnostic at the API surface but compiles **exclusively to
Taproot multipath descriptors** and round-trips back from them via
`Policy::from_descriptor`.

The model was extracted from `liana/`'s descriptor analysis so that `bwk-bup` stays
independent of the rest of the Liana stack. License is BSD 3-Clause; copyright held
by "The Liana developers".

The `musig` feature (off by default) enables the `musig` module and the MuSig2 shapes,
through `bwk-keys/musig` and `bwk-descriptor/musig`.

Descriptor keys are `bwk_descriptor::wallet::WalletKey` (descriptors are
`WalletDescriptor`): `DescriptorPublicKey` without `musig`, `bwk_keys::musig::MusigKey`
with it, every plain key then being `MusigKey::Plain`. Signer keys stay `OXpub`. A
plain descriptor parses, compiles and prints identically in both builds.
`multipath::plain_key` / `multipath::wallet_key` are the only conversions between the
two key types.

## Build / test

Run from the bwk workspace root.

- `cargo test -p bwk-bup` - full test suite (unit tests, all in
  `#[cfg(test)] mod tests` inside source files; there's no `tests/` directory)
- `cargo test -p bwk-bup --features musig` - same suite with the `musig` feature
- `cargo test -p bwk-bup <name>` - run a single test by substring (e.g.
  `cargo test -p bwk-bup sanitize_rejects_two_primaries`)
- `cargo clippy -p bwk-bup --all-targets -- -D warnings`
- `cargo fmt --all -- --check`

`Cargo.lock` is the workspace's.

## Architecture

The public model is **`Policy` → `Vec<Path>` → `(Semantic, Locktime, TapPosition)`**.
A `Policy` either is constructed from typed `Path`s (`Policy::new`) and then compiled
(`Policy::compile`) into a Tr multipath descriptor, or is parsed back from such a
descriptor (`Policy::from_descriptor`). Round-tripping is a load-bearing invariant.

### Module map (`src/`)

- **`lib.rs`** - re-exports the public surface. The crate's docs live in `policy.rs`
  / `path.rs`.
- **`path.rs`** - `Path`, `Semantic`, `Locktime`, `OXpub`, `TapPosition`, `Leaf`.
  Defines the per-spending-path data model and its structural validation
  (`validate()` methods). Also defines two grid constants: `CLTV_ALIGNMENT = 1024`
  (~1 week of blocks; renewable CLTV heights must be a non-zero multiple) and
  `MULTIPATH_SEMANTIC_FACTOR = 512` (each path role lives within a
  `[start, start + 512)` zone in the multipath index space).
- **`policy.rs`** - `Policy`, `PolicyType`, `PolicyError`. Holds `from_descriptor`
  (parser orchestration) and `compile` (compiler orchestration), plus `sanitize()` -
  the single source of truth for compile-readiness. `auto_promote_internal_key_maybe`
  lifts an eligible single-key, locktime-free path to the Tr internal key before
  compile; otherwise the deterministic NUMS unspendable key is used. Largest file
  (~1700 lines), and contains the bulk of the integration tests.
- **`compile.rs`** - helpers for `Policy::compile`. Converts `Semantic` / `Locktime`
  into `miniscript::policy::Concrete`, allocates fresh multipath derivation indices
  via a cursor, and handles m-of-n splitting (`split_m_of_n`).
- **`parse.rs`** - helpers for `Policy::from_descriptor`. Classifies a group of
  tap-tree leaves into a `Semantic` shape, infers `PolicyType`, computes per-path
  satisfaction weights.
- **`tree_builder.rs`** - generic tap-tree builder. `SubTree<T>` is created with a
  fixed slot layout (each slot has its absolute tap-tree depth pre-decided) and slots
  are mutated from `Free` → `Leaf` / `Link` as paths are placed and as padding fills
  the rest. DFS iteration is just a `Vec` walk.
- **`multipath.rs`** - reads the `<a;b>` group out of a Liana descriptor key, groups
  tap-tree leaves by their multipath index, and defines
  `NUMS_MARKER_MULTIPATH = [0x7FFF_FFFE, 0x7FFF_FFFF]` - the two largest unhardened
  indices, used as a marker on the NUMS internal key the compiler emits so the parser
  can recognise it cheaply (without recomputing the chain-code hash). The legacy
  chain-code recompute path still works in parallel. Exposes two public helpers:
  `get_multipath_index` (strict - single index, parser-internal contract: even start,
  consecutive `<a; a+1>`) and `key_indices` (returns every index a `MultiXPub` or
  `XPub` key claims, used by the compile-side collision check; enforces single-step,
  unhardened, and `<a; a+1>` consecutive shape but permits any starting parity).
  Under `musig` both also read a musig() aggregate: its BIP-328 synthetic xpub and the
  indices of the musig() derivation.
- **`nums.rs`** - the BIP-341 NUMS ("Nothing Up My Sleeve") public key and
  `unspendable_internal_key` (the deterministic NUMS xpub derivation used as Tr
  internal key when no path qualifies for key-path spending). Pulled out of liana's
  `descriptors::analysis` so this crate stays independent.
- **`key_role.rs`** - `KeyType` key role carried in R, the last origin step of a
  BIP-87 key `[fp/87'/coin'/account'/R]xpub`, `R = (index << 4) | role` (low 4 bits
  the role, 4 to 15 reserved). `Bip87Account` holds an account xpub fetched once and
  derives the role keys (`role_key`); `key_type` / `key_type_of` read the role back
  from an origin. `Path::key_types` and `Policy::key_types` list every signer key with
  its role. A role is descriptive, it never constrains which path a key sits on.
- **`musig.rs`** (`musig` only) - MuSig2 helpers the compiler and the reader call:
  `musig_key` / `musig_leaf` build `musig(keys)/<a;a+1>/*`, `musig_participants`
  reads the keys and zone index back.

### Conceptual invariants

These are enforced by `Policy::sanitize` / `validate_paths_for_type` and should be
respected when adding new path shapes or policy types:

- A `Policy` mixes **only one locktime flavor**: relative (`older`),
  aligned-renewable absolute (`after`, multiple of `CLTV_ALIGNMENT`), or
  foreign-unaligned absolute. Mixing flavors is `PolicyError::MixedTimelockKinds`.
- The Tr internal key path is **always** `Locktime::None` and `Semantic::Single`, or
  with `musig` an n-of-n `Semantic::Multi` (`musig(all)/<a;a+1>/*`). If no such path
  exists, the internal key falls back to the deterministic NUMS unspendable.
- With `musig`, a policy compiles to at most `MAX_LEAVES = 32` tap leaves, padding and
  the internal key path excluded (`Policy::leaf_count`), else
  `PolicyError::TooManyLeaves`.
- `MultiMandatory.threshold` must be in
  `[mandatory_count + 1, mandatory_count + cosigner_count]` - every leaf requires all
  mandatory keys plus at least one cosigner.
- `MultiMandatoryNested` thresholds must each be a proper subset selector
  (`1 <= threshold < key_count`) on both sides. Per-class frequencies
  (`mandatory_threshold * cosigner_count` vs `threshold * mandatory_count`) must
  differ - equal frequencies collapse the partition into something the parser can't
  recover. Canonical form requires the mandatory class to be the lower-frequency one
  (`mt * n < t * m`); swap the two key sets to canonicalise.
- `AbsoluteRenewable` heights must be on the block-height side of
  `LOCK_TIME_THRESHOLD` and aligned to `CLTV_ALIGNMENT`. "Renewable" means the
  descriptor can be re-issued at a later aligned height while remaining
  brute-forceable from the seed.
- `OXpub` rejects three sentinel/placeholder shapes: BIP-341 NUMS pubkey, zeroed
  x-coordinate, zeroed chain code. Real signer keys must pass `OXpub::validate`.
- **No `(xpub, multipath-index)` pair may be claimed by two distinct paths.**
  Enforced at compile time by `check_multipath_uniqueness` (run inside
  `Policy::compile` immediately after `assign_start_indices`) and raised as
  `PolicyError::DuplicateMultipathIndex { xpub, index }`. Catches `Custom`-vs-typed
  and `Custom`-vs-`Custom` overlaps at the individual-index level - so `<3;4>`
  collides with `<4;5>` on index `4`. The same error variant catches the degenerate
  within-key case `<n;n>` (two legs collapse onto one derivation). Non-consecutive
  multipath legs like `<3;5>` are rejected earlier by `key_indices` with
  `MultipathError::NonConsecutive`.

### Multipath index layout

`Semantic::starting_index(&Locktime)` assigns each (semantic, locktime) pair a base
multipath index:

```
+----------------------------------------+------------+
| Locktime / Semantic                    | base index |
+----------------------------------------+------------+
| None + Single/Multi                    | 512 * 1    |
| Relative + Single/Multi                | 512 * 2    |
| Relative + MultiMandatory              | 512 * 3    |
| AbsoluteRenewable + Single/Multi       | 512 * 4    |
| Absolute + Single/Multi                | 512 * 5    |
| None + Custom                          | 512 * 6    |
| AbsoluteRenewable + MultiMandatory     | 512 * 7    |
| Absolute + MultiMandatory              | 512 * 8    |
| Relative + MultiMandatoryNested        | 512 * 9    |
+----------------------------------------+------------+
```

The NUMS internal key is tagged with `[0x7FFF_FFFE, 0x7FFF_FFFF]`
(`NUMS_MARKER_MULTIPATH`).

### MuSig2 compile (`musig`)

Under `musig` the compiler never emits `thresh` / `multi_a`: every multisig is a set
of `pk(musig(S)/<a;a+1>/*)` leaves, aggregate then derive (each participant is the
signer's xpub with its origin and no derivation, the zone index sits on the musig()
expression). `compile::leaf_policy` is the one switch point, fed key sets per shape:

- `Multi { keys, threshold: m }`, `1 < m < n`: one leaf per m-subset, in
  `split_m_of_n` lexicographic order, so C(n,m) leaves.
- `Multi` with m == n: one `pk(musig(all))` leaf, or the internal key when it is the
  primary path.
- `Multi` with m == 1: one plain `pk(K/<a;a+1>/*)` leaf per key (a musig() of one
  participant is never emitted).
- `MultiMandatory`: one leaf per cosigner subset, `pk(musig(mandatory then subset))`.
- `MultiMandatoryNested`: one leaf per `(mandatory subset, cosigner subset)` pair.
- `Single` and `Custom`: unchanged. Locktimes wrap each leaf as without `musig`.

Participants keep the path's key order. The cursor walks `+2` per leaf and `+2` per
path boundary, so `Path::leaf_count` of a `Multi` is C(n,m). The NUMS chain code and
the `(xpub, index)` uniqueness check see a musig() key through its BIP-328 synthetic
xpub (`nums::chain_code_xkey`, `multipath::key_indices`).

Tests that assert a layout only the plain build produces are
`#[cfg(not(feature = "musig"))]`. Tests that read a compiled `Multi`,
`MultiMandatory` or `MultiMandatoryNested` back through `Policy::from_descriptor` are
`#[cfg_attr(feature = "musig", ignore = "reader does not lift musig leaves yet")]`
until the reader learns the musig leaves. `test_keys::test_key` gives deterministic
signer keys to the musig tests. `test_vectors/musig_examples.txt` holds example
descriptors for device checks, regenerated by the ignored `write_musig_examples` test
and guarded by `musig_examples_file_is_current`.

### `PolicyType` variants

Inferred by `parse::infer_policy_type`; declared up-front for `Policy::new`:

- `Csv` - relative timelock recovery (legacy Liana shape).
- `Cltv` - absolute (height-based) timelock recovery, aligned to `CLTV_ALIGNMENT`.
- `CsvWithMandatoryKey` - `Csv` plus at least one `MultiMandatory` path.
- `CsvWithNestedMandatory` - `Csv` plus at least one `MultiMandatoryNested` path.
  Mixing `MultiMandatory` and `MultiMandatoryNested` in the same policy is `Unknown`
  (distinct typed homes).
- `Unknown` - descriptor / path set the typed classifier can't fold into the variants
  above. `PolicyType::Unknown` is constructable via `Policy::new` and skips
  policy-level invariants (primary count, recovery presence, mixing). It does NOT
  accept `Semantic::Unknown` paths - those are parser-only. Consumers who need an
  arbitrary tap-leaf script use
  `Semantic::Custom(Miniscript<WalletKey, Tap>)`, which the compiler emits
  verbatim - multipath indices on the consumer's keys are the consumer's
  responsibility. `Custom` paths require `Locktime::None`; encode any locktime gate
  inside the embedded miniscript.
- `Invalid` - parser-only verdict; not constructable via `Policy::new`. Returned by
  `infer_policy_type` for path sets that can never be a valid policy (no recovery,
  mixed locktime flavors).

## Conventions when modifying this crate

- `Policy::sanitize` is non-mutating and is the canonical compile-readiness check.
  New invariants belong here, not duplicated inside `compile`. `compile` calls
  `sanitize` first and then trusts every invariant established by it.
- `auto_promote_internal_key_maybe` runs **before** `sanitize` inside `compile`, but
  `sanitize` itself stays non-mutating - don't introduce side-effecting validation.
- Round-trip is a hard guarantee for typed `Policy`s and for `Semantic::Custom`: any
  compiler change must keep `Policy::from_descriptor(policy.compile()?)` semantically
  equal to the input for those shapes. The test suite in `policy.rs` exercises this
  aggressively. The exception is `Semantic::Unknown` paths produced by the parser
  when classification fails - those are deliberately uncompilable
  (`PolicyError::UnknownNotConstructable` / `InconsistentPathsForType(Unknown)`).
  Consumers who need to reissue a descriptor that originally classified as `Unknown`
  must rebuild it themselves using `Semantic::Custom` with the raw miniscript.
- NUMS detection has two paths (marker check + legacy chain-code recompute) on
  purpose - keep both working so descriptors emitted by older code still parse.
- The crate intentionally has no dev-dependencies and no `tests/` integration suite;
  tests live next to the code they cover.
