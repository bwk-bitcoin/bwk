# bwk-descriptor

**Experimental. Do not use in production or with real coins. API will break.**

Descriptor construction and SPK derivation utilities.

Wraps miniscript descriptors to provide convenient address/scriptPubKey
derivation for standard wallet patterns. Handles multipath descriptors
(recv/change) and validates descriptor structure on construction.

**Scope:** Descriptor building (wpkh/tr), the `Descriptor` enum covering both
miniscript and BIP392 `sp()` descriptors, SpkDerivator for address derivation,
BIP84/BIP86 path helpers. Does NOT handle raw key operations (use bwk-keys)
or full miniscript policy (use miniscript directly).

## Usage

```rust
use bwk_descriptor::{
    derivator::SpkDerivator,
    descriptor::{tr, wpkh},
};
use bwk_keys::keys::OXpub;
use miniscript::bitcoin::Network;

// Build descriptor from xpub
let descriptor = wpkh(xpub);  // wpkh([fg/84'/1'/0']xpub.../<0;1>/*)

// Create derivator
let derivator = SpkDerivator::new(descriptor, Network::Regtest).unwrap();

// Or use convenience constructors
let derivator = SpkDerivator::new_wpkh(xpub, Network::Regtest).unwrap();
let derivator = SpkDerivator::new_tr(xpub, Network::Regtest).unwrap();

// Derive addresses
let recv_addr = derivator.receive_at(0);
let change_addr = derivator.change_at(0);

// Get scriptPubKeys
let recv_spk = derivator.receive_spk_at(0);
let change_spk = derivator.change_spk_at(0);
```

## SpkDerivator

Derives receive/change scriptPubKeys from a multipath descriptor:

```
wpkh([fg/84'/1'/0']xpub.../<0;1>/*)
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
    recv descriptor                 change descriptor
    (path 0)                        (path 1)
```

Validates on construction:
- All keys must be `DescriptorPublicKey::MultiXPub`
- Multipath must have exactly 2 elements (recv/change)
- Paths must be unhardened with unhardened wildcard
- Network must match xpub network

## Descriptor Helpers

- `wpkh(xpub)`: Build P2WPKH descriptor with `<0;1>/*` multipath
- `tr(xpub)`: Build P2TR key-path descriptor with `<0;1>/*` multipath
- `wpkh_path(network, account)`: Returns BIP84 derivation path
- `tr_path(network, account)`: Returns BIP86 derivation path

## Descriptor

`descriptor::Descriptor` is the descriptor bwk passes around: either a
`Miniscript` one or an `Sp` one. It parses from a string (anything starting
with `sp(` goes to `SpDescriptor`, everything else to miniscript), prints back
with or without a checksum, and answers `as_miniscript`, `as_sp`, `is_sp`,
`into_miniscript` and `fingerprint`.

The name is deliberately the same as `miniscript::Descriptor`. The convention
across the workspace is to import this one as `Descriptor`. The wallet descriptor
is `wallet::WalletDescriptor`; the raw miniscript one stays
`miniscript::Descriptor<DescriptorPublicKey>`.

## Wallet Key

`wallet::WalletKey` is the key type every wallet descriptor uses:
`DescriptorPublicKey`, or `bwk_keys::musig::MusigKey` under the `musig` feature
(a plain key is then `MusigKey::Plain`). `WalletDescriptor` and
`WalletDefiniteDescriptor` are the matching miniscript descriptors, and
`to_wallet` converts a plain `miniscript::Descriptor<DescriptorPublicKey>` into
one. The `WalletDescriptorExt` (`single_paths`, `derive_at`, `plain_keys`,
`has_musig`) and `WalletKeyExt` traits stand in for the calls miniscript only
offers for `DescriptorPublicKey`. `updater::update_input` and
`updater::update_output` fill PSBT inputs and outputs from a derived wallet
descriptor.

## MuSig2 Descriptors

Under the `musig` feature, `musig` parses and prints BIP-390 `musig()` key
expressions. miniscript cannot split `musig(K1,...,Kn)`, so before parsing bwk
rewrites each one into the token `musig|K1|...|Kn|` (`to_token_form`), and
`MusigKey` prints and parses that token form, which is what
`miniscript::Descriptor<MusigKey>` round-trips through. The standard BIP-390
text, with a checksum computed over it, comes out of `Descriptor` (`Display`,
serde) and `musig_descriptor_to_string`; `parse_musig_descriptor` reads it back
and verifies the checksum. `musig()` is only accepted inside `tr()`, anything
else is `Error::MusigOutsideTr`. `musig_tr` builds the key path descriptor
`tr(musig(...)/<0;1>/*)` from cosigner xpubs. A descriptor without `musig()`
prints exactly as without the feature.

## PSBT Updater

`updater::update_input` and `updater::update_output` run miniscript's PSBT
updater on the derived descriptor; without the `musig` feature that is all they
do. Under `musig`, each musig() key first goes to miniscript as the derived
aggregate with its BIP-328 synthetic origin (`to_plain_definite`), then for each
musig() key of the `tr()` the updater writes the BIP-373 participant field
(`0x1a` on an input, `0x08` on an output), keyed by the untweaked KeyAgg output,
with the participants in KeySort order. Every cosigner also gets a
`tap_key_origins` entry with its own origin and the hashes of every leaf its
aggregate sits in (none for the internal key), sorted and deduplicated, as
Bitcoin Core's updater does. Running it twice gives the same result.

## Spending metadata

`spend::spend_variants(descriptor, keychain, index)` returns the original wallet
descriptor and every supported satisfaction alternative. `Account::spend_variants`
under `musig` resolves the derivation for one owned coin. The descriptor-level API
also works without `musig`, including BIP32 subaccounts of an SP wallet.

Each `SpendVariant` carries:

- A `PathId`: SHA256 of the underived descriptor's standard text without checksum,
  key path/DFS leaf position/script, and alternative index. It is independent of
  coin derivation, chain state and device availability. Persist the complete ID
  with the policy, not a derived tapleaf hash. `Display` is a fallback path label.
- Required `WalletKey` expressions, preserving origins and MuSig participants,
  and typed hash-preimage requirements. Every listed key is required; each
  threshold subset is a separate alternative. No signer roster is consulted.
- `Locks` using Bitcoin's absolute height/time and relative block/time enums.
  Relative time values are in 512-second intervals, not seconds.
- A conservative satisfaction bound in weight units, not vbytes or a minimum.
  It covers the maximum satisfaction of the selected leaf/script, including
  scriptSig, witness script, control block and witness count framing, without an
  annex. It excludes the base input, transaction marker/flag and outputs. Add it
  to the weight of an empty input and budget transaction overhead separately.
  For non-witness scripts the extra witness count WU is harmless overestimation.

`Locks::maturity` checks timelocks for the block following an explicit
`ChainContext`. Supply a coherent tip hash/height/MTP and coin confirmation from
that chain. CSV time uses the MTP of the block before confirmation. CLTV time
uses tip MTP, never wall-clock time. Missing data returns `Unknown`; a known
unmet constraint returns `Immature`. `Mature` is only timelock eligibility, not
coinbase maturity, unspent status or signer readiness. Recompute on every chain
change, including reorgs; never reuse confirmation data from another tip.

`Locks::apply` sets the minimum transaction version, locktime and input sequence
before signing. `validate_transaction` checks an assembled transaction. CLTV
height/time conflicts are errors; CSV block/time choices on different inputs
are independent. `Locks::merge` combines requirements for the same input only.

Under `musig`, `restrict_variant` reuses the input restriction helpers, checks
the selected ID and prevout script, applies its locks, and preserves unrelated
inputs and global metadata. Errors leave the PSBT unchanged. Selection must
precede signatures and MuSig nonces. A PSBT leaf restriction cannot force one
satisfaction within that leaf (or exclude a known internal-key spender on a
single-leaf tree). Keep the selected ID with the request, provide the specified
signers/preimages, and validate the finalized spend against that selection.

For PSBTv2 construction, use `Coin::to_psbt_input()` and the existing
`SpInputUpdater` for the input metadata. Keep the prevout, scripts, origins,
BIP373 participant fields and required proprietary fields intact. Carry the
original descriptor separately for hardware registration. Assemble inputs and
outputs into `bwk_psbt::PsbtV2`, with each input's selected absolute requirement
in its required height/time field and CSV in its sequence. Merge global maps
with conflict detection; do not combine complete account transactions blindly.
The v0/v2 bridge preserves populated input and global maps, but callers must
retain alternative selection IDs separately.

Reusable templates must not contain signatures, nonces, attempt IDs, private
keys or transaction-dependent SP shares/proofs. This API does not implement SP
multi-owner contributions, SP foreign-input bookkeeping, a coordinator, or a
transaction builder. Unsupported backend combinations must still be reported
explicitly by the consumer. Existing `SpendLeaf` and restriction APIs remain
available; use this export rather than their height-only summary for templates.

## Silent Payment Keys

`sp_key` encodes a silent payment key pair as one bech32m string, the form
BIP392 defines:

- `spscan` (`tspscan` on test networks): the scan secret key plus the spend
  public key, enough to detect payments but not to spend them.
- `spspend` (`tspspend`): both secret keys.

`SpKey` is either of the two, `SpScanKey` and `SpSpendKey` hold the keys, and
all three print and parse through `Display` and `FromStr`. Only version 0 is
accepted; a payload of the wrong length, one that does not decode to a valid
key, or a non-canonical encoding is refused.

## Silent Payment Descriptors

`sp_descriptor::SpDescriptor` is a BIP392 `sp()` descriptor. It takes either
one packed key expression, `sp(spspend1...)`, or a split pair,
`sp(scan_priv,spend_key)`, where the scan side is always a private key and the
spend side is public for a watch-only wallet and private for a spending one.

Parsing refuses a nested expression, a wildcard or multipath key, and an
uncompressed or x-only key. `scan_secret_key`, `spend_public_key` and
`spend_secret_key` resolve the keys, `is_watch_only` reports whether the spend
secret is missing, and `network_kind` says which network the keys belong to.

A key expression may carry a `[fingerprint/path]` origin, on the packed key or
on the scan key of a split pair. `origin` and `fingerprint` return it.

`Display` appends the usual descriptor checksum and `to_string_no_checksum`
leaves it off. A string that carries a checksum must match it, or parsing
fails.

## DescriptorDerivator Trait

Extension trait on `WalletDescriptor` for creating `SpkDerivator`:
```rust
use bwk_descriptor::descriptor::DescriptorDerivator;

let derivator = descriptor.spk_derivator(Network::Regtest)?;
```
