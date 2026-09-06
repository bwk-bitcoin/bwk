# bwk-descriptor

**Experimental. Do not use in production or with real coins. API will break.**

Descriptor construction and SPK derivation utilities.

Wraps miniscript descriptors to provide convenient address/scriptPubKey
derivation for standard wallet patterns. Handles multipath descriptors
(recv/change) and validates descriptor structure on construction.

**Scope:** Descriptor building (wpkh/tr), SpkDerivator for address derivation,
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

Extension trait on `Descriptor<DescriptorPublicKey>` for creating `SpkDerivator`:
```rust
use bwk_descriptor::descriptor::DescriptorDerivator;

let derivator = descriptor.spk_derivator(Network::Regtest)?;
```
