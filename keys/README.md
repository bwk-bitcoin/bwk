# bwk-keys

**Experimental. Do not use in production or with real coins. API will break.**

Key derivation utilities and origin-aware key types.

Provides `OXpriv` and `OXpub`, extended keys bundled with their origin
(fingerprint + derivation path). Also includes `KeyDerivator` for deriving
keys from mnemonics, and, under the `musig` feature, `MusigKey`, a BIP-390
key expression.

**Scope:** Key types with origin info, mnemonic-to-xpriv derivation. Does NOT
handle signing (use bwk-sign), descriptor parsing (use bwk-descriptor), or
address generation.

## Usage

```rust
use bwk_keys::{
    derivator::KeyDerivator,
    keys::{OXpriv, OXpub},
};
use bitcoin::Network;

// Derive from mnemonic
let derivator = KeyDerivator::new(mnemonic_words, Network::Bitcoin)?;
let path = "m/84'/0'/0'".parse()?;
let xpriv: OXpriv = derivator.derive_xpriv(&path);
let xpub: OXpub = derivator.derive_xpub(&path);

// OXpub displays with origin: [fingerprint/path]xpub...
println!("{}", xpub);  // [73c5da0a/84'/0'/0']xpub6...
```

## Types

- `OXpriv`: Extended private key with origin (fingerprint, derivation path)
- `OXpub`: Extended public key with origin
- `KeyDerivator`: Derives keys from BIP39 mnemonic
- `MusigKey` (feature `musig`): a plain key or a `musig()` aggregate

## MusigKey

Behind the `musig` feature, `musig::MusigKey` is the miniscript key type of a
descriptor that can hold BIP-390 `musig()` expressions: `Plain` wraps a
`DescriptorPublicKey`, `Musig` a `MusigAggregate`.

**Token form.** miniscript splits descriptors on `(`, `)` and `,`, so it cannot
parse `musig(K1,K2)/<0;1>/*`. `MusigKey` prints and parses the paren-free token
`musig|K1|K2|/<0;1>/*` instead (the suffix after the last `|` is the derivation
after aggregation), and `miniscript::Descriptor<MusigKey>` round-trips through
it. `to_bip390_string()` prints the standard `musig(K1,K2)/<0;1>/*` text;
`FromStr` refuses that text, bwk-descriptor converts it to the token first.

**Cosigners and participants.** `cosigners()` keeps the keys in the written
order, with their origin and derivation as written. `participants()` is the
BIP-327 KeySort order of their keys, the order KeyAgg takes (BIP-390 sorts
after all derivation and before aggregation).

**Aggregate then derive.** With no ranged cosigner, the aggregate is computed
once, with its BIP-328 synthetic xpub (depth 0, no parent, fixed chain code).
The derivation after `musig()`, unhardened only, is BIP-32 from that xpub: each
step is a plain tweak on the aggregate, and the derived key carries the origin
(synthetic xpub fingerprint, path after aggregation).

**Derive then aggregate.** With ranged or multipath cosigners and no
derivation after `musig()`, the aggregate only exists per index: `aggregate()`
and `synthetic_xpub()` are `None` and `derives_cosigners()` is true.

**Definite keys.** `at_derivation_index(i)` gives a `DefiniteMusigKey`: for a
musig, the derived cosigners, the participants, the untweaked aggregate, the
BIP-32 tweaks and the derived `key()`. `key_agg()` rebuilds the KeyAgg with the
tweaks (script path), `key_path_key_agg(merkle_root)` adds the BIP-341 taptweak
(key path). Split a multipath key with `into_single_keys()` first.
`to_plain_definite()` turns the derived aggregate into the single
`DefiniteDescriptorKey` miniscript's updater sees, with the origin above (a
static aggregate gets the synthetic fingerprint and an empty path, as Bitcoin
Core lists it).

```rust
use std::str::FromStr;

use bwk_keys::musig::MusigKey;

let key = MusigKey::from_str(&format!("musig|{xpub_a}|{xpub_b}|/<0;1>/*"))?;
assert_eq!(key.to_bip390_string(), format!("musig({xpub_a},{xpub_b})/<0;1>/*"));
let receive = key.into_single_keys().remove(0);
let derived = receive.at_derivation_index(0)?;
let internal_key = derived.as_musig().unwrap().key_path_key_agg(None)?.output_key();
```
