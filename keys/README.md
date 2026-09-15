# bwk-keys

**Experimental. Do not use in production or with real coins. API will break.**

Key derivation utilities and origin-aware key types.

Provides `OXpriv` and `OXpub`, extended keys bundled with their origin
(fingerprint + derivation path). Also includes `KeyDerivator` for deriving
keys from mnemonics.

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
