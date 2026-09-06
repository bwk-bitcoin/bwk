# bwk-sign

**Experimental. Do not use in production or with real coins. API will break.**

PSBT signing infrastructure with support for hot signers and hardware wallets.

Provides a unified interface for managing signers and signing PSBTs. Signers
communicate via async notifications, making it easy to integrate hardware
wallets that require user interaction.

**Scope:** Signer trait, HotSigner (in-memory BIP32), the
`manager::SigningManager` trait every signing back end implements,
`signing_manager::SigningManager` (multi-signer coordination), PSBT signing
for segwit/taproot. Does NOT handle key derivation paths (use bwk-keys) or
descriptor parsing (use bwk-descriptor).

## Usage

```rust
use bwk_sign::{
    signer::{Signer, SignerNotif},
    signing_manager::SigningManager,
};
use miniscript::bitcoin::Network;
use std::path::PathBuf;

// Create signing manager
let mut manager = SigningManager::new(data_dir, ".my_wallet");

// Create hot signer from mnemonic
let mnemonic = "abandon abandon abandon ...";
manager.new_bip32_signer_from_mnemonic(Network::Regtest, mnemonic.to_string());

// Poll for notifications
while let Some(notif) = manager.poll() {
    match notif {
        SignerNotif::Info(fingerprint, info) => {
            println!("Signer {} ready", fingerprint);
        }
        SignerNotif::Signed(fingerprint, psbt) => {
            println!("PSBT signed by {}", fingerprint);
        }
        _ => {}
    }
}

// Sign a PSBT
manager.sign(Network::Regtest, psbt_string);
```

## Architecture

```
SigningManager
     │
     ├──► bip32_signers: BTreeMap<Fingerprint, HotSigner>
     │
     └──► channel: mpsc::Sender<SignerNotif>
              │
              ▼
         SignerNotif enum (Info, Xpub, Signed, Error, ...)
```

## Signer Trait

All signers implement `Signer` trait with async notification pattern:
- `init()`: Register notification channel, emit `SignerNotif::Info`
- `get_xpub()`: Request xpub at derivation path, emit `SignerNotif::Xpub`
- `sign_with_descriptor()`: Sign PSBT, emit `SignerNotif::Signed`
- `register_descriptor()` / `is_descriptor_registered()`: For hardware wallets

## SigningManager Trait

`manager::SigningManager` is the object-safe, store-free abstraction every
signing back end implements. Every operation queues work and returns a
`RequestId` at once: none of them blocks and none of them carries a result.
The result arrives later as a notification, and the `RequestId` ties it back
to the call that triggered it. A back end may also report what nobody asked
for, such as a device being unplugged.

Operations take a `SignerId`, not a fingerprint: a fingerprint identifies a
seed, and two signers (a hot one and a device) can hold the same seed. Each
manager mints its own ids. `signers()` lists what the manager knows from a
local cache and never does IO, and `set_polling` turns device discovery on and
off for the back ends that have any.

## send! Macro

Helper macro for sending notifications with fingerprint:
```rust
send!(self, Signed(psbt));
// expands to: sender.send(SignerNotif::Signed(self.fingerprint(), psbt))
```

## HotSigner

In-memory BIP32 signer from mnemonic. Supports:
- P2WPKH (segwit)
- P2TR key-path (tapkey)
- P2TR script-path (taptree)

## SigningManager

Manages multiple signers with unified notification channel. Persists hot signers
to `.signers` JSON file.
