# bwk-sign

**Experimental. Do not use in production or with real coins. API will break.**

PSBT signing infrastructure with support for hot signers and hardware wallets.

Provides a unified interface for managing signers and signing PSBTs. Signers
communicate via async notifications, making it easy to integrate hardware
wallets that require user interaction.

**Scope:** Signer trait, HotSigner (in-memory BIP32), the `SigningManager`
trait and the back ends implementing it, PSBT signing for segwit/taproot. Does
NOT handle key derivation paths (use bwk-keys) or descriptor parsing (use
bwk-descriptor).

## Usage

```rust
use bwk_sign::{manager::SigningManager, protocol::Response, signing_manager::HotManager};
use crossbeam::channel;
use miniscript::bitcoin::Network;

// A manager for hot signers, plus the channel its answers arrive on
let mut manager = HotManager::new();
let (sender, responses) = channel::unbounded();
manager.subscribe(sender);

// Create a hot signer from a mnemonic; the manager mints its SignerId
let mnemonic = "abandon abandon abandon ...";
let signer =
    manager.new_bip32_signer_from_mnemonic(Network::Regtest, mnemonic.to_string());

// Queue a signature; the returned id correlates the answer
let request = manager.sign(&signer, descriptor, psbt_bytes)?;

for response in responses {
    match response {
        Response::Signed { signer, psbt, .. } => println!("{signer} signed"),
        Response::Error { message, .. } => println!("failed: {message}"),
        _ => {}
    }
}
```

## Architecture

```
consumer
   │  SigningManager trait: every call queues work and returns a RequestId
   ▼
HotManager ──► bip32_signers: BTreeMap<SignerId, HotSigner>
HwiManager ──► devices discovered through HwiService
   │
   └──► subscriber: channel::Sender<Response>
            │
            ▼
       Response (Signers, Xpub, Signed, Error, ...)
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
The result arrives later as a `Response` on the channel handed to
`subscribe`, and the `RequestId` ties it back to the call that triggered it.
A back end may also push what nobody asked for, such as a device being
unplugged.

Operations take a `SignerId`, not a fingerprint: a fingerprint identifies a
seed, and two signers (a hot one and a device) can hold the same seed. Each
manager mints its own ids. `signers()` lists what the manager knows from a
local cache and never does IO, and `set_polling` turns device discovery on and
off for the back ends that have any.

## Protocol

`Request` and `Response` are the whole vocabulary between a manager and its
back end, and `RequestId` correlates the two. Every `Request` carries its own
id, because a remote back end has to echo it, so it travels on the wire rather
than living in a caller-side map.

`Response::SignersChanged` and `Response::Error` are the two unsolicited
variants: device discovery can change the signer list with nothing having
asked, and a back end can fail without any request having caused it.

A remote back end is therefore a channel pair carrying exactly these two
enums, so an out-of-tree signer never has to implement a Rust trait.

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

## HotManager

The hot back end: a set of `HotSigner`s behind the `SigningManager` trait. Hot
signing is CPU-bound and needs no IO, so every trait method does its work
inline before returning, with no in-flight request table and no worker thread.
The `RequestId` and `Response` contract is honored all the same, so a caller
written against a hardware or remote back end works unmodified against this
one.

`sign` takes raw bytes and answers in the version it was given: a PSBTv2 is
signed as one, anything else is read as a PSBTv0.

Nothing here is persisted: a hot signer is re-seeded from the mnemonic its
consumer already holds, so the manager keeps no store of its own.

## HwiManager

The hardware back end, behind the `hwi` feature. Devices come from
`bwk_hwi::service::HwiService`, and every one it finds is listed, including
the locked and the unsupported ones, so a user learns there is something to
unlock or fix. A device can move between those states at any time, so each
request is dispatched onto a freshly read view of it, and the set of
descriptors registered per signer is tracked by the manager rather than by
that short-lived view.
