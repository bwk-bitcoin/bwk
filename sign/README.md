# bwk-sign

**Experimental. Do not use in production or with real coins. API will break.**

PSBT signing infrastructure with support for hot signers, hardware wallets and
out-of-tree remote signers.

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
RemoteManager ──► a Request/Response channel pair to an out-of-tree signer
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
- MuSig2 (BIP-327) key path and script path, behind the `musig` feature

## MuSig2

Under the `musig` feature a `HotSigner` is a MuSig2 participant for the BIP-390
`musig()` keys of its registered descriptors, and behaves like an external
device: one round per `inner_sign` / `sign_with_descriptor` call.

The slots (input, participant, aggregate, leaf) come from the registered
descriptor, never from the PSBT 0x1a. A script path slot exists only for a leaf
present in the input's `tap_scripts`, and the key path slot only when the input
carries the 0x1a of the internal aggregate. The signer tells the rounds apart
from its own 0x1b:

```
+------------------------------+-----------------------------------------------+
| own 0x1b in the PSBT         | action                                        |
+------------------------------+-----------------------------------------------+
| on none of its slots         | round 1: add the 0x1b only, no signature      |
| on all of its slots          | round 2: add the 0x1c, then ordinary sigs     |
| on some of its slots only    | Error::MusigSession                           |
| no musig slot                | ordinary signing                              |
+------------------------------+-----------------------------------------------+
```

Round 1 draws 32 fresh bytes from the OS per slot and binds the nonce to the
slot's sighash. The secret nonces stay in memory, in a session whose id is the
sha256 of the unsigned transaction, every spent output, the policy text and the
signer fingerprint, so a change to any of them between the rounds is refused.
The store keeps one session per (policy, signer fingerprint): a new round 1 for
the same wallet replaces the older session, so only the PSBT that ran round 1
last can finish round 2.
Round 2 first runs the ordinary signing on a copy, so its failure keeps the
session. It then takes the session out of the store before any check, so a
later failure erases it and a nonce never signs twice; it checks the sighash
and its own 0x1b against the session and needs every cosigner's 0x1b
(`MusigNonces` otherwise). Losing the session only costs a restart from round 1.

The ordinary pass never signs with a participant key: it skips every origin of
the signer whose path is exactly a participant path of one of its `musig()`
cosigner keys in any registered descriptor or the one being signed (the
cosigner's own path for `musig(A,B)/<0;1>/*`, the cosigner at a derivation index
for `musig(A/<0;1>/*,B/<0;1>/*)`), whatever the PSBT claims, so signing another
account cannot use a participant key, and a script path origin whose path does
not derive its key. A key derived under a cosigner, like the recovery key
`A/<1024;1025>/*` next to `musig(A,B)/<512;513>/*`, still signs.

`register_descriptor` refuses with `Error::MusigParticipantReuse` a descriptor
that uses one of the signer's participant keys as a plain key, like
`tr(A/<0;1>/*)` next to `musig(A/<0;1>/*,B/<0;1>/*)`, or that makes a
participant of a key already used as a plain key, whatever the registration
order.

`MusigSessionStore` is a cloneable handle: clones share the sessions. A
consumer that rebuilds its `HotSigner` per call passes one process-wide store
with `set_musig_sessions` so round 2 finds the session of round 1.

The finalizer role lives in `bwk_sign::musig`: `musig_status` reports the round
and each cosigner's progress, and `aggregate_partial_sigs` verifies every 0x1c
and aggregates each complete slot into `tap_key_sig` or `tap_script_sigs`,
ready for the miniscript finalizer.

### Persisted hot sessions

`hot_musig::HotMusigSession` is a transaction-independent secret value for an
application-owned encrypted cache. It adds no store or cache inside bwk. Use it
instead of `inner_sign` when supplying cached hot nonces:

```rust
let session = hot.create_musig_session(&descriptor, caller_id, 8)?;
// Optional: every owned expression at all eight input positions, including paths
// not selected in a transaction. Repeat for the desired public derivation indexes.
let public = session.public_nonces(&descriptor, keychain, derivation_index)?;
let plaintext = session.encode(); // consumes session; encrypt plaintext.as_bytes()
// Drop plaintext after encryption; both the value and bytes erase on drop.

// Later, without unlocking the hot signer:
let session = HotMusigSession::decode(
    HotMusigSessionBytes::from_bytes(decrypted_bytes),
    &descriptor,
    fingerprint,
)?;
// Durably allocate the entry to this signing attempt before publishing.
session.publish_nonces(&mut psbt, &descriptor)?;

// Once every participant has published, unlock hot and durably burn the entry.
hot.sign_musig_session(&mut psbt, &descriptor, session)?;
```

Import both secret types from `bwk_sign::hot_musig`. `caller_id` is a
`musig::MusigSessionId([u8; 32])`; every creation draws a fresh 32-byte root,
including repeated IDs. The application owns atomic same-ID replacement,
invalidation of old allocations, FIFO ordering, and durable consumption. Neither
the session nor its exported plaintext is `Clone` or `Debug`. Copies made by a
caller or restored from persistence cannot be revoked by a pure value API.

Coverage is one to eight absolute input positions. Every owned MuSig expression
is available on every public keychain and derivation index the policy supports.
Creation requires the ordinary signer's descriptor shape: two unhardened
receive/change paths with wildcards on the signer network. Unsupported shapes
return `Error::Derivator` at creation or consuming signing, including restored
sessions; decode alone checks the stored public binding, not signer support.
`public_nonces` prefetches all owned occurrences; `publish_nonces` resolves only
the slots requested by the real PSBT. No mnemonic is needed for either public
operation. Creation and signing verify actual participant public keys against
the hot signer, including rejection of forged fingerprint claims.

Nonce randomness is domain-separated SHA256 of the fresh root, caller ID, policy,
owner, input position and expression occurrence. BIP-327 NonceGen receives the
participant public key and omits the optional secret key, aggregate key and
message. Signing regenerates the secret nonce from that root, checks the own
published nonce, and uses the real tweaked key aggregation and BIP-341 sighash.
The entire session is consumed by one signing call, on success or any failure,
including failure of ordinary signing. A failed call leaves the PSBT unchanged.
The ordinary pass retains its participant-key cross-protocol reuse guards.

The fixed 102-byte encoding is version (one byte), caller ID (32), canonical
policy SHA256 (32), fingerprint (four), input coverage (one), and secret root
(32). Decode rejects wrong lengths, versions, owners, policies, invalid coverage
and a zero root, and erases its input bytes on success and failure. Persist only
authenticated encrypted bytes; this encoding provides no encryption or MAC.

`musig::SlotInfo` exposes the existing slot, aggregate, origin and merkle root,
plus `expression_index`. `musig::slot_infos` resolves selected PSBT slots;
`musig::expression_slots` lists all occurrences of a definite descriptor for
hardware adapters too. Index zero is the internal key; DFS leaf `iter_pk()` order
follows, counting all plain and foreign keys before ownership filtering. Spend
path selection never renumbers indexes. BIP-373 cannot distinguish duplicate
slots within the same leaf, so the cached API rejects those ambiguous requests.
Slot eligibility retains the existing 0x1a and `tap_scripts` rules. If the same
aggregate appears in the root and a selected leaf, retaining their shared 0x1a
still requests the key path too; partial leaf data does not disable it.

## Durable hot QR MuSig peer

With `musig`, `qr_musig::QrMusigPeer::from_store(signer, store, cipher)` owns a
`HotSigner`, a caller-selected `Store<Key = [u8; 32], Value = QrMusigPeerRecord>`
and an `Arc<dyn bwk_persist::cipher::Cipher>`. The cipher must provide authenticated
encryption. Secret exports are sealed before entering cloneable store records;
neither the peer's record codec nor its QR responses contain plaintext roots.
`qr_musig::{encode_record, decode_record}` are value codecs for caller-owned
`RamStore` instances. The peer does not select a backend or perform file IO.

The store must be exclusively held and durable: a successful `flush` must commit
all preceding writes. No `NoopBackend`, parallel peer sharing the same store,
rollback, restored backup or deletion of used session IDs is safe. Keep burned
tombstones permanently. A cipher does not prevent rollback or nonce reuse.

`prepare(PrepareMusig)` accepts a full BIP380 descriptor, bounded public
derivations and absolute input coverage, with no transaction. An identical
prepared request returns the same attributed public nonces after another
successful flush. A changed request never replaces an existing same-ID root.

`sign(SignMusig)` binds the selected session to the attempt, transaction, policy,
owner and exact descriptor-resolved slots, including expression occurrence,
derivation and actual sighash. Only advertised derivations are eligible. The
allocation is flushed before any nonce publication. Incomplete participant
transcripts return a `MusigSigned` PSBT containing nonces but no new signatures.
Once complete, the attributed transcript is pinned in KeyAgg order and flushed.
The encrypted record is then replaced with a root-free tombstone and flushed
before the consuming `HotSigner::sign_musig_session` call. There is no ordinary
signing fallback. Completed or missing sessions refuse signing retries.

Every publication, including identical retries, requires a successful flush.
A failed burn drops the transient root and disables further operations on that
peer. Later calls retry persisting the tombstone but still refuse signing.
Do not reopen an older store after a failed durability barrier; retain the live
peer until its tombstone has been durably written. A signing failure after a
successful burn also leaves the session permanently consumed.

`handle(QrRequest)` preserves the inner request ID and returns explicit QR
errors. `handle_remote(protocol::Request::Raw)` decodes the QR payload and returns
`Response::Raw` with the same outer request ID and signer. Malformed wire data
and non-Raw manager operations return attributed manager errors. Other inner
operations are refused, never passed through to ordinary hot signing.

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

## RemoteManager

A back end that is nothing but a channel pair: every trait call becomes a
`Request` on an outbound channel, and every `Response` arriving on the inbound
channel is forwarded to the subscriber. This is the plugin boundary for an
out-of-tree signer that cannot implement a Rust trait, such as one reached
across an FFI boundary.

`RemoteManager::pair()` returns the manager plus the two channel ends its far
end answers on. The far end reads every `Request` and answers with a
`Response` carrying the same `RequestId`, pushes `Response::SignersChanged`
whenever its signer list changes, and uses `Response::unsolicited_error` for
anything nobody asked for.
