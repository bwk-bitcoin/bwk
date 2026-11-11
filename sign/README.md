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

### Nonce cache sessions

`nonce_cache::SessionSecret` is the secret of one session of the nonce cache BIP
(`bip-nonce-cache/BIP-DRAFT.md`): 32 bytes from the OS (`SessionSecret::random`),
never derived from the seed, never exported. `session_ref` is its 4-byte
reference, and `nonce(i, j, secret_key, public_key)` is BIP-327 NonceGen with
`tagged_hash("BIPXXXX_NONCE_SEED", secret | ser32(i) | ser32(j))` as rand' and
the aggregate key, the message and extra_in omitted. Nothing else enters the
nonce: no policy, aggregate, cosigner set or transaction.

`HotSigner::sign_nonce_cache(&mut psbt, &descriptor, &secret)` signs in one
round: each own MuSig2 slot must already carry, as its 0x1b, the nonce the
secret derives for its input `i` and key expression index `j`, or it refuses
with `Error::MusigSession`. The ordinary keys sign too, and the PSBT is only
changed on success. The caller deletes the session durably before it releases
the signed PSBT.

`musig::SlotInfo::key_expression_index` is that `j`: the position of the slot's
key expression among the key expressions holding a key of the participant's
signer (by fingerprint), the internal key first, then the keys of each leaf in
DFS order. Key expressions holding none of its keys are not counted; a `musig()`
counts once. Spend path selection never renumbers them. `musig::slot_infos`
resolves the slots a PSBT selects, `musig::expression_slots` every musig()
occurrence of a definite descriptor.

## QR MuSig on nonce cache sessions

With `musig`, `qr_musig::QrMusigPeer` and `qr_musig_host::QrMusigHost` sign MuSig2
in one round over the QR protocol, with the nonce cache sessions of
`bip-nonce-cache/BIP-DRAFT.md`: nonces are issued with Nonce Preparation before
any transaction exists, and signing is an ordinary Signing exchange whose PSBT
names the session in `PSBT_GLOBAL_NONCE_CACHE_SESSION`. Only aggregate then
derive, as in `musig(A,B)/<0;1>/*`, is in scope: the participant key is then the
same at every input.

### Peer

`QrMusigPeer::from_store(signer, store)` owns a `HotSigner` and a caller-selected
`Store<Key = [u8; 4], Value = QrMusigPeerRecord>` holding the sessions by
`session_id`. A session is a random secret (see Nonce cache sessions above) and
its creation order; the secret lives only in this store, which the peer must own
exclusively and whose successful `flush` must be durable.
`qr_musig::{encode_record, decode_record}` are value codecs for a caller-owned
`RamStore`: the creation order (8 bytes, little endian) then the secret (32
bytes).

`prepare(PrepareNonces)` answers from the session holding `session_id`, and
creates it when there is none and the request carries no reference. A reference
that does not match the session, or names a session the peer does not hold, is
refused and creates nothing. Storing more than `MAX_SESSIONS` (16) sessions
evicts the oldest. The nonces are those of the key at the request path for every
key expression index of the range and every input below `max_inputs`, ordered by
key expression index then input. The store is flushed before the answer leaves.

`sign(Sign)` takes a PSBT v0 or v2 and answers in the same version. It refuses a
PSBT that names no session, and a session it does not hold with that reference.
Every descriptor carries a full BIP-380 body, and the signer signs each through
`HotSigner::sign_nonce_cache` (`sign_nonce_cache_v2` for a PSBTv2), which refuses
a slot whose 0x1b is not the nonce it derives. The session is then removed and the
store flushed before the signed PSBT leaves: a failed flush releases nothing.

`handle(QrRequest)` preserves the inner request ID and answers a refused session
with the session `ERROR` `0x0D`, an input it does not own with nothing to sign,
a malformed request with malformed request and a persistence failure with
internal error. `handle_remote(protocol::Request::Raw)` decodes the QR payload
and returns `Response::Raw` with the same outer request ID and signer. Other
operations are refused, never passed through to ordinary hot signing.

### Host

`QrMusigHost::from_store(store)` keeps, in a
`Store<Key = [u8; 4], Value = QrMusigHostRecord>`, the public nonces each signer
issued per session, by key path, key expression index and input index.
`qr_musig_host::{encode_host_record, decode_host_record}` are value codecs for a
caller-owned `RamStore`.

- `issue_request` draws a random `session_id` and asks for an `Issuance`: a key
  path, the input coverage and a range of key expression indexes.
- `extend_request` asks for more of a session it holds, with the session
  reference once known, so the signer refuses rather than answer from another
  secret after an eviction.
- `sign_request` sets, for every slot of the signer in the PSBT, the issued nonce
  at the slot's participant path, `SlotInfo::key_expression_index` and input
  index as its 0x1b, names the session and builds the Signing request.

Each returns the wire bytes. `submit_pending` sends them through
`SigningManager::raw`, or `bind_outer_request` binds an outer ID when the caller
sends them itself, and `accept_response` checks both request IDs and the signer.
A signed PSBT, or a refusal for the session, drops the session; other refusals
keep it.

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
