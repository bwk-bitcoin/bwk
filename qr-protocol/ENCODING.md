```
  Title: Signing-flow message encoding for miniscript wallets
  Authors: Pyth <pythcoiner@wizardsardine.com>
  Status: Draft
  Type: Specification
  License: BSD-2-Clause
```

## Introduction

### Abstract

This document defines the byte encoding of the signing-flow messages exchanged
between a **wallet** (online software) and a **signer** (offline device) in the
miniscript context: Get Keys, Register Descriptor, Address Verification, Signing
and their exact byte layout. It is the authoritative byte-level contract two
implementations must agree on.

The encoding is **transport agnostic**: a `MESSAGE` is a self-contained byte
string, and how it is delivered (animated QR via BBQR, NFC, a file, a socket) is
out of scope.

### Scope

Transport is out of scope,the encoding defined here is independent of any
third-party serialization format.

## Specification

### Integer Encodings

All variable-length integers (the `COUNT` and `LENGTH` fields below) are encoded as
[compact size](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer).
All fixed-width multi-byte integers are big-endian.

### Optional Fields

An OPTIONAL field is encoded as a 1-byte `PRESENCE` (`0x00` absent, `0x01`
present), followed by the field's encoding only when `PRESENCE` is `0x01`. Any
other `PRESENCE` value MUST be rejected.

### Vectors

A vector of some element type is encoded as a `COUNT` (compact size) followed by
`COUNT` elements back to back.

### Common Field Encodings

`BOOL`: 1-byte unsigned integer, `0x00` false or `0x01` true. Any other value MUST
be rejected.

`BYTES`: a `LENGTH` (compact size) followed by `LENGTH` raw bytes.

`STRING`: a `BYTES` (`LENGTH` followed by `LENGTH` raw bytes) whose content MUST be
valid UTF-8 and MUST NOT contain a nul byte. Every `STRING` in this format is an
alias, an address, a descriptor, a key expression, a policy or a URI, so nothing
legitimate carries one, and forbidding it lets a consumer hand the value straight to
a language whose strings are nul-terminated without silently truncating it.

`DESCRIPTOR_ALIAS`: a `STRING` whose encoded length MUST be at most 32 bytes.

`FINGERPRINT`: 4 bytes, the BIP-32 master key fingerprint.

`EXTENDED_KEY`: 78 bytes, the BIP-32 serialization of an extended public or private
key (4 version + 1 depth + 4 parent fingerprint + 4 child number + 32 chain code +
33 key). A private key carries `0x00` followed by its 32-byte key in place of the
33-byte public key, and its own version bytes, so both have the same length.

`PSBT`: a `BYTES` (`LENGTH` followed by `LENGTH` raw bytes) whose content is the
BIP-174 binary serialization. Base64 is NOT used on the wire.

`DERIVATION_PATH` follows this format:

`CHILD_COUNT` `CHILD` `...` `CHILD`

`CHILD_COUNT`: 1-byte unsigned integer (0–255), the number of children.
`CHILD`: 4-byte big-endian unsigned integer, a child index per BIP-32 (a hardened
step has bit 31 set, `index | 0x80000000`).

`DESCRIPTOR_BODY` follows this format:

`FORM` `BODY`

`FORM`: 1-byte unsigned integer selecting the descriptor form.

```
+-------+-----------------------+
| Value | Definition            |
+-------+-----------------------+
| 0x00  | Reserved              |
| 0x01  | BIP-380 descriptor    |
| 0x02  | BIP-388 wallet policy |
| 0x03  | Silent payment keys   |
+-------+-----------------------+
```

`BODY` depends on `FORM`:
- `0x01`: a `STRING`, the BIP-380 descriptor text.
- `0x02`: `KEYS` `POLICY`, the BIP-388 wallet policy. BIP-388 defines no byte
  encoding, so it is serialized here as its two components:
  - `KEYS`: a vector of `STRING`, the key information, each a BIP-380 key expression
    referenced by `@0`, `@1`, ... in `POLICY`.
  - `POLICY`: a `STRING`, the descriptor template with `@i` key placeholders.

- `0x03`: a `STRING`, a silent payment account's keys as
  `<fingerprint>|<spend_path>|<scan_path>`: the key's master fingerprint as 8
  lowercase hex characters, then the BIP-32 paths of the BIP-352 spend and scan keys,
  each written `m/` followed by its steps with `'` marking a hardened step. Example:
  `73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0`. It carries no key material: the
  signer derives both keys from its own seed, which is enough to rebuild the
  account's BIP-392 `sp()` descriptor. A signer MUST refuse it when the fingerprint
  is not its own. Used only by Address Verification.

Note: `KEYS` must be sorted following the `@n` order.

### Encoding

A message is encoded as follows:

`MAGIC` `VERSION` `MSG_TYPE` `REQUEST_ID` `BODY`

#### Magic

`MAGIC`: 6 bytes, the ASCII representation of **BIPXXX** (TBD)
(`0x42 0x49 0x50 0x58 0x58 0x58`). A parser MUST reject any input that does not
begin with `MAGIC` before parsing further. `BIPXXX` is a placeholder: once a BIP
number is assigned, the three `X` bytes are replaced by its ASCII digits (e.g.
**BIP138** -> `0x42 0x49 0x50 0x31 0x33 0x38`).

#### Version

`VERSION`: 1-byte unsigned integer representing the protocol version that produced
the message. This specification defines version `0x01`.

#### Message Type

`MSG_TYPE`: 1 byte, packing the direction, status, and message type.

Bits (bit 7 is the MSB):

```
+--------+-------------+------------------------------------------------------------+
| Bit(s) | Field       | Meaning                                                    |
+--------+-------------+------------------------------------------------------------+
| 7      | `DIRECTION` | `0` request, `1` response                                  |
| 6      | `STATUS`    | response-only: `0` ok, `1` error; MUST be `0` in a request |
| 5–0    | `TYPE`      | message type (table below)                                 |
+--------+-------------+------------------------------------------------------------+
```

`TYPE` values:

```
+-------+----------------------+
| Value | Type                 |
+-------+----------------------+
| 0x00  | Reserved             |
| 0x01  | Get Keys             |
| 0x02  | Register Descriptor  |
| 0x03  | Address Verification |
| 0x04  | Signing              |
+-------+----------------------+
```

Values `0x05`–`0x3F` are reserved. A parser MUST reject an unknown `TYPE`, and
MUST reject `STATUS` = `1` on a request (`DIRECTION` = `0`).

#### Request Id

`REQUEST_ID`: 2 opaque bytes with no `LENGTH` prefix. The requester chooses the
value, and the responder echoes it verbatim in the matching response, including
an error response, so a wallet can pair a response with the request it sent. It
carries no structure and a receiver MUST NOT interpret it. It MUST be present in
every message.

#### Error response body

When `STATUS` = `1`, the response `BODY` is the following, regardless of `TYPE`,
in place of the type's normal (ok) response body:

`ERROR` `ERROR_MESSAGE`

`ERROR`: 1-byte unsigned integer selecting an entry from the global error table
below.
`ERROR_MESSAGE`: 32 bytes, a UTF-8 string right-padded with `0x00`. The value is
the bytes up to the first `0x00` (or all 32 bytes when none is `0x00`); every byte
after it MUST be `0x00`, and the value MUST be valid UTF-8.

Global error table:

This table is the wire `ERROR` field inside an error response. It is separate
from the C binding return codes documented in `README.md` and
`include/bwk_qr_protocol.h`.

```
+-----------+------------------------------------------------------+
| `ERROR`   | Meaning                                              |
+-----------+------------------------------------------------------+
| 0x00      | Reserved                                             |
| 0x01      | User declined / cancelled on device                  |
| 0x02      | Unsupported protocol version                         |
| 0x03      | Malformed request                                    |
| 0x04      | Unknown / unregistered `DESCRIPTOR_ALIAS`            |
| 0x05      | Descriptor registration failed                       |
| 0x06      | Unsupported descriptor form (`FORM`)                 |
| 0x07      | Invalid proof of registration                        |
| 0x08      | Address mismatch (Address Verification)              |
| 0x09      | Nothing to sign / no matching key for any input      |
| 0x0A      | Invalid or unparsable PSBT                           |
| 0x0B      | Internal device error                                |
| 0x0C      | Private key export refused (Get Keys)                |
| 0x0D      | MuSig2 session missing or mismatch (Signing)         |
| 0x0E–0xFE | Reserved for future standard codes                   |
| 0xFF      | Vendor-specific (meaning carried by `ERROR_MESSAGE`) |
+-----------+------------------------------------------------------+
```

`0x00` is reserved and MUST NOT be sent. `0x01`–`0x0D` are the standard codes above;
`0x0E`–`0xFE` are reserved for future standard codes. `0xFF` is vendor-specific: the
code alone is not meaningful, so `ERROR_MESSAGE` carries the description. A receiver
MUST NOT reject an unrecognized `ERROR`; `STATUS` = `1` already denotes an error,
and it SHOULD fall back to `ERROR_MESSAGE`.

#### Body

For an ok response (`STATUS` = `0`) and for requests, `BODY` is the type's
fields below, in listed order. Fields are ordered by the version in which they were
introduced (see Versioning); within a version they appear in listed order.

The message definitions below give each type's request body and ok response
body.

### Get Keys

**Request** (`TYPE` = `0x01`, request):

`KEYS`

`KEYS`: a vector of `KEY_REQUEST`, the keys to derive.

`KEY_REQUEST` follows this format:

`DERIVATION_PATH` `KIND`

`DERIVATION_PATH`: the path of the key from the master key.
`KIND`: 1-byte unsigned integer selecting the key returned at that path.

```
+-----------+-------------------------------+
| Value     | Definition                    |
+-----------+-------------------------------+
| 0x00      | Public: extended public key   |
| 0x01      | Private: extended private key |
| 0x02–0xFF | Reserved                      |
+-----------+-------------------------------+
```

Values `0x02`–`0xFF` are reserved; a parser MUST reject them.

A signer MUST refuse a `KEY_REQUEST` of `KIND` `0x01` unless its path is a BIP-352
scan key path or under it: `m/352'/coin'/account'/1'` and deeper, with `coin` and
`account` hardened. Exporting the scan key reveals the account's incoming silent
payments but cannot spend them; any other private key spends funds. A signer
without the Silent Payments capability (bit 2) MUST refuse any `KIND` `0x01`. A
signer refusing a `KEY_REQUEST` refuses the whole request with an error response,
`ERROR` `0x0C`, never a partial answer. The signer SHOULD tell the user, before
exporting, that the key reveals incoming payments but cannot spend them.

A silent payment wallet asks for the spend key public and the scan key private
(e.g. `m/352'/0'/0'/0'` `KIND` `0x00` and `m/352'/0'/0'/1'` `KIND` `0x01`) and builds
the BIP-392 `sp()` descriptor itself, alongside any other xpubs (e.g. `m/86'/0'/0'`,
`m/84'/0'/0'`) in the same request.

**Ok response** (`TYPE` = `0x01`, response):

`KEYS` `FINGERPRINT` `VENDOR` `MODEL` `VERSION` `CAPABILITIES`

`KEYS`: a vector of `EXTENDED_KEY`, one per request `KEY_REQUEST` in the same
order, each of the `KIND` requested.
`FINGERPRINT`: the `FINGERPRINT` of the master key. Mandatory.
`VENDOR`: 16 bytes, a UTF-8 device-vendor string with no `LENGTH` prefix, right-padded
with `0x00` when shorter than 16 bytes. The value is the bytes up to the first
`0x00` (or all 16 bytes when none is `0x00`); every byte after it MUST be `0x00`.
Mandatory.
`MODEL`: 16 bytes, a UTF-8 device-model string with no `LENGTH` prefix, right-padded
with `0x00` when shorter than 16 bytes. The value is the bytes up to the first
`0x00` (or all 16 bytes when none is `0x00`); every byte after it MUST be `0x00`.
Mandatory.
`VERSION`: 8 bytes of device firmware version, `MAJOR` `MINOR` `PATCH` `FLAG`.
`MAJOR` and `MINOR` are 2-byte big-endian unsigned integers, `PATCH` is a 3-byte
big-endian unsigned integer, and `FLAG` is a 1-byte pre-release channel. Mandatory.

```
+--------+-------------------+
| `FLAG` | Pre-release       |
+--------+-------------------+
| 0x00   | Stable (final)    |
| 0x01   | Alpha             |
| 0x02   | Beta              |
| 0x03   | Release candidate |
+--------+-------------------+
```

Values `0x04`–`0xFF` are reserved. A reader SHOULD treat an unknown `FLAG` as an
unspecified pre-release rather than reject.
`CAPABILITIES`: 4-byte big-endian bitfield of the capabilities the signer supports.
Mandatory. Bit 0 is the LSB.

```
+------+----------------------------------+
| Bit  | Capability                       |
+------+----------------------------------+
| 0    | Miniscript, SegWit v0            |
| 1    | Miniscript, Taproot (v1)         |
| 2    | Silent Payments (v0)             |
| 3    | MuSig2                           |
| 4–30 | Reserved for future capabilities |
| 31   | Upgrade signal (MSB)             |
+------+----------------------------------+
```

Bit 2 implies the signer can return a signed `PSBT` (Signing response `KIND`
`0x01`), the only response form carrying the BIP-375 shares and proofs.

Bit 3 means the signer is a BIP-327 MuSig2 participant for BIP-390 `musig()` keys
inside `tr()` of a registered descriptor (`FORM` `0x01`) or wallet policy (`FORM`
`0x02`): it reads and writes the BIP-373 PSBT fields, follows the rules of the
MuSig2 subsection of Signing, and MAY answer with `SIG_KIND` `0x04` / `0x05`. A
wallet MUST NOT register or send a `musig()` descriptor to a signer without bit 3.

Bits 4–30 are reserved for future capabilities and MUST be `0` in this version; a
reader MUST ignore an unknown capability bit rather than reject, so a newer signer
can advertise capabilities an older wallet does not know. Bit 31 (the MSB) MUST be
`0` in this version; a `1` signals that the signer exposes capabilities beyond this
bitfield and the wallet should upgrade to interpret them.

### Register Descriptor

**Request** (`TYPE` = `0x02`, request):

`DESCRIPTOR_ALIAS` `DESCRIPTOR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
Mandatory.
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`. When absent, the request only queries the
registration status of `DESCRIPTOR_ALIAS`. At most one descriptor per request.

**Ok response** (`TYPE` = `0x02`, response):

`DESCRIPTOR_ALIAS` `REGISTERED` `STORED` `POR`

`DESCRIPTOR_ALIAS`: echoes the alias from the request.
`REGISTERED`: OPTIONAL `BOOL`, the registration status.
`STORED`: OPTIONAL `BOOL`, whether the device persisted the descriptor under
`DESCRIPTOR_ALIAS`. A device may persist the descriptor, or stay stateless and
prove the registration with a `POR`; a device supporting both lets the user choose
on the device, so only the device knows which happened. When `true`, a later
request MAY reference the descriptor by `DESCRIPTOR_ALIAS` alone. When `false` or
absent, the wallet MUST send the `DESCRIPTOR_BODY` again in every later request,
together with the `POR` when the device issued one; absent means the device does
not report whether it stored the descriptor, so the wallet MUST assume it did not.
A device MAY both store the descriptor and return a `POR`, so `STORED` and the
presence of `POR` are independent.
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

A failed registration is reported as an error response (`STATUS` = `1`), not via a
body field.

### Address Verification

**Request** (`TYPE` = `0x03`, request):

`DESCRIPTOR_ALIAS` `DERIV` `ADDRESS` `DESCRIPTOR` `POR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
`DERIV`: `DERIVATION_PATH`, the path under the descriptor.
`ADDRESS`: OPTIONAL `STRING`, the expected address (recommended).
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`, the full descriptor / wallet policy (for
stateless devices).
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

A silent payment address is verified with a `DESCRIPTOR` of `FORM` `0x03`
(silent payment keys) instead of a descriptor, and no `POR`:
- `DESCRIPTOR_ALIAS`: the account's alias, for display only; nothing is registered.
- `DERIV`: the BIP-352 label. Empty for the account's base address; one step `m`
  for the address labelled `m` (`m` ≥ 1, as label `0` is reserved for change).
- `ADDRESS`: the expected silent payment address.

The signer derives the spend and scan keys at the given paths, applies the label
tweak when `DERIV` has one, encodes the address for its network, shows it, and
answers with a `URI` holding it, or with the error `0x08` when it differs from
`ADDRESS`. Only a signer advertising capability bit 2 accepts it.

**Ok response** (`TYPE` = `0x03`, response):

`URI`

`URI`: OPTIONAL `STRING`, a BIP-21 payment URI for the verified address.

### Signing

**Request** (`TYPE` = `0x04`, request):

`DESCRIPTORS` `PSBT` `WANT_KIND`

`DESCRIPTORS`: a vector of `DESCRIPTOR`, one entry per descriptor the inputs spend
from.
`PSBT`: the `PSBT` to sign.
`WANT_KIND`: OPTIONAL, the response `KIND` the wallet prefers (see the response
below). A preference only: the signer MAY answer with another `KIND` it supports
(some devices could return only a `PSBT`), and MUST do so where the response below
requires `0x01`.

`DESCRIPTOR` follows this format:

`DESCRIPTOR_ALIAS` `DESCRIPTOR` `POR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`: the descriptor / wallet policy itself.
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

**Ok response** (`TYPE` = `0x04`, response):

`KIND` `DATA`

`KIND`: 1-byte unsigned integer selecting the response form.

```
+-------+------------------------------------------------+
| Value | Definition                                     |
+-------+------------------------------------------------+
| 0x00  | Reserved                                       |
| 0x01  | Full PSBT (input PSBT with partial signatures) |
| 0x02  | Signatures only                                |
+-------+------------------------------------------------+
```

`DATA` depends on `KIND`:
- `0x01`: a `PSBT`. A silent-payment send carries its BIP-375 fields in the PSBT
  itself (`PSBT_IN_SP_ECDH_SHARE` or `PSBT_GLOBAL_SP_ECDH_SHARE` and the matching
  DLEQ proofs), so nothing extra is encoded here.
- `0x02`: `SIGS`, a vector of `SIG_ENTRY`.

When the transaction has silent-payment outputs, the signer MUST answer with
`KIND` `0x01` regardless of `WANT_KIND`: the BIP-375 shares and DLEQ proofs have
no representation in the signatures-only form.

`SIG_ENTRY` follows this format:

`INPUT_INDEX` `SIG_KIND` `KIND_FIELDS`

`INPUT_INDEX`: 4-byte big-endian unsigned integer, the input index.
`SIG_KIND`: 1-byte unsigned integer.

```
+-----------+-------------------+
| Value     | Definition        |
+-----------+-------------------+
| 0x00      | Reserved          |
| 0x01      | segwit            |
| 0x02      | tapkey            |
| 0x03      | taptree           |
| 0x04      | musig pubnonce    |
| 0x05      | musig partial sig |
| 0x06–0xFF | Reserved          |
+-----------+-------------------+
```

`KIND_FIELDS` depends on `SIG_KIND`:
- `0x01` segwit: `PUBLIC_KEY` `SIGNATURE`.
  - `PUBLIC_KEY`: 33 bytes, the compressed public key that produced the
    signature, i.e. the key of the PSBT `partial_sigs` entry.
  - `SIGNATURE`: `BYTES`, the signature.
- `0x02` tapkey: `SIGNATURE`.
  - `SIGNATURE`: `BYTES`, a taproot key-path Schnorr signature.
- `0x03` taptree: `XONLY_PUBLIC_KEY` `TAP_LEAF_HASH` `SIGNATURE`.
  - `XONLY_PUBLIC_KEY`: 32 bytes.
  - `TAP_LEAF_HASH`: 32 bytes. Together with `XONLY_PUBLIC_KEY` it is the key of
    the PSBT `tap_script_sigs` map.
  - `SIGNATURE`: `BYTES`, the signature.
- `0x04` musig pubnonce: `PARTICIPANT` `AGGREGATE` `LEAF_HASH` `PUB_NONCE`.
  - `PARTICIPANT`: 33 bytes, the compressed participant key.
  - `AGGREGATE`: 33 bytes, the compressed key signed for (BIP-373: the taproot
    output key on the key path, the key as it appears in the leaf on a script
    path).
  - `LEAF_HASH`: OPTIONAL, 32 bytes, the BIP-341 tap leaf hash, absent on the key
    path.
  - `PUB_NONCE`: 66 bytes, no `LENGTH`.

  Together they are the key and value of the PSBT `PSBT_IN_MUSIG2_PUB_NONCE`
  (`0x1b`) field.
- `0x05` musig partial sig: `PARTICIPANT` `AGGREGATE` `LEAF_HASH` `PARTIAL_SIG`.
  - `PARTICIPANT`, `AGGREGATE`, `LEAF_HASH`: as for `0x04`.
  - `PARTIAL_SIG`: 32 bytes, no `LENGTH`.

  Together they are the key and value of the PSBT `PSBT_IN_MUSIG2_PARTIAL_SIG`
  (`0x1c`) field.

The key material travels with the signature because the coordinator inserts each
signature into its PSBT keyed by those values. No control block is sent: the
coordinator rebuilds it from the descriptor at finalize time.

Spending an output received via silent payments is an ordinary taproot key-path
spend, so `0x02` (tapkey) already covers it.

#### MuSig2

This subsection applies to a signer advertising capability bit 3. A MuSig2 key
uses the BIP-373 PSBT fields: `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (`0x1a`), keyed
by the untweaked KeyAgg aggregate; `PSBT_IN_MUSIG2_PUB_NONCE` (`0x1b`, 66 bytes)
and `PSBT_IN_MUSIG2_PARTIAL_SIG` (`0x1c`, 32 bytes), both keyed by
`participant(33) || aggregate(33) [|| leaf_hash(32)]`, where `aggregate` is the key
signed for: the taproot output key on the key path (no leaf hash), the key as it
appears in the leaf on a script path (with the leaf hash).

**Rounds.** Each cosigner takes part in two Signing exchanges; there is no new
message and `VERSION` stays 1.

- Round 1: the request `PSBT` carries no `0x1b` and no `0x1c` from anyone. The
  answer carries the signer's own `0x1b` only (`KIND` `0x01` with them in the PSBT,
  or `KIND` `0x02` with `SIG_KIND` `0x04` entries) and no signature of any kind.
- Round 2: the request `PSBT` carries every participant's `0x1b` for every slot.
  The answer carries the signer's `0x1c` (`SIG_KIND` `0x05` entries, or in the
  PSBT) and its ordinary signatures (`SIG_KIND` `0x01` to `0x03`). A signer that
  holds every partial signature MAY also aggregate them and add the final
  signature; the wallet MUST accept either.

**Slots.** A slot is one (input, participant, aggregate, leaf). The signer tells
the rounds apart from its own `0x1b` over its slots only; foreign `0x1b` / `0x1c`
never decide the round, and a signer in round 1 ignores them (a wallet still strips
them, see the wallet rules):

```
+--------------------------------------+----------------------+
| Signer's own `0x1b` in the PSBT      | Meaning              |
+--------------------------------------+----------------------+
| on none of its slots                 | Round 1              |
| on all of its slots                  | Round 2              |
| on some of its slots only            | Error `0x0D`         |
| the signer has no MuSig2 slot        | Ordinary signing     |
+--------------------------------------+----------------------+
```

**Signer rules.** The signer MUST:

- take the cosigners and the slots from the registered descriptor, never from the
  PSBT `0x1a`, and ignore a `0x1a` whose aggregate it does not know;
- consider a script-path slot only for a leaf present in the input's
  `PSBT_IN_TAP_LEAF_SCRIPT`, and the key-path slot only when the input carries the
  `0x1a` of the internal aggregate;
- require the session of round 1 for round 2, and answer `0x0D` when that session
  is missing, when the transaction or a spent output changed, when a recomputed
  sighash or its own `0x1b` differs from what the session holds, or when any
  cosigner's `0x1b` is missing;
- never sign with a participant key outside MuSig2.

**Nonce safety.** The signer MUST:

- draw each secret nonce from BIP-327 `NonceGen` with 32 fresh bytes from a
  cryptographically secure random source, bound to its slot's key and sighash;
- bind the session to the unsigned transaction, every spent output, the registered
  policy and the signer's fingerprint;
- keep secret nonces in volatile memory only, never export, serialize, log or
  persist them, and use each at most once;
- erase the session before a partial signature leaves the signer, and on any
  round-2 failure after the session was looked up;
- replace any earlier session for the same transaction on a new round 1.

Losing the session (power cycle, timeout) only costs a restart from round 1, never
a nonce reuse.

**Wallet rules.** The wallet MUST:

- strip every `0x1b` and `0x1c` from the PSBT before round 1, so no foreign nonce
  reaches a signer in that round;
- for an m-of-n policy, restrict the PSBT to one leaf (one m-subset) before round 1,
  so each cosigner answers for that leaf only;
- never change the transaction, a spent output or the chosen leaf between the
  rounds;
- send round 2 only once every participant's `0x1b` is merged;
- on `0x0D` from any cosigner, discard every nonce of the attempt and restart
  round 1 with every cosigner;
- verify each partial signature (BIP-327 `PartialSigVerify`) before aggregating it
  into `PSBT_IN_TAP_KEY_SIG` or `PSBT_IN_TAP_SCRIPT_SIG`.

These rules follow Bitcoin Core, Coldcard EDGE (`shared/psbt.py`
`musig_process_input`: strict round separation, the public nonce recomputed and
compared with the PSBT's, the session erased after use) and Ledger (no foreign
nonce in the round-1 PSBT, cosigners rebuilt from the registered policy). The
reference signer is `bwk_sign::hot_signer::HotSigner` under the `musig` feature.

### Versioning

`BODY` is encoded append-only: fields are ordered by the `VERSION` in which they
were introduced, then by listed order within a version. A parser built for version
`N`:

- For a message with `VERSION` ≤ `N`: parse exactly that version's field set.
- For a message with `VERSION` > `N`: parse the fields introduced up to version
  `N`, then ignore the trailing bytes.[^trailing] They belong to fields added in
  later versions, which by ordering come strictly after everything `N` knows.
- For a message with `VERSION` < `N`: only the fields introduced up to the
  message's version are present; the parser MUST NOT expect later-version fields.

The transport MUST deliver each `MESSAGE` in full and length-delimited; a parser
therefore always knows where it ends, so "ignore the trailing bytes" is
unambiguous.

Rules for future versions:
1. New fields MUST only be appended (a higher introduction version); an existing
   field MUST NOT be reordered, removed, or have its size/encoding changed.
2. To change an existing field's meaning, add a new field and deprecate the old.
3. Bump `VERSION` when adding fields; document each field's introduction version.

[^trailing]: **Why ignore trailing bytes?**
    Appending fields and ignoring unknown trailing bytes lets an older parser read
    a newer message (up to the fields it knows) and a newer parser read an older
    message (which simply carries fewer fields), without an external schema.

### Errors

- A parser MUST reject input whose first 6 bytes are not `MAGIC`.
- A parser MUST reject input that ends before a required field is fully read, a
  compact-size `LENGTH`/`COUNT` that exceeds the remaining input, a `BOOL` or
  `PRESENCE` outside `{0x00, 0x01}`, a discriminant (`TYPE`, `FORM`, `KIND`,
  `SIG_KIND`) outside its defined range, `STATUS` = `1` on a request, or a
  `STRING` that is not valid UTF-8 or that contains a nul byte.
- Trailing bytes after the final field a parser understands are NOT an error
  (Versioning).

### Parser limits

These are not wire-format fields but the bounds a parser applies so absurd input
is rejected before anything large is allocated. Recommended values:

```
+-------------------+---------------+
| Field             | Bound         |
+-------------------+---------------+
| `BYTES`           | 512 KiB       |
| `STRING`          | 64 KiB        |
| vector `COUNT`    | 4096 elements |
| `DERIVATION_PATH` | 255 children  |
+-------------------+---------------+
```

A parser MAY use different bounds, but it MUST reject input that exceeds what it
can hold rather than allocate unboundedly. A `COUNT` is attacker-controlled, so a
parser MUST NOT reserve room for it before the items have been read.

### Worked examples

Bytes are shown space-separated in hex.

Get Keys request, the public key at `m/48'/0'/0'/2'`:
```
42 49 50 58 58 58    MAGIC "BIPXXX"
01                   VERSION = 1
01                   MSG_TYPE: request, ok, TYPE 0x01 (Get Keys)
00 01                REQUEST_ID (2 bytes)
01                   KEYS: vector count = 1
04                   CHILD_COUNT = 4
80 00 00 30          48' = 0x80000030 (big-endian)
80 00 00 00          0'  = 0x80000000
80 00 00 00          0'  = 0x80000000
80 00 00 02          2'  = 0x80000002
00                   KIND = 0x00 (public)
```

Address Verification response, `URI = "bitcoin:bc1qxyz"`:
```
42 49 50 58 58 58    MAGIC "BIPXXX"
01                   VERSION = 1
83                   MSG_TYPE: response, ok, TYPE 0x03 (Addr Verif)
00 01                REQUEST_ID, echoed
01                   URI: PRESENCE = present
0f                   LENGTH = 15
62 69 74 63 6f 69 6e 3a 62 63 31 71 78 79 7a   "bitcoin:bc1qxyz"
```

The `0x83` `MSG_TYPE` byte is `DIRECTION` 1 (response) | `STATUS` 0 (ok) |
`TYPE` `0x03`, i.e. `0b1000_0011`.

## Test Vectors

Machine-checkable vectors are produced alongside the codec implementation and
checked into `qr-protocol/tests/`:

- `get_keys.json`: Get Keys request/response.
- `register_descriptor.json`: Register Descriptor request/response, each `FORM`.
- `address_verification.json`: Address Verification request/response.
- `signing.json`: Signing request and both response `KIND`s, including the MuSig2
  signatures-only entries (`SIG_KIND` `0x04` and `0x05`, with and without a leaf
  hash).
- `errors.json`: error responses (`STATUS` = `1`), standard and vendor codes,
  including `0x0D` (MuSig2 session).
- `versioning.json`: forward compatibility, a message whose `VERSION` is above 1
  and which carries trailing bytes a version-1 parser does not know.

Every file holds one JSON object with a single `vectors` array:

```json
{
  "vectors": [
    {
      "name": "get_keys_request_one_path",
      "description": "Get Keys request for the extended public key at m/48'/0'/0'/2', so a single KEY_REQUEST whose KIND is 0x00 (public). This is the worked example of the spec.",
      "direction": "request",
      "hex": "4249505858580101000101048000003080000000800000008000000200",
      "decode_only": false
    }
  ]
}
```

All five fields are mandatory:

- `name`: unique within the file. An implementation pairs each vector with the
  message it builds for it by this name.
- `description`: what the message contains, in plain words.
- `direction`: `request` or `response`, matching bit 7 of `MSG_TYPE`.
- `hex`: the complete `MESSAGE`, from the first `MAGIC` byte to the last body
  byte, as lowercase hex with no separators.
- `decode_only`: when `false`, the vector is a round trip: decoding `hex` yields
  the described message, and encoding that message yields `hex` byte for byte.
  When `true`, only the decoding direction holds, because an encoder writes the
  version it implements and cannot produce these bytes. The `versioning.json`
  vectors are the only ones that set it.

## Rationale

See footnotes for design rationale.

### Future extensions

Candidates for version 2+, added as appended fields:
- Per-input spend-path selection for multi-path miniscript policies in Signing.
- Registering multiple descriptors in one Register exchange.
