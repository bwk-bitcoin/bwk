```
  Title: Signing-flow message encoding in miniscript context
  Authors: Pyth <pythcoiner@wizardsardine.com>
  Status: Draft
  Type: Specification
  License: BSD-2-Clause
```

## Introduction

### Abstract

This document defines the byte encoding of the signing-flow messages exchanged
between a **wallet** (online software) and a **signer** (signing device) in the
miniscript context.

The encoding is **transport agnostic**: a `MESSAGE` is a self-contained byte
string, and how it is delivered (animated QR, USB, NFC, a file, a socket) is
out of scope.

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
valid UTF-8 and MUST NOT contain a nul byte.

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
  - `KEYS`: a vector of `STRING`, the key information, each a BIP-380 key
    expression. Entry `i` is the key that `@i` refers to in `POLICY`, so the
    vector MUST be in `@0`, `@1`, ... order.
  - `POLICY`: a `STRING`, the descriptor template with `@i` key placeholders.

- `0x03`: `FINGERPRINT` `SPEND_PATH` `SCAN_PATH` `SCAN_KEY`, a silent payment
  account's keys:
  - `FINGERPRINT`: the `FINGERPRINT` of the master key.
  - `SPEND_PATH`: a `DERIVATION_PATH`, the path of the BIP-352 spend key from the
    master key.
  - `SCAN_PATH`: OPTIONAL `DERIVATION_PATH`, the path of the BIP-352 scan key from
    the master key, when the scan key is the signer's.
  - `SCAN_KEY`: OPTIONAL, 32 bytes, the BIP-352 scan private key as a big-endian
    scalar, when the scan key is not the signer's.

  Exactly one of `SCAN_PATH` and `SCAN_KEY` MUST be present: a reader MUST reject
  the form when both or neither are.

`VENDOR`: `STRING`, the device vendor.

`MODEL`: `STRING`, the device model.

`VERSION`: in a response body, 8 bytes of device firmware version, `MAJOR` `MINOR`
`PATCH` `FLAG` (the message's protocol `VERSION` is defined under Encoding). `MAJOR`
and `MINOR` are 2-byte big-endian unsigned integers, `PATCH` is a 3-byte big-endian
unsigned integer, and `FLAG` is a 1-byte pre-release channel.

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
Bit 0 is the LSB.

```
+------+----------------------------------+
| Bit  | Capability                       |
+------+----------------------------------+
| 0    | Miniscript, SegWit v0            |
| 1    | Miniscript, Taproot (v1)         |
| 2    | Silent Payments (v0)             |
| 3    | MuSig2                           |
| 4    | MuSig cache                      |
| 5    | Nonce cache                      |
| 6–30 | Reserved for future capabilities |
| 31   | Upgrade signal (MSB)             |
+------+----------------------------------+
```

Bit 3 means the signer is a BIP-327 MuSig2 participant for BIP-390 `musig()` keys,
and MAY answer with `SIG_KIND` `0x04` / `0x05` (see Signing).

Bit 4 advertises the separate MuSig Preparation and MuSig Signing operations below.
It is not implied by bit 3.

Bit 5 advertises the Nonce Preparation operation below, and that a Signing `PSBT`
may name a cached nonce session for MuSig2, as the nonce cache BIP
(`bip-nonce-cache/BIP-DRAFT.md`) defines.

Bits 6–30 are reserved for future capabilities and MUST be `0` in this version; a
reader MUST ignore an unknown capability bit rather than reject, so a newer signer
can advertise capabilities an older wallet does not know. Bit 31 (the MSB) MUST be
`0` in this version; a `1` signals that the signer exposes capabilities beyond this
bitfield and the wallet should upgrade to interpret them.

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
| 0x01  | Get Info             |
| 0x02  | Get Keys             |
| 0x03  | Register Descriptor  |
| 0x04  | Address Verification |
| 0x05  | Signing              |
| 0x06  | MuSig Preparation    |
| 0x07  | MuSig Signing        |
| 0x08  | Nonce Preparation    |
+-------+----------------------+
```

Values `0x09`–`0x3F` are reserved. A parser MUST reject an unknown `TYPE`, and
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
`ERROR_MESSAGE`: `STRING`, the error description.

Global error table:

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
| 0x0D      | Session missing, consumed or mismatched              |
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

### Get Info

**Request** (`TYPE` = `0x01`, request):

The body is empty.

A signer answers it without user interaction, also when locked or without a seed.

**Ok response** (`TYPE` = `0x01`, response):

`VENDOR` `MODEL` `VERSION` `CAPABILITIES` `STATE` `NETWORKS` `MAX_MESSAGE` `MAX_ALIAS`
`MAX_KEYS` `SLOTS` `FINGERPRINT`

`VENDOR`, `MODEL`, `VERSION`, `CAPABILITIES`: the device fields defined in Common
Field Encodings.
`STATE`: 1-byte unsigned integer, whether the signer can serve a request now.

```
+-----------+---------------------------------------+
| Value     | State                                 |
+-----------+---------------------------------------+
| 0x00      | Ready: seed present, signer unlocked  |
| 0x01      | Locked: seed present, signer locked   |
| 0x02      | Uninitialized: no seed                |
| 0x03–0xFF | Reserved                              |
+-----------+---------------------------------------+
```

Values `0x03`–`0xFF` are reserved. A reader MUST treat an unknown `STATE` as not
ready rather than reject, so a newer signer can report a state an older wallet does
not know.

`NETWORKS`: 1-byte bitfield of the networks the signer signs for. Bit 0 is the LSB.

```
+-----+----------+
| Bit | Network  |
+-----+----------+
| 0   | Reserved |
| 1   | Mainnet  |
| 2   | Testnet  |
| 3   | Signet   |
| 4   | Regtest  |
| 5–7 | Reserved |
+-----+----------+
```

Bits 0 and 5–7 are reserved: they MUST be `0` when written, and a reader MUST
ignore them.

`MAX_MESSAGE`: 4-byte big-endian unsigned integer, the size in bytes of the largest
complete `MESSAGE` the signer accepts.
`MAX_ALIAS`: 1-byte unsigned integer, the length in bytes of the longest
`DESCRIPTOR_ALIAS` the signer stores. It MUST be at most 32, the `DESCRIPTOR_ALIAS`
bound, and a reader MUST reject a larger value.
`MAX_KEYS`: 1-byte unsigned integer, the most keys one descriptor or wallet policy
may hold on this signer.
`SLOTS`: 2-byte big-endian unsigned integer, the number of registrations the signer
can store. `0` means it stores none and relies on the proof of registration (`POR`)
alone.
`FINGERPRINT`: OPTIONAL, the `FINGERPRINT` of the master key. It is present only
when `STATE` is `0x00` (ready) and MUST be absent otherwise; a reader MUST reject a
response carrying it with any other `STATE`.

Fields added to this response later are appended after `FINGERPRINT`, so an older
reader ignores them as trailing bytes (see Versioning).

### Get Keys

**Request** (`TYPE` = `0x02`, request):

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

Note: a silent payment wallet needs the BIP-352 scan private key to scan. When the
scan key is the signer's, the wallet fetches it with `KIND` `0x01` at the scan key's
path. The spend key never needs to leave the signer.

**Ok response** (`TYPE` = `0x02`, response):

`KEYS` `FINGERPRINT` `VENDOR` `MODEL` `VERSION` `CAPABILITIES`

`KEYS`: a vector of `EXTENDED_KEY`, one per request `KEY_REQUEST` in the same
order, each of the `KIND` requested.
`FINGERPRINT`: the `FINGERPRINT` of the master key. Mandatory.
`VENDOR`, `MODEL`, `VERSION`, `CAPABILITIES`: the device fields defined in Common
Field Encodings. Mandatory.

### Register Descriptor

**Request** (`TYPE` = `0x03`, request):

`DESCRIPTOR_ALIAS` `DESCRIPTOR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
Mandatory.
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`. When absent, the request only queries the
registration status of `DESCRIPTOR_ALIAS`. At most one descriptor per request.

**Ok response** (`TYPE` = `0x03`, response):

`DESCRIPTOR_ALIAS` `REGISTERED` `STORED` `POR`

`DESCRIPTOR_ALIAS`: echoes the alias from the request.
`REGISTERED`: OPTIONAL `BOOL`, the registration status.
`STORED`: OPTIONAL `BOOL`, whether the device persisted the descriptor under
`DESCRIPTOR_ALIAS`. When `true`, a later request MAY reference the descriptor by
`DESCRIPTOR_ALIAS` alone. When `false` or absent, later requests carry the
`DESCRIPTOR_BODY`, together with the `POR` when the device issued one. `STORED`
and the presence of `POR` are independent.
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

A failed registration is reported as an error response (`STATUS` = `1`), not via a
body field.

### Address Verification

**Request** (`TYPE` = `0x04`, request):

`DESCRIPTOR_ALIAS` `DERIV` `ADDRESS` `DESCRIPTOR` `POR`

`DESCRIPTOR_ALIAS`: the alias the descriptor is registered under on the device.
`DERIV`: `DERIVATION_PATH`, the path under the descriptor.
`ADDRESS`: OPTIONAL `STRING`, the expected address (recommended).
`DESCRIPTOR`: OPTIONAL `DESCRIPTOR_BODY`, the full descriptor / wallet policy (for
stateless devices).
`POR`: OPTIONAL `BYTES`, a proof of registration (for stateless devices).

A silent payment address is verified with a `DESCRIPTOR` of `FORM` `0x03`
(silent payment keys) instead of a descriptor, with an optional `POR`:
- `DESCRIPTOR_ALIAS`: the alias the keys are registered under, or a display alias
  when they are not registered.
- `DERIV`: the BIP-352 label. Empty for the account's base address; one step `m`
  for the address labelled `m` (`m` ≥ 1, as label `0` is reserved for change).
- `ADDRESS`: the expected silent payment address.

The answer is a `URI` holding the address, or the error `0x08` when the address
differs from `ADDRESS`. It requires capability bit 2.

**Ok response** (`TYPE` = `0x04`, response):

`URI`

`URI`: OPTIONAL `STRING`, a BIP-21 payment URI for the verified address.

### Signing

**Request** (`TYPE` = `0x05`, request):

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

**Ok response** (`TYPE` = `0x05`, response):

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
- `0x01`: a `PSBT`.
- `0x02`: `SIGS`, a vector of `SIG_ENTRY`.

When the transaction has silent payment outputs, a `KIND` `0x02` answer MUST
contain, for each distinct scan key among those outputs, an ECDH share (`SIG_KIND`
`0x06`) and its BIP-374 DLEQ proof (`SIG_KIND` `0x07`), either global or one per
eligible input the signer signs, as BIP-375 lays them out, plus the usual
signatures. A signer that cannot provide them answers with `KIND` `0x01`. Output
scripts are not carried.

`SIG_ENTRY` follows this format:

`INPUT_INDEX` `SIG_KIND` `LENGTH` `KIND_FIELDS`

`INPUT_INDEX`: 4-byte big-endian unsigned integer, the input index.
`SIG_KIND`: 1-byte unsigned integer.
`LENGTH`: compact size, the byte length of `KIND_FIELDS`.

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
| 0x06      | sp ecdh share     |
| 0x07      | sp dleq proof     |
| 0x08–0xFF | Reserved          |
+-----------+-------------------+
```

`0x00` is reserved and MUST NOT be sent; `0x08`–`0xFF` are reserved for future
kinds. A reader MUST skip an entry whose `SIG_KIND` it does not know, reserved
values included, by reading past its `LENGTH` bytes, rather than reject the message.
`KIND_FIELDS` of a known `SIG_KIND` MUST fill its `LENGTH` exactly; a reader MUST
reject the message otherwise.

`KIND_FIELDS` depends on `SIG_KIND`:
- `0x01` segwit: `PUBLIC_KEY` `SIGNATURE`.
  - `PUBLIC_KEY`: 33 bytes, the compressed public key that produced the
    signature.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_PARTIAL_SIG` (`0x02`)
    entry keyed by `PUBLIC_KEY`: a DER-encoded ECDSA signature followed by its
    sighash type byte.
- `0x02` tapkey: `SIGNATURE`.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_TAP_KEY_SIG` (`0x13`)
    field: a 64-byte BIP-340 signature, or 65 bytes with a sighash type byte. A
    reader MUST reject any other length.
- `0x03` taptree: `XONLY_PUBLIC_KEY` `TAP_LEAF_HASH` `SIGNATURE`.
  - `XONLY_PUBLIC_KEY`: 32 bytes.
  - `TAP_LEAF_HASH`: 32 bytes.
  - `SIGNATURE`: `BYTES`, the value of the input's `PSBT_IN_TAP_SCRIPT_SIG`
    (`0x14`) entry keyed by `XONLY_PUBLIC_KEY` and `TAP_LEAF_HASH`: 64 or 65 bytes
    as for `0x02`.
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
- `0x06` sp ecdh share: `GLOBAL` `SCAN_KEY` `SHARE`.
  - `GLOBAL`: `BOOL`, `true` when the share covers every eligible input of the
    transaction, `false` when it covers the input at `INPUT_INDEX` only.
  - `SCAN_KEY`: 33 bytes, the compressed scan key of the recipient the share is for.
  - `SHARE`: 33 bytes, the compressed ECDH share point.

  Together they are the key and value of the BIP-375 `PSBT_GLOBAL_SP_ECDH_SHARE`
  (`0x07`) field when `GLOBAL` is `true`, of the input's `PSBT_IN_SP_ECDH_SHARE`
  (`0x1d`) field when it is `false`.
- `0x07` sp dleq proof: `GLOBAL` `SCAN_KEY` `PROOF`.
  - `GLOBAL`, `SCAN_KEY`: as for `0x06`.
  - `PROOF`: 64 bytes, no `LENGTH`, the BIP-374 DLEQ proof of the share for the
    same `GLOBAL`, `INPUT_INDEX` and `SCAN_KEY`.

  Together they are the key and value of the BIP-375 `PSBT_GLOBAL_SP_DLEQ` (`0x08`)
  field when `GLOBAL` is `true`, of the input's `PSBT_IN_SP_DLEQ` (`0x1e`) field
  when it is `false`.

When `GLOBAL` is `true`, `INPUT_INDEX` MUST be `0`, and a reader MUST reject any
other value. `GLOBAL` is a field of its own rather than a reserved `INPUT_INDEX`
value, as every input index is a valid one.

In one response, a scope (global, or one input) and `SCAN_KEY` with a `0x06` or
`0x07` entry MUST have exactly one of each, and a reader MUST reject a share
without its proof, a proof without its share, or a duplicate of either.

#### MuSig2

A MuSig2 signer takes part in two Signing exchanges on the same transaction. Its
first answer carries its public nonces only (`SIG_KIND` `0x04` entries, or in the
PSBT with `KIND` `0x01`), and no signature of any kind. Its second answer carries
its partial signatures (`SIG_KIND` `0x05` entries, or in the PSBT) and its ordinary
signatures (`SIG_KIND` `0x01` to `0x03`). A session missing, consumed or mismatched
on the second exchange is refused with `ERROR` `0x0D`.

#### Nonce cache

For a signer advertising capability bit 5, a Signing `PSBT` MAY name a cached nonce
session as the nonce cache BIP (`bip-nonce-cache/BIP-DRAFT.md`) defines. There is no
separate signing `TYPE`: the resulting partial signatures are ordinary `SIG_KIND`
`0x05` entries, or partial signatures in the PSBT. A session missing, consumed or
mismatched is refused with `ERROR` `0x0D`.

### MuSig Preparation

This operation requires capability bit 4 and has `TYPE` `0x06`. It prepares public
nonces without a transaction, PSBT, sighash or attempt ID. It does not change the
ordinary Signing operation. No secret nonce, root or encrypted secret export may
appear in these messages.

**Request:**

`DESCRIPTOR` `SESSION_ID` `MAX_INPUTS` `DERIVATIONS`

- `DESCRIPTOR`: the single `DESCRIPTOR` entry defined under Signing, including its
  alias, optional descriptor body and optional proof.
- `SESSION_ID`: 32 opaque bytes chosen by the caller, with no length prefix.
- `MAX_INPUTS`: one byte, the absolute input coverage, at least 1.
- `DERIVATIONS`: a non-empty vector of distinct `MUSIG_DERIVATION` entries.
  Each entry is `KEYCHAIN` `INDEX`, both 4-byte big-endian unsigned integers.
  `KEYCHAIN` selects the descriptor's public derivation branch. `INDEX` MUST be
  below `0x80000000`, so no hardened child index is accepted. Uniqueness uses both
  fields.

**Ok response:**

`SESSION_ID` `MAX_INPUTS` `NONCES`

`SESSION_ID` and `MAX_INPUTS` echo the request. `NONCES` is a nonempty vector with
at most 4096 entries. Each entry is:

`DERIVATION` `INPUT_INDEX` `EXPRESSION_INDEX` `PARTICIPANT` `AGGREGATE` `LEAF_HASH` `NONCE`

- `DERIVATION`: a `MUSIG_DERIVATION` as above.
- `INPUT_INDEX`: a 4-byte big-endian unsigned integer below `MAX_INPUTS`. The vector
  MUST include every input index from zero through `MAX_INPUTS` minus one.
- `EXPRESSION_INDEX`: a 4-byte big-endian unsigned integer identifying the occurrence
  of the MuSig expression in the descriptor, not just the resulting aggregate key.
- `PARTICIPANT`, `AGGREGATE`, `LEAF_HASH`: the compressed keys and optional 32-byte
  leaf hash defined for ordinary MuSig public nonces.
- `NONCE`: 66 public nonce bytes, without a length prefix.

Entries MUST be unique by derivation, input index, expression index, participant,
aggregate and leaf hash.

### MuSig Signing

This operation requires capability bit 4 and has `TYPE` `0x07`.

**Request and ok response:**

`SESSION_ID` `ATTEMPT_ID` `PSBT`

`SESSION_ID` selects the prepared cache session. `ATTEMPT_ID` is an independent
caller-chosen 32-byte opaque identifier. Both have no length prefix, and the
response echoes both. `PSBT` is a bounded `BYTES` field, carried without parsing,
and may contain serialized PSBT v0 or v2. There is no response-kind selector.

Missing, consumed, lost or mismatched sessions refuse with `ERROR` `0x0D`.

### Nonce Preparation

This operation requires capability bit 5 and has `TYPE` `0x08`. It prepares public
nonces for a cached nonce session, bound to no descriptor, for use by later Signing
exchanges as the nonce cache BIP (`bip-nonce-cache/BIP-DRAFT.md`) defines. No root,
secret nonce or other secret material may appear in these messages.

`MAX_NONCE_EXPRESSIONS` is 16.

**Request:**

`SESSION_ID` `SESSION_REF` `MAX_INPUTS` `DERIVATION_PATH` `START` `END`

- `SESSION_ID`: 4 opaque bytes chosen by the caller, with no length prefix.
- `SESSION_REF`: OPTIONAL, 4 bytes, the session reference the nonce cache BIP
  defines, from an earlier answer for this `SESSION_ID`.
- `MAX_INPUTS`: one byte, the absolute input coverage, at least 1.
- `DERIVATION_PATH`: the key's path from the master key.
- `START`: a 4-byte big-endian unsigned integer, the first key expression index.
- `END`: a 4-byte big-endian unsigned integer, the last key expression index.

`START` MUST NOT exceed `END`, and the range `START` through `END` MUST hold at most
`MAX_NONCE_EXPRESSIONS` indexes. The range lets the wallet fetch a session in
chunks.

A signer MUST refuse a request whose `SESSION_REF` does not match its stored session
for `SESSION_ID`, or names a session it does not hold, with `ERROR` `0x0D`, and MUST
NOT create a new session for it.

**Ok response:**

`SESSION_ID` `SESSION_REF` `MAX_INPUTS` `START` `END` `NONCES`

`SESSION_ID`, `MAX_INPUTS`, `START` and `END` echo the request, with the same
bounds. `SESSION_REF` is 4 bytes, always present, the reference of the session that
issued the nonces. `NONCES` is a vector of exactly (`END` minus `START` plus 1) times
`MAX_INPUTS` entries, each a 66-byte BIP-327 public nonce without a length prefix.

Entries are positional, ordered by key expression index then by input index: the
nonce for key expression index `j` and input index `i` is entry
(`j` minus `START`) times `MAX_INPUTS` plus `i`.

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
  `PRESENCE` outside `{0x00, 0x01}`, a discriminant (`TYPE`, `FORM`, `KIND`)
  outside its defined range, `STATUS` = `1` on a request, a `STRING` that is not
  valid UTF-8 or that contains a nul byte, or a `FORM` `0x03` body with both or
  neither of `SCAN_PATH` and `SCAN_KEY`.
- `SIG_KIND` is not such a discriminant: a reader skips an entry whose `SIG_KIND`
  it does not know. It MUST reject a `SIG_ENTRY` of a known `SIG_KIND` whose
  `KIND_FIELDS` do not exactly fill its `LENGTH`, a `SIG_KIND` `0x02` or `0x03`
  `SIGNATURE` that is not 64 or 65 bytes, a global silent payment entry whose
  `INPUT_INDEX` is not `0`, and an ECDH share and DLEQ proof that do not pair up
  (Signing).
- `STATE` is not such a discriminant either: a reader treats an unknown `STATE` as
  not ready. It MUST reject a Get Info response whose `MAX_ALIAS` is above 32, or
  that carries `FINGERPRINT` while `STATE` is not `0x00` (Get Info).
- Trailing bytes after the final field a parser understands are NOT an error
  (Versioning).

### Parser limits

Recommended bounds for a parser:

```
+----------------+---------------+
| Field          | Bound         |
+----------------+---------------+
| `BYTES`        | 512 KiB       |
| `STRING`       | 64 KiB        |
| vector `COUNT` | 4096 elements |
+----------------+---------------+
```

The `BYTES` bound also applies to the `LENGTH` of a `SIG_ENTRY`. A parser MAY use
different bounds.

## Test Vectors

Machine-checkable vectors accompany this specification:

- `get_info.json`: Get Info request, an ok response from a ready signer with its
  `FINGERPRINT`, and one from a locked signer without it.
- `get_keys.json`: Get Keys request/response.
- `register_descriptor.json`: Register Descriptor request/response, each `FORM`.
- `address_verification.json`: Address Verification request/response, including a
  silent payment address with the signer's own scan key (`SCAN_PATH`), the same
  with a `POR`, and a labelled one with a scan key it does not hold (`SCAN_KEY`).
- `signing.json`: Signing request and both response `KIND`s, including the MuSig2
  signatures-only entries (`SIG_KIND` `0x04` and `0x05`, with and without a leaf
  hash), a silent payment send answered with a global ECDH share and DLEQ proof and
  one answered with per-input ones (`SIG_KIND` `0x06` and `0x07`), and an entry of
  an unknown `SIG_KIND` that a reader skips.
- `musig.json`: MuSig Preparation and MuSig Signing request/response, including a
  preparation request with only an alias and nonce entries with and without a leaf
  hash.
- `nonce_cache.json`: Nonce Preparation request/response.
- `errors.json`: error responses (`STATUS` = `1`), standard and vendor codes,
  including `0x0D` (session).
- `versioning.json`: forward compatibility, a message whose `VERSION` is above 1
  and which carries trailing bytes a version-1 parser does not know.

Every file holds one JSON object with a single `vectors` array:

```json
{
  "vectors": [
    {
      "name": "get_keys_request_one_path",
      "description": "Get Keys request for the extended public key at m/48'/0'/0'/2', so a single KEY_REQUEST whose KIND is 0x00 (public).",
      "direction": "request",
      "hex": "4249505858580102000101048000003080000000800000008000000200",
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
