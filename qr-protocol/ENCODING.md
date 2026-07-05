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
miniscript context: Get Xpubs, Register Descriptor, Address Verification,
Signing, Get SP Descriptor and their exact byte layout. It is the
authoritative byte-level contract two implementations must agree on.

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

`XPUB`: 78 bytes, the BIP-32 extended public key serialization (4 version +
1 depth + 4 parent fingerprint + 4 child number + 32 chain code + 33 key).

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
+-------+-----------------------+
```

`BODY` depends on `FORM`:
- `0x01`: a `STRING`, the BIP-380 descriptor text.
- `0x02`: `KEYS` `POLICY`, the BIP-388 wallet policy. BIP-388 defines no byte
  encoding, so it is serialized here as its two components:
  - `KEYS`: a vector of `STRING`, the key information, each a BIP-380 key expression
    referenced by `@0`, `@1`, ... in `POLICY`.
  - `POLICY`: a `STRING`, the descriptor template with `@i` key placeholders.

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
| 0x01  | Get Xpubs            |
| 0x02  | Register Descriptor  |
| 0x03  | Address Verification |
| 0x04  | Signing              |
| 0x05  | Get SP Descriptor    |
+-------+----------------------+
```

Values `0x06`–`0x3F` are reserved. A parser MUST reject an unknown `TYPE`, and
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
| 0x0C–0xFE | Reserved for future standard codes                   |
| 0xFF      | Vendor-specific (meaning carried by `ERROR_MESSAGE`) |
+-----------+------------------------------------------------------+
```

`0x00` is reserved and MUST NOT be sent. `0x01`–`0x0B` are the standard codes above;
`0x0C`–`0xFE` are reserved for future standard codes. `0xFF` is vendor-specific: the
code alone is not meaningful, so `ERROR_MESSAGE` carries the description. A receiver
MUST NOT reject an unrecognized `ERROR`; `STATUS` = `1` already denotes an error,
and it SHOULD fall back to `ERROR_MESSAGE`.

#### Body

For an ok response (`STATUS` = `0`) and for requests, `BODY` is the type's
fields below, in listed order. Fields are ordered by the version in which they were
introduced (see Versioning); within a version they appear in listed order.

The message definitions below give each type's request body and ok response
body.

### Get Xpubs

**Request** (`TYPE` = `0x01`, request):

`PATHS`

`PATHS`: a vector of `DERIVATION_PATH`, the paths to derive xpubs at.

**Ok response** (`TYPE` = `0x01`, response):

`XPUBS` `FINGERPRINT` `MODEL` `VERSION` `CAPABILITIES`

`XPUBS`: a vector of `XPUB`, in the same order as the request `PATHS`.
`FINGERPRINT`: the `FINGERPRINT` of the master key. Mandatory.
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
+-----------+------------+
| Value     | Definition |
+-----------+------------+
| 0x00      | Reserved   |
| 0x01      | segwit     |
| 0x02      | tapkey     |
| 0x03      | taptree    |
| 0x04–0xFF | Reserved   |
+-----------+------------+
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

The key material travels with the signature because the coordinator inserts each
signature into its PSBT keyed by those values. No control block is sent: the
coordinator rebuilds it from the descriptor at finalize time.

Spending an output received via silent payments is an ordinary taproot key-path
spend, so `0x02` (tapkey) already covers it.

### Get SP Descriptor

**Request** (`TYPE` = `0x05`, request):

The request body is empty.

**Ok response** (`TYPE` = `0x05`, response):

`DESCRIPTOR`

`DESCRIPTOR`: a `STRING` holding a BIP-392 `sp()` descriptor. The scan key must be
private because a wallet needs it to detect incoming silent payments, while the
spend key may be public.

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

Get Xpubs request, one path `m/48'/0'/0'/2'`:
```
42 49 50 58 58 58    MAGIC "BIPXXX"
01                   VERSION = 1
01                   MSG_TYPE: request, ok, TYPE 0x01 (Get Xpubs)
00 01                REQUEST_ID (2 bytes)
01                   PATHS: vector count = 1
04                   CHILD_COUNT = 4
80 00 00 30          48' = 0x80000030 (big-endian)
80 00 00 00          0'  = 0x80000000
80 00 00 00          0'  = 0x80000000
80 00 00 02          2'  = 0x80000002
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

- `get_xpubs.json`: Get Xpubs request/response.
- `register_descriptor.json`: Register Descriptor request/response, each `FORM`.
- `address_verification.json`: Address Verification request/response.
- `signing.json`: Signing request and both response `KIND`s.
- `get_sp_descriptor.json`: Get SP Descriptor request/response.
- `errors.json`: error responses (`STATUS` = `1`), standard and vendor codes.
- `versioning.json`: forward compatibility, a message whose `VERSION` is above 1
  and which carries trailing bytes a version-1 parser does not know.

Every file holds one JSON object with a single `vectors` array:

```json
{
  "vectors": [
    {
      "name": "get_xpubs_request_one_path",
      "description": "Get Xpubs request with a single path m/48'/0'/0'/2'. This is the worked example of the spec.",
      "direction": "request",
      "hex": "4249505858580101000102030405060708090a0b0c0d0e0f010480000030800000008000000080000002",
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
