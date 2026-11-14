```
  BIP: ?
  Layer: Applications
  Title: One-round anti-exfil signing from cached nonces
  Authors: Pyth <pythcoiner@wizardsardine.com>
  Status: Draft
  Type: Specification
  License: BSD-2-Clause
  Requires: 32, 174, 327, 340
```

## Introduction

### Abstract

This BIP defines one-round anti-exfil signing. The signer's nonce commitment is a
nonce of the nonce cache BIP, issued before the transaction exists. At signing time
the coordinator sends fresh coordinator entropy $t$ with the PSBT, the signer
combines its two cached nonces with a coefficient bound to $t$ and to the message,
and the coordinator checks that every signature uses the combined nonce.

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the above copyright notice and this permission notice appear
in all copies.

### Motivation

A signing device chooses its nonces. A malicious or faulty device can bias them to
leak its secret key through signatures that look valid, with ECDSA as with BIP-0340.
Anti-exfil (sign-to-contract with host randomness, implemented for ECDSA in
libsecp256k1-zkp) makes the final nonce depend on randomness the device cannot
predict, and lets the host check it.

That protocol needs two round trips per signature:

1. The host sends a commitment to its randomness $\rho$.
2. The device answers with its nonce commitment $R_0$.
3. The host reveals $\rho$.
4. The device answers with the signature.

Over QR codes each round trip is one or more scans by the user, which makes
anti-exfil impractical on air-gapped devices. This BIP moves step 2 ahead of time:
the nonce commitment is a cached nonce, and signing takes one round.

### Expected properties

* **One round**: the nonce commitment is issued before the transaction exists.
* **Signature-agnostic**: only the nonce changes, so any signature scheme where the
  signer picks a nonce point works, ECDSA and BIP-0340 included.
* **Coordinator-verifiable**: the coordinator checks the nonce of each signature.
* **Single use**: each cached nonce signs at most once, by the signing rules of the
  nonce cache BIP.

### Scope

This BIP covers single-key signatures, ECDSA and BIP-0340 alike. Sessions, issuance,
`PSBT_GLOBAL_NONCE_CACHE_SESSION` and the signing rules are those of the nonce cache
BIP.

## Specification

Notation, in addition to the nonce cache BIP's:

- $n$ is the secp256k1 group order and $G$ its generator.
- int($x$) is the 32-byte array $x$ as a big-endian unsigned integer.
- x($P$) is the x coordinate of $P$ as an integer.

### Nonce

For the signature of input $i$ by the signer's key $pk$ at key expression $j$, let
$k_1$, $k_2$ be the secret scalars and $R_1$, $R_2$ the points of the nonce cache
nonce for ($i$, $j$, $pk$). The coordinator learns $pubnonce$ = $R_1$ | $R_2$ through
the nonce cache issuance.

### Signing

- Let $m$ be the 32-byte message the signature commits to, for example the BIP-0143
  or BIP-0341 sighash.
- Let $t$ be the 32-byte coordinator entropy.
- Let $b$ = int(tagged_hash("BIPXXXX_NONCE_COEF", $pubnonce$ | $pk$ | $m$ | $t$)) mod
  $n$
- Let $k$ = $(k_1 + b \cdot k_2) \bmod n$. Fail if $k = 0$.

The signer signs with $k$ as its nonce, following the input's signature scheme as
usual, normalizations included. The signature's nonce point then has the x coordinate
x($R_1 + b \cdot R_2$), which the coordinator computes from $pubnonce$, $pk$, $m$ and
$t$.[^coef] [^normalization]

A failure happens with negligible probability, after the session is deleted. The
signer refuses the request and the coordinator retries with a new session.

[^coef]: **Why one coefficient bound to $t$ and $m$?**
    $t$ makes $b$, and so the nonce point, unknown to the device when it issued
    $R_1$, $R_2$, so it cannot bias the nonce. $m$ and $t$ make the nonce point
    change unpredictably whenever the coordinator changes either, as the BIP-0327
    nonce coefficient does, which defeats ROS and Wagner forgeries (see
    [Security](#security)).

[^normalization]: **Why do normalizations keep the check valid?**
    ECDSA low-S negates $s$, and BIP-0340 negates $k$ when the nonce point has an odd
    y. Neither changes the x coordinate of the nonce point.

### PSBT field

| Name       | `<keytype>` | `<keydata>`              | `<valuedata>` |
|:-----------|:------------|:-------------------------|:--------------|
| Anti-exfil | 0x21        | keydata of the signature | $t$ (32)      |

`PSBT_IN_ANTI_EXFIL` is a per-input field. Its keydata is the keydata of the field
the signature goes in, for example the public key of
`PSBT_IN_PARTIAL_SIG`.[^keyed-like-sig]

[^keyed-like-sig]: **Why key it like the signature?**
    The coordinator entropy belongs to one signature. Keying it like the signature
    field puts it next to the signature it governs.

### Signer rules

The signing rules of the nonce cache BIP apply. A PSBT carrying `PSBT_IN_ANTI_EXFIL`
MUST carry `PSBT_GLOBAL_NONCE_CACHE_SESSION`.

For each `PSBT_IN_ANTI_EXFIL` of input $i$, the signer finds $j$ for its key at input
$i$ in the descriptor it signs for. After the session deletion, it signs as in
[Signing](#signing) and releases each signature in its usual field. It MUST NOT sign
such an input with a plain nonce.[^no-plain]

[^no-plain]: **Why forbid a plain signature?**
    A device that silently signs plainly would defeat anti-exfil while looking
    normal. The coordinator check catches it, but the rule keeps an honest device
    from producing such a signature at all.

### Coordinator rules

The coordinator rules of the nonce cache BIP apply. The coordinator:

- MUST draw $t$ as 32 random bytes after it received the $pubnonce$ it pairs with,
  and MUST NOT use that $t$ with any other $pubnonce$.[^freshness]
- MUST verify every signature, and check that the x coordinate of its nonce point is
  x($R_1 + b \cdot R_2$). If one check fails, it MUST reject the whole attempt.
- MAY send a session again with the same $t$ for each $pubnonce$ after an attempt
  refused before the session was deleted, for example rejected at review.

[^freshness]: **Why draw $t$ after the $pubnonce$?**
    With $t$ random and chosen after $R_1$, $R_2$ are fixed, $b$ is uniform, and so
    is $R_1 + b \cdot R_2$, whatever $R_1$ and $R_2$ the device picked ($R_2$ is
    never the point at infinity in a valid BIP-0327 $pubnonce$). A device that knew
    $t$ before issuing could grind its nonces to bias the result.

## Rationale

See footnotes throughout the specification for design rationale.

### No host commitment

In the libsecp256k1-zkp protocol the device is stateless. The host commitment
tagged_hash("s2c/ecdsa/data", $\rho$) is the extra data of RFC 6979, so $k_0$ is
deterministic for one $\rho$ and unique across them, and the device commits to $R_0$
before it learns $\rho$.

Here the nonce commitment is fixed at issuance, before $t$ exists, and single use
makes each cached nonce sign at most once. Both jobs of the commitment are done
without it, which removes a round trip.

### Security

The scheme protects against two parties: a device that tries to leak its key through
its nonces, and a coordinator that tries to forge or to extract the key.

**Exfiltration.** The device fixes $R_1$ and $R_2$ at issuance. $t$ is uniform and
drawn afterwards, so $b$ is uniform and unknown to the device, and the nonce point
$R_1 + b \cdot R_2$ is uniform whatever nonces the device chose. The device can only
refuse to sign when the nonce point does not suit it. Each abort costs a session and
gives the device one more draw, leaking little per draw. The libsecp256k1-zkp
protocol counters this by retrying with the same $\rho$; a deleted session cannot be
retried.

**Forgery by the coordinator.** The coordinator sees cached nonces before it chooses
the messages, and can keep many sessions outstanding. With a single nonce per
signature, as in libsecp256k1-zkp, that allows ROS and Wagner attacks: after $\ell$
signatures on messages chosen adaptively, the coordinator forges one more. The cost
is about $2^{256/(1 + \log_2 \ell)}$ operations, practical for a few dozen sessions,
and polynomial past about 256. Here, any change of $m$ or $t$ changes $b$ and moves
the nonce point unpredictably, as in BIP-0327. For BIP-0340 the construction is
single-signer BIP-0327 with $t$ added to the coefficient hash, and its security
argument carries over. For ECDSA it is a message-bound re-randomization of a
presignature, the countermeasure known for ECDSA with presignatures.

**Nonce reuse.** Each cached nonce MUST sign at most once. Two or three signatures
with one $k_1$, $k_2$ give linear equations in $k_1$, $k_2$ and $d$ that reveal the
secret key $d$, since $b$ is public. The signing rules prevent this.

These arguments are informal and need review by cryptographers.

| Threat                                          | Outcome                                                         |
|:------------------------------------------------|:----------------------------------------------------------------|
| Device biases its nonces                        | Defeated: the nonce point is uniform given $t$.                 |
| Device ignores $t$, or signs plainly            | Coordinator check fails, attempt rejected.                      |
| Device aborts selectively                       | Bounded leak per abort.                                         |
| Coordinator chooses messages after many nonces  | Defeated: $b$ binds $m$ and $t$ to the nonce point.             |
| Coordinator reuses a session with new $t$       | Refused: the session is deleted.                                |
| Coordinator names an unknown session            | Refused.                                                        |
| Crash after deletion, before release            | Session lost, no leak.                                          |

### Implementation

- Coordinator: a standard signature verification, one scalar multiplication and one
  point addition.
- Signer: the libsecp256k1-zkp signer API derives its nonce with RFC 6979 and cannot
  take an external one. A signer needs a signing primitive that takes its nonce from
  the caller.
- Transport: the bwk QR signing protocol, "Nonce Preparation" message
  (`qr-protocol/ENCODING.md`).

### Test Vectors

Planned vectors:

- $b$, $k$ and a signature for a given $pubnonce$, $pk$, $m$, $t$ and key, for ECDSA
  (including a low-S case) and BIP-0340 (including an odd-y nonce point, on the key
  path and a script path).
- `PSBT_IN_ANTI_EXFIL` serialization for each keydata form.
- Refusal cases: coordinator entropy without a session field, unknown session, used
  session.
- A plain signature for an input with the field, failing the coordinator check.

## Backward Compatibility

Signatures are ordinary signatures in their usual fields. A signer that does not know
`PSBT_IN_ANTI_EXFIL` ignores it and signs plainly, and the coordinator check then
fails. A coordinator SHOULD send the field only to signers known to support it.

## Acknowledgements

The nonce coefficient follows BIP-0327. This BIP replaces the two-round anti-exfil
protocol of the libsecp256k1-zkp `ecdsa_s2c` module.
