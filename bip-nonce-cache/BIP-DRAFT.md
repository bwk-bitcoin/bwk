```
  BIP: ?
  Layer: Applications
  Title: Signer nonce cache sessions for one-round signing
  Authors: Pyth <pythcoiner@wizardsardine.com>
  Status: Draft
  Type: Specification
  License: BSD-2-Clause
  Requires: 32, 174, 327, 340, 373
```

## Introduction

### Abstract

This BIP lets a signing device issue public nonces before a transaction exists, then
sign a PSBT that uses them in a single round.

The device keeps a few **sessions**. Each session holds a random secret and serves
one PSBT signing. Nonces derive from that secret, the input index, the key expression
index and the signer's key only. The session is deleted before any signature leaves
the device.

This BIP defines the session, the nonce derivation, the issuance exchange, a PSBT
field naming the session, the signing rules, and their use for MuSig2 (BIP-0327).

### Copyright

This BIP is licensed under the BSD 2-Clause License.  
Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the above copyright notice and this permission notice appear
in all copies.

### Motivation

BIP-0327 needs two rounds per signature: nonces, then partial signatures. For a
signer reached over QR codes or another manual channel, each round is one or more
scans by the user.

The cost is worst for MuSig2 with keys kept in different places, for example one
person holding cosigner devices in several countries. No cosigner can sign before
every cosigner's nonce is known, so each device must be visited twice per
transaction: once for its nonce, once for its partial signature. Each visit can mean
a trip, a plane ride in the worst case. With nonces issued during a previous visit, a
single round of visits signs, and can sign several transactions at once.

The first round does not need the transaction: BIP-0327 allows nonce generation
before the message is known. A device that can issue nonces early and keep them until
their single use signs in one round.

The Ledger Bitcoin app already does this for MuSig2, with a random secret per
session. Its session id hashes the wallet policy, and its nonces commit to the
aggregate key and to an index within the policy. This BIP keeps the session model and
drops every policy binding.

### Expected properties

* **One round**: nonces are issued before the transaction exists, signing takes a
  single exchange.
* **Policy-agnostic**: one issuance serves any descriptor where the key sits at the
  issued key expression index.
* **Single use**: a session is deleted before any signature that uses it leaves the
  signer.
* **Small state**: the sessions are the signer's whole state.

### Scope

This BIP defines the nonce cache and its MuSig2 use. Other signing schemes MAY use
the cache, under the [signing rules](#signing-rules).

## Specification

Notation:

- tagged_hash(tag, m) = sha256(sha256(tag) | sha256(tag) | m) is the tagged hash
  construction from [BIP340](bip-0340.mediawiki#design).
- ser32($i$) is the 4-byte big-endian serialization of the 32-bit unsigned integer
  $i$, as in BIP-0032.
- | is byte concatenation.

### Sessions

The signer keeps sessions. A session holds:

- `session_id`: 4 bytes chosen by the coordinator.
- $secret$: 32 bytes drawn from the signer's random number generator.[^hardware-rng]

$secret$ MUST NOT be derived from the seed or from any key, and MUST NOT be exported,
displayed or included in any backup.

The number of sessions is implementation-defined. When it is reached, storing a new
session evicts the oldest one. At most one session holds a given `session_id`.

A session serves one transaction: every input and every key of one PSBT
signing.[^one-session-per-tx]

[^hardware-rng]: **Why not derive the secret from the seed?**
    Two devices restored from one seed would derive the same nonces with separate
    session states, and could sign twice with one nonce. A random secret also means
    no session survives a restore from seed.

[^one-session-per-tx]: **Why one session per transaction?**
    Using the whole session in one signing keeps the rule simple: one session, one
    PSBT. The signer does not track which nonces of a session are used, and no
    partial state survives a signing.

### Key expression index

- Let $E_0, E_1, \dots, E_m$ be the key expressions of the descriptor that hold one
  of the signer's keys, in the order they appear in the descriptor.
- Let $j$ be the index of a key expression in that list.

Key expressions holding none of the signer's keys are external and not counted. A
`musig()` expression counts as a single key expression, held by the signer if one of
its participant keys is.

The order is the order of appearance:

- `tr(K, TREE)`: the internal key `K` first, then the keys of the script tree, leaf
  by leaf in depth-first order, left to right, and within each leaf in the order of
  the leaf's script.
- any other descriptor: the keys in the order they are written.

### Nonce derivation

- Let $secret$ be the session secret.
- Let $i$ be the index of the input in the PSBT, starting at 0.
- Let $j$ be the [key expression index](#key-expression-index) of the signing key.
- Let $pk$ be the signer's 33-byte compressed public key at key expression $j$ for
  input $i$, and $sk$ its secret key. For a `musig()` expression, $pk$ is the
  signer's participant key, as keyed in BIP-0373.
- Let $seed$ = tagged_hash("BIPXXXX_NONCE_SEED", $secret$ | ser32($i$) | ser32($j$))
- Let ($secnonce$, $pubnonce$) = NonceGen($sk$, $pk$, $seed$) as defined in BIP-0327,
  with $seed$ used as $rand'$, and $aggpk$, $msg$ and $extra\_in$
  omitted.[^nonce-gen]

$pubnonce$ is the 66-byte $R_1$ | $R_2$, and $k_1$, $k_2$ are the secret scalars of
$secnonce$.

The nonce MUST depend only on $secret$, $i$, $j$, $sk$ and $pk$. It MUST NOT commit
to the descriptor, the wallet policy, the aggregate key, the cosigner set or the
transaction.[^no-policy-binding] [^sk-pk] [^position]

The signer never stores $secnonce$: it recomputes it from $secret$ when it signs.

[^nonce-gen]: **Why these NonceGen inputs?**
    $seed$ replaces the random $rand'$ so the signer can recompute $secnonce$ instead
    of storing it. $aggpk$ would bind the aggregate key, $msg$ does not exist at
    issuance, and $extra\_in$ would add a binding. As in BIP-0327 CounterNonceGen,
    $rand'$ is not drawn at each call, so $sk$ is required and security rests on each
    $seed$ being used for at most one signature.

[^no-policy-binding]: **Why no policy binding?**
    One issuance then serves any descriptor where the key sits at index $j$: the
    coordinator does not need to know which wallet it will spend from when it issues,
    and the signer keeps no per-policy state. A binding protects nothing that single
    use does not: a nonce is dangerous only if it signs twice, and deleting the
    session before release rules that out, whatever the policy.

[^sk-pk]: **Why mix in $sk$ and $pk$?**
    Someone who steals $secret$ still cannot compute a secret nonce without $sk$. A
    nonce made for one key cannot sign for another: BIP-0327 Sign refuses a
    $secnonce$ whose $pk$ is not the signing key's. Two keys of the signer at the
    same ($i$, $j$) get different nonces.

[^position]: **Why index by input and key expression?**
    ($i$, $j$) is the smallest position naming one signature within one transaction.
    Indexing by position, not by content, lets a session be issued before the
    transaction exists.

### Issuance

Request:

- `session_id`: 4 bytes.
- $ref$: optional, the session reference returned by a previous issuance.
- $N$: the number of inputs, at least 1.
- $path$: a BIP-0032 derivation path from the master key.
- $start$, $end$: the range of key expression indexes, $start \leq end$.

Answer:

- $ref$ = the first 4 bytes of tagged_hash("BIPXXXX_SESSION_REF", $secret$)
- for each $i$ from 0 to $N - 1$ and each $j$ from $start$ to $end$, the $pubnonce$
  for ($i$, $j$, $pk$), $pk$ being the public key at $path$.[^range]

[^range]: **Why a range?**
    The answer grows with $N$ times the number of key expressions. A range lets the
    coordinator fetch it in chunks over a small channel.

The signer:

- MUST, if a session holds `session_id`, recompute the nonces from its $secret$, so
  the same ($i$, $j$, $pk$) always gives the same $pubnonce$.
- MUST, if the request carries $ref$, refuse it unless the session holding
  `session_id` has that $ref$.[^ref]
- MUST otherwise draw a new $secret$ and store a new session.
- MUST store the session durably before it releases the answer.

Issuing an existing `session_id` again with another $N$, range or $path$ returns
nonces of the same session. The coordinator MUST send $ref$ when it extends a session
it already holds nonces of.

[^ref]: **Why a session reference?**
    Between two chunks, the session can be evicted, for example by another
    coordinator issuing many sessions. Without $ref$, the next chunk would silently
    come from a new $secret$ and not match the nonces the coordinator already holds.
    $ref$ only detects such a mismatch and protects no secret, so 4 bytes are enough.

The transport defines how the request and answer are encoded, and MAY limit $N$ and
the range.

### PSBT field

| Name                     | `<keytype>` | `<keydata>` | `<valuedata>`                      |
|:-------------------------|:------------|:------------|:-----------------------------------|
| Nonce cache session      | 0x09        | none        | `session_id` (4) \| $ref$ (4)      |

`PSBT_GLOBAL_NONCE_CACHE_SESSION` is a global field.

### Signing rules

These rules apply to every use of the cache. When a PSBT carries
`PSBT_GLOBAL_NONCE_CACHE_SESSION`, the signer:

1. MUST refuse the request if no session holds `session_id` with that $ref$.
2. MUST delete the session, durably, before any signature leaves the
   signer.[^delete-before-release]
3. Signs every requested ($i$, $j$, $pk$) with the nonces of the deleted session.

Each nonce of a session signs at most once, and a session serves a single signing,
whatever it is used for. After the deletion, the same `session_id` MAY be issued
again and gets a new $secret$.

[^delete-before-release]: **Why delete before release?**
    A crash between release and deletion would leave a session that already signed. A
    crash between deletion and release only loses the session, which is safe.

### MuSig2

A MuSig2 signature is one input $i$ and one BIP-0373 `PSBT_IN_MUSIG2_PUB_NONCE`
(`0x1b`) keydata `participant | aggregate [| leaf_hash]`, `participant` being one of
the signer's keys. $pk$ is `participant` and $j$ is the index of the `musig()`
expression `aggregate` comes from.

For each such signature, the signer MUST refuse the request unless the $pubnonce$
recomputed for ($i$, $j$, $pk$) equals its own `0x1b` value. After the session
deletion, it signs with the recomputed $secnonce$.

This applies to aggregate then derive, as in `musig(A,B)/<0;1>/*`: $pk$ is `A` for
every input, so one issuance serves every input, and a session can be issued before
the transaction exists and used by any later transaction with at most $N$ inputs.

#### Two rounds

A PSBT without `PSBT_GLOBAL_NONCE_CACHE_SESSION` runs the two rounds of BIP-0327 on a
session without issuance.

- Let $D$ be the descriptors the signer signs the PSBT for.
- Let `session_id` be derived by the signer from $D$ alone, the same way in both
  rounds. It never leaves the signer.[^two-rounds]

Round 1, a PSBT without the signer's `0x1b` entry: the signer draws a new $secret$,
stores it under `session_id` durably, replacing any session held there, then
returns the $pubnonce$ for each of its signatures.

Round 2, a PSBT with the `0x1b` entry of every participant: the signer MUST refuse
the request if no session is held under `session_id`, then follows
[signing rules](#signing-rules) 2 and 3 on that session.

[^two-rounds]: **Why derive `session_id` from the descriptors?**
    The coordinator keeps and returns nothing between the rounds. `session_id` only
    selects the session: the nonces still depend on $secret$, $i$, $j$, $sk$ and $pk$
    alone. A signer then holds at most one two-round session per set of descriptors;
    a coordinator needing more uses issuance.

### Coordinator rules

- The coordinator SHOULD draw a new `session_id` as 4 random bytes. Once that session
  is used, it MAY issue the same `session_id` again, which gets a new
  $secret$.[^shared-device]
- The coordinator MUST expect eviction: signing with an evicted session fails, and
  the coordinator then issues a new session and builds a new PSBT.

[^shared-device]: **What if two coordinators pick the same `session_id`?**
    The second issuance returns the nonces of the first. The first PSBT signed
    deletes the session and the second is refused. No nonce signs twice.

## Rationale

See footnotes throughout the specification for design rationale.

### Test Vectors

[seed.json](./test_vectors/seed.json) contains test vectors for $seed$.  
[session_ref.json](./test_vectors/session_ref.json) contains test vectors for $ref$.  
[nonce.json](./test_vectors/nonce.json) contains test vectors for $secnonce$ and
$pubnonce$, including two keys at the same ($i$, $j$).  
[key_expression_index.json](./test_vectors/key_expression_index.json) contains test
vectors for the key expression index, on BIP-0388 wallet policies, with `musig()`
expressions and external keys.  
[psbt_field.json](./test_vectors/psbt_field.json) contains test vectors for the
`PSBT_GLOBAL_NONCE_CACHE_SESSION` key-value pair.  
[musig2_signing.json](./test_vectors/musig2_signing.json) contains a one-round 2-of-2
MuSig2 signing where one signer uses its cached nonce.

[gen_vectors.py](./test_vectors/gen_vectors.py) generates these files with the
BIP-0327 reference implementation.

## Backward Compatibility

BIP-0327 and BIP-0373 are unchanged. A cached nonce is an ordinary BIP-0327 nonce in
an ordinary `0x1b` entry. A signer that does not know
`PSBT_GLOBAL_NONCE_CACHE_SESSION` ignores it, as BIP-0174 requires for unknown
fields.
