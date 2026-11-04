<pre>
  BIP: XXX
  Layer: Applications
  Title: Tweak Accumulator for Chain Code Delegation
  Author: &lt;to be assigned&gt;
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXX
  Status: Draft
  Type: Standards Track
  Created: 2026-09-14
  License: BSD-2-Clause
  Requires: 32, 89, 174, 322, 340, 341
</pre>

## Abstract

This proposal lets a BIP89 delegator reject derivation tweaks that do not belong
to the wallet. A signing device holding a key of the descriptor commits, in
Merkle trees whose leaves are blinded commitments, to the delegation bundles of
the wallet's derivation indexes, one tree per keychain, and MAY sign each tree
root with a BIP322 signature by that key. The roots are recorded with the
delegator at registration, after any signature they carry is verified, and are
not carried in each spend. Whenever the delegator is asked to treat a transaction output as
owned by the wallet, change or receive (self-send), the bundle for that output
comes with a membership proof, and the delegator verifies it against a recorded
root. A forged tweak has no leaf and is refused. Revealing a bundle reveals
nothing about bundles not revealed, and the proof does not reveal the derivation
index.

## Motivation

BIP89 withholds chain codes from a delegator and hands it, per signing
context, a bundle of `(P_i, t_i)` pairs where `t_i` is the aggregated
non-hardened derivation tweak of participant key `P_i`. The delegator
substitutes `P_i + t_i*G` into its template, rebuilds the script and compares
it with the script under review.

That check proves the script is built from the template over tweaked keys. It
does not prove that `t_i` is the output of `ComputeBIP32Tweak` for any
derivation index. The delegator has no chain code, so it cannot recompute any
tweak, and every 32-byte scalar passes `ChangeOutputVerification`.

A compromised delegatee exploits this on every output the delegator must
certify as owned: change, and receive outputs of a self-send. Taking change as
the example, it sends genuine tweaks for the inputs and scalars of its own
choosing for the change output. The change script rebuilds from what was
disclosed, verification passes, the input signatures are valid and the
transaction confirms. The change output is still a policy over tweaked versions
of the wallet's keys, so the attacker cannot spend it alone. But the tweaks are
the aggregate for no index vector, so no scan over the descriptor ever finds
the output, and there is no index to record. The only handle to the coins is
the set of forged scalars, which the attacker holds. The coins are held for
ransom, and if the scalars are lost they are unspendable by everyone.

BIP89 notes that incorrect scalars could leave the delegator unable to sign.
On an input that is a retry. On an owned output, change or receive, it is a
permanent loss, and nothing in BIP89 lets the delegator tell a genuine tweak
from a forged one.

What is wanted is a way for the delegator to recognize a tweak as the
wallet's without learning the chain code, the descriptor, the derivation
index, or any bundle it is not shown. The blinded address accumulator solves
the same shape of problem for a sender verifying a recipient's addresses.
This proposal reuses that construction unchanged and commits to delegation
bundles instead of scriptPubKeys.

Throughout this document the roles are fixed:

- The **delegator** is the BIP89 delegator. It holds a non-extended keypair
  and co-signs.
- The **coordinator** is the BIP89 delegatee software that builds
  transactions, computes bundles and serves proofs.
- The **signing key holder** is a signing device that holds the full wallet
  descriptor, including the delegated extended keys, and the secret key of one
  key of the descriptor. It is a BIP89 delegatee.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in RFC 2119.

### Tagged hashing

All hashes in this specification are BIP340-style tagged hashes:

```
tagged_hash(tag, data) = sha256(sha256(tag) || sha256(tag) || data)
```

The following tags are used. Throughout this document, `BIPXXX` is a literal
placeholder for the assigned BIP number; implementations MUST substitute the
final assigned number in every tag string.

```
+------------------------+-----------------+
| Purpose                | Tag             |
+------------------------+-----------------+
| Leaf                   | BIPXXX_LEAF     |
| Internal node          | BIPXXX_BRANCH   |
| Root                   | BIPXXX_ROOT     |
| Nonce derivation       | BIPXXX_NONCE    |
| Chaincode seed         | BIPXXX_POLICY   |
| Shuffle key and stream | BIPXXX_SHUFFLE  |
| Root signature         | BIPXXX_ROOT_SIG |
+------------------------+-----------------+
```

### Descriptor

The wallet descriptor MUST be a `tr()` descriptor. Every key expression in it,
including the internal key, MUST be an extended public key followed by zero or
more non-hardened fixed steps, one multipath step with exactly two
non-hardened elements, and an unhardened wildcard:

```
[origin]xpub/fixed_1/.../fixed_k/<a;b>/*
```

The **keychain** of a derivation is the position of the multipath element
used: `0` selects `a`, `1` selects `b`. Keychain `0` is the receive keychain
and keychain `1` is the change keychain.

The **base key** `P` of a key expression is the 33-byte compressed public key
of its extended public key. The **tweak path** of a key expression for a
keychain and an index is:

```
tweak_path(keychain, index) = (fixed_1, ..., fixed_k, element(keychain), index)
```

The **branch pair** of a key expression is its two branch paths, the tweak
paths of keychain `0` and `1` without the index:

```
branches = ((fixed_1, ..., fixed_k, a), (fixed_1, ..., fixed_k, b))
```

A **slot** is a distinct pair of a base key and a branch pair: key
expressions with the same base key, chain code and branch pair are one slot,
whatever their key origin. A base key used on one branch pair has one slot;
a base key used on several branch pairs, for example `/<0;1>/*` and
`/<2;3>/*`, has one slot per branch pair. The slots of a base key are numbered
from `0` in ascending order of their branch pairs, comparing the keychain `0`
branch paths first, element by element as unsigned integers, a path that is a
prefix of another first, then the keychain `1` branch paths. A slot is written
`(P, N)` for slot number `N` of base key `P`.

The descriptor is invalid if:

1. Two key expressions with the same base key carry different chain codes.
2. Two slots of the same base key share a branch path, so they would derive
   the same keys (for example `/<0;1>/*` and `/<1;2>/*`).
3. A base key has more than 256 slots.

The **template** `D` is the descriptor with every key expression replaced by
its template key: the base key `P` written as its compressed hex encoding for
slot `0`, and as `P@N` for slot `N` above `0`, with `N` in decimal, from `1` to
`255` and with no leading zero. The template carries the slot number and never
the branch pair. BIP89 verification substitutes the tweaked key of slot `(P,
N)` for template key `P@N`. `template_bytes` is the canonical string
serialization of `D`, encoded as UTF-8 with no added whitespace or trailing
newline. A descriptor whose base keys each have one slot gives the template
over base keys alone.

```
template_id = sha256(template_bytes)
```

### Delegation bundle

For a keychain and an index below 2^31, the bundle holds one entry per slot of
the descriptor:

```
t_i = ComputeBIP32Tweak(xpub_i, tweak_path_i(keychain, index)).t
bundle(keychain, index) = [(P_i, N_i, t_i) for every slot (P_i, N_i)]
```

`ComputeBIP32Tweak` is the algorithm of BIP89, and `tweak_path_i` is the tweak
path of the key expressions of slot `(P_i, N_i)`. A base key with one slot has
one entry, as in BIP89; a base key with several slots has one entry per slot,
each with its own tweak.

A bundle is serialized with entries sorted in ascending byte order of `P_i`,
and the entries of one base key in ascending order of slot number:

```
ser(bundle) = concat_all(P_i || bytes(32, t_i))
```

Each entry is 65 bytes. There is no count prefix and no slot number: the
entries of one base key are its slots `0`, `1`, `2`, ... in order, so a base key
repeated in a serialized bundle is its next slot. A bundle MUST contain exactly
one entry for each slot of the template and no other entry. An entry whose
tweak is not below the curve order is invalid, and so is a base key appearing
more than 256 times.

### Nonce derivation

Unchanged from the blinded address accumulator.

```
policy_id   = sha256(descriptor_bytes)
keys_digest = sha256(concat_all(sort(dedup(concat(chain_code, public_key)))))

policy_hash(policy_id, keychain, tree_start) =
    tagged_hash("BIPXXX_POLICY",
                concat(policy_id, be32(keychain), be32(tree_start)))

chaincode = policy_hash(policy_id, keychain, tree_start)

next_chaincode, nonce = split32(hmac_sha512(chaincode,
                                            concat("BIPXXX_NONCE",
                                                   keys_digest,
                                                   be32(keychain),
                                                   be32(index))))
```

`descriptor_bytes` is the canonical string serialization of the full wallet
descriptor, with extended public keys, encoded as UTF-8 with no added
whitespace or trailing newline. `chain_code` and `public_key` are the 32-byte
chain code and 33-byte compressed public key of each extended public key in
the descriptor. `sort` orders the 65-byte records in ascending byte order and
`dedup` removes records identical to their predecessor, so the slots of one
base key give one record.

Nonce derivation is sequential inside a tree. Each leaf consumes the current
chaincode and produces the next chaincode and that leaf's nonce by splitting
the 64-byte HMAC output into two 32-byte halves, the first being the next
chaincode. The chaincode is NOT threaded across trees: each tree reseeds from
`policy_id`, the keychain and its own `tree_start`.

### Leaf construction

```
leaf(bundle, nonce) = tagged_hash("BIPXXX_LEAF",
                                  concat(ser(bundle), nonce))
```

This is the only change from the blinded address accumulator, where the leaf
commits to a scriptPubKey.

### Tree construction

Unchanged from the blinded address accumulator. Each tree contains exactly 256
leaves for one keychain. A tree MAY start at any derivation index; the start is
not required to be a multiple of 256, and trees MAY overlap in derivation index
space. `tree_start + 255` MUST be below 2^31, since every index is a
non-hardened derivation step.

```
generate_tree(keychain, tree_start):
    leaves = []
    chaincode = policy_hash(policy_id, keychain, tree_start)
    for offset in 0 .. 256:
        index = tree_start + offset
        chaincode, nonce = leaf_nonce(chaincode, keys_digest, keychain, index)
        leaves[offset] = leaf(bundle(keychain, index), nonce)

    nodes = []
    for each offset in shuffle_order(shuffle_key(policy_id, keychain,
                                                 tree_start)):
        nodes.append(leaves[offset])

    return root_hash(collapse(nodes))

collapse(nodes):
    while length(nodes) > 1:
        nodes = [branch_hash(nodes[2k], nodes[2k+1]) for each pair]
    return nodes[0]

branch_hash(left, right) = tagged_hash("BIPXXX_BRANCH",
                                       concat(left, right))

root_hash(root) = tagged_hash("BIPXXX_ROOT", root)
```

`shuffle_key(policy_id, keychain, tree_start)` is the tagged hash of
`concat(policy_id, be32(keychain), be32(tree_start))` using the
`BIPXXX_SHUFFLE` tag.

`shuffle_order(key)` returns the list of 256 byte offsets where
`order[position] = offset`. It is a descending Fisher-Yates shuffle over a
deterministic byte stream:

```
stream(key) = concat_all(hmac_sha512(key, concat("BIPXXX_SHUFFLE",
                                                 be32(counter)))
                         for counter = 0, 1, 2, ...)

shuffle_order(key):
    order = [0, 1, ..., 255]
    for i from 255 down to 1:
        repeat:
            b = next byte of stream(key)
        until b <= i
        swap(order[i], order[b])
    return order
```

The following requirements each apply to every implementation:

1. The shuffle order is derived from the wallet policy id, the keychain, and
   the tree start. Implementations MUST NOT use tree position as the derivation
   index.

2. A tree has exactly 256 leaves. Implementations MUST NOT use a different
   tree size.

3. Inside `branch_hash`, the two children are combined in the order given.
   Implementations MUST NOT sort the two children before hashing.

4. The shuffle loop runs descending, a rejected draw consumes its stream byte,
   the acceptance bound `b <= i` is inclusive, and draws MUST NOT be reduced
   modulo `i + 1`.

### Root signature

A root that is signed is signed by one key of the descriptor, with a BIP322
simple signature for the single-key taproot address of that key's branch key.

For the key expressions of slot `0` of base key `P`, whose extended public key
`xpub` has chain code `c`, with secret key `p` for `P`, the branch path, branch
tweak and branch key of a keychain are:

```
branch_path(keychain) = (fixed_1, ..., fixed_k, element(keychain))
t_branch = ComputeBIP32Tweak(xpub, branch_path(keychain)).t
K = P + t_branch*G
```

The signature is made for `tr(K)`, the taproot address whose internal key is
`K` with no script tree, spent by key path:

```
root_message = tagged_hash("BIPXXX_ROOT_SIG", concat(template_id, root))
signature = bip322_sign_simple(tr(K), root_message, p + t_branch)
```

The BIP322 message is the 32 bytes of `root_message`. The signature is the
BIP322 simple signature: the consensus-serialized witness stack.

The root record carries:

```
root_record = { keychain,
                tree_start,
                root: 32 bytes,
                signature: optional { key: P, 33 bytes,
                                      branch_tweak: t_branch, 32 bytes,
                                      signature } }
```

`keychain` and `tree_start` identify the tree and are not covered by the
signature. The signature is optional: a record without one carries the root
alone, and whether a delegator accepts such a record is its policy (see
[Registration](#registration)).

The signing key holder builds one tree per keychain: receive (keychain `0`) and
change (keychain `1`). It MUST build the tree itself, from the descriptor it
holds. It MUST NOT sign, or hand over for registration, a root computed by
another party. The signing key holder MAY build new trees at any time; the
delegator uses a new root only once it is recorded (see
[Registration](#registration)).

### Verifying a root signature

A root record that carries a signature is verified against a template `D`. The
verifier refuses it unless all of the following hold:

1. `key` MUST be a base key of `D`.
2. `branch_tweak` MUST be below the curve order, and
   `K = key + branch_tweak*G` MUST NOT be the point at infinity.
3. The BIP322 simple signature `signature` MUST verify for `tr(K)` over
   `root_message`, computed from the `template_id` of `D` and `root`.

The verifier holds no chain code, so it cannot check that `branch_tweak` is
the branch tweak of `key`; a forged branch tweak does not help a party that
does not hold the secret key of `key`, since signing for `tr(K)` still
requires it.

### Registration

When the descriptor is registered with the delegator, the delegator receives
the root record of a receive tree (keychain `0`) and the root record of a
change tree (keychain `1`), and records:

```
registration = { template D, receive accumulator root, change accumulator root }
```

The delegator MUST NOT record a root whose record carries a signature that
fails to verify (see
[Verifying a root signature](#verifying-a-root-signature)).

Whether the delegator records a root whose record carries no signature is its
policy. From a signature it gets the statement that a key holder of the wallet
built the tree; without one, the setup channel carries that statement alone, so
a delegator MUST NOT accept an unsigned root unless it trusts that channel to
carry the roots with the same authority it carries the template.

The delegator MUST obtain the registration over the same authenticated setup
channel it uses to accept the template.

The delegator MUST fix the policy at registration and MUST apply it to every
later root of the same registration, so a root recorded later is never less
authenticated than the ones registration accepted.

Which keys of the descriptor a delegator accepts as root signers is policy
outside this proposal, agreed between the cosigning service and its users.

Registration is performed by the consumer: how and where the template and
roots are stored, and how they are associated with an account or descriptor, is
out of scope.

After registration, the delegator MUST use the recorded template and roots for
every verification and MUST NOT use a template or root supplied with a signing
request. A changed template requires a new registration.

When the tree of a keychain is exhausted, a signing key holder builds the next
tree for that keychain. The delegator checks its record under the policy it
fixed at registration and records the root with the account the same way.

### Proof format and verification

Unchanged from the blinded address accumulator.

```
proof = { nonce: 32 bytes,
          position: u8,
          siblings: [32 bytes; 8] }

verify(bundle, proof, root):
    node = tagged_hash("BIPXXX_LEAF", concat(ser(bundle), proof.nonce))
    for level in 0 .. 8:
        sibling = proof.siblings[level]
        if bit(proof.position, level) == 0:
            node = branch_hash(node, sibling)
        else:
            node = branch_hash(sibling, node)
    return root_hash(node) == root
```

`position` is the position of the leaf inside its tree, in the range 0 to 255
(the tree start MUST NOT be added to it). `bit(position, level)` is bit
`level` of `position`, with bit 0 being the least significant. A position is
serialized as a single byte; any other width is invalid.

Proof size is fixed: nonce 32 bytes, position 1 byte, and 8 siblings of 32
bytes, for a total of 289 bytes, serialized in that order.

### Proof against recorded roots

A spend carries, for each owned output, only the 289-byte proof of its bundle.
The root and its signature are not carried: the delegator checked the record
when it recorded the root.

A proof verifies against any root recorded with the account:
`verify_recorded(bundle, proof, registration)` succeeds when
`verify(bundle, proof, root)` holds for one of them.

```
verify_recorded(bundle, proof, registration):
    for each root recorded in registration:
        if verify(bundle, proof, root):
            succeed
    fail
```

### Delegator verification

This section applies to the non-blinded signing mode of BIP89. In the blinded
mode the delegator sees no transaction, script or bundle, and this proposal
does not apply.

For a transaction to be signed, the delegator MUST, before producing any
signature:

1. For each input it is asked to sign for, read the input bundle and run BIP89
   `InputVerification(D, W, T)` with the registered template `D`, the
   scriptPubKey `W` of the output being spent, and the bundle `T`. Fail if it
   returns false.

2. For each transaction output that carries a bundle:
   1. Run BIP89 `ChangeOutputVerification(D, W, T)` with the registered
      template `D`, the scriptPubKey `W` read from that transaction output,
      and the bundle `T`. Fail if it returns false.
   2. Read the membership proof of that output. Fail if it is absent.
   3. Run `verify_recorded(T, proof, registration)`. Fail if it fails.
   4. Treat the output as owned by the wallet.

3. Treat every output that carries no bundle as not owned by the wallet.

For taproot, the script compared by BIP89 verification is the output
scriptPubKey. For an input it is the scriptPubKey of the output being spent;
for an output it is the scriptPubKey of the transaction output itself. It MUST
NOT be read from data accompanying the bundle.

A delegator that enforces spending policy MAY compute the outflow of the
transaction as the value of the verified inputs minus the value of the owned
outputs. That value includes the fee.

A delegator that implements this proposal MUST NOT treat an output as owned
based on BIP89 `ChangeOutputVerification` alone.

### PSBT fields

Bundles and membership proofs travel in proprietary PSBT fields (BIP174 type
`0xFC`) with the identifier `BIPXXX`:

```
PSBT_IN_PROPRIETARY  | "BIPXXX" | 0x00 | slot (33 or 34)  ->  tweak (32)
PSBT_OUT_PROPRIETARY | "BIPXXX" | 0x00 | slot (33 or 34)  ->  tweak (32)
PSBT_OUT_PROPRIETARY | "BIPXXX" | 0x01                    ->  proof (289)
```

The key of a proprietary field is
`0xFC || compact_size(6) || "BIPXXX" || compact_size(subtype) || keydata`.

- Subtype `0x00` holds one bundle entry. The entries of all subtype `0x00`
  fields in one map form the bundle of that input or output. The keydata is
  the slot of the entry: the 33-byte base key `P` for slot `0`, and `P ||
  byte(N)`, 34 bytes, for slot `N` above `0`. The value is the 32-byte
  big-endian tweak. Any other length is invalid, and so is a 34-byte keydata
  whose last byte is `0`, so each slot has one keydata.
- Subtype `0x01` holds the membership proof of an output, the 289-byte proof.
  Its keydata is empty. An output map MUST NOT hold more than one such field.

The fields are scoped to a single input or output map, so the binding between
bundle, membership proof and script is structural: they apply to the input or
output in whose map they appear.

The root never travels with the proof. As in the blinded address accumulator,
a host supplying both could verify a proof against a root of its choosing, so
the delegator verifies a proof only against the roots recorded at registration.

## Rationale

**Commit to the bundle rather than the script.** Committing to the output script
would bind the same thing: a script fixes the tweaked keys, and the tweaked keys
fix the tweaks. The bundle is chosen because it is exactly the data BIP89 hands
the delegator and the delegator cannot check, so the proof attests the untrusted
input itself. It also keeps tree construction cheap for the signing key holder:
a leaf needs one `ComputeBIP32Tweak` step per key, while a taproot script needs
every tapleaf script, the tap tree and the output key tweak.

**Every participant tweak in the leaf.** Recovering an output needs every
participant key at the same derivation index. A single forged tweak, or tweaks
of different indexes for different participants, strands the output as surely
as a fully forged bundle. The leaf therefore binds the whole bundle, and a
bundle with a missing or extra entry has no leaf.

**One entry per slot.** A wallet may use one key on several derivation paths,
for example a key that signs alone after a timelock on `/<2;3>/*` and with a
cosigner on `/<0;1>/*`. Each path derives other keys, so the bundle carries a
tweak per path and the template has to tell which tweak goes where. A base key
alone cannot: `B/<0;1>/*` and `B/<2;3>/*` would get the same tweak. A wallet
whose keys each have one path keeps exactly the BIP89 bundle, template and
PSBT fields.

**The template carries a slot number, not a path.** The template carries no
derivation step, so the delegator learns that a key is used on several paths,
and nothing of the paths themselves. The number only needs to tell the slots
of a key apart, and numbering them in path order makes it a function of the
descriptor, so every party derives the same template. The `P@N` form is the
shortest that keeps the template a descriptor string: `@` belongs to the
descriptor checksum character set, so the checksum covers the slot, and it
appears in no key expression or miniscript fragment, so a parser reads `P@N` as
one key and splits it at the only `@`. Slot `0` has no suffix and `N` has no
leading zero, so each template has one spelling and one `template_id`, and a
template whose keys each have one slot is unchanged.

**Overlapping paths are refused.** Two slots of one base key sharing a branch
path derive the same keys on two keychains, or twice on one, so an address
would belong to two slots and a tweak to two places in the template.

**Sorted, fixed-width bundle.** A bundle has exactly one encoding. Two
encodings of one bundle would give two leaves, so a genuine bundle could fail
to verify, and ambiguity in the encoding could let different bundles share a
leaf. Entries are sorted by base key then slot number, and the slot number of
an entry is its rank among the entries of its base key, so it needs no byte of
its own and cannot be spelled two ways. Entries are fixed width and the nonce
is a fixed-size suffix, so no length prefix is needed.

**Construction reused unchanged.** The blinded address accumulator was designed
for a signing device to build and for a constrained verifier to check. Both
properties carry over, since only the leaf payload changes: the signing key
holder builds a 256-leaf tree with fixed memory, and the delegator verifies a
proof with one running node and one sibling at a time.

**Blinding still protects against the delegator.** Nonces and the shuffle key
derive from `descriptor_bytes` and the chain codes. The delegator holds only
the template over template keys, never the descriptor or a chain code, so it
cannot compute a nonce or a shuffle order. A sibling is a hash of a bundle it has not
seen and a nonce it cannot compute, so it reveals nothing about that bundle.
The tweaks themselves are pseudorandom outputs of the chain code, so a bundle
the delegator has not been shown cannot be guessed.

**Placement by keyed shuffle.** If leaves sat at their derivation index, the
proof position would reveal the index to the delegator, which is the address
count and order BIP89 withholds by withholding the chain code. The shuffle
keeps position uncorrelated with index.

**BIP322 signature by a descriptor key.** BIP322 is the standard format for
signing a message with a bitcoin key, so a signing device can sign a root with
a key it already holds. Using a key of the descriptor needs no separate owner
key, and no derivation path to specify, back up and register for it: the
delegator already knows the base keys from the template. The signature is made
by the branch key of the tree's keychain, so the receive and change roots of a
key holder are signed under different keys and each signature is tied to one
of its two accumulators.

**Root message binds the template and nothing else.** The delegator needs one
statement: this root is a tree a key holder of this wallet built. The template
id is bound so a root signed under the same key for another wallet is not
accepted for this registration; the delegator already knows the template, so
binding it leaks nothing. The keychain and tree start are not bound. The
delegator does not need them to verify a proof.

**Accumulators recorded at registration.** The delegator checks each root
record once, when the root is recorded, rather than on every spend. A spend then
carries only the proof, and a host cannot supply a root of its own: a proof
verifies against recorded roots only. When a tree is exhausted a signing key
holder builds the next one for that keychain, and the delegator records it the
same way.

**The signature is optional.** The registration travels over the authenticated
setup channel that carries the template, and a delegator that trusts that
channel for the template can trust it for the roots. Some signing devices have
no BIP322 support, and requiring a signature would keep them out. What a
delegator gives up by accepting an unsigned root is the proof that a key holder
of the wallet, and not the coordinator, built the tree: the guarantee then rests
on the setup channel alone. The choice is the delegator's, and it is fixed at
registration so a later root is never recorded under a weaker rule than the
wallet was registered with.

**The signing key holder builds the tree.** A root is only as trustworthy as the
bundles hashed into it. A device that signed a root computed by the coordinator
would let a compromised coordinator commit forged bundles and reinstate the
attack.

**Root not in the PSBT.** As in the blinded address accumulator, the root is
not carried with the proof, because a host supplying both could verify a proof
against a root of its choosing. The PSBT carries only the proof, and the root
comes from the registration.

**Inputs keep plain BIP89 verification.** An input spends an output that
already exists on chain. Its bundle must rebuild the script of that output, so
a wrong tweak on an input fails verification, and the spend fails without
loss. Owned outputs, change and receive (self-send), are created by the
transaction being signed, so they are where a forged tweak turns into lost
coins, and both carry a membership proof.

**Outputs without a bundle.** An output that carries no bundle is not claimed
as owned. The delegator counts it as outflow and applies its spending policy.
This proposal does not constrain payments; it removes the ability to pass a
payment to an unrecoverable script off as an owned output.

**Tags carry the version.** As in the blinded address accumulator, a revision
changes the tag strings, so proofs and signatures under two versions are
non-interchangeable by construction.

## Security Considerations

- A compromised coordinator can still attach to an output the genuine bundle
  of another derivation index. The output then lands at a real index of the
  wallet and is found by a scan. This proposal does not prevent it.
- The proof does not tell the delegator whether an index was already used.
  A coordinator can reuse an index, which is an address reuse and a privacy
  loss, not a loss of funds.
- A compromised key that the delegator's policy accepts as a root signer lets
  an attacker sign a root over forged bundles. Choosing which keys are
  acceptable signers is the delegator's policy.
- A delegator that accepts unsigned roots has no statement from a key holder
  that a tree is theirs, so anything that can write on the setup channel can
  register a root over forged bundles. The setup channel carries the whole
  guarantee there.
- A template substituted on the setup channel remains out of scope: the
  registration channel carries the same trust as the BIP89 setup.
- A delegator that verifies bundles but does not implement this proposal
  remains exposed to forged tweaks on owned outputs.

## Backwards Compatibility

This proposal introduces no changes to consensus rules, transaction structure,
or on-chain data. Bundles and membership proofs travel in PSBT proprietary
fields that are stripped at finalization. BIP89 signing is unchanged.

A descriptor whose base keys each have one slot has the BIP89 template, bundle
and PSBT fields. Only a descriptor that uses a base key on several paths gets
template keys `P@N`, repeated base keys in its bundles and 34-byte keydata,
which software that does not implement slots refuses.

A delegator that implements this proposal refuses owned outputs without a
membership proof, so its coordinators and signing key holders MUST implement it
before the delegator enables it. Software that does not implement this proposal
ignores the unknown proprietary fields.

## Reference Implementation

The reference implementation is the `bwk-bip89` crate of this repository.
Slots are in `slot.rs` and the bundle in `bundle.rs`; the template keys are
`TemplateKey` in `rust_bitcoin/descriptor.rs`. Hash primitives and tree
generation are in `accumulator/mod.rs`. The shuffle order is in
`accumulator/shuffle.rs`. Proofs and the tree builders are in
`accumulator/tree.rs`. Root records, their signature and the root policy
are in `accumulator/record.rs`. Registration and verification on the delegator
side are in `delegator.rs`. BIP322 signing and verification are in
`rust_bitcoin/mod.rs`, and the PSBT fields are in `rust_bitcoin/psbt.rs`.

It MUST be the source of the test vectors below; vectors MUST NOT be
authored by hand. The vectors are generated by the `#[ignore]` test
`regenerate_vectors` in `tests/accumulator_vectors.rs`, run with:

```
cargo test -p bwk-bip89 --test accumulator_vectors regenerate_vectors -- --ignored
```

## Test Vectors

The reference implementation generates four files under
`test_vectors/accumulator/`:

```
+-----------------+-----------------------------------------------------------+
| File            | Covers                                                    |
+-----------------+-----------------------------------------------------------+
| primitives.json | Descriptor, template, digests, nonces, shuffle, bundle.   |
| tree.json       | Full tree: nonces, leaves, order, levels, root, root      |
|                 | message, signer key, branch tweak and key, BIP322         |
|                 | signature.                                                |
| proof.json      | One 289-byte proof with its trace, and four negative      |
|                 | vectors.                                                  |
| slots.json      | Two keys each on two paths: slots, template, template id, |
|                 | bundle with PSBT keydata, roots and one proof, and        |
|                 | refused template keys, keydata and descriptors.           |
+-----------------+-----------------------------------------------------------+
```

Each bullet of the minimum coverage below maps to a field of these files:

- A multisig `tr()` descriptor exercising extended key serialization, sort,
  and deduplication in `keys_digest`, including records whose byte order
  differs from any extended key ordering: `primitives.json`, the second
  `keys_digest` case (description "raw record order differs from key
  order, with a duplicate"), fields `xpubs` and `sorted_records`.
- Bundle serialization for a keychain and an index, with every tweak path:
  `primitives.json`, field `bundle`, one `entries[].tweak_path` per key.
- A tree with every intermediate value printed: per-leaf nonces, per-leaf
  hashes, shuffled order, every branch hash, the root, the template id, the
  root message, and the root signature with the signer's secret key, base
  key, branch tweak and branch key: `tree.json`, fields `leaves`, `order`,
  `levels`, `root`, `template_id`, `root_message`, `signer_secret`, `key`,
  `branch_tweak`, `branch_key` and `signature`.
- At least one full proof with its complete verification trace: the running
  node value before and after each level, the sibling consumed at each
  level, and the bit of `position` that selects the ordering at each
  level: `proof.json`, fields `proof` (the 289-byte proof) and `trace`.
- Negative vectors: a proof that fails because a tweak in the bundle is
  altered, one because a sibling is altered, one because the position is
  altered, and one because the nonce is altered: `proof.json`, field
  `negatives`, in that order.
- A descriptor with base keys on two paths, `/<0;1>/*` and `/<2;3>/*`: its
  slots with their numbers and branch pairs, the template with `P@1` keys and
  its id, a bundle with one entry per slot, its tweak paths and the PSBT
  keydata of each entry, the receive and change roots and a proof that
  verifies against one: `slots.json`, fields `slots`, `template`,
  `template_id`, `bundle`, `roots` and `proof`.
- Refused slot encodings and descriptors: template keys `P@0`, `P@01` and
  `P@256`, PSBT keydata `P || 00` and `P || 01 00`, a base key with a second
  chain code and a base key on two paths sharing a branch, each with the
  refusal and the base key it names: `slots.json`, fields
  `invalid_template_keys`, `invalid_psbt_keydata` and `invalid_descriptors`.

Byte strings in every vector file are lowercase hex. The tags are the
literal `BIPXXX` placeholder used throughout this document, so every
vector MUST be regenerated once the BIP number is assigned. The wallet
descriptor, template and signer secret key used across the first three files
are the ones recorded in `primitives.json` and `tree.json`; `slots.json`
records its own descriptor.

## Open Items

The following items are unresolved. Implementations MUST NOT fabricate values
for them; interoperable deployments require they be settled first.

- **BIP number.** Every tag string and the PSBT identifier contain `BIPXXX` as
  a placeholder. The assigned BIP number replaces it throughout.

- **Canonical descriptor and template strings.** `descriptor_bytes` and
  `template_bytes` require one canonical string form: hardened step marker,
  checksum, key origin, key encoding, and the `@N` slot suffix of a template
  key. Two implementations that disagree produce different trees and a
  different template id, with no error.

- **Test vectors.** As above, MUST be generated from the reference
  implementation.

## Acknowledgements

TBD.

## Copyright

This document is licensed under the BSD 2-clause license.
