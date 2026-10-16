<pre>
  BIP: ????
  Layer: Applications
  Title: Embedding user-facing policy semantics in Taproot multipath descriptors
  Author: pythcoiner <pythcoiner@proton.me>
  Comments-Summary: No comments yet.
  Comments-URI:
  Status: Draft
  Type: Informational
  Created: 2026-05-12
  License: BSD-3-Clause
</pre>

## Abstract

This BIP specifies a convention for **embedding user-facing policy semantics directly
into the multipath derivation index of a Taproot descriptor**. By partitioning the
unhardened-index space into a small number of fixed-width _zones_, each associated
with a `(role, locktime-kind)` pair, an emitting wallet tags every signer key with
the role that key plays in the policy. Any reader presented with a compliant
`tr(...)` descriptor - a co-signing wallet, a multisig or coinjoin coordinator, a
payment-constructing service - can recover that role from the descriptor alone,
without out-of-band manifests, proprietary PSBT fields, or wallet-private metadata.

The spec defines:

1. A normative zone table mapping `(role, locktime-kind)` pairs to multipath index
   ranges.
2. A cursor allocation rule inside each zone that lets readers group co-leaves of the
   same path.
3. A NUMS marker outside the zones (`<0x7FFF_FFFE; 0x7FFF_FFFF>`) for unspendable
   internal keys and padding leaves, recognisable in O(1).
4. A reader-side role-recovery procedure that consumes any compliant descriptor and
   yields the typed policy.
5. Emitter and reader conformance requirements.

## Copyright

This BIP is licensed under the BSD 3-Clause License.

## Motivation

Bitcoin descriptors faithfully encode the _scripts_ a wallet can spend from, but they
say nothing about the **role** each key plays in the user-facing policy. A
`tr(NUMS, {pk(A), and(pk(B), older(26280))})` descriptor tells a reader that there
are two leaves and three keys, but not which key is the "primary signer," which is a
"recovery cosigner," or which is a "mandatory escrow agent." Today this role
information is stored out-of-band - in wallet-private databases, in proprietary PSBT
fields, in human-readable JSON wrapped around the descriptor - and is routinely lost
when descriptors cross wallet boundaries.

This makes three classes of consumer unnecessarily painful to build:

1. **Co-signing wallets and watch-only viewers.** A wallet handed a descriptor it
   didn't author can render addresses, but cannot reliably render _labels_ ("Primary
   1-of-2," "Recovery after 6 months"), pick a default spending path, or warn the
   user when they are about to use a recovery key for a routine payment.
   Implementations either store an extra blob of role metadata next to every imported
   descriptor or guess at structure heuristically.
2. **Coordinators (multisig, coinjoin, payjoin).** A coordinator orchestrating a
   signing session must know which participant holds which role. With descriptor-only
   state, coordinators today either define a per-protocol metadata schema or restrict
   themselves to fixed-shape policies (e.g. plain k-of-n).
3. **Senders and payment-constructing services.** A service constructing a PSBT on
   behalf of a user (an exchange withdrawing to a user's recovery wallet, a payment
   router that wants to spend along the cheapest path) needs to pick a spending path.
   Without role tagging, the service either probes weights manually or asks the user
   out-of-band.

The contribution of this BIP is the observation that **the unhardened multipath-index
space already carried by every BIP-389 key has enough room to encode the policy role
of that key**, and that doing so requires no new descriptor syntax, no consensus
change, and no addition to PSBT. Wallets that adopt the convention emit descriptors
whose role structure is self-describing; readers that adopt the convention can lift
any such descriptor back to a typed policy with no extra channel.

The standard rests on three existing BIPs:

- BIP-341 (Taproot, the NUMS point used for unspendable internal keys).
- BIP-386 (`tr()` descriptor).
- BIP-389 (multipath `<a;b>` derivation in descriptors).

It does not extend or modify any of them.

## Specification

In what follows, "MUST" / "SHOULD" / "MAY" carry their RFC 2119 meaning. All hex
values are lowercase. All "indices" refer to BIP-32 unhardened indices
(`u32 < 2^31`). All "multipath legs" refer to the two-element form `<a;b>` introduced
in BIP-389.

### 1. Definitions

- **Path.** One spending path in the user-facing policy. Conceptually, the answer to
  "under which set of signatures plus which timelock can the user move funds." A
  policy is an ordered set of paths.
- **Role.** The semantic shape of keys participating in a path. This BIP defines five
  roles (Section 3).
- **Locktime kind.** The flavor of timelock gating a path. This BIP defines four
  (Section 4).
- **Zone.** A contiguous range of unhardened multipath indices reserved for a
  particular `(role, locktime-kind)` pair (Section 2).
- **Multipath group.** The two indices `<a; a+1>` carried by a single multipath key
  (BIP-389). All keys on one tap-leaf share one multipath group.

### 2. Zone layout

The unhardened multipath-index space is partitioned into **zones** of width `512`
(`= 2^9`). Each zone is reserved for exactly one `(role, locktime-kind)` pair. The
base index of each zone is a fixed multiple of `512`:

| Locktime            | Role                   | Zone range     |
| ------------------- | ---------------------- | -------------- |
| `None`              | `Single` / `Multi`     | `[512, 1024)`  |
| `Relative`          | `Single` / `Multi`     | `[1024, 1536)` |
| `Relative`          | `MultiMandatory`       | `[1536, 2048)` |
| `AbsoluteRenewable` | `Single` / `Multi`     | `[2048, 2560)` |
| `Absolute`          | `Single` / `Multi`     | `[2560, 3072)` |
| `None`              | `Custom` (role-opaque) | `[3072, 3584)` |
| `AbsoluteRenewable` | `MultiMandatory`       | `[3584, 4096)` |
| `Absolute`          | `MultiMandatory`       | `[4096, 4608)` |
| `Relative`          | `MultiMandatoryNested` | `[4608, 5120)` |

`Single` and `Multi` share a zone per locktime kind because a reader can disambiguate
them from the leaf's miniscript shape (one key vs many under a `thresh`).

The `Custom` zone is **role-opaque**: keys whose multipath indices fall in
`[3072, 3584)` carry no role information beyond "consumer-defined script." A reader
MUST treat such leaves as raw miniscript and surface them as `Custom` to the
application layer. The zone is reserved so consumer-defined paths cannot collide with
typed paths.

Indices `< 512` are reserved for future use and MUST NOT be emitted by a compliant
wallet.

### 3. Role catalog

A **role** is the structural shape of the keys on a path. Five roles are defined.

#### 3.1 `Single`

One signer. Per-leaf miniscript:

    pk(K)

Leaf count: 1. Multipath group: `<s; s+1>` where `s` is the path's allocated base.

#### 3.2 `Multi`

`t`-of-`n` multisig with `1 ≤ t ≤ n`. Per-leaf miniscript:

    thresh(t, pk(K_1), …, pk(K_n))

(compiles via miniscript to `multi_a(t, …)` under Taproot). Leaf count: 1. All `n`
keys share one multipath group `<s; s+1>`.

#### 3.3 `MultiMandatory`

"Every key in a mandatory set `M` must sign, plus a `(t − |M|)`-subset of a cosigner
set `K`." Requires `M ∩ K = ∅` and `|M| + 1 ≤ t ≤ |M| + |K|`. Per-leaf miniscript,
for each cosigner subset `S ⊆ K` with `|S| = t − |M|`:

    thresh(t, pk(M_1), …, pk(M_m), pk(S_1), …, pk(S_{t-m}))

Leaf count: `C(|K|, t − |M|)`. Each leaf gets a fresh multipath group; the mandatory
keys appear on every leaf, the cosigner keys each appear on a strict subset of
leaves.

#### 3.4 `MultiMandatoryNested`

AND of two independent subset gates on disjoint key sets `M` and `K`, with thresholds
`mt` and `t`. Requires `1 ≤ mt < |M|`, `1 ≤ t < |K|`, and `mt · |K| ≠ t · |M|`
(per-class frequencies differ - equal frequencies are unrecoverable by a reader). The
canonical form has the mandatory class as the lower-frequency one
(`mt · |K| < t · |M|`); emitters MUST swap the two key sets to canonicalise if
necessary. Per-leaf miniscript, for each `(Ms ⊆ M, Ks ⊆ K)` with
`|Ms| = mt, |Ks| = t`:

    thresh(mt + t, pk(Ms_1), …, pk(Ms_mt), pk(Ks_1), …, pk(Ks_t))

Leaf count: `C(|M|, mt) · C(|K|, t)`.

#### 3.5 `Custom`

An opaque `Miniscript<DescriptorPublicKey, Tap>` leaf. The compiler emits the
miniscript verbatim. `Custom` paths MUST have `Locktime::None`; any timelock gate is
encoded inside the miniscript. Multipath indices on the embedded keys are the
consumer's responsibility, and MUST fall in the `Custom` zone `[3072, 3584)`. Readers
MUST surface `Custom` leaves opaquely.

### 4. Locktime kinds

The locktime flavor of a path determines which zone its keys fall into.

| Locktime                | Wire form             | Constraint                                      |
| ----------------------- | --------------------- | ----------------------------------------------- |
| `None`                  | none                  | Path is immediately spendable.                  |
| `Relative(rl)`          | `older(rl)` (OP_CSV)  | Block-height encoding only.                     |
| `AbsoluteRenewable(al)` | `after(al)` (OP_CLTV) | Block-height side; aligned and renewable.       |
| `Absolute(al)`          | `after(al)` (OP_CLTV) | Block-height side; not aligned; not renewable.  |

`AbsoluteRenewable(al)` values MUST be non-zero multiples of
`CLTV_ALIGNMENT = 1024` and less than `LOCK_TIME_THRESHOLD`.

`CLTV_ALIGNMENT = 1024` blocks is approximately one week of bitcoin time. "Renewable"
means a wallet can re-issue a fresh descriptor at a later aligned height while
keeping every signer's keys constant.

Timestamp-side absolute locktimes (`al ≥ 500_000_000`) are out of scope.

A given policy uses a single locktime flavor across its recovery paths. The locktime
value itself lives in the leaf's miniscript (`older` / `after` fragments); the
multipath zone tags only the _kind_.

### 5. Cursor allocation within a zone

Inside each zone, multipath groups are allocated by a cursor starting at the zone
base. The cursor advances:

- **`+2` per emitted leaf** (one even/odd multipath pair per multipath group).
- **`+2` boundary** between distinct paths in the same zone.

The first index of every multipath group MUST be even, and the second MUST be the
first plus one. Total cursor advance for a path with `L` leaves is `2L + 2`.

Within a single `Multi` leaf, all keys share one multipath group `<s; s+1>`. Within a
single `MultiMandatory` or `MultiMandatoryNested` leaf, all keys (mandatory and
cosigner) share one multipath group; subsequent leaves of the same path get fresh,
contiguous groups.

**Collision rule.** No `(xpub, multipath-index)` pair MAY be claimed by two distinct
paths. Emitters MUST reject any policy that would produce such a collision.

### 6. NUMS marker

The two largest unhardened indices, `[0x7FFF_FFFE; 0x7FFF_FFFF]`, are reserved as the
**NUMS marker**. A multipath key with these indices MUST have public key equal to the
BIP-341 NUMS point:

    BIP341_NUMS =
        0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0

The marker has two uses:

1. **Unspendable internal key.** When no path qualifies for key-path spending, the Tr
   internal key SHOULD be a NUMS-marker key whose chain code is
   `sha256(BIP341_NUMS || concat(serialized public keys of every tap-tree leaf key,
   DFS order))`.
   Readers MUST recognise such an internal key as unspendable.
2. **Padding leaves.** Tap-tree slots that exist for shape reasons but carry no
   policy meaning SHOULD be filled with `pk(NUMS-marker-key)`. Readers MUST discard
   such leaves before role recovery (Section 7).

**Legacy detection.** A reader MAY also recognise as unspendable any key whose public
key equals `BIP341_NUMS` and whose chain code matches the recomputed value above,
without requiring the marker indices. Wallets conforming to this BIP for new
emissions SHOULD use the marker form; older descriptors using only the chain-code
form continue to parse.

### 7. Reader role-recovery procedure

A reader presented with a `tr(...)` descriptor recovers the typed policy as follows.

1. **Reject non-Tr.** A reader MUST refuse any non-`tr(...)` descriptor under this
   BIP.
2. **Classify the internal key.** a. If the internal key carries the NUMS marker
   (Section 6), treat it as unspendable. b. Else if its public key equals
   `BIP341_NUMS` and its chain code matches the recomputed value, treat it as
   unspendable. c. Otherwise emit a `Path(Single, Locktime::None)` for the internal
   key.
3. **Walk tap-tree leaves DFS.** For each leaf: a. Extract every key's multipath
   group. Each key MUST be `MultiXPub` with exactly two single-step unhardened
   derivation paths, the first index even, the second `first + 1`. b. If the leaf has
   only one key whose public key equals `BIP341_NUMS` (marker or chain-code form),
   classify the leaf as **padding** and discard it.
4. **Group leaves into paths.** Two leaves belong to the same path iff their keys'
   multipath base indices lie in the same zone and on the same cursor walk:
   contiguous even-base groups separated by `+2`, starting from a path-internal first
   base. Equivalently: leaves whose multipath bases fall in
   `[path_start, path_start + 2 · leaf_count)` and where every base is even and
   reachable from `path_start` by `+2` steps.
5. **Look up zone → `(role, locktime-kind)`.** The base index of any group in a path
   locates the zone (Section 2), which fixes the role and locktime kind.
6. **Lift the path into a typed `(Role, Locktime, key sets)` triple.**
   - 1 leaf → `Single` (one key) or `Multi` (≥ 2 keys under a `thresh`).
   - ≥ 2 leaves in a `MultiMandatory` zone → recover by frequency: keys appearing on
     every leaf are mandatory; keys appearing at the same lower frequency are
     cosigners; leaf count MUST equal `C(|K|, t − |M|)`.
   - ≥ 2 leaves in a `MultiMandatoryNested` zone → recover by two-frequency
     partition: keys cluster into exactly two frequency classes; the lower-frequency
     class is mandatory; thresholds derived from frequencies; leaf count MUST equal
     `C(|M|, mt) · C(|K|, t)`.
   - `Custom` zone → emit `Custom(ms)` opaquely; the role-opaque guarantee of Section
     2 applies.
7. **Recover the locktime value.** The zone tags only the _kind_ (relative vs
   aligned-renewable absolute vs foreign absolute). The numeric value is read from
   the leaf's `older(rl)` or `after(al)` fragment. All leaves of one path MUST carry
   the same locktime value.
8. **Mixed-kind detection.** If recovered paths carry inconsistent locktime kinds
   (some relative, some absolute, after dropping `None`), the descriptor is
   non-conformant; the reader SHOULD surface this as an error.

The result is a typed policy: an ordered list of `(Role, Locktime, [key sets])`
tuples, with the internal-key role recovered separately.

### 8. Emitter conformance

A compliant emitter MUST:

1. Assign every path's signer keys to a multipath group inside the path's
   `(role, locktime-kind)` zone, allocated by the cursor rule of Section 5.
2. Ensure no `(xpub, multipath-index)` pair is claimed by two paths (Section 5
   collision rule).
3. Canonicalise `MultiMandatoryNested` shapes to `mt · |K| < t · |M|` by swapping key
   sets if necessary (Section 3.4).
4. For paths whose role is `Custom`, restrict caller-managed multipath indices to the
   `Custom` zone `[3072, 3584)` and reject any other allocation.
5. Tag every padding tap-leaf and any unspendable internal key with the NUMS marker
   (Section 6), unless emitting a legacy chain-code-only NUMS form for backwards
   compatibility.
6. Use only block-height locktimes (no timestamp-side absolute values).

A compliant emitter SHOULD:

- Prefer the NUMS marker form over the chain-code-only form for new descriptors.
- Reject input policies that mix locktime kinds across recovery paths.

The shape of the tap-tree itself (depth, ordering, padding count) is _not_ normative.
Two emitters of the same policy MAY produce different tap-tree shapes; readers MUST
recover the same typed policy from either.

### 9. Reader conformance

A compliant reader MUST:

1. Recognise NUMS marker indices in O(1) and discard the corresponding internal key
   or leaf.
2. Recognise the legacy chain-code-only NUMS form as unspendable.
3. Group leaves by zone-and-cursor (Section 7 step 4) before attempting role
   recovery.
4. Reject any `MultiXPub` whose two derivation steps are not consecutive,
   single-step, or unhardened.
5. Recover roles from leaf shape + zone (Section 7 steps 5–6).
6. Surface `Custom` zone leaves opaquely without inferring further role structure.

A compliant reader SHOULD:

- Report `MixedTimelockKinds` when a descriptor mixes relative and absolute recovery
  paths.
- Treat unrecognised zones (e.g. `[5120, …)`) as opaque, forward-compatible role
  tags.

## Rationale

### Why embed in the multipath index?

Three obvious alternatives were considered and rejected:

- **Out-of-band labels.** Wallet-private metadata stored next to each imported
  descriptor. Does not survive descriptor exchange; defeats the purpose of
  self-describing wallets.
- **Proprietary PSBT fields.** Only present during signing; absent from a freshly
  imported watch-only descriptor; does not help coordinators or senders deriving
  addresses.
- **Comments or annotations in descriptor text.** Would require a syntax extension to
  BIP-380 / BIP-386; descriptors are typically hashed/normalised by tooling, dropping
  any annotation.

The unhardened multipath-index space, in contrast, is carried by every signer key in
every BIP-389 descriptor today. It is a structured, lossless channel that survives
any tooling that respects BIP-389. Using ~10 bits of it (zones up to `5120`, plus a
marker near `2^31 − 1`) costs nothing operationally and requires no new syntax.

### Why 512-wide zones?

`512 = 2^9` is comfortably above any operationally plausible leaf count for typed
roles. The dominant expansion is `MultiMandatory` with cosigner-subset enumeration: a
7-of-10 mandatory shape produces `C(10, 3) = 120` leaves, well inside one zone.
Powers of two also give readers O(1) zone lookup by integer division.

### Why `+2` per leaf with a `+2` boundary?

Each multipath group is an even/odd pair (the receive/change semantics established by
BIP-389), so `+2` per leaf is forced. The `+2` boundary between paths is deliberate
slack: an off-by-one in cursor advancement surfaces as a parse error (a path's keys
land in the wrong zone or with the wrong even/odd alignment) rather than as silent
index reuse across paths.

### Why a NUMS marker at `[0x7FFF_FFFE; 0x7FFF_FFFF]`?

Detecting an unspendable internal key the legacy way requires recomputing the chain
code `sha256(BIP341_NUMS || concat(leaf_keys))` over the whole tap tree - `O(n)` in
the number of leaves. The marker indices reduce this to two integer compares. The two
indices chosen are the largest unhardened indices, far above any operationally
allocated zone, so they cannot be confused with role tagging.

### Why split `MultiMandatory` and `MultiMandatoryNested` into separate zones?

A reader recovers `MultiMandatory` by _every-key frequency_ (keys appearing on every
leaf are mandatory); `MultiMandatoryNested` by _two-frequency partition_ (keys
cluster into exactly two frequency classes). The recovery algorithms differ, and a
reader needs to know which to attempt. Putting them in separate zones makes the
algorithm choice O(1) and disambiguates edge cases (e.g. a 2-leaf nested shape that
could superficially be lifted as `MultiMandatory`).

### Why a role-opaque `Custom` zone instead of dropping `Custom` entirely?

Real wallets sometimes need a script the typed role catalog does not cover. Two
options for handling them:

- Drop `Custom` from the spec entirely, and let consumers pick _any_ multipath index
  they want. This leaks: a custom path's keys could accidentally land in a typed
  zone, mis-tagging them.
- Reserve a zone for opaque scripts. The zone carries no semantic role beyond
  "consumer-defined," but it isolates custom scripts from accidentally colliding with
  typed roles.

The spec takes the second option. The collision benefit is real even if no role is
recoverable.

### Why is the tap-tree shape not normative?

This BIP's contribution is role tagging via multipath indices. Role recovery is
independent of the tap-tree shape: a reader groups leaves by their multipath bases
(Section 7 step 4), not by their tree position. Two emitters of the same policy can
produce trees of different depth and balance and the reader recovers identical typed
policies from both. Mandating one tap-tree algorithm would be additional surface for
no interop benefit at this layer; individual implementations can still commit to
byte-stable layouts if they want PSBT-level descriptor equality.

## Use cases

### 9.1 A watch-only wallet rendering an imported descriptor

A wallet imports a watch-only descriptor over QR. Without this BIP, the wallet can
render addresses but cannot tell whether the user owns the "primary" key or merely a
"recovery cosigner" key, so the UI must either ask the user or fall back to generic
labels.

With this BIP, the wallet runs the reader procedure (Section 7). Each leaf's
multipath base places it in a zone, which yields `(role, locktime-kind)`. The wallet
now knows that, say, leaf 0 is `(Single, None)` and leaf 1 is
`(MultiMandatory, Relative)` - enough to render "Primary signer" vs "Recovery
(mandatory cosigner)" and to highlight the cheapest spending path.

### 9.2 A multisig coordinator orchestrating a signing session

A coordinator service holds a descriptor for each managed wallet and orchestrates
signing sessions among participating signers. Without this BIP, the coordinator must
store an extra per-participant role table.

With this BIP, the coordinator reads roles directly from the descriptor: keys in zone
`[1536, 2048)` are mandatory cosigners on a relative-timelock recovery path; the
coordinator routes signature requests to those participants for any recovery-side
PSBT it constructs, and to the keys in zone `[512, 1024)` for primary-path PSBTs.

### 9.3 A payment-constructing service picking a spending path

A payment service constructs PSBTs spending from a user's wallet. The user's
descriptor has a primary 2-of-3 path and a 1-of-3 recovery path gated on a 6-month
CLTV. Today, the service either always picks one path (probably the cheapest static
one) or stores user-side metadata about which path to prefer.

With this BIP, the service reads from the descriptor: the recovery path lives in zone
`[2048, 2560)` with `AbsoluteRenewable` locktime kind, value `840_000` (read from
`after(...)` in the leaf miniscript). The service consults the current block height;
if below `840_000`, the recovery path is unspendable and the primary path is used;
otherwise both are viable and the service picks the cheaper witness weight.

## Backwards compatibility

This BIP introduces no new descriptor syntax. A compliant descriptor is a plain
`tr(...)` multipath descriptor as defined by BIP-386 + BIP-389:

- Any BIP-386 + BIP-389 wallet can derive addresses from a compliant descriptor.
- Any miniscript-aware wallet can spend from a compliant descriptor via the script
  path.
- A non-conformant reader sees the NUMS marker as a regular x-only pubkey with two
  derivation legs and treats it as any other unspendable internal key - the marker is
  invisible at the descriptor-syntax layer.
- Legacy descriptors using only the chain-code form for NUMS detection remain
  readable under this BIP.

There are no consensus or P2P changes. There is no PSBT extension.

Adoption is incremental: a wallet that emits compliant descriptors interoperates with
non-conformant wallets at the address-derivation and signing levels, gaining the
role-recovery benefit only when reading or being read by another compliant
implementation.

## Reference implementation

The `bwk-bup` Rust crate of the bwk workspace
([https://github.com/pythcoiner/bwk](https://github.com/pythcoiner/bwk), directory
`bup/`, BSD 3-Clause) is one reference implementation of this BIP. It provides:

- An emitter that takes a typed policy value and produces a compliant `tr(...)`
  multipath descriptor.
- A reader that recovers a typed policy from any compliant descriptor.
- ~100 unit tests exercising emitter → reader round trips for the role catalog of
  Section 3.

The crate also implements deterministic tap-tree layout (so two `bup` emitters of the
same policy produce byte-identical descriptors), but that is an implementation detail
above this BIP, not a normative requirement.

## Test vectors

The reference implementation includes the following classes of round-trip vectors.
Each is exercised as `compile → from_descriptor → semantic-equality` against the
source policy.

1. **Single-key wallet.** One `(Single, None)` path. Key allocated in zone
   `[512, 1024)`; auto-promoted to the Tr internal key. No tap tree.
2. **2-of-3 multisig, no recovery.** One `(Multi, None)` path with three keys sharing
   multipath group `<512;513>`. Unspendable internal key carries the NUMS marker.
3. **CSV recovery.** Primary `(Single, None)` + recovery `(Multi, Relative(rl))`.
   Recovery keys allocated in zone `[1024, 1536)`. Two leaves.
4. **Aligned CLTV recovery.** Primary `(Multi, None)` + recovery
   `(Multi, AbsoluteRenewable(840_000))`. Recovery keys allocated in zone
   `[2048, 2560)`. Demonstrates renewal: re-issuing at `al' > al` (aligned) yields a
   fresh address space, existing UTXOs still spendable under the older descriptor.
5. **Mandatory cosigner recovery.** Primary `(Single, None)` + recovery
   `(MultiMandatory(|M|=1, |K|=2, t=2), Relative(rl))`. Recovery keys allocated in
   zone `[1536, 2048)`. Expands to `C(2, 1) = 2` leaves.
6. **Nested mandatory recovery.** Primary `(Single, None)` + recovery
   `(MultiMandatoryNested(|M|=3, mt=1, |K|=4, t=2), Relative(rl))`. Recovery keys
   allocated in zone `[4608, 5120)`. Expands to `C(3, 1) · C(4, 2) = 18` leaves.
   Canonical form check: `mt · |K| = 4 < t · |M| = 6` ✓.
7. **Custom escape hatch.** One `(Custom, None)` path with consumer-assigned
   multipath indices in zone `[3072, 3584)`. Reader surfaces opaquely.
8. **Collision detection.** Two paths whose keys overlap at the same `(xpub, index)`
   are rejected at emit time.
9. **Mixed-kind detection.** A hand-crafted descriptor mixing relative and absolute
   recovery paths is reported as non-conformant by the reader.

A machine-readable test vector file (`bip-XXXX-vectors.json`) is planned as a
companion to this draft. For now, see the test suite in `src/policy.rs` of the
reference implementation.

## Acknowledgements

The role catalog of Section 3 and the zone layout of Section 2 were extracted from
descriptor-analysis code shipped in the Liana wallet, where the multipath-tagging
convention was developed in practice over several releases. Thanks to the Liana
developers and to the authors of BIP-341, BIP-379, BIP-386, and BIP-389, whose
primitives this BIP composes.
