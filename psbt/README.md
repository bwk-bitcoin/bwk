# bwk-psbt

**Experimental. Do not use in production or with real coins. API will break.**

Native BIP370 PSBTv2 types.

A silent payment output has no scriptPubKey while the transaction is being
built: the script only exists once a signer derives it from the shared secret.
PSBTv0 cannot carry such an output, because its unsigned transaction fixes
every script up front. PSBTv2 drops the unsigned transaction and keeps the
inputs and outputs as plain fields, which is what lets the script arrive
later, so bwk carries silent payment spends in this format.

**Scope:** the PSBTv2 field model. Does NOT sign (use bwk-sign), build
transactions (use bwk-tx), or replace `bitcoin::Psbt` for wallets that stay on
PSBTv0.

## Types

- `PsbtV2`: the whole PSBT. Transaction version, fallback locktime, modifiable
  flags, global xpubs, the proprietary and unknown key-value maps, and the
  input and output lists.
- `Input`: previous output, sequence, the two required locktimes, and a
  `bitcoin::psbt::Input` holding every per-input field rust-bitcoin already
  models.
- `Output`: amount, the scriptPubKey (absent while a silent payment output is
  still underived), and a `bitcoin::psbt::Output`.
- `TxModifiable`: the inputs / outputs / sighash-single flags, rejecting any
  other bit.
- `Error`: every way a PSBTv2 can be malformed.

## Serialization

`serialize` writes the BIP370 key-value maps and `deserialize` reads them back.
Both refuse anything that is not version 2, including a PSBTv0 unsigned
transaction, a duplicate key or a missing required field.

```rust
use bwk_psbt::PsbtV2;

let bytes = psbt.serialize()?;
assert_eq!(PsbtV2::deserialize(&bytes)?, psbt);
```

## Validation

`validate` checks what the key-value layout alone cannot: no PSBTv2 keytype
hiding in an unknown map, each required locktime of the right kind (and a
height requirement never zero, which BIP370 reserves for "no requirement"),
every output carrying a script unless it is a silent payment output (see
below), modifiable flags only on a version 2 transaction, and per-input
locktime requirements that agree on one transaction locktime.

## PSBTv0 bridge

`from_bitcoin_psbt` takes an unsigned `bitcoin::Psbt` and `into_bitcoin_psbt`
goes back, so a PSBTv2 whose outputs all have a script still reaches every
rust-bitcoin and miniscript routine. `to_bitcoin_psbt_with_empty_sp_outputs`
converts by borrowing and substitutes an empty script, which is how a PSBT
with a still underived output is handed to code that insists on a complete
transaction. `unsigned_tx` builds the transaction the PSBT describes, at the
resolved locktime.

## Silent payment fields

The `sp` module holds the BIP375 keytypes rust-bitcoin does not model, under
their real keytype numbers so the wire bytes stay spec-correct: the ECDH share
and the DLEQ proof a sender publishes per scan key, and, on an output, the
scan and spend keys (`SpV0Output`) plus the optional label. The global getters
and setters come in a PSBTv0 and a PSBTv2 flavour, since a sender may still be
working on either; the per-output ones take a `bitcoin::psbt::Output`, which
both versions share.

`validate` reads those fields: an output with silent payment info may have no
script, a label without that info is refused, and an output whose script has
already been computed is refused unless the transaction is frozen, because the
script is derived from the inputs and any remaining modifiable field would
invalidate it.

The module also carries the BIP376 per-input fields, which describe an input
that is itself a silent payment: its own ECDH shares and DLEQ proofs, the
derivation of the spend key it needs, and the tweak `t` such that the input's
output key is `b_spend + t`, which is how a signer holding `b_spend`
recognises a silent payment it can spend.

## MuSig2 fields (BIP-373)

The `musig` module, behind the `musig` feature, holds the four BIP-373 keytypes
rust-bitcoin does not model. They live in the `unknown` map of a
`bitcoin::psbt::Input` / `Output` under their real keytype numbers, so the same
functions serve a `bitcoin::Psbt` (`psbt.inputs[i]`) and a `PsbtV2`
(`psbt.inputs[i].psbt`), and both serializations keep them.

```
+------+------------------+---------------------------------------------+---------------------+
| type | field            | keydata                                     | value               |
+------+------------------+---------------------------------------------+---------------------+
| 0x1a | in participants  | aggregate (33)                              | participant (33) *n |
| 0x1b | in pub nonce     | participant (33) aggregate (33) [leaf (32)] | public nonce (66)   |
| 0x1c | in partial sig   | participant (33) aggregate (33) [leaf (32)] | partial sig (32)    |
| 0x08 | out participants | aggregate (33)                              | participant (33) *n |
+------+------------------+---------------------------------------------+---------------------+
```

Every key is a 33-byte compressed key: an x-only key is refused. Participants
are listed in aggregation order (sorted when KeySort was used), at least one.

Which key goes in the aggregate slot:

- 0x1a and 0x08: the plain KeyAgg output, with no tweak. The path from it to the
  internal or script key is a `tap_key_origins` entry under the BIP-328 synthetic
  xpub fingerprint.
- 0x1b and 0x1c on the key path: the taproot output key (BIP-32 tweaks then the
  BIP-341 taptweak), with no leaf hash.
- 0x1b and 0x1c on a script path: the key as it appears in the leaf (BIP-32
  tweaks only), with the hash of that leaf.

The module stores what the caller passes and checks lengths and key encodings
only: applying the slot rule is the caller's job, and the nonce points and the
partial signature scalars are checked by bwk-musig.

```rust
use bwk_psbt::musig::{musig_input_pub_nonces, set_musig_input_participants};

set_musig_input_participants(&mut psbt.inputs[0], aggregate, &participants);
let nonces = musig_input_pub_nonces(&psbt_v2.inputs[0].psbt)?;
```
