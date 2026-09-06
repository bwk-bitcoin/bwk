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
