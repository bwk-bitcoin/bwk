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
