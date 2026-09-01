# bwk-coin

**Experimental. Do not use in production or with real coins. API will break.**

Coin domain types shared by scanning and transaction building.

A coin is what scanning finds and what spending consumes, so these types sit
below both `bwk-electrum` and `bwk-tx` rather than inside either one. A wallet
can hand the same `Coin` from its store straight to a transaction builder.

**Scope:** the coin type, its status and spend info, and the two traits a wallet
implements to feed a builder. Does NOT do coin selection or transaction building
(use bwk-tx), address derivation (use bwk-descriptor), or signing (use
bwk-sign).

## Usage

```rust
use bwk_coin::{Coin, CoinSource};

struct MyStore(Vec<Coin>);

impl CoinSource for MyStore {
    fn spendable_coins(&self) -> Vec<Coin> {
        self.0.clone()
    }
}
```

## Types

- `Coin`: the UTXO, with its outpoint, txout, height, sequence, label,
  satisfaction size and spend info.
- `CoinStatus`: unconfirmed, confirmed but not yet proven by a merkle branch
  (`ConfirmedUnverified`), confirmed, being spent, spent.
- `CoinSpendInfo`: how the coin is spent. `Bip32` carries the keychain, index
  and descriptor, `Sp` carries the BIP352 derivation and tweak.
- `CoinSourceKind`: what kind of output the coin is (silent payment, segwit,
  taproot, other).
- `KeyChain`: receive, change, or a custom index.

`Coin` converts to a `TxIn`, and to a PSBT input through `to_psbt_input()`,
which fills in the descriptor derivation for BIP32 coins.

## Traits

- `CoinSource`: implemented by a wallet to hand its spendable coins to a
  transaction builder. Implemented for `BTreeMap<OutPoint, Coin>` under the
  `test` feature.
- `ChangeTip`: implemented by a wallet to hand out the next change index.

## Helpers

- `max_input_satisfaction_size(descriptor)`: worst case satisfaction size in
  weight units for an input spending that descriptor.
- `shuffle_coins(coins)`: shuffle a coin list into random order.
- `TAPROOT_KEYSPEND_SATISFACTION_WU`: 66 WU, the witness satisfaction weight of
  a single taproot key-spend input.
