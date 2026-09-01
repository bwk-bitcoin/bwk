# bwk-tx

**Experimental. Do not use in production or with real coins. API will break.**

Transaction building, coin selection, and PSBT generation.

Provides `TxBuilder` for constructing transactions with automatic coin selection
and fee estimation. Supports both standard descriptor outputs and Silent Payment
recipients through the `RecipientProvider` trait.

**Scope:** Transaction construction, coin selection algorithm, fee calculation,
PSBT creation. Does NOT handle signing (use bwk-sign), broadcasting or UTXO
tracking (use bwk-electrum or bwk-sp), and does not define the coin types it
selects over (they come from bwk-coin).

## Usage

```rust
use bwk_tx::{ChangeRecipientProvider, TxBuilder};

// The change provider and the coin source are boxed trait objects
let change_provider = ChangeRecipientProvider::new(descriptor, network);

// Create builder with change provider, coin source and fee rate
let mut builder = TxBuilder::new(Box::new(change_provider))
    .coin_source(Box::new(wallet_coins))
    .feerate_sat_vb(2);

// Add recipient
builder.send_to(address, 50_000);

// Build transaction; inputs are selected from the coin source
let psbt = builder.generate()?;
```

## Key Traits

- `RecipientProvider`: Creates outputs (address + amount + PSBT metadata)
- `CoinSource`: Provides spendable coins for selection
- `ChangeTip`: Manages change address index progression
- `CoinCandidate`: Coin with value and satisfaction weight for selection

The coin domain types this builder works over, `Coin`, `CoinSource` and
`ChangeTip`, are defined in bwk-coin and re-used by bwk-electrum.

## Coin Selection

Weighted random selection algorithm that:
- Prefers fewer inputs to reduce fees
- Avoids dust change outputs
- Respects target feerate

## Types

- `TxBuilder`: Main builder with fluent API
- `TxTemplate`: Inputs, outputs, and fee specification
- `Fees`: Fee specification, absolute sats or msat/vB
