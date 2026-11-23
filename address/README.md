# bwk-address

`bwk-address` parses BIP-321 `bitcoin:` URIs, with BIP-352 silent payment
addresses. It is `no_std` plus `alloc`. The `Backend` trait turns what a URI
carries into the consumer's types; the `bitcoin_0_32` feature provides
`backend::rust_bitcoin::RustBitcoin`, over rust-bitcoin types, and is on by default. A custom
backend depends on the crate with `default-features = false`.

## Usage

```rust
use bwk_address::backend::{
    rust_bitcoin::{Address, RustBitcoin, SilentPaymentAddress},
    Backend,
};

match RustBitcoin::parse_uri("bitcoin:?sp=sp1q...")? {
    Address::Bitcoin(address) => { /* bitcoin::Address<NetworkUnchecked>, any network */ }
    Address::SilentPayment(address) => { /* SilentPaymentAddress over secp256k1 keys */ }
}

let address = SilentPaymentAddress::try_from("sp1q...")?;
```

`RustBitcoin::parse_uri` refuses an `amount` that is not a bitcoin amount or is
zero. `sp::Network` converts from a `bitcoin::Network` (signet maps to testnet).

A custom backend picks its address types and implements
`Backend::bitcoin_address` (the address string of the URI path, checked against
the URI grammar only), `Backend::silent_payment_address` (the network and the two
33-byte keys of a decoded silent payment address) and `Backend::check_amount`; it
gets `Backend::parse_uri` and `Backend::parse_silent_payment_address` from them.

The URI parser follows the one of the `bip321` crate (MIT), but accepts every
network, does not check the values it discards, and refuses a URI with no address
or with more than one.

## Features

```
+------------------+---------+----------------------------------------------+
| Feature flag     | Default | Description                                  |
+------------------+---------+----------------------------------------------+
| `bitcoin_0_32`   | -       | Convert to and from `bitcoin` 0.32           |
| `bitcoin_latest` | yes     | Alias for `bitcoin_0_32`                     |
| `serde`          | -       | Serialize the network, and with a backend    |
|                  |         | the silent payment address as its string     |
+------------------+---------+----------------------------------------------+
```

The bitcoin release features are mutually exclusive.

The silent payment address derives from rust-silentpayments (MIT), see
[NOTICE](NOTICE).
