# bwk-qr-protocol

The binary codec for the draft signing-flow protocol between a wallet and a signer.
[ENCODING.md](ENCODING.md) is the authoritative format; this crate implements it and
nothing else. Framing (BBQR) and QR rendering live in `bwk-qr`.

The crate is `no_std` plus `alloc` and pulls no dependency in its default
configuration, so a bare-metal signer can vendor it as-is. `bitcoin` types are
deliberately absent: every one of them is a fixed-size array or an opaque blob on the
wire, so the codec carries `Xpub([u8; 78])`, `Fingerprint([u8; 4])`,
`PublicKey([u8; 33])`, `DerivationPath(Vec<u32>)` and a plain `Vec<u8>` for the PSBT.
That keeps `secp256k1-sys` and its vendored C off the firmware build.

## Features

- `bitcoin` adds `From`/`TryFrom` between those types and the `bitcoin` ones, for
  callers that already run on `std`. `bwk-qr` enables it.

## Rust

```rust
use bwk_qr_protocol::{decode, encode_response, Message};

match decode(bytes)? {
    Message::Request(request) => { /* a signer answers it */ }
    Message::Response(response) => { /* a wallet consumes it */ }
}
let bytes = encode_response(&response)?;
```
