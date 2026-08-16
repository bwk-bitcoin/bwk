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
- `ffi` adds the C binding: `#[repr(C)]` mirrors of the message tree and four
  exported functions.

## Rust

```rust
use bwk_qr_protocol::{decode, encode_response, Message};

match decode(bytes)? {
    Message::Request(request) => { /* a signer answers it */ }
    Message::Response(response) => { /* a wallet consumes it */ }
}
let bytes = encode_response(&response)?;
```

## C

[`include/bwk_qr_protocol.h`](include/bwk_qr_protocol.h) is written by hand and
covers the signer direction: decode a request, encode a response. There is no
cbindgen and no build script.

```c
const bwk_qr_request *request = NULL;
const char *err = NULL;
if (bwk_qr_request_decode(bytes, len, &request, &err) != BWK_QR_OK) {
    fprintf(stderr, "%s\n", err);
    return 1;
}
/* read request->body.sign.psbt, then answer */
bwk_qr_request_free(request);
```

Ownership: the library never frees your memory, and you never free its memory except
through `bwk_qr_request_free` and `bwk_qr_buf_free`. On encode your struct is
borrowed for the duration of the call only.

The C functions return `BWK_QR_OK` on success or one of the C binding status codes
from `include/bwk_qr_protocol.h` on failure. These codes are not the wire `ERROR`
field from `ENCODING.md`; they report local decode, encode, or FFI failures.

```
+-------------------+------------------+
| Return code range | Source           |
+-------------------+------------------+
| 0                 | Success          |
| 100..199          | Byte reader      |
| 200..299          | Protocol decoder |
| 300..399          | Protocol encoder |
| 400..499          | C binding        |
+-------------------+------------------+
```

A `staticlib` needs a global allocator and a panic handler, which a library cannot
supply, so link this crate as an rlib from your own staticlib crate:

```toml
[lib]
crate-type = ["staticlib"]

[dependencies]
bwk-qr-protocol = { version = "0.0.1", features = ["ffi"] }
```

```rust
pub use bwk_qr_protocol::ffi::*;
```

[`examples/signer.c`](examples/signer.c) is a smoke test against that setup. It is
compiled by hand rather than from CI, which keeps `cc` out of the build:

```sh
cc -I include -Wall -Wextra -o signer examples/signer.c path/to/libyourshim.a
```
