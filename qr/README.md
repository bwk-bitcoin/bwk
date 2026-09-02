# bwk-qr

`bwk-qr` provides QR generation, scanning, and the draft signing-flow
message transport for the bwk workspace.

Two layers sit on top of each other and are usable on their own:

- QR primitives: render a payload into a grayscale raster, read the codes back
  out of a camera frame. Pure Rust, no `unsafe`, no vendored C, no build script.
- The signing-flow protocol: the binary codec from
  [`bwk-qr-protocol`](../qr-protocol/README.md), chunked across animated frames
  with BBQR generic-binary framing.
  [ENCODING.md](../qr-protocol/ENCODING.md) is the authoritative wire format.

The codec is its own crate so a bare-metal signer can take it without the QR
layer; `bwk-qr` is the QR and framing layer on top.

Features, all on by default:

- `gen` uses `qrcodegen` to render grayscale QR images. It pulls nothing else.
- `scan` uses `quircs` to scan grayscale frames. It pulls only quircs' own small
  tree.
- `protocol` implies `gen` and `scan`, and adds BBQR framing over the
  signing-flow codec, which lives in `bwk-qr-protocol`. It turns on that crate's
  `bitcoin` feature, for the adapters between its byte-level types and the
  `bitcoin` ones.

`Encoder`, `Decoder`, `Config` and `Image` are the whole public surface;
generation and scanning are crate-internal helpers. `Image` is an 8-bit
grayscale raster, row-major, `width * height` bytes, `0` dark and `255` light: a
camera frame on the way in, a rendered QR on the way out.

Camera capture, windowing and rendering belong to the consumer, and so do
signing, PSBT finalization and descriptor evaluation: the protocol layer carries
PSBTs and descriptors, it does not interpret them. There is no async, no thread
and no global state, and the `Decoder` is the only stateful type.

```
qr/src/
  lib.rs      public modules, crate docs
  config.rs   Config, QR density and parser bounds
  error.rs    Error
  image.rs    Image, the one raw-data type crossing the API
  gen.rs      QR generation                          (feature: gen)
  scan.rs     grayscale decode                       (feature: scan)
  encoder.rs  plain text and protocol -> frames      (feature: gen)
  decoder.rs  frames -> Decoded, BBQR reassembly     (feature: scan)
```

The Rust API returns `Result` and `Option`. FFI consumers should translate those
types at their own boundary; `bwk-qr-protocol` ships a C binding for the codec.
