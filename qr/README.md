# bwk-qr

`bwk-qr` provides QR generation, scanning, and the draft signing-flow
message transport for the bwk workspace.

Two layers sit on top of each other and are usable on their own:

- QR primitives: render a payload into a grayscale raster, read the codes back
  out of a camera frame. Pure Rust, no `unsafe`, no vendored C, no build script.
- The signing-flow protocol: the binary codec from
  [`bipqr`](https://github.com/pythcoiner/bipqr), chunked across animated frames
  with BBQR generic-binary framing. Its ENCODING.md is the authoritative wire
  format.

The codec lives in its own repository so a bare-metal signer can take it without
the QR layer; `bwk-qr` is the QR and framing layer on top.

Features, all on by default:

- `gen` uses `qrcodegen` to render grayscale QR images. It pulls nothing else.
- `scan` uses `quircs` to scan grayscale frames. It pulls only quircs' own small
  tree.
- `bbqr` implies `gen` and `scan`, and adds BBQR generic-binary framing for any
  payload: `Encoder::encode_bbqr` splits bytes into frames, and
  `Decoder::process_raw` joins them back into `Decoded::Bytes`, undecoded.
  The parts go out in hex unless `Encoder::with_bbqr_encoding` picks base32,
  which carries a quarter more per frame, or zlib, which compresses the payload
  first and writes one that does not shrink in base32. The `Decoder` reads all
  three. `Decoder::progress` returns a `bwk_bbqr::Progress` and
  `with_bbqr_encoding` takes a `bwk_bbqr::Encoding`, so a caller that uses
  either depends on `bwk-bbqr`.
- `protocol` implies `bbqr`, and decodes the joined payloads as the signing-flow
  codec, which lives in `bipqr`: the codec under `bipqr::ll`, and with its
  `bitcoin_0_32` feature on, `bipqr::backend` converts between its byte-level
  types and the `bitcoin` ones. A caller of the protocol depends on `bipqr` for
  these types.

`serde`, off by default, derives `Serialize` and `Deserialize` on `QrDensity`, so a
caller can store the setting.

`Encoder`, `Decoder` with `Decoded`, the `config` module (`QrSize`, `QrDensity`,
`DecoderConfig`), the `image` module (`Image`, `crop_center_square`, `box_shrink`,
`shrink_factor`, `SCAN_SIDE`) and `Error` are the whole public surface; generation
and scanning are crate-internal helpers. The `Encoder` is built with a size, a
`QrSize` or the coarser `QrDensity`, and has no default one. That size is a
ceiling: a plain text code renders at the smallest size it fits, and a BBQR
payload is cut into as few equal parts as the ceiling allows, every frame of the
series at the smallest size that holds such a part. A BBQR frame with room left
at that size takes a higher error-correction level. `Image` is an 8-bit
grayscale square, row-major, `side * side` bytes, `0` dark and `255` light: a camera
frame on the way in, cropped to its centered square by `Image::from_frame`, a
rendered QR on the way out. The `Decoder` reads it shrunk by the largest integer
factor that keeps its side at or above `SCAN_SIDE` (1080), so a 1080 frame is read
whole and a 2160 one at 1080, unless `DecoderConfig::fine_scan` is set; a code
outside the centered square of the camera frame is not read.

Camera capture, windowing and rendering belong to the consumer, and so do
signing, PSBT finalization and descriptor evaluation: the protocol layer carries
PSBTs and descriptors, it does not interpret them. There is no async, no thread
and no global state, and the `Decoder` is the only stateful type.

```
qr/src/
  lib.rs       public modules, crate docs
  config.rs    QrSize, QrDensity, DecoderConfig: QR size and scan bounds
  error.rs     Error
  image.rs     Image, the one raw-data type crossing the API
  gen.rs       QR generation                          (feature: gen)
  scan.rs      grayscale decode                       (feature: scan)
  threshold.rs local adaptive threshold fallback      (feature: scan)
  encoder.rs   plain text, bytes, protocol -> frames  (feature: gen)
  decoder.rs   frames -> Decoded, BBQR reassembly     (feature: scan)
```

The Rust API returns `Result` and `Option`. FFI consumers should translate those
types at their own boundary; `bipqr-ll` ships a C binding for the codec.
