# bwk-bbqr

BBQR split and join for binary data.

`split` cuts a payload into as few parts as the given maximum part length
allows, all of equal length: only the last part may be shorter, and never by
much, so 164 bytes in hex, at 163 a part, are two parts of 82 rather than 163
and 1. `Joiner` takes the parts back in any order.

A part writes its bytes in hex (`H`), two chars a byte, or in base32 (`2`),
8 chars per 5 bytes, without padding. A part that another follows decodes on
its own, so in base32 it carries a multiple of 5 bytes; a payload that fits a
sole part needs not, and packs up to 4 bytes more into it. The parts of one
series share one encoding.

In a zlib series (`Z`) the payload is first compressed as a whole into a raw
deflate stream, with neither a zlib header nor a checksum, which the parts then
carry in base32. `split` keeps the stream only when it is shorter than the
payload, and writes the payload in plain base32 otherwise, as the format has a
sender do: `Split::encoding` tells which.

Both the compressor and the inflater are the crate's own, with no dependency:

- the compressor writes for a decoder that keeps a window of 1024 bytes
  (zlib's `wbits=10`), and like zlib never reaches back more than 762 bytes.
  Its tests hold its streams to the length of zlib's own at that window;
- the inflater reads any raw deflate stream, and stops at
  `MAX_INFLATED_BYTES`, the 3,470,600 bytes a full series of version 40 codes
  carries in base32, so a compressed series takes no more memory than an
  uncompressed one may. A stream that ends early, or that bytes follow, is an
  error.

**Scope:** the three encodings and the binary file type (`B`), so `is_part`
accepts only `B$HB`, `B$2B` and `B$ZB` parts. The other file types are not
supported, and a foreign part (e.g. `B$HP...`) is not recognised as BBQR.
bwk's own signing-flow messages are binary `bipqr` payloads, which is all this
codec carries.
