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

**Scope:** the hex (`H`) and base32 (`2`) encodings and the binary file type
(`B`), so `is_part` accepts only `B$HB` and `B$2B` parts. Zlib (`Z`) and the
other file types are not supported, and a foreign part (e.g. `B$HP...`) is not
recognised as BBQR. bwk's own signing-flow messages are binary `bipqr`
payloads, which is all this codec carries.
