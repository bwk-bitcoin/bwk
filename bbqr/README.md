# bwk-bbqr

BBQR split and join for binary data.

`split` cuts a payload into as few parts as the given maximum allows, all of
equal length: only the last part may be shorter, and never by much, so 164 bytes
at a maximum of 163 are two parts of 82 rather than 163 and 1. `Joiner` takes
the parts back in any order.

**Scope:** only the hex encoding (`H`) and the binary file type (`B`), so
`is_part` accepts only `B$HB` parts. Base32 (`2`), zlib (`Z`) and the other
file types are not supported, and a foreign part (e.g. `B$HP...`) is not
recognised as BBQR. bwk's own signing-flow messages are binary `bipqr`
payloads, which is all this codec carries.
