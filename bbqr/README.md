# bwk-bbqr

BBQR split and join for binary data.

**Scope:** only the hex encoding (`H`) and the binary file type (`B`), so
`is_part` accepts only `B$HB` parts. Base32 (`2`), zlib (`Z`) and the other
file types are not supported, and a foreign part (e.g. `B$HP...`) is not
recognised as BBQR. bwk's own signing-flow messages are binary `bipqr`
payloads, which is all this codec carries.
