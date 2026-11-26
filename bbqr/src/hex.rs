use crate::Error;

/// `bytes` as uppercase hex, two digits per byte, high nibble first: `[0x1f, 0xa0]` is
/// `1FA0`. Uppercase keeps the part in the QR alphanumeric set.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The inverse of [`encode`]: `1FA0` is `[0x1f, 0xa0]`, and so is `1fa0`. An odd length
/// is refused.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::OddHexLength(s.len()));
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(value(pair[0])? << 4 | value(pair[1])?))
        .collect()
}

/// The value of the hex digit `b`, 0 to 15.
fn value(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Error::InvalidHexDigit(b)),
    }
}
