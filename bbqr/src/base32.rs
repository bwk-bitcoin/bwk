use crate::Error;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `bytes` in base32, the RFC 4648 alphabet (`A` to `Z` then `2` to `7`) without its `=`
/// padding: 8 chars per 5 bytes, high bits first, so `fo` is `MZXQ`. Every char is in
/// the QR alphanumeric set.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    // the low `bits` bits of `buffer` are not written yet
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = buffer << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(buffer >> bits) as usize & 0x1f] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (5 - bits)) as usize & 0x1f] as char);
    }
    out
}

/// The inverse of [`encode`]. Refuses a char outside the alphabet, lowercase included,
/// a length no whole number of bytes encodes to (1, 3 or 6 chars past a multiple of 8),
/// and a bit set past the last whole byte: a string cut off a byte boundary rather than
/// encoded on its own.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if matches!(s.len() % 8, 1 | 3 | 6) {
        return Err(Error::InvalidBase32Length(s.len()));
    }
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    // the low `bits` bits of `buffer` are not written yet
    let mut buffer = 0u32;
    let mut bits = 0;
    for digit in s.bytes() {
        buffer = buffer << 5 | u32::from(value(digit)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if buffer & ((1 << bits) - 1) != 0 {
        return Err(Error::Base32TrailingBits);
    }
    Ok(out)
}

/// The value of the base32 digit `digit`, 0 to 31.
fn value(digit: u8) -> Result<u8, Error> {
    match digit {
        b'A'..=b'Z' => Ok(digit - b'A'),
        b'2'..=b'7' => Ok(digit - b'2' + 26),
        _ => Err(Error::InvalidBase32Digit(digit)),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        base32::{decode, encode},
        Error,
    };

    // RFC 4648 section 10, without the padding
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn encodes_the_rfc_vectors_without_padding() {
        for (text, encoded) in VECTORS {
            assert_eq!(encode(text.as_bytes()), encoded);
            assert_eq!(decode(encoded), Ok(text.as_bytes().to_vec()));
        }
    }

    #[test]
    fn every_length_round_trips() {
        for len in 0..=64usize {
            let bytes: Vec<u8> = (0..len).map(|index| (index * 37 + 11) as u8).collect();
            let encoded = encode(&bytes);
            assert_eq!(encoded.len(), (len * 8).div_ceil(5), "{len} bytes");
            assert_eq!(decode(&encoded), Ok(bytes), "{len} bytes");
        }
    }

    #[test]
    fn rejects_a_length_no_whole_bytes_encode_to() {
        for encoded in ["A", "AAA", "AAAAAA", "AAAAAAAAA", "AAAAAAAAAAA"] {
            assert_eq!(
                decode(encoded),
                Err(Error::InvalidBase32Length(encoded.len()))
            );
        }
    }

    #[test]
    fn rejects_a_digit_outside_the_alphabet() {
        for (encoded, digit) in [("M1", b'1'), ("my", b'm'), ("MY======", b'='), ("M8", b'8')] {
            assert_eq!(decode(encoded), Err(Error::InvalidBase32Digit(digit)));
        }
    }

    // `MZ` is the first two chars of `MZXQ`: `f`, then two bits of the next byte
    #[test]
    fn rejects_bits_past_the_last_whole_byte() {
        for encoded in ["MZ", "MZXW", "MZXW7", "MZXW6YR"] {
            assert_eq!(decode(encoded), Err(Error::Base32TrailingBits));
        }
    }
}
