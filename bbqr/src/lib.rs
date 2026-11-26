const PREFIX: &str = "B$HB";
pub const HEADER_LEN: usize = 8;
pub const MAX_PARTS: usize = 36 * 36 - 1;
// A version 1 QR code at error correction Low holds 25 alphanumeric chars: after the
// header, 8 bytes fill it, `/ 2` as each byte takes two hex chars. A smaller part
// still needs a version 1 code, so it only adds parts.
pub const MIN_PART_BYTES: usize = (25 - HEADER_LEN) / 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub received: Vec<bool>,
    pub last: usize,
}

impl Progress {
    pub fn total(&self) -> usize {
        self.received.len()
    }

    pub fn seen(&self) -> usize {
        self.received.iter().filter(|received| **received).count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("empty payload")]
    EmptyPayload,
    #[error("part count {0} exceeds the maximum of {max}", max = MAX_PARTS)]
    TooManyParts(usize),
    #[error("conflicting part count")]
    ConflictingPartCount,
    #[error("part index {0} is out of range")]
    PartIndexOutOfRange(usize),
    #[error("conflicting duplicate part at index {0}")]
    ConflictingDuplicatePart(usize),
    #[error("invalid part header")]
    InvalidPartHeader,
    #[error("invalid file type")]
    InvalidFileType,
    #[error("part count is zero")]
    ZeroParts,
    #[error("invalid base36 digit {0:#04x}")]
    InvalidBase36Digit(u8),
    #[error("odd hex length {0}")]
    OddHexLength(usize),
    #[error("invalid hex digit {0:#04x}")]
    InvalidHexDigit(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    pub parts: Vec<String>,
}

impl Split {
    /// The bytes the longest part carries. [`split`] gives every part as many, except the
    /// last, which may carry fewer.
    pub fn part_bytes(&self) -> usize {
        self.parts
            .iter()
            .map(|part| part.len().saturating_sub(HEADER_LEN) / 2)
            .max()
            .unwrap_or(0)
    }
}

/// The first [`HEADER_LEN`] chars of a part, e.g. `B$HB0A03`: `B$`, `H` for hex
/// encoding, `B` for binary file type, then the part count (10) and the part index (3),
/// each as two base36 digits. The digits are `0` to `9` then `A` to `Z`, uppercase only
/// so a part stays in the QR alphanumeric set: a field runs from `00` to `ZZ` (1295,
/// [`MAX_PARTS`]) and a lowercase digit is refused.
struct Header {
    total: usize,
    index: usize,
}

impl Header {
    fn parse(part: &str) -> Result<Self, Error> {
        if part.len() < HEADER_LEN || !part.is_ascii() {
            return Err(Error::InvalidPartHeader);
        }
        if !part.starts_with(PREFIX) {
            return Err(Error::InvalidFileType);
        }
        let bytes = part.as_bytes();
        let total = Self::parse_field(bytes[4], bytes[5])?;
        if total == 0 {
            return Err(Error::ZeroParts);
        }
        let index = Self::parse_field(bytes[6], bytes[7])?;
        if index >= total {
            return Err(Error::PartIndexOutOfRange(index));
        }
        Ok(Self { total, index })
    }

    /// `split` keeps `total` at most [`MAX_PARTS`] and `index` below it, so both fields
    /// fit two digits.
    fn serialize(&self) -> String {
        let mut header = String::with_capacity(HEADER_LEN);
        header.push_str(PREFIX);
        for field in [self.total, self.index] {
            header.push(Self::digit(field / 36));
            header.push(Self::digit(field % 36));
        }
        header
    }

    fn parse_field(hi: u8, lo: u8) -> Result<usize, Error> {
        Ok(Self::value(hi)? * 36 + Self::value(lo)?)
    }

    fn digit(n: usize) -> char {
        match n {
            0..=9 => (b'0' + n as u8) as char,
            10..=35 => (b'A' + (n as u8 - 10)) as char,
            _ => unreachable!(),
        }
    }

    fn value(b: u8) -> Result<usize, Error> {
        match b {
            b'0'..=b'9' => Ok((b - b'0') as usize),
            b'A'..=b'Z' => Ok((b - b'A' + 10) as usize),
            _ => Err(Error::InvalidBase36Digit(b)),
        }
    }
}

struct Part {
    total: usize,
    index: usize,
    data: Vec<u8>,
}

impl Part {
    fn parse(part: &str) -> Result<Self, Error> {
        let Header { total, index } = Header::parse(part)?;
        let data = parse_hex(&part[HEADER_LEN..])?;
        Ok(Self { total, index, data })
    }
}

#[derive(Debug, Clone)]
pub struct Joiner {
    total: Option<usize>,
    parts: Vec<Option<Vec<u8>>>,
    last: Option<usize>,
}

impl Joiner {
    pub fn new() -> Self {
        Self {
            total: None,
            parts: Vec::new(),
            last: None,
        }
    }

    pub fn add_part(&mut self, part: &str) -> Result<Option<Vec<u8>>, Error> {
        let parsed = Part::parse(part)?;
        if self.total.is_some_and(|total| total != parsed.total) {
            return Err(Error::ConflictingPartCount);
        }
        match self.parts.get(parsed.index) {
            Some(Some(existing)) if existing != &parsed.data => {
                return Err(Error::ConflictingDuplicatePart(parsed.index));
            }
            Some(Some(_)) => {
                self.last = Some(parsed.index);
                return Ok(None);
            }
            Some(None) | None => {
                if self.total.is_none() {
                    self.total = Some(parsed.total);
                    self.parts = vec![None; parsed.total];
                }
                self.parts[parsed.index] = Some(parsed.data);
                self.last = Some(parsed.index);
            }
        }
        if self.is_complete() {
            let mut data = Vec::new();
            for item in &self.parts {
                data.extend_from_slice(item.as_ref().expect("checked complete"));
            }
            return Ok(Some(data));
        }
        Ok(None)
    }

    fn is_complete(&self) -> bool {
        self.total.is_some() && self.parts.iter().all(Option::is_some)
    }

    pub fn progress(&self) -> Option<Progress> {
        self.last.map(|last| Progress {
            received: self.parts.iter().map(Option::is_some).collect(),
            last,
        })
    }
}

impl Default for Joiner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_part(s: &str) -> bool {
    s.starts_with(PREFIX)
}

/// Cuts `data` into BBQR parts of equal length, in index order: as few parts as
/// `max_part_bytes` bytes each allows, then the shortest length that fills that many.
/// Every part carries the same number of bytes and only the last may carry fewer, by
/// less than the part count: 164 bytes at a maximum of 163 are two parts of 82, not 163
/// and 1. A part is written as an 8-char header such as `B$HB0A03` (index 3 of 10 parts)
/// followed by its bytes in hex.
///
/// A `max_part_bytes` below [`MIN_PART_BYTES`] is raised to it, which only bounds the
/// part count: an equal part may still be shorter. Refuses empty `data` and a `data`
/// that needs more than [`MAX_PARTS`] parts.
pub fn split(data: &[u8], max_part_bytes: usize) -> Result<Split, Error> {
    let max_part_bytes = max_part_bytes.max(MIN_PART_BYTES);
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }
    let total = data.len().div_ceil(max_part_bytes);
    if total > MAX_PARTS {
        return Err(Error::TooManyParts(total));
    }
    // at most `max_part_bytes`, and cuts `data` into exactly `total` chunks
    let part_bytes = data.len().div_ceil(total);
    let mut parts = Vec::new();
    for (index, chunk) in data.chunks(part_bytes).enumerate() {
        let mut part = Header { total, index }.serialize();
        part.push_str(&hex(chunk));
        parts.push(part);
    }
    Ok(Split { parts })
}

/// `bytes` as uppercase hex, two digits per byte, high nibble first: `[0x1f, 0xa0]` is
/// `1FA0`. Uppercase keeps the part in the QR alphanumeric set.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The inverse of [`hex`]: `1FA0` is `[0x1f, 0xa0]`, and so is `1fa0`. An odd length is
/// refused.
fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::OddHexLength(s.len()));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
        .collect()
}

/// The value of the hex digit `b`, 0 to 15.
fn hex_value(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(Error::InvalidHexDigit(b)),
    }
}

#[cfg(test)]
mod tests {
    use crate::{split, Error, Joiner, Progress, Split, HEADER_LEN, MAX_PARTS, MIN_PART_BYTES};

    const DATA: &[u8] = b"abcdefghijklmnopqrst";

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|index| index as u8).collect()
    }

    fn part_lengths(split: &Split) -> Vec<usize> {
        split
            .parts
            .iter()
            .map(|part| (part.len() - HEADER_LEN) / 2)
            .collect()
    }

    fn join(split: &Split) -> Option<Vec<u8>> {
        let mut joiner = Joiner::new();
        let mut joined = None;
        for part in &split.parts {
            assert_eq!(joined, None);
            joined = joiner.add_part(part).unwrap();
        }
        joined
    }

    #[test]
    fn split_join_round_trip() {
        let split = split(DATA, 8).unwrap();
        assert_eq!(
            split.parts,
            vec![
                "B$HB030061626364656667",
                "B$HB030168696A6B6C6D6E",
                "B$HB03026F7071727374",
            ]
        );
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part(&split.parts[2]).unwrap(), None);
        assert_eq!(
            joiner.progress(),
            Some(Progress {
                received: vec![false, false, true],
                last: 2,
            })
        );
        assert_eq!(joiner.add_part(&split.parts[0]).unwrap(), None);
        assert_eq!(
            joiner.add_part(&split.parts[1]).unwrap(),
            Some(DATA.to_vec())
        );
    }

    #[test]
    fn progress_tracks_out_of_order_parts() {
        let split = split(DATA, 8).unwrap();
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part(&split.parts[2]), Ok(None));
        assert_eq!(joiner.progress().unwrap().last, 2);
        assert_eq!(joiner.add_part(&split.parts[0]), Ok(None));
        let progress = joiner.progress().unwrap();
        assert_eq!(progress.received, vec![true, false, true]);
        assert_eq!(progress.last, 0);
        assert_eq!(progress.seen(), 2);
        assert_eq!(progress.total(), 3);
        assert_eq!(joiner.add_part(&split.parts[2]), Ok(None));
        let progress = joiner.progress().unwrap();
        assert_eq!(progress.received, vec![true, false, true]);
        assert_eq!(progress.last, 2);
        assert_eq!(joiner.add_part(&split.parts[0]), Ok(None));
        assert_eq!(joiner.progress().unwrap().last, 0);
    }

    #[test]
    fn a_part_of_a_completed_message_is_a_duplicate() {
        let split = split(DATA, 8).unwrap();
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part(&split.parts[0]), Ok(None));
        assert_eq!(joiner.add_part(&split.parts[1]), Ok(None));
        assert_eq!(joiner.add_part(&split.parts[2]), Ok(Some(DATA.to_vec())));
        assert_eq!(joiner.add_part(&split.parts[1]), Ok(None));
        assert_eq!(
            joiner.progress(),
            Some(Progress {
                received: vec![true, true, true],
                last: 1,
            })
        );
    }

    #[test]
    fn a_completed_message_refuses_a_part_of_another_part_count() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part("B$HB020061"), Ok(None));
        assert_eq!(joiner.add_part("B$HB020162"), Ok(Some(b"ab".to_vec())));
        assert_eq!(
            joiner.add_part("B$HB030063"),
            Err(Error::ConflictingPartCount)
        );
    }

    #[test]
    fn parts_are_equal_except_a_last_one_that_may_be_shorter() {
        for max in MIN_PART_BYTES..=70 {
            for len in 1..=300 {
                let data = payload(len);
                let split = split(&data, max).unwrap();
                let lengths = part_lengths(&split);
                let (last, rest) = lengths.split_last().unwrap();
                let part_bytes = split.part_bytes();
                assert_eq!(lengths.len(), len.div_ceil(max), "{len} at {max}");
                assert!(part_bytes <= max, "{len} at {max}");
                assert!(rest.iter().all(|length| *length == part_bytes));
                assert!((1..=part_bytes).contains(last), "{len} at {max}");
                assert!(part_bytes - last < lengths.len(), "{len} at {max}");
                assert_eq!(join(&split), Some(data), "{len} at {max}");
            }
        }
    }

    #[test]
    fn a_split_leaves_no_runt_part() {
        let cases: [(usize, usize, &[usize]); 5] = [
            (17, 8, &[6, 6, 5]),
            (163, 163, &[163]),
            (164, 163, &[82, 82]),
            (327, 163, &[109, 109, 109]),
            (1000, 163, &[143, 143, 143, 143, 143, 143, 142]),
        ];
        for (len, max, lengths) in cases {
            let split = split(&payload(len), max).unwrap();
            assert_eq!(part_lengths(&split), lengths, "{len} at {max}");
            assert_eq!(split.part_bytes(), lengths[0], "{len} at {max}");
        }
    }

    #[test]
    fn raises_a_part_size_below_the_minimum_to_it() {
        let minimum = split(DATA, MIN_PART_BYTES).unwrap();
        assert_eq!(split(DATA, 0), Ok(minimum.clone()));
        assert_eq!(split(DATA, 7), Ok(minimum));
    }

    #[test]
    fn accepts_lowercase_hex() {
        assert_eq!(
            Joiner::new().add_part("B$HB01001fA0"),
            Ok(Some(vec![0x1f, 0xa0]))
        );
    }

    #[test]
    fn rejects_malformed_parts() {
        let mut joiner = Joiner::new();
        assert!(joiner.add_part("B$HB0000").is_err());
        assert!(joiner.add_part("B$HB0100F").is_err());
        assert!(joiner.add_part("B$HB0100FG").is_err());
    }

    #[test]
    fn rejects_too_many_parts() {
        assert_eq!(
            split(&[0; (MAX_PARTS + 1) * MIN_PART_BYTES], MIN_PART_BYTES),
            Err(Error::TooManyParts(MAX_PARTS + 1))
        );
    }

    #[test]
    fn rejects_a_conflicting_part_count() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part("B$HB020061"), Ok(None));
        assert_eq!(
            joiner.add_part("B$HB030162"),
            Err(Error::ConflictingPartCount)
        );
    }

    #[test]
    fn rejects_a_part_index_out_of_range() {
        let mut joiner = Joiner::new();
        assert_eq!(
            joiner.add_part("B$HB020261"),
            Err(Error::PartIndexOutOfRange(2))
        );
    }

    #[test]
    fn a_rejected_first_part_does_not_lock_the_part_count() {
        let mut joiner = Joiner::new();
        assert_eq!(
            joiner.add_part("B$HB020261"),
            Err(Error::PartIndexOutOfRange(2))
        );
        assert_eq!(joiner.progress(), None);
        assert_eq!(joiner.add_part("B$HB03006162"), Ok(None));
        assert_eq!(joiner.add_part("B$HB03016364"), Ok(None));
        assert_eq!(
            joiner.add_part("B$HB03026566"),
            Ok(Some(b"abcdef".to_vec()))
        );
    }

    #[test]
    fn rejects_a_conflicting_duplicate_part() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part("B$HB020061"), Ok(None));
        assert_eq!(
            joiner.add_part("B$HB020062"),
            Err(Error::ConflictingDuplicatePart(0))
        );
    }
}
