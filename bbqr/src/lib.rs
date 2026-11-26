mod base32;
mod hex;
mod inflate;
#[cfg(test)]
mod test_data;

const MAGIC: &str = "B$";
/// The binary file type, the only one this crate reads and writes.
const FILE_TYPE: u8 = b'B';
pub const HEADER_LEN: usize = 8;
pub const MAX_PARTS: usize = 36 * 36 - 1;
// A version 1 QR code at error correction Low holds 25 alphanumeric chars. A shorter
// part still needs a version 1 code, so it only adds parts.
pub const MIN_PART_LEN: usize = 25;
/// The most bytes [`Joiner`] inflates a compressed series to: what the [`MAX_PARTS`]
/// parts of a series carry at most in base32, 2680 bytes in each QR code of version 40.
/// A compressed series then takes no more memory than an uncompressed one may, when a
/// deflate stream can hold a thousand times its own length.
pub const MAX_INFLATED_BYTES: usize = MAX_PARTS * 2680;

/// How a part writes its bytes after the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `H`: two uppercase hex digits per byte.
    Hex,
    /// `2`: base32 in the RFC 4648 alphabet, without padding, 8 chars per 5 bytes.
    Base32,
    /// `Z`: the whole payload compressed into one raw deflate stream, with neither a
    /// zlib header nor a checksum, that the parts then carry as [`Encoding::Base32`].
    /// [`Joiner`] reads it. [`split`] does not compress yet and writes such a payload in
    /// base32, as the format has a sender do with one that compression does not shrink.
    Zlib,
}

impl Encoding {
    /// The bytes a part of `part_len` chars carries, header included, when another part
    /// follows it: as many whole units as fit after the header, a unit being 2 hex chars
    /// for a byte or 8 base32 chars for 5 bytes. A sole part needs not end on a unit, so
    /// in base32 it may carry up to 4 bytes more. A compressed part carries bytes of the
    /// deflate stream, not of the payload.
    pub fn part_bytes(self, part_len: usize) -> usize {
        let (unit_chars, unit_bytes) = self.unit();
        part_len.saturating_sub(HEADER_LEN) / unit_chars * unit_bytes
    }

    /// The chars, then the bytes they decode to, of the shortest run of chars that
    /// decodes on its own to whole bytes whatever the bytes.
    fn unit(self) -> (usize, usize) {
        match self {
            Self::Hex => (2, 1),
            Self::Base32 | Self::Zlib => (8, 5),
        }
    }

    fn code(self) -> char {
        match self {
            Self::Hex => 'H',
            Self::Base32 => '2',
            Self::Zlib => 'Z',
        }
    }

    fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            b'H' => Ok(Self::Hex),
            b'2' => Ok(Self::Base32),
            b'Z' => Ok(Self::Zlib),
            _ => Err(Error::InvalidEncoding(code)),
        }
    }

    fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Hex => hex::encode(bytes),
            Self::Base32 | Self::Zlib => base32::encode(bytes),
        }
    }

    fn decode(self, body: &str) -> Result<Vec<u8>, Error> {
        match self {
            Self::Hex => hex::decode(body),
            Self::Base32 | Self::Zlib => base32::decode(body),
        }
    }
}

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
    #[error("conflicting encoding")]
    ConflictingEncoding,
    #[error("part index {0} is out of range")]
    PartIndexOutOfRange(usize),
    #[error("conflicting duplicate part at index {0}")]
    ConflictingDuplicatePart(usize),
    #[error("invalid part header")]
    InvalidPartHeader,
    #[error("invalid encoding {0:#04x}")]
    InvalidEncoding(u8),
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
    #[error("invalid base32 length {0}")]
    InvalidBase32Length(usize),
    #[error("invalid base32 digit {0:#04x}")]
    InvalidBase32Digit(u8),
    #[error("base32 bits set past the last byte")]
    Base32TrailingBits,
    #[error("deflate stream ends before its last block")]
    TruncatedDeflate,
    #[error("bytes after the last block of the deflate stream")]
    TrailingDeflateData,
    #[error("invalid deflate block")]
    InvalidDeflateBlock,
    #[error("invalid deflate code")]
    InvalidDeflateCode,
    #[error("deflate distance is out of range")]
    InvalidDeflateDistance,
    #[error("inflated payload exceeds {max} bytes", max = MAX_INFLATED_BYTES)]
    InflatedTooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    /// The encoding of every part, which is not always the one [`split`] was asked for.
    pub encoding: Encoding,
    pub parts: Vec<String>,
}

impl Split {
    /// The chars of the longest part, header included. [`split`] gives every part as
    /// many, except the last, which may be shorter.
    pub fn part_len(&self) -> usize {
        self.parts.iter().map(String::len).max().unwrap_or(0)
    }
}

/// The first [`HEADER_LEN`] chars of a part, e.g. `B$HB0A03`: `B$`, the encoding (`H`
/// for hex, `2` for base32, `Z` for zlib), `B` for the binary file type, then the part
/// count (10) and the part index (3), each as two base36 digits. The digits are `0` to `9` then `A` to
/// `Z`, uppercase only so a part stays in the QR alphanumeric set: a field runs from
/// `00` to `ZZ` (1295, [`MAX_PARTS`]) and a lowercase digit is refused.
struct Header {
    encoding: Encoding,
    total: usize,
    index: usize,
}

impl Header {
    fn parse(part: &str) -> Result<Self, Error> {
        let Some(bytes) = part.as_bytes().get(..HEADER_LEN) else {
            return Err(Error::InvalidPartHeader);
        };
        if !bytes.starts_with(MAGIC.as_bytes()) {
            return Err(Error::InvalidPartHeader);
        }
        let encoding = Encoding::from_code(bytes[2])?;
        if bytes[3] != FILE_TYPE {
            return Err(Error::InvalidFileType);
        }
        let total = Self::parse_field(bytes[4], bytes[5])?;
        if total == 0 {
            return Err(Error::ZeroParts);
        }
        let index = Self::parse_field(bytes[6], bytes[7])?;
        if index >= total {
            return Err(Error::PartIndexOutOfRange(index));
        }
        Ok(Self {
            encoding,
            total,
            index,
        })
    }

    /// `split` keeps `total` at most [`MAX_PARTS`] and `index` below it, so both fields
    /// fit two digits.
    fn serialize(&self) -> String {
        let mut header = String::with_capacity(HEADER_LEN);
        header.push_str(MAGIC);
        header.push(self.encoding.code());
        header.push(FILE_TYPE as char);
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
    encoding: Encoding,
    total: usize,
    index: usize,
    data: Vec<u8>,
}

impl Part {
    fn parse(part: &str) -> Result<Self, Error> {
        let Header {
            encoding,
            total,
            index,
        } = Header::parse(part)?;
        // a header that parses is ASCII, so the body starts on a char boundary
        let data = encoding.decode(&part[HEADER_LEN..])?;
        Ok(Self {
            encoding,
            total,
            index,
            data,
        })
    }
}

/// Takes the parts of one series in any order, each decoded on its own as it comes, and
/// gives the payload with the last one: the bytes of the parts in index order, inflated
/// when the series is compressed.
///
/// A compressed series that does not inflate, or to more than [`MAX_INFLATED_BYTES`],
/// is an error of the part that completes it. Its parts are then duplicates like those
/// of any complete series, until a new `Joiner` takes over.
#[derive(Debug, Clone)]
pub struct Joiner {
    /// The encoding and the part count of the first part accepted, that every other
    /// part must carry.
    series: Option<(Encoding, usize)>,
    parts: Vec<Option<Vec<u8>>>,
    last: Option<usize>,
}

impl Joiner {
    pub fn new() -> Self {
        Self {
            series: None,
            parts: Vec::new(),
            last: None,
        }
    }

    pub fn add_part(&mut self, part: &str) -> Result<Option<Vec<u8>>, Error> {
        let parsed = Part::parse(part)?;
        if let Some((encoding, total)) = self.series {
            if total != parsed.total {
                return Err(Error::ConflictingPartCount);
            }
            if encoding != parsed.encoding {
                return Err(Error::ConflictingEncoding);
            }
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
                if self.series.is_none() {
                    self.series = Some((parsed.encoding, parsed.total));
                    self.parts = vec![None; parsed.total];
                }
                self.parts[parsed.index] = Some(parsed.data);
                self.last = Some(parsed.index);
            }
        }
        if self.is_complete() {
            return self.join().map(Some);
        }
        Ok(None)
    }

    fn join(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        for item in &self.parts {
            data.extend_from_slice(item.as_ref().expect("checked complete"));
        }
        match self.series {
            Some((Encoding::Zlib, _)) => {
                inflate::inflate(&data, MAX_INFLATED_BYTES, inflate::MAX_DISTANCE)
            }
            _ => Ok(data),
        }
    }

    fn is_complete(&self) -> bool {
        self.series.is_some() && self.parts.iter().all(Option::is_some)
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

/// Whether `s` starts like a part this crate reads: `B$`, an encoding it knows, and the
/// binary file type. A part of another file type, such as `B$HP...`, is not one.
pub fn is_part(s: &str) -> bool {
    match s.as_bytes() {
        [b'B', b'$', encoding, FILE_TYPE, ..] => Encoding::from_code(*encoding).is_ok(),
        _ => false,
    }
}

/// Cuts `data` into BBQR parts of equal length, in index order: as few parts as
/// `max_part_len` chars each allows, header included, then the shortest length that
/// fills that many. Every part carries the same number of bytes and only the last may
/// carry fewer: 164 bytes in hex, at 163 a part, are two parts of 82, not 163 and 1. A
/// part is written as an 8-char header such as `B$HB0A03` (index 3 of 10 parts, in hex)
/// followed by its bytes in `encoding`.
///
/// A part that another follows decodes on its own, so it carries whole units of its
/// encoding: 2 hex chars for a byte, 8 base32 chars for 5 bytes. The last part is then
/// shorter than the others by less than one unit per part: in bytes, less than the part
/// count in hex and less than 5 times it in base32. A payload that fits a sole part
/// needs no whole unit, which in base32 packs up to 4 bytes more into it.
///
/// [`Encoding::Zlib`] is written as [`Encoding::Base32`] for now, which
/// [`Split::encoding`] then is.
///
/// A `max_part_len` below [`MIN_PART_LEN`] is raised to it, which only bounds the part
/// count: an equal part may still be shorter. Refuses empty `data` and a `data` that
/// needs more than [`MAX_PARTS`] parts.
pub fn split(data: &[u8], encoding: Encoding, max_part_len: usize) -> Result<Split, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }
    let encoding = match encoding {
        Encoding::Zlib => Encoding::Base32,
        encoding => encoding,
    };
    let max_part_len = max_part_len.max(MIN_PART_LEN);
    let (unit_chars, unit_bytes) = encoding.unit();
    let body = max_part_len - HEADER_LEN;
    let sole_part_bytes =
        body / unit_chars * unit_bytes + body % unit_chars * unit_bytes / unit_chars;
    let total = if data.len() <= sole_part_bytes {
        1
    } else {
        data.len().div_ceil(encoding.part_bytes(max_part_len))
    };
    if total > MAX_PARTS {
        return Err(Error::TooManyParts(total));
    }
    // whole units, at most those of `max_part_len`, that cut `data` into exactly `total`
    // chunks
    let part_bytes = data.len().div_ceil(total * unit_bytes) * unit_bytes;
    let mut parts = Vec::new();
    for (index, chunk) in data.chunks(part_bytes).enumerate() {
        let header = Header {
            encoding,
            total,
            index,
        };
        let mut part = header.serialize();
        part.push_str(&encoding.encode(chunk));
        parts.push(part);
    }
    Ok(Split { encoding, parts })
}

#[cfg(test)]
mod tests {
    use crate::{
        is_part, split, test_data::ramp, Encoding, Error, Joiner, Progress, Split, HEADER_LEN,
        MAX_PARTS, MIN_PART_LEN,
    };

    const DATA: &[u8] = b"abcdefghijklmnopqrst";
    const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog, ";
    const ENCODINGS: [Encoding; 2] = [Encoding::Hex, Encoding::Base32];

    /// The length of a part carrying `bytes` bytes in hex.
    fn hex_len(bytes: usize) -> usize {
        HEADER_LEN + 2 * bytes
    }

    fn split_hex(data: &[u8], max_part_bytes: usize) -> Result<Split, Error> {
        split(data, Encoding::Hex, hex_len(max_part_bytes))
    }

    /// The bytes each part of `split` carries.
    fn part_bytes(split: &Split) -> Vec<usize> {
        split
            .parts
            .iter()
            .map(|part| split.encoding.decode(&part[HEADER_LEN..]).unwrap().len())
            .collect()
    }

    fn join<S: AsRef<str>>(parts: &[S]) -> Option<Vec<u8>> {
        let mut joiner = Joiner::new();
        let mut joined = None;
        for part in parts {
            assert_eq!(joined, None);
            joined = joiner.add_part(part.as_ref()).unwrap();
        }
        joined
    }

    #[test]
    fn split_join_round_trip() {
        let split = split_hex(DATA, 8).unwrap();
        assert_eq!(split.encoding, Encoding::Hex);
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
    fn base32_parts_carry_five_bytes_in_eight_chars() {
        let split = split(DATA, Encoding::Base32, MIN_PART_LEN).unwrap();
        assert_eq!(split.encoding, Encoding::Base32);
        assert_eq!(
            split.parts,
            vec!["B$2B0200MFRGGZDFMZTWQ2LK", "B$2B0201NNWG23TPOBYXE43U"]
        );
        assert_eq!(join(&split.parts), Some(DATA.to_vec()));
    }

    #[test]
    fn progress_tracks_out_of_order_parts() {
        let split = split_hex(DATA, 8).unwrap();
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
        let split = split_hex(DATA, 8).unwrap();
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
        for encoding in ENCODINGS {
            let (unit_chars, unit_bytes) = encoding.unit();
            for max in MIN_PART_LEN..=150 {
                let sole = (max - HEADER_LEN) * unit_bytes / unit_chars;
                for len in 1..=300 {
                    let case = format!("{len} bytes at {max} in {encoding:?}");
                    let data = ramp(len);
                    let split = split(&data, encoding, max).unwrap();
                    assert_eq!(split.encoding, encoding, "{case}");
                    assert!(split.part_len() <= max, "{case}");
                    let lengths = part_bytes(&split);
                    let (last, rest) = lengths.split_last().unwrap();
                    if len <= sole {
                        assert_eq!(lengths, [len], "{case}");
                        continue;
                    }
                    let part = encoding.part_bytes(split.part_len());
                    assert_eq!(lengths.len(), len.div_ceil(encoding.part_bytes(max)));
                    assert!(rest.iter().all(|length| *length == part), "{case}");
                    assert_eq!(part % unit_bytes, 0, "{case}");
                    assert!((1..=part).contains(last), "{case}");
                    assert!(part - last < unit_bytes * lengths.len(), "{case}");
                    assert_eq!(join(&split.parts), Some(data), "{case}");
                }
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
            let split = split_hex(&ramp(len), max).unwrap();
            assert_eq!(part_bytes(&split), lengths, "{len} at {max}");
            assert_eq!(split.part_len(), hex_len(lengths[0]), "{len} at {max}");
        }
    }

    // 335 chars hold 327 after the header: 40 units of 5 bytes, or 204 bytes off a unit
    #[test]
    fn a_base32_part_before_another_ends_on_five_bytes() {
        let cases: [(usize, usize, &[usize]); 9] = [
            (10, 25, &[10]),
            (11, 25, &[10, 1]),
            (21, 25, &[10, 10, 1]),
            (200, 335, &[200]),
            (204, 335, &[204]),
            (205, 335, &[105, 100]),
            (400, 335, &[200, 200]),
            (401, 335, &[135, 135, 131]),
            (1000, 335, &[200, 200, 200, 200, 200]),
        ];
        for (len, max, lengths) in cases {
            let split = split(&ramp(len), Encoding::Base32, max).unwrap();
            assert_eq!(part_bytes(&split), lengths, "{len} at {max}");
        }
    }

    #[test]
    fn a_part_carries_whole_units_after_its_header() {
        let cases = [
            (Encoding::Hex, 0, 0),
            (Encoding::Hex, 25, 8),
            (Encoding::Hex, 26, 9),
            (Encoding::Hex, 335, 163),
            (Encoding::Base32, 7, 0),
            (Encoding::Base32, 15, 0),
            (Encoding::Base32, 16, 5),
            (Encoding::Base32, 25, 10),
            (Encoding::Base32, 335, 200),
            (Encoding::Zlib, 25, 10),
            (Encoding::Zlib, 335, 200),
        ];
        for (encoding, part_len, bytes) in cases {
            assert_eq!(encoding.part_bytes(part_len), bytes, "{encoding:?}");
        }
    }

    #[test]
    fn raises_a_part_length_below_the_minimum_to_it() {
        for encoding in ENCODINGS {
            let minimum = split(DATA, encoding, MIN_PART_LEN).unwrap();
            assert_eq!(split(DATA, encoding, 0), Ok(minimum.clone()));
            assert_eq!(split(DATA, encoding, MIN_PART_LEN - 1), Ok(minimum));
        }
    }

    #[test]
    fn handles_unbounded_part_length_without_overflow() {
        for encoding in [Encoding::Hex, Encoding::Base32, Encoding::Zlib] {
            for max in [usize::MAX, usize::MAX / 5 + HEADER_LEN + 1] {
                let split = split(DATA, encoding, max).unwrap();
                assert_eq!(split.parts.len(), 1, "{encoding:?} at {max}");
                assert_eq!(join(&split.parts), Some(DATA.to_vec()));
            }
        }
    }

    // the two series the reference implementation cuts 23 bytes into, at 16 and at 8
    // base32 chars a part:
    //   body = base64.b32encode(bytes(range(23))).decode().rstrip("=")
    //   parts = [header(index) + body[at:at + chars] for at in range(0, len(body), chars)]
    #[test]
    fn joins_the_base32_parts_of_the_reference_in_any_order() {
        let series: [&[&str]; 2] = [
            &[
                "B$2B0302CQKRM",
                "B$2B0300AAAQEAYEAUDAOCAJ",
                "B$2B0301BIFQYDIOB4IBCEQT",
            ],
            &[
                "B$2B0503B4IBCEQT",
                "B$2B0501AUDAOCAJ",
                "B$2B0504CQKRM",
                "B$2B0500AAAQEAYE",
                "B$2B0502BIFQYDIO",
            ],
        ];
        for parts in series {
            assert_eq!(join(parts), Some(ramp(23)));
        }
    }

    // series the reference implementation compresses and cuts, at 8 then at 32 base32
    // chars a part:
    //   c = zlib.compressobj(wbits=-10); stream = c.compress(payload) + c.flush()
    //   body = base64.b32encode(stream).decode().rstrip("=")
    #[test]
    fn joins_the_zlib_parts_of_the_reference_in_any_order() {
        let series: [(&[&str], Vec<u8>); 2] = [
            (&["B$ZB0201AA", "B$ZB0200MNT2OPIA"], vec![7; 100]),
            (
                &[
                    "B$ZB0301ZAVM2LJIK3EC6SZNKIUACSXHERLFKKVE",
                    "B$ZB03024ST6XADZQNADCAA",
                    "B$ZB0300FPEUQVJIFTGUZTSWJAVMUL6PKNEMXL2Q",
                ],
                TEXT.repeat(4),
            ),
        ];
        for (parts, payload) in series {
            assert_eq!(join(parts), Some(payload));
        }
    }

    // the stream of the series above in one part, less its last byte, then with one more
    #[test]
    fn rejects_a_zlib_series_that_does_not_inflate() {
        let cases = [
            (
                "B$ZB0100FPEUQVJIFTGUZTSWJAVMUL6PKNEMXL2QZAVM2LJIK3EC6SZNKIUACSXHERLFKKVE4ST6XADZQ\
                 NADC",
                Error::TruncatedDeflate,
            ),
            (
                "B$ZB0100FPEUQVJIFTGUZTSWJAVMUL6PKNEMXL2QZAVM2LJIK3EC6SZNKIUACSXHERLFKKVE4ST6XADZQ\
                 NADCAAA",
                Error::TrailingDeflateData,
            ),
        ];
        for (part, error) in cases {
            let mut joiner = Joiner::new();
            assert_eq!(joiner.add_part(part), Err(error), "{part}");
            assert_eq!(joiner.add_part(part), Ok(None), "{part}");
        }
    }

    #[test]
    fn writes_base32_for_zlib() {
        let split = split(DATA, Encoding::Zlib, MIN_PART_LEN).unwrap();
        assert_eq!(
            Ok(split),
            super::split(DATA, Encoding::Base32, MIN_PART_LEN)
        );
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
        assert_eq!(
            Joiner::new().add_part("B$HB0100\u{00e9}"),
            Err(Error::InvalidHexDigit(0xc3))
        );
    }

    #[test]
    fn rejects_malformed_base32() {
        let cases = [
            ("B$2B0100M", Error::InvalidBase32Length(1)),
            ("B$2B0100my", Error::InvalidBase32Digit(b'm')),
            ("B$2B0100MY======", Error::InvalidBase32Digit(b'=')),
            ("B$2B0100MZ", Error::Base32TrailingBits),
            ("B$2B0100\u{00e9}", Error::InvalidBase32Digit(0xc3)),
        ];
        for (part, error) in cases {
            assert_eq!(Joiner::new().add_part(part), Err(error), "{part}");
        }
    }

    #[test]
    fn rejects_a_malformed_header() {
        let cases = [
            ("B$HB010", Error::InvalidPartHeader),
            ("A$HB0100", Error::InvalidPartHeader),
            ("B$XB0100", Error::InvalidEncoding(b'X')),
            ("B$hB0100", Error::InvalidEncoding(b'h')),
            ("B$HP0100", Error::InvalidFileType),
            ("B$2B0000", Error::ZeroParts),
            ("B$2B0a00", Error::InvalidBase36Digit(b'a')),
            // a char that starts in the header and ends past it
            ("B$HB010\u{e9}", Error::InvalidBase36Digit(0xc3)),
        ];
        for (part, error) in cases {
            assert_eq!(Joiner::new().add_part(part), Err(error), "{part}");
        }
    }

    #[test]
    fn only_a_binary_part_in_a_known_encoding_is_a_part() {
        let parts = [
            "B$HB",
            "B$2B",
            "B$ZB",
            "B$HB0100FF",
            "B$2B0100MY",
            "B$ZB0100AMAA",
        ];
        for part in parts {
            assert!(is_part(part), "{part}");
        }
        let texts = [
            "",
            "B$H",
            "B$HP0100FF",
            "B$2P0100MY",
            "B$ZP0100AMAA",
            "B$XB0100",
            "b$HB0100",
            "bitcoin:",
        ];
        for text in texts {
            assert!(!is_part(text), "{text}");
        }
    }

    #[test]
    fn rejects_too_many_parts() {
        let part_bytes = Encoding::Hex.part_bytes(MIN_PART_LEN);
        assert_eq!(
            split(
                &vec![0; (MAX_PARTS + 1) * part_bytes],
                Encoding::Hex,
                MIN_PART_LEN
            ),
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
    fn rejects_a_conflicting_encoding() {
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part("B$HB020061"), Ok(None));
        for part in ["B$2B0201MI", "B$ZB0201MI"] {
            assert_eq!(joiner.add_part(part), Err(Error::ConflictingEncoding));
        }
        assert_eq!(joiner.add_part("B$HB020162"), Ok(Some(b"ab".to_vec())));
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
    fn a_rejected_first_part_locks_neither_the_part_count_nor_the_encoding() {
        let mut joiner = Joiner::new();
        assert_eq!(
            joiner.add_part("B$HB020261"),
            Err(Error::PartIndexOutOfRange(2))
        );
        assert_eq!(joiner.progress(), None);
        assert_eq!(joiner.add_part("B$2B0300MFRA"), Ok(None));
        assert_eq!(joiner.add_part("B$2B0301MNSA"), Ok(None));
        assert_eq!(
            joiner.add_part("B$2B0302MVTA"),
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
