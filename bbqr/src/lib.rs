const PREFIX: &str = "B$HB";
const HEADER_LEN: usize = 8;
pub const MAX_PARTS: usize = 1295;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub seen: usize,
    pub total: usize,
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
    #[error("joined data of {0} bytes exceeds the message limit")]
    JoinedDataTooLarge(usize),
    #[error("invalid part header")]
    InvalidPartHeader,
    #[error("invalid file type")]
    InvalidFileType,
    #[error("part count is zero")]
    ZeroParts,
    #[error("base36 value {0} does not fit two digits")]
    Base36OutOfRange(usize),
    #[error("base36 field of {0} chars, expected 2")]
    InvalidBase36Length(usize),
    #[error("invalid base36 digit {0:#04x}")]
    InvalidBase36Digit(u8),
    #[error("odd hex length {0}")]
    OddHexLength(usize),
    #[error("invalid hex digit {0:#04x}")]
    InvalidHexDigit(u8),
    #[error("BBQR part size is zero")]
    ZeroPartSize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Split {
    pub parts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Joiner {
    total: Option<usize>,
    parts: Vec<Option<Vec<u8>>>,
}

impl Joiner {
    pub fn new() -> Self {
        Self {
            total: None,
            parts: Vec::new(),
        }
    }

    pub fn add_part(&mut self, part: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
        if self.is_complete() {
            *self = Self::new();
        }
        let parsed = Part::parse(part)?;
        if parsed.total > MAX_PARTS {
            return Err(Error::TooManyParts(parsed.total));
        }
        match self.total {
            Some(total) if total != parsed.total => {
                return Err(Error::ConflictingPartCount);
            }
            Some(_) => {}
            None => {
                self.total = Some(parsed.total);
                self.parts = vec![None; parsed.total];
            }
        }
        if parsed.index >= parsed.total {
            return Err(Error::PartIndexOutOfRange(parsed.index));
        }
        match &self.parts[parsed.index] {
            Some(existing) if existing != &parsed.data => {
                return Err(Error::ConflictingDuplicatePart(parsed.index));
            }
            Some(_) => return Ok(None),
            None => self.parts[parsed.index] = Some(parsed.data),
        }
        if self.is_complete() {
            let mut data = Vec::new();
            for item in &self.parts {
                data.extend_from_slice(item.as_ref().expect("checked complete"));
                if data.len() > max_bytes {
                    return Err(Error::JoinedDataTooLarge(data.len()));
                }
            }
            return Ok(Some(data));
        }
        Ok(None)
    }

    fn is_complete(&self) -> bool {
        self.total.is_some() && self.parts.iter().all(Option::is_some)
    }

    pub fn progress(&self) -> Option<Progress> {
        self.total.map(|total| Progress {
            seen: self.parts.iter().filter(|part| part.is_some()).count(),
            total,
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

pub fn split(data: &[u8], part_bytes: usize) -> Result<Split, Error> {
    if data.is_empty() {
        return Err(Error::EmptyPayload);
    }
    if part_bytes == 0 {
        return Err(Error::ZeroPartSize);
    }
    let total = data.len().div_ceil(part_bytes);
    if total == 0 || total > MAX_PARTS {
        return Err(Error::TooManyParts(total));
    }
    let total = base36(total)?;
    let mut parts = Vec::new();
    for (index, chunk) in data.chunks(part_bytes).enumerate() {
        let mut part = String::with_capacity(HEADER_LEN + chunk.len() * 2);
        part.push_str(PREFIX);
        part.push_str(&total);
        part.push_str(&base36(index)?);
        part.push_str(&hex(chunk));
        parts.push(part);
    }
    Ok(Split { parts })
}

struct Part {
    total: usize,
    index: usize,
    data: Vec<u8>,
}

impl Part {
    fn parse(part: &str) -> Result<Self, Error> {
        if part.len() < HEADER_LEN || !part.is_ascii() {
            return Err(Error::InvalidPartHeader);
        }
        if !part.starts_with(PREFIX) {
            return Err(Error::InvalidFileType);
        }
        let total = parse_base36(&part[4..6])?;
        if total == 0 {
            return Err(Error::ZeroParts);
        }
        let index = parse_base36(&part[6..8])?;
        let data = parse_hex(&part[8..])?;
        Ok(Self { total, index, data })
    }
}

fn base36(n: usize) -> Result<String, Error> {
    if n >= 36 * 36 {
        return Err(Error::Base36OutOfRange(n));
    }
    let hi = digit(n / 36);
    let lo = digit(n % 36);
    Ok(format!("{hi}{lo}"))
}

fn parse_base36(s: &str) -> Result<usize, Error> {
    if s.len() != 2 {
        return Err(Error::InvalidBase36Length(s.len()));
    }
    let bytes = s.as_bytes();
    Ok(value(bytes[0])? * 36 + value(bytes[1])?)
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.len() % 2 != 0 {
        return Err(Error::OddHexLength(s.len()));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
        .collect()
}

fn hex_value(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::InvalidHexDigit(b)),
    }
}

#[cfg(test)]
mod tests {
    use crate::{split, Error, Joiner, Progress};

    #[test]
    fn split_join_round_trip() {
        let split = split(b"abcdef", 2).unwrap();
        assert_eq!(
            split.parts,
            vec!["B$HB03006162", "B$HB03016364", "B$HB03026566"]
        );
        let mut joiner = Joiner::new();
        assert_eq!(joiner.add_part(&split.parts[2], 10).unwrap(), None);
        assert_eq!(joiner.progress(), Some(Progress { seen: 1, total: 3 }));
        assert_eq!(joiner.add_part(&split.parts[0], 10).unwrap(), None);
        assert_eq!(
            joiner.add_part(&split.parts[1], 10).unwrap(),
            Some(b"abcdef".to_vec())
        );
    }

    #[test]
    fn rejects_a_zero_part_size() {
        assert_eq!(split(b"abcdef", 0), Err(Error::ZeroPartSize));
    }

    #[test]
    fn rejects_malformed_parts() {
        let mut joiner = Joiner::new();
        assert!(joiner.add_part("B$HB0000", 10).is_err());
        assert!(joiner.add_part("B$HB0100F", 10).is_err());
        assert!(joiner.add_part("B$HB0100FG", 10).is_err());
    }
}
