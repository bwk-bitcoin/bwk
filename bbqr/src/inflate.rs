use crate::Error;

/// The farthest back a deflate stream may copy from: its largest window.
pub(crate) const MAX_DISTANCE: usize = 32768;

/// The longest code of a deflate stream, in bits.
const MAX_BITS: usize = 15;
const END_OF_BLOCK: usize = 256;
/// The symbols of the literal and length code, 286 and 287 being none.
const LITERAL_SYMBOLS: usize = 288;
/// The symbols of the distance code, 30 and 31 being none.
const DISTANCE_SYMBOLS: usize = 32;
// RFC 1951 section 3.2.5: the length of symbol 257 + n is `LENGTH_BASE[n]` plus the
// value of `LENGTH_EXTRA[n]` more bits, and likewise the distance of symbol n
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// The symbols of the code length code, in the order a dynamic block sends their
/// lengths.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// The bytes of the raw deflate stream `data` (RFC 1951), which has neither a zlib
/// header nor a checksum.
///
/// Refuses a stream that ends before its last block does, one with bytes after it, one
/// that copies from farther back than `max_distance` or than its own output, and one
/// that holds more than `max_len` bytes, without inflating it any further.
pub(crate) fn inflate(data: &[u8], max_len: usize, max_distance: usize) -> Result<Vec<u8>, Error> {
    let mut reader = Reader::new(data);
    let mut output = Output {
        bytes: Vec::new(),
        max_len,
        max_distance,
    };
    loop {
        let last = reader.bits(1)? == 1;
        match reader.bits(2)? {
            0 => stored(&mut reader, &mut output)?,
            1 => {
                let (literals, distances) = fixed_codes()?;
                compressed(&mut reader, &mut output, &literals, &distances)?;
            }
            2 => {
                let (literals, distances) = dynamic_codes(&mut reader)?;
                compressed(&mut reader, &mut output, &literals, &distances)?;
            }
            _ => return Err(Error::InvalidDeflateBlock),
        }
        if last {
            break;
        }
    }
    if reader.at != data.len() {
        return Err(Error::TrailingDeflateData);
    }
    Ok(output.bytes)
}

/// The bits of a stream, each byte from its lowest bit. It takes a byte only once it
/// needs one of its bits, so every byte before `at` is at least partly read.
struct Reader<'a> {
    data: &'a [u8],
    /// The next byte to take.
    at: usize,
    /// The bits taken and not read yet, the next one lowest.
    buffer: u32,
    /// How many bits `buffer` holds, at most 7 between two reads.
    count: u32,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            at: 0,
            buffer: 0,
            count: 0,
        }
    }

    /// The next `count` bits, at most 16, as a number whose lowest bit is the first one.
    fn bits(&mut self, count: u32) -> Result<usize, Error> {
        while self.count < count {
            let byte = self.data.get(self.at).ok_or(Error::TruncatedDeflate)?;
            self.buffer |= u32::from(*byte) << self.count;
            self.count += 8;
            self.at += 1;
        }
        let value = self.buffer & ((1 << count) - 1);
        self.buffer >>= count;
        self.count -= count;
        Ok(value as usize)
    }

    /// Drops the bits left of the byte being read, then takes the next `count` bytes.
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], Error> {
        self.buffer = 0;
        self.count = 0;
        let bytes = self
            .data
            .get(self.at..)
            .and_then(|rest| rest.get(..count))
            .ok_or(Error::TruncatedDeflate)?;
        self.at += count;
        Ok(bytes)
    }
}

struct Output {
    bytes: Vec<u8>,
    max_len: usize,
    max_distance: usize,
}

impl Output {
    fn extend(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends `length` bytes read from `distance` bytes back, one at a time: a distance
    /// shorter than the length repeats the bytes it has just written.
    fn copy(&mut self, distance: usize, length: usize) -> Result<(), Error> {
        if distance > self.bytes.len() || distance > self.max_distance {
            return Err(Error::InvalidDeflateDistance);
        }
        self.reserve(length)?;
        for _ in 0..length {
            self.bytes.push(self.bytes[self.bytes.len() - distance]);
        }
        Ok(())
    }

    fn reserve(&self, more: usize) -> Result<(), Error> {
        if more > self.max_len - self.bytes.len() {
            return Err(Error::InflatedTooLarge);
        }
        Ok(())
    }
}

/// A canonical Huffman code, the one its code lengths define (RFC 1951 section 3.2.2):
/// `counts[n]` symbols have a code of `n` bits, and `symbols` lists them from the
/// shortest code to the longest, then by value.
struct Huffman {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    /// The code of `lengths`, one length of at most [`MAX_BITS`] per symbol, 0 for a
    /// symbol with no code. Refuses lengths that are those of no prefix code, and
    /// lengths that leave some bit strings to no symbol: unless `lone`, which lets a
    /// code hold no symbol at all, or a single one in one bit, the way a block with no
    /// match or a single distance is written.
    fn new(lengths: &[u8], lone: bool) -> Result<Self, Error> {
        let mut counts = [0u16; MAX_BITS + 1];
        for length in lengths {
            counts[usize::from(*length)] += 1;
        }
        // the codes left unused at each length
        let mut left = 1i32;
        for count in &counts[1..] {
            left = (left << 1) - i32::from(*count);
            if left < 0 {
                return Err(Error::InvalidDeflateCode);
            }
        }
        let coded = lengths.len() - usize::from(counts[0]);
        if left > 0 && !(lone && coded == usize::from(counts[1])) {
            return Err(Error::InvalidDeflateCode);
        }
        // where the symbols of each length start in `symbols`
        let mut starts = [0usize; MAX_BITS + 1];
        for bits in 1..MAX_BITS {
            starts[bits + 1] = starts[bits] + usize::from(counts[bits]);
        }
        let mut symbols = vec![0; coded];
        for (symbol, length) in lengths.iter().enumerate() {
            if *length != 0 {
                let start = &mut starts[usize::from(*length)];
                symbols[*start] = symbol as u16;
                *start += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    /// Reads one symbol, a bit at a time: the codes of a length are consecutive numbers
    /// that start where the shorter ones end, so at each length the bits read so far are
    /// either one of them or the start of a longer code.
    fn decode(&self, reader: &mut Reader) -> Result<usize, Error> {
        let mut code = 0;
        // the first code of this length, and where its symbol is in `symbols`
        let mut first = 0;
        let mut index = 0;
        for count in &self.counts[1..] {
            let count = usize::from(*count);
            code |= reader.bits(1)?;
            if code < first + count {
                return Ok(usize::from(self.symbols[index + code - first]));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(Error::InvalidDeflateCode)
    }
}

/// A stored block: its length, the complement of that length, then the bytes as they
/// are, all from the next whole byte.
fn stored(reader: &mut Reader, output: &mut Output) -> Result<(), Error> {
    let header = reader.bytes(4)?;
    let length = u16::from_le_bytes([header[0], header[1]]);
    let complement = u16::from_le_bytes([header[2], header[3]]);
    if length != !complement {
        return Err(Error::InvalidDeflateBlock);
    }
    output.extend(reader.bytes(usize::from(length))?)
}

/// The literal and length code, then the distance code, of a fixed block (RFC 1951
/// section 3.2.6).
fn fixed_codes() -> Result<(Huffman, Huffman), Error> {
    let mut lengths = [8u8; LITERAL_SYMBOLS];
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    Ok((
        Huffman::new(&lengths, false)?,
        Huffman::new(&[5; DISTANCE_SYMBOLS], false)?,
    ))
}

/// The two codes a dynamic block starts with (RFC 1951 section 3.2.7): their code
/// lengths, themselves written in a third code that comes first.
fn dynamic_codes(reader: &mut Reader) -> Result<(Huffman, Huffman), Error> {
    let literals = reader.bits(5)? + 257;
    let distances = reader.bits(5)? + 1;
    let code_lengths = reader.bits(4)? + 4;
    // RFC 1951 section 3.2.7: HLIT is 257..=286, HDIST is 1..=32 (distance symbols 30
    // and 31 are rejected in `value` if a match ever uses them).
    if literals > LITERAL_SYMBOLS - 2 {
        return Err(Error::InvalidDeflateCode);
    }
    let mut lengths = [0u8; CODE_LENGTH_ORDER.len()];
    for symbol in &CODE_LENGTH_ORDER[..code_lengths] {
        lengths[*symbol] = reader.bits(3)? as u8;
    }
    let code = Huffman::new(&lengths, false)?;

    let mut lengths: Vec<u8> = Vec::with_capacity(literals + distances);
    while lengths.len() < literals + distances {
        let (length, repeat) = match code.decode(reader)? {
            16 => {
                let previous = lengths.last().ok_or(Error::InvalidDeflateCode)?;
                (*previous, 3 + reader.bits(2)?)
            }
            17 => (0, 3 + reader.bits(3)?),
            18 => (0, 11 + reader.bits(7)?),
            length => (length as u8, 1),
        };
        if repeat > literals + distances - lengths.len() {
            return Err(Error::InvalidDeflateCode);
        }
        lengths.resize(lengths.len() + repeat, length);
    }
    if lengths[END_OF_BLOCK] == 0 {
        return Err(Error::InvalidDeflateCode);
    }
    let (literals, distances) = lengths.split_at(literals);
    Ok((
        Huffman::new(literals, true)?,
        Huffman::new(distances, true)?,
    ))
}

/// The symbols of a fixed or dynamic block up to its end: a literal byte, or a length
/// then a distance to copy from.
fn compressed(
    reader: &mut Reader,
    output: &mut Output,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), Error> {
    loop {
        let symbol = literals.decode(reader)?;
        if symbol == END_OF_BLOCK {
            return Ok(());
        }
        if symbol < END_OF_BLOCK {
            output.extend(&[symbol as u8])?;
            continue;
        }
        let length = value(
            reader,
            symbol - END_OF_BLOCK - 1,
            &LENGTH_BASE,
            &LENGTH_EXTRA,
        )?;
        let symbol = distances.decode(reader)?;
        let distance = value(reader, symbol, &DISTANCE_BASE, &DISTANCE_EXTRA)?;
        output.copy(distance, length)?;
    }
}

/// The length or the distance of `symbol`: its base, plus its extra bits read as a
/// number.
fn value(reader: &mut Reader, symbol: usize, base: &[u16], extra: &[u8]) -> Result<usize, Error> {
    let base = base.get(symbol).ok_or(Error::InvalidDeflateCode)?;
    Ok(usize::from(*base) + reader.bits(u32::from(extra[symbol]))?)
}

#[cfg(test)]
mod tests {
    use miniz_oxide::deflate::compress_to_vec;

    use crate::{
        hex,
        inflate::{inflate, MAX_DISTANCE},
        test_data::{noise, ramp, records},
        Error,
    };

    fn stream(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    fn inflate_all(data: &[u8]) -> Result<Vec<u8>, Error> {
        inflate(data, usize::MAX, MAX_DISTANCE)
    }

    /// 40 bytes of noise, 1200 zeros, then the same noise: a compressor with a window
    /// of 1024 bytes cannot reach the first copy from the second.
    fn far_apart() -> Vec<u8> {
        let key = noise(40, 3);
        [key.clone(), vec![0; 1200], key].concat()
    }

    /// Streams zlib wrote, each with the bytes it holds:
    ///   c = zlib.compressobj(level, zlib.DEFLATED, -10, 8, strategy)
    ///   stream = c.compress(data) + c.flush()
    fn streams() -> Vec<(&'static str, Vec<u8>)> {
        let mixed = (0..240).map(|i| ((i * 7) % 11) * ((i / 13) % 3) + 65);
        vec![
            // a fixed block that holds only its end
            ("0300", vec![]),
            ("4b0400", b"a".to_vec()),
            // stored blocks: at level 0, then as noise does not compress
            ("010500faff68656c6c6f", b"hello".to_vec()),
            (
                "014000bfff6c4e74921325222e31a1cd13be12ed426966ce24fc23d7da8d2097616a06956ec2\
                 8ad403136828d4571e3c5dee6e5ec04a91115f5d3b513ec253a416ad6ee538",
                noise(64, 7),
            ),
            // fixed blocks, the first with the Z_FIXED strategy
            ("4b4c4a4ec44000", b"abcabcabcabcabcabcabc".to_vec()),
            (
                "2bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae7245655\
                 2aa4e4a7eb807983403100",
                b"the quick brown fox jumps over the lazy dog, ".repeat(4),
            ),
            // a match that copies the bytes it writes
            ("4b4c1c05c40200", vec![b'a'; 300]),
            // dynamic blocks: without a match (Z_HUFFMAN_ONLY), then with matches
            (
                "05c1010100300cc320ada4bb7f0b070080aaaa6dbb7b00005555db76f70000aaaab6edee0100\
                 54556ddbdd0300a8aadab6bb07005055b56d77ef03",
                b"aaaaaaaaaaaaaaaabbbbbbbbccccdde".repeat(6),
            ),
            (
                "75cc310ec0200c43d1b3b921a434420821ee7f1586303843bdfae903b4e2265f7d9ae22dde75\
                 b9cc8661bb2b2b5c10f682b0691c338eadc438a61c1b89714c38e689fdc62cfe03",
                mixed.map(|byte: usize| byte as u8).collect(),
            ),
            // three blocks, each ended by the empty stored block of a Z_SYNC_FLUSH, one
            // every 16 bytes
            (
                "6260646266616563e7e0e4e2e6e1e5e307000000ffff1210141216111513979094929691959307\
                 000000ffff525054525651555307000000ffff0300",
                ramp(40),
            ),
        ]
    }

    // written with a window of 32768 bytes (wbits=-15)
    const FAR_APART: &str = "0b3e5c5bd1b7c577bb877eae9bade4d302159fdd0b1e47fca928f9d5b3716accfaad\
                             4642c1ff265f54d6611805a360148c82210282892cd700";

    #[test]
    fn inflates_what_zlib_wrote() {
        for (hex, bytes) in streams() {
            assert_eq!(inflate_all(&stream(hex)), Ok(bytes), "{hex}");
        }
    }

    #[test]
    fn inflates_what_miniz_wrote() {
        let corpus = [
            vec![],
            ramp(1),
            ramp(700),
            noise(3000, 1),
            records(40),
            records(900),
            [noise(20_000, 5), ramp(9000), noise(20_000, 5)].concat(),
        ];
        for data in corpus {
            for level in 0..=10 {
                let written = compress_to_vec(&data, level);
                let case = format!("{} bytes at level {level}", data.len());
                assert_eq!(inflate_all(&written).as_ref(), Ok(&data), "{case}");
            }
        }
    }

    #[test]
    fn a_stream_cut_short_is_truncated() {
        for (hex, _) in streams() {
            let stream = stream(hex);
            for len in 0..stream.len() {
                assert_eq!(
                    inflate_all(&stream[..len]),
                    Err(Error::TruncatedDeflate),
                    "{len} bytes of {hex}"
                );
            }
        }
    }

    #[test]
    fn rejects_bytes_after_the_last_block() {
        for (hex, _) in streams() {
            let mut stream = stream(hex);
            stream.push(0);
            assert_eq!(
                inflate_all(&stream),
                Err(Error::TrailingDeflateData),
                "{hex}"
            );
        }
    }

    // zlib refuses each of them too
    #[test]
    fn rejects_malformed_streams() {
        let cases = [
            // block type 3
            ("07", Error::InvalidDeflateBlock),
            // a stored length that its complement does not match
            ("010500000068656c6c6f", Error::InvalidDeflateBlock),
            // a match before any output
            ("030200", Error::InvalidDeflateDistance),
            // length symbol 286, then distance symbol 30
            ("1b0300", Error::InvalidDeflateCode),
            ("4b043e00", Error::InvalidDeflateCode),
            // code lengths of more codes than there are, then of fewer
            ("05e00104000000401000", Error::InvalidDeflateCode),
            ("05e00108000000802000", Error::InvalidDeflateCode),
            // a repeat of the previous length with none before it, then one past the
            // last length
            ("05e00300000000001004", Error::InvalidDeflateCode),
            ("05e081000000000010fcff03", Error::InvalidDeflateCode),
            // no code for the end of the block
            ("05e081000000000010fc6f03", Error::InvalidDeflateCode),
            // 287 literal and length symbols
            ("f5e00104000000001000", Error::InvalidDeflateCode),
        ];
        for (hex, error) in cases {
            assert_eq!(inflate_all(&stream(hex)), Err(error), "{hex}");
        }
    }

    // 32 distance code lengths, the most a dynamic block may declare (RFC 1951 section
    // 3.2.7), all of them 0, in a block that holds only its end. zlib refuses any count
    // above 30, the last two distance symbols being of no use to a stream.
    #[test]
    fn accepts_a_dynamic_block_of_32_distance_code_lengths() {
        assert_eq!(
            inflate_all(&stream("05df81000000000090ff6b2b00")),
            Ok(vec![])
        );
    }

    #[test]
    fn rejects_a_distance_beyond_the_window() {
        let stream = stream(FAR_APART);
        assert_eq!(inflate_all(&stream), Ok(far_apart()));
        assert_eq!(inflate(&stream, usize::MAX, 1240), Ok(far_apart()));
        assert_eq!(
            inflate(&stream, usize::MAX, 1239),
            Err(Error::InvalidDeflateDistance)
        );
    }

    #[test]
    fn rejects_more_bytes_than_the_maximum() {
        for (hex, bytes) in streams() {
            let stream = stream(hex);
            assert_eq!(
                inflate(&stream, bytes.len(), MAX_DISTANCE),
                Ok(bytes.clone()),
                "{hex}"
            );
            if !bytes.is_empty() {
                assert_eq!(
                    inflate(&stream, bytes.len() - 1, MAX_DISTANCE),
                    Err(Error::InflatedTooLarge),
                    "{hex}"
                );
            }
        }
    }

    #[test]
    fn a_corrupt_stream_does_not_panic() {
        let mut streams: Vec<Vec<u8>> = streams().iter().map(|(hex, _)| stream(hex)).collect();
        streams.push(stream(FAR_APART));
        for stream in streams {
            for bit in 0..stream.len() * 8 {
                let mut corrupt = stream.clone();
                corrupt[bit / 8] ^= 1 << (bit % 8);
                let _ = inflate(&corrupt, 1 << 16, MAX_DISTANCE);
            }
        }
    }
}
