use crate::inflate::{
    fixed_lengths, CODE_LENGTH_ORDER, DISTANCE_BASE, DISTANCE_EXTRA, END_OF_BLOCK, LENGTH_BASE,
    LENGTH_EXTRA, MAX_BITS,
};

/// The bytes a decoder of these streams keeps to copy from: zlib's `wbits=10`.
const WINDOW: usize = 1024;
/// The farthest back a match copies from. The window allows 1024, but zlib keeps 262
/// bytes of it for what it reads ahead and never writes more than this, so no decoder
/// in use is known to have met a longer distance.
pub(crate) const MAX_DISTANCE: usize = WINDOW - 262;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// The earlier positions a match is looked for at, at most.
const MAX_CHAIN: usize = 128;
/// The tokens after which a block ends, each block having the codes that suit it.
const BLOCK_TOKENS: usize = 16383;
const HASH_BITS: u32 = 12;
/// No position, in the chains of a [`Matcher`].
const NONE: usize = usize::MAX;
/// The symbols a block may use of the literal and length code, then of the distance
/// code.
const LITERAL_SYMBOLS: usize = END_OF_BLOCK + 1 + LENGTH_BASE.len();
const DISTANCE_SYMBOLS: usize = DISTANCE_BASE.len();
/// The longest code of the code length code, in bits.
const MAX_CODE_LENGTH_BITS: usize = 7;

// a slot of `Matcher::prev` is still that of its position while a match may reach it
const _: () = assert!(MAX_DISTANCE <= WINDOW);

/// `data` as a raw deflate stream (RFC 1951), with neither a zlib header nor a
/// checksum, that a decoder holding a window of 1024 bytes inflates: what zlib writes
/// at `wbits=-10`. The same bytes always give the same stream.
pub(crate) fn deflate(data: &[u8]) -> Vec<u8> {
    let mut writer = Writer::default();
    let mut matcher = Matcher::new(data);
    let mut tokens = Vec::with_capacity(BLOCK_TOKENS);
    loop {
        let start = matcher.at;
        tokens.clear();
        while tokens.len() < BLOCK_TOKENS && !matcher.is_done() {
            matcher.step(&mut tokens);
        }
        write_block(
            &mut writer,
            &data[start..matcher.at],
            &tokens,
            matcher.is_done(),
        );
        if matcher.is_done() {
            return writer.finish();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Literal(u8),
    /// `length` bytes, 3 to 258, that repeat those `distance` bytes back.
    Match {
        length: u16,
        distance: u16,
    },
}

/// Cuts `data` into tokens from its start, finding the bytes that repeat earlier ones
/// through chains of the positions whose first three bytes share a hash.
struct Matcher<'a> {
    data: &'a [u8],
    /// The next byte to cut a token from.
    at: usize,
    /// For each hash, the last position entered.
    head: Vec<usize>,
    /// For a position entered, at its remainder by [`WINDOW`], the one before it of the
    /// same hash.
    prev: [usize; WINDOW],
}

impl<'a> Matcher<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            at: 0,
            head: vec![NONE; 1 << HASH_BITS],
            prev: [NONE; WINDOW],
        }
    }

    fn is_done(&self) -> bool {
        self.at == self.data.len()
    }

    /// Appends the next token, behind the literals it comes with: when the match found
    /// one byte further is longer, that byte goes out as a literal and the longer match
    /// is the one taken.
    fn step(&mut self, tokens: &mut Vec<Token>) {
        let mut found = self.longest(self.at);
        self.enter(self.at);
        while let Some((length, _)) = found {
            if length == MAX_MATCH {
                break;
            }
            match self.longest(self.at + 1) {
                Some(next) if next.0 > length => {
                    tokens.push(Token::Literal(self.data[self.at]));
                    self.at += 1;
                    self.enter(self.at);
                    found = Some(next);
                }
                _ => break,
            }
        }
        let Some((length, distance)) = found else {
            tokens.push(Token::Literal(self.data[self.at]));
            self.at += 1;
            return;
        };
        tokens.push(Token::Match {
            length: length as u16,
            distance: distance as u16,
        });
        for at in self.at + 1..self.at + length {
            self.enter(at);
        }
        self.at += length;
    }

    /// The length and the distance of the longest match for the bytes at `at` among the
    /// positions entered, the nearest of them when several are as long.
    fn longest(&self, at: usize) -> Option<(usize, usize)> {
        let ahead = self.data.get(at..)?;
        let limit = ahead.len().min(MAX_MATCH);
        let mut best = (MIN_MATCH - 1, 0);
        let mut candidate = self.head[Self::hash(ahead)?];
        for _ in 0..MAX_CHAIN {
            if candidate == NONE || at - candidate > MAX_DISTANCE {
                break;
            }
            let earlier = &self.data[candidate..];
            // a longer match has the byte past the best one so far
            if earlier[best.0] == ahead[best.0] {
                let length = earlier
                    .iter()
                    .zip(&ahead[..limit])
                    .take_while(|(earlier, ahead)| earlier == ahead)
                    .count();
                if length > best.0 {
                    best = (length, at - candidate);
                    if length == limit {
                        break;
                    }
                }
            }
            candidate = self.prev[candidate % WINDOW];
        }
        (best.0 >= MIN_MATCH).then_some(best)
    }

    /// Makes `at` a position later matches are looked for at.
    fn enter(&mut self, at: usize) {
        if let Some(hash) = self.data.get(at..).and_then(Self::hash) {
            self.prev[at % WINDOW] = self.head[hash];
            self.head[hash] = at;
        }
    }

    /// The hash of the first three bytes of `bytes`, none when it is shorter.
    fn hash(bytes: &[u8]) -> Option<usize> {
        let bytes = bytes.get(..MIN_MATCH)?;
        let value = u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16;
        Some((value.wrapping_mul(0x9e37_79b1) >> (32 - HASH_BITS)) as usize)
    }
}

/// The bits of a stream, each byte filled from its lowest bit.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    /// The bits not yet in `bytes`, the first one lowest.
    buffer: u64,
    /// How many bits `buffer` holds, at most 7 between two writes.
    count: u32,
}

impl Writer {
    /// Appends the `count` low bits of `value`, at most 16, from the lowest.
    fn bits(&mut self, value: usize, count: u32) {
        self.buffer |= (value as u64) << self.count;
        self.count += count;
        while self.count >= 8 {
            self.bytes.push(self.buffer as u8);
            self.buffer >>= 8;
            self.count -= 8;
        }
    }

    fn code(&mut self, code: Code) {
        self.bits(usize::from(code.bits), u32::from(code.length));
    }

    /// Pads to the next whole byte with zero bits, then appends `bytes`.
    fn bytes(&mut self, bytes: &[u8]) {
        if self.count > 0 {
            self.bytes.push(self.buffer as u8);
            self.buffer = 0;
            self.count = 0;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.bytes.push(self.buffer as u8);
        }
        self.bytes
    }
}

/// The code of a symbol: its bits in the order they are written, the first one lowest,
/// where RFC 1951 numbers a code from its last bit.
#[derive(Clone, Copy, Default)]
struct Code {
    bits: u16,
    length: u8,
}

/// The canonical codes of `lengths` (RFC 1951 section 3.2.2): consecutive numbers
/// within a length, in symbol order, the shorter codes first.
fn codes(lengths: &[u8]) -> Vec<Code> {
    let mut counts = [0u16; MAX_BITS + 1];
    for length in lengths {
        counts[usize::from(*length)] += 1;
    }
    counts[0] = 0;
    // the first code of each length
    let mut next = [0u16; MAX_BITS + 1];
    for bits in 1..=MAX_BITS {
        next[bits] = (next[bits - 1] + counts[bits - 1]) << 1;
    }
    lengths
        .iter()
        .map(|length| {
            if *length == 0 {
                return Code::default();
            }
            let code = next[usize::from(*length)];
            next[usize::from(*length)] += 1;
            Code {
                bits: code.reverse_bits() >> (16 - u32::from(*length)),
                length: *length,
            }
        })
        .collect()
}

/// The lengths of an optimal prefix code for symbols used `counts` times each, none
/// longer than `limit` bits, and 0 for a symbol never used. By package-merge: of the
/// packages that pair up, `limit - 1` times over, the lightest items left of the round
/// before, a symbol is as long as it is in the lightest `2 * symbols - 2` of the last
/// round.
///
/// A code of fewer than two symbols would leave bit strings to no symbol: as zlib
/// does, the first symbols never used then get a code too.
fn code_lengths(counts: &[u32], limit: usize) -> Vec<u8> {
    let mut leaves: Vec<(u64, Vec<usize>)> = counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count != 0)
        .map(|(symbol, count)| (u64::from(*count), vec![symbol]))
        .collect();
    for (symbol, count) in counts.iter().enumerate() {
        if leaves.len() < 2 && *count == 0 {
            leaves.push((1, vec![symbol]));
        }
    }
    leaves.sort();
    let mut items = leaves.clone();
    for _ in 1..limit {
        let packages = items
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (pair[0].0 + pair[1].0, [&pair[0].1[..], &pair[1].1].concat()));
        let mut merged = leaves.clone();
        merged.extend(packages);
        merged.sort_by_key(|(weight, _)| *weight);
        items = merged;
    }
    let mut lengths = vec![0; counts.len()];
    for (_, symbols) in items.iter().take(2 * leaves.len() - 2) {
        for symbol in symbols {
            lengths[*symbol] += 1;
        }
    }
    lengths
}

/// Appends `lengths` as symbols of the code length code, each with the value of its
/// extra bits: a length as it is, 16 for the previous length 3 to 6 times more, 17 for
/// 3 to 10 zeros and 18 for 11 to 138.
fn run_lengths(lengths: &[u8], symbols: &mut Vec<(usize, usize)>) {
    let mut at = 0;
    while at < lengths.len() {
        let length = lengths[at];
        let run = lengths[at..]
            .iter()
            .take_while(|other| **other == length)
            .count();
        at += match (length, run) {
            (0, 11..) => {
                symbols.push((18, run.min(138) - 11));
                run.min(138)
            }
            (0, 3..) => {
                symbols.push((17, run - 3));
                run
            }
            (_, 4..) => {
                symbols.push((usize::from(length), 0));
                let mut rest = run - 1;
                while rest >= 3 {
                    symbols.push((16, rest.min(6) - 3));
                    rest -= rest.min(6);
                }
                run - rest
            }
            _ => {
                symbols.push((usize::from(length), 0));
                1
            }
        };
    }
}

/// The extra bits that follow a symbol of the code length code.
fn repeat_bits(symbol: usize) -> u32 {
    match symbol {
        16 => 2,
        17 => 3,
        18 => 7,
        _ => 0,
    }
}

/// The codes of a dynamic block, and the account of them the block starts with (RFC
/// 1951 section 3.2.7).
struct Dynamic {
    /// The code lengths of the literal and length code, up to its last symbol used.
    literals: Vec<u8>,
    /// Those of the distance code.
    distances: Vec<u8>,
    /// Both, as symbols of the code length code with the value of their extra bits.
    lengths: Vec<(usize, usize)>,
    /// The lengths of the code length code.
    code: Vec<u8>,
    /// How many of them the block sends, in [`CODE_LENGTH_ORDER`].
    sent: usize,
}

impl Dynamic {
    fn new(literal_counts: &[u32], distance_counts: &[u32]) -> Self {
        let mut literals = code_lengths(literal_counts, MAX_BITS);
        literals.truncate(used(&literals).max(END_OF_BLOCK + 1));
        let mut distances = code_lengths(distance_counts, MAX_BITS);
        distances.truncate(used(&distances).max(1));

        let mut lengths = Vec::new();
        run_lengths(&literals, &mut lengths);
        run_lengths(&distances, &mut lengths);
        let mut counts = [0; CODE_LENGTH_ORDER.len()];
        for (symbol, _) in &lengths {
            counts[*symbol] += 1;
        }
        let code = code_lengths(&counts, MAX_CODE_LENGTH_BITS);
        let ordered: Vec<u8> = CODE_LENGTH_ORDER
            .iter()
            .map(|symbol| code[*symbol])
            .collect();
        Self {
            literals,
            distances,
            lengths,
            sent: used(&ordered).max(4),
            code,
        }
    }

    /// The bits [`Dynamic::write`] takes.
    fn bits(&self) -> u64 {
        let lengths = self.lengths.iter();
        let lengths = lengths
            .map(|(symbol, _)| u64::from(self.code[*symbol]) + u64::from(repeat_bits(*symbol)));
        5 + 5 + 4 + 3 * self.sent as u64 + lengths.sum::<u64>()
    }

    fn write(&self, writer: &mut Writer) {
        writer.bits(self.literals.len() - END_OF_BLOCK - 1, 5);
        writer.bits(self.distances.len() - 1, 5);
        writer.bits(self.sent - 4, 4);
        for symbol in &CODE_LENGTH_ORDER[..self.sent] {
            writer.bits(usize::from(self.code[*symbol]), 3);
        }
        let codes = codes(&self.code);
        for (symbol, extra) in &self.lengths {
            writer.code(codes[*symbol]);
            writer.bits(*extra, repeat_bits(*symbol));
        }
    }
}

/// How many of `lengths` there are up to the last one that is not 0.
fn used(lengths: &[u8]) -> usize {
    lengths
        .iter()
        .rposition(|length| *length != 0)
        .map_or(0, |last| last + 1)
}

/// The bits the symbols counted in `counts` take in the code of `lengths`.
fn cost(counts: &[u32], lengths: &[u8]) -> u64 {
    let symbols = counts.iter().zip(lengths);
    symbols
        .map(|(count, length)| u64::from(*count) * u64::from(*length))
        .sum()
}

/// The symbol of a length or of a distance: the last one whose base is not above
/// `value`, which then goes on in the symbol's extra bits.
fn symbol(bases: &[u16], value: u16) -> usize {
    bases.partition_point(|base| *base <= value) - 1
}

/// Writes `tokens` as one block, the last of the stream or not: stored, fixed, or in
/// codes of its own, whichever takes the fewest bits.
fn write_block(writer: &mut Writer, raw: &[u8], tokens: &[Token], last: bool) {
    let mut literal_counts = [0; LITERAL_SYMBOLS];
    let mut distance_counts = [0; DISTANCE_SYMBOLS];
    let mut extra_bits = 0u64;
    literal_counts[END_OF_BLOCK] = 1;
    for token in tokens {
        match token {
            Token::Literal(byte) => literal_counts[usize::from(*byte)] += 1,
            Token::Match { length, distance } => {
                let len = symbol(&LENGTH_BASE, *length);
                let dist = symbol(&DISTANCE_BASE, *distance);
                literal_counts[END_OF_BLOCK + 1 + len] += 1;
                distance_counts[dist] += 1;
                extra_bits += u64::from(LENGTH_EXTRA[len]) + u64::from(DISTANCE_EXTRA[dist]);
            }
        }
    }
    let (fixed_literals, fixed_distances) = fixed_lengths();
    let fixed_bits = cost(&literal_counts, &fixed_literals)
        + cost(&distance_counts, &fixed_distances)
        + extra_bits;
    let dynamic = Dynamic::new(&literal_counts, &distance_counts);
    let dynamic_bits = dynamic.bits()
        + cost(&literal_counts, &dynamic.literals)
        + cost(&distance_counts, &dynamic.distances)
        + extra_bits;
    let stored_bits = u16::try_from(raw.len()).ok().map(|len| {
        let padding = u64::from((8 - (writer.count + 3) % 8) % 8);
        padding + 32 + u64::from(len) * 8
    });

    writer.bits(usize::from(last), 1);
    if stored_bits.is_some_and(|bits| bits < fixed_bits && bits < dynamic_bits) {
        let len = raw.len() as u16;
        writer.bits(0, 2);
        writer.bytes(&len.to_le_bytes());
        writer.bytes(&(!len).to_le_bytes());
        writer.bytes(raw);
        return;
    }
    let (literals, distances) = if dynamic_bits < fixed_bits {
        writer.bits(2, 2);
        dynamic.write(writer);
        (codes(&dynamic.literals), codes(&dynamic.distances))
    } else {
        writer.bits(1, 2);
        (codes(&fixed_literals), codes(&fixed_distances))
    };
    for token in tokens {
        match token {
            Token::Literal(byte) => writer.code(literals[usize::from(*byte)]),
            Token::Match { length, distance } => {
                let index = symbol(&LENGTH_BASE, *length);
                writer.code(literals[END_OF_BLOCK + 1 + index]);
                let extra = usize::from(*length - LENGTH_BASE[index]);
                writer.bits(extra, u32::from(LENGTH_EXTRA[index]));
                let index = symbol(&DISTANCE_BASE, *distance);
                writer.code(distances[index]);
                let extra = usize::from(*distance - DISTANCE_BASE[index]);
                writer.bits(extra, u32::from(DISTANCE_EXTRA[index]));
            }
        }
    }
    writer.code(literals[END_OF_BLOCK]);
}

#[cfg(test)]
mod tests {
    use miniz_oxide::inflate::decompress_to_vec;

    use crate::{
        deflate::{
            code_lengths, deflate, run_lengths, Matcher, Token, BLOCK_TOKENS, MAX_DISTANCE,
            MAX_MATCH, MIN_MATCH,
        },
        inflate::inflate,
        test_data::{noise, ramp, records},
    };

    const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog, ";

    fn corpus() -> Vec<Vec<u8>> {
        vec![
            vec![],
            b"a".to_vec(),
            b"ab".to_vec(),
            TEXT.repeat(4),
            vec![7; 5000],
            ramp(700),
            noise(3000, 1),
            records(40),
            records(900),
            // a key that comes back just within the reach of a match, then just beyond
            noise(MAX_DISTANCE, 9).repeat(4),
            noise(MAX_DISTANCE + 1, 9).repeat(4),
            // more tokens than a block takes
            [noise(20_000, 5), ramp(9000), noise(20_000, 5)].concat(),
        ]
    }

    fn tokens(data: &[u8]) -> Vec<Token> {
        let mut matcher = Matcher::new(data);
        let mut tokens = Vec::new();
        while !matcher.is_done() {
            matcher.step(&mut tokens);
        }
        tokens
    }

    fn runs(lengths: &[u8]) -> Vec<(usize, usize)> {
        let mut symbols = Vec::new();
        run_lengths(lengths, &mut symbols);
        symbols
    }

    /// The bits of the code space the code of `lengths` takes, out of the `1 << limit`
    /// a complete code takes.
    fn kraft(lengths: &[u8], limit: usize) -> usize {
        let coded = lengths.iter().filter(|length| **length != 0);
        coded
            .map(|length| 1 << (limit - usize::from(*length)))
            .sum()
    }

    // inflated with the reach of the compressor as its window: a longer distance fails
    #[test]
    fn inflates_back_within_its_window() {
        for data in corpus() {
            let stream = deflate(&data);
            assert_eq!(
                inflate(&stream, data.len(), MAX_DISTANCE).as_ref(),
                Ok(&data),
                "{} bytes",
                data.len()
            );
        }
    }

    #[test]
    fn every_short_payload_inflates_back() {
        for len in 0..=600 {
            let payloads = [
                ramp(len),
                noise(len, len as u64),
                records(len / 50 + 1)[..len].to_vec(),
                ramp(len / 3 + 1).repeat(3),
            ];
            for data in payloads {
                let stream = deflate(&data);
                assert_eq!(
                    inflate(&stream, data.len(), MAX_DISTANCE),
                    Ok(data),
                    "{len} bytes"
                );
            }
        }
    }

    #[test]
    fn miniz_inflates_it() {
        for data in corpus() {
            assert_eq!(decompress_to_vec(&deflate(&data)).unwrap(), data);
        }
    }

    #[test]
    fn writes_the_shortest_streams_as_zlib_does() {
        assert_eq!(deflate(b""), [0x03, 0x00]);
        assert_eq!(deflate(b"a"), [0x4b, 0x04, 0x00]);
    }

    #[test]
    fn stores_an_incompressible_block_as_is() {
        let data = noise(300, 1);
        let stream = deflate(&data);
        assert_eq!(stream.len(), data.len() + 5);
        assert_eq!(stream[0], 0x01);
        assert_eq!(u16::from_le_bytes([stream[1], stream[2]]), 300);
        assert_eq!(u16::from_le_bytes([stream[3], stream[4]]), !300u16);
        assert_eq!(&stream[5..], &data[..]);
        assert_eq!(inflate(&stream, data.len(), MAX_DISTANCE), Ok(data));
    }

    // the lengths of what zlib writes at its level 9, with a window of 1024 bytes
    #[test]
    fn compresses_about_as_well_as_zlib() {
        let cases = [
            (TEXT.repeat(4), 49),
            (TEXT.repeat(200), 169),
            (vec![7; 5000], 22),
            (ramp(600), 278),
            (records(5), 221),
            (records(40), 1559),
            (records(900), 33479),
        ];
        for (data, zlib_len) in cases {
            let len = deflate(&data).len();
            assert!(
                len <= zlib_len * 101 / 100 + 2,
                "{} bytes to {len}, zlib to {zlib_len}",
                data.len()
            );
        }
    }

    #[test]
    fn matches_are_of_a_legal_length_and_within_reach() {
        for data in corpus() {
            let mut replayed = Vec::new();
            for token in tokens(&data) {
                match token {
                    Token::Literal(byte) => replayed.push(byte),
                    Token::Match { length, distance } => {
                        let (length, distance) = (usize::from(length), usize::from(distance));
                        assert!((MIN_MATCH..=MAX_MATCH).contains(&length));
                        assert!((1..=MAX_DISTANCE.min(replayed.len())).contains(&distance));
                        for _ in 0..length {
                            replayed.push(replayed[replayed.len() - distance]);
                        }
                    }
                }
            }
            assert_eq!(replayed, data);
        }
    }

    #[test]
    fn a_key_within_reach_is_matched_and_one_beyond_is_not() {
        let within = tokens(&noise(MAX_DISTANCE, 9).repeat(2));
        assert!(within.contains(&Token::Match {
            length: MAX_MATCH as u16,
            distance: MAX_DISTANCE as u16,
        }));
        let beyond = tokens(&noise(MAX_DISTANCE + 1, 9).repeat(2));
        assert!(beyond
            .iter()
            .all(|token| matches!(token, Token::Literal(_))));
    }

    #[test]
    fn a_long_payload_takes_several_blocks() {
        let data = [noise(20_000, 5), ramp(9000), noise(20_000, 5)].concat();
        assert!(tokens(&data).len() > 2 * BLOCK_TOKENS);
    }

    #[test]
    fn code_lengths_are_those_of_a_huffman_code_when_the_limit_allows() {
        assert_eq!(code_lengths(&[1, 1, 2, 4, 8], 15), [4, 4, 3, 2, 1]);
        assert_eq!(code_lengths(&[0, 5, 0, 5, 5, 5], 15), [0, 2, 0, 2, 2, 2]);
        assert_eq!(code_lengths(&[9, 0, 1], 15), [1, 0, 1]);
    }

    #[test]
    fn code_lengths_are_complete_within_the_limit() {
        // counts that grow like Fibonacci numbers give the longest Huffman codes
        let fibonacci = |symbols: usize| {
            let mut counts = vec![1u32, 1];
            while counts.len() < symbols {
                counts.push(counts[counts.len() - 1] + counts[counts.len() - 2]);
            }
            counts
        };
        let uneven = |symbols: usize| -> Vec<u32> {
            noise(symbols, 3)
                .iter()
                .map(|b| u32::from(*b) * u32::from(*b))
                .collect()
        };
        let cases = [
            (fibonacci(19), 7),
            (fibonacci(30), 15),
            (fibonacci(40), 15),
            (uneven(19), 7),
            (uneven(30), 15),
            (uneven(286), 15),
            (vec![1; 286], 15),
            (vec![1; 19], 7),
            (vec![1; 128], 7),
        ];
        for (counts, limit) in cases {
            let lengths = code_lengths(&counts, limit);
            let case = format!("{} symbols at {limit}", counts.len());
            assert!(
                lengths.iter().all(|length| usize::from(*length) <= limit),
                "{case}"
            );
            assert_eq!(kraft(&lengths, limit), 1 << limit, "{case}");
            for (count, length) in counts.iter().zip(&lengths) {
                assert_eq!(*count == 0, *length == 0, "{case}");
            }
        }
    }

    #[test]
    fn a_code_has_two_symbols_at_least() {
        assert_eq!(code_lengths(&[0, 0, 0, 0], 15), [1, 1, 0, 0]);
        assert_eq!(code_lengths(&[0, 0, 0, 6], 15), [1, 0, 0, 1]);
        assert_eq!(code_lengths(&[6, 0, 0, 0], 15), [1, 1, 0, 0]);
    }

    #[test]
    fn run_lengths_repeat_what_they_can() {
        assert_eq!(runs(&[0; 2]), [(0, 0), (0, 0)]);
        assert_eq!(runs(&[0; 3]), [(17, 0)]);
        assert_eq!(runs(&[0; 10]), [(17, 7)]);
        assert_eq!(runs(&[0; 11]), [(18, 0)]);
        assert_eq!(runs(&[0; 138]), [(18, 127)]);
        assert_eq!(runs(&[0; 139]), [(18, 127), (0, 0)]);
        assert_eq!(runs(&[5; 3]), [(5, 0), (5, 0), (5, 0)]);
        assert_eq!(runs(&[5; 7]), [(5, 0), (16, 3)]);
        assert_eq!(runs(&[5; 12]), [(5, 0), (16, 3), (16, 2)]);
        assert_eq!(
            runs(&[8, 8, 8, 8, 8, 8, 0, 0, 0, 9, 7, 7]),
            [(8, 0), (16, 2), (17, 0), (9, 0), (7, 0), (7, 0)]
        );
    }
}
