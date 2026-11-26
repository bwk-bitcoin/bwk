//! Payloads the tests of several modules share.

/// The bytes 0, 1, 2 and so on, back to 0 after 255.
pub(crate) fn ramp(len: usize) -> Vec<u8> {
    (0..len).map(|index| index as u8).collect()
}

/// `len` bytes no compressor shrinks, the same ones for the same `seed`. The Python that
/// wrote the fixture streams draws them alike:
///   x = (x * 1103515245 + 12345) & 0x7fffffff; byte = (x >> 16) & 0xff
pub(crate) fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = (state * 1_103_515_245 + 12_345) & 0x7fff_ffff;
            (state >> 16) as u8
        })
        .collect()
}

/// A payload shaped like a PSBT: `count` records that repeat a few fixed fields around
/// bytes of noise, as its keys and signatures are.
pub(crate) fn records(count: usize) -> Vec<u8> {
    let mut out = b"psbt\xff\x01\x00".to_vec();
    for index in 0..count {
        out.extend_from_slice(&[0x22, 0x06]);
        out.extend(noise(33, index as u64));
        out.extend_from_slice(&[
            0x18, 0x73, 0xc5, 0xda, 0x0a, 0x54, 0, 0, 0x80, 1, 0, 0, 0x80,
        ]);
        out.extend_from_slice(&(index as u32).to_le_bytes());
    }
    out
}
