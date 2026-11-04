//! Pure scalar and point helpers, and the tagged hashes and HMAC built on the
//! backend's hash engines. Nothing here does curve arithmetic itself: point
//! operations go through `BitcoinBackend`.

use crate::backend::{BitcoinBackend, Sha256Engine, Sha512Engine};

/// The secp256k1 curve order, big-endian.
pub const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// True when `a` is below the curve order. Zero is valid.
pub fn scalar_is_valid(a: &[u8; 32]) -> bool {
    a < &N
}

pub fn scalar_is_zero(a: &[u8; 32]) -> bool {
    *a == [0u8; 32]
}

/// Reduces `a` modulo the curve order with a single conditional subtract,
/// which suffices for any 256-bit value.
pub fn scalar_reduce(a: &[u8; 32]) -> [u8; 32] {
    if scalar_is_valid(a) {
        *a
    } else {
        sub(a, &N)
    }
}

/// Negates `a` modulo the curve order. For canonical input this is "n minus
/// a, zero stays zero".
pub fn scalar_neg(a: &[u8; 32]) -> [u8; 32] {
    let a = scalar_reduce(a);
    if scalar_is_zero(&a) {
        a
    } else {
        sub(&N, &a)
    }
}

/// Big-endian subtraction with borrow. Assumes `a >= b`.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = false;
    for i in (0..32).rev() {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
        out[i] = d2;
        borrow = b1 || b2;
    }
    out
}

/// True when the compressed point has an even y coordinate.
pub fn has_even_y(p: &[u8; 33]) -> bool {
    p[0] == 0x02
}

/// The x-only coordinate of a compressed point.
pub fn xbytes(p: &[u8; 33]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&p[1..33]);
    out
}

/// Negates a compressed point by flipping its parity prefix.
pub fn point_neg(p: &[u8; 33]) -> [u8; 33] {
    let mut out = *p;
    out[0] = if has_even_y(p) { 0x03 } else { 0x02 };
    out
}

/// Adds two optional points, where None is infinity.
pub fn add_opt<B: BitcoinBackend>(
    c: &B,
    a: Option<[u8; 33]>,
    b: Option<[u8; 33]>,
) -> Option<[u8; 33]> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => c.point_add(&a, &b),
    }
}

/// Builds the even-y point for x-only coordinate `x`, if it lies on the curve.
pub fn lift_x<B: BitcoinBackend>(c: &B, x: &[u8; 32]) -> Option<[u8; 33]> {
    let mut p = [0u8; 33];
    p[0] = 0x02;
    p[1..33].copy_from_slice(x);
    if c.point_is_valid(&p) {
        Some(p)
    } else {
        None
    }
}

/// Returns a fresh SHA-256 engine pre-fed with the tag hash twice, per BIP340
/// tagged hashing.
pub fn tagged_hash256<B: BitcoinBackend>(c: &B, tag: &[u8]) -> B::Sha256 {
    let mut tag_engine = c.sha256();
    tag_engine.update(tag);
    let t = tag_engine.finalize();
    let mut engine = c.sha256();
    engine.update(&t);
    engine.update(&t);
    engine
}

/// Returns a fresh SHA-512 engine pre-fed with the tag hash twice, matching
/// BIP89's hash512_tag: SHA512(SHA512(tag) concatenated with SHA512(tag)
/// concatenated with the payload).
pub fn tagged_hash512<B: BitcoinBackend>(c: &B, tag: &[u8]) -> B::Sha512 {
    let mut tag_engine = c.sha512();
    tag_engine.update(tag);
    let t = tag_engine.finalize();
    let mut engine = c.sha512();
    engine.update(&t);
    engine.update(&t);
    engine
}

/// HMAC-SHA512 over a 32-byte key. The 128-byte block is the SHA-512 block
/// size, so a 32-byte key never needs pre-hashing.
pub struct HmacSha512<E> {
    inner: E,
    outer: E,
}

impl<E: Sha512Engine> HmacSha512<E> {
    pub fn new<B: BitcoinBackend<Sha512 = E>>(c: &B, key: &[u8; 32]) -> Self {
        let mut ipad = [0x36u8; 128];
        let mut opad = [0x5cu8; 128];
        for i in 0..32 {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }
        let mut inner = c.sha512();
        inner.update(&ipad);
        let mut outer = c.sha512();
        outer.update(&opad);
        Self { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
        let ih = self.inner.finalize();
        let mut outer = self.outer;
        outer.update(&ih);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use crate::scalar::{
        has_even_y, point_neg, scalar_is_valid, scalar_is_zero, scalar_neg, scalar_reduce, xbytes,
        N,
    };

    const ZERO: [u8; 32] = [0u8; 32];
    const ONE: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    const N_MINUS_1: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    const MAX: [u8; 32] = [0xffu8; 32];
    const MAX_REDUCED: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9,
        0xbe, 0xbe,
    ];
    const MAX_NEG: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfd, 0x75, 0x5d, 0xb9, 0xcd, 0x5e, 0x91, 0x40, 0x77, 0x7f, 0xa4, 0xbd, 0x19, 0xa0, 0x6c,
        0x82, 0x83,
    ];
    const G: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const NEG_G: [u8; 33] = [
        0x03, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const G_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[test]
    fn scalar_is_valid_bounds() {
        assert!(scalar_is_valid(&ZERO));
        assert!(scalar_is_valid(&ONE));
        assert!(scalar_is_valid(&N_MINUS_1));
        assert!(!scalar_is_valid(&N));
        assert!(!scalar_is_valid(&MAX));
    }

    #[test]
    fn scalar_is_zero_literals() {
        assert!(scalar_is_zero(&ZERO));
        assert!(!scalar_is_zero(&ONE));
        assert!(!scalar_is_zero(&N));
    }

    #[test]
    fn scalar_reduce_bounds() {
        assert_eq!(scalar_reduce(&ZERO), ZERO);
        assert_eq!(scalar_reduce(&ONE), ONE);
        assert_eq!(scalar_reduce(&N_MINUS_1), N_MINUS_1);
        assert_eq!(scalar_reduce(&N), ZERO);
        assert_eq!(scalar_reduce(&MAX), MAX_REDUCED);
    }

    #[test]
    fn scalar_neg_bounds() {
        assert_eq!(scalar_neg(&ZERO), ZERO);
        assert_eq!(scalar_neg(&ONE), N_MINUS_1);
        assert_eq!(scalar_neg(&N_MINUS_1), ONE);
        assert_eq!(scalar_neg(&N), ZERO);
        assert_eq!(scalar_neg(&MAX), MAX_NEG);
    }

    #[test]
    fn point_helpers() {
        assert!(has_even_y(&G));
        assert!(!has_even_y(&NEG_G));
        assert_eq!(point_neg(&G), NEG_G);
        assert_eq!(point_neg(&NEG_G), G);
        assert_eq!(xbytes(&G), G_X);
        assert_eq!(xbytes(&NEG_G), G_X);
    }
}
