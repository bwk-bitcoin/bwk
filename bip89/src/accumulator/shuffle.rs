//! Deterministic shuffle of the derivation index range of a tree.
//!
//! Tree position must not correlate with derivation index: if it did, a
//! delegator holding a membership proof could infer how many bundles the
//! wallet had derived before that one, and in what order. This module
//! produces a permutation of the index offsets of a tree that is a pure
//! function of the descriptor, so any wallet holding the descriptor rebuilds
//! the same tree, while a delegator, which holds only the template and
//! neither the descriptor nor the shuffle key, cannot compute it.
//!
//! Fisher-Yates over an HMAC counter stream. The alternatives were
//! considered and rejected:
//!
//! - Affine maps, LCGs and LFSRs: constant state, but linear. Bundles are
//!   used in roughly ascending derivation order, so a delegator can guess
//!   that two observed positions come from nearly consecutive indices,
//!   solve for the coefficients, and then invert every position it ever
//!   sees.
//! - Open-addressed insertion (linear or double hashing): the resulting
//!   permutation depends on insertion order, so displacement correlates
//!   with derivation index, and the correlation strengthens as the table
//!   fills.
//! - Keyed pseudorandom permutations (swap-or-not, Feistel): constant state
//!   and no array. Correct and strictly better for large ranges, but for a
//!   range of at most 256 entries the array costs 256 bytes while the
//!   permutation costs a primitive that must be pinned exactly in the spec.
//!
//! Fisher-Yates is uniform over all permutations, which is a one-line claim
//! a reviewer can check, and it needs no auxiliary occupancy bitmap.

use crate::{
    backend::{BitcoinBackend, Sha256Engine},
    scalar::{tagged_hash256, HmacSha512},
};

pub const SHUFFLE_TAG: &[u8] = b"BIPXXX_SHUFFLE";

/// Largest supported range. A byte holds 256 distinct values, so 256
/// entries is the exact ceiling. Going beyond this is not a parameter
/// change: the stream must be read in wider units and the rejection bound
/// changes with it.
pub const MAX_RANGE: usize = 256;

/// Derive the shuffle key from the wallet policy id, the keychain and the
/// tree start.
///
/// Domain separated so this key has a single purpose. Binding the policy
/// id, the keychain and the tree start gives each tree its own permutation:
/// two trees never share one, even across keychains at equal starts or
/// across policies over the same keys, so membership proofs cannot be
/// linked across trees by tree position.
pub fn shuffle_key<B: BitcoinBackend>(
    c: &B,
    policy_id: &[u8; 32],
    keychain: u32,
    tree_start: u32,
) -> [u8; 32] {
    let mut engine = tagged_hash256(c, SHUFFLE_TAG);
    engine.update(policy_id);
    engine.update(&keychain.to_be_bytes());
    engine.update(&tree_start.to_be_bytes());
    engine.finalize()
}

/// Deterministic byte stream: HMAC-SHA512 blocks keyed by the shuffle key
/// over the shuffle tag followed by a big-endian 4-byte counter.
///
/// Pseudorandom, not random. Nothing here touches an entropy source. Every
/// byte is a pure function of the key.
struct ShuffleStream<'a, B: BitcoinBackend> {
    c: &'a B,
    key: [u8; 32],
    block: [u8; 64],
    counter: u32,
    offset: usize,
}

impl<'a, B: BitcoinBackend> ShuffleStream<'a, B> {
    fn new(c: &'a B, key: [u8; 32]) -> Self {
        let mut s = Self {
            c,
            key,
            block: [0u8; 64],
            counter: 0,
            offset: 64,
        };
        s.refill();
        s
    }

    fn refill(&mut self) {
        let mut engine = HmacSha512::new(self.c, &self.key);
        engine.update(SHUFFLE_TAG);
        engine.update(&self.counter.to_be_bytes());
        self.block = engine.finalize();
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }

    fn next_byte(&mut self) -> u8 {
        if self.offset == self.block.len() {
            self.refill();
        }
        let b = self.block[self.offset];
        self.offset += 1;
        b
    }
}

/// Fisher-Yates, descending, with rejection sampling.
///
/// Returns the order indexed by tree position, holding the derivation
/// index offset placed at that position.
///
/// Four details below are load-bearing for cross-implementation
/// reproducibility. Each is a point where two correct-looking
/// implementations diverge, and the failure is silent: a different root,
/// no error, discovered only when a proof fails to verify.
///
/// 1. The loop runs descending, from the last position down to position
///    one. Ascending is an equally valid shuffle and yields a different
///    permutation from the same stream.
/// 2. A rejected draw consumes a stream byte. It is not retried against
///    the same position with the same byte. Implementations that disagree
///    here fall out of step at the first rejection.
/// 3. The bound is inclusive: a byte equal to the current position is
///    accepted, and swapping a position with itself is a valid no-op.
///    Excluding it biases the result.
/// 4. Draws use rejection, never the remainder of a division. Taking the
///    remainder biases toward low indices, which is a privacy defect rather
///    than a cosmetic one: it makes some index and position pairings
///    likelier than others.
pub fn shuffle_order<B: BitcoinBackend>(c: &B, key: &[u8; 32]) -> [u8; 256] {
    let mut order = [0u8; MAX_RANGE];
    for (i, slot) in order.iter_mut().enumerate() {
        *slot = i as u8;
    }

    let mut stream = ShuffleStream::new(c, *key);
    for i in (1..MAX_RANGE).rev() {
        // uniform draw at or below i
        let j = loop {
            let b = stream.next_byte() as usize;
            if b <= i {
                break b;
            }
        };
        order.swap(i, j);
    }

    order
}

/// Invert the permutation: the result is indexed by derivation index
/// offset and holds the tree position of that offset.
///
/// The coordinator needs this direction to serve a membership proof for
/// the bundle at a given derivation index, and tree generation uses it to
/// place each bundle derived in index order at its tree position.
pub fn invert(order: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; MAX_RANGE];
    for (pos, &offset) in order.iter().enumerate() {
        inv[offset as usize] = pos as u8;
    }
    inv
}
