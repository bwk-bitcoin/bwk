//! BIP-327 KeySort, KeyAgg and tweaks, and the BIP-328 synthetic xpub.

use alloc::vec::Vec;

use crate::{backend::MusigBackend, Error};

/// Fixed chain code of the BIP-328 synthetic xpub: SHA256 of "MuSig2MuSig2MuSig2".
pub const BIP328_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// A tweak applied to the aggregate key, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tweak {
    pub scalar: [u8; 32],
    pub x_only: bool,
}

/// The BIP-328 synthetic xpub of an aggregate: depth 0, no parent, fixed chain code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyntheticXpub {
    pub key: [u8; 33],
    pub chain_code: [u8; 32],
}

/// Participants, their aggregate and the tweaks applied on top, with the backend cache.
///
/// BIP-390 `musig()` requires KeySort before KeyAgg: build it with `sorted`. `new`
/// keeps the given order, as the BIP-327 and BIP-328 vectors and the BIP-373 0x1a
/// field ("in the order required for aggregation") expect.
pub struct KeyAgg<B: MusigBackend> {
    participants: Vec<[u8; 33]>,
    aggregate: [u8; 33],
    tweaks: Vec<Tweak>,
    output_key: [u8; 33],
    cache: B::KeyAggCache,
}

impl<B: MusigBackend> Clone for KeyAgg<B> {
    fn clone(&self) -> Self {
        Self {
            participants: self.participants.clone(),
            aggregate: self.aggregate,
            tweaks: self.tweaks.clone(),
            output_key: self.output_key,
            cache: self.cache.clone(),
        }
    }
}

impl<B: MusigBackend> KeyAgg<B> {
    /// KeyAgg over `participants` in the given order (BIP-327 vectors).
    pub fn new(backend: &B, participants: &[[u8; 33]]) -> Result<Self, Error> {
        let cache = backend.key_agg(participants)?;
        let aggregate = backend.agg_pk(&cache);
        Ok(Self {
            participants: participants.to_vec(),
            aggregate,
            tweaks: Vec::new(),
            output_key: aggregate,
            cache,
        })
    }

    /// KeySort then KeyAgg.
    pub fn sorted(backend: &B, participants: &[[u8; 33]]) -> Result<Self, Error> {
        Self::new(backend, &key_sort(backend, participants))
    }

    /// Applies `tweak` on top of the previous ones. On error `self` is left unchanged.
    pub fn apply_tweak(&mut self, backend: &B, tweak: Tweak) -> Result<(), Error> {
        let mut cache = self.cache.clone();
        let key = backend.tweak_add(&mut cache, &tweak.scalar, tweak.x_only)?;
        self.cache = cache;
        self.output_key = key;
        self.tweaks.push(tweak);
        Ok(())
    }

    /// Applies `tweaks` in order, stopping at the first failure.
    pub fn with_tweaks(mut self, backend: &B, tweaks: &[Tweak]) -> Result<Self, Error> {
        for tweak in tweaks {
            self.apply_tweak(backend, *tweak)?;
        }
        Ok(self)
    }

    pub fn participants(&self) -> &[[u8; 33]] {
        &self.participants
    }

    /// The KeyAgg output before any tweak.
    pub fn aggregate(&self) -> [u8; 33] {
        self.aggregate
    }

    /// The aggregate after every tweak.
    pub fn output_key(&self) -> [u8; 33] {
        self.output_key
    }

    pub fn tweaks(&self) -> &[Tweak] {
        &self.tweaks
    }

    pub fn cache(&self) -> &B::KeyAggCache {
        &self.cache
    }
}

/// BIP-327 KeySort of `keys` into a new list.
pub fn key_sort<B: MusigBackend>(backend: &B, keys: &[[u8; 33]]) -> Vec<[u8; 33]> {
    let mut sorted = keys.to_vec();
    backend.key_sort(&mut sorted);
    sorted
}

/// The BIP-328 synthetic xpub of `aggregate`. Depth 0, parent fingerprint 0 and child
/// number 0 are implied: the caller building a BIP-32 xpub fills them.
pub fn synthetic_xpub(aggregate: &[u8; 33]) -> SyntheticXpub {
    SyntheticXpub {
        key: *aggregate,
        chain_code: BIP328_CHAIN_CODE,
    }
}
