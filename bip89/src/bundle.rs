//! The canonical BIP89 delegation bundle: one tweak entry per key slot,
//! sorted by slot, with a strict byte codec. The accumulator hashes this
//! encoding as a leaf, so a bundle has exactly one valid encoding, sorted with
//! fixed-width entries and no count prefix, because two encodings would give
//! two leaves for the same data. The encoding carries no slot number: the
//! entries of a key are its slots 0, 1, 2, ... in order. Bundle derivation from
//! a descriptor lives here too: `KeychainState` caches the fixed part of a
//! slot's tweak path so deriving each index costs one more BIP32 step instead
//! of walking the fixed steps again.

use alloc::vec::Vec;

use crate::{
    backend::{BitcoinBackend, Sha256Engine},
    scalar::scalar_is_valid,
    slot::{check_numbering, descriptor_slots, DescriptorSlot, Slot},
    tweak::{ckd_pub, compute_bip32_tweak},
    Error,
};

/// Byte length of one entry: a 33-byte compressed key plus a 32-byte tweak.
pub const ENTRY_LEN: usize = 65;

/// A key slot and its accumulated tweak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub slot: Slot,
    pub tweak: [u8; 32],
}

/// A canonical delegation bundle: entries sorted by slot, the slots of each
/// key numbered from 0 with no gap. The inner vector stays private so every
/// `Bundle` in existence is canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle(Vec<Entry>);

impl Bundle {
    /// Sorts `entries` by slot and validates them. Fails on an empty input, a
    /// tweak not below the curve order, a repeated slot, or a gap in the slots
    /// of a key.
    pub fn new(mut entries: Vec<Entry>) -> Result<Bundle, Error> {
        if entries.is_empty() {
            return Err(Error::EntryLength);
        }
        for entry in &entries {
            if !scalar_is_valid(&entry.tweak) {
                return Err(Error::ScalarRange);
            }
        }
        entries.sort_by(|a, b| a.slot.cmp(&b.slot));
        let slots: Vec<Slot> = entries.iter().map(|entry| entry.slot).collect();
        check_numbering(&slots)?;
        Ok(Bundle(entries))
    }

    /// Parses a bundle from its canonical encoding. Never sorts: rejects a
    /// length that is not a positive multiple of 65, a tweak not below the
    /// curve order, keys that are not ascending, or more than 256 entries of
    /// one key. The entries of a key are its slots in order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Bundle, Error> {
        if bytes.is_empty() || bytes.len() % ENTRY_LEN != 0 {
            return Err(Error::EntryLength);
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(bytes.len() / ENTRY_LEN);
        for chunk in bytes.chunks_exact(ENTRY_LEN) {
            let mut key = [0u8; 33];
            let mut tweak = [0u8; 32];
            key.copy_from_slice(&chunk[..33]);
            tweak.copy_from_slice(&chunk[33..]);
            if !scalar_is_valid(&tweak) {
                return Err(Error::ScalarRange);
            }
            let number = match entries.last() {
                Some(prev) if key < prev.slot.key => return Err(Error::UnsortedBundle),
                Some(prev) if key == prev.slot.key => prev
                    .slot
                    .number
                    .checked_add(1)
                    .ok_or(Error::TooManySlots(key))?,
                _ => 0,
            };
            entries.push(Entry {
                slot: Slot { key, number },
                tweak,
            });
        }
        Ok(Bundle(entries))
    }

    /// The canonical encoding: `key` then `tweak` per entry in sorted order,
    /// with no count prefix.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * ENTRY_LEN);
        for entry in &self.0 {
            out.extend_from_slice(&entry.slot.key);
            out.extend_from_slice(&entry.tweak);
        }
        out
    }

    pub fn entries(&self) -> &[Entry] {
        &self.0
    }

    /// The tweak for `slot`, if the bundle has an entry for it.
    pub fn tweak(&self, slot: &Slot) -> Option<[u8; 32]> {
        match self.0.binary_search_by(|entry| entry.slot.cmp(slot)) {
            Ok(i) => Some(self.0[i].tweak),
            Err(_) => None,
        }
    }

    /// Streams the same bytes as `to_bytes` into `engine`, without
    /// allocating the concatenation.
    pub fn feed<E: Sha256Engine>(&self, engine: &mut E) {
        for entry in &self.0 {
            engine.update(&entry.slot.key);
            engine.update(&entry.tweak);
        }
    }
}

/// The fixed part of one slot's tweak path for one keychain, computed once
/// and reused for every index.
pub(crate) struct KeychainState {
    slot: Slot,
    base_tweak: [u8; 32],
    child_key: [u8; 33],
    child_cc: [u8; 32],
}

impl KeychainState {
    pub(crate) fn new<B: BitcoinBackend>(
        c: &B,
        slot: &DescriptorSlot,
        keychain: u32,
    ) -> Result<Self, Error> {
        let xpub = &slot.xpub;
        let branch = xpub
            .branches
            .get(keychain as usize)
            .ok_or(Error::InvalidKeychain)?;
        let d = compute_bip32_tweak(c, &xpub.key, &xpub.chain_code, branch)?;
        Ok(Self {
            slot: slot.slot(),
            base_tweak: d.tweak,
            child_key: d.key,
            child_cc: d.chain_code,
        })
    }

    /// The aggregated tweak at `index`. Equal to `compute_bip32_tweak` over
    /// the full tweak path, but the fixed steps are hashed only once.
    pub(crate) fn tweak_at<B: BitcoinBackend>(&self, c: &B, index: u32) -> Result<[u8; 32], Error> {
        let d = ckd_pub(c, &self.child_key, &self.child_cc, index)?;
        Ok(c.scalar_add(&self.base_tweak, &d.tweak))
    }

    pub(crate) fn slot(&self) -> &Slot {
        &self.slot
    }
}

/// Builds one `KeychainState` per slot of `d` for `keychain`, sorted by slot.
/// Keychain 2 or above is `InvalidKeychain`.
pub(crate) fn keychain_states<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    keychain: u32,
) -> Result<Vec<KeychainState>, Error> {
    if keychain >= 2 {
        return Err(Error::InvalidKeychain);
    }
    descriptor_slots(c, d)?
        .iter()
        .map(|slot| KeychainState::new(c, slot, keychain))
        .collect()
}

/// Computes the BIP89 delegation bundle of descriptor `d` for `keychain` and
/// `index`: one tweak entry per slot.
pub fn derive_bundle<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    keychain: u32,
    index: u32,
) -> Result<Bundle, Error> {
    let states = keychain_states(c, d, keychain)?;
    let entries = states
        .iter()
        .map(|state| {
            Ok(Entry {
                slot: state.slot,
                tweak: state.tweak_at(c, index)?,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Bundle::new(entries)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use crate::{
        backend::Sha256Engine,
        bundle::{Bundle, Entry},
        slot::Slot,
        Error,
    };

    const A_KEY: [u8; 33] = [
        0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11,
    ];
    const B_KEY: [u8; 33] = [
        0x02, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22,
    ];
    const C_KEY: [u8; 33] = [
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    const MISSING_KEY: [u8; 33] = [
        0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];
    const N_BYTES: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    const fn slot(key: [u8; 33], number: u8) -> Slot {
        Slot { key, number }
    }

    const A: Entry = Entry {
        slot: slot(A_KEY, 0),
        tweak: [0x01; 32],
    };
    const A1: Entry = Entry {
        slot: slot(A_KEY, 1),
        tweak: [0x04; 32],
    };
    const B: Entry = Entry {
        slot: slot(B_KEY, 0),
        tweak: [0x02; 32],
    };
    const C: Entry = Entry {
        slot: slot(C_KEY, 0),
        tweak: [0x03; 32],
    };

    struct Collect(Vec<u8>);

    impl Sha256Engine for Collect {
        fn update(&mut self, data: &[u8]) {
            self.0.extend_from_slice(data);
        }

        fn finalize(self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[test]
    fn new_sorts_entries() {
        let bundle = Bundle::new(vec![C, A, B]).unwrap();
        assert_eq!(bundle.entries(), [A, B, C]);
    }

    #[test]
    fn new_sorts_slots_of_a_key() {
        let bundle = Bundle::new(vec![B, A1, A]).unwrap();
        assert_eq!(bundle.entries(), [A, A1, B]);
    }

    #[test]
    fn new_rejects_duplicate_slot() {
        let dup = Entry {
            slot: A.slot,
            tweak: [0x09; 32],
        };
        assert_eq!(Bundle::new(vec![A, dup]), Err(Error::DuplicateKey));
    }

    #[test]
    fn new_rejects_slot_gap() {
        assert_eq!(Bundle::new(vec![A1, B]), Err(Error::SlotGap));
    }

    #[test]
    fn new_rejects_empty_and_tweak_n() {
        assert_eq!(Bundle::new(vec![]), Err(Error::EntryLength));
        let bad = Entry {
            slot: B.slot,
            tweak: N_BYTES,
        };
        assert_eq!(Bundle::new(vec![A, bad]), Err(Error::ScalarRange));
    }

    #[test]
    fn bytes_roundtrip_literal() {
        let bytes = Bundle::new(vec![B, A]).unwrap().to_bytes();
        assert_eq!(bytes.len(), 130);
        let expected = [
            &[0x02][..],
            &[0x11; 32],
            &[0x01; 32],
            &[0x02],
            &[0x22; 32],
            &[0x02; 32],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(
            Bundle::from_bytes(&bytes).unwrap(),
            Bundle::new(vec![A, B]).unwrap()
        );
    }

    #[test]
    fn from_bytes_rejects_bad_length() {
        assert_eq!(Bundle::from_bytes(&[]), Err(Error::EntryLength));
        assert_eq!(Bundle::from_bytes(&[0u8; 64]), Err(Error::EntryLength));
        assert_eq!(Bundle::from_bytes(&[0u8; 66]), Err(Error::EntryLength));
    }

    #[test]
    fn from_bytes_rejects_unsorted() {
        let mut b_then_a = Vec::new();
        b_then_a.extend_from_slice(&B.slot.key);
        b_then_a.extend_from_slice(&B.tweak);
        b_then_a.extend_from_slice(&A.slot.key);
        b_then_a.extend_from_slice(&A.tweak);
        assert_eq!(Bundle::from_bytes(&b_then_a), Err(Error::UnsortedBundle));
    }

    #[test]
    fn from_bytes_numbers_repeated_key_as_slots() {
        let bundle = Bundle::new(vec![A, A1, B]).unwrap();
        let bytes = bundle.to_bytes();
        let expected = [
            &[0x02][..],
            &[0x11; 32],
            &[0x01; 32],
            &[0x02],
            &[0x11; 32],
            &[0x04; 32],
            &[0x02],
            &[0x22; 32],
            &[0x02; 32],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(Bundle::from_bytes(&bytes).unwrap(), bundle);
    }

    #[test]
    fn from_bytes_rejects_a_257th_slot() {
        let mut bytes = Vec::new();
        for _ in 0..257 {
            bytes.extend_from_slice(&A.slot.key);
            bytes.extend_from_slice(&A.tweak);
        }
        let bundle = Bundle::from_bytes(&bytes[..256 * 65]).unwrap();
        assert_eq!(bundle.entries()[255].slot, slot(A_KEY, 255));
        assert_eq!(Bundle::from_bytes(&bytes), Err(Error::TooManySlots(A_KEY)));
    }

    #[test]
    fn from_bytes_rejects_tweak_n() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&A.slot.key);
        bytes.extend_from_slice(&N_BYTES);
        assert_eq!(Bundle::from_bytes(&bytes), Err(Error::ScalarRange));
    }

    #[test]
    fn tweak_lookup() {
        let bundle = Bundle::new(vec![A, A1, B, C]).unwrap();
        assert_eq!(bundle.tweak(&B.slot), Some([0x02; 32]));
        assert_eq!(bundle.tweak(&A1.slot), Some([0x04; 32]));
        assert_eq!(bundle.tweak(&slot(B_KEY, 1)), None);
        assert_eq!(bundle.tweak(&slot(MISSING_KEY, 0)), None);
    }

    #[test]
    fn feed_streams_serialization() {
        let bundle = Bundle::new(vec![A, B, C]).unwrap();
        let mut collect = Collect(Vec::new());
        bundle.feed(&mut collect);
        assert_eq!(collect.0, bundle.to_bytes());
    }
}
