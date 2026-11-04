//! Key slots. A slot is one distinct (base key, branch pair) of a descriptor:
//! a base key used on two derivation paths has two slots, each with its own
//! tweak in a bundle. The slots of a base key are numbered from 0 in path
//! order. Outside the descriptor a slot is only its base key and its number,
//! never its path, so the delegator learns that a key is reused but nothing of
//! its paths.

use alloc::vec::Vec;

use crate::{
    backend::{BitcoinBackend, Xpub},
    Error,
};

/// A base key and the number of one of its slots. Ordered by key, then number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot {
    pub key: [u8; 33],
    pub number: u8,
}

/// One slot of a descriptor: its number and the key expression of its path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorSlot {
    pub number: u8,
    pub xpub: Xpub,
}

impl DescriptorSlot {
    pub fn slot(&self) -> Slot {
        Slot {
            key: self.xpub.key,
            number: self.number,
        }
    }
}

/// The slots of a descriptor from its key expressions `xpubs`, in any order
/// and repeats included: the distinct expressions sorted by key then branches,
/// each numbered by its rank among the expressions of its key, so in path
/// order. An empty list is `NoKeys`. A base key with two chain codes is
/// `ConflictingChainCode`, two slots of a key sharing a branch
/// `OverlappingPaths`, more than 256 slots of a key `TooManySlots`.
pub fn slots(mut xpubs: Vec<Xpub>) -> Result<Vec<DescriptorSlot>, Error> {
    if xpubs.is_empty() {
        return Err(Error::NoKeys);
    }
    xpubs.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.branches.cmp(&b.branches)));
    xpubs.dedup();
    let mut slots = Vec::with_capacity(xpubs.len());
    for key_xpubs in xpubs.chunk_by(|a, b| a.key == b.key) {
        check_key_paths(key_xpubs)?;
        for (rank, xpub) in key_xpubs.iter().enumerate() {
            let number = u8::try_from(rank).map_err(|_| Error::TooManySlots(xpub.key))?;
            slots.push(DescriptorSlot {
                number,
                xpub: xpub.clone(),
            });
        }
    }
    Ok(slots)
}

/// The slots of descriptor `d`, from the key expressions `descriptor_xpubs`
/// returns.
pub(crate) fn descriptor_slots<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
) -> Result<Vec<DescriptorSlot>, Error> {
    slots(c.descriptor_xpubs(d)?)
}

/// Checks the key expressions of one base key, distinct and sorted by
/// branches: one chain code, at most 256 of them, no branch path shared by
/// two of them. The count is checked before the pairwise path scan.
fn check_key_paths(key_xpubs: &[Xpub]) -> Result<(), Error> {
    let first = &key_xpubs[0];
    if key_xpubs.iter().any(|x| x.chain_code != first.chain_code) {
        return Err(Error::ConflictingChainCode(first.key));
    }
    if key_xpubs.len() > 256 {
        return Err(Error::TooManySlots(first.key));
    }
    for (i, a) in key_xpubs.iter().enumerate() {
        for b in &key_xpubs[i + 1..] {
            if a.branches.iter().any(|branch| b.branches.contains(branch)) {
                return Err(Error::OverlappingPaths(first.key));
            }
        }
    }
    Ok(())
}

/// Checks that `slots`, sorted, number the slots of every key 0, 1, 2, ...:
/// a repeated slot is `DuplicateKey`, a missing one `SlotGap`.
pub(crate) fn check_numbering(slots: &[Slot]) -> Result<(), Error> {
    let mut prev: Option<&Slot> = None;
    for slot in slots {
        let expected = match prev {
            Some(prev) if prev == slot => return Err(Error::DuplicateKey),
            Some(prev) if prev.key == slot.key => u16::from(prev.number) + 1,
            _ => 0,
        };
        if u16::from(slot.number) != expected {
            return Err(Error::SlotGap);
        }
        prev = Some(slot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use crate::{
        backend::Xpub,
        slot::{check_numbering, slots, Slot},
        Error,
    };

    const A: [u8; 33] = [0x02; 33];
    const B: [u8; 33] = [0x03; 33];

    fn path(key: [u8; 33], receive: u32, change: u32) -> Xpub {
        Xpub {
            key,
            chain_code: [0x01; 32],
            branches: [vec![receive], vec![change]],
        }
    }

    fn slot(key: [u8; 33], number: u8) -> Slot {
        Slot { key, number }
    }

    /// The (slot, xpub) pairs `slots` returns for `xpubs`.
    fn numbered(xpubs: Vec<Xpub>) -> Result<Vec<(Slot, Xpub)>, Error> {
        Ok(slots(xpubs)?
            .into_iter()
            .map(|s| (s.slot(), s.xpub))
            .collect())
    }

    #[test]
    fn slots_sort_deduplicate_and_number() {
        let expressions = vec![path(B, 0, 1), path(A, 2, 3), path(A, 0, 1), path(A, 2, 3)];
        assert_eq!(
            numbered(expressions).unwrap(),
            vec![
                (slot(A, 0), path(A, 0, 1)),
                (slot(A, 1), path(A, 2, 3)),
                (slot(B, 0), path(B, 0, 1)),
            ]
        );
    }

    #[test]
    fn slots_order_by_path() {
        let fixed = Xpub {
            key: A,
            chain_code: [0x01; 32],
            branches: [vec![5, 0], vec![5, 1]],
        };
        let expressions = vec![fixed.clone(), path(A, 6, 7), path(A, 2, 3)];
        assert_eq!(
            numbered(expressions).unwrap(),
            vec![
                (slot(A, 0), path(A, 2, 3)),
                (slot(A, 1), fixed),
                (slot(A, 2), path(A, 6, 7)),
            ]
        );
    }

    #[test]
    fn slots_refusals() {
        assert_eq!(slots(vec![]), Err(Error::NoKeys));

        let other_chain_code = Xpub {
            chain_code: [0x02; 32],
            ..path(A, 2, 3)
        };
        assert_eq!(
            slots(vec![path(A, 0, 1), other_chain_code]),
            Err(Error::ConflictingChainCode(A))
        );

        for overlapping in [path(A, 1, 2), path(A, 2, 1), path(A, 1, 0), path(A, 0, 2)] {
            assert_eq!(
                slots(vec![path(B, 0, 1), path(A, 0, 1), overlapping]),
                Err(Error::OverlappingPaths(A))
            );
        }

        let many: Vec<Xpub> = (0..257).map(|i| path(A, 2 * i, 2 * i + 1)).collect();
        let first_256 = numbered(many[..256].to_vec()).unwrap();
        assert_eq!(first_256[255].0, slot(A, 255));
        assert_eq!(slots(many), Err(Error::TooManySlots(A)));
    }

    #[test]
    fn check_numbering_cases() {
        assert_eq!(check_numbering(&[]), Ok(()));
        assert_eq!(
            check_numbering(&[slot(A, 0), slot(A, 1), slot(B, 0)]),
            Ok(())
        );
        assert_eq!(
            check_numbering(&[slot(A, 0), slot(A, 0)]),
            Err(Error::DuplicateKey)
        );
        assert_eq!(check_numbering(&[slot(A, 1)]), Err(Error::SlotGap));
        assert_eq!(
            check_numbering(&[slot(A, 0), slot(A, 2)]),
            Err(Error::SlotGap)
        );
        assert_eq!(
            check_numbering(&[slot(A, 0), slot(B, 1)]),
            Err(Error::SlotGap)
        );
    }
}
