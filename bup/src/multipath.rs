//! Multipath helpers - read the `<a;b>` group out of a Liana descriptor key, and group
//! tap-tree leaves by their multipath layout.

use std::collections::BTreeMap;

use bwk_descriptor::wallet::WalletKey;
#[cfg(feature = "musig")]
use bwk_keys::musig::MusigKey;
use miniscript::{
    bitcoin::bip32,
    descriptor::{self, DescriptorPublicKey},
    Miniscript, Tap,
};

use crate::{path::Path, policy::PolicyError};

/// The plain key behind `key`, None for a musig() aggregate.
#[cfg(not(feature = "musig"))]
pub(crate) fn plain_key(key: &WalletKey) -> Option<&DescriptorPublicKey> {
    Some(key)
}

/// The plain key behind `key`, None for a musig() aggregate.
#[cfg(feature = "musig")]
pub(crate) fn plain_key(key: &WalletKey) -> Option<&DescriptorPublicKey> {
    match key {
        MusigKey::Plain(k) => Some(k),
        MusigKey::Musig(_) => None,
    }
}

/// `key` as the wallet key type.
#[cfg(not(feature = "musig"))]
pub(crate) fn wallet_key(key: DescriptorPublicKey) -> WalletKey {
    key
}

/// `key` as the wallet key type.
#[cfg(feature = "musig")]
pub(crate) fn wallet_key(key: DescriptorPublicKey) -> WalletKey {
    MusigKey::Plain(key)
}

/// Lowest index of the reserved NUMS block `[0x7FFF_FF00, 0x7FFF_FFFF]`. Every unspendable
/// key `Policy::compile` emits (internal key and padding leaves) is the one NUMS xpub, each
/// slot on its own two-leg multipath inside this block, so a reader spots a NUMS slot by
/// its public key and an index at or above this bound. The block sits far above every zone.
pub(super) const NUMS_BLOCK_START: u32 = 0x7FFF_FF00;

/// First index of NUMS slot 0, the internal key: `<0x7FFF_FFFE;0x7FFF_FFFF>`. Slot `k` takes
/// `<0x7FFF_FFFE-2k;0x7FFF_FFFF-2k>`.
const NUMS_SLOT_0: u32 = 0x7FFF_FFFE;

/// NUMS slots the block holds: slot 0 for the internal key, 1 to 127 for padding leaves.
pub(super) const NUMS_SLOTS: usize = 128;

/// The multipath of NUMS slot `slot`, see [`NUMS_SLOT_0`].
pub(super) fn nums_slot_paths(slot: usize) -> descriptor::DerivPaths {
    assert!(slot < NUMS_SLOTS, "NUMS slot {slot} outside the block");
    deriv_paths_starting_at(NUMS_SLOT_0 - 2 * slot as u32)
}

/// `<a;a+1>` multipath `DerivPaths` starting at `start`.
pub(super) fn deriv_paths_starting_at(start: u32) -> descriptor::DerivPaths {
    descriptor::DerivPaths::new(vec![
        [bip32::ChildNumber::from_normal_idx(start).expect("non-hardened")][..].into(),
        [bip32::ChildNumber::from_normal_idx(start + 1).expect("non-hardened")][..].into(),
    ])
    .expect("two paths")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipathError {
    /// Key is not a `MultiXPub`.
    NotMultiXPub,
    /// The key's path count is not exactly 2.
    WrongPathCount(usize),
    /// One of the two derivation paths has more than one step.
    MultiStepPath,
    /// A path step is hardened rather than normal.
    HardenedStep,
    /// Multipath child are not consecutives
    NonConsecutive,
    /// A leaf's keys span two distinct multipath groups.
    LeafInMultipleGroups(usize),
    /// Keys within a single leaf do not all share the same multipath index.
    MixedLeafIndices(usize),
    /// Two distinct leaves share the same multipath group index.
    DuplicatedLeafIndices(u32),
    /// The first multipath index is odd; Liana requires even-aligned group starts.
    OddIndex,
    /// A tap-tree leaf carries no multipath xpub.
    LeafNotMultipath(usize),
}

impl std::fmt::Display for MultipathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMultiXPub => write!(f, "key is not a multipath xpub"),
            Self::WrongPathCount(n) => write!(f, "expected 2 multipath derivations, got {n}"),
            Self::MultiStepPath => write!(f, "multipath derivation must have exactly one step"),
            Self::HardenedStep => write!(f, "multipath step must be a normal (unhardened) index"),
            Self::NonConsecutive => write!(f, "multipath index are not consecutive"),
            Self::LeafInMultipleGroups(idx) => {
                write!(f, "leaf {idx} belongs to multiple multipath groups")
            }
            Self::MixedLeafIndices(idx) => {
                write!(f, "leaf {idx} has keys with different multipath indices")
            }
            Self::DuplicatedLeafIndices(idx) => {
                write!(f, "two different leaves share multipath index {idx}")
            }
            Self::OddIndex => {
                write!(f, "multipath group start index must be even")
            }
            Self::LeafNotMultipath(idx) => {
                write!(f, "leaf {idx} has no multipath xpub")
            }
        }
    }
}

/// Per-leaf bookkeeping returned by [`tap_tree_to_entries`].
pub struct LeafEntry<'a> {
    pub index: usize,
    pub depth: u8,
    /// Every multipath group index found among this leaf's keys. Empty when the leaf has no
    /// multipath xpubs.
    pub indices: Vec<u32>,
    /// The lifted leaf miniscript.
    pub ms: &'a Miniscript<WalletKey, Tap>,
}

impl<'a> LeafEntry<'a> {
    /// Returns the multipath index shared by all keys in this leaf, or `None` if the leaf has no
    /// multipath keys. Errors if the keys carry inconsistent indices.
    pub fn get_index(&self) -> Result<Option<u32>, MultipathError> {
        check_uniform_indices(self)?;
        Ok(self.indices.first().copied())
    }
}

/// A logical group of tap-tree leaves sharing consecutive `+2` multipath indices, identified by
/// their leaf indices into the tap tree.
pub struct LeafGroup(pub Vec<usize>);

impl Default for LeafGroup {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafGroup {
    pub fn new() -> Self {
        Self(vec![])
    }
    pub fn push(&mut self, index: usize) {
        self.0.push(index);
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for LeafGroup {
    type Item = usize;
    type IntoIter = std::vec::IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::error::Error for MultipathError {}

pub fn get_multipath_index(key: &WalletKey) -> Result<u32, MultipathError> {
    #[cfg(feature = "musig")]
    if let MusigKey::Musig(agg) = key {
        if agg.derives_cosigners() {
            return Err(MultipathError::NotMultiXPub);
        }
        let derivation = agg.derivation().ok_or(MultipathError::NotMultiXPub)?;
        return multipath_start(derivation.paths.paths());
    }
    let Some(DescriptorPublicKey::MultiXPub(xpub)) = plain_key(key) else {
        return Err(MultipathError::NotMultiXPub);
    };
    multipath_start(xpub.derivation_paths.paths())
}

/// The even start `a` of a strict `<a;a+1>` pair of single-step paths.
pub(crate) fn multipath_start(paths: &[bip32::DerivationPath]) -> Result<u32, MultipathError> {
    if paths.len() != 2 {
        return Err(MultipathError::WrongPathCount(paths.len()));
    }
    for p in paths {
        if p.len() != 1 {
            return Err(MultipathError::MultiStepPath);
        }
    }
    let first = paths[0][0];
    let second = paths[1][0];
    if first.is_hardened() || second.is_hardened() {
        return Err(MultipathError::HardenedStep);
    }
    let (first, second): (u32, u32) = (first.into(), second.into());
    if first % 2 != 0 {
        return Err(MultipathError::OddIndex);
    }
    if first + 1 != second {
        return Err(MultipathError::NonConsecutive);
    }
    Ok(first)
}

/// Extract every derivation index a key claims at the wildcard slot, alongside its xpub.
/// Returns `Ok(None)` for `Single(_)` (no derivation, nothing to collide on).
///
/// Shape constraints (mirroring `get_multipath_index`):
/// - `MultiXPub`: exactly two single-step, unhardened paths; both indices returned.
/// - `XPub`: exactly one single-step, unhardened derivation_path; the single index returned.
/// - musig() aggregate: its BIP-328 synthetic xpub with the indices of the musig()
///   derivation, under the same rules as `MultiXPub` (two paths) or `XPub` (one path);
///   `Ok(None)` without a derivation (a fixed key, like `Single`). Derived cosigners
///   (derive then aggregate) error with `NotMultiXPub`.
///
/// Multi-step / hardened / wrong-count paths error with the same `MultipathError` variants
/// the parser already uses, so the compile-side check and the parser stay aligned.
pub fn key_indices(key: &WalletKey) -> Result<Option<(bip32::Xpub, Vec<u32>)>, MultipathError> {
    #[cfg(feature = "musig")]
    if let MusigKey::Musig(agg) = key {
        if agg.derives_cosigners() {
            return Err(MultipathError::NotMultiXPub);
        }
        let Some(derivation) = agg.derivation() else {
            return Ok(None);
        };
        let paths = derivation.paths.paths();
        let indices = match paths.len() {
            2 => pair_indices(paths)?,
            1 => single_index(&paths[0])?,
            n => return Err(MultipathError::WrongPathCount(n)),
        };
        let xpub = *agg.synthetic_xpub().ok_or(MultipathError::NotMultiXPub)?;
        return Ok(Some((xpub, indices)));
    }
    match plain_key(key) {
        Some(DescriptorPublicKey::MultiXPub(xpub)) => Ok(Some((
            xpub.xkey,
            pair_indices(xpub.derivation_paths.paths())?,
        ))),
        Some(DescriptorPublicKey::XPub(xpub)) => {
            Ok(Some((xpub.xkey, single_index(&xpub.derivation_path)?)))
        }
        Some(DescriptorPublicKey::Single(_)) | None => Ok(None),
    }
}

/// Both indices of a `<a;a+1>` (or `<a;a>`) pair of single-step, unhardened paths.
fn pair_indices(paths: &[bip32::DerivationPath]) -> Result<Vec<u32>, MultipathError> {
    if paths.len() != 2 {
        return Err(MultipathError::WrongPathCount(paths.len()));
    }
    for p in paths {
        if p.len() != 1 {
            return Err(MultipathError::MultiStepPath);
        }
    }
    let first = paths[0][0];
    let second = paths[1][0];
    if first.is_hardened() || second.is_hardened() {
        return Err(MultipathError::HardenedStep);
    }
    let (first_u, second_u): (u32, u32) = (first.into(), second.into());
    // Reject gaps like `<3;5>`. We deliberately *don't* fire here when the two
    // legs are identical (e.g. `<3;3>`) so that the higher-level intra-key
    // duplicate detector can surface that case as `DuplicateMultipathIndex`
    // rather than `NonConsecutive`.
    if first_u != second_u && first_u + 1 != second_u {
        return Err(MultipathError::NonConsecutive);
    }
    Ok(vec![first_u, second_u])
}

/// The index of a single-step, unhardened path.
fn single_index(path: &bip32::DerivationPath) -> Result<Vec<u32>, MultipathError> {
    if path.len() != 1 {
        return Err(MultipathError::MultiStepPath);
    }
    let step = path[0];
    if step.is_hardened() {
        return Err(MultipathError::HardenedStep);
    }
    Ok(vec![step.into()])
}

/// Returns `Err(MixedLeafIndices)` if the entry's keys do not all share the same multipath index.
fn check_uniform_indices(entry: &LeafEntry) -> Result<(), MultipathError> {
    if let Some(&first) = entry.indices.first() {
        if entry.indices.iter().any(|&i| i != first) {
            return Err(MultipathError::MixedLeafIndices(entry.index));
        }
    }
    Ok(())
}

/// Walk a tap tree, bucket each leaf by its multipath group, then convert each bucket into
/// spending [`Path`]s via [`super::parse::leaves_to_path`].
pub fn group_taptree_leaves(all_leaves: Vec<LeafEntry>) -> Result<Vec<Path>, PolicyError> {
    let mut leaf_map: BTreeMap<usize, LeafEntry> =
        all_leaves.into_iter().map(|e| (e.index, e)).collect();

    let mut by_mp: BTreeMap<u32, usize> = BTreeMap::new();
    for (&leaf_idx, entry) in &leaf_map {
        if let Some(mp_idx) = entry.get_index()? {
            if by_mp.insert(mp_idx, leaf_idx).is_some() {
                return Err(MultipathError::DuplicatedLeafIndices(mp_idx).into());
            }
        }
    }

    let mut leaf_groups: Vec<LeafGroup> = Vec::new();
    let mut current = LeafGroup::new();
    let mut prev_mp: Option<u32> = None;

    for (&mp_idx, &leaf_idx) in &by_mp {
        match prev_mp {
            None => current.push(leaf_idx),
            // Belt-and-suspenders: every `mp_idx` here came from `get_multipath_index`
            // (via `extract_leaves` → `LeafEntry::indices`), which already rejects odd
            // starts. This arm is unreachable through the normal call path but kept as
            // a safety net for any future caller that constructs `LeafEntry` directly.
            Some(p) if p % 2 != 0 => return Err(MultipathError::OddIndex.into()),
            Some(p) if mp_idx == p + 2 => current.push(leaf_idx),
            Some(_) => {
                leaf_groups.push(current);
                current = LeafGroup::new();
                current.push(leaf_idx);
            }
        }
        prev_mp = Some(mp_idx);
    }
    if !current.is_empty() {
        leaf_groups.push(current);
    }

    let mut paths: Vec<Path> = Vec::new();
    for g in leaf_groups {
        let group: Vec<LeafEntry> = g
            .into_iter()
            .map(|idx| {
                leaf_map
                    .remove(&idx)
                    .ok_or(MultipathError::LeafInMultipleGroups(idx))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(PolicyError::from)?;
        paths.push(crate::parse::group_to_path(&group)?);
    }

    if let Some((&idx, _)) = leaf_map.iter().next() {
        return Err(MultipathError::LeafNotMultipath(idx).into());
    }

    Ok(paths)
}

/// Walk `paths` sorted by `Path::order`, bucketing by each path's role zone, and lay each
/// path out via `Path::set_start_index` (which also compiles the leaf miniscripts and
/// stores them on the path itself).
///
/// Assumes `Policy::resolve_global_order` ran first (every path has `order = Some(_)`)
/// and that the policy passed `Policy::sanitize` (so `Semantic::starting_index` returns
/// `Some` for every path).
pub(super) fn assign_start_indices(paths: &mut [Path]) -> Result<(), PolicyError> {
    let mut order: Vec<usize> = (0..paths.len()).collect();
    // Stable sort: paths sharing the same `order` keep their `paths[]` insertion order,
    // matching the leaf-concat order in `tree_builder::build` so multipath indices and
    // tap-leaf placement agree within a priority group.
    order.sort_by_key(|&i| paths[i].order().expect("set by resolve_global_order"));
    let mut zone_cursors: BTreeMap<u32, u32> = BTreeMap::new();
    for path_idx in order {
        let path = &mut paths[path_idx];
        let zone = path
            .semantic()
            .starting_index(path.locktime())
            .expect("validated by sanitize");
        let cursor = *zone_cursors.entry(zone).or_insert(zone);
        let next = path.set_start_index(cursor)?;
        zone_cursors.insert(zone, next);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "musig")]
    use bwk_keys::musig::{MusigAggregate, MusigDerivation};
    #[cfg(feature = "musig")]
    use miniscript::{bitcoin::NetworkKind, descriptor::Wildcard};

    #[cfg(feature = "musig")]
    use crate::multipath::{deriv_paths_starting_at, key_indices, MultipathError};
    use crate::multipath::{
        get_multipath_index, nums_slot_paths, plain_key, wallet_key, NUMS_BLOCK_START, NUMS_SLOTS,
    };

    #[test]
    fn nums_slots_fill_the_block() {
        let indices = |slot| -> Vec<u32> {
            nums_slot_paths(slot)
                .paths()
                .iter()
                .map(|p| u32::from(p[0]))
                .collect()
        };
        assert_eq!(indices(0), vec![0x7FFF_FFFE, 0x7FFF_FFFF]);
        assert_eq!(indices(1), vec![0x7FFF_FFFC, 0x7FFF_FFFD]);
        assert_eq!(indices(NUMS_SLOTS - 1), vec![NUMS_BLOCK_START, 0x7FFF_FF01]);
    }

    #[test]
    #[should_panic(expected = "NUMS slot 128 outside the block")]
    fn nums_slot_past_the_block_panics() {
        nums_slot_paths(NUMS_SLOTS);
    }

    const KEY_4_5: &str = "[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<4;5>/*";

    /// `musig(K1, K2)` over the two policy test xpubs, aggregate then derive at
    /// `<start;start+1>/*`, or with no derivation when `start` is None.
    #[cfg(feature = "musig")]
    fn musig_key_at(start: Option<u32>) -> MusigKey {
        let cosigners = vec![
            DescriptorPublicKey::from_str("[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW").unwrap(),
            DescriptorPublicKey::from_str("[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe").unwrap(),
        ];
        let derivation = start.map(|start| MusigDerivation {
            paths: deriv_paths_starting_at(start),
            wildcard: Wildcard::Unhardened,
        });
        MusigKey::Musig(MusigAggregate::new(cosigners, derivation, NetworkKind::Main).unwrap())
    }

    #[test]
    fn key_multipath_extraction() {
        let key = wallet_key(DescriptorPublicKey::from_str(KEY_4_5).unwrap());
        assert_eq!(get_multipath_index(&key), Ok(4));
    }

    #[test]
    fn plain_key_round_trips_wallet_key() {
        let k = DescriptorPublicKey::from_str(KEY_4_5).unwrap();
        assert_eq!(plain_key(&wallet_key(k.clone())), Some(&k));
        assert_eq!(get_multipath_index(&wallet_key(k)), Ok(4));
    }

    #[cfg(feature = "musig")]
    #[test]
    fn get_multipath_index_reads_musig_derivation() {
        assert_eq!(get_multipath_index(&musig_key_at(Some(512))), Ok(512));
    }

    #[cfg(feature = "musig")]
    #[test]
    fn get_multipath_index_rejects_musig_without_derivation() {
        assert_eq!(
            get_multipath_index(&musig_key_at(None)),
            Err(MultipathError::NotMultiXPub)
        );
    }

    #[cfg(feature = "musig")]
    #[test]
    fn get_multipath_index_rejects_derive_then_aggregate() {
        let cosigners = vec![
            DescriptorPublicKey::from_str("[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*").unwrap(),
            DescriptorPublicKey::from_str("[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*").unwrap(),
        ];
        let key = MusigKey::Musig(MusigAggregate::new(cosigners, None, NetworkKind::Main).unwrap());
        assert_eq!(get_multipath_index(&key), Err(MultipathError::NotMultiXPub));
        assert_eq!(key_indices(&key), Err(MultipathError::NotMultiXPub));
    }

    #[cfg(feature = "musig")]
    #[test]
    fn key_indices_musig_uses_synthetic_xpub() {
        let key = musig_key_at(Some(512));
        let MusigKey::Musig(agg) = &key else {
            panic!("expected a musig() key");
        };
        assert_eq!(
            key_indices(&key),
            Ok(Some((*agg.synthetic_xpub().unwrap(), vec![512, 513])))
        );
        assert_eq!(key_indices(&musig_key_at(None)), Ok(None));
    }
}
