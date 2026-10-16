//! Multipath helpers - read the `<a;b>` group out of a Liana descriptor key, and group
//! tap-tree leaves by their multipath layout.

use std::collections::BTreeMap;

use miniscript::{
    bitcoin::bip32,
    descriptor::{self, DescriptorPublicKey},
    Miniscript, Tap,
};

use crate::{path::Path, policy::PolicyError};

/// Marker multipath used on the NUMS internal key emitted by `Policy::compile`. The two
/// largest unhardened indices (`2^31 - 2` and `2^31 - 1`) tag the internal key as
/// unspendable-by-construction so the parser can detect it without recomputing the
/// chain-code hash. The chain-code algorithm itself stays byte-identical to
/// `analysis::unspendable_internal_xpub`, so the legacy detection path also still
/// recognises it.
pub(super) const NUMS_MARKER_MULTIPATH: [u32; 2] = [0x7FFF_FFFE, 0x7FFF_FFFF];

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
    pub ms: &'a Miniscript<DescriptorPublicKey, Tap>,
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

pub fn get_multipath_index(key: &DescriptorPublicKey) -> Result<u32, MultipathError> {
    let DescriptorPublicKey::MultiXPub(xpub) = key else {
        return Err(MultipathError::NotMultiXPub);
    };
    let paths = xpub.derivation_paths.paths();
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
///
/// Multi-step / hardened / wrong-count paths error with the same `MultipathError` variants
/// the parser already uses, so the compile-side check and the parser stay aligned.
pub fn key_indices(
    key: &DescriptorPublicKey,
) -> Result<Option<(bip32::Xpub, Vec<u32>)>, MultipathError> {
    match key {
        DescriptorPublicKey::MultiXPub(xpub) => {
            let paths = xpub.derivation_paths.paths();
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
            Ok(Some((xpub.xkey, vec![first_u, second_u])))
        }
        DescriptorPublicKey::XPub(xpub) => {
            let path = &xpub.derivation_path;
            if path.len() != 1 {
                return Err(MultipathError::MultiStepPath);
            }
            let step = path[0];
            if step.is_hardened() {
                return Err(MultipathError::HardenedStep);
            }
            Ok(Some((xpub.xkey, vec![step.into()])))
        }
        DescriptorPublicKey::Single(_) => Ok(None),
    }
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

    #[test]
    fn key_multipath_extraction() {
        use std::str::FromStr;
        let s = "[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<4;5>/*";
        let key = DescriptorPublicKey::from_str(s).unwrap();
        assert_eq!(get_multipath_index(&key), Ok(4));
    }
}
