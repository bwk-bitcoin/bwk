//! `Path` and friends - the per-spending-path representation used by the new `Policy` model.

use miniscript::{
    bitcoin::{absolute, bip32, relative},
    policy::Semantic as SemanticPolicy,
    DescriptorPublicKey, Miniscript, Tap,
};

use crate::key_role::KeyType;

/// CLTV alignment grid (~ 1 week of blocks). `Locktime::AbsoluteRenewable` heights are
/// constrained to non-zero multiples of this - the small candidate set keeps a future
/// descriptor brute-forceable from the seed.
pub const CLTV_ALIGNMENT: u32 = 1024;

/// Width of a path-role's multipath zone. Each role's leaves live within
/// `[starting_index(), starting_index() + ROLE_ZONE_WIDTH)`.
pub const MULTIPATH_SEMANTIC_FACTOR: u32 = 2u32.pow(9);

/// Round `target` up to the next [`CLTV_ALIGNMENT`] multiple. Always >= [`CLTV_ALIGNMENT`].
///
/// Panics if `target` is too large to round up without overflowing `u32` (i.e.
/// `target >= u32::MAX - CLTV_ALIGNMENT + 1`). Realistic block heights never come
/// anywhere near this edge; the panic catches programmer error rather than a
/// production concern.
pub fn cltv_align(target: u32) -> u32 {
    (target & !(CLTV_ALIGNMENT - 1))
        .checked_add(CLTV_ALIGNMENT)
        .expect("cltv_align: target too large to round up without overflow")
}

/// Whether `target` is non-zero and aligned to the [`CLTV_ALIGNMENT`] grid.
pub fn is_cltv_aligned(target: u32) -> bool {
    target != 0 && (target & (CLTV_ALIGNMENT - 1)) == 0
}

/// Binomial coefficient `C(n, k)`. Returns `1` for `k == 0` and `0` for `k > n`. Avoids
/// overflow by alternating multiply/divide on running symmetric `min(k, n-k)`.
pub(crate) fn count_combinations(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    let k = k.min(n - k);
    (0..k).fold(1usize, |acc, i| acc * (n - i) / (i + 1))
}

/// Whether any [`OXpub`] appears in both `mandatory_keys` and `keys`. Used by
/// [`Semantic::validate`] to enforce disjoint sets on `MultiMandatory` and
/// `MultiMandatoryNested` paths.
fn has_mandatory_cosigner_overlap(mandatory_keys: &[OXpub], keys: &[OXpub]) -> bool {
    let mset: std::collections::BTreeSet<&OXpub> = mandatory_keys.iter().collect();
    keys.iter().any(|k| mset.contains(k))
}

/// Signer identity: the HD origin (fingerprint + derivation path) and master xpub, stripped
/// of any multipath derivation. Two keys with the same `OXpub` represent the same signer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OXpub {
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    pub xkey: bip32::Xpub,
}

impl OXpub {
    pub fn new(
        origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
        xkey: bip32::Xpub,
    ) -> Self {
        Self { origin, xkey }
    }

    /// Reject xpubs that can't represent a real signer:
    /// - public key equals the BIP-341 NUMS unspendable key,
    /// - public key x-coordinate is all zeros (sentinel / placeholder),
    /// - chain code is all zeros (sentinel / placeholder).
    pub fn validate(&self) -> Result<(), OXpubError> {
        if self.xkey.public_key == crate::nums::bip341_nums() {
            return Err(OXpubError::NumsKey);
        }
        // The compressed serialization is [parity, x_coord(32B)]. A real key on the curve
        // can't have x=0 (no point with x=0 satisfies y^2 = x^3 + 7), but we defensively
        // reject it anyway in case a placeholder slipped past upstream validation.
        if self.xkey.public_key.serialize()[1..33] == [0u8; 32] {
            return Err(OXpubError::ZeroedPubkey);
        }
        if self.xkey.chain_code.to_bytes() == [0u8; 32] {
            return Err(OXpubError::ZeroedChainCode);
        }
        Ok(())
    }
}

/// Structural problem with an [`OXpub`]: it points at a known-unspendable key (BIP-341 NUMS),
/// has a zeroed public-key x-coordinate, or carries a zeroed chain code (sentinel /
/// placeholder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OXpubError {
    /// The xpub's public key is the BIP-341 NUMS unspendable key.
    NumsKey,
    /// The xpub's public key has an all-zero x-coordinate.
    ZeroedPubkey,
    /// The xpub's chain code is all zeros.
    ZeroedChainCode,
}

/// Where in a Taproot descriptor a [`Path`] sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapPosition {
    /// Path lives in the Tr internal key.
    InternalKey,
    /// Path occupies one or more tap-tree leaves. For [`Semantic::MultiMandatory`] this
    /// holds the leaves the path was flattened into.
    TapTree(Vec<Leaf>),
}

/// Depth-first index of a tap-tree leaf occupied by a [`Path`]. The leaf hash is intentionally
/// omitted: it depends on the derived (single-index) leaf script, which a multipath descriptor
/// can't supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf(pub usize);

/// Structural problem with a [`Locktime`]: timestamp-side absolute heights or unaligned
/// renewable heights. Lifted into [`crate::policy::PolicyError`] via `From`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocktimeError {
    /// Absolute height encodes a timestamp (`>= LOCK_TIME_THRESHOLD`); we don't model that.
    InsaneAbsoluteHeight(u32),
    /// `AbsoluteRenewable` height is not aligned to the [`CLTV_ALIGNMENT`] grid.
    Unaligned(u32),
}

/// Per-path locktime gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locktime {
    /// No locktime gate (immediately spendable).
    None,
    /// `older(...)` / OP_CSV - a relative timelock. Only block-height encoding is
    /// supported (`u16`); time-based relative locktimes (bit-22 set) are out of
    /// scope and rejected by both parse (falls back to `Semantic::Unknown`) and
    /// compile (errors as `InsaneTimelock`).
    Relative(relative::LockTime),
    /// `after(...)` aligned to [`CLTV_ALIGNMENT`]. Renewable: re-issuing the descriptor with
    /// a later aligned height stays brute-forceable from the seed.
    AbsoluteRenewable(absolute::LockTime),
    /// `after(...)` not aligned to our grid. Recorded so the wallet can spend; renewal is
    /// disallowed (foreign creator's scheme unknown).
    Absolute(absolute::LockTime),
}

impl Locktime {
    /// Structural sanity check on this locktime:
    /// - `Absolute` / `AbsoluteRenewable` heights must be a block height, not a timestamp
    ///   (`< LOCK_TIME_THRESHOLD`),
    /// - `AbsoluteRenewable` heights must additionally be aligned to [`CLTV_ALIGNMENT`].
    ///
    /// `None` and `Relative(_)` are always structurally fine.
    pub fn validate(&self) -> Result<(), LocktimeError> {
        match self {
            Locktime::None | Locktime::Relative(_) => Ok(()),
            Locktime::AbsoluteRenewable(lt) => {
                let h = lt.to_consensus_u32();
                if h >= miniscript::bitcoin::absolute::LOCK_TIME_THRESHOLD {
                    return Err(LocktimeError::InsaneAbsoluteHeight(h));
                }
                if !is_cltv_aligned(h) {
                    return Err(LocktimeError::Unaligned(h));
                }
                Ok(())
            }
            Locktime::Absolute(lt) => {
                let h = lt.to_consensus_u32();
                if h >= miniscript::bitcoin::absolute::LOCK_TIME_THRESHOLD {
                    return Err(LocktimeError::InsaneAbsoluteHeight(h));
                }
                Ok(())
            }
        }
    }
}

/// Structural problem with a [`Semantic`]: out-of-range thresholds for `Multi` /
/// `MultiMandatory`, or a key that fails [`OXpub::validate`]. Lifted into
/// [`crate::policy::PolicyError`] via `From`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticError {
    /// `Multi.threshold` must be in `[1, keys.len()]`.
    InvalidThreshold { threshold: usize, key_count: usize },
    /// `MultiMandatory.threshold` must be in
    /// `[mandatory_count + 1, mandatory_count + cosigner_count]`.
    InvalidMandatoryThreshold {
        threshold: usize,
        mandatory_count: usize,
        cosigner_count: usize,
    },
    /// `MultiMandatoryNested` threshold on one side is out of the open range
    /// `(0, key_count)` - both `mandatory_threshold` and `threshold` must be a
    /// *proper* subset selector (`1 <= threshold < key_count`). Equality on either
    /// side would compile to a leaf set indistinguishable from a `MultiMandatory`.
    InvalidNestedMandatoryThreshold {
        side: NestedSide,
        threshold: usize,
        key_count: usize,
    },
    /// `MultiMandatoryNested` has matching frequencies on both sides
    /// (`mandatory_threshold * keys.len() == threshold * mandatory_keys.len()`).
    /// The compiled leaves are unrecoverable: the parser cannot tell which class is
    /// `mandatory_keys` vs `keys`.
    NestedMandatoryAmbiguousFrequencies {
        mandatory_threshold: usize,
        mandatory_count: usize,
        threshold: usize,
        cosigner_count: usize,
    },
    /// `MultiMandatoryNested` is not in canonical form. The `mandatory_keys` class must be
    /// the lower-frequency side (`mandatory_threshold * keys.len() < threshold *
    /// mandatory_keys.len()`); swap the two key sets to canonicalise.
    NestedMandatoryNonCanonical {
        mandatory_threshold: usize,
        mandatory_count: usize,
        threshold: usize,
        cosigner_count: usize,
    },
    /// A key appears in both `mandatory_keys` and `keys` (cosigners) of a
    /// [`Semantic::MultiMandatory`] or [`Semantic::MultiMandatoryNested`] path. The two
    /// sets must be disjoint: a mandatory key already signs every leaf, so including it
    /// among the cosigners is structurally degenerate (the cosigner sig is
    /// indistinguishable from the mandatory one).
    MandatoryCosignerOverlap,
    /// One of the path's keys is not a real signer key (NUMS or zeroed chain code).
    InvalidKey(OXpubError),
}

/// Which side of a [`Semantic::MultiMandatoryNested`] a threshold-range error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedSide {
    Mandatory,
    Cosigner,
}

/// Shape of the keys participating in a [`Path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Semantic {
    /// `pk(K)` - exactly one signer.
    Single(OXpub),
    /// `thresh(t, K1, …, Kn)` - `t`-of-`n` multisig.
    Multi { keys: Vec<OXpub>, threshold: usize },
    /// Every key in `mandatory_keys` must sign, plus `(threshold - m)`-of-`keys`.
    /// `threshold` is the total signer count per leaf (mandatory + chosen cosigners),
    /// so it must satisfy `m + 1 <= threshold <= m + n`.
    MultiMandatory {
        keys: Vec<OXpub>,
        mandatory_keys: Vec<OXpub>,
        threshold: usize,
    },

    /// `and(thresh(mandatory_threshold, mandatory_keys), thresh(threshold, keys))` -
    /// two independent subset gates on two disjoint key sets. Both must be satisfied.
    /// Compiled by enumerating one tap-leaf per `(mandatory_subset, cosigner_subset)`
    /// pair where each subset has the size of its threshold: total leaves
    /// `C(mandatory_keys.len(), mandatory_threshold) * C(keys.len(), threshold)`,
    /// each leaf a flat `thresh(mandatory_threshold + threshold, selected ∪ selected)`.
    ///
    /// Canonical form (enforced by [`Semantic::validate`]):
    /// - `1 <= mandatory_threshold < mandatory_keys.len()` and
    ///   `1 <= threshold < keys.len()` (strict subsets - equality collapses to
    ///   [`Semantic::MultiMandatory`]).
    /// - `mandatory_threshold * keys.len() != threshold * mandatory_keys.len()`
    ///   (distinct per-class frequencies - identical frequencies make the parser
    ///   unable to recover the partition).
    /// - `mandatory_threshold * keys.len() < threshold * mandatory_keys.len()`
    ///   (`mandatory_keys` is the lower-frequency class - canonical ordering for
    ///   round-trip).
    MultiMandatoryNested {
        mandatory_keys: Vec<OXpub>,
        mandatory_threshold: usize,
        keys: Vec<OXpub>,
        threshold: usize,
    },
    /// Any one sub-semantic must be satisfied (`thresh(1, …)`).
    Or(Vec<Semantic>),
    /// A policy we couldn't classify into any known spending-path shape. Produced by
    /// `Policy::from_descriptor`; not constructable via `Policy::new` (consumers use
    /// [`Semantic::Custom`] instead). Uncompilable: a policy containing `Unknown` paths
    /// cannot round-trip back through `Policy::compile`.
    Unknown {
        policy: SemanticPolicy<DescriptorPublicKey>,
    },
    /// Consumer-provided tap-context miniscript leaf. The compiler reissues the multipath
    /// derivation indices on every key but otherwise emits the miniscript as-is.
    /// `Custom` paths require `Locktime::None`; any locktime gate must be encoded inside
    /// the embedded miniscript by the consumer.
    Custom(Miniscript<DescriptorPublicKey, Tap>),
}

impl Semantic {
    /// Iterator over every signer key in this `Semantic` (mandatory + cosigners for the
    /// mandatory-key shape). Empty for `Unknown` and `Or`.
    pub fn keys(&self) -> impl Iterator<Item = &OXpub> + '_ {
        let v: Vec<&OXpub> = match self {
            Semantic::Single(k) => vec![k],
            Semantic::Multi { keys, .. } => keys.iter().collect(),
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                ..
            }
            | Semantic::MultiMandatoryNested {
                mandatory_keys,
                keys,
                ..
            } => mandatory_keys.iter().chain(keys.iter()).collect(),
            Semantic::Unknown { .. } | Semantic::Or(_) | Semantic::Custom(_) => vec![],
        };
        v.into_iter()
    }

    /// Signatures required by one leaf script. `None` for `Unknown` or `Or` (branch-dependent).
    pub fn sig_count(&self) -> Option<usize> {
        match self {
            Semantic::Single(_) => Some(1),
            Semantic::Multi { threshold, .. } => Some(*threshold),
            Semantic::MultiMandatory { threshold, .. } => Some(*threshold),
            Semantic::MultiMandatoryNested {
                mandatory_threshold,
                threshold,
                ..
            } => Some(*mandatory_threshold + *threshold),
            Semantic::Unknown { .. } | Semantic::Or(_) | Semantic::Custom(_) => None,
        }
    }

    /// Structural sanity check: `Multi` / `MultiMandatory` thresholds must be in range,
    /// and every signer key (`OXpub`) must pass [`OXpub::validate`] (no NUMS, no zeroed
    /// chain code). `Or`, `Unknown`, and `Custom` carry no thresholds or `OXpub` keys to
    /// check; they pass unconditionally. `Or` and `Unknown` are uncompilable; `Custom`
    /// compiles by reissuing multipath indices on its embedded miniscript.
    pub fn validate(&self) -> Result<(), SemanticError> {
        for k in self.keys() {
            k.validate().map_err(SemanticError::InvalidKey)?;
        }
        match self {
            Semantic::Single(_)
            | Semantic::Or(_)
            | Semantic::Unknown { .. }
            | Semantic::Custom(_) => Ok(()),
            Semantic::Multi { keys, threshold } => {
                if *threshold == 0 || *threshold > keys.len() {
                    return Err(SemanticError::InvalidThreshold {
                        threshold: *threshold,
                        key_count: keys.len(),
                    });
                }
                Ok(())
            }
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                let m = mandatory_keys.len();
                let n = keys.len();
                if *threshold <= m || *threshold > m + n {
                    return Err(SemanticError::InvalidMandatoryThreshold {
                        threshold: *threshold,
                        mandatory_count: m,
                        cosigner_count: n,
                    });
                }
                if has_mandatory_cosigner_overlap(mandatory_keys, keys) {
                    return Err(SemanticError::MandatoryCosignerOverlap);
                }
                Ok(())
            }
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                mandatory_threshold,
                keys,
                threshold,
            } => {
                let m = mandatory_keys.len();
                let n = keys.len();
                let mt = *mandatory_threshold;
                let t = *threshold;
                if has_mandatory_cosigner_overlap(mandatory_keys, keys) {
                    return Err(SemanticError::MandatoryCosignerOverlap);
                }
                // Strict subsets on both sides: equality collapses to MultiMandatory.
                if mt == 0 || mt >= m {
                    return Err(SemanticError::InvalidNestedMandatoryThreshold {
                        side: NestedSide::Mandatory,
                        threshold: mt,
                        key_count: m,
                    });
                }
                if t == 0 || t >= n {
                    return Err(SemanticError::InvalidNestedMandatoryThreshold {
                        side: NestedSide::Cosigner,
                        threshold: t,
                        key_count: n,
                    });
                }
                // Distinct per-class frequencies (mt/m vs t/n).
                let lhs = mt * n;
                let rhs = t * m;
                if lhs == rhs {
                    return Err(SemanticError::NestedMandatoryAmbiguousFrequencies {
                        mandatory_threshold: mt,
                        mandatory_count: m,
                        threshold: t,
                        cosigner_count: n,
                    });
                }
                // Canonical ordering: mandatory class has the *lower* frequency.
                if lhs > rhs {
                    return Err(SemanticError::NestedMandatoryNonCanonical {
                        mandatory_threshold: mt,
                        mandatory_count: m,
                        threshold: t,
                        cosigner_count: n,
                    });
                }
                Ok(())
            }
        }
    }

    /// Multipath base index emitted by the compiler for a path with this `Semantic` and the
    /// given `locktime`. Encodes the path's role.
    pub fn starting_index(&self, locktime: &Locktime) -> Option<u32> {
        #[allow(clippy::identity_op)]
        match (locktime, self) {
            (Locktime::None, Semantic::Single(_) | Semantic::Multi { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 1)
            }
            (Locktime::Relative(_), Semantic::Single(_) | Semantic::Multi { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 2)
            }
            (Locktime::Relative(_), Semantic::MultiMandatory { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 3)
            }
            (Locktime::AbsoluteRenewable(_), Semantic::Single(_) | Semantic::Multi { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 4)
            }
            (Locktime::Absolute(_), Semantic::Single(_) | Semantic::Multi { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 5)
            }
            (Locktime::None, Semantic::Custom(_)) => Some(MULTIPATH_SEMANTIC_FACTOR * 6),
            (Locktime::AbsoluteRenewable(_), Semantic::MultiMandatory { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 7)
            }
            (Locktime::Absolute(_), Semantic::MultiMandatory { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 8)
            }
            (Locktime::Relative(_), Semantic::MultiMandatoryNested { .. }) => {
                Some(MULTIPATH_SEMANTIC_FACTOR * 9)
            }
            _ => None,
        }
    }
}

/// One spending path of a [`super::policy::Policy`]. Carries its keys (via `semantic`), its
/// locktime gate, its position in the Tr descriptor, and a precomputed witness-unit cost to
/// satisfy.
///
/// Compile inputs (caller-set): `order`.
/// Compile outputs (set by `Policy::compile`): `satisfaction_wu`, `indices`, `miniscript`,
/// `start_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    semantic: Semantic,
    locktime: Locktime,
    position: TapPosition,
    /// Caller-supplied global tap-tree position for this path. With `N` paths in the policy,
    /// valid values are `0..N`. Caller-set orders are honoured first; remaining `None`s are
    /// filled by ascending-locktime sort during compile. Caller input, not populated by
    /// `Policy::compile` / `Policy::from_descriptor`.
    order: Option<usize>,
    /// Multipath base index assigned by the compiler. `None` until `Policy::compile` runs;
    /// caller does not set this.
    start_index: Option<u32>,
    /// Witness units to satisfy this path (rust-miniscript's satisfaction module + control
    /// block). `None` until populated by `Policy::from_descriptor` / `Policy::compile`.
    satisfaction_wu: Option<u64>,
    /// Even multipath indices (0, 2, 4, …) assigned to this path's leaves. Only populated
    /// by `Policy::compile`; remains empty on paths produced by `Policy::from_descriptor`.
    indices: Vec<u32>,
    /// All compiled tap-leaf miniscripts produced for this path. Populated by
    /// `Policy::compile` (one entry for `Single`/`Multi`, one entry per cosigner-subset
    /// for `MultiMandatory`); empty for `TapPosition::InternalKey` and for paths
    /// produced by `Policy::from_descriptor`.
    leaves: Vec<Miniscript<DescriptorPublicKey, Tap>>,
}

impl Path {
    pub fn new(semantic: Semantic, locktime: Locktime, position: TapPosition) -> Self {
        Self {
            semantic,
            locktime,
            position,
            order: None,
            start_index: None,
            satisfaction_wu: None,
            indices: Vec::new(),
            leaves: Vec::new(),
        }
    }

    pub fn semantic(&self) -> &Semantic {
        &self.semantic
    }

    pub fn locktime(&self) -> &Locktime {
        &self.locktime
    }

    pub(super) fn set_position(&mut self, position: TapPosition) {
        self.position = position;
    }

    /// Per-zone cursor advance after laying out this path's leaves: `+2` per leaf plus
    /// `+2` for the between-paths boundary. Override on a custom `Path` shape if a future
    /// variant needs a different stride.
    pub fn cursor_increment(&self) -> u32 {
        2 * self.leaf_count() as u32 + 2
    }

    /// Number of tap-tree leaves this path expands into during compilation. `0` for shapes
    /// the compiler can't emit (`Or`, `Unknown`) or for an out-of-range mandatory-key
    /// threshold. `Custom` always expands into a single tap-leaf.
    pub fn leaf_count(&self) -> usize {
        match &self.semantic {
            Semantic::Single(_) | Semantic::Multi { .. } | Semantic::Custom(_) => 1,
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                let m = mandatory_keys.len();
                let n = keys.len();
                if *threshold <= m || *threshold > m + n {
                    return 0;
                }
                count_combinations(n, threshold - m)
            }
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                mandatory_threshold,
                keys,
                threshold,
            } => {
                let m = mandatory_keys.len();
                let n = keys.len();
                let mt = *mandatory_threshold;
                let t = *threshold;
                if mt == 0 || mt >= m || t == 0 || t >= n {
                    return 0;
                }
                count_combinations(m, mt) * count_combinations(n, t)
            }
            Semantic::Or(_) | Semantic::Unknown { .. } => 0,
        }
    }

    pub fn position(&self) -> &TapPosition {
        &self.position
    }

    pub fn satisfaction_wu(&self) -> Option<u64> {
        self.satisfaction_wu
    }

    pub fn set_satisfaction_wu(&mut self, wu: Option<u64>) {
        self.satisfaction_wu = wu;
    }

    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    pub fn set_indices(&mut self, indices: Vec<u32>) {
        self.indices = indices;
    }

    /// Compiled tap-leaf miniscripts for this path. Empty for `TapPosition::InternalKey`
    /// paths and for paths produced by `Policy::from_descriptor` (which only stores leaf
    /// indices, not the lifted miniscripts).
    pub fn leaves(&self) -> &[Miniscript<DescriptorPublicKey, Tap>] {
        &self.leaves
    }

    /// Iterator over every signer key in this path.
    pub fn keys(&self) -> impl Iterator<Item = &OXpub> + '_ {
        self.semantic.keys()
    }

    pub fn order(&self) -> Option<usize> {
        self.order
    }

    pub fn set_order(&mut self, order: Option<usize>) {
        self.order = order;
    }

    pub fn start_index(&self) -> Option<u32> {
        self.start_index
    }

    pub fn key_types(&self) -> Vec<(OXpub, Option<KeyType>)> {
        todo!()
    }

    /// Lay out this path at multipath base `start`: assign `start_index`, populate
    /// `indices`, and (for script-path positions) compile every fragment into a
    /// tap-leaf miniscript stored back on `self.leaves`. Returns the next cursor
    /// position (`start + self.cursor_increment()`).
    ///
    /// Compile-only entry point: clears `self.leaves` on every call and re-fills via
    /// `compile::path_into_fragments`. Not safe to call mid-lifecycle outside
    /// `Policy::compile`: consumers should use the public `Policy` API.
    pub(super) fn set_start_index(
        &mut self,
        start: u32,
    ) -> Result<u32, crate::policy::PolicyError> {
        self.start_index = Some(start);
        self.leaves.clear();
        if matches!(self.position, TapPosition::InternalKey) {
            self.indices = vec![start];
            return Ok(start + self.cursor_increment());
        }
        let mut cursor = start;
        let (leaves, indices) = crate::compile::path_into_fragments(self, &mut cursor)?;
        self.indices = indices;
        self.leaves = leaves;
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniscript::{policy::Liftable, Miniscript, Tap};
    use std::str::FromStr;

    fn oxpub(s: &str) -> OXpub {
        use miniscript::DescriptorPublicKey;
        let k = DescriptorPublicKey::from_str(s).unwrap();
        let DescriptorPublicKey::MultiXPub(x) = k else {
            panic!("expected MultiXPub");
        };
        OXpub::new(x.origin, x.xkey)
    }

    #[test]
    fn semantic_keys_iteration() {
        let k1 = oxpub(
            "[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*",
        );
        let k2 = oxpub(
            "[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*",
        );
        let k3 = oxpub(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );

        let s = Semantic::Single(k1.clone());
        assert_eq!(s.keys().count(), 1);
        assert_eq!(s.sig_count(), Some(1));

        let s = Semantic::Multi {
            keys: vec![k1.clone(), k2.clone()],
            threshold: 1,
        };
        assert_eq!(s.keys().count(), 2);
        assert_eq!(s.sig_count(), Some(1));

        // threshold=2 = 1 mandatory + 1 cosigner per leaf (total signers per leaf).
        let s = Semantic::MultiMandatory {
            keys: vec![k2.clone(), k3.clone()],
            mandatory_keys: vec![k1.clone()],
            threshold: 2,
        };
        // mandatory + cosigners
        assert_eq!(s.keys().count(), 3);
        // sig_count returns the total signer count per leaf.
        assert_eq!(s.sig_count(), Some(2));

        let policy = Miniscript::<DescriptorPublicKey, Tap>::from_str(
            "pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*)",
        )
        .unwrap()
        .lift()
        .unwrap()
        .normalized();
        let s = Semantic::Unknown { policy };
        assert_eq!(s.keys().count(), 0);
        assert_eq!(s.sig_count(), None);
    }

    #[test]
    fn path_satisfaction_wu_starts_none() {
        let k = oxpub(
            "[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<4;5>/*",
        );
        let p = Path::new(
            Semantic::Single(k),
            Locktime::None,
            TapPosition::InternalKey,
        );
        // Path::new initialises satisfaction_wu to None - Policy::compile /
        // Policy::from_descriptor refines it once the tap-tree depth is known.
        assert_eq!(p.satisfaction_wu(), None);
    }

    #[test]
    fn unknown_path_has_no_weight() {
        let policy = Miniscript::<DescriptorPublicKey, Tap>::from_str(
            "pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*)",
        )
        .unwrap()
        .lift()
        .unwrap()
        .normalized();
        let p = Path::new(
            Semantic::Unknown { policy },
            Locktime::None,
            TapPosition::TapTree(vec![Leaf(0)]),
        );
        assert_eq!(p.satisfaction_wu(), None);
    }
}
