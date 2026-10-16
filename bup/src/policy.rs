//! `Policy` and `SemanticDescriptor` - the new model for Tr Liana policies plus the top-level
//! enum that wraps a legacy [`LianaDescriptor`] or a new [`Policy`].

use std::{
    collections::{BTreeMap, BTreeSet},
    error, fmt,
};

use bwk_descriptor::wallet::{WalletDescriptor, WalletKey};
use miniscript::{
    bitcoin::absolute::LOCK_TIME_THRESHOLD,
    descriptor::{TapTree, Tr},
    policy::Semantic as SemanticPolicy,
    {Descriptor, DescriptorPublicKey},
};

use crate::{
    key_role::{KeyRoleError, KeyType},
    multipath::{
        assign_start_indices, get_multipath_index, group_taptree_leaves, plain_key, LeafEntry,
        NUMS_MARKER_MULTIPATH,
    },
    nums::{bip341_nums, unspendable_internal_key},
    parse::{compute_satisfaction_wu, infer_policy_type, oxpub, TR_KEY_PATH_WU},
    path::{
        Locktime, LocktimeError, NestedSide, OXpub, Path, Semantic, SemanticError, TapPosition,
    },
};

/// Most tap leaves a policy may compile to, padding excluded.
#[cfg(feature = "musig")]
pub const MAX_LEAVES: usize = 32;

/// Recognise an internal key tagged with `NUMS_MARKER_MULTIPATH` and the BIP-341 NUMS
/// pubkey. The marker is a structural contract by design: short-circuits before the
/// legacy chain-code recompute, so a foreign descriptor that reuses the marker on a
/// NUMS-keyed internal key is treated as unspendable regardless of derivation. Legacy
/// detection (chain-code recompute) still runs as a fallback for older descriptors.
fn is_new_style_nums(key: &WalletKey) -> bool {
    let Some(DescriptorPublicKey::MultiXPub(m)) = plain_key(key) else {
        return false;
    };
    if m.xkey.public_key != bip341_nums() {
        return false;
    }
    let paths = m.derivation_paths.paths();
    paths.len() == 2
        && paths[0].len() == 1
        && paths[1].len() == 1
        && u32::from(paths[0][0]) == NUMS_MARKER_MULTIPATH[0]
        && u32::from(paths[1][0]) == NUMS_MARKER_MULTIPATH[1]
}

fn extract_leaves<'a>(
    tap_tree: &'a TapTree<WalletKey>,
) -> Result<Vec<LeafEntry<'a>>, crate::multipath::MultipathError> {
    let mut entries = Vec::new();
    for (idx, (depth, ms)) in tap_tree.iter().enumerate() {
        if is_nums_padding_leaf(ms) {
            continue;
        }
        let mut indices = Vec::new();
        for k in ms.iter_pk() {
            indices.push(get_multipath_index(&k)?);
        }
        entries.push(LeafEntry {
            index: idx,
            depth,
            indices,
            ms,
        });
    }
    Ok(entries)
}

/// Structural match for a compiler-emitted NUMS padding leaf: a single `pk` over
/// a NUMS-pubkey'd `MultiXPub`. Parsing accepts any valid miniscript, so this
/// drops the leaf without verifying the chain-code chain, so a foreign descriptor
/// with an intentional `pk(NUMS)` leaf is silently dropped here. `compile`
/// enforces stricter rules: `OXpub::validate` rejects NUMS at the signer-key
/// boundary, so we never produce real `pk(NUMS)` signer leaves.
fn is_nums_padding_leaf(ms: &miniscript::Miniscript<WalletKey, miniscript::Tap>) -> bool {
    let mut keys = ms.iter_pk();
    let Some(first) = keys.next() else {
        return false;
    };
    if keys.next().is_some() {
        return false;
    }
    let Some(DescriptorPublicKey::MultiXPub(m)) = plain_key(&first) else {
        return false;
    };
    m.xkey.public_key == bip341_nums()
}

/// Tag identifying the on-chain shape of a [`Policy`]. Inferred from the path set's semantic
/// content (locktime kind + presence of mandatory keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyType {
    /// Original Csv shape - relative timelock recovery (`older(...)`).
    Csv,
    /// Absolute-timelock recovery (`after(...)`).
    Cltv,
    /// Relative timelock with one or more mandatory-key paths.
    CsvWithMandatoryKey,
    /// Relative timelock with one or more nested-mandatory-key paths
    /// ([`Semantic::MultiMandatoryNested`]). Distinct from
    /// [`PolicyType::CsvWithMandatoryKey`]; mixing the two flavors in the same policy
    /// falls into [`PolicyType::Unknown`].
    CsvWithNestedMandatory,
    /// Path set the typed classifier (`Csv` / `Cltv` / `CsvWithMandatoryKey`) doesn't recognise.
    /// Produced by `Policy::from_descriptor` when the descriptor can't be folded into a typed
    /// shape, and acceptable to `Policy::new` for consumers building arbitrary path sets.
    /// Compile-readiness is checked structurally per-path (`Semantic::validate` +
    /// `Locktime::validate`) without policy-level invariants like the single-primary rule.
    Unknown,
    /// Parser-only verdict for path sets that can never be a valid policy (no recovery,
    /// mixed locktime flavors, etc.). Not constructable via [`Policy::new`].
    Invalid,
}

#[derive(Debug)]
pub enum PolicyError {
    /// A `Policy` must have at least one [`Path`].
    EmptyPaths,
    /// `Cltv` policies require absolute heights aligned to `CLTV_ALIGNMENT`.
    UnalignedCltv(u32),
    /// `Cltv` height is on the timestamp side (`>= LOCK_TIME_THRESHOLD`), which we don't accept.
    InsaneCltvHeight(u32),
    /// The given `paths` don't fit the declared `PolicyType` (e.g. `Cltv` with a relative
    /// locktime, or `Csv` with a `MultiMandatory` semantic).
    InconsistentPathsForType(PolicyType),
    /// `CsvWithMandatoryKey` requires at least one `MultiMandatory` path.
    NoMandatoryKeyPath,
    /// `MultiMandatory.threshold` is invalid: must satisfy
    /// `mandatory_count + 1 <= threshold <= mandatory_count + cosigner_count` so each leaf
    /// requires every mandatory key plus at least one cosigner.
    InvalidMandatoryThreshold {
        threshold: usize,
        mandatory_count: usize,
        cosigner_count: usize,
    },
    /// `MultiMandatoryNested` threshold on one side is out of the open range
    /// `(0, key_count)`. Both `mandatory_threshold` and `threshold` must be a proper
    /// subset selector; equality on either side would collapse to `MultiMandatory`.
    InvalidNestedMandatoryThreshold {
        side: NestedSide,
        threshold: usize,
        key_count: usize,
    },
    /// `MultiMandatoryNested` has matching per-class frequencies
    /// (`mandatory_threshold * keys.len() == threshold * mandatory_keys.len()`). The
    /// parser cannot recover the partition; reject at construction time.
    NestedMandatoryAmbiguousFrequencies {
        mandatory_threshold: usize,
        mandatory_count: usize,
        threshold: usize,
        cosigner_count: usize,
    },
    /// `MultiMandatoryNested` is not in canonical form. Canonical form requires
    /// `mandatory_threshold * keys.len() < threshold * mandatory_keys.len()` (the
    /// `mandatory_keys` class must be the lower-frequency one). Swap the two key
    /// sets to canonicalise.
    NestedMandatoryNonCanonical {
        mandatory_threshold: usize,
        mandatory_count: usize,
        threshold: usize,
        cosigner_count: usize,
    },
    /// `CsvWithNestedMandatory` requires at least one `MultiMandatoryNested` path.
    NoNestedMandatoryKeyPath,
    /// A key appears in both `mandatory_keys` and `keys` of a [`Semantic::MultiMandatory`]
    /// or [`Semantic::MultiMandatoryNested`] path. The two sets must be disjoint.
    MandatoryCosignerOverlap,
    /// `Policy` cannot be constructed with `PolicyType::Invalid` - that variant is only produced
    /// by the parser when the path set has no recovery or mixes locktime flavors.
    InvalidNotConstructable,
    /// `Semantic::Unknown` is the parser-only escape hatch for descriptors we can't
    /// classify. Consumers must use [`crate::path::Semantic::Custom`] to embed an
    /// arbitrary tap-leaf miniscript instead.
    UnknownNotConstructable,
    /// A [`crate::path::Semantic::Custom`] path was given a non-`None` locktime. The
    /// embedded miniscript carries its own locktime gate; the `Path::locktime` field
    /// must stay `Locktime::None` for Custom paths.
    CustomWithLocktime,
    /// `Policy::from_descriptor` requires a Taproot descriptor.
    NotTaproot,
    /// A miniscript error bubbled up from compilation, parsing or lifting.
    Miniscript(miniscript::Error),
    /// A multipath-layout error from descriptor parsing.
    Multipath(crate::multipath::MultipathError),
    /// A locktime height that miniscript can't represent (timestamp side or > u16 height).
    InsaneTimelock(u32),
    /// Compilation hasn't been performed yet (called `descriptor()` on a fresh `Policy::new`
    /// before `compile`).
    NotYetCompiled,
    /// A group of tap-tree leaves could not be classified into a known [`Path`] shape.
    UnrecognizedLeafGroup,
    /// `threshold` is out of range for the given key count (`threshold` must be in `[1, n]`,
    /// or exactly `1` for a single-key path).
    InvalidThreshold { threshold: usize, key_count: usize },
    /// Wrong number of non-timelocked (primary) paths. Every policy must have exactly one.
    InvalidPrimaryCount(usize),
    /// Two recovery paths share the same timelock height; recovery timelocks must be distinct.
    DuplicateTimelock(u32),
    /// Policy has no timelocked recovery path; every policy must have at least one.
    MissingRecoveryPath,
    /// Policy mixes more than one locktime flavor in the same descriptor. Each policy may use
    /// only one of: relative (`older`), aligned-renewable absolute (`after`), or
    /// foreign-unaligned absolute (`after`).
    MixedTimelockKinds,
    /// A signer key in the policy is not a real signer key (BIP-341 NUMS unspendable key,
    /// or zeroed chain code / pubkey).
    InvalidSignerKey(crate::path::OXpubError),
    /// A `TapPosition::InternalKey` path carries a non-`None` locktime; the Tr internal key
    /// must be unconditionally spendable.
    InternalKeyWithLocktime,
    /// A `TapPosition::InternalKey` path's semantic is not `Single`; the Tr internal key is
    /// a single-key spend, not a multisig or threshold shape.
    InternalKeyNotSingle,
    /// More than one path is at `TapPosition::InternalKey`; a Tr descriptor has exactly one
    /// internal key.
    MultipleInternalKeys,
    /// The internal tree builder reported an error.
    TreeBuilder(crate::tree_builder::TreeBuilderError),
    /// Two distinct paths claim the same `(xpub, multipath index)`. Triggered when a
    /// `Custom` path's keys overlap with another path's cursor-allocated zone, with
    /// another `Custom` path, or with an `XPub` single-derivation. Detected post-cursor
    /// allocation in `Policy::compile`.
    DuplicateMultipathIndex {
        xpub: miniscript::bitcoin::bip32::Xpub,
        index: u32,
    },
    /// More tap leaves than `MAX_LEAVES`, padding excluded.
    #[cfg(feature = "musig")]
    TooManyLeaves { count: usize, max: usize },
    /// A musig() whose cosigners carry derivation: only aggregate then derive is read.
    #[cfg(feature = "musig")]
    MusigDerivation,
    /// A key-role encoding error.
    KeyRole(KeyRoleError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EmptyPaths => write!(f, "Policy must contain at least one path."),
            Self::UnalignedCltv(t) => {
                write!(f, "CLTV height '{t}' is not aligned to the CLTV grid.")
            }
            Self::InsaneCltvHeight(t) => {
                write!(
                    f,
                    "CLTV height '{t}' is invalid (>= LOCK_TIME_THRESHOLD = {LOCK_TIME_THRESHOLD})."
                )
            }
            Self::InconsistentPathsForType(pt) => write!(
                f,
                "Path set is inconsistent with declared PolicyType '{pt:?}'."
            ),
            Self::NoMandatoryKeyPath => write!(
                f,
                "CsvWithMandatoryKey requires at least one MultiMandatory path."
            ),
            Self::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            } => write!(
                f,
                "Invalid MultiMandatory threshold {threshold}: must be in [{lo}, {hi}].",
                lo = mandatory_count + 1,
                hi = mandatory_count + cosigner_count,
            ),
            Self::InvalidNotConstructable => write!(
                f,
                "PolicyType::Invalid cannot be constructed; only the parser produces it."
            ),
            Self::UnknownNotConstructable => write!(
                f,
                "Semantic::Unknown is parser-only; use Semantic::Custom for arbitrary tap-leaf scripts."
            ),
            Self::CustomWithLocktime => write!(
                f,
                "Semantic::Custom requires Locktime::None; encode any locktime gate inside the miniscript."
            ),
            Self::NotTaproot => write!(f, "Policy::from_descriptor requires a Taproot descriptor."),
            Self::Miniscript(e) => write!(f, "Miniscript error: '{e}'."),
            Self::Multipath(e) => write!(f, "{e}"),
            Self::InsaneTimelock(t) => {
                write!(f, "Timelock value '{t}' isn't valid or safe to use.")
            }
            Self::NotYetCompiled => write!(f, "Policy has not been compiled to a descriptor yet."),
            Self::UnrecognizedLeafGroup => write!(
                f,
                "tap-tree leaf group could not be classified into a known path shape"
            ),
            Self::InvalidThreshold {
                threshold,
                key_count,
            } => write!(
                f,
                "threshold {threshold} is out of range for {key_count} key(s): must be in [1, {key_count}]",
            ),
            Self::InvalidPrimaryCount(c) => write!(
                f,
                "policy has {c} non-timelocked path(s); exactly one is required"
            ),
            Self::DuplicateTimelock(h) => write!(
                f,
                "two recovery paths share timelock height {h}; recovery timelocks must be distinct"
            ),
            Self::MissingRecoveryPath => {
                write!(
                    f,
                    "policy has no timelocked recovery path; at least one is required"
                )
            }
            Self::MixedTimelockKinds => write!(
                f,
                "policy mixes more than one locktime flavor; only one of relative, aligned absolute, or foreign absolute is allowed per policy"
            ),
            Self::InvalidSignerKey(e) => match e {
                crate::path::OXpubError::NumsKey => write!(
                    f,
                    "policy contains the BIP-341 NUMS unspendable key as a signer; that key cannot sign"
                ),
                crate::path::OXpubError::ZeroedPubkey => write!(
                    f,
                    "policy contains a key with a zeroed public-key x-coordinate (placeholder / sentinel)"
                ),
                crate::path::OXpubError::ZeroedChainCode => write!(
                    f,
                    "policy contains a key with a zeroed chain code (placeholder / sentinel)"
                ),
            },
            Self::InternalKeyWithLocktime => write!(
                f,
                "Tr internal-key path has a non-None locktime; the internal key must be unconditionally spendable"
            ),
            Self::InternalKeyNotSingle => write!(
                f,
                "Tr internal-key path semantic is not Single; the internal key is a single-key spend"
            ),
            Self::MultipleInternalKeys => write!(
                f,
                "policy declares more than one TapPosition::InternalKey path; a Tr descriptor has exactly one internal key"
            ),
            Self::TreeBuilder(e) => write!(f, "tree builder error: {e}"),
            Self::DuplicateMultipathIndex { xpub, index } => write!(
                f,
                "multipath index {index} is claimed by two distinct paths for xpub {xpub}"
            ),
            Self::InvalidNestedMandatoryThreshold {
                side,
                threshold,
                key_count,
            } => {
                let which = match side {
                    NestedSide::Mandatory => "mandatory_threshold",
                    NestedSide::Cosigner => "threshold",
                };
                write!(
                    f,
                    "MultiMandatoryNested {which} {threshold} must be in [1, {hi}] (strict subset of {key_count} key(s))",
                    hi = key_count.saturating_sub(1),
                )
            }
            Self::NestedMandatoryAmbiguousFrequencies {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            } => write!(
                f,
                "MultiMandatoryNested has matching frequencies on both sides (mt/m = {mandatory_threshold}/{mandatory_count} = t/n = {threshold}/{cosigner_count}); the parser cannot recover the partition"
            ),
            Self::NestedMandatoryNonCanonical {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            } => write!(
                f,
                "MultiMandatoryNested is non-canonical: mandatory class must be the lower-frequency one (mt*n = {} >= t*m = {}); swap the key sets to canonicalise",
                mandatory_threshold * cosigner_count,
                threshold * mandatory_count,
            ),
            Self::NoNestedMandatoryKeyPath => write!(
                f,
                "CsvWithNestedMandatory requires at least one MultiMandatoryNested path."
            ),
            Self::MandatoryCosignerOverlap => write!(
                f,
                "a key appears in both mandatory_keys and keys of a MultiMandatory or MultiMandatoryNested path; the two sets must be disjoint"
            ),
            #[cfg(feature = "musig")]
            Self::TooManyLeaves { count, max } => write!(
                f,
                "policy needs {count} tap leaves, more than the {max} allowed"
            ),
            #[cfg(feature = "musig")]
            Self::MusigDerivation => write!(
                f,
                "musig() with derivation on its cosigners is not supported: only aggregate then derive"
            ),
            Self::KeyRole(e) => write!(f, "{e}"),
        }
    }
}

impl error::Error for PolicyError {}

impl From<crate::tree_builder::TreeBuilderError> for PolicyError {
    fn from(e: crate::tree_builder::TreeBuilderError) -> Self {
        PolicyError::TreeBuilder(e)
    }
}

impl From<miniscript::Error> for PolicyError {
    fn from(e: miniscript::Error) -> Self {
        Self::Miniscript(e)
    }
}

impl From<crate::multipath::MultipathError> for PolicyError {
    fn from(e: crate::multipath::MultipathError) -> Self {
        Self::Multipath(e)
    }
}

impl From<SemanticError> for PolicyError {
    fn from(e: SemanticError) -> Self {
        match e {
            SemanticError::InvalidThreshold {
                threshold,
                key_count,
            } => PolicyError::InvalidThreshold {
                threshold,
                key_count,
            },
            SemanticError::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            } => PolicyError::InvalidMandatoryThreshold {
                threshold,
                mandatory_count,
                cosigner_count,
            },
            SemanticError::InvalidNestedMandatoryThreshold {
                side,
                threshold,
                key_count,
            } => PolicyError::InvalidNestedMandatoryThreshold {
                side,
                threshold,
                key_count,
            },
            SemanticError::NestedMandatoryAmbiguousFrequencies {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            } => PolicyError::NestedMandatoryAmbiguousFrequencies {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            },
            SemanticError::NestedMandatoryNonCanonical {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            } => PolicyError::NestedMandatoryNonCanonical {
                mandatory_threshold,
                mandatory_count,
                threshold,
                cosigner_count,
            },
            SemanticError::MandatoryCosignerOverlap => PolicyError::MandatoryCosignerOverlap,
            SemanticError::InvalidKey(e) => PolicyError::InvalidSignerKey(e),
        }
    }
}

impl From<LocktimeError> for PolicyError {
    fn from(e: LocktimeError) -> Self {
        match e {
            LocktimeError::InsaneAbsoluteHeight(h) => PolicyError::InsaneCltvHeight(h),
            LocktimeError::Unaligned(h) => PolicyError::UnalignedCltv(h),
        }
    }
}

impl From<KeyRoleError> for PolicyError {
    fn from(e: KeyRoleError) -> Self {
        Self::KeyRole(e)
    }
}

/// A Tr-only Liana policy. Carries its [`Path`]s, an optional cached compiled
/// [`WalletDescriptor`], and the [`PolicyType`] tag.
#[derive(Debug, Clone)]
pub struct Policy {
    paths: Vec<Path>,
    descriptor: Option<WalletDescriptor>,
    policy_type: PolicyType,
}

/// Logical equality: compares `paths` and `policy_type`. The cached `descriptor`
/// is deliberately ignored so that a freshly-built `Policy::new` and the same
/// policy after `compile()` compare equal.
impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.paths == other.paths && self.policy_type == other.policy_type
    }
}

impl Eq for Policy {}

impl Policy {
    /// Build a `Policy` from an explicit set of [`Path`]s and a [`PolicyType`].
    ///
    /// Validates that the paths are coherent with the tag (e.g. no `Absolute` locktimes in a
    /// `Csv` policy, no unaligned absolute heights in `Cltv`, at least one `MultiMandatory`
    /// in `CsvWithMandatoryKey`). Leaves `descriptor` as `None` - call [`Self::compile`] to
    /// produce the on-chain artefact.
    pub fn new(paths: Vec<Path>, policy_type: PolicyType) -> Result<Self, PolicyError> {
        if matches!(policy_type, PolicyType::Invalid) {
            return Err(PolicyError::InvalidNotConstructable);
        }
        let policy = Self {
            paths,
            descriptor: None,
            policy_type,
        };
        policy.sanitize()?;
        Ok(policy)
    }

    /// Construct a `Policy` from an existing Taproot multipath descriptor.
    ///
    /// Walks the descriptor:
    /// 1. **Internal key.** If the Tr internal key is *not* the deterministic NUMS unspendable,
    ///    record it as a `Path { semantic: Single, locktime: None, position: InternalKey }`.
    /// 2. **Tap tree leaves.** Enumerate `(index, depth, miniscript)` for each leaf, group
    ///    by multipath group, and try to classify each group as a [`Semantic`] shape with an
    ///    optional `older()` / `after()` locktime.
    /// 3. **Sort paths** by ascending multipath group.
    /// 4. **Infer `PolicyType`** from the resulting path set.
    /// 5. **Cache** the descriptor.
    ///
    /// Accepts any valid miniscript descriptor; `Policy::compile` enforces stricter
    /// rules. Notably, this does not check cross-path multipath uniqueness: two
    /// paths may share an individual index on the same xpub, which `compile` would
    /// refuse to produce (see `check_multipath_uniqueness`).
    pub fn from_descriptor(desc: &WalletDescriptor) -> Result<Self, PolicyError> {
        let tr = match desc {
            Descriptor::Tr(tr) => tr,
            _ => return Err(PolicyError::NotTaproot),
        };

        let mut paths: Vec<Path> = Vec::new();

        // Skip the internal key when it's the deterministic NUMS unspendable. Two
        // detection paths: the cheap marker check (new-style NUMS carries
        // `NUMS_MARKER_MULTIPATH`), and the legacy chain-code recompute.
        let internal_key = tr.internal_key();
        let is_unspendable = is_new_style_nums(internal_key)
            || unspendable_internal_key(tr).as_ref() == Some(internal_key);
        if !is_unspendable {
            let semantic = if let Some(o) = oxpub(internal_key) {
                Semantic::Single(o)
            } else {
                Semantic::Unknown {
                    policy: SemanticPolicy::Key(internal_key.clone()),
                }
            };
            let mut p = Path::new(semantic, Locktime::None, TapPosition::InternalKey);
            p.set_satisfaction_wu(Some(TR_KEY_PATH_WU));
            paths.push(p);
        }

        if let Some(tap_tree) = tr.tap_tree() {
            let leaves = extract_leaves(tap_tree).map_err(PolicyError::from)?;
            paths.extend(group_taptree_leaves(leaves)?);
        }

        paths.sort_by_key(|p| match p.position() {
            TapPosition::InternalKey => 0usize,
            TapPosition::TapTree(leaves) => leaves.first().map(|l| l.0 + 1).unwrap_or(usize::MAX),
        });

        let policy_type = infer_policy_type(&paths);

        // Compute satisfaction_wu via rust-miniscript's satisfaction module now that each
        // leaf's depth and concrete miniscript are known.
        if let Some(tap_tree) = tr.tap_tree() {
            let by_leaf: BTreeMap<
                usize,
                (u8, &miniscript::Miniscript<WalletKey, miniscript::Tap>),
            > = tap_tree.iter().enumerate().collect();
            for path in paths.iter_mut() {
                if let TapPosition::TapTree(leaves) = path.position() {
                    let refined = leaves
                        .first()
                        .and_then(|l| by_leaf.get(&l.0))
                        .and_then(|(depth, ms)| compute_satisfaction_wu(ms, *depth));
                    path.set_satisfaction_wu(refined);
                }
            }
        }

        Ok(Self {
            paths,
            descriptor: Some(desc.clone()),
            policy_type,
        })
    }

    /// Compile the policy into a Taproot multipath descriptor, rewriting every key's multipath
    /// to follow the path-role scheme.
    ///
    /// The compiler runs in three steps:
    /// 1. **Resolve global order.** Caller-set `Path::order` values define explicit tap-tree
    ///    positions (errors on duplicates or out-of-range); remaining `None`s are filled by
    ///    sorting on ascending locktime height.
    /// 2. **Assign `start_index` per path.** Walk paths in the resolved global order; each
    ///    path's role zone (`Semantic::starting_index(locktime)`) supplies the base, a per-zone
    ///    cursor walks `+2` per leaf inside a path and `+4` between paths.
    /// 3. **Emit.** For each path in global order: emit one fragment per `Single`/`Multi`
    ///    path or one fragment per `k`-of-`n` cosigner subset for `MultiMandatory`, AND
    ///    each fragment with the locktime, ask miniscript to compile each fragment **as a
    ///    single tap leaf** (we don't ask miniscript to build the tap tree or pick an internal
    ///    key), then assemble the tap tree manually via `assemble_tap_tree`. The internal key
    ///    is the `TapPosition::InternalKey` path's key if there is one, else the deterministic
    ///    BIP-341 NUMS unspendable from `compute_nums_internal_key`.
    ///
    /// Each call recompiles from scratch, populating `start_index`, `indices`, and `miniscript`
    /// on each path.
    pub fn compile(&mut self) -> Result<&WalletDescriptor, PolicyError> {
        self.descriptor = None;
        let promoted = self.auto_promote_internal_key_maybe();
        if let Err(e) = self.sanitize() {
            // Revert the promotion so a failed `compile()` leaves `self.paths` untouched.
            if let Some((idx, old)) = promoted {
                self.paths[idx].set_position(old);
            }
            return Err(e);
        }

        self.resolve_global_order();
        assign_start_indices(&mut self.paths)?;
        check_multipath_uniqueness(&self.paths)?;

        let (internal_key, tap_tree) = crate::tree_builder::build(&self.paths)?;

        let tr = Tr::new(internal_key, tap_tree).map_err(PolicyError::Miniscript)?;
        self.descriptor = Some(Descriptor::Tr(tr));
        Ok(self.descriptor.as_ref().unwrap())
    }

    /// Promote an eligible single-key path to the Tr internal key. Runs at the very start
    /// of [`Self::compile`], **before** [`Self::resolve_global_order`] auto-fills any
    /// unset ordering. Only caller-supplied `order` values are visible at this point.
    /// `Policy::sanitize` stays non-mutating.
    ///
    /// **Caller priority:** if any path already sits at `TapPosition::InternalKey`, the
    /// caller has made an explicit choice and this function is a no-op. Auto-promotion
    /// only kicks in when no path is currently on the internal key.
    ///
    /// A candidate is any path satisfying both:
    /// - locktime is `Locktime::None`,
    /// - semantic is [`Semantic::Single`].
    ///
    /// Position isn't in the filter: the caller-priority early return above already
    /// guarantees every remaining path sits at `TapPosition::TapTree(_)`. Paths the
    /// caller intended to live in the tree are still eligible. Promotion lifts them out
    /// of the tap tree onto the internal key.
    ///
    /// Selection: among candidates, pick the one whose caller-set `order` is smallest,
    /// with `order = None` ranked after any `Some(_)` (ties broken by position in
    /// `self.paths` for determinism). For typed policies the `InvalidPrimaryCount` rule
    /// keeps the candidate set tiny; for `PolicyType::Unknown` several candidates can
    /// coexist and the smallest caller order wins.
    ///
    /// If at least one candidate exists, the selected path is rewritten to
    /// `TapPosition::InternalKey`. Otherwise this is a no-op and `compile` falls back to
    /// the deterministic NUMS unspendable internal key.
    fn auto_promote_internal_key_maybe(&mut self) -> Option<(usize, TapPosition)> {
        if self
            .paths
            .iter()
            .any(|p| matches!(p.position(), TapPosition::InternalKey))
        {
            return None;
        }
        let candidate = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                matches!(p.locktime(), Locktime::None)
                    && matches!(p.semantic(), Semantic::Single(_))
            })
            .min_by_key(|(idx, p)| (p.order().unwrap_or(usize::MAX), *idx))
            .map(|(idx, _)| idx);
        let idx = candidate?;
        let old = self.paths[idx].position().clone();
        self.paths[idx].set_position(TapPosition::InternalKey);
        Some((idx, old))
    }

    /// Validate that the policy is compile-ready without producing a descriptor or mutating
    /// any state. This is the single source of truth for compile-readiness: [`Self::compile`]
    /// calls it as its first step and then trusts every invariant established here.
    ///
    /// `Ok(())` means [`Self::compile`] will not fail on validation; it can still fail later
    /// in miniscript compilation for a degenerate satisfaction shape.
    pub fn sanitize(&self) -> Result<(), PolicyError> {
        if self.paths.is_empty() {
            return Err(PolicyError::EmptyPaths);
        }
        validate_paths_for_type(&self.paths, self.policy_type)?;

        let mut internal_key_seen = false;
        for path in &self.paths {
            if path.semantic().starting_index(path.locktime()).is_none() {
                return Err(PolicyError::InconsistentPathsForType(self.policy_type));
            }
            if matches!(path.position(), TapPosition::InternalKey) {
                if !matches!(path.locktime(), Locktime::None) {
                    return Err(PolicyError::InternalKeyWithLocktime);
                }
                if !matches!(path.semantic(), Semantic::Single(_)) {
                    return Err(PolicyError::InternalKeyNotSingle);
                }
                if internal_key_seen {
                    return Err(PolicyError::MultipleInternalKeys);
                }
                internal_key_seen = true;
            }
        }

        Ok(())
    }

    /// Assign every path a concrete `order`, then return the slot-ordered `Vec<usize>`.
    ///
    /// Algorithm:
    /// 1. Collect every caller-set order into `used`. Caller values may repeat: paths
    ///    sharing an `order` form a priority group that the tap-tree builder later
    ///    places together at a single leaf depth.
    /// 2. Sort the unordered paths by ascending locktime height (insertion-index tie-break).
    /// 3. Walk a cursor from 0 upward, skipping values in `used`, and assign each
    ///    unordered path a fresh unique order. Fresh values never collide with
    ///    caller-supplied ones, so unordered paths never join a caller group.
    /// 4. Every path now has `order = Some(_)`; downstream helpers walk paths sorted by
    ///    that field.
    fn resolve_global_order(&mut self) {
        let used: BTreeSet<usize> = self.paths.iter().filter_map(|p| p.order()).collect();

        let mut unordered: Vec<usize> = self
            .paths
            .iter()
            .enumerate()
            .filter_map(|(i, p)| if p.order().is_none() { Some(i) } else { None })
            .collect();
        unordered.sort_by_key(|&i| {
            let h = match self.paths[i].locktime() {
                Locktime::Relative(rl) => rl.to_consensus_u32(),
                Locktime::Absolute(a) | Locktime::AbsoluteRenewable(a) => a.to_consensus_u32(),
                Locktime::None => 0,
            };
            (h, i)
        });

        let mut next_free = 0;
        for path_idx in unordered {
            while used.contains(&next_free) {
                next_free += 1;
            }
            self.paths[path_idx].set_order(Some(next_free));
            next_free += 1;
        }
    }

    pub fn paths(&self) -> &[Path] {
        &self.paths
    }

    pub fn descriptor(&self) -> Option<&WalletDescriptor> {
        self.descriptor.as_ref()
    }

    pub fn policy_type(&self) -> PolicyType {
        self.policy_type
    }

    /// Tap leaves the compiled descriptor holds, padding excluded.
    pub fn leaf_count(&self) -> usize {
        todo!()
    }

    /// Every signer key with the role its origin carries (None when it has none).
    pub fn key_types(&self) -> BTreeMap<OXpub, Option<KeyType>> {
        todo!()
    }
}

/// Collect every `(xpub, multipath-index)` pair claimed by `path`. Distinct paths must not
/// share any pair; within a single path the same pair can legitimately repeat (e.g.
/// `Multi` puts every cosigner on the same group, `MultiMandatory` repeats the
/// mandatory key across leaves under different groups). See [`check_multipath_uniqueness`].
fn collect_path_xpub_indices(
    path: &Path,
) -> Result<BTreeSet<(miniscript::bitcoin::bip32::Xpub, u32)>, PolicyError> {
    let mut out: BTreeSet<(miniscript::bitcoin::bip32::Xpub, u32)> = BTreeSet::new();
    match path.position() {
        TapPosition::InternalKey => {
            if let Semantic::Single(oxpub) = path.semantic() {
                let g = path.indices().first().copied().unwrap_or(0);
                out.insert((oxpub.xkey, g));
                out.insert((oxpub.xkey, g + 1));
            }
        }
        TapPosition::TapTree(_) => {
            for leaf in path.leaves() {
                for key in leaf.iter_pk() {
                    if let Some((xpub, idxs)) = crate::multipath::key_indices(&key)? {
                        // Within a single MultiXPub key the two legs must derive distinct
                        // children: `<3;3>` collapses to one derivation and is
                        // structurally degenerate. Catch it here using the same
                        // `DuplicateMultipathIndex` variant as cross-path collisions.
                        let mut per_key: BTreeSet<u32> = BTreeSet::new();
                        for i in idxs {
                            if !per_key.insert(i) {
                                return Err(PolicyError::DuplicateMultipathIndex {
                                    xpub,
                                    index: i,
                                });
                            }
                            out.insert((xpub, i));
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Reject any two distinct paths that claim the same `(xpub, multipath-index)` pair.
/// Catches `Custom`-vs-`Custom`, `Custom`-vs-typed, and `XPub`/`MultiXPub` overlap at the
/// individual-index level (so `<3;4>` and `<4;5>` collide on index `4`). Runs in
/// `Policy::compile` after `assign_start_indices` has populated every path's leaves.
fn check_multipath_uniqueness(paths: &[Path]) -> Result<(), PolicyError> {
    let mut owner: BTreeMap<(miniscript::bitcoin::bip32::Xpub, u32), usize> = BTreeMap::new();
    for (path_idx, path) in paths.iter().enumerate() {
        let claimed = collect_path_xpub_indices(path)?;
        for (xpub, idx) in claimed {
            if let Some(prev) = owner.insert((xpub, idx), path_idx) {
                if prev != path_idx {
                    return Err(PolicyError::DuplicateMultipathIndex { xpub, index: idx });
                }
            }
        }
    }
    Ok(())
}

fn validate_paths_for_type(paths: &[Path], policy_type: PolicyType) -> Result<(), PolicyError> {
    match policy_type {
        PolicyType::Csv => validate_csv_paths(paths),
        PolicyType::Cltv => validate_cltv_paths(paths),
        PolicyType::CsvWithMandatoryKey => validate_csv_with_mandatory_paths(paths),
        PolicyType::CsvWithNestedMandatory => validate_csv_with_nested_mandatory_paths(paths),
        PolicyType::Unknown => validate_unknown_paths(paths),
        PolicyType::Invalid => Err(PolicyError::InvalidNotConstructable),
    }
}

/// Unknown: skip the policy-level invariants (primary count, recovery presence, mixing, etc.):
/// `Unknown` is the escape hatch for descriptors / path sets that the typed classifier
/// can't fit, so those invariants don't apply. Every path must still be **structurally**
/// valid (`Semantic::validate` + `Locktime::validate`). `Semantic::Unknown` is parser-only
/// and rejected here; consumers use `Semantic::Custom` for arbitrary tap-leaf scripts.
fn validate_unknown_paths(paths: &[Path]) -> Result<(), PolicyError> {
    for p in paths {
        if matches!(p.semantic(), Semantic::Unknown { .. }) {
            return Err(PolicyError::UnknownNotConstructable);
        }
        // `Custom` carries its own locktime (encoded inside the miniscript). A Path-level
        // locktime would not be wrapped around the consumer's miniscript, so reject it
        // up-front rather than silently dropping the gate.
        if matches!(p.semantic(), Semantic::Custom(_)) && !matches!(p.locktime(), Locktime::None) {
            return Err(PolicyError::CustomWithLocktime);
        }
        p.semantic().validate()?;
        p.locktime().validate()?;
    }
    Ok(())
}

/// Per-flavor dedup sets returned by [`check_common_invariants`]. Each set holds the heights
/// the validator already saw for that locktime flavor, so per-type validators can decide
/// which flavors are admissible without re-walking `self.paths`.
struct CommonInvariants {
    relative: BTreeSet<u32>,
    absolute_renewable: BTreeSet<u32>,
    absolute_foreign: BTreeSet<u32>,
}

/// Invariants every policy type must satisfy:
/// - exactly one non-timelocked (primary) path,
/// - at least one timelocked recovery,
/// - no two recoveries share a timelock height **within the same flavor** (relative,
///   aligned absolute, foreign absolute),
/// - no mixing of more than one locktime flavor in the same policy,
/// - no `Or` / `Unknown` semantics (uncompilable shapes regardless of policy type).
///
/// Returns the per-flavor sets of seen heights so per-type validators can assert which
/// flavors are admissible (e.g. Csv only allows `relative`).
fn check_common_invariants(
    paths: &[Path],
    policy_type: PolicyType,
) -> Result<CommonInvariants, PolicyError> {
    let mut primary_count: usize = 0;
    let mut relative: BTreeSet<u32> = BTreeSet::new();
    let mut absolute_renewable: BTreeSet<u32> = BTreeSet::new();
    let mut absolute: BTreeSet<u32> = BTreeSet::new();
    for p in paths {
        p.semantic().validate()?;
        p.locktime().validate()?;
        match p.semantic() {
            Semantic::Unknown { .. } | Semantic::Or(_) | Semantic::Custom(_) => {
                return Err(PolicyError::InconsistentPathsForType(policy_type));
            }
            _ => {}
        }
        match p.locktime() {
            Locktime::None => {
                primary_count += 1;
            }
            Locktime::Relative(rl) => {
                let h = rl.to_consensus_u32();
                if !relative.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
            Locktime::AbsoluteRenewable(lt) => {
                let h = lt.to_consensus_u32();
                if !absolute_renewable.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
            Locktime::Absolute(lt) => {
                let h = lt.to_consensus_u32();
                if !absolute.insert(h) {
                    return Err(PolicyError::DuplicateTimelock(h));
                }
            }
        }
    }
    if primary_count != 1 {
        return Err(PolicyError::InvalidPrimaryCount(primary_count));
    }
    let flavors_present = [&relative, &absolute_renewable, &absolute]
        .iter()
        .filter(|s| !s.is_empty())
        .count();
    if flavors_present == 0 {
        return Err(PolicyError::MissingRecoveryPath);
    }
    if flavors_present > 1 {
        return Err(PolicyError::MixedTimelockKinds);
    }
    Ok(CommonInvariants {
        relative,
        absolute_renewable,
        absolute_foreign: absolute,
    })
}

/// Csv: only relative-locktime recoveries; no `MultiMandatory` /
/// `MultiMandatoryNested` semantic.
fn validate_csv_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::Csv)?;
    if !inv.absolute_renewable.is_empty() || !inv.absolute_foreign.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(PolicyType::Csv));
    }
    for p in paths {
        if matches!(
            p.semantic(),
            Semantic::MultiMandatory { .. } | Semantic::MultiMandatoryNested { .. }
        ) {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Csv));
        }
    }
    Ok(())
}

/// Cltv: only absolute-locktime recoveries (renewable **or** foreign, but not both, since
/// the common invariants forbid mixing flavors). No `MultiMandatory` /
/// `MultiMandatoryNested` semantic. Renewable heights must be aligned to
/// [`CLTV_ALIGNMENT`]; foreign (`Absolute`) heights are accepted without alignment but
/// rejected if they encode a timestamp (`>= LOCK_TIME_THRESHOLD`).
fn validate_cltv_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::Cltv)?;
    if !inv.relative.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(PolicyType::Cltv));
    }
    for p in paths {
        if matches!(
            p.semantic(),
            Semantic::MultiMandatory { .. } | Semantic::MultiMandatoryNested { .. }
        ) {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Cltv));
        }
    }
    Ok(())
}

/// CsvWithMandatoryKey: only relative-locktime recoveries, with at least one
/// [`Semantic::MultiMandatory`] path. Rejects [`Semantic::MultiMandatoryNested`]
/// (which belongs to [`PolicyType::CsvWithNestedMandatory`]). Mandatory-key thresholds
/// must satisfy `mandatory_count + 1 <= threshold <= mandatory_count + cosigner_count`.
fn validate_csv_with_mandatory_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::CsvWithMandatoryKey)?;
    if !inv.absolute_renewable.is_empty() || !inv.absolute_foreign.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithMandatoryKey,
        ));
    }
    let has_mandatory = paths
        .iter()
        .any(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }));
    if !has_mandatory {
        return Err(PolicyError::NoMandatoryKeyPath);
    }
    if paths
        .iter()
        .any(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
    {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithMandatoryKey,
        ));
    }
    Ok(())
}

/// CsvWithNestedMandatory: only relative-locktime recoveries, with at least one
/// [`Semantic::MultiMandatoryNested`] path. Rejects [`Semantic::MultiMandatory`] (which
/// belongs to [`PolicyType::CsvWithMandatoryKey`]). Nested thresholds must satisfy the
/// canonical-form invariants enforced by [`Semantic::validate`].
fn validate_csv_with_nested_mandatory_paths(paths: &[Path]) -> Result<(), PolicyError> {
    let inv = check_common_invariants(paths, PolicyType::CsvWithNestedMandatory)?;
    if !inv.absolute_renewable.is_empty() || !inv.absolute_foreign.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithNestedMandatory,
        ));
    }
    let has_nested = paths
        .iter()
        .any(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }));
    if !has_nested {
        return Err(PolicyError::NoNestedMandatoryKeyPath);
    }
    if paths
        .iter()
        .any(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
    {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithNestedMandatory,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::{Leaf, OXpub, Path, Semantic, TapPosition};
    use miniscript::{
        bitcoin::{absolute, relative},
        policy::Liftable,
        DescriptorPublicKey, Miniscript, Tap,
    };
    use std::str::FromStr;

    fn oxpub_from_str(s: &str) -> OXpub {
        let k = DescriptorPublicKey::from_str(s).unwrap();
        let DescriptorPublicKey::MultiXPub(x) = k else {
            panic!("expected MultiXPub")
        };
        OXpub::new(x.origin, x.xkey)
    }

    fn k1() -> OXpub {
        oxpub_from_str(
            "[abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*",
        )
    }

    fn k2() -> OXpub {
        oxpub_from_str(
            "[abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<0;1>/*",
        )
    }

    #[test]
    fn semantic_starting_index_by_role() {
        // Primary: no locktime + Single/Multi.
        let primary = Semantic::Single(k1());
        assert_eq!(primary.starting_index(&Locktime::None), Some(512));

        // Csv recovery: relative locktime + Single/Multi.
        let csv = Semantic::Single(k1());
        let rel = Locktime::Relative(relative::LockTime::from_height(144));
        assert_eq!(csv.starting_index(&rel), Some(1024));

        // Csv with mandatory key: relative locktime + MultiMandatory.
        let mk = Semantic::MultiMandatory {
            keys: vec![k1(), k2()],
            mandatory_keys: vec![k2()],
            threshold: 2,
        };
        assert_eq!(mk.starting_index(&rel), Some(1536));

        // Cltv recovery: absolute locktime + Single/Multi.
        let cltv = Semantic::Single(k1());
        let abs = Locktime::AbsoluteRenewable(absolute::LockTime::from_height(824320).unwrap());
        assert_eq!(cltv.starting_index(&abs), Some(2048));

        // Off-table combinations return None.
        assert_eq!(mk.starting_index(&Locktime::None), None);
    }

    #[test]
    fn policy_new_rejects_empty() {
        assert!(matches!(
            Policy::new(vec![], PolicyType::Csv),
            Err(PolicyError::EmptyPaths)
        ));
    }

    #[test]
    fn policy_new_rejects_invalid_type() {
        let p = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        assert!(matches!(
            Policy::new(vec![p], PolicyType::Invalid),
            Err(PolicyError::InvalidNotConstructable)
        ));
    }

    #[test]
    fn cltv_rejects_unaligned_renewable() {
        // AbsoluteRenewable claims alignment - 824321 isn't on the 1024 grid → reject.
        let height = 824321;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        assert!(matches!(
            Policy::new(vec![primary, recov], PolicyType::Cltv),
            Err(PolicyError::UnalignedCltv(h)) if h == height
        ));
    }

    #[test]
    fn cltv_accepts_unaligned_foreign() {
        // The same unaligned height wrapped as Locktime::Absolute (foreign) is accepted.
        let height = 824321;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Absolute(lt),
            TapPosition::TapTree(vec![]),
        );
        let p = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        assert_eq!(p.policy_type(), PolicyType::Cltv);
    }

    #[test]
    fn cltv_accepts_aligned_height() {
        let height = 824320; // 805 * 1024
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let p = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        assert_eq!(p.policy_type(), PolicyType::Cltv);
        assert!(p.descriptor().is_none());
    }

    #[test]
    fn csv_rejects_absolute_locktime() {
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let bad = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        assert!(matches!(
            Policy::new(vec![primary, bad], PolicyType::Csv),
            Err(PolicyError::InconsistentPathsForType(PolicyType::Csv))
        ));
    }

    #[test]
    fn cltv_compile_then_parse_round_trip() {
        // Compile a Cltv policy with an aligned height; parser sees AbsoluteRenewable back.
        // Strict round-trip: key set + threshold + locktime on both primary and recovery.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary_xkey = k1().xkey;
        let recov_xkey = k2().xkey;
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .expect("primary path missing");
        match parsed_primary.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, primary_xkey),
            other => panic!("expected Single primary, got {other:?}"),
        }
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::AbsoluteRenewable(_)))
            .expect("AbsoluteRenewable recovery missing");
        match parsed_recov.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, recov_xkey),
            other => panic!("expected Single recovery, got {other:?}"),
        }
        assert_eq!(parsed_recov.locktime(), &Locktime::AbsoluteRenewable(lt));
    }

    #[test]
    fn cltv_compile_emits_after() {
        // Build a Cltv policy: one primary key on the internal key, one recovery key behind an
        // absolute timelock in the tap tree. Compile and assert that:
        //   - the resulting descriptor is Tr,
        //   - it contains `after(<aligned_height>)`,
        //   - the primary key sits in the primary role zone (<512;513>),
        //   - the recovery branch's keys live in the Cltv role zone (<2048;2049>).
        let height = 824320; // aligned to 1024
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains(&format!("after({height})")), "got {s}");
        assert!(s.contains("<512;513>"), "got {s}");
        assert!(s.contains("<2048;2049>"), "got {s}");
    }

    #[test]
    fn csv_with_mandatory_round_trip() {
        // 1 mandatory + 2 cosigners, choosing 1 per leaf, total threshold 2. That gives
        // 2 leaves at <1536;1537> and <1538;1539> in the CsvWithMandatory role zone, which
        // is a power of 2 so both land at the same depth in the balanced binary tree.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );

        let lt = Locktime::Relative(relative::LockTime::from_height(144));
        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            lt,
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();

        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let mk_path = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .expect("expected a MultiMandatory path after recombine");
        if let Semantic::MultiMandatory {
            keys,
            mandatory_keys,
            threshold,
        } = mk_path.semantic()
        {
            assert_eq!(*threshold, 2);
            assert_eq!(mandatory_keys.len(), 1);
            assert_eq!(keys.len(), 2);
            assert_eq!(mandatory_keys[0].xkey, mandatory.xkey);
        } else {
            unreachable!("matched above");
        }
    }

    #[test]
    fn mandatory_threshold_must_exceed_mandatory_count() {
        // 1 mandatory + 2 cosigners but threshold=1 ≤ mandatory_count → reject.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let bad = Path::new(
            Semantic::MultiMandatory {
                keys: vec![
                    k2(),
                    oxpub_from_str(
                        "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
                    ),
                ],
                mandatory_keys: vec![k1()],
                threshold: 1,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, bad], PolicyType::CsvWithMandatoryKey).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InvalidMandatoryThreshold {
                threshold: 1,
                mandatory_count: 1,
                cosigner_count: 2
            }
        ));
    }

    #[test]
    fn satisfaction_wu_populated_after_compile_and_parse() {
        // After compile+parse, every TapTree path's satisfaction_wu must be Some(_) and > 0.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        for p in parsed.paths() {
            if matches!(p.position(), TapPosition::TapTree(_)) {
                let w = p.satisfaction_wu().expect("expected wu for TapTree path");
                assert!(w > 0, "non-positive wu for TapTree path");
            }
        }
    }

    #[test]
    fn csv_with_mandatory_compile_emits_leaves() {
        // Build a CsvWithMandatoryKey policy with 1 mandatory + 2 cosigners and a *total*
        // threshold of 2 (1 mandatory + 1 cosigner per leaf). Picking 1 of 2 cosigners gives
        // 2 leaves; the path lives in the CsvWithMandatory role zone, so they get
        // multipath groups <1536;1537> and <1538;1539>.
        let mandatory = k1();
        let cosigner_a = k2();
        let cosigner_b = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );
        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![cosigner_a, cosigner_b],
                mandatory_keys: vec![mandatory],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("<1536;1537>"), "missing <1536;1537> in {s}");
        assert!(s.contains("<1538;1539>"), "missing <1538;1539> in {s}");
    }

    #[test]
    fn non_pow2_mandatory_leaves_round_trip_at_same_depth() {
        // 1 mandatory + 3 cosigners, threshold 2 (1 mandatory + 1 cosigner per leaf).
        // Picking 1 of 3 cosigners gives 3 leaves, which is not a power of 2. The
        // floor-based builder must place all 3 leaves at the same depth (size-4 floor
        // with one NUMS padding leaf), and the parser must filter the padding leaf and
        // recognise the MultiMandatory shape on round-trip.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );
        let c3 = oxpub_from_str(
            "[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*",
        );

        let primary = Path::new(
            Semantic::Single(mandatory.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1, c2, c3],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );

        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();

        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let leaves: Vec<_> = tap_tree.iter().collect();
        assert_eq!(leaves.len(), 4, "size-4 floor: 3 real + 1 padding leaf");
        let real_depths: Vec<u8> = leaves
            .iter()
            .filter(|(_, ms)| !is_nums_padding_leaf(ms))
            .map(|(d, _)| *d)
            .collect();
        assert_eq!(real_depths.len(), 3);
        assert!(
            real_depths.iter().all(|&d| d == real_depths[0]),
            "all 3 real leaves must be at the same depth, got {real_depths:?}"
        );

        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let mk_parsed = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .expect("MultiMandatory path recovered after round-trip");
        if let Semantic::MultiMandatory {
            keys,
            mandatory_keys,
            threshold,
        } = mk_parsed.semantic()
        {
            assert_eq!(*threshold, 2);
            assert_eq!(mandatory_keys.len(), 1);
            assert_eq!(keys.len(), 3);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn internal_key_carries_seed_when_no_real_promotion() {
        // Multi primary + single timelocked recovery: no Single+Locktime::None candidate,
        // so no auto-promotion. Internal key falls back to NUMS, whose chain code must
        // equal what `analysis::unspendable_internal_xpub` recomputes.
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![k1(), k2()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let internal = tr.internal_key();
        let DescriptorPublicKey::MultiXPub(m) = plain_key(internal).unwrap() else {
            panic!("internal key is not a MultiXPub")
        };
        assert_eq!(m.xkey.public_key, crate::nums::bip341_nums());
        let legacy = crate::nums::unspendable_internal_key(tr).expect("legacy key");
        let DescriptorPublicKey::MultiXPub(legacy_m) = plain_key(&legacy).unwrap() else {
            panic!("legacy key is not a MultiXPub")
        };
        assert_eq!(
            m.xkey.chain_code, legacy_m.xkey.chain_code,
            "new-style internal key chain code must match legacy unspendable_internal_xpub"
        );
    }

    #[test]
    fn first_padding_leaf_reuses_seed_when_internal_key_is_real() {
        // Primary single-key path + 3-leaf MultiMandatory recovery. The primary auto-
        // promotes to the internal key (real), so the first padding leaf takes the seed
        // chain code (= what the legacy detector would compute for a NUMS internal key).
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );
        let c3 = oxpub_from_str(
            "[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*",
        );

        let primary = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1, c2, c3],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let legacy = crate::nums::unspendable_internal_key(tr).expect("legacy key");
        let DescriptorPublicKey::MultiXPub(legacy_m) = plain_key(&legacy).unwrap() else {
            panic!("legacy key is not a MultiXPub")
        };
        let seed = legacy_m.xkey.chain_code;

        let padding_leaves: Vec<_> = tr
            .tap_tree()
            .as_ref()
            .expect("tap tree present")
            .iter()
            .filter(|(_, ms)| is_nums_padding_leaf(ms))
            .collect();
        assert!(
            !padding_leaves.is_empty(),
            "expected at least one padding leaf"
        );
        let first_padding = padding_leaves[0].1;
        let key = first_padding
            .iter_pk()
            .next()
            .expect("padding leaf has a key");
        let DescriptorPublicKey::MultiXPub(m) = plain_key(&key).unwrap() else {
            panic!("padding key is not MultiXPub")
        };
        assert_eq!(
            m.xkey.chain_code, seed,
            "first padding leaf chain code must equal the seed when internal key is real"
        );
    }

    #[test]
    fn padding_leaves_chain_via_sha256() {
        use miniscript::bitcoin::{bip32, hashes::sha256, hashes::Hash};
        // 1 mandatory + 5 cosigners, threshold 2 → C(5, 1) = 5 leaves. With auto-promoted
        // primary (single-key), the recovery subtree is size 8 with `m = 3` so the
        // canonical compaction exposes 2 free chunks (size 1 at depth 3, size 2 at
        // depth 2) → 2 padding leaves at distinct depths.
        let mandatory = k1();
        let c1 = k2();
        let c2 = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );
        let c3 = oxpub_from_str(
            "[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*",
        );
        let c4 = oxpub_from_str(
            "[abcdef05]xpub661MyMwAqRbcEqgeH5cqyxRwY4UG21ey1MBJkNBX2xSTmGS9dCRmGQezqHE9mXUXzs9HqFzNEN2KkNw5o8xpqAXw2XxsVhGVm1LbRaEnxyT/<0;1>/*",
        );
        let c5 = oxpub_from_str(
            "[abcdef06]xpub661MyMwAqRbcEtYavp2XsS9QfH93wyVQnkWenWxWuWdaxDtjBqfzFfWPY83z3da5oYv2XmwgTT97GhGwX9HUGDEP4FERzzgmwaGNAz1emZr/<0;1>/*",
        );

        let primary = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1, c2, c3, c4, c5],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };

        let padding_chain_codes: Vec<bip32::ChainCode> = tr
            .tap_tree()
            .as_ref()
            .expect("tap tree present")
            .iter()
            .filter_map(|(_, ms)| {
                if !is_nums_padding_leaf(ms) {
                    return None;
                }
                let key = ms.iter_pk().next()?;
                let DescriptorPublicKey::MultiXPub(m) = plain_key(&key)? else {
                    return None;
                };
                Some(m.xkey.chain_code)
            })
            .collect();
        assert!(
            padding_chain_codes.len() >= 2,
            "expected at least 2 padding leaves to exercise chaining, got {}",
            padding_chain_codes.len()
        );
        for w in padding_chain_codes.windows(2) {
            let prev_bytes = w[0].to_bytes();
            let expected: [u8; 32] = sha256::Hash::hash(prev_bytes.as_ref()).to_byte_array();
            assert_eq!(
                w[1].to_bytes(),
                expected,
                "consecutive padding leaves must chain via sha256"
            );
        }
    }

    #[test]
    fn legacy_csv_layout_parses_as_csv() {
        // Hand-rolled Csv-shape Tr descriptor using the legacy `<0;1>` (primary) / `<2;3>`
        // (recovery) adjacent-multipath layout. The compiler now emits the new 512+ layout,
        // but on-chain wallets created with the legacy layout must keep parsing as Csv.
        let s = "tr([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*,and_v(v:pk([abcdef02]xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe/<2;3>/*),older(144)))";
        let desc = WalletDescriptor::from_str(s).unwrap();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
    }

    #[test]
    fn csv_compile_emits_role_based_layout() {
        // Smoke test: Csv with primary on the internal key + a single relative-locked recovery
        // leaf must place primary at <512;513> (Primary role) and recovery at <1024;1025>
        // (Csv recovery role).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("<512;513>"), "missing <512;513> in {s}");
        assert!(s.contains("<1024;1025>"), "missing <1024;1025> in {s}");
    }

    #[test]
    fn csv_with_mandatory_requires_mandatory_path() {
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov_seq = relative::LockTime::from_height(144);
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(recov_seq),
            TapPosition::TapTree(vec![]),
        );
        // No MultiMandatory anywhere - should reject.
        assert!(matches!(
            Policy::new(vec![primary, recov], PolicyType::CsvWithMandatoryKey),
            Err(PolicyError::NoMandatoryKeyPath)
        ));
    }

    #[test]
    fn start_index_populated_after_compile() {
        // After compile, both paths must carry their assigned multipath base via start_index.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1024));
    }

    #[test]
    fn csv_recoveries_sorted_by_relative_height() {
        // Two recovery paths inserted with the larger height first; both `order = None`. The
        // pre-emit pass must sort them by ascending locktime height, so `older(144)` lands at
        // the lower slot in the Csv zone.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let big = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        let small = Path::new(
            Semantic::Single(oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            )),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, big, small], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        // primary at 512; small (older(144)) at 1024; big (older(1000)) at 1028.
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1028));
        assert_eq!(policy.paths()[2].start_index(), Some(1024));
    }

    #[test]
    fn caller_order_overrides_timelock_sort() {
        // Same two recoveries as above, but the caller forces `older(1000)` to come before
        // `older(144)` in the global tap-tree order. The Csv-zone walk visits the
        // `older(1000)` path first → start_index = 1024; then `older(144)` → 1028.
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        primary.set_order(Some(0));
        let mut big = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        big.set_order(Some(1));
        let small = Path::new(
            Semantic::Single(oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            )),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, big, small], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        assert_eq!(policy.paths()[1].start_index(), Some(1024));
        assert_eq!(policy.paths()[2].start_index(), Some(1028));
    }

    #[test]
    fn path_order_reorders_tap_tree() {
        // Build a Cltv policy with both paths in the tap tree (no InternalKey path), then
        // pin recovery to global slot 0 and primary to slot 1. The first leaf in the tap
        // tree must then be the recovery leaf, i.e. `after(...)` shows up before the
        // primary's `pk` in the tap-tree iteration.
        let height = 824320;
        let lt = absolute::LockTime::from_height(height).unwrap();
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        primary.set_order(Some(1));
        let mut recov = Path::new(
            Semantic::Single(k2()),
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        recov.set_order(Some(0));
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let (_, first_leaf) = tap_tree.iter().next().expect("at least one leaf");
        let s = first_leaf.to_string();
        assert!(
            s.contains(&format!("after({height})")),
            "{}",
            format!("first leaf should be the recovery (`after`) path; got `{s}`"),
        );
    }

    #[test]
    fn duplicate_order_groups_leaves_at_one_depth() {
        // Two recoveries declare `order = Some(1)` and form a single priority group.
        // `tree_builder::build` concatenates their leaves into one `place_path` call,
        // so both land at the same tap-leaf depth.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mut recov_a = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        recov_a.set_order(Some(1));
        let mut recov_b = Path::new(
            Semantic::Single(oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            )),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        recov_b.set_order(Some(1));
        let mut policy = Policy::new(vec![primary, recov_a, recov_b], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let tr = match &desc {
            miniscript::Descriptor::Tr(tr) => tr,
            _ => panic!("expected Tr"),
        };
        let tap_tree = tr.tap_tree().as_ref().expect("tap tree present");
        let recov_depths: Vec<u8> = tap_tree
            .iter()
            .filter_map(|(d, ms)| ms.to_string().contains("older(").then_some(d))
            .collect();
        assert_eq!(recov_depths.len(), 2, "expected both recovery leaves");
        assert_eq!(
            recov_depths[0], recov_depths[1],
            "same-order recoveries must share tap-leaf depth"
        );
    }

    #[test]
    fn order_treats_caller_values_as_relative_ranking() {
        // Caller orders are gaps + values larger than path count: 7 and 100. Both should
        // be accepted; relative ranking puts the path with order=7 before the one with
        // order=100, and any unset paths after both. After compile the resolved positions
        // collapse into the dense slot range 0..N.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mut later = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(1000)),
            TapPosition::TapTree(vec![]),
        );
        later.set_order(Some(100));
        let mut earlier = Path::new(
            Semantic::Single(oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            )),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        earlier.set_order(Some(7));
        let mut policy = Policy::new(vec![primary, later, earlier], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        // primary auto-promotes to InternalKey at start_index 512.
        assert_eq!(policy.paths()[0].start_index(), Some(512));
        // earlier (order=7) gets the lower Csv slot, later (order=100) gets the next.
        assert_eq!(policy.paths()[2].start_index(), Some(1024));
        assert_eq!(policy.paths()[1].start_index(), Some(1028));
    }

    #[test]
    fn sanitize_passes_for_valid_policy() {
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        assert!(policy.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_two_primaries() {
        // Two Locktime::None paths → InvalidPrimaryCount(2). `Policy::new` runs sanitize so
        // the rejection lands at construction.
        let p1 = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let p2 = Path::new(
            Semantic::Single(k2()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![p1, p2, recov], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPrimaryCount(2)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_internal_key_with_locktime() {
        // InternalKey path with a non-None locktime is structurally invalid. With a proper
        // primary in the tap tree the primary-count rule passes, and sanitize's per-path
        // InternalKey-position check is the gate that fires.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let bad = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, bad, recov], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InternalKeyWithLocktime),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_no_primary() {
        // Zero Locktime::None paths → InvalidPrimaryCount(0).
        let r1 = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let r2 = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![r1, r2], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidPrimaryCount(0)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn sanitize_rejects_duplicate_csv_timelock() {
        // Two recovery paths sharing the same `older(144)` height → DuplicateTimelock(144).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let r1 = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let r2 = Path::new(
            Semantic::Single(oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            )),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, r1, r2], PolicyType::Csv).unwrap_err();
        assert!(
            matches!(err, PolicyError::DuplicateTimelock(144)),
            "{}",
            format!("got {err:?}"),
        );
    }

    #[test]
    fn compile_auto_promotes_single_primary_to_internal_key() {
        // Caller forgot to put the Single primary on `TapPosition::InternalKey`. After
        // compile, that path should land at the Tr internal key and the descriptor's
        // internal key should be the caller's xpub (not a NUMS unspendable).
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        // The promoted path's position is now InternalKey.
        assert!(matches!(
            policy.paths()[0].position(),
            TapPosition::InternalKey
        ));
        // And the rendered descriptor's internal key carries the primary's xpub fingerprint.
        let s = desc.to_string();
        assert!(
            s.contains("[abcdef01]"),
            "{}",
            format!("primary xpub should appear at the Tr internal key; got `{s}`"),
        );
    }

    #[test]
    fn compile_promotes_first_ordered_single_primary() {
        // Caller pinned `order = Some(0)` on the Single primary. It's still a candidate
        // for promotion (caller-set order doesn't opt out anymore, the promotion picks
        // by lowest order to align with the caller's tap-tree intent).
        let mut primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        primary.set_order(Some(0));
        let recov = Path::new(
            Semantic::Single(k2()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let _ = policy.compile().unwrap();
        assert!(matches!(
            policy.paths()[0].position(),
            TapPosition::InternalKey
        ));
    }

    fn unknown_policy_from(ms: &str) -> SemanticPolicy<WalletKey> {
        Miniscript::<WalletKey, Tap>::from_str(ms)
            .unwrap()
            .lift()
            .unwrap()
            .normalized()
    }

    fn custom_miniscript(ms: &str) -> Miniscript<WalletKey, Tap> {
        Miniscript::<WalletKey, Tap>::from_str(ms).unwrap()
    }

    #[test]
    fn policy_new_rejects_unknown_semantic() {
        // Semantic::Unknown is parser-only: Policy::new rejects it. Consumers must use
        // Semantic::Custom to embed an arbitrary tap-leaf miniscript.
        let pol = unknown_policy_from(
            "and_v(v:pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),sha256(deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef))",
        );
        let unknown_path = Path::new(
            Semantic::Unknown { policy: pol },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![unknown_path], PolicyType::Unknown).unwrap_err();
        assert!(
            matches!(err, PolicyError::UnknownNotConstructable),
            "got {err:?}"
        );
    }

    #[test]
    fn policy_new_accepts_custom_semantic() {
        // A hash-gated leaf doesn't fit any typed shape. Custom embeds the miniscript
        // directly; PolicyType::Unknown allows it through.
        let ms = custom_miniscript(
            "and_v(v:pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*),sha256(deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef))",
        );
        let custom_path = Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        assert!(Policy::new(vec![custom_path], PolicyType::Unknown).is_ok());
    }

    #[test]
    fn policy_new_rejects_custom_with_locktime() {
        let ms = custom_miniscript(
            "pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*)",
        );
        let bad = Path::new(
            Semantic::Custom(ms),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![bad], PolicyType::Unknown).unwrap_err();
        assert!(
            matches!(err, PolicyError::CustomWithLocktime),
            "got {err:?}"
        );
    }

    #[test]
    fn compile_custom_path_emits_descriptor_verbatim() {
        // Hand-built Custom path with a hash gate. The compiler emits the consumer's
        // miniscript as-is; the embedded keys keep whatever multipath the consumer
        // baked in (here, `<7;8>`). The sha256 gate survives untouched.
        let ms = custom_miniscript(
            "and_v(v:pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<7;8>/*),sha256(deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef))",
        );
        let custom_path = Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![Leaf(0)]),
        );
        let mut policy = Policy::new(vec![custom_path], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(
            s.contains("<7;8>"),
            "consumer multipath should pass through verbatim, got {s}"
        );
        assert!(s.contains("sha256("), "got {s}");
    }

    #[test]
    fn compile_cltv_with_mandatory_key_via_unknown() {
        // `(AbsoluteRenewable | Absolute) + MultiMandatory` is infer'd as `Unknown`
        // because the typed taxonomy doesn't have a CLTV-with-mandatory variant. The
        // multipath table maps that pair to zone 7 (renewable) / 8 (foreign absolute),
        // so it compiles.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let c1 = k2();
        let c2 = oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        );
        let lt = absolute::LockTime::from_height(824320).unwrap();
        let recov = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1, c2],
                mandatory_keys: vec![k1()],
                threshold: 2,
            },
            Locktime::AbsoluteRenewable(lt),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("after(824320)"), "got {s}");
        // CLTV-renewable + Mandatory lives in zone 7 = 3584.
        assert!(s.contains("<3584;3585>"), "got {s}");
    }

    #[test]
    fn starting_index_covers_all_compilable_pairs() {
        // Every (Locktime, Semantic) pair the compiler can emit must have a multipath
        // zone, otherwise `assign_start_indices` panics. `Or` and `Unknown` are
        // intentionally absent (the compiler rejects them).
        let s1 = Semantic::Single(k1());
        let s2 = Semantic::Multi {
            keys: vec![k1(), k2()],
            threshold: 2,
        };
        let s3 = Semantic::MultiMandatory {
            keys: vec![k2()],
            mandatory_keys: vec![k1()],
            threshold: 2,
        };
        let s4 = Semantic::Custom(custom_miniscript(
            "pk([abcdef01]xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW/<0;1>/*)",
        ));
        let rel = Locktime::Relative(relative::LockTime::from_height(144));
        let abs_r = Locktime::AbsoluteRenewable(absolute::LockTime::from_height(824320).unwrap());
        let abs_f = Locktime::Absolute(absolute::LockTime::from_height(500_001).unwrap());
        // Single/Multi cover every locktime flavor.
        for s in [&s1, &s2] {
            for lt in [&Locktime::None, &rel, &abs_r, &abs_f] {
                assert!(
                    s.starting_index(lt).is_some(),
                    "missing zone for ({lt:?}, {s:?})"
                );
            }
        }
        // MultiMandatory: all locktime flavors map (no primary slot).
        for lt in [&rel, &abs_r, &abs_f] {
            assert!(
                s3.starting_index(lt).is_some(),
                "missing zone for ({lt:?}, MultiMandatory)"
            );
        }
        // Custom: only Locktime::None has a zone (locktime gates live inside the miniscript).
        assert!(s4.starting_index(&Locktime::None).is_some());
        // Sanity: MultiMandatory + None remains unmapped.
        assert_eq!(s3.starting_index(&Locktime::None), None);
    }

    // cross-path multipath-index collision detection

    // k1's xpub string body (no origin / multipath / wildcard suffix).
    const K1_XPUB_BARE: &str = "xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW";

    fn custom_path_at(multipath: &str) -> Path {
        let ms = custom_miniscript(&format!("pk([abcdef01]{K1_XPUB_BARE}/{multipath}/*)"));
        Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        )
    }

    #[test]
    fn compile_rejects_custom_custom_full_overlap() {
        // Two Custom paths, both using K1 at <7;8>. Both indices collide.
        let p1 = custom_path_at("<7;8>");
        let p2 = custom_path_at("<7;8>");
        let mut policy = Policy::new(vec![p1, p2], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::DuplicateMultipathIndex { index, .. } => {
                assert!(index == 7 || index == 8, "got index {index}");
            }
            other => panic!("expected DuplicateMultipathIndex, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_custom_duplicate_multipath_index() {
        // A single Custom key using `<3;3>` (both multipath legs equal) is structurally
        // degenerate: the two derivation paths collapse to one address. Reject with the
        // same `DuplicateMultipathIndex` variant the cross-path check uses.
        let p1 = custom_path_at("<3;3>");
        let mut policy = Policy::new(vec![p1], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::DuplicateMultipathIndex { index, .. } => assert_eq!(index, 3),
            other => panic!("expected DuplicateMultipathIndex on 3, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_gap_in_multipath() {
        // `<3;5>` skips index 4: the two multipath legs are not consecutive. The shape
        // rule mirrors the parser's invariant (`get_multipath_index` rejects the same way
        // when round-tripping a compiled descriptor).
        let p1 = custom_path_at("<3;5>");
        let mut policy = Policy::new(vec![p1], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::Multipath(crate::multipath::MultipathError::NonConsecutive) => {}
            other => panic!("expected Multipath(NonConsecutive), got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_custom_custom_partial_overlap() {
        // K1 at <3;4> in one path, <4;5> in another. Shared index 4 should trip the check.
        let p1 = custom_path_at("<3;4>");
        let p2 = custom_path_at("<4;5>");
        let mut policy = Policy::new(vec![p1, p2], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::DuplicateMultipathIndex { index, .. } => {
                assert_eq!(index, 4);
            }
            other => panic!("expected DuplicateMultipathIndex on 4, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_custom_vs_typed_primary() {
        // Typed Single primary at InternalKey: cursor allocates <512;513>.
        // Custom path embeds the same xpub K1 at <512;513>. Collision.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let custom = custom_path_at("<512;513>");
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::DuplicateMultipathIndex { index, .. } => {
                assert!(index == 512 || index == 513, "got index {index}");
            }
            other => panic!("expected DuplicateMultipathIndex, got {other:?}"),
        }
    }

    #[test]
    fn compile_rejects_custom_xpub_variant_overlap() {
        // Typed primary allocated at <512;513>. Custom uses an `XPub` (single-path
        // `/512/*`, not MultiXPub) which contributes index {512}. Must collide.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let ms = custom_miniscript(&format!("pk([abcdef01]{K1_XPUB_BARE}/512/*)"));
        let custom = Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        let err = policy.compile().unwrap_err();
        match err {
            PolicyError::DuplicateMultipathIndex { index, .. } => assert_eq!(index, 512),
            other => panic!("expected DuplicateMultipathIndex on 512, got {other:?}"),
        }
    }

    #[test]
    fn compile_accepts_disjoint_custom() {
        // Typed primary at <512;513>; Custom far away at <9000;9001>. No overlap.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let custom = custom_path_at("<9000;9001>");
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        assert!(policy.compile().is_ok());
    }

    #[test]
    fn compile_accepts_same_xpub_disjoint_indices() {
        // Same xpub K1 in both a typed primary (allocated at <512;513>) and a Custom
        // path at <3000;3001>. Same xpub, no index overlap, accepted.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let custom = custom_path_at("<3000;3001>");
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        assert!(policy.compile().is_ok());
    }

    #[test]
    fn compile_accepts_different_xpubs_same_index() {
        // Typed primary uses K1 at cursor-allocated <512;513>. Custom path uses a
        // DIFFERENT xpub (K2) at the same multipath <512;513>. Different keys derive
        // different addresses, so the check must NOT flag this, only same-xpub
        // overlaps count as collisions.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let k2_xpub_bare = "xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe";
        let ms = custom_miniscript(&format!("pk([abcdef02]{k2_xpub_bare}/<512;513>/*)"));
        let custom = Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        assert!(policy.compile().is_ok());
    }

    // MultiMandatoryNested

    fn mks_2() -> (OXpub, OXpub) {
        (k1(), k2())
    }

    fn cks_3() -> (OXpub, OXpub, OXpub) {
        (
            oxpub_from_str(
                "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
            ),
            oxpub_from_str(
                "[abcdef04]xpub661MyMwAqRbcEbs6ohRoUqTckEfLeT3vB2EsuWuckrEuDSKqdFXV6so8xJb4kvA4ZxT6hCydyFKsKwJrDm2LgSfTCphVqZgQbLzF49KwaXc/<0;1>/*",
            ),
            oxpub_from_str(
                "[abcdef05]xpub661MyMwAqRbcEqgeH5cqyxRwY4UG21ey1MBJkNBX2xSTmGS9dCRmGQezqHE9mXUXzs9HqFzNEN2KkNw5o8xpqAXw2XxsVhGVm1LbRaEnxyT/<0;1>/*",
            ),
        )
    }

    fn primary_key() -> OXpub {
        oxpub_from_str(
            "[abcdef06]xpub661MyMwAqRbcEtYavp2XsS9QfH93wyVQnkWenWxWuWdaxDtjBqfzFfWPY83z3da5oYv2XmwgTT97GhGwX9HUGDEP4FERzzgmwaGNAz1emZr/<0;1>/*",
        )
    }

    #[test]
    fn nested_mandatory_validate_canonical_accepted() {
        // m=2, mt=1, n=3, t=2 → mt*n = 3 < t*m = 4 (canonical), distinct frequencies,
        // strict subsets. Should validate.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![m1, m2],
            mandatory_threshold: 1,
            keys: vec![c1, c2, c3],
            threshold: 2,
        };
        s.validate().expect("canonical form should validate");
    }

    #[test]
    fn nested_mandatory_validate_rejects_collapsing_mandatory_side() {
        // mt == |mks| collapses to MultiMandatory.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![m1, m2],
            mandatory_threshold: 2,
            keys: vec![c1, c2, c3],
            threshold: 2,
        };
        assert!(matches!(
            s.validate(),
            Err(
                crate::path::SemanticError::InvalidNestedMandatoryThreshold {
                    side: NestedSide::Mandatory,
                    ..
                }
            )
        ));
    }

    #[test]
    fn nested_mandatory_validate_rejects_collapsing_cosigner_side() {
        // t == |ks| collapses to MultiMandatory (with roles swapped).
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![m1, m2],
            mandatory_threshold: 1,
            keys: vec![c1, c2, c3],
            threshold: 3,
        };
        assert!(matches!(
            s.validate(),
            Err(
                crate::path::SemanticError::InvalidNestedMandatoryThreshold {
                    side: NestedSide::Cosigner,
                    ..
                }
            )
        ));
    }

    #[test]
    fn nested_mandatory_validate_rejects_ambiguous_frequencies() {
        // m=2, mt=1, n=2, t=1 → mt*n = 2 == t*m = 2: ambiguous.
        let (m1, m2) = mks_2();
        let (c1, c2, _) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![m1, m2],
            mandatory_threshold: 1,
            keys: vec![c1, c2],
            threshold: 1,
        };
        assert!(matches!(
            s.validate(),
            Err(crate::path::SemanticError::NestedMandatoryAmbiguousFrequencies { .. })
        ));
    }

    #[test]
    fn nested_mandatory_validate_rejects_non_canonical_ordering() {
        // Swap the canonical (m=2, mt=1, n=3, t=2) so the "mandatory" class has the
        // *higher* frequency: m=3, mt=2, n=2, t=1 → mt*n = 4 > t*m = 3 → non-canonical.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![c1, c2, c3],
            mandatory_threshold: 2,
            keys: vec![m1, m2],
            threshold: 1,
        };
        assert!(matches!(
            s.validate(),
            Err(crate::path::SemanticError::NestedMandatoryNonCanonical { .. })
        ));
    }

    #[test]
    fn mandatory_validate_rejects_overlap_between_mandatory_and_cosigner() {
        // mandatory_keys = [A, B], keys = [A, C] → A appears in both → reject.
        let a = k1();
        let b = k2();
        let (c, _, _) = cks_3();
        let s = Semantic::MultiMandatory {
            mandatory_keys: vec![a.clone(), b],
            keys: vec![a, c],
            threshold: 3,
        };
        assert!(matches!(
            s.validate(),
            Err(crate::path::SemanticError::MandatoryCosignerOverlap)
        ));
    }

    #[test]
    fn nested_mandatory_validate_rejects_overlap_between_mandatory_and_cosigner() {
        // mandatory_keys = [A, B], keys = [A, C, D] → A appears in both → reject.
        let a = k1();
        let b = k2();
        let (c, d, _) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![a.clone(), b],
            mandatory_threshold: 1,
            keys: vec![a, c, d],
            threshold: 2,
        };
        assert!(matches!(
            s.validate(),
            Err(crate::path::SemanticError::MandatoryCosignerOverlap)
        ));
    }

    #[test]
    fn csv_with_mandatory_policy_new_rejects_overlap() {
        // Same check, bubbled up through Policy::new as PolicyError::MandatoryCosignerOverlap.
        let a = k1();
        let b = k2();
        let (c, _, _) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                mandatory_keys: vec![a.clone(), b],
                keys: vec![a, c],
                threshold: 3,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap_err();
        assert!(matches!(err, PolicyError::MandatoryCosignerOverlap));
    }

    #[test]
    fn nested_mandatory_starting_index_relative_only() {
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let s = Semantic::MultiMandatoryNested {
            mandatory_keys: vec![m1, m2],
            mandatory_threshold: 1,
            keys: vec![c1, c2, c3],
            threshold: 2,
        };
        let rel = Locktime::Relative(relative::LockTime::from_height(144));
        assert_eq!(s.starting_index(&rel), Some(512 * 9));
        assert_eq!(s.starting_index(&Locktime::None), None);
        let lt = absolute::LockTime::from_height(824320).unwrap();
        assert_eq!(s.starting_index(&Locktime::AbsoluteRenewable(lt)), None);
        assert_eq!(s.starting_index(&Locktime::Absolute(lt)), None);
    }

    #[test]
    fn nested_mandatory_leaf_count_binomial_product() {
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let p = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1, m2],
                mandatory_threshold: 1,
                keys: vec![c1, c2, c3],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        // C(2,1) * C(3,2) = 2 * 3 = 6.
        assert_eq!(p.leaf_count(), 6);
    }

    #[test]
    fn csv_with_nested_mandatory_round_trip() {
        // Smallest distinct-frequency canonical case: m=2, mt=1, n=3, t=2 → 6 leaves.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, nested], PolicyType::CsvWithNestedMandatory).unwrap();
        let desc = policy.compile().unwrap().clone();

        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithNestedMandatory);
        let nested_path = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
            .expect("expected a MultiMandatoryNested path after recombine");
        if let Semantic::MultiMandatoryNested {
            mandatory_keys,
            mandatory_threshold,
            keys,
            threshold,
        } = nested_path.semantic()
        {
            assert_eq!(*mandatory_threshold, 1);
            assert_eq!(*threshold, 2);
            assert_eq!(mandatory_keys.len(), 2);
            assert_eq!(keys.len(), 3);
            // Mandatory class is the lower-frequency one (here cnt=3 for each mk,
            // cnt=4 for each cosigner). Verify both expected key sets show up.
            let mut got_mk_xkeys: Vec<_> = mandatory_keys.iter().map(|k| k.xkey).collect();
            got_mk_xkeys.sort();
            let mut want_mk_xkeys = vec![m1.xkey, m2.xkey];
            want_mk_xkeys.sort();
            assert_eq!(got_mk_xkeys, want_mk_xkeys);
        } else {
            unreachable!("matched above");
        }
    }

    #[test]
    fn csv_with_nested_mandatory_compile_emits_zone_9_indices() {
        // 6 leaves consume <4608;4609>..<4618;4619> (zone 9 = 512*9 = 4608, +2 per leaf).
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1, m2],
                mandatory_threshold: 1,
                keys: vec![c1, c2, c3],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, nested], PolicyType::CsvWithNestedMandatory).unwrap();
        let desc = policy.compile().unwrap().clone();
        let s = desc.to_string();
        assert!(s.contains("<4608;4609>"), "missing <4608;4609> in {s}");
        assert!(s.contains("<4618;4619>"), "missing <4618;4619> in {s}");
    }

    #[test]
    fn nested_mandatory_rejected_in_csv_policy_type() {
        // Same nested path under PolicyType::Csv must be rejected as Inconsistent.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1, m2],
                mandatory_threshold: 1,
                keys: vec![c1, c2, c3],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(vec![primary, nested], PolicyType::Csv).unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InconsistentPathsForType(PolicyType::Csv)
        ));
    }

    #[test]
    fn csv_with_nested_mandatory_rejects_plain_multi_mandatory_path() {
        // PolicyType::CsvWithNestedMandatory must reject a `MultiMandatory` path mixed in.
        let (m1, m2) = mks_2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let flat = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1, c2],
                mandatory_keys: vec![m1],
                threshold: 2,
            },
            Locktime::Relative(relative::LockTime::from_height(288)),
            TapPosition::TapTree(vec![]),
        );
        let err = Policy::new(
            vec![primary, nested, flat],
            PolicyType::CsvWithNestedMandatory,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PolicyError::InconsistentPathsForType(PolicyType::CsvWithNestedMandatory)
        ));
    }

    #[test]
    fn csv_with_nested_mandatory_requires_a_nested_path() {
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(k1()),
            Locktime::Relative(relative::LockTime::from_height(144)),
            TapPosition::TapTree(vec![]),
        );
        let err =
            Policy::new(vec![primary, recov], PolicyType::CsvWithNestedMandatory).unwrap_err();
        assert!(matches!(err, PolicyError::NoNestedMandatoryKeyPath));
    }

    // Exhaustive round-trip coverage
    //
    // Each test below compiles a Policy, parses the resulting descriptor back, and asserts
    // strict equality on PolicyType, locktime, and threshold(s). Keys are compared as
    // sets (BTreeSet<Xpub>) because the compiler enumerates subsets in lex order and the
    // parser then sorts, so input key ordering isn't preserved through the round-trip.

    fn keyset(keys: &[OXpub]) -> std::collections::BTreeSet<miniscript::bitcoin::bip32::Xpub> {
        keys.iter().map(|k| k.xkey).collect()
    }

    fn extra_key() -> OXpub {
        // 7th distinct test xpub, used by larger nested-mandatory shapes (m=3, n=3) and
        // any test that needs a 6th non-overlapping signer.
        oxpub_from_str(
            "[abcdef07]xpub661MyMwAqRbcF2FpaYbnrN7K6uPhiwg5u1LiqmsMSTnphuhQzpPv9RGdERxDd7pnnrEC8hxttAPi4wbSVsKeJYiHYymfpuxSD7TALTXqjq6/<0;1>/*",
        )
    }

    fn rel(height: u16) -> Locktime {
        Locktime::Relative(relative::LockTime::from_height(height))
    }

    fn abs_renewable(height: u32) -> Locktime {
        Locktime::AbsoluteRenewable(absolute::LockTime::from_height(height).unwrap())
    }

    fn abs_foreign(height: u32) -> Locktime {
        Locktime::Absolute(absolute::LockTime::from_height(height).unwrap())
    }

    // Csv

    #[test]
    fn csv_single_primary_single_recovery_round_trip() {
        let primary_k = k1();
        let recov_k = k2();
        let primary = Path::new(
            Semantic::Single(primary_k.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(recov_k.clone()),
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::Relative(_)))
            .expect("Relative recovery missing");
        match parsed_recov.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, recov_k.xkey),
            other => panic!("expected Single recovery, got {other:?}"),
        }
        assert_eq!(parsed_recov.locktime(), &rel(144));
    }

    #[test]
    fn csv_single_primary_multi_recovery_round_trip() {
        let primary_k = k1();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_k.clone()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Multi {
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::Multi { .. }))
            .expect("Multi recovery missing");
        match parsed_recov.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected Multi recovery, got {other:?}"),
        }
        assert_eq!(parsed_recov.locktime(), &rel(144));
    }

    #[test]
    fn csv_multi_primary_single_recovery_round_trip() {
        // Multi primary stays in TapTree (no auto-promotion); NUMS internal key.
        let (m1, m2) = mks_2();
        let m3 = extra_key();
        let recov_k = primary_key();
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![m1.clone(), m2.clone(), m3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(recov_k.clone()),
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .expect("primary missing");
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[m1, m2, m3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::Relative(_)))
            .expect("recovery missing");
        match parsed_recov.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, recov_k.xkey),
            other => panic!("expected Single recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_multi_primary_multi_recovery_round_trip() {
        let (m1, m2) = mks_2();
        let m3 = extra_key();
        let (c1, c2, _) = cks_3();
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![m1.clone(), m2.clone(), m3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Multi {
                keys: vec![c1.clone(), c2.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .unwrap();
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::Relative(_)))
            .unwrap();
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[m1, m2, m3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        match parsed_recov.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected Multi recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_two_relative_recoveries_round_trip() {
        let primary_k = k1();
        let r1 = k2();
        let (r2, _, _) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_k),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov_a = Path::new(
            Semantic::Single(r1.clone()),
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let recov_b = Path::new(
            Semantic::Single(r2.clone()),
            rel(288),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov_a, recov_b], PolicyType::Csv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Csv);
        let recoveries: Vec<_> = parsed
            .paths()
            .iter()
            .filter(|p| matches!(p.locktime(), Locktime::Relative(_)))
            .collect();
        assert_eq!(recoveries.len(), 2);
        let heights: std::collections::BTreeSet<u32> = recoveries
            .iter()
            .filter_map(|p| match p.locktime() {
                Locktime::Relative(lt) => Some(lt.to_consensus_u32()),
                _ => None,
            })
            .collect();
        assert_eq!(heights, [144u32, 288u32].into_iter().collect());
        let recov_keyset: std::collections::BTreeSet<_> = recoveries
            .iter()
            .filter_map(|p| match p.semantic() {
                Semantic::Single(k) => Some(k.xkey),
                _ => None,
            })
            .collect();
        assert_eq!(recov_keyset, keyset(&[r1, r2]));
    }

    // Cltv

    #[test]
    fn cltv_single_primary_single_foreign_round_trip() {
        // Foreign (unaligned) absolute height: 824321 (not a multiple of 1024).
        let lt = abs_foreign(824321);
        let primary_k = k1();
        let recov_k = k2();
        let primary = Path::new(
            Semantic::Single(primary_k),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Single(recov_k.clone()),
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::Absolute(_)))
            .expect("foreign Absolute recovery missing");
        match parsed_recov.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, recov_k.xkey),
            other => panic!("expected Single recovery, got {other:?}"),
        }
        assert_eq!(parsed_recov.locktime(), &lt);
    }

    #[test]
    fn cltv_single_primary_multi_recovery_round_trip() {
        let primary_k = k1();
        let (c1, c2, c3) = cks_3();
        let lt = abs_renewable(824320);
        let primary = Path::new(
            Semantic::Single(primary_k),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov = Path::new(
            Semantic::Multi {
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::Multi { .. }))
            .unwrap();
        match parsed_recov.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected Multi recovery, got {other:?}"),
        }
        assert_eq!(parsed_recov.locktime(), &lt);
    }

    #[test]
    fn cltv_multi_primary_single_recovery_round_trip() {
        let (m1, m2) = mks_2();
        let m3 = extra_key();
        let recov_k = primary_key();
        let lt = abs_renewable(824320);
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![m1.clone(), m2.clone(), m3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Single(recov_k.clone()),
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .unwrap();
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[m1, m2, m3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::AbsoluteRenewable(_)))
            .unwrap();
        match parsed_recov.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, recov_k.xkey),
            other => panic!("expected Single recovery, got {other:?}"),
        }
    }

    #[test]
    fn cltv_multi_primary_multi_recovery_round_trip() {
        let (m1, m2) = mks_2();
        let m3 = extra_key();
        let (c1, c2, _) = cks_3();
        let lt = abs_renewable(824320);
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![m1.clone(), m2.clone(), m3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let recov = Path::new(
            Semantic::Multi {
                keys: vec![c1.clone(), c2.clone()],
                threshold: 2,
            },
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .unwrap();
        let parsed_recov = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::AbsoluteRenewable(_)))
            .unwrap();
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[m1, m2, m3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        match parsed_recov.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected Multi recovery, got {other:?}"),
        }
    }

    #[test]
    fn cltv_two_renewable_recoveries_round_trip() {
        let primary_k = k1();
        let r1 = k2();
        let (r2, _, _) = cks_3();
        let lt_a = abs_renewable(824320);
        let lt_b = abs_renewable(1024 * 850);
        let primary = Path::new(
            Semantic::Single(primary_k),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let recov_a = Path::new(
            Semantic::Single(r1.clone()),
            lt_a.clone(),
            TapPosition::TapTree(vec![]),
        );
        let recov_b = Path::new(
            Semantic::Single(r2.clone()),
            lt_b.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, recov_a, recov_b], PolicyType::Cltv).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Cltv);
        let renewables: Vec<_> = parsed
            .paths()
            .iter()
            .filter(|p| matches!(p.locktime(), Locktime::AbsoluteRenewable(_)))
            .collect();
        assert_eq!(renewables.len(), 2);
        let recov_keyset: std::collections::BTreeSet<_> = renewables
            .iter()
            .filter_map(|p| match p.semantic() {
                Semantic::Single(k) => Some(k.xkey),
                _ => None,
            })
            .collect();
        assert_eq!(recov_keyset, keyset(&[r1, r2]));
    }

    // CsvWithMandatoryKey

    #[test]
    fn csv_with_mandatory_multi_primary_round_trip() {
        // Multi primary stays in TapTree (NUMS internal). Recovery is the mandatory path.
        let (mp1, mp2) = mks_2();
        let mp3 = extra_key();
        let mandatory = primary_key();
        let (c1, c2, _) = cks_3();
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![mp1.clone(), mp2.clone(), mp3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .unwrap();
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[mp1, mp2, mp3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        let parsed_mk = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        match parsed_mk.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[mandatory]));
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected MultiMandatory recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_with_mandatory_larger_threshold_round_trip() {
        // m=2, n=2, t=3 → each leaf is 2 mandatory + 1 cosigner; C(2,1) = 2 leaves.
        let (m1, m2) = mks_2();
        let (c1, c2, _) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![m1.clone(), m2.clone()],
                threshold: 3,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_path], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let parsed_mk = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        match parsed_mk.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 3);
                assert_eq!(keyset(mandatory_keys), keyset(&[m1, m2]));
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected MultiMandatory recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_with_mandatory_plus_single_recovery_round_trip() {
        // CsvWithMandatoryKey policy with a mandatory recovery + a plain Single recovery
        // at a distinct relative height. Both round-trip.
        let mandatory = k1();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let plain_recov = Path::new(
            Semantic::Single(c3.clone()),
            rel(288),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(
            vec![primary, mk_path, plain_recov],
            PolicyType::CsvWithMandatoryKey,
        )
        .unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let parsed_mk = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        match parsed_mk.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[mandatory]));
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected MultiMandatory recovery, got {other:?}"),
        }
        assert_eq!(parsed_mk.locktime(), &rel(144));
        let parsed_plain = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::Single(_)) && p.locktime() == &rel(288))
            .expect("plain Single recovery missing");
        match parsed_plain.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, c3.xkey),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn csv_with_two_mandatory_recoveries_round_trip() {
        // Two distinct MultiMandatory recoveries under PolicyType::CsvWithMandatoryKey.
        let m_a = k1();
        let m_b = k2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_a = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![m_a.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mk_b = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c2.clone(), c3.clone()],
                mandatory_keys: vec![m_b.clone()],
                threshold: 2,
            },
            rel(288),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, mk_a, mk_b], PolicyType::CsvWithMandatoryKey).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithMandatoryKey);
        let mks: Vec<_> = parsed
            .paths()
            .iter()
            .filter(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .collect();
        assert_eq!(mks.len(), 2);
        let mk_xkeys: std::collections::BTreeSet<_> = mks
            .iter()
            .filter_map(|p| match p.semantic() {
                Semantic::MultiMandatory { mandatory_keys, .. } => Some(mandatory_keys[0].xkey),
                _ => None,
            })
            .collect();
        assert_eq!(mk_xkeys, keyset(&[m_a, m_b]));
    }

    // CsvWithNestedMandatory

    #[test]
    fn csv_with_nested_mandatory_multi_primary_round_trip() {
        let (mp1, mp2) = mks_2();
        let mp3 = extra_key();
        let m1 = k1();
        let m2 = k2();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Multi {
                keys: vec![mp1.clone(), mp2.clone(), mp3.clone()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, nested], PolicyType::CsvWithNestedMandatory).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithNestedMandatory);
        let parsed_primary = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.locktime(), Locktime::None))
            .unwrap();
        match parsed_primary.semantic() {
            Semantic::Multi { keys, threshold } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(keys), keyset(&[mp1, mp2, mp3]));
            }
            other => panic!("expected Multi primary, got {other:?}"),
        }
        let parsed_nested = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
            .unwrap();
        match parsed_nested.semantic() {
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                mandatory_threshold,
                keys,
                threshold,
            } => {
                assert_eq!(*mandatory_threshold, 1);
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[m1, m2]));
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected nested recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_with_nested_mandatory_larger_shape_round_trip() {
        // m=3, mt=1, n=3, t=2 → mt*n = 3 < t*m = 6 (canonical); C(3,1) * C(3,2) = 9 leaves.
        let m1 = k1();
        let m2 = k2();
        let m3 = extra_key();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone(), m3.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let mut policy =
            Policy::new(vec![primary, nested], PolicyType::CsvWithNestedMandatory).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithNestedMandatory);
        let parsed_nested = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
            .unwrap();
        match parsed_nested.semantic() {
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                mandatory_threshold,
                keys,
                threshold,
            } => {
                assert_eq!(*mandatory_threshold, 1);
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[m1, m2, m3]));
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected nested recovery, got {other:?}"),
        }
    }

    #[test]
    fn csv_with_nested_mandatory_plus_single_recovery_round_trip() {
        let m1 = k1();
        let m2 = k2();
        let (c1, c2, c3) = cks_3();
        let plain = extra_key();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let extra = Path::new(
            Semantic::Single(plain.clone()),
            rel(288),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(
            vec![primary, nested, extra],
            PolicyType::CsvWithNestedMandatory,
        )
        .unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::CsvWithNestedMandatory);
        let parsed_nested = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
            .unwrap();
        match parsed_nested.semantic() {
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                keys,
                ..
            } => {
                assert_eq!(keyset(mandatory_keys), keyset(&[m1, m2]));
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected nested recovery, got {other:?}"),
        }
        let parsed_extra = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::Single(_)) && p.locktime() == &rel(288))
            .expect("plain Single recovery missing");
        match parsed_extra.semantic() {
            Semantic::Single(k) => assert_eq!(k.xkey, plain.xkey),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    // Unknown

    #[test]
    fn unknown_cltv_with_mandatory_renewable_round_trip() {
        // MultiMandatory + AbsoluteRenewable lands in zone 7; PolicyType inferred as Unknown.
        let mandatory = k1();
        let (c1, c2, _) = cks_3();
        let lt = abs_renewable(824320);
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, mk_path], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Unknown);
        let parsed_mk = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        match parsed_mk.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[mandatory]));
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected MultiMandatory recovery, got {other:?}"),
        }
        assert_eq!(parsed_mk.locktime(), &lt);
    }

    #[test]
    fn unknown_cltv_with_mandatory_foreign_round_trip() {
        // MultiMandatory + Absolute (unaligned) → zone 8; PolicyType inferred as Unknown.
        let mandatory = k1();
        let (c1, c2, _) = cks_3();
        let lt = abs_foreign(824321);
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let mk_path = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            lt.clone(),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, mk_path], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Unknown);
        let parsed_mk = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        match parsed_mk.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[mandatory]));
                assert_eq!(keyset(keys), keyset(&[c1, c2]));
            }
            other => panic!("expected MultiMandatory recovery, got {other:?}"),
        }
        assert_eq!(parsed_mk.locktime(), &lt);
    }

    #[test]
    fn unknown_mixed_mandatory_flavors_round_trip() {
        // Mixing MultiMandatory and MultiMandatoryNested in the same Relative policy
        // forces PolicyType::Unknown. Both recoveries round-trip preserved.
        let mandatory = k1();
        let m1 = k2();
        let m2 = extra_key();
        let (c1, c2, c3) = cks_3();
        let primary = Path::new(
            Semantic::Single(primary_key()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        let flat = Path::new(
            Semantic::MultiMandatory {
                keys: vec![c1.clone(), c2.clone()],
                mandatory_keys: vec![mandatory.clone()],
                threshold: 2,
            },
            rel(144),
            TapPosition::TapTree(vec![]),
        );
        let nested = Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: vec![m1.clone(), m2.clone()],
                mandatory_threshold: 1,
                keys: vec![c1.clone(), c2.clone(), c3.clone()],
                threshold: 2,
            },
            rel(288),
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, flat, nested], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Unknown);
        let parsed_flat = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatory { .. }))
            .unwrap();
        let parsed_nested = parsed
            .paths()
            .iter()
            .find(|p| matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }))
            .unwrap();
        match parsed_flat.semantic() {
            Semantic::MultiMandatory {
                keys,
                mandatory_keys,
                threshold,
            } => {
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[mandatory]));
                assert_eq!(keyset(keys), keyset(&[c1.clone(), c2.clone()]));
            }
            other => panic!("expected MultiMandatory, got {other:?}"),
        }
        assert_eq!(parsed_flat.locktime(), &rel(144));
        match parsed_nested.semantic() {
            Semantic::MultiMandatoryNested {
                mandatory_keys,
                mandatory_threshold,
                keys,
                threshold,
            } => {
                assert_eq!(*mandatory_threshold, 1);
                assert_eq!(*threshold, 2);
                assert_eq!(keyset(mandatory_keys), keyset(&[m1, m2]));
                assert_eq!(keyset(keys), keyset(&[c1, c2, c3]));
            }
            other => panic!("expected MultiMandatoryNested, got {other:?}"),
        }
        assert_eq!(parsed_nested.locktime(), &rel(288));
    }

    #[test]
    fn unknown_custom_path_round_trip() {
        // Custom path doesn't survive as `Semantic::Custom` on the parsed side: the parser
        // lifts the embedded miniscript and re-classifies. A hash-gated leaf doesn't fit
        // any typed shape, so the parser produces `Semantic::Unknown` → PolicyType::Unknown.
        // The test only asserts compile + reparse succeed with the expected top-level type.
        let primary = Path::new(
            Semantic::Single(k1()),
            Locktime::None,
            TapPosition::InternalKey,
        );
        // Use a different xpub family for the Custom path so the (xpub, multipath-index)
        // uniqueness check doesn't trip on the primary's <512;513> claim.
        let k2_xpub_bare = "xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe";
        let ms = custom_miniscript(&format!(
            "and_v(v:pk([abcdef02]{k2_xpub_bare}/<3072;3073>/*),sha256(deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef))"
        ));
        let custom = Path::new(
            Semantic::Custom(ms),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut policy = Policy::new(vec![primary, custom], PolicyType::Unknown).unwrap();
        let desc = policy.compile().unwrap().clone();
        let parsed = Policy::from_descriptor(&desc).unwrap();
        assert_eq!(parsed.policy_type(), PolicyType::Unknown);
    }
}
