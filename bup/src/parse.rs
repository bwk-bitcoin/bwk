//! Parser-side helpers used by `Policy::from_descriptor`.

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    sync,
};

use miniscript::{
    bitcoin::{absolute, relative},
    descriptor::Wildcard,
    policy::{Liftable, Semantic as SemanticPolicy},
    DescriptorPublicKey, Miniscript, Tap,
};

use crate::{
    multipath::LeafEntry,
    path::{
        count_combinations, is_cltv_aligned, Leaf, Locktime, OXpub, Path, Semantic, TapPosition,
    },
    policy::{PolicyError, PolicyType},
};

/// Tr key-path satisfaction in WU. `1` varint length prefix + `65` max BIP-341
/// Schnorr signature length (64 raw + 1 optional sighash flag). Replicates
/// `rust-bitcoin`'s `taproot::serialized_signature::MAX_LEN` (declared
/// `pub(crate)` upstream); a BIP-341 consensus invariant, not expected to drift.
pub(super) const TR_KEY_PATH_WU: u64 = 1 + 65;

pub(super) fn oxpub(k: &DescriptorPublicKey) -> Option<OXpub> {
    if let DescriptorPublicKey::MultiXPub(xpub) = k {
        // Require an origin (fingerprint): classification is keyed on signer
        // identity. Origin-less keys fall through to `Semantic::Unknown`.
        xpub.origin.as_ref()?;
        Some(OXpub::new(xpub.origin.clone(), xpub.xkey))
    } else {
        None
    }
}

/// Construct a `DescriptorPublicKey` from an [`OXpub`] and a set of derivation paths.
/// Used by `compile.rs` and `policy.rs` when they need to assign fresh multipath indices.
/// Always emits `Wildcard::Unhardened`: bup descriptors are always wildcarded multipath,
/// and `OXpub` doesn't carry the original wildcard kind.
pub(super) fn oxpub_to_key(
    o: &OXpub,
    paths: miniscript::descriptor::DerivPaths,
) -> DescriptorPublicKey {
    DescriptorPublicKey::MultiXPub(miniscript::descriptor::DescriptorMultiXKey {
        origin: o.origin.clone(),
        xkey: o.xkey,
        derivation_paths: paths,
        wildcard: Wildcard::Unhardened,
    })
}

/// If `sub` is `older(...)` / `after(...)`, build the matching [`Locktime`]; `None` otherwise.
/// Absolute heights are tagged renewable iff aligned to the CLTV grid.
fn try_into_locktime(sub: &SemanticPolicy<DescriptorPublicKey>) -> Option<Locktime> {
    match sub {
        SemanticPolicy::Older(v) => {
            let raw = v.to_consensus_u32();
            u16::try_from(raw)
                .ok()
                .map(|h| Locktime::Relative(relative::LockTime::from_height(h)))
        }
        SemanticPolicy::After(v) => {
            let raw = v.to_consensus_u32();
            let lt = absolute::LockTime::from_consensus(raw);
            Some(if is_cltv_aligned(raw) {
                Locktime::AbsoluteRenewable(lt)
            } else {
                Locktime::Absolute(lt)
            })
        }
        _ => None,
    }
}

type ThreshOfPolicy = miniscript::Threshold<sync::Arc<SemanticPolicy<DescriptorPublicKey>>, 0>;

/// `thresh(2, locktime, body)`: must be exactly `k == n == 2` with one sub a locktime and the
/// other a non-locktime body. Recurses on the body. `None` if the shape doesn't match.
fn classify_thresh2_locktime_body(
    t: &ThreshOfPolicy,
) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    if t.k() != 2 || t.n() != 2 {
        return Ok(None);
    }
    let mut timelock: Option<Locktime> = None;
    let mut body: Option<&SemanticPolicy<DescriptorPublicKey>> = None;
    for sub in t.data() {
        if let Some(lt) = try_into_locktime(sub.as_ref()) {
            if timelock.is_some() {
                return Ok(None); // two locktimes is not a body+locktime shape
            }
            timelock = Some(lt);
        } else {
            if body.is_some() {
                return Ok(None); // two bodies - caller should try a different shape
            }
            body = Some(sub.as_ref());
        }
    }
    let (locktime, body) = match (timelock, body) {
        (Some(lt), Some(b)) => (lt, b),
        _ => return Ok(None),
    };
    let Some((semantic, _)) = policy_to_known_semantic(body)? else {
        return Ok(None);
    };
    if !matches!(
        semantic,
        Semantic::Single(_) | Semantic::Multi { .. } | Semantic::MultiMandatory { .. }
    ) {
        return Ok(None);
    }
    Ok(Some((semantic, locktime)))
}

/// `thresh(k, key_1, …, key_m, locktime)` (any permutation): keys-plus-one-locktime shape for
/// any `k`. Every sub must be either a key or a locktime; exactly one locktime is required.
/// The locktime is assumed to consume one slot of `k`, so the effective key threshold is `k − 1`.
fn classify_kofm_with_locktime(
    t: &ThreshOfPolicy,
) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    let mut locktime: Option<Locktime> = None;
    let mut keys: Vec<OXpub> = Vec::new();
    let mut seen_fps = HashSet::new();
    for sub in t.data() {
        match sub.as_ref() {
            SemanticPolicy::Key(k) => {
                let Some(o) = oxpub(k) else {
                    return Ok(None);
                };
                let Some((fp, _)) = &o.origin else {
                    return Ok(None);
                };
                if !seen_fps.insert(*fp) {
                    return Ok(None);
                }
                keys.push(o);
            }
            other => {
                let Some(lt) = try_into_locktime(other) else {
                    return Ok(None);
                };
                if locktime.is_some() {
                    return Ok(None);
                }
                locktime = Some(lt);
            }
        }
    }
    let Some(locktime) = locktime else {
        return Ok(None);
    };
    // the real k is k - 1 and must be >= 1
    let Some(threshold) = t.k().checked_sub(1).filter(|&k| k >= 1) else {
        return Ok(None);
    };
    // (single) key + timelock are classified with classify_thresh2_locktime_body()
    if keys.len() < 2 || threshold > keys.len() {
        return Ok(None);
    }
    keys.sort();
    Ok(Some((Semantic::Multi { keys, threshold }, locktime)))
}

/// `thresh(k, keys…)` with no locktime - every sub is a key.
fn classify_pure_thresh(t: &ThreshOfPolicy) -> Result<Option<Semantic>, PolicyError> {
    if t.k() > t.n() {
        return Ok(None);
    }
    let mut keys: Vec<OXpub> = Vec::new();
    for sub in t.data() {
        let SemanticPolicy::Key(k) = sub.as_ref() else {
            return Ok(None);
        };
        let Some(o) = oxpub(k) else {
            return Ok(None);
        };
        keys.push(o);
    }
    multi_or_single(keys, t.k()).map(Some)
}

/// Returns `true` if every key in `keys` is a `MultiXPub` with an origin and all origin
/// fingerprints are distinct.
fn has_unique_origins(keys: &[&DescriptorPublicKey]) -> bool {
    let mut seen = HashSet::new();
    for k in keys {
        let DescriptorPublicKey::MultiXPub(x) = k else {
            return false;
        };
        let Some((fp, _)) = &x.origin else {
            return false;
        };
        if !seen.insert(*fp) {
            return false;
        }
    }
    true
}

fn multi_or_single(keys: Vec<OXpub>, threshold: usize) -> Result<Semantic, PolicyError> {
    let n = keys.len();
    if threshold == 0 || threshold > n || (n == 1 && threshold != 1) {
        return Err(PolicyError::InvalidThreshold {
            threshold,
            key_count: n,
        });
    }
    if n == 1 {
        Ok(Semantic::Single(keys.into_iter().next().unwrap()))
    } else {
        Ok(Semantic::Multi { keys, threshold })
    }
}

/// `thresh(1, A, B, …)` where at least one sub is itself a `Thresh`. Recursively classifies
/// each sub; only produces `Or(subs)` when `k == 1` and all subs classify successfully.
fn classify_thresh_nested(t: &ThreshOfPolicy) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    if t.k() != 1 {
        return Ok(None);
    }
    let subs_opt: Vec<Option<Semantic>> = t
        .data()
        .iter()
        .map(|s| Ok(policy_to_known_semantic(s.as_ref())?.map(|(sem, _)| sem)))
        .collect::<Result<Vec<_>, PolicyError>>()?;
    let Some(subs): Option<Vec<Semantic>> = subs_opt.into_iter().collect() else {
        return Ok(None);
    };
    // plain Single/Multi - the pure-thresh classifier handles these
    if subs
        .iter()
        .all(|s| matches!(s, Semantic::Single(_) | Semantic::Multi { .. }))
    {
        return Ok(None);
    }
    if subs
        .iter()
        .any(|s| matches!(s, Semantic::Or(_) | Semantic::Unknown { .. }))
    {
        return Ok(None);
    }
    Ok(Some((Semantic::Or(subs), Locktime::None)))
}

/// Try the threshold-shape classifiers in priority order:
/// 1. `thresh(2, locktime, body)` - `body` may be a nested threshold, so this comes first.
/// 2. `thresh(k, key_1, …, key_m, locktime)` - any k, keys + one locktime.
/// 3. `thresh(k, keys…)` - pure key threshold, no locktime.
/// 4. `thresh(k, …)` with nested thresholds - `Or` / `And` / `Threshold` of sub-semantics.
fn classify_thresh(t: &ThreshOfPolicy) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    if let Some(r) = classify_thresh2_locktime_body(t)? {
        return Ok(Some(r));
    }
    if let Some(r) = classify_kofm_with_locktime(t)? {
        return Ok(Some(r));
    }
    if let Some(s) = classify_pure_thresh(t)? {
        return Ok(Some((s, Locktime::None)));
    }
    classify_thresh_nested(t)
}

/// Recognise a normalised semantic policy as a known shape. `Ok(None)` if unrecognised - the
/// caller decides whether to fall back to `Semantic::Unknown`.
fn policy_to_known_semantic(
    policy: &SemanticPolicy<DescriptorPublicKey>,
) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    match policy {
        SemanticPolicy::Key(k) => {
            let Some(o) = oxpub(k) else {
                return Ok(None);
            };
            Ok(Some((Semantic::Single(o), Locktime::None)))
        }
        SemanticPolicy::Thresh(t) => classify_thresh(t),
        _ => Ok(None),
    }
}

/// Classify a normalised semantic policy, falling back to `Semantic::Unknown` if unrecognised.
fn policy_to_semantic(policy: &SemanticPolicy<DescriptorPublicKey>) -> (Semantic, Locktime) {
    policy_to_known_semantic(policy).ok().flatten().unwrap_or((
        Semantic::Unknown {
            policy: policy.clone(),
        },
        Locktime::None,
    ))
}

/// Lift a tap-leaf miniscript to a semantic policy and classify it, falling back to
/// `Semantic::Unknown` if unrecognised.
fn miniscript_to_semantic(
    ms: &Miniscript<DescriptorPublicKey, Tap>,
) -> Result<(Semantic, Locktime), PolicyError> {
    let lifted = ms.lift().map_err(PolicyError::Miniscript)?.normalized();
    Ok(policy_to_semantic(&lifted))
}

/// Parsed shape of a single tap-tree leaf: N-of-N keys, optionally gated by one locktime.
struct LeafShape {
    threshold: usize,
    keys: Vec<DescriptorPublicKey>,
    locktime: Locktime,
}

impl LeafShape {
    /// Returns `true` if the shape is internally consistent: threshold in `[1, keys.len()]`,
    /// every key is a valid multipath xpub with an origin, and all origins are distinct.
    fn is_valid(&self) -> bool {
        if self.threshold == 0 || self.threshold > self.keys.len() {
            return false;
        }
        let key_refs: Vec<&DescriptorPublicKey> = self.keys.iter().collect();
        self.keys.iter().all(|k| oxpub(k).is_some()) && has_unique_origins(&key_refs)
    }
}

/// Returns `Some((threshold, locktime))` if all shapes share the same threshold, key count,
/// and locktime; threshold equals each shape's key count (N-of-N); and threshold >= 2.
fn shapes_consistent(shapes: &[LeafShape]) -> Option<(usize, Locktime)> {
    let first = shapes.first()?;
    let threshold = first.threshold;
    let key_count = first.keys.len();
    let locktime = first.locktime.clone();
    if threshold < 2 {
        return None;
    }
    for s in shapes {
        if s.threshold != s.keys.len()
            || s.threshold != threshold
            || s.keys.len() != key_count
            || s.locktime != locktime
        {
            return None;
        }
    }
    Some((threshold, locktime))
}

/// Parse a miniscript into a [`LeafShape`] if it's an N-of-N AND optionally gated by a single
/// `older()` / `after()` - the shape every `MultiMandatory` leaf takes.
fn miniscript_to_leaf_shape(ms: &Miniscript<DescriptorPublicKey, Tap>) -> Option<LeafShape> {
    let lifted = ms.lift().ok()?.normalized();
    let SemanticPolicy::Thresh(t) = lifted else {
        return None;
    };
    if t.k() != t.n() {
        return None;
    }
    let mut keys = Vec::new();
    let mut locktime = Locktime::None;
    for sub in t.data() {
        if let SemanticPolicy::Key(k) = sub.as_ref() {
            keys.push(k.clone());
        } else {
            // Must be a single locktime; reject duplicates and any other shape.
            let lt = try_into_locktime(sub.as_ref())?;
            if !matches!(locktime, Locktime::None) {
                return None;
            }
            locktime = lt;
        }
    }
    if keys.is_empty() {
        return None;
    }
    let shape = LeafShape {
        threshold: keys.len(),
        keys,
        locktime,
    };
    if !shape.is_valid() {
        return None;
    }
    Some(shape)
}

impl Path {
    /// Return `Some` if `leaves` are the flattened leaf set of a `MultiMandatory` path.
    pub fn try_from_mandatory_multi(leaves: &[LeafEntry]) -> Option<Self> {
        if leaves.len() < 2 {
            return None;
        }
        // all leaves must have same depth
        let depth = leaves[0].depth;
        if leaves.iter().any(|e| e.depth != depth) {
            return None;
        }
        let mut shapes: Vec<LeafShape> = Vec::new();
        for leaf in leaves {
            shapes.push(miniscript_to_leaf_shape(leaf.ms)?);
        }
        // fail early if shapes not matches the same pattern
        let (threshold, locktime) = shapes_consistent(&shapes)?;

        let leaves_count = leaves.len();
        let mut key_usage_count: HashMap<OXpub, usize> = HashMap::new();
        for shape in &shapes {
            for k in &shape.keys {
                if let Some(o) = oxpub(k) {
                    *key_usage_count.entry(o).or_insert(0) += 1;
                }
            }
        }

        // select keys that DO appear in ALL leaves
        let mut mandatory_oxpubs: Vec<OXpub> = key_usage_count
            .iter()
            .filter(|&(_, &cnt)| cnt == leaves_count)
            .map(|(o, _)| o.clone())
            .collect();
        if mandatory_oxpubs.is_empty() {
            return None;
        }

        // select keys that DONT appear in ALL leaves
        let mut cosigner_oxpubs: Vec<OXpub> = key_usage_count
            .iter()
            .filter(|&(_, &cnt)| cnt < leaves_count)
            .map(|(o, _)| o.clone())
            .collect();
        if cosigner_oxpubs.is_empty() {
            return None;
        }

        // all cosigners has same occurences count
        let cosigner_leaf_freq = key_usage_count[&cosigner_oxpubs[0]];
        if cosigner_oxpubs
            .iter()
            .any(|o| key_usage_count[o] != cosigner_leaf_freq)
        {
            return None;
        }

        // process threshold
        let cosigners_count = cosigner_oxpubs.len();
        let k_num = cosigner_leaf_freq * cosigners_count;
        if k_num % leaves_count != 0 {
            return None;
        }
        let cosigner_threshold = k_num / leaves_count;
        if count_combinations(cosigners_count, cosigner_threshold) != leaves_count {
            return None;
        }
        if threshold != mandatory_oxpubs.len() + cosigner_threshold {
            return None;
        }

        mandatory_oxpubs.sort();
        cosigner_oxpubs.sort();
        let leaf_records: Vec<Leaf> = leaves.iter().map(|e| Leaf(e.index)).collect();
        Some(Path::new(
            Semantic::MultiMandatory {
                keys: cosigner_oxpubs,
                mandatory_keys: mandatory_oxpubs,
                threshold,
            },
            locktime,
            TapPosition::TapTree(leaf_records),
        ))
    }

    /// Return `Some` if `leaves` are the flattened leaf set of a
    /// [`Semantic::MultiMandatoryNested`] path. Recognised shape: every leaf is a flat
    /// N-of-N with a `Locktime::Relative` gate; keys partition into exactly two frequency
    /// classes; the lower-frequency class becomes `mandatory_keys`. Returns `None` for any
    /// other shape (including descriptors with non-Relative locktimes, which this variant
    /// does not support).
    pub fn try_from_mandatory_nested(leaves: &[LeafEntry]) -> Option<Self> {
        // Smallest valid set is C(2,1) * C(2,1) = 4 leaves; anything smaller can't be a
        // proper-subset enumeration on both sides.
        if leaves.len() < 4 {
            return None;
        }
        let depth = leaves[0].depth;
        if leaves.iter().any(|e| e.depth != depth) {
            return None;
        }
        let mut shapes: Vec<LeafShape> = Vec::new();
        for leaf in leaves {
            shapes.push(miniscript_to_leaf_shape(leaf.ms)?);
        }
        let (threshold, locktime) = shapes_consistent(&shapes)?;
        // MultiMandatoryNested only supports relative locktimes.
        if !matches!(locktime, Locktime::Relative(_)) {
            return None;
        }

        let leaves_count = leaves.len();
        let mut key_usage_count: HashMap<OXpub, usize> = HashMap::new();
        for shape in &shapes {
            for k in &shape.keys {
                if let Some(o) = oxpub(k) {
                    *key_usage_count.entry(o).or_insert(0) += 1;
                }
            }
        }
        // Any key appearing in every leaf means this is a MultiMandatory shape, not nested.
        if key_usage_count.values().any(|&cnt| cnt == leaves_count) {
            return None;
        }
        // Collect distinct frequency counts.
        let mut distinct_counts: Vec<usize> = key_usage_count.values().copied().collect();
        distinct_counts.sort_unstable();
        distinct_counts.dedup();
        if distinct_counts.len() != 2 {
            return None;
        }
        let cnt_low = distinct_counts[0];
        let cnt_high = distinct_counts[1];

        // Partition keys: lower frequency → mandatory (canonical rule); higher → cosigner.
        let mut mandatory_oxpubs: Vec<OXpub> = key_usage_count
            .iter()
            .filter(|&(_, &cnt)| cnt == cnt_low)
            .map(|(o, _)| o.clone())
            .collect();
        let mut cosigner_oxpubs: Vec<OXpub> = key_usage_count
            .iter()
            .filter(|&(_, &cnt)| cnt == cnt_high)
            .map(|(o, _)| o.clone())
            .collect();
        let m = mandatory_oxpubs.len();
        let n = cosigner_oxpubs.len();
        if m == 0 || n == 0 {
            return None;
        }

        // Recover the thresholds. cnt_low * m = mt * leaves_count; similarly for cnt_high.
        let mt_num = cnt_low * m;
        let t_num = cnt_high * n;
        if mt_num % leaves_count != 0 || t_num % leaves_count != 0 {
            return None;
        }
        let mt = mt_num / leaves_count;
        let t = t_num / leaves_count;

        // Canonical-form checks: strict subsets and exact leaf count.
        if mt == 0 || mt >= m || t == 0 || t >= n {
            return None;
        }
        if mt + t != threshold {
            return None;
        }
        if count_combinations(m, mt) * count_combinations(n, t) != leaves_count {
            return None;
        }
        // The canonical rule mt*n < t*m is guaranteed by cnt_low < cnt_high (lower
        // per-class frequency goes to the mandatory side).

        mandatory_oxpubs.sort();
        cosigner_oxpubs.sort();
        let leaf_records: Vec<Leaf> = leaves.iter().map(|e| Leaf(e.index)).collect();
        Some(Path::new(
            Semantic::MultiMandatoryNested {
                mandatory_keys: mandatory_oxpubs,
                mandatory_threshold: mt,
                keys: cosigner_oxpubs,
                threshold: t,
            },
            locktime,
            TapPosition::TapTree(leaf_records),
        ))
    }
}

/// Path satisfaction WU at tap-tree `depth`. Sums miniscript's `max_satisfaction_size`,
/// `script_size`, the script length-prefix, and the control block (`1 + 33 + 32 * depth`).
/// `None` if miniscript can't size the satisfaction.
pub fn compute_satisfaction_wu(
    leaf_ms: &Miniscript<DescriptorPublicKey, Tap>,
    depth: u8,
) -> Option<u64> {
    let sat_size = leaf_ms.max_satisfaction_size().ok()? as u64;
    let script_size = leaf_ms.script_size() as u64;
    let control_block_wu = 1 + 33 + 32 * (depth as u64);
    let script_prefix_wu = 1;
    Some(sat_size + script_size + script_prefix_wu + control_block_wu)
}

/// Convert a logical group of leaves into a single [`Path`]. Fails if the group is empty or
/// cannot be classified into a known path shape.
pub fn group_to_path(leaves: &[LeafEntry]) -> Result<Path, PolicyError> {
    if leaves.len() == 1 {
        let e = &leaves[0];
        let (semantic, locktime) = miniscript_to_semantic(e.ms)?;
        return Ok(Path::new(
            semantic,
            locktime,
            TapPosition::TapTree(vec![Leaf(e.index)]),
        ));
    }
    // MultiMandatory could have been split into several n-of-n leaves; if that fails,
    // try the nested-mandatory shape (subset enumeration on both sides).
    if let Some(p) = Path::try_from_mandatory_multi(leaves) {
        return Ok(p);
    }
    Path::try_from_mandatory_nested(leaves).ok_or(PolicyError::UnrecognizedLeafGroup)
}

/// Pick the [`PolicyType`] that fits a parsed path set, or `Unknown` if none match.
pub(super) fn infer_policy_type(paths: &[Path]) -> PolicyType {
    if paths.is_empty() {
        return PolicyType::Unknown;
    }
    let mut has_unknown = false;
    let mut has_relative = false;
    let mut has_absolute = false;
    let mut has_mandatory = false;
    let mut has_nested_mandatory = false;
    for p in paths {
        if matches!(p.semantic(), Semantic::Unknown { .. }) {
            has_unknown = true;
        }
        if matches!(p.semantic(), Semantic::MultiMandatory { .. }) {
            has_mandatory = true;
        }
        if matches!(p.semantic(), Semantic::MultiMandatoryNested { .. }) {
            has_nested_mandatory = true;
        }
        match p.locktime() {
            Locktime::None => {}
            Locktime::Relative(_) => has_relative = true,
            Locktime::AbsoluteRenewable(_) | Locktime::Absolute(_) => has_absolute = true,
        }
    }
    match (
        has_absolute,
        has_relative,
        has_unknown,
        has_mandatory,
        has_nested_mandatory,
    ) {
        // Any `Semantic::Unknown` path forces the whole policy into the Unknown escape
        // hatch, regardless of locktime layout. CLTV + mandatory (either flavor) is still
        // Unknown because the typed taxonomy has no variant for it. Mixing
        // `MultiMandatory` + `MultiMandatoryNested` in the same policy is also Unknown -
        // the two have distinct typed homes.
        (_, _, true, _, _) | (true, _, _, true, _) | (true, _, _, _, true) => PolicyType::Unknown,
        (_, _, _, true, true) => PolicyType::Unknown,
        (true, true, _, _, _) | (false, false, _, _, _) => PolicyType::Invalid,
        (true, false, false, false, false) => PolicyType::Cltv,
        (false, true, false, true, false) => PolicyType::CsvWithMandatoryKey,
        (false, true, false, false, true) => PolicyType::CsvWithNestedMandatory,
        (false, true, false, false, false) => PolicyType::Csv,
    }
}
