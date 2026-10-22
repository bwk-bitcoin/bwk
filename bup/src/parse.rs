//! Parser-side helpers used by `Policy::from_descriptor`.

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    sync,
};

use bwk_descriptor::wallet::WalletKey;
#[cfg(feature = "musig")]
use bwk_keys::musig::MusigKey;
use miniscript::{
    bitcoin::{absolute, relative},
    descriptor::Wildcard,
    policy::{Liftable, Semantic as SemanticPolicy},
    DescriptorPublicKey, Miniscript, Tap,
};

use crate::{
    multipath::{plain_key, LeafEntry},
    path::{
        count_combinations, count_nested_combinations, is_cltv_aligned, Leaf, Locktime, OXpub,
        Path, Semantic, TapPosition,
    },
    policy::{PolicyError, PolicyType},
};
#[cfg(feature = "musig")]
use crate::{musig::musig_participants, path::MULTIPATH_SEMANTIC_FACTOR};

/// Tr key-path satisfaction in WU. `1` varint length prefix + `65` max BIP-341
/// Schnorr signature length (64 raw + 1 optional sighash flag). Replicates
/// `rust-bitcoin`'s `taproot::serialized_signature::MAX_LEN` (declared
/// `pub(crate)` upstream); a BIP-341 consensus invariant, not expected to drift.
pub(super) const TR_KEY_PATH_WU: u64 = 1 + 65;

pub(super) fn oxpub(k: &WalletKey) -> Option<OXpub> {
    if let Some(DescriptorPublicKey::MultiXPub(xpub)) = plain_key(k) {
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
fn try_into_locktime(sub: &SemanticPolicy<WalletKey>) -> Option<Locktime> {
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

type ThreshOfPolicy = miniscript::Threshold<sync::Arc<SemanticPolicy<WalletKey>>, 0>;

/// `thresh(2, locktime, body)`: must be exactly `k == n == 2` with one sub a locktime and the
/// other a non-locktime body. Recurses on the body. `None` if the shape doesn't match.
fn classify_thresh2_locktime_body(
    t: &ThreshOfPolicy,
) -> Result<Option<(Semantic, Locktime)>, PolicyError> {
    if t.k() != 2 || t.n() != 2 {
        return Ok(None);
    }
    let mut timelock: Option<Locktime> = None;
    let mut body: Option<&SemanticPolicy<WalletKey>> = None;
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
fn has_unique_origins(keys: &[&WalletKey]) -> bool {
    let mut seen = HashSet::new();
    for k in keys {
        let Some(DescriptorPublicKey::MultiXPub(x)) = plain_key(k) else {
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
    policy: &SemanticPolicy<WalletKey>,
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
fn policy_to_semantic(policy: &SemanticPolicy<WalletKey>) -> (Semantic, Locktime) {
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
    ms: &Miniscript<WalletKey, Tap>,
) -> Result<(Semantic, Locktime), PolicyError> {
    let lifted = ms.lift().map_err(PolicyError::Miniscript)?.normalized();
    Ok(policy_to_semantic(&lifted))
}

/// Parsed shape of a single tap-tree leaf: N-of-N keys, optionally gated by one locktime.
struct LeafShape {
    threshold: usize,
    keys: Vec<WalletKey>,
    locktime: Locktime,
}

impl LeafShape {
    /// Returns `true` if the shape is internally consistent: threshold in `[1, keys.len()]`,
    /// every key is a valid multipath xpub with an origin, and all origins are distinct.
    fn is_valid(&self) -> bool {
        if self.threshold == 0 || self.threshold > self.keys.len() {
            return false;
        }
        let key_refs: Vec<&WalletKey> = self.keys.iter().collect();
        self.keys.iter().all(|k| oxpub(k).is_some()) && has_unique_origins(&key_refs)
    }
}

/// Returns the locktime shared by all shapes if they share the same threshold, key count,
/// and locktime; threshold equals each shape's key count (N-of-N); and threshold >= 2.
fn shapes_consistent(shapes: &[LeafShape]) -> Option<Locktime> {
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
    Some(locktime)
}

/// Parse a miniscript into a [`LeafShape`] if it's an N-of-N AND optionally gated by a single
/// `older()` / `after()` - the shape every `MultiMandatory` leaf takes.
fn miniscript_to_leaf_shape(ms: &Miniscript<WalletKey, Tap>) -> Option<LeafShape> {
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

/// The key set of every script-form leaf and their shared locktime: the leaves sit at one
/// depth and are consistent N-of-N shapes.
fn leaf_shape_key_sets(leaves: &[LeafEntry]) -> Option<(Vec<Vec<OXpub>>, Locktime)> {
    let depth = leaves.first()?.depth;
    if leaves.iter().any(|e| e.depth != depth) {
        return None;
    }
    let mut shapes: Vec<LeafShape> = Vec::new();
    for leaf in leaves {
        shapes.push(miniscript_to_leaf_shape(leaf.ms)?);
    }
    let locktime = shapes_consistent(&shapes)?;
    let sets = shapes
        .iter()
        .map(|s| s.keys.iter().map(oxpub).collect::<Option<Vec<_>>>())
        .collect::<Option<Vec<_>>>()?;
    Some((sets, locktime))
}

/// The size shared by every key set, None if the sets are empty, differ in size, or one
/// repeats a key.
fn uniform_set_size(sets: &[Vec<OXpub>]) -> Option<usize> {
    let size = sets.first()?.len();
    for set in sets {
        let distinct: HashSet<&OXpub> = set.iter().collect();
        if set.len() != size || distinct.len() != size {
            return None;
        }
    }
    Some(size)
}

/// Whether no two key sets hold the same keys, whatever their order.
fn sets_distinct(sets: &[Vec<OXpub>]) -> bool {
    let mut sorted_sets: Vec<Vec<&OXpub>> = sets
        .iter()
        .map(|set| {
            let mut sorted: Vec<&OXpub> = set.iter().collect();
            sorted.sort();
            sorted
        })
        .collect();
    sorted_sets.sort();
    sorted_sets.dedup();
    sorted_sets.len() == sets.len()
}

/// How many key sets each key appears in.
fn key_usage_count(sets: &[Vec<OXpub>]) -> HashMap<OXpub, usize> {
    let mut count: HashMap<OXpub, usize> = HashMap::new();
    for key in sets.iter().flatten() {
        *count.entry(key.clone()).or_insert(0) += 1;
    }
    count
}

/// The tap-tree position of `leaves`.
fn leaves_position(leaves: &[LeafEntry]) -> TapPosition {
    TapPosition::TapTree(leaves.iter().map(|e| Leaf(e.index)).collect())
}

/// `Multi { keys, threshold: m }` if the key sets are every m-subset of their union, once
/// each. The union keeps the order of first appearance (sets in the given order, then
/// position inside each set). A threshold of 1 needs at least two sets.
#[cfg(feature = "musig")]
fn multi_from_key_sets(
    leaves: &[LeafEntry],
    sets: &[Vec<OXpub>],
    locktime: Locktime,
) -> Option<Path> {
    let threshold = uniform_set_size(sets)?;
    if threshold == 1 && sets.len() < 2 {
        return None;
    }
    if !sets_distinct(sets) {
        return None;
    }
    let mut keys: Vec<OXpub> = Vec::new();
    for key in sets.iter().flatten() {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    if count_combinations(keys.len(), threshold) != Some(sets.len()) {
        return None;
    }
    Some(Path::new(
        Semantic::Multi { keys, threshold },
        locktime,
        leaves_position(leaves),
    ))
}

/// `MultiMandatory` from the key set of every leaf: the keys in every set are mandatory,
/// the others are cosigners sharing one frequency, and the set size is the threshold.
/// The sets are distinct, so they are every cosigner subset once each.
fn mandatory_from_key_sets(
    leaves: &[LeafEntry],
    sets: &[Vec<OXpub>],
    locktime: Locktime,
) -> Option<Path> {
    let threshold = uniform_set_size(sets)?;
    if !sets_distinct(sets) {
        return None;
    }
    let leaves_count = sets.len();
    let key_usage_count = key_usage_count(sets);

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
    if count_combinations(cosigners_count, cosigner_threshold) != Some(leaves_count) {
        return None;
    }
    if threshold != mandatory_oxpubs.len() + cosigner_threshold {
        return None;
    }

    mandatory_oxpubs.sort();
    cosigner_oxpubs.sort();
    Some(Path::new(
        Semantic::MultiMandatory {
            keys: cosigner_oxpubs,
            mandatory_keys: mandatory_oxpubs,
            threshold,
        },
        locktime,
        leaves_position(leaves),
    ))
}

/// `MultiMandatoryNested` from the key set of every leaf: the keys split in two frequency
/// classes, the lower one mandatory; relative locktimes only. The sets are distinct and
/// each holds `mandatory_threshold` mandatory keys, so they are every
/// `(mandatory subset, cosigner subset)` pair once each.
fn nested_from_key_sets(
    leaves: &[LeafEntry],
    sets: &[Vec<OXpub>],
    locktime: Locktime,
) -> Option<Path> {
    // MultiMandatoryNested only supports relative locktimes.
    if !matches!(locktime, Locktime::Relative(_)) {
        return None;
    }
    let threshold = uniform_set_size(sets)?;
    if !sets_distinct(sets) {
        return None;
    }
    let leaves_count = sets.len();
    let key_usage_count = key_usage_count(sets);
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
    if count_nested_combinations(m, mt, n, t) != Some(leaves_count) {
        return None;
    }
    let mandatory: HashSet<&OXpub> = mandatory_oxpubs.iter().collect();
    if sets
        .iter()
        .any(|set| set.iter().filter(|k| mandatory.contains(k)).count() != mt)
    {
        return None;
    }
    // The canonical rule mt*n < t*m is guaranteed by cnt_low < cnt_high (lower
    // per-class frequency goes to the mandatory side).

    mandatory_oxpubs.sort();
    cosigner_oxpubs.sort();
    Some(Path::new(
        Semantic::MultiMandatoryNested {
            mandatory_keys: mandatory_oxpubs,
            mandatory_threshold: mt,
            keys: cosigner_oxpubs,
            threshold: t,
        },
        locktime,
        leaves_position(leaves),
    ))
}

impl Path {
    /// Return `Some` if `leaves` are the flattened leaf set of a `MultiMandatory` path.
    pub fn try_from_mandatory_multi(leaves: &[LeafEntry]) -> Option<Self> {
        if leaves.len() < 2 {
            return None;
        }
        let (sets, locktime) = leaf_shape_key_sets(leaves)?;
        mandatory_from_key_sets(leaves, &sets, locktime)
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
        let (sets, locktime) = leaf_shape_key_sets(leaves)?;
        nested_from_key_sets(leaves, &sets, locktime)
    }
}

/// The key of a `pk(K)` leaf, alone or ANDed with one `older()` / `after()`.
#[cfg(feature = "musig")]
fn leaf_key(ms: &Miniscript<WalletKey, Tap>) -> Result<Option<(WalletKey, Locktime)>, PolicyError> {
    let lifted = ms.lift().map_err(PolicyError::Miniscript)?.normalized();
    match lifted {
        SemanticPolicy::Key(k) => Ok(Some((k, Locktime::None))),
        SemanticPolicy::Thresh(t) if t.k() == 2 && t.n() == 2 => {
            match (t.data()[0].as_ref(), t.data()[1].as_ref()) {
                (SemanticPolicy::Key(k), other) | (other, SemanticPolicy::Key(k)) => {
                    Ok(try_into_locktime(other).map(|lt| (k.clone(), lt)))
                }
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// The signers of a [`leaf_key`] leaf: the participants of a musig() key, or the plain key.
#[cfg(feature = "musig")]
fn leaf_key_set(
    ms: &Miniscript<WalletKey, Tap>,
) -> Result<Option<(Vec<OXpub>, Locktime)>, PolicyError> {
    let Some((key, locktime)) = leaf_key(ms)? else {
        return Ok(None);
    };
    let set = match &key {
        MusigKey::Musig(aggregate) => musig_participants(aggregate)?.0,
        MusigKey::Plain(_) => match oxpub(&key) {
            Some(o) => vec![o],
            None => return Ok(None),
        },
    };
    Ok(Some((set, locktime)))
}

/// Whether the MuSig2 reader lifts `leaves`: one of them holds a musig() key, or there are
/// at least two leaves that are each one plain key.
#[cfg(feature = "musig")]
fn is_musig_group(leaves: &[LeafEntry]) -> Result<bool, PolicyError> {
    if leaves.iter().any(|e| e.ms.iter_pk().any(|k| k.is_musig())) {
        return Ok(true);
    }
    if leaves.len() < 2 {
        return Ok(false);
    }
    for leaf in leaves {
        match leaf_key(leaf.ms)? {
            Some((key, _)) if plain_key(&key).is_some() => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// Lift the key sets of a MuSig2 group: `Multi`, then `MultiMandatory`, then
/// `MultiMandatoryNested`.
#[cfg(feature = "musig")]
fn musig_key_sets_to_path(
    leaves: &[LeafEntry],
    sets: &[Vec<OXpub>],
    locktime: Locktime,
) -> Option<Path> {
    if let Some(path) = multi_from_key_sets(leaves, sets, locktime.clone()) {
        return Some(path);
    }
    if leaves.len() < 2 || sets[0].len() < 2 {
        return None;
    }
    mandatory_from_key_sets(leaves, sets, locktime.clone())
        .or_else(|| nested_from_key_sets(leaves, sets, locktime))
}

/// Lift a group of `pk(musig(S))` / `pk(K)` leaves (in cursor order) to the path they
/// compile from. `Ok(None)` when the leaves share no locktime, fit no shape, or the shape
/// does not sit in the zone of the first and last leaves.
#[cfg(feature = "musig")]
fn group_to_musig_path(leaves: &[LeafEntry]) -> Result<Option<Path>, PolicyError> {
    let Some(first) = leaves.first() else {
        return Ok(None);
    };
    let mut sets: Vec<Vec<OXpub>> = Vec::with_capacity(leaves.len());
    let mut locktimes: Vec<Locktime> = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let Some((set, locktime)) = leaf_key_set(leaf.ms)? else {
            return Ok(None);
        };
        sets.push(set);
        locktimes.push(locktime);
    }
    let locktime = locktimes[0].clone();
    if locktimes.iter().any(|lt| *lt != locktime) {
        return Ok(None);
    }
    let Some(path) = musig_key_sets_to_path(leaves, &sets, locktime) else {
        return Ok(None);
    };
    let zone = path.semantic().starting_index(path.locktime());
    for leaf in [first, &leaves[leaves.len() - 1]] {
        let Some(index) = leaf.get_index()? else {
            return Ok(None);
        };
        if zone != Some(index - index % MULTIPATH_SEMANTIC_FACTOR) {
            return Ok(None);
        }
    }
    Ok(Some(path))
}

/// Path satisfaction WU at tap-tree `depth`. Sums miniscript's `max_satisfaction_size`,
/// `script_size`, the script length-prefix, and the control block (`1 + 33 + 32 * depth`).
/// `None` if miniscript can't size the satisfaction.
pub fn compute_satisfaction_wu(leaf_ms: &Miniscript<WalletKey, Tap>, depth: u8) -> Option<u64> {
    let sat_size = leaf_ms.max_satisfaction_size().ok()? as u64;
    let script_size = leaf_ms.script_size() as u64;
    let control_block_wu = 1 + 33 + 32 * (depth as u64);
    let script_prefix_wu = 1;
    Some(sat_size + script_size + script_prefix_wu + control_block_wu)
}

/// Convert a logical group of leaves into a single [`Path`]. Fails if the group is empty or
/// cannot be classified into a known path shape. With `musig`, a group holding a musig()
/// key, or made of two or more one-plain-key leaves, is lifted by the MuSig2 rules; a lone
/// leaf they do not lift is classified alone (`Semantic::Unknown`).
pub fn group_to_path(leaves: &[LeafEntry]) -> Result<Path, PolicyError> {
    #[cfg(feature = "musig")]
    if is_musig_group(leaves)? {
        if let Some(p) = group_to_musig_path(leaves)? {
            return Ok(p);
        }
        if leaves.len() > 1 {
            return Err(PolicyError::UnrecognizedLeafGroup);
        }
    }
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

/// Pick the [`PolicyType`] that fits a path set, from its paths' semantics and
/// locktimes only (positions, orders and keys are not looked at):
/// - `Unknown` for an empty set, any `Semantic::Unknown` path, an absolute locktime next
///   to a `MultiMandatory` or `MultiMandatoryNested` path, or both mandatory flavors in
///   one set;
/// - otherwise `PrimaryOnly` for a lone locktime-free `Single` or `Multi` path;
/// - otherwise `Invalid` when absolute and relative locktimes mix, or when no path has
///   a locktime;
/// - otherwise `Cltv` for absolute locktimes, and for relative ones
///   `CsvWithMandatoryKey` with a `MultiMandatory` path, `CsvWithNestedMandatory` with a
///   `MultiMandatoryNested` path, else `Csv`.
pub fn infer_policy_type(paths: &[Path]) -> PolicyType {
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
        (false, false, false, false, false) if is_primary_only(paths) => PolicyType::PrimaryOnly,
        (true, true, _, _, _) | (false, false, _, _, _) => PolicyType::Invalid,
        (true, false, false, false, false) => PolicyType::Cltv,
        (false, true, false, true, false) => PolicyType::CsvWithMandatoryKey,
        (false, true, false, false, true) => PolicyType::CsvWithNestedMandatory,
        (false, true, false, false, false) => PolicyType::Csv,
    }
}

/// Whether `paths` is the lone locktime-free `Single` or `Multi` path of a
/// [`PolicyType::PrimaryOnly`] policy.
pub(crate) fn is_primary_only(paths: &[Path]) -> bool {
    match paths {
        [p] => {
            matches!(p.locktime(), Locktime::None)
                && matches!(p.semantic(), Semantic::Single(_) | Semantic::Multi { .. })
        }
        _ => false,
    }
}
