//! Compiler-side helpers used by `Policy::compile`.

use std::{convert::TryFrom, sync};

use bwk_descriptor::wallet::WalletKey;
#[cfg(not(feature = "musig"))]
use miniscript::Threshold;
use miniscript::{policy::Concrete as ConcretePolicy, AbsLockTime, Miniscript, RelLockTime, Tap};

use crate::{
    multipath::{deriv_paths_starting_at, wallet_key},
    parse::oxpub_to_key,
    path::{Locktime, OXpub, Path, Semantic},
    policy::{PolicyError, PolicyType},
};

/// Every choice of `k` key indices out of `n`, in lexicographic order. Each choice is
/// one tap leaf of a k-of-n split.
///
/// Example for `split_m_of_n(3, 2)` (2-of-3):
///   `[[0, 1], [0, 2], [1, 2]]`
/// → three tap leaves: `thresh(2, k0, k1)`, `thresh(2, k0, k2)`, `thresh(2, k1, k2)`
/// without `musig`, `pk(musig(k0, k1))`, `pk(musig(k0, k2))`, `pk(musig(k1, k2))` with it.
fn split_m_of_n(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(k);
    fn rec(start: usize, n: usize, k: usize, buf: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if buf.len() == k {
            out.push(buf.clone());
            return;
        }
        let need = k - buf.len();
        for i in start..=n.saturating_sub(need) {
            buf.push(i);
            rec(i + 1, n, k, buf, out);
            buf.pop();
        }
    }
    rec(0, n, k, &mut buf, &mut out);
    out
}

fn single_to_miniscript_policy(k: &OXpub, cursor: &mut u32) -> ConcretePolicy<WalletKey> {
    let group = deriv_paths_starting_at(*cursor);
    *cursor += 2;
    ConcretePolicy::Key(wallet_key(oxpub_to_key(k, group)))
}

#[cfg(not(feature = "musig"))]
fn multi_to_miniscript_policy(
    keys: &[OXpub],
    threshold: usize,
    cursor: &mut u32,
) -> Result<ConcretePolicy<WalletKey>, PolicyError> {
    let group = deriv_paths_starting_at(*cursor);
    *cursor += 2;
    let subs: Vec<sync::Arc<ConcretePolicy<WalletKey>>> = keys
        .iter()
        .map(|k| {
            sync::Arc::new(ConcretePolicy::Key(wallet_key(oxpub_to_key(
                k,
                group.clone(),
            ))))
        })
        .collect();
    Ok(ConcretePolicy::Thresh(
        Threshold::new(threshold, subs)
            .map_err(|e| PolicyError::Miniscript(miniscript::Error::Threshold(e)))?,
    ))
}

/// The leaf fragments of a [`Semantic::Multi`]: one `thresh(threshold, keys)`.
#[cfg(not(feature = "musig"))]
fn multi_fragments(
    keys: &[OXpub],
    threshold: usize,
    cursor: &mut u32,
) -> Result<Vec<ConcretePolicy<WalletKey>>, PolicyError> {
    Ok(vec![multi_to_miniscript_policy(keys, threshold, cursor)?])
}

/// The leaf fragments of a [`Semantic::Multi`]: one leaf per `threshold`-subset.
#[cfg(feature = "musig")]
fn multi_fragments(
    keys: &[OXpub],
    threshold: usize,
    cursor: &mut u32,
) -> Result<Vec<ConcretePolicy<WalletKey>>, PolicyError> {
    leaf_policies(multi_key_sets(keys, threshold), cursor)
}

/// One key set per `threshold`-subset of `keys`, in `split_m_of_n` order.
#[cfg(feature = "musig")]
fn multi_key_sets(keys: &[OXpub], threshold: usize) -> Vec<Vec<OXpub>> {
    split_m_of_n(keys.len(), threshold)
        .into_iter()
        .map(|subset| subset.into_iter().map(|i| keys[i].clone()).collect())
        .collect()
}

/// The key sets of a [`Semantic::MultiMandatoryNested`], one per
/// `(mk_subset, k_subset)` pair, mandatory part then cosigner part. Enumeration order:
/// outer loop walks `split_m_of_n(mandatory_keys.len(), mandatory_threshold)`, inner
/// loop walks `split_m_of_n(keys.len(), threshold)`. Returns
/// `C(mandatory_keys.len(), mandatory_threshold) * C(keys.len(), threshold)` sets.
fn nested_key_sets(
    mandatory_keys: &[OXpub],
    mandatory_threshold: usize,
    keys: &[OXpub],
    threshold: usize,
) -> Result<Vec<Vec<OXpub>>, PolicyError> {
    let m = mandatory_keys.len();
    let n = keys.len();
    let mt = mandatory_threshold;
    let t = threshold;
    // Defensive guard mirroring `Semantic::validate`: sanitize already rejects
    // `==` (ambiguous frequencies) and `>` (non-canonical), so `>=` here is loose
    // but behaviorally equivalent: it also catches the `==` case if invoked
    // outside the sanitize path.
    if mt == 0 || mt >= m || t == 0 || t >= n || mt * n >= t * m {
        return Err(PolicyError::InconsistentPathsForType(PolicyType::Unknown));
    }
    let mk_subsets = split_m_of_n(m, mt);
    let k_subsets = split_m_of_n(n, t);
    let mut sets = Vec::with_capacity(mk_subsets.len() * k_subsets.len());
    for mk_subset in &mk_subsets {
        for k_subset in &k_subsets {
            let mut set = Vec::with_capacity(mt + t);
            set.extend(mk_subset.iter().map(|&i| mandatory_keys[i].clone()));
            set.extend(k_subset.iter().map(|&i| keys[i].clone()));
            sets.push(set);
        }
    }
    Ok(sets)
}

/// The key sets of a [`Semantic::MultiMandatory`], one per cosigner subset: every
/// mandatory key then the subset's keys.
fn mandatory_key_sets(
    keys: &[OXpub],
    mandatory_keys: &[OXpub],
    threshold: usize,
) -> Result<Vec<Vec<OXpub>>, PolicyError> {
    let m = mandatory_keys.len();
    let n = keys.len();
    if threshold <= m || threshold > m + n {
        return Err(PolicyError::InvalidMandatoryThreshold {
            threshold,
            mandatory_count: m,
            cosigner_count: n,
        });
    }
    let cosigner_threshold = threshold - m;
    let subsets = split_m_of_n(n, cosigner_threshold);
    if subsets.is_empty() {
        return Err(PolicyError::InconsistentPathsForType(
            PolicyType::CsvWithMandatoryKey,
        ));
    }
    Ok(subsets
        .into_iter()
        .map(|subset| {
            let mut set = mandatory_keys.to_vec();
            set.extend(subset.into_iter().map(|i| keys[i].clone()));
            set
        })
        .collect())
}

/// The leaf every key of `set` must sign, on the group at `cursor`, then `cursor += 2`:
/// `thresh(set.len(), set)` without `musig`.
#[cfg(not(feature = "musig"))]
fn leaf_policy(set: &[OXpub], cursor: &mut u32) -> Result<ConcretePolicy<WalletKey>, PolicyError> {
    multi_to_miniscript_policy(set, set.len(), cursor)
}

/// The leaf every key of `set` must sign, on the group at `cursor`, then `cursor += 2`:
/// `pk(K)` for one key, `pk(musig(set))` for more.
#[cfg(feature = "musig")]
fn leaf_policy(set: &[OXpub], cursor: &mut u32) -> Result<ConcretePolicy<WalletKey>, PolicyError> {
    let start = *cursor;
    *cursor += 2;
    match set {
        [key] => Ok(ConcretePolicy::Key(wallet_key(oxpub_to_key(
            key,
            deriv_paths_starting_at(start),
        )))),
        _ => Ok(ConcretePolicy::Key(crate::musig::musig_key(set, start)?)),
    }
}

/// [`leaf_policy`] over `sets`, in order.
fn leaf_policies(
    sets: Vec<Vec<OXpub>>,
    cursor: &mut u32,
) -> Result<Vec<ConcretePolicy<WalletKey>>, PolicyError> {
    sets.iter().map(|set| leaf_policy(set, cursor)).collect()
}

pub(super) type TapLeaves = (Vec<Miniscript<WalletKey, Tap>>, Vec<u32>);

/// Emit one or more `Miniscript<WalletKey, Tap>` leaves for `path`, advancing
/// `cursor` per the `+2` (intra-leaf) / `+4` (between-path) convention. For typed shapes
/// the path's `Locktime` is AND'd into a `ConcretePolicy` and then compiled to Miniscript.
/// Without `musig` a `Multi` is one `multi_a` leaf and each mandatory subset one
/// `thresh` leaf; with `musig` every multisig leaf is `pk(musig(..))` over one key set
/// (a one-key set is a plain `pk(K)`), one leaf per subset.
/// `Semantic::Custom(ms)` bypasses the `ConcretePolicy` pipeline entirely: the consumer-
/// provided miniscript is emitted as-is. Multipath indices on the embedded keys are the
/// consumer's responsibility: the compiler does not rewrite them. Custom paths require
/// `Locktime::None`; the consumer embeds any locktime gate inside the miniscript.
pub(super) fn path_into_fragments(path: &Path, cursor: &mut u32) -> Result<TapLeaves, PolicyError> {
    let start = *cursor;

    if let Semantic::Custom(ms) = path.semantic() {
        // Reserve a multipath slot + boundary so the rest of the cursor allocation stays
        // consistent across Custom and typed paths. The consumer's keys do NOT land at
        // `start`: they keep whatever multipath the consumer baked into the miniscript.
        *cursor += 4;
        return Ok((vec![ms.clone()], vec![start]));
    }

    let mut frags: Vec<ConcretePolicy<WalletKey>> = match path.semantic() {
        Semantic::Single(k) => vec![single_to_miniscript_policy(k, cursor)],
        Semantic::Multi { keys, threshold } => multi_fragments(keys, *threshold, cursor)?,
        Semantic::MultiMandatory {
            keys,
            mandatory_keys,
            threshold,
        } => leaf_policies(
            mandatory_key_sets(keys, mandatory_keys, *threshold)?,
            cursor,
        )?,
        Semantic::MultiMandatoryNested {
            mandatory_keys,
            mandatory_threshold,
            keys,
            threshold,
        } => leaf_policies(
            nested_key_sets(mandatory_keys, *mandatory_threshold, keys, *threshold)?,
            cursor,
        )?,
        Semantic::Custom(_) => unreachable!("handled above"),
        Semantic::Unknown { .. } | Semantic::Or(_) => {
            return Err(PolicyError::InconsistentPathsForType(PolicyType::Unknown));
        }
    };
    let indices: Vec<u32> = (start..*cursor).step_by(2).collect();

    // AND each fragment with the path's locktime.
    frags = match path.locktime() {
        Locktime::None => frags,
        Locktime::Relative(rl) => {
            let raw = rl.to_consensus_u32();
            let height: u16 = u16::try_from(raw).map_err(|_| PolicyError::InsaneTimelock(raw))?;
            let lt = ConcretePolicy::Older(RelLockTime::from_height(height));
            frags
                .into_iter()
                .map(|f| ConcretePolicy::And(vec![sync::Arc::new(f), sync::Arc::new(lt.clone())]))
                .collect()
        }
        Locktime::AbsoluteRenewable(al) | Locktime::Absolute(al) => {
            let h = al.to_consensus_u32();
            let abs = AbsLockTime::from_consensus(h).map_err(|_| PolicyError::InsaneTimelock(h))?;
            let lt = ConcretePolicy::After(abs);
            frags
                .into_iter()
                .map(|f| ConcretePolicy::And(vec![sync::Arc::new(f), sync::Arc::new(lt.clone())]))
                .collect()
        }
    };

    // `+2` boundary so the next path starts at +4 from this path's first leaf group.
    *cursor += 2;

    let leaves: Vec<Miniscript<WalletKey, Tap>> = frags
        .into_iter()
        .map(|f| {
            f.compile::<Tap>()
                .map_err(|e| PolicyError::Miniscript(e.into()))
        })
        .collect::<Result<_, _>>()?;
    Ok((leaves, indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multipath::plain_key,
        path::{OXpub, TapPosition},
    };
    use miniscript::{
        bitcoin::{absolute, relative},
        DescriptorPublicKey,
    };
    use std::str::FromStr;

    fn oxpub_from_str(s: &str) -> OXpub {
        let DescriptorPublicKey::MultiXPub(x) = DescriptorPublicKey::from_str(s).unwrap() else {
            panic!("expected MultiXPub");
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

    fn k3() -> OXpub {
        oxpub_from_str(
            "[abcdef03]xpub6Bw79HbNSeS2xXw1sngPE3ehnk1U3iSPCgLYzC9LpN8m9nDuaKLZvkg8QXxL5pDmEmQtYscmUD8B9MkAAZbh6vxPzNXMaLfGQ9Sb3z85qhR/<0;1>/*",
        )
    }

    fn k4() -> OXpub {
        oxpub_from_str(
            "[abcdef04]xpub661MyMwAqRbcF2FpaYbnrN7K6uPhiwg5u1LiqmsMSTnphuhQzpPv9RGdERxDd7pnnrEC8hxttAPi4wbSVsKeJYiHYymfpuxSD7TALTXqjq6/<0;1>/*",
        )
    }

    /// Read the two multipath-leg indices off a Key fragment. Asserts the wrapped key is a
    /// `MultiXPub` with exactly two single-step paths and returns `(idx0, idx1)`.
    fn key_indices(p: &ConcretePolicy<WalletKey>) -> (u32, u32) {
        let ConcretePolicy::Key(k) = p else {
            panic!("expected Key(MultiXPub)");
        };
        let Some(DescriptorPublicKey::MultiXPub(m)) = plain_key(k) else {
            panic!("expected Key(MultiXPub)");
        };
        let paths = m.derivation_paths.paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].len(), 1);
        assert_eq!(paths[1].len(), 1);
        (u32::from(paths[0][0]), u32::from(paths[1][0]))
    }

    // split_m_of_n

    #[test]
    fn split_m_of_n_three_two() {
        // Canonical 2-of-3.
        assert_eq!(split_m_of_n(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
    }

    #[test]
    fn split_m_of_n_four_two() {
        // All 6 lexicographic pairs from {0,1,2,3}.
        assert_eq!(
            split_m_of_n(4, 2),
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3],
            ]
        );
    }

    #[test]
    fn split_m_of_n_full_set() {
        assert_eq!(split_m_of_n(3, 3), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn split_m_of_n_empty_subset() {
        // k = 0 yields a single empty subset.
        assert_eq!(split_m_of_n(3, 0), vec![Vec::<usize>::new()]);
    }

    #[test]
    fn split_m_of_n_k_greater_than_n() {
        assert!(split_m_of_n(2, 3).is_empty());
    }

    // single_to_miniscript_policy

    #[test]
    fn single_advances_cursor_by_two() {
        let mut cursor = 10;
        let pol = single_to_miniscript_policy(&k1(), &mut cursor);
        assert_eq!(cursor, 12);
        assert_eq!(key_indices(&pol), (10, 11));
    }

    // multi_to_miniscript_policy

    #[test]
    #[cfg(not(feature = "musig"))]
    fn multi_two_of_three_shared_group_cursor_plus_two() {
        let mut cursor = 100;
        let pol = multi_to_miniscript_policy(&[k1(), k2(), k3()], 2, &mut cursor).unwrap();
        assert_eq!(cursor, 102);
        let ConcretePolicy::Thresh(t) = &pol else {
            panic!("expected Thresh");
        };
        assert_eq!(t.k(), 2);
        let subs = t.data();
        assert_eq!(subs.len(), 3);
        // All three sub-keys share the same (100, 101) derivation-path group.
        for sub in subs {
            assert_eq!(key_indices(sub.as_ref()), (100, 101));
        }
    }

    #[test]
    #[cfg(not(feature = "musig"))]
    fn multi_one_of_one_degenerate() {
        let mut cursor = 0;
        let pol = multi_to_miniscript_policy(&[k1()], 1, &mut cursor).unwrap();
        assert_eq!(cursor, 2);
        let ConcretePolicy::Thresh(t) = &pol else {
            panic!("expected Thresh");
        };
        assert_eq!(t.k(), 1);
        assert_eq!(t.data().len(), 1);
    }

    #[test]
    #[cfg(not(feature = "musig"))]
    fn multi_invalid_threshold_propagates_miniscript_error() {
        let mut cursor = 0;
        // threshold > keys.len() makes miniscript's Threshold::new reject.
        let err = multi_to_miniscript_policy(&[k1(), k2()], 5, &mut cursor).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::Miniscript(miniscript::Error::Threshold(_))
            ),
            "got {err:?}"
        );
    }

    // mandatory_key_sets + leaf_policies

    #[test]
    #[cfg(not(feature = "musig"))]
    fn mandatory_one_mand_two_cosigners_threshold_two() {
        // m=1, n=2, threshold=2 → cosigner_threshold = 1 → C(2,1)=2 leaves.
        let mut cursor = 50;
        let leaves = leaf_policies(
            mandatory_key_sets(&[k2(), k3()], &[k1()], 2).unwrap(),
            &mut cursor,
        )
        .unwrap();
        assert_eq!(leaves.len(), 2);
        // Each leaf consumes 2 multipath slots; cursor advanced by 4.
        assert_eq!(cursor, 54);
        // First leaf: [k1, k2] sharing group (50, 51).
        // Second leaf: [k1, k3] sharing group (52, 53).
        let expected_groups = [(50, 51), (52, 53)];
        for (leaf, group) in leaves.iter().zip(expected_groups.iter()) {
            let ConcretePolicy::Thresh(t) = leaf else {
                panic!("expected Thresh");
            };
            assert_eq!(t.k(), 2);
            let subs = t.data();
            assert_eq!(subs.len(), 2);
            for sub in subs {
                assert_eq!(key_indices(sub.as_ref()), *group);
            }
        }
    }

    #[test]
    fn mandatory_one_mand_three_cosigners_threshold_three() {
        // m=1, n=3, threshold=3 → cosigner_threshold = 2 → C(3,2)=3 leaves.
        let mut cursor = 0;
        let leaves = leaf_policies(
            mandatory_key_sets(&[k2(), k3(), k4()], &[k1()], 3).unwrap(),
            &mut cursor,
        )
        .unwrap();
        assert_eq!(leaves.len(), 3);
        assert_eq!(cursor, 6);
    }

    #[test]
    fn mandatory_threshold_equal_to_m_rejected() {
        let err = mandatory_key_sets(&[k2(), k3()], &[k1()], 1).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InvalidMandatoryThreshold {
                    threshold: 1,
                    mandatory_count: 1,
                    cosigner_count: 2,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn mandatory_threshold_above_m_plus_n_rejected() {
        let err = mandatory_key_sets(&[k2(), k3()], &[k1()], 4).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InvalidMandatoryThreshold {
                    threshold: 4,
                    mandatory_count: 1,
                    cosigner_count: 2,
                }
            ),
            "got {err:?}"
        );
    }

    // path_into_fragments

    fn single_path(locktime: Locktime) -> Path {
        Path::new(
            Semantic::Single(k1()),
            locktime,
            TapPosition::TapTree(vec![]),
        )
    }

    #[test]
    fn fragments_single_no_locktime_advances_cursor_by_four() {
        let p = single_path(Locktime::None);
        let mut cursor = 200;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(indices, vec![200]);
        // +2 for the leaf group, +2 for the inter-path boundary.
        assert_eq!(cursor, 204);
        let s = frags[0].to_string();
        assert!(s.starts_with("pk("), "expected pk(...) leaf, got {s}");
    }

    #[test]
    #[cfg(not(feature = "musig"))]
    fn fragments_multi_two_of_three_one_fragment() {
        let p = Path::new(
            Semantic::Multi {
                keys: vec![k1(), k2(), k3()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 0;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(indices, vec![0]);
        assert_eq!(cursor, 4);
        let s = frags[0].to_string();
        assert!(s.contains("multi_a(2,"), "expected multi_a(2,...), got {s}");
    }

    #[test]
    fn fragments_mandatory_indices_step_by_two() {
        // 1 mandatory + 2 cosigners, threshold 2 → 2 leaves, indices at start and start+2.
        let p = Path::new(
            Semantic::MultiMandatory {
                keys: vec![k2(), k3()],
                mandatory_keys: vec![k1()],
                threshold: 2,
            },
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 1000;
        let (frags, indices) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(indices, vec![1000, 1002]);
        // 2 leaves * 2 + boundary 2 = 6.
        assert_eq!(cursor, 1006);
    }

    #[test]
    fn fragments_relative_locktime_wraps_with_older() {
        let p = single_path(Locktime::Relative(relative::LockTime::from_height(144)));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        assert_eq!(frags.len(), 1);
        let s = frags[0].to_string();
        assert!(
            s.contains("older(144)"),
            "expected older(144) in leaf, got {s}"
        );
        assert!(s.contains("pk("), "expected pk(...) in leaf, got {s}");
    }

    #[test]
    fn fragments_absolute_locktime_wraps_with_after() {
        let p = single_path(Locktime::Absolute(
            absolute::LockTime::from_height(500_000).unwrap(),
        ));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        let s = frags[0].to_string();
        assert!(
            s.contains("after(500000)"),
            "expected after(500000), got {s}"
        );
    }

    #[test]
    fn fragments_absolute_renewable_uses_same_after_branch() {
        let p = single_path(Locktime::AbsoluteRenewable(
            absolute::LockTime::from_height(500_000).unwrap(),
        ));
        let mut cursor = 0;
        let (frags, _) = path_into_fragments(&p, &mut cursor).unwrap();
        let s = frags[0].to_string();
        assert!(
            s.contains("after(500000)"),
            "expected after(500000), got {s}"
        );
    }

    #[test]
    fn fragments_or_semantic_rejected() {
        let p = Path::new(
            Semantic::Or(vec![Semantic::Single(k1()), Semantic::Single(k2())]),
            Locktime::None,
            TapPosition::TapTree(vec![]),
        );
        let mut cursor = 0;
        let err = path_into_fragments(&p, &mut cursor).unwrap_err();
        assert!(
            matches!(
                err,
                PolicyError::InconsistentPathsForType(PolicyType::Unknown)
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn fragments_cursor_continues_across_paths_with_plus_four_boundary() {
        // Run two consecutive single-path calls and assert the inter-path boundary: the
        // second path's first index sits exactly 4 above the first path's last index.
        let p1 = single_path(Locktime::None);
        let p2 = single_path(Locktime::Relative(relative::LockTime::from_height(144)));
        let mut cursor = 0;
        let (_, indices1) = path_into_fragments(&p1, &mut cursor).unwrap();
        let (_, indices2) = path_into_fragments(&p2, &mut cursor).unwrap();
        let last1 = *indices1.last().unwrap();
        let first2 = indices2[0];
        assert_eq!(first2, last1 + 4);
    }
}
