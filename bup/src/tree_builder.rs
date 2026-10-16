//! Tap-tree builder used by `Policy::compile`.
//!
//! Each [`SubTree<T>`] is created with a fixed shape: a flat `Vec<Slot<T>>` whose
//! per-slot depths are decided at creation. Slots start as `Leaf` (for the path's
//! leaves at `leaf_depth`) or `Free` (for trailing pruned chunks at varying depths).
//! Subsequent `place_path` calls and the padding pass mutate slot contents from
//! `Free` to `Leaf` or `Link`. DFS walks just iterate the Vec.

use std::sync;

use bwk_descriptor::wallet::WalletKey;
use miniscript::{
    bitcoin::{
        bip32,
        hashes::{sha256, Hash},
        network::NetworkKind,
    },
    descriptor::{self, TapTree},
    policy::Concrete as ConcretePolicy,
    DescriptorPublicKey, Miniscript, Tap,
};

use crate::{
    multipath::{deriv_paths_starting_at, nums_slot_paths, wallet_key, NUMS_SLOTS},
    nums::{bip341_nums, chain_code_xkey},
    parse::oxpub_to_key,
    path::{Path, Semantic, TapPosition},
    policy::PolicyError,
};

/// Errors returned by the generic [`TreeBuilder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeBuilderError {
    /// `place_path` was called with an empty `leaves` slice.
    EmptyLeaves,
}

impl std::fmt::Display for TreeBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLeaves => write!(f, "place_path called with no leaves"),
        }
    }
}

impl std::error::Error for TreeBuilderError {}

#[derive(Debug, Clone)]
enum Content<T> {
    Leaf(T),
    Link(usize),
    Free,
}

#[derive(Debug, Clone)]
struct Slot<T> {
    /// Absolute depth of this slot in the tap tree.
    depth: u8,
    content: Content<T>,
}

#[derive(Debug)]
struct SubTree<T> {
    /// Slots in DFS order. The leftmost slots are the path's leaves at the subtree's
    /// leaf depth; the rest are chunk slots at canonically pruned depths (one per set
    /// bit of `m_initial = size - initial_leaves`, deepest first).
    slots: Vec<Slot<T>>,
}

impl<T> SubTree<T> {
    /// Build a `SubTree` rooted at `parent_depth`, containing `leaves` and reserving
    /// `slack_after` extra positions (rounded up to the next power of two). The slot
    /// layout (positions and per-slot depths) is computed once and never recomputed.
    fn new(leaves: Vec<T>, slack_after: usize, parent_depth: u8) -> Self {
        let initial_leaves = leaves.len();
        let size = (initial_leaves + slack_after).next_power_of_two();
        let size_log2 = size.trailing_zeros() as u8;
        let leaf_depth = parent_depth + size_log2;
        let m_initial = size - initial_leaves;

        let mut slots: Vec<Slot<T>> = leaves
            .into_iter()
            .map(|t| Slot {
                depth: leaf_depth,
                content: Content::Leaf(t),
            })
            .collect();
        for j in 0..size_log2 {
            if (m_initial >> j) & 1 == 1 {
                slots.push(Slot {
                    depth: leaf_depth - j,
                    content: Content::Free,
                });
            }
        }

        Self { slots }
    }

    fn free_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s.content, Content::Free))
            .count()
    }
}

/// Generic tap-tree placement engine.
pub(super) struct TreeBuilder<T> {
    subtrees: Vec<SubTree<T>>,
}

/// What [`TreeBuilder::dfs_slots`] yields per slot in tap-tree iteration order.
pub(super) enum DfsSlot<'a, T> {
    Free,
    Leaf(&'a T),
}

/// Generic balanced binary tree. The descriptor layer converts it to `TapTree`.
#[derive(Debug)]
pub(super) enum Tree<T> {
    Leaf(T),
    Branch(Box<Tree<T>>, Box<Tree<T>>),
}

impl<T: Clone> TreeBuilder<T> {
    pub(super) fn new() -> Self {
        Self {
            subtrees: Vec::new(),
        }
    }

    /// Place `leaves` into a single subtree (so all leaves end at the same depth).
    /// `more_after = true` means the caller will place at least one more path; the
    /// builder reserves enough free capacity so the next call always has a home.
    ///
    /// Returns [`TreeBuilderError::EmptyLeaves`] if `leaves` is empty.
    pub(super) fn place_path(
        &mut self,
        leaves: &[T],
        more_after: bool,
    ) -> Result<(), TreeBuilderError> {
        if leaves.is_empty() {
            return Err(TreeBuilderError::EmptyLeaves);
        }
        let leaves_count = leaves.len();
        let slack_after = if more_after { 1 } else { 0 };

        // First-path bootstrap.
        if self.subtrees.is_empty() {
            self.subtrees
                .push(SubTree::new(leaves.to_vec(), slack_after, 0));
            return Ok(());
        }

        // Sub-subtree attach: pick the Free slot that produces the shallowest leaves.
        // `new_size` is uniform across slots in a single call, so `new_path_depth =
        // slot.depth + log2(new_size)` is monotonic in `slot.depth`, no ties between
        // slots at different depths, and ties at the same depth resolve to whichever
        // we encounter first.
        let leaves_floor = leaves_count.next_power_of_two();
        let total_slack: usize = self.subtrees.iter().map(|s| s.free_slots()).sum();

        let mut best: Option<(usize, usize, usize, u8)> = None;
        for (sidx, sub) in self.subtrees.iter().enumerate() {
            for (slot_idx, slot) in sub.slots.iter().enumerate() {
                if !matches!(slot.content, Content::Free) {
                    continue;
                }
                let mut new_size = leaves_floor;
                if more_after {
                    let post_existing = total_slack - 1;
                    let post_new = (new_size - leaves_count).count_ones() as usize;
                    if post_existing + post_new < 1 {
                        new_size *= 2;
                    }
                }
                let new_path_depth = slot.depth + (new_size.trailing_zeros() as u8);
                if best.is_none_or(|(_, _, _, b_depth)| new_path_depth < b_depth) {
                    best = Some((sidx, slot_idx, new_size, new_path_depth));
                }
            }
        }
        let (host_idx, slot_idx, new_size, _) =
            best.expect("at least one Free slot fits the new path");
        let chunk_depth = self.subtrees[host_idx].slots[slot_idx].depth;
        let new_idx = self.subtrees.len();
        self.subtrees.push(SubTree::new(
            leaves.to_vec(),
            new_size - leaves_count,
            chunk_depth,
        ));
        self.subtrees[host_idx].slots[slot_idx].content = Content::Link(new_idx);

        Ok(())
    }

    /// Visit slots in tap-tree iteration order (DFS). Each Free slot is one
    /// `DfsSlot::Free` (regardless of the slot's chunk capacity).
    pub(super) fn dfs_slots<F: FnMut(DfsSlot<'_, T>)>(&self, mut visit: F) {
        if !self.subtrees.is_empty() {
            self.dfs_slots_rec(0, &mut visit);
        }
    }

    fn dfs_slots_rec<F: FnMut(DfsSlot<'_, T>)>(&self, idx: usize, visit: &mut F) {
        for slot in &self.subtrees[idx].slots {
            match &slot.content {
                Content::Leaf(t) => visit(DfsSlot::Leaf(t)),
                Content::Link(j) => self.dfs_slots_rec(*j, visit),
                Content::Free => visit(DfsSlot::Free),
            }
        }
    }

    /// Replace every Free slot with a single-leaf sub-subtree at the slot's depth.
    /// The padding closure is called once per Free slot in DFS order, so the caller
    /// can number the padding leaves.
    pub(super) fn fill_free_with<F: FnMut() -> T>(&mut self, mut pad_fn: F) {
        if self.subtrees.is_empty() {
            return;
        }
        self.fill_free_rec(0, &mut pad_fn);
    }

    fn fill_free_rec<F: FnMut() -> T>(&mut self, idx: usize, pad_fn: &mut F) {
        let len = self.subtrees[idx].slots.len();
        for i in 0..len {
            match self.subtrees[idx].slots[i].content {
                Content::Free => {
                    let slot_depth = self.subtrees[idx].slots[i].depth;
                    let leaf = pad_fn();
                    let new_idx = self.subtrees.len();
                    self.subtrees.push(SubTree::new(vec![leaf], 0, slot_depth));
                    self.subtrees[idx].slots[i].content = Content::Link(new_idx);
                }
                Content::Link(j) => self.fill_free_rec(j, pad_fn),
                Content::Leaf(_) => {}
            }
        }
    }

    /// Consume the builder and produce a balanced binary tree. Returns `None` if no
    /// path was placed. Panics if any Free slot remains.
    pub(super) fn into_tree(self) -> Option<Tree<T>> {
        if self.subtrees.is_empty() {
            return None;
        }
        Some(Self::into_tree_rec(&self.subtrees, 0))
    }

    /// Build the `Tree<T>` for one subtree by stack-merging slots in DFS order:
    /// for each slot, push `(depth, leaf-or-recursed-tree)` and repeatedly merge
    /// with the stack top while the top's depth equals the current depth, decreasing
    /// the depth by 1 per merge.
    fn into_tree_rec(subtrees: &[SubTree<T>], idx: usize) -> Tree<T> {
        let sub = &subtrees[idx];
        let mut stack: Vec<(u8, Tree<T>)> = Vec::with_capacity(sub.slots.len());
        for slot in &sub.slots {
            let item = match &slot.content {
                Content::Leaf(t) => Tree::Leaf(t.clone()),
                Content::Link(j) => Self::into_tree_rec(subtrees, *j),
                Content::Free => panic!("Slot::Free remained at into_tree; pad first"),
            };
            let mut current = (slot.depth, item);
            while let Some(&(top_depth, _)) = stack.last() {
                if top_depth == current.0 {
                    let (_, top_tree) = stack.pop().expect("non-empty");
                    current = (
                        current.0 - 1,
                        Tree::Branch(Box::new(top_tree), Box::new(current.1)),
                    );
                } else {
                    break;
                }
            }
            stack.push(current);
        }
        debug_assert_eq!(stack.len(), 1);
        stack.pop().expect("non-empty").1
    }
}

/// Recursive helper for [`Tree::ascii_diagram`].
#[cfg(test)]
struct RenderBlock {
    rows: Vec<String>,
    width: usize,
    /// Column where this block's root sits in `rows[0]`.
    center: usize,
}

#[cfg(test)]
impl<T: std::fmt::Display> Tree<T> {
    /// Render the tree as a vertical ASCII diagram (root at top, leaves at bottom).
    /// Every leaf is centred-padded to the maximum `{}`-width across the tree, so
    /// columns line up regardless of leaf-label size. Trailing spaces are trimmed
    /// per line. Output starts with a leading newline so the root sits on its own
    /// line, keeping asserts that embed the diagram in a raw string aligned (the
    /// first row's indentation no longer collides with the raw-string opener).
    pub(super) fn ascii_diagram(&self) -> String {
        let leaf_width = self.max_leaf_width();
        let block = self.render_block(leaf_width);
        let mut out = String::from("\n");
        for row in &block.rows {
            out.push_str(row.trim_end());
            out.push('\n');
        }
        out
    }

    fn max_leaf_width(&self) -> usize {
        match self {
            Tree::Leaf(v) => format!("{v}").chars().count(),
            Tree::Branch(l, r) => l.max_leaf_width().max(r.max_leaf_width()),
        }
    }

    fn render_block(&self, leaf_width: usize) -> RenderBlock {
        match self {
            Tree::Leaf(v) => {
                let s = format!("{v}");
                let cur = s.chars().count();
                let total_pad = leaf_width.saturating_sub(cur);
                let left = total_pad / 2;
                let right = total_pad - left;
                let padded = format!("{}{s}{}", " ".repeat(left), " ".repeat(right));
                let w = padded.chars().count();
                RenderBlock {
                    rows: vec![padded],
                    width: w,
                    center: w / 2,
                }
            }
            Tree::Branch(l, r) => {
                let lb = l.render_block(leaf_width);
                let rb = r.render_block(leaf_width);
                let gap = 1;
                let total = lb.width + gap + rb.width;
                let l_c = lb.center;
                let r_c = lb.width + gap + rb.center;
                let new_center = (l_c + r_c) / 2;
                let l_slash = (new_center + l_c) / 2;
                let r_slash = (new_center + r_c).div_ceil(2);

                let mut top: Vec<char> = vec![' '; total];
                top[new_center] = '.';
                let mut conn: Vec<char> = vec![' '; total];
                conn[l_slash] = '/';
                conn[r_slash] = '\\';

                let pad_to = |s: &str, w: usize| -> String {
                    let cur = s.chars().count();
                    if cur >= w {
                        s.to_string()
                    } else {
                        format!("{s}{}", " ".repeat(w - cur))
                    }
                };

                let max_rows = lb.rows.len().max(rb.rows.len());
                let mut rows: Vec<String> = Vec::with_capacity(2 + max_rows);
                rows.push(top.iter().collect());
                rows.push(conn.iter().collect());
                for i in 0..max_rows {
                    let lp = lb
                        .rows
                        .get(i)
                        .map(|s| pad_to(s, lb.width))
                        .unwrap_or_else(|| " ".repeat(lb.width));
                    let rp = rb
                        .rows
                        .get(i)
                        .map(|s| pad_to(s, rb.width))
                        .unwrap_or_else(|| " ".repeat(rb.width));
                    rows.push(format!("{lp}{}{rp}", " ".repeat(gap)));
                }

                RenderBlock {
                    rows,
                    width: total,
                    center: new_center,
                }
            }
        }
    }
}

#[cfg(test)]
impl<T: Clone + std::fmt::Display> TreeBuilder<T> {
    /// Render the current placement state as an ASCII diagram. Free slots show as
    /// `_` so the partial tree (before `fill_free_with`) can be visualised.
    fn state_diagram(&self) -> String {
        if self.subtrees.is_empty() {
            return String::new();
        }
        Self::to_string_tree(&self.subtrees, 0).ascii_diagram()
    }

    fn to_string_tree(subtrees: &[SubTree<T>], idx: usize) -> Tree<String> {
        let sub = &subtrees[idx];
        let mut stack: Vec<(u8, Tree<String>)> = Vec::with_capacity(sub.slots.len());
        for slot in &sub.slots {
            let item = match &slot.content {
                Content::Leaf(t) => Tree::Leaf(format!("{t}")),
                Content::Link(j) => Self::to_string_tree(subtrees, *j),
                Content::Free => Tree::Leaf("_".to_string()),
            };
            let mut current = (slot.depth, item);
            while let Some(&(top_depth, _)) = stack.last() {
                if top_depth == current.0 {
                    let (_, top_tree) = stack.pop().expect("non-empty");
                    current = (
                        current.0 - 1,
                        Tree::Branch(Box::new(top_tree), Box::new(current.1)),
                    );
                } else {
                    break;
                }
            }
            stack.push(current);
        }
        stack.pop().expect("non-empty").1
    }
}

// Descriptor-specific layer

pub(super) fn build(
    paths: &[Path],
) -> Result<(WalletKey, Option<TapTree<WalletKey>>), PolicyError> {
    let network = network_from_paths(paths).unwrap_or(NetworkKind::Main);
    let mut order: Vec<usize> = (0..paths.len())
        .filter(|&i| !paths[i].leaves().is_empty())
        .collect();
    // Stable sort: paths sharing the same `order` keep their `paths[]` insertion order,
    // matching `assign_start_indices`' walk so leaf miniscripts and multipath cursors line up.
    order.sort_by_key(|&i| paths[i].order().expect("set by resolve_global_order"));

    // Group paths by `order` into priority runs; each run becomes one `place_path` call so
    // every path in the group shares one tap-tree leaf depth.
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for &path_idx in &order {
        let o = paths[path_idx].order().expect("set above");
        match groups.last_mut() {
            Some(last) if paths[last[0]].order() == Some(o) => last.push(path_idx),
            _ => groups.push(vec![path_idx]),
        }
    }

    let mut builder: TreeBuilder<Miniscript<WalletKey, Tap>> = TreeBuilder::new();
    for (i, group) in groups.iter().enumerate() {
        let more_after = i + 1 < groups.len();
        let combined: Vec<Miniscript<WalletKey, Tap>> = group
            .iter()
            .flat_map(|&idx| paths[idx].leaves().iter().cloned())
            .collect();
        builder.place_path(&combined, more_after)?;
    }

    let seed = nums_seed_chain_code(&builder);

    let internal_key = match paths
        .iter()
        .find(|p| matches!(p.position(), TapPosition::InternalKey))
    {
        Some(p) => {
            let cursor = p.start_index().expect("set by assign_start_indices");
            match p.semantic() {
                Semantic::Single(key) => {
                    wallet_key(oxpub_to_key(key, deriv_paths_starting_at(cursor)))
                }
                #[cfg(feature = "musig")]
                Semantic::Multi { keys, .. } => match keys.as_slice() {
                    [key] => wallet_key(oxpub_to_key(key, deriv_paths_starting_at(cursor))),
                    _ => crate::musig::musig_key(keys, cursor)?,
                },
                _ => unreachable!("validated by sanitize"),
            }
        }
        None => wallet_key(nums_descriptor_key(network, seed, 0)),
    };

    check_padding_fits(&builder)?;
    let mut slot = 0;
    builder.fill_free_with(|| {
        slot += 1;
        nums_pk_leaf(network, seed, slot)
    });

    let tap_tree = builder.into_tree().map(into_tap_tree);
    Ok((internal_key, tap_tree))
}

/// Every padding leaf of `builder` needs its own NUMS slot: slot 0 is the internal
/// key's, padding leaves take slots 1 and up.
fn check_padding_fits<T: Clone>(builder: &TreeBuilder<T>) -> Result<(), PolicyError> {
    let mut padding = 0;
    builder.dfs_slots(|s| padding += usize::from(matches!(s, DfsSlot::Free)));
    if padding >= NUMS_SLOTS {
        return Err(PolicyError::TooManyPaddingLeaves {
            count: padding,
            max: NUMS_SLOTS - 1,
        });
    }
    Ok(())
}

fn nums_seed_chain_code(builder: &TreeBuilder<Miniscript<WalletKey, Tap>>) -> bip32::ChainCode {
    let nums = bip341_nums().serialize();
    let mut concat: Vec<u8> = Vec::new();
    builder.dfs_slots(|s| match s {
        DfsSlot::Free => concat.extend_from_slice(&nums),
        DfsSlot::Leaf(ms) => {
            for k in ms.iter_pk() {
                if let Some(xkey) = chain_code_xkey(&k) {
                    concat.extend_from_slice(&xkey.public_key.serialize());
                }
            }
        }
    });
    bip32::ChainCode::from(sha256::Hash::hash(&concat).as_ref())
}

fn into_tap_tree(tree: Tree<Miniscript<WalletKey, Tap>>) -> TapTree<WalletKey> {
    match tree {
        Tree::Leaf(ms) => TapTree::Leaf(sync::Arc::new(ms)),
        Tree::Branch(l, r) => TapTree::combine(into_tap_tree(*l), into_tap_tree(*r)),
    }
}

fn network_from_paths(paths: &[Path]) -> Option<NetworkKind> {
    paths
        .iter()
        .flat_map(|p| p.semantic().keys())
        .map(|k| k.xkey.network)
        .next()
}

/// The NUMS xpub on NUMS slot `slot` (see `multipath::NUMS_BLOCK_START`). Every slot shares
/// the one chain code: Ledger refuses two keys with one public key, and Coldcard merges
/// them under one chain code, so distinct chain codes per slot break both devices.
fn nums_descriptor_key(
    network: NetworkKind,
    chain_code: bip32::ChainCode,
    slot: usize,
) -> DescriptorPublicKey {
    let xpub = bip32::Xpub {
        public_key: bip341_nums(),
        chain_code,
        depth: 0,
        parent_fingerprint: [0u8; 4].into(),
        child_number: 0.into(),
        network,
    };
    DescriptorPublicKey::MultiXPub(descriptor::DescriptorMultiXKey {
        origin: None,
        xkey: xpub,
        derivation_paths: nums_slot_paths(slot),
        wildcard: descriptor::Wildcard::Unhardened,
    })
}

fn nums_pk_leaf(
    network: NetworkKind,
    chain_code: bip32::ChainCode,
    slot: usize,
) -> Miniscript<WalletKey, Tap> {
    let key = nums_descriptor_key(network, chain_code, slot);
    ConcretePolicy::Key(wallet_key(key))
        .compile::<Tap>()
        .expect("pk(NUMS) compiles trivially")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Entry<T> {
        Leaf(u8, T),
        Free(u8),
    }

    fn snapshot<T: Clone>(b: &TreeBuilder<T>) -> Vec<Entry<T>> {
        let mut out = Vec::new();
        if !b.subtrees.is_empty() {
            rec(&b.subtrees, 0, &mut out);
        }
        out
    }

    fn rec<T: Clone>(subtrees: &[SubTree<T>], idx: usize, out: &mut Vec<Entry<T>>) {
        for slot in &subtrees[idx].slots {
            match &slot.content {
                Content::Leaf(t) => out.push(Entry::Leaf(slot.depth, t.clone())),
                Content::Link(j) => rec(subtrees, *j, out),
                Content::Free => out.push(Entry::Free(slot.depth)),
            }
        }
    }

    #[test]
    fn first_path_pow2_no_free_slots() {
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2], false).unwrap();
        let entries = snapshot(&b);
        assert_eq!(entries, vec![Entry::Leaf(1, 1), Entry::Leaf(1, 2)]);
        assert_eq!(
            b.state_diagram(),
            r#"
 .
/ \
1 2
"#
        );
    }

    #[test]
    fn first_path_5_of_8_exposes_two_chunks() {
        // 5 leaves placed in a size-8 subtree; trailing chunks are Free@3 (size 1)
        // and Free@2 (size 2). Both render as `_` in the placement-state diagram.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], false).unwrap();
        assert_eq!(
            b.state_diagram(),
            r#"
      .
    /   \
   .      .
  / \    / \
 .   .   .  _
/ \ / \ / \
1 2 3 4 5 _
"#
        );
        let entries = snapshot(&b);
        // 5 leaves at depth 3, then a Free at depth 3, then a Free at depth 2.
        assert_eq!(
            entries,
            vec![
                Entry::Leaf(3, 1),
                Entry::Leaf(3, 2),
                Entry::Leaf(3, 3),
                Entry::Leaf(3, 4),
                Entry::Leaf(3, 5),
                Entry::Free(3),
                Entry::Free(2),
            ]
        );
        assert_eq!(b.subtrees[0].free_slots(), 2);
    }

    #[test]
    fn second_path_takes_shallower_chunk() {
        // The 6th leaf lands at d=2 (the shallowest Free slot); the size-1 chunk at
        // d=3 stays free for NUMS padding.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], true).unwrap();
        b.place_path(&[6], false).unwrap();
        assert_eq!(
            b.state_diagram(),
            r#"
      .
    /   \
   .      .
  / \    / \
 .   .   .  6
/ \ / \ / \
1 2 3 4 5 _
"#
        );
        let entries = snapshot(&b);
        assert_eq!(
            entries,
            vec![
                Entry::Leaf(3, 1),
                Entry::Leaf(3, 2),
                Entry::Leaf(3, 3),
                Entry::Leaf(3, 4),
                Entry::Leaf(3, 5),
                Entry::Free(3),
                Entry::Leaf(2, 6),
            ]
        );
        assert_eq!(b.subtrees[0].free_slots(), 1);
    }

    #[test]
    fn third_single_leaf_lands_at_d3_after_d2_taken() {
        // The 6th leaf takes the shallowest slot at d=2. The 7th has only the d=3
        // size-1 chunk left and lands there.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], true).unwrap();
        b.place_path(&[6], true).unwrap();
        b.place_path(&[7], false).unwrap();
        assert_eq!(
            b.state_diagram(),
            r#"
      .
    /   \
   .      .
  / \    / \
 .   .   .  6
/ \ / \ / \
1 2 3 4 5 7
"#
        );
        let entries = snapshot(&b);
        assert_eq!(
            entries,
            vec![
                Entry::Leaf(3, 1),
                Entry::Leaf(3, 2),
                Entry::Leaf(3, 3),
                Entry::Leaf(3, 4),
                Entry::Leaf(3, 5),
                Entry::Leaf(3, 7),
                Entry::Leaf(2, 6),
            ]
        );
    }

    #[test]
    fn third_single_leaf_more_after_drills_deeper_for_slack() {
        // Same shape as the previous test, but the 7th placement has more_after=true.
        // With only the d=3 size-1 chunk left and total_slack=1, the more_after branch
        // doubles new_size to 2, so 7 lands inside a size-2 sub-subtree at d=4 next to
        // a fresh Free slot that the next caller can fill.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], true).unwrap();
        b.place_path(&[6], true).unwrap();
        b.place_path(&[7], true).unwrap();
        assert_eq!(
            b.state_diagram(),
            r#"
       .
     /   \
   .       .
  / \     /  \
 .   .   .    6
/ \ / \ / \
1 2 3 4 5  .
          / \
          7 _
"#
        );
        let entries = snapshot(&b);
        assert_eq!(
            entries,
            vec![
                Entry::Leaf(3, 1),
                Entry::Leaf(3, 2),
                Entry::Leaf(3, 3),
                Entry::Leaf(3, 4),
                Entry::Leaf(3, 5),
                Entry::Leaf(4, 7),
                Entry::Free(4),
                Entry::Leaf(2, 6),
            ]
        );
    }

    #[test]
    fn fill_free_with_pads_chunks_at_their_depths() {
        // After fill_free_with on the 5-of-8 subtree, the two free chunks are
        // replaced by single-leaf sub-subtrees: pad 100 at depth 3 (the size-1
        // chunk) and pad 101 at depth 2 (the size-2 chunk). All leaves padded to
        // width 3.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], false).unwrap();
        let mut next: u32 = 100;
        b.fill_free_with(|| {
            let v = next;
            next += 1;
            v
        });
        assert_eq!(
            b.state_diagram(),
            r#"
              .
          /       \
       .              .
     /   \          /   \
   .       .       .    101
  / \     / \     / \
 1   2   3   4   5  100
"#
        );
        let entries = snapshot(&b);
        // Padding leaves: one at depth 3 (the size-1 chunk), one at depth 2 (size-2 chunk).
        assert_eq!(
            entries,
            vec![
                Entry::Leaf(3, 1),
                Entry::Leaf(3, 2),
                Entry::Leaf(3, 3),
                Entry::Leaf(3, 4),
                Entry::Leaf(3, 5),
                Entry::Leaf(3, 100),
                Entry::Leaf(2, 101),
            ]
        );
    }

    #[test]
    fn appended_leaf_keeps_layout_frozen() {
        // Place 5+1 leaves; the host subtree's slot layout is unchanged (slots set at
        // creation), only one slot's content went from Free to Link/Leaf.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], true).unwrap();
        b.place_path(&[6], false).unwrap();
        let host = &b.subtrees[0];
        let depths: Vec<u8> = host.slots.iter().map(|s| s.depth).collect();
        assert_eq!(depths, vec![3, 3, 3, 3, 3, 3, 2]);
        assert_eq!(host.free_slots(), 1);
        assert_eq!(
            b.state_diagram(),
            r#"
      .
    /   \
   .      .
  / \    / \
 .   .   .  6
/ \ / \ / \
1 2 3 4 5 _
"#
        );
    }

    #[test]
    fn place_path_rejects_empty_leaves() {
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        let err = b.place_path(&[], false).unwrap_err();
        assert_eq!(err, TreeBuilderError::EmptyLeaves);
        assert!(b.subtrees.is_empty());
    }

    #[test]
    fn into_tree_balanced_pow2() {
        // 2-leaf path: 1 Branch with 2 leaves at depth 1.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2], false).unwrap();
        let tree = b.into_tree().expect("non-empty");
        match &tree {
            Tree::Branch(l, r) => match (l.as_ref(), r.as_ref()) {
                (Tree::Leaf(1), Tree::Leaf(2)) => {}
                other => panic!("unexpected: {other:?}"),
            },
            _ => panic!("expected branch"),
        }
        assert_eq!(
            tree.ascii_diagram(),
            r#"
 .
/ \
1 2
"#
        );
    }

    #[test]
    fn ascii_diagram_single_leaf_root() {
        let tree: Tree<u32> = Tree::Leaf(42);
        assert_eq!(
            tree.ascii_diagram(),
            r#"
42
"#
        );
    }

    #[test]
    fn ascii_diagram_balanced_4_leaves() {
        let tree: Tree<u32> = Tree::Branch(
            Box::new(Tree::Branch(
                Box::new(Tree::Leaf(1)),
                Box::new(Tree::Leaf(2)),
            )),
            Box::new(Tree::Branch(
                Box::new(Tree::Leaf(3)),
                Box::new(Tree::Leaf(4)),
            )),
        );
        assert_eq!(
            tree.ascii_diagram(),
            r#"
   .
  / \
 .   .
/ \ / \
1 2 3 4
"#
        );
    }

    #[test]
    fn ascii_diagram_unbalanced_sibling_leaf() {
        // The lone leaf `3` sits on the same row as the inner Branch's root marker:
        // both are children of the outer root.
        let tree: Tree<u32> = Tree::Branch(
            Box::new(Tree::Branch(
                Box::new(Tree::Leaf(1)),
                Box::new(Tree::Leaf(2)),
            )),
            Box::new(Tree::Leaf(3)),
        );
        assert_eq!(
            tree.ascii_diagram(),
            r#"
  .
 / \
 .  3
/ \
1 2
"#
        );
    }

    #[test]
    fn ascii_diagram_unbalanced_sibling_leaf_left() {
        // Same as `ascii_diagram_unbalanced_sibling_leaf` with the lone leaf on the
        // left and the inner Branch on the right.
        let tree: Tree<u32> = Tree::Branch(
            Box::new(Tree::Leaf(3)),
            Box::new(Tree::Branch(
                Box::new(Tree::Leaf(1)),
                Box::new(Tree::Leaf(2)),
            )),
        );
        assert_eq!(
            tree.ascii_diagram(),
            r#"
 .
/ \
3  .
  / \
  1 2
"#
        );
    }

    #[test]
    fn ascii_diagram_built_4_leaves() {
        // Single 4-leaf path: balanced size-4 subtree, no padding.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4], false).unwrap();
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
   .
  / \
 .   .
/ \ / \
1 2 3 4
"#
        );
    }

    #[test]
    fn ascii_diagram_built_5_leaves_padded() {
        // Single 5-leaf path: size-8 subtree with two trailing free chunks (size 1
        // at depth 3, size 2 at depth 2). Padding fills them as size-1 sub-subtrees:
        // pad 100 at depth 3, pad 101 at depth 2. Every leaf is padded to width 3
        // so columns align across the whole tree.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3, 4, 5], false).unwrap();
        let mut next: u32 = 100;
        b.fill_free_with(|| {
            let v = next;
            next += 1;
            v
        });
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
              .
          /       \
       .              .
     /   \          /   \
   .       .       .    101
  / \     / \     / \
 1   2   3   4   5  100
"#
        );
    }

    #[test]
    fn ascii_diagram_built_two_paths() {
        // Place a 2-leaf path then a 1-leaf path. The 2-leaf path creates a size-4
        // subtree with leaves at d=2 plus a size-2 chunk at d=1. The 1-leaf path
        // lands directly at the d=1 slot (no drilling), no padding needed.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2], true).unwrap();
        b.place_path(&[3], false).unwrap();
        let mut next: u32 = 100;
        b.fill_free_with(|| {
            let v = next;
            next += 1;
            v
        });
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
  .
 / \
 .  3
/ \
1 2
"#
        );
    }

    #[test]
    fn ascii_diagram_built_three_leaf_path_padded() {
        // Single 3-leaf path: size-4 subtree with 1 free chunk of size 1 at
        // depth 2. Padding fills it with one leaf at depth 2. Every leaf padded
        // to width 3.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2, 3], false).unwrap();
        let mut next: u32 = 100;
        b.fill_free_with(|| {
            let v = next;
            next += 1;
            v
        });
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
       .
     /   \
   .       .
  / \     / \
 1   2   3  100
"#
        );
    }

    #[test]
    fn ascii_diagram_built_one_leaf_path() {
        // A 1-leaf path produces a size-1 subtree with just that leaf as the root.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1], false).unwrap();
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
1
"#
        );
    }

    #[test]
    fn ascii_diagram_built_two_leaf_path() {
        // A 2-leaf path produces a size-2 subtree with both leaves at depth 1.
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        b.place_path(&[1, 2], false).unwrap();
        let tree = b.into_tree().unwrap();
        assert_eq!(
            tree.ascii_diagram(),
            r#"
 .
/ \
1 2
"#
        );
    }

    /// Build a closure for [`check_scenario`] from a list of path sizes. Leaves are
    /// auto-numbered starting at 1; `more_after = true` for every path except the
    /// last. Example: `place_paths!(1, 2, 1, 1, 3)` expands to a closure that calls
    /// `place_path(&[1], true)`, `place_path(&[2, 3], true)`, `place_path(&[4], true)`,
    /// `place_path(&[5], true)`, then `place_path(&[6, 7, 8], false)`.
    macro_rules! place_paths {
        ($($size:expr),+ $(,)?) => {
            |b: &mut TreeBuilder<u32>| {
                let sizes: &[usize] = &[$($size),+];
                let last = sizes.len() - 1;
                let mut next: u32 = 1;
                for (i, &n) in sizes.iter().enumerate() {
                    let leaves: Vec<u32> = (next..next + n as u32).collect();
                    next += n as u32;
                    b.place_path(&leaves, i != last).unwrap();
                }
            }
        };
    }

    #[test]
    fn padding_leaves_must_fit_the_nums_slots() {
        // A path of 129 leaves fills 256 slots, leaving 7 free chunks; each later one
        // takes a chunk and leaves 7 of its own: 7 + 6 * (paths - 1) free slots.
        let leaves: Vec<u32> = (0..129).collect();
        let builder = |paths: usize| {
            let mut b: TreeBuilder<u32> = TreeBuilder::new();
            for i in 0..paths {
                b.place_path(&leaves, i + 1 < paths).unwrap();
            }
            b
        };
        assert!(check_padding_fits(&builder(21)).is_ok());
        assert!(matches!(
            check_padding_fits(&builder(22)),
            Err(PolicyError::TooManyPaddingLeaves {
                count: 133,
                max: 127
            })
        ));
    }

    /// Run a sequence of `place_path` calls and assert the placement-state diagram
    /// (`state_diagram`). Free slots show as `_` so the diagram fully captures the
    /// tree shape. Pads with `100..` and runs `into_tree` to ensure both succeed.
    fn check_scenario<F: FnOnce(&mut TreeBuilder<u32>)>(place: F, expected: &str) {
        let mut b: TreeBuilder<u32> = TreeBuilder::new();
        place(&mut b);
        assert_eq!(b.state_diagram(), expected);
        let mut next: u32 = 100;
        b.fill_free_with(|| {
            let v = next;
            next += 1;
            v
        });
        b.into_tree().unwrap();
    }

    #[test]
    fn tree_12113() {
        check_scenario(
            place_paths!(1, 2, 1, 1, 3),
            r#"
  .
 /  \
1    .
    /  \
   .    .
  / \  / \
  2 3 4   .
         /  \
        5    .
            / \
           .   .
          / \ / \
          6 7 8 _
"#,
        );
    }

    #[test]
    fn tree_5213() {
        check_scenario(
            place_paths!(5, 2, 1, 3),
            r#"
              .
         /         \
     .                  .
   /   \            /       \
  .     .       .               .
 / \   / \    /   \            / \
1  2  3  4  5      .          6  7
                 /   \
               8       .
                     /   \
                    .     .
                   / \   / \
                  9  10 11 _
"#,
        );
    }

    #[test]
    fn tree_81() {
        check_scenario(
            place_paths!(8, 1),
            r#"
           .
         /    \
       .        9
     /   \
   .       .
  / \     / \
 .   .   .   .
/ \ / \ / \ / \
1 2 3 4 5 6 7 8
"#,
        );
    }

    #[test]
    fn tree_82() {
        check_scenario(
            place_paths!(8, 2),
            r#"
                  .
              /       \
           .              .
        /     \          / \
     .           .      9  10
   /   \       /   \
  .     .     .     .
 / \   / \   / \   / \
1  2  3  4  5  6  7  8
"#,
        );
    }

    #[test]
    fn tree_821() {
        check_scenario(
            place_paths!(8, 2, 1),
            r#"
                   .
               /        \
           .                .
        /     \            /  \
     .           .        .   11
   /   \       /   \     / \
  .     .     .     .   9  10
 / \   / \   / \   / \
1  2  3  4  5  6  7  8
"#,
        );
    }

    #[test]
    fn tree_8213() {
        check_scenario(
            place_paths!(8, 2, 1, 3),
            r#"
                    .
               /         \
           .                  .
        /     \             /   \
     .           .        .       .
   /   \       /   \     / \    /   \
  .     .     .     .   9  10 11      .
 / \   / \   / \   / \              /   \
1  2  3  4  5  6  7  8             .     .
                                  / \   / \
                                 12 13 14 _
"#,
        );
    }

    #[test]
    fn tree_7213() {
        check_scenario(
            place_paths!(7, 2, 1, 3),
            r#"
           .
        /      \
     .            .
   /   \        /    \
  .     .     .        .
 / \   / \   / \     /   \
1  2  3  4  5  6  7        .
                         /   \
                       .       .
                      / \    /   \
                     8  9  10      .
                                 /   \
                                .     .
                               / \   / \
                              11 12 13 _
"#,
        );
    }

    #[test]
    fn tree_9213() {
        check_scenario(
            place_paths!(9, 2, 1, 3),
            r#"
                         .
                  /             \
           .                           .
        /     \                     /     \
     .           .                .         .
   /   \       /   \           /     \     / \
  .     .     .     .       .          12 10 11
 / \   / \   / \   / \    /   \
1  2  3  4  5  6  7  8  9       .
                              /   \
                             .     .
                            / \   / \
                           13 14 15 _
"#,
        );
    }

    #[test]
    fn tree_16213() {
        check_scenario(
            place_paths!(16, 2, 1, 3),
            r#"
                                      .
                              /               \
                       .                              .
                 /           \                      /   \
           .                       .              .       .
        /     \                 /     \          / \    /   \
     .           .           .           .      17 18 19      .
   /   \       /   \       /   \       /   \                /   \
  .     .     .     .     .     .     .     .              .     .
 / \   / \   / \   / \   / \   / \   / \   / \            / \   / \
1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16          20 21 22 _
"#,
        );
    }
}
