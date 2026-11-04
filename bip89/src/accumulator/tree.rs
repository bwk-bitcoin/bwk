//! Merkle proofs of membership and the tree builders that produce them.
//!
//! A proof is a fixed-size sibling path from a leaf to the tree root and lets
//! a delegator, holding only a bundle and a root, check that the bundle was
//! committed without learning any other leaf. Two builders share one
//! construction: the signing key holder signs a root with `NullTreeBuilder`, which
//! keeps nothing, while the coordinator records every level with
//! `ProofTreeBuilder` so it can serve a proof for any index afterward.

use alloc::{vec, vec::Vec};

use crate::{
    accumulator::{branch_hash, leaf_hash, root_hash, shuffle::MAX_RANGE},
    backend::BitcoinBackend,
    bundle::Bundle,
    Error,
};

pub const HEIGHT: usize = 8;

/// A membership proof: the leaf nonce, its position in the tree, and one
/// sibling hash per level from the leaf up to the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub nonce: [u8; 32],
    pub position: u8,
    pub siblings: [[u8; 32]; HEIGHT],
}

impl Proof {
    pub const LEN: usize = 289;

    /// Encodes as nonce, then position, then the siblings in level order.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[..32].copy_from_slice(&self.nonce);
        bytes[32] = self.position;
        for (level, sibling) in self.siblings.iter().enumerate() {
            bytes[33 + 32 * level..65 + 32 * level].copy_from_slice(sibling);
        }
        bytes
    }

    /// Any length other than `LEN` is `Error::ProofLength`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::LEN {
            return Err(Error::ProofLength);
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&bytes[..32]);
        let position = bytes[32];
        let mut siblings = [[0u8; 32]; HEIGHT];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            sibling.copy_from_slice(&bytes[33 + 32 * level..65 + 32 * level]);
        }
        Ok(Proof {
            nonce,
            position,
            siblings,
        })
    }
}

/// The position of the other child at `level`, given the position at level 0.
pub fn sibling_position(position: u8, level: u8) -> u8 {
    position.checked_shr(u32::from(level)).unwrap_or(0) ^ 1
}

/// Checks a proof against `root` for `bundle`. The tree start is never added
/// to `proof.position`: it is the position inside the tree only.
pub fn verify_proof<B: BitcoinBackend>(
    c: &B,
    bundle: &Bundle,
    proof: &Proof,
    root: &[u8; 32],
) -> bool {
    let mut node = leaf_hash(c, bundle, &proof.nonce);
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let bit = (proof.position >> level) & 1;
        node = if bit == 0 {
            branch_hash(c, &node, sibling)
        } else {
            branch_hash(c, sibling, &node)
        };
    }
    root_hash(c, &node) == *root
}

/// Receives every node of a tree as it is built. The signing key holder uses
/// `NullTreeBuilder` to sign a root without keeping the tree; the coordinator
/// uses `ProofTreeBuilder` to keep enough to serve a proof for any index.
pub trait TreeBuilder {
    type Tree;

    /// Level 0. `position` is the position within this tree; `index` is the
    /// derivation index that produced it. The keyed shuffle means these do
    /// not correlate.
    fn leaf(&mut self, position: u8, index: u32, hash: &[u8; 32], nonce: &[u8; 32]);

    /// Level 1 and above, increasing upward.
    fn node(&mut self, level: u8, position: u8, hash: &[u8; 32]);

    fn finish(self, root: [u8; 32]) -> Self::Tree;
}

/// Signing key holder side: records nothing.
pub struct NullTreeBuilder;

impl TreeBuilder for NullTreeBuilder {
    type Tree = [u8; 32];

    fn leaf(&mut self, _position: u8, _index: u32, _hash: &[u8; 32], _nonce: &[u8; 32]) {}
    fn node(&mut self, _level: u8, _position: u8, _hash: &[u8; 32]) {}

    fn finish(self, root: [u8; 32]) -> Self::Tree {
        root
    }
}

/// Coordinator side: records every leaf nonce and position, and every level's
/// hashes, so a proof can be produced for any index in the tree afterward.
pub struct ProofTreeBuilder {
    keychain: u32,
    tree_start: u32,
    nonces: Vec<[u8; 32]>,
    positions: Vec<u8>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl ProofTreeBuilder {
    pub fn new(keychain: u32, tree_start: u32) -> Self {
        let levels = (0..=HEIGHT)
            .map(|level| vec![[0u8; 32]; MAX_RANGE >> level])
            .collect();
        Self {
            keychain,
            tree_start,
            nonces: vec![[0u8; 32]; MAX_RANGE],
            positions: vec![0u8; MAX_RANGE],
            levels,
        }
    }
}

impl TreeBuilder for ProofTreeBuilder {
    type Tree = Tree;

    fn leaf(&mut self, position: u8, index: u32, hash: &[u8; 32], nonce: &[u8; 32]) {
        let offset = index.wrapping_sub(self.tree_start) as usize;
        if offset < MAX_RANGE {
            self.nonces[offset] = *nonce;
            self.positions[offset] = position;
            self.levels[0][position as usize] = *hash;
        }
    }

    fn node(&mut self, level: u8, position: u8, hash: &[u8; 32]) {
        if let Some(slot) = self
            .levels
            .get_mut(level as usize)
            .and_then(|nodes| nodes.get_mut(position as usize))
        {
            *slot = *hash;
        }
    }

    fn finish(self, root: [u8; 32]) -> Self::Tree {
        Tree {
            root,
            keychain: self.keychain,
            tree_start: self.tree_start,
            nonces: self.nonces,
            positions: self.positions,
            levels: self.levels,
        }
    }
}

/// A committed tree, kept by the coordinator to serve membership proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub root: [u8; 32],
    pub keychain: u32,
    pub tree_start: u32,
    nonces: Vec<[u8; 32]>,
    positions: Vec<u8>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl Tree {
    /// The proof for the bundle derived at `index` on `keychain`, or `None`
    /// if the keychain does not match or `index` falls outside this tree.
    pub fn proof(&self, keychain: u32, index: u32) -> Option<Proof> {
        if keychain != self.keychain {
            return None;
        }
        let offset = index.checked_sub(self.tree_start)? as usize;
        if offset >= MAX_RANGE {
            return None;
        }
        let position = *self.positions.get(offset)?;
        let nonce = *self.nonces.get(offset)?;

        let mut siblings = [[0u8; 32]; HEIGHT];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let sibling_pos = sibling_position(position, level as u8);
            *sibling = *self.levels.get(level)?.get(sibling_pos as usize)?;
        }

        Some(Proof {
            nonce,
            position,
            siblings,
        })
    }
}
