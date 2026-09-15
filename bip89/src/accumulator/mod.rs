//! The tweak accumulator of `bip-tweak-accumulator.md`, a port of the blinded
//! address accumulator whose leaves commit to BIP89 tweak bundles instead of
//! scriptPubKeys. The hash primitives are streaming so the signing key
//! holder can hash a bundle with fixed memory.

use alloc::vec::Vec;

use crate::{
    accumulator::{
        shuffle::{invert, shuffle_key, shuffle_order, MAX_RANGE},
        tree::TreeBuilder,
    },
    backend::{BitcoinBackend, Sha256Engine, Xpub},
    bundle::{keychain_states, Bundle, KeychainState},
    scalar::{tagged_hash256, HmacSha512},
    Error,
};

pub mod record;
pub mod shuffle;
pub mod tree;

pub const LEAF_TAG: &[u8] = b"BIPXXX_LEAF";
pub const BRANCH_TAG: &[u8] = b"BIPXXX_BRANCH";
pub const ROOT_TAG: &[u8] = b"BIPXXX_ROOT";
pub const NONCE_TAG: &[u8] = b"BIPXXX_NONCE";
pub const POLICY_TAG: &[u8] = b"BIPXXX_POLICY";

/// Number of keychains: 0 is receive, 1 is change.
pub const KEYCHAINS: u32 = 2;

/// Plain sha256 of the canonical descriptor bytes.
pub fn policy_id<B: BitcoinBackend>(c: &B, policy_bytes: &[u8]) -> [u8; 32] {
    let mut engine = c.sha256();
    engine.update(policy_bytes);
    engine.finalize()
}

/// Sha256 of the sorted, deduplicated `chain_code||key` records of every xpub.
pub fn keys_digest<B: BitcoinBackend>(c: &B, xpubs: &[Xpub]) -> [u8; 32] {
    let mut records: Vec<[u8; 65]> = Vec::with_capacity(xpubs.len());
    for xpub in xpubs {
        let mut record = [0u8; 65];
        record[..32].copy_from_slice(&xpub.chain_code);
        record[32..].copy_from_slice(&xpub.key);
        records.push(record);
    }
    records.sort_unstable();
    records.dedup();

    let mut engine = c.sha256();
    for record in &records {
        engine.update(record);
    }
    engine.finalize()
}

/// Tagged hash seeding a tree's chaincode from the policy id, keychain and tree start.
pub fn policy_hash<B: BitcoinBackend>(
    c: &B,
    policy_id: &[u8; 32],
    keychain: u32,
    tree_start: u32,
) -> [u8; 32] {
    let mut engine = tagged_hash256(c, POLICY_TAG);
    engine.update(policy_id);
    engine.update(&keychain.to_be_bytes());
    engine.update(&tree_start.to_be_bytes());
    engine.finalize()
}

/// Splits HMAC-SHA512 of the chaincode into the next chaincode and this leaf's nonce.
pub fn leaf_nonce<B: BitcoinBackend>(
    c: &B,
    chaincode: &[u8; 32],
    keys_digest: &[u8; 32],
    keychain: u32,
    index: u32,
) -> ([u8; 32] /* chaincode */, [u8; 32] /* nonce */) {
    let mut engine = HmacSha512::new(c, chaincode);
    engine.update(NONCE_TAG);
    engine.update(keys_digest);
    engine.update(&keychain.to_be_bytes());
    engine.update(&index.to_be_bytes());
    let hmac = engine.finalize();
    let mut chaincode = [0u8; 32];
    let mut nonce = [0u8; 32];
    chaincode.copy_from_slice(&hmac[..32]);
    nonce.copy_from_slice(&hmac[32..]);
    (chaincode, nonce)
}

/// Tagged hash of the bundle's canonical bytes followed by its leaf nonce.
pub fn leaf_hash<B: BitcoinBackend>(c: &B, bundle: &Bundle, nonce: &[u8; 32]) -> [u8; 32] {
    let mut engine = tagged_hash256(c, LEAF_TAG);
    bundle.feed(&mut engine);
    engine.update(nonce);
    engine.finalize()
}

/// Tagged hash of two child hashes, in the order given.
pub fn branch_hash<B: BitcoinBackend>(c: &B, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut engine = tagged_hash256(c, BRANCH_TAG);
    engine.update(left);
    engine.update(right);
    engine.finalize()
}

/// Tagged hash of the collapsed tree root.
pub fn root_hash<B: BitcoinBackend>(c: &B, root: &[u8; 32]) -> [u8; 32] {
    let mut engine = tagged_hash256(c, ROOT_TAG);
    engine.update(root);
    engine.finalize()
}

/// Same bytes as `leaf_hash` over the bundle these states derive at `index`,
/// streamed without allocating a `Bundle`. `states` must already be sorted
/// strictly ascending by key.
pub(crate) fn leaf_hash_derived<B: BitcoinBackend>(
    c: &B,
    states: &[KeychainState],
    index: u32,
    nonce: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let mut engine = tagged_hash256(c, LEAF_TAG);
    for state in states {
        let tweak = state.tweak_at(c, index)?;
        engine.update(state.key());
        engine.update(&tweak);
    }
    engine.update(nonce);
    Ok(engine.finalize())
}

/// Hashes `nodes` bottom-up in place, emitting levels 1 to 8 to `builder`.
/// The leaf level is not emitted; the caller already reported it.
fn collapse<B: BitcoinBackend, T: TreeBuilder>(
    c: &B,
    nodes: &mut [[u8; 32]; MAX_RANGE],
    builder: &mut T,
) -> [u8; 32] {
    let mut width = MAX_RANGE;
    let mut level = 0u8;
    while width > 1 {
        for i in 0..width / 2 {
            nodes[i] = branch_hash(c, &nodes[2 * i], &nodes[2 * i + 1]);
        }
        width /= 2;
        level += 1;
        for (i, hash) in nodes.iter().enumerate().take(width) {
            builder.node(level, i as u8, hash);
        }
    }
    nodes[0]
}

/// Generates the 256-leaf tree of `d` for `keychain` starting at `tree_start`.
/// The chaincode is reseeded once per tree from the policy id, keychain and
/// tree start; the builder decides what of the walk is kept.
pub fn generate_tree<B: BitcoinBackend, T: TreeBuilder>(
    c: &B,
    d: &B::Descriptor,
    keychain: u32,
    tree_start: u32,
    mut builder: T,
) -> Result<T::Tree, Error> {
    if keychain >= KEYCHAINS {
        return Err(Error::InvalidKeychain);
    }
    let last = tree_start
        .checked_add(MAX_RANGE as u32 - 1)
        .ok_or(Error::IndexRange)?;
    if last >= 0x8000_0000 {
        return Err(Error::IndexRange);
    }

    let pid = policy_id(c, &c.descriptor_policy(d));
    let kd = keys_digest(c, &c.descriptor_xpubs(d)?);
    let mut states = keychain_states(c, d, keychain)?;
    states.sort_unstable_by(|a, b| a.key().cmp(b.key()));
    for pair in states.windows(2) {
        if pair[0].key() == pair[1].key() {
            return Err(Error::DuplicateKey);
        }
    }

    let order = shuffle_order(c, &shuffle_key(c, &pid, keychain, tree_start));
    let inv = invert(&order);

    let mut chaincode = policy_hash(c, &pid, keychain, tree_start);
    let mut nodes = [[0u8; 32]; MAX_RANGE];
    for offset in 0..MAX_RANGE as u32 {
        let index = tree_start + offset;
        let (next_chaincode, nonce) = leaf_nonce(c, &chaincode, &kd, keychain, index);
        chaincode = next_chaincode;
        let hash = leaf_hash_derived(c, &states, index, &nonce)?;
        let position = inv[offset as usize];
        nodes[position as usize] = hash;
        builder.leaf(position, index, &hash, &nonce);
    }

    let top = collapse(c, &mut nodes, &mut builder);
    Ok(builder.finish(root_hash(c, &top)))
}
