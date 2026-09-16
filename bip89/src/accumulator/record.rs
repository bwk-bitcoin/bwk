//! Root records. A record pairs a tree with its accumulator root, and carries
//! a signature when a key of the descriptor signs that root. The signature is
//! BIP322, for the single-key taproot address of the signer's branch key on the
//! tree's keychain, so the delegator checks it against a base key of the
//! template it holds. The signed message binds the template id, so a root for
//! another wallet under the same key is refused.

use alloc::vec::Vec;

use crate::{
    accumulator::{
        generate_tree,
        tree::{NullTreeBuilder, ProofTreeBuilder, Tree},
    },
    backend::{BitcoinBackend, Sha256Engine},
    scalar::{scalar_is_valid, scalar_is_zero, tagged_hash256},
    tweak::{compute_bip32_tweak, tweak_key},
    Error,
};

pub const ROOT_SIG_TAG: &[u8] = b"BIPXXX_ROOT_SIG";

/// Plain sha256 of the canonical template bytes.
pub fn template_id<B: BitcoinBackend>(c: &B, template_bytes: &[u8]) -> [u8; 32] {
    let mut engine = c.sha256();
    engine.update(template_bytes);
    engine.finalize()
}

/// Tagged hash of the template id followed by the root.
pub fn root_message<B: BitcoinBackend>(c: &B, template_id: &[u8; 32], root: &[u8; 32]) -> [u8; 32] {
    let mut engine = tagged_hash256(c, ROOT_SIG_TAG);
    engine.update(template_id);
    engine.update(root);
    engine.finalize()
}

/// The accumulator root of one tree, with the signature of a key of the
/// descriptor over it when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecord {
    pub keychain: u32,
    pub tree_start: u32,
    pub root: [u8; 32],
    /// None when the root is registered without a signature.
    pub signature: Option<RootSignature>,
}

/// The signature of one key of the descriptor over an accumulator root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSignature {
    /// Base key of the signer.
    pub key: [u8; 33],
    /// Tweak from `key` to its branch key for `keychain`.
    pub branch_tweak: [u8; 32],
    /// BIP322 simple signature for the taproot address of the branch key.
    pub signature: Vec<u8>,
}

/// Builds the tree of `d` for `keychain` and `tree_start` with `NullTreeBuilder`
/// and returns its root with no signature. The caller builds the tree itself;
/// this function never accepts a root from the caller.
pub fn tree_root<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    keychain: u32,
    tree_start: u32,
) -> Result<RootRecord, Error> {
    Ok(RootRecord {
        keychain,
        tree_start,
        root: generate_tree(c, d, keychain, tree_start, NullTreeBuilder)?,
        signature: None,
    })
}

/// `tree_root`, with the root signed by the branch key of `secret` for
/// `keychain`. A secret whose public key is not a key of `d` is
/// `NotParticipant`.
pub fn sign_tree_root<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    secret: &[u8; 32],
    keychain: u32,
    tree_start: u32,
) -> Result<RootRecord, Error> {
    if !scalar_is_valid(secret) {
        return Err(Error::SecretKey);
    }
    let key = c.base_mul(secret).ok_or(Error::SecretKey)?;
    let xpub = c
        .descriptor_xpubs(d)?
        .into_iter()
        .find(|xpub| xpub.key == key)
        .ok_or(Error::NotParticipant)?;
    let branch = xpub
        .branches
        .get(keychain as usize)
        .ok_or(Error::InvalidKeychain)?;
    let branch_tweak = compute_bip32_tweak(c, &xpub.key, &xpub.chain_code, branch)?.tweak;
    let branch_secret = c.scalar_add(secret, &branch_tweak);
    if scalar_is_zero(&branch_secret) {
        return Err(Error::SecretKey);
    }

    let mut record = tree_root(c, d, keychain, tree_start)?;
    let tid = template_id(c, &c.descriptor_template(d)?);
    let signature = c.bip322_sign(&branch_secret, &root_message(c, &tid, &record.root))?;
    record.signature = Some(RootSignature {
        key,
        branch_tweak,
        signature,
    });
    Ok(record)
}

/// Builds the tree of `d` for `keychain` and `tree_start` with `ProofTreeBuilder`,
/// for the coordinator to serve membership proofs from.
pub fn build_tree<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    keychain: u32,
    tree_start: u32,
) -> Result<Tree, Error> {
    generate_tree(
        c,
        d,
        keychain,
        tree_start,
        ProofTreeBuilder::new(keychain, tree_start),
    )
}

/// Checks the signature of `record` as a BIP322 signature over
/// `root_message(template_id, root)` for the taproot address of its key plus
/// its branch tweak. A record with no signature is `MissingRootSignature`; a
/// key that is not a base key of `template` is `NotParticipant`; a failing
/// signature is `RootSignature`.
pub fn verify_root<B: BitcoinBackend>(
    c: &B,
    template: &B::Template,
    record: &RootRecord,
) -> Result<(), Error> {
    let signature = record
        .signature
        .as_ref()
        .ok_or(Error::MissingRootSignature)?;
    c.template_base_keys(template)
        .binary_search(&signature.key)
        .map_err(|_| Error::NotParticipant)?;
    let branch_key = tweak_key(c, &signature.key, &signature.branch_tweak)?;
    let tid = template_id(c, &c.template_bytes(template));
    let message = root_message(c, &tid, &record.root);
    if c.bip322_verify(&branch_key, &message, &signature.signature) {
        Ok(())
    } else {
        Err(Error::RootSignature)
    }
}
