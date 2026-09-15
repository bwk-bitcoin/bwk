//! Root signatures. A key of the descriptor signs each accumulator root with
//! BIP322, for the single-key taproot address of its branch key on the tree's
//! keychain, so the delegator checks it against a base key of the template it
//! holds. The signed message binds the template id, so a root for another
//! wallet under the same key is refused.

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

/// A root signed by one key of the descriptor, paired with the tree it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRoot {
    pub keychain: u32,
    pub tree_start: u32,
    pub root: [u8; 32],
    /// Base key of the signer.
    pub key: [u8; 33],
    /// Tweak from `key` to its branch key for `keychain`.
    pub branch_tweak: [u8; 32],
    /// BIP322 simple signature for the taproot address of the branch key.
    pub signature: Vec<u8>,
}

/// Builds the tree of `d` for `keychain` and `tree_start` with `NullTreeBuilder`,
/// then signs its root with the branch key of `secret` for `keychain`. The
/// signer builds the tree itself; this function never accepts a root from the
/// caller. A secret whose public key is not a key of `d` is `NotParticipant`.
pub fn sign_tree_root<B: BitcoinBackend>(
    c: &B,
    d: &B::Descriptor,
    secret: &[u8; 32],
    keychain: u32,
    tree_start: u32,
) -> Result<SignedRoot, Error> {
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

    let root = generate_tree(c, d, keychain, tree_start, NullTreeBuilder)?;
    let tid = template_id(c, &c.descriptor_template(d)?);
    let signature = c.bip322_sign(&branch_secret, &root_message(c, &tid, &root))?;
    Ok(SignedRoot {
        keychain,
        tree_start,
        root,
        key,
        branch_tweak,
        signature,
    })
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

/// Checks `signed` as a BIP322 signature over `root_message(template_id, root)`
/// for the taproot address of its key plus its branch tweak. A key that is not
/// a base key of `template` is `NotParticipant`; a failing signature is
/// `RootSignature`.
pub fn verify_root<B: BitcoinBackend>(
    c: &B,
    template: &B::Template,
    signed: &SignedRoot,
) -> Result<(), Error> {
    c.template_base_keys(template)
        .binary_search(&signed.key)
        .map_err(|_| Error::NotParticipant)?;
    let branch_key = tweak_key(c, &signed.key, &signed.branch_tweak)?;
    let tid = template_id(c, &c.template_bytes(template));
    let message = root_message(c, &tid, &signed.root);
    if c.bip322_verify(&branch_key, &message, &signed.signature) {
        Ok(())
    } else {
        Err(Error::RootSignature)
    }
}
