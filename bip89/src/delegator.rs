//! The delegator pins the template, the accumulator roots and its root policy
//! at registration, and never uses a template, root or policy from a signing
//! request. An output is owned only when its bundle rebuilds its script and is
//! committed under a root that passed the pinned policy when it was recorded:
//! `ChangeOutputVerification` alone accepts forged tweaks, since it cannot
//! tell a genuine tweak from any other scalar. A delegator that registers under
//! `AllowUnsigned` trusts the authenticated setup channel the roots came over
//! instead of a signature. Verification here applies to the non-blinded mode
//! only; in blinded mode the delegator sees no transaction, script or bundle.

use alloc::{vec, vec::Vec};

use crate::{
    accumulator::{
        record::{verify_root, RootPolicy, RootRecord},
        tree::verify_proof,
    },
    backend::{BitcoinBackend, Rng},
    scalar::{scalar_is_valid, xbytes},
    sign::delegator_sign,
    tweak::tweak_key,
    verify::{change_output_verification, input_verification, tweaked_keys},
    Error,
};

/// A delegator's pinned template, root policy and recorded accumulator roots.
pub struct Registration<B: BitcoinBackend> {
    template: B::Template,
    policy: RootPolicy,
    base_keys: Vec<[u8; 33]>,
    roots: Vec<[u8; 32]>,
}

/// Registers `template` under `policy` with the root of the receive tree
/// (keychain 0) and of the change tree (keychain 1). A template with no base
/// keys is `Template`; a root on another keychain is `InvalidKeychain`. Both
/// records must pass `verify_root` under `policy` before their roots are
/// recorded.
pub fn register<B: BitcoinBackend>(
    b: &B,
    template: B::Template,
    policy: RootPolicy,
    receive: &RootRecord,
    change: &RootRecord,
) -> Result<Registration<B>, Error> {
    let base_keys = b.template_base_keys(&template);
    if base_keys.is_empty() {
        return Err(Error::Template);
    }
    if receive.keychain != 0 || change.keychain != 1 {
        return Err(Error::InvalidKeychain);
    }
    verify_root(b, &template, receive, policy)?;
    verify_root(b, &template, change, policy)?;
    Ok(Registration {
        template,
        policy,
        base_keys,
        roots: vec![receive.root, change.root],
    })
}

impl<B: BitcoinBackend> Registration<B> {
    /// Records the root of the next tree of a keychain, once the current one
    /// is exhausted. The record must pass `verify_root` first, under the policy
    /// pinned at registration: a caller cannot relax it for one tree.
    pub fn record_root(&mut self, b: &B, record: &RootRecord) -> Result<(), Error> {
        verify_root(b, &self.template, record, self.policy)?;
        self.roots.push(record.root);
        Ok(())
    }
}

/// Verifies every input and every bundle-carrying output of `psbt` against
/// `reg`, and returns the outflow: the amount leaving the wallet, fee
/// included.
///
/// Every input needs a bundle (`MissingBundle`) whose tweaked script matches
/// the spent output (`InputMismatch`). Every output carrying a bundle needs a
/// matching script (`OutputMismatch`) and an accumulator proof (`MissingProof`)
/// that verifies against one of the recorded roots (`NotCommitted`); outputs
/// without a bundle count as outflow. A proof field on any output must decode
/// (`ProofLength`). The scripts compared are always the PSBT's own
/// scriptPubKeys, never data next to the bundle.
/// Every PSBT input must belong to the wallet, so the outflow covers every spent value.
pub fn verify_spend<B: BitcoinBackend>(
    b: &B,
    reg: &Registration<B>,
    psbt: &B::Psbt,
) -> Result<u64, Error> {
    let mut inputs: u64 = 0;
    for i in 0..b.input_count(psbt) {
        let bundle = b.input_bundle(psbt, i)?.ok_or(Error::MissingBundle(i))?;
        let spent = b.spent_output(psbt, i)?;
        if !input_verification(b, &reg.template, &spent.script_pubkey, &bundle)? {
            return Err(Error::InputMismatch(i));
        }
        inputs = inputs.checked_add(spent.value).ok_or(Error::Amount)?;
    }

    let mut owned: u64 = 0;
    for o in 0..b.output_count(psbt) {
        let proof = b.output_proof(psbt, o)?;
        let Some(bundle) = b.output_bundle(psbt, o)? else {
            continue;
        };
        let output = b.output(psbt, o)?;
        if !change_output_verification(b, &reg.template, &output.script_pubkey, &bundle)? {
            return Err(Error::OutputMismatch(o));
        }
        let proof = proof.ok_or(Error::MissingProof(o))?;
        if !reg
            .roots
            .iter()
            .any(|root| verify_proof(b, &bundle, &proof, root))
        {
            return Err(Error::NotCommitted);
        }
        owned = owned.checked_add(output.value).ok_or(Error::Amount)?;
    }

    inputs.checked_sub(owned).ok_or(Error::Amount)
}

/// Verifies `psbt` against `reg`, then signs every tapleaf that carries the
/// delegator's tweaked key on every input with BIP89 `DelegatorSign`, and
/// adds the signatures through the backend. Verification always runs
/// first, so a refused spend writes no signature. The signing key of each
/// input is `secret` plus that input's tweak for `secret`'s base key.
pub fn sign_spend<B: BitcoinBackend, R: Rng>(
    b: &B,
    rng: &mut R,
    reg: &Registration<B>,
    secret: &[u8; 32],
    psbt: &mut B::Psbt,
) -> Result<u64, Error> {
    let outflow = verify_spend(b, reg, psbt)?;

    if !scalar_is_valid(secret) {
        return Err(Error::SecretKey);
    }
    let base = b.base_mul(secret).ok_or(Error::SecretKey)?;
    reg.base_keys
        .binary_search(&base)
        .map_err(|_| Error::NotParticipant)?;

    let mut planned = Vec::with_capacity(b.input_count(psbt));
    for i in 0..b.input_count(psbt) {
        let bundle = b.input_bundle(psbt, i)?.ok_or(Error::MissingBundle(i))?;
        let tweak = bundle.tweak(&base).ok_or(Error::MissingTweak)?;
        let tweaked = tweak_key(b, &base, &tweak)?;
        let pairs = tweaked_keys(b, &reg.base_keys, &bundle)?;
        let leaves = b.template_leaf_hashes(&reg.template, &pairs, &tweaked)?;
        if leaves.is_empty() {
            return Err(Error::NothingToSign(i));
        }
        planned.push((i, tweak, xbytes(&tweaked), leaves));
    }

    for (i, tweak, xonly, leaves) in planned {
        for leaf in leaves {
            let msg = b.tap_leaf_sighash(psbt, i, &leaf)?;
            let mut aux = [0u8; 32];
            rng.fill_bytes(&mut aux);
            let sig = delegator_sign(b, &tweak, secret, &msg, &aux)?;
            b.add_tap_script_sig(psbt, i, &xonly, &leaf, &sig)?;
        }
    }

    Ok(outflow)
}
