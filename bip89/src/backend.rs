//! The `BitcoinBackend` trait: everything the protocol takes from a bitcoin
//! library. Hashing, curve arithmetic, BIP322 message signing, descriptor and
//! template handling and PSBT access all go through it, so the protocol code
//! stays no_std and dependency-free. Secret scalar arithmetic goes through the backend, so a
//! constant-time backend keeps the whole crate constant time. Hashing is
//! streaming so large inputs never need a buffer.

use alloc::vec::Vec;

use crate::{accumulator::tree::Proof, bundle::Bundle, Error};

/// A streaming SHA-256 engine.
pub trait Sha256Engine {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 32];
}

/// A streaming SHA-512 engine.
pub trait Sha512Engine {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 64];
}

/// A source of randomness for nonces and secrets. Kept apart from the
/// backend: entropy is supplied per call.
pub trait Rng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// An extended public key inside a descriptor. `branches[k]` is the fixed
/// steps followed by multipath element `k`: the tweak path of keychain `k`
/// without the final index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xpub {
    pub key: [u8; 33],
    pub chain_code: [u8; 32],
    pub branches: [Vec<u32>; 2],
}

/// A transaction output as the protocol reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub script_pubkey: Vec<u8>,
    pub value: u64,
}

/// The bitcoin library the protocol runs on.
pub trait BitcoinBackend {
    type Sha256: Sha256Engine;
    type Sha512: Sha512Engine;
    /// The full wallet descriptor, held by the signing key holder and the
    /// coordinator: every key carries its chain code and fixed steps.
    type Descriptor;
    /// What the delegator holds: the descriptor reduced to its base keys.
    type Template;
    type Psbt;

    fn sha256(&self) -> Self::Sha256;
    fn sha512(&self) -> Self::Sha512;

    // Inputs are valid points and canonical scalars; None means infinity.
    /// True when `p` is a valid 33-byte compressed encoding of a curve point.
    fn point_is_valid(&self, p: &[u8; 33]) -> bool;
    fn point_add(&self, a: &[u8; 33], b: &[u8; 33]) -> Option<[u8; 33]>;
    fn point_mul(&self, p: &[u8; 33], k: &[u8; 32]) -> Option<[u8; 33]>;
    /// Multiplies the curve generator by `k`. None for a zero scalar.
    fn base_mul(&self, k: &[u8; 32]) -> Option<[u8; 33]>;
    fn scalar_add(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32];
    fn scalar_mul(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32];

    /// BIP322 simple signature of `message` for the single-key taproot
    /// address of `secret`'s public key, as consensus-serialized witness bytes.
    fn bip322_sign(&self, secret: &[u8; 32], message: &[u8; 32]) -> Result<Vec<u8>, Error>;
    /// Checks a BIP322 simple signature of `message` for the single-key
    /// taproot address of `key`.
    fn bip322_verify(&self, key: &[u8; 33], message: &[u8; 32], signature: &[u8]) -> bool;

    /// The canonical descriptor bytes.
    fn descriptor_policy(&self, d: &Self::Descriptor) -> Vec<u8>;
    /// The canonical bytes of the descriptor's template.
    fn descriptor_template(&self, d: &Self::Descriptor) -> Result<Vec<u8>, Error>;
    /// Validates the descriptor shape and returns its keys sorted by key.
    fn descriptor_xpubs(&self, d: &Self::Descriptor) -> Result<Vec<Xpub>, Error>;

    /// The canonical template bytes.
    fn template_bytes(&self, t: &Self::Template) -> Vec<u8>;
    /// The base keys of the template, sorted and deduplicated.
    fn template_base_keys(&self, t: &Self::Template) -> Vec<[u8; 33]>;
    /// Builds the script pubkey from tweaked keys. `tweaked` pairs each base
    /// key with its tweaked key, sorted by base key.
    fn template_script_pubkey(
        &self,
        t: &Self::Template,
        tweaked: &[([u8; 33], [u8; 33])],
    ) -> Result<Vec<u8>, Error>;
    /// The tapleaf hashes in which `key`, a tweaked key, appears.
    fn template_leaf_hashes(
        &self,
        t: &Self::Template,
        tweaked: &[([u8; 33], [u8; 33])],
        key: &[u8; 33],
    ) -> Result<Vec<[u8; 32]>, Error>;

    /// Number of inputs of the transaction.
    fn input_count(&self, p: &Self::Psbt) -> usize;
    /// Number of outputs of the transaction.
    fn output_count(&self, p: &Self::Psbt) -> usize;
    /// The output spent by `input` (every input here is taproot).
    fn spent_output(&self, p: &Self::Psbt, input: usize) -> Result<Output, Error>;
    /// The transaction output at `output`.
    fn output(&self, p: &Self::Psbt, output: usize) -> Result<Output, Error>;
    /// The bundle carried by `input`, if any.
    fn input_bundle(&self, p: &Self::Psbt, input: usize) -> Result<Option<Bundle>, Error>;
    fn set_input_bundle(
        &self,
        p: &mut Self::Psbt,
        input: usize,
        bundle: &Bundle,
    ) -> Result<(), Error>;
    /// The bundle carried by `output`, if any.
    fn output_bundle(&self, p: &Self::Psbt, output: usize) -> Result<Option<Bundle>, Error>;
    fn set_output_bundle(
        &self,
        p: &mut Self::Psbt,
        output: usize,
        bundle: &Bundle,
    ) -> Result<(), Error>;
    /// The accumulator proof carried by `output`, if any.
    fn output_proof(&self, p: &Self::Psbt, output: usize) -> Result<Option<Proof>, Error>;
    fn set_output_proof(
        &self,
        p: &mut Self::Psbt,
        output: usize,
        proof: &Proof,
    ) -> Result<(), Error>;
    /// The BIP341 script-path sighash of `input` for `leaf_hash`, over every
    /// spent output with the default sighash type.
    fn tap_leaf_sighash(
        &self,
        p: &Self::Psbt,
        input: usize,
        leaf_hash: &[u8; 32],
    ) -> Result<[u8; 32], Error>;
    /// Adds a tapscript signature for `xonly` and `leaf_hash` to `input`.
    fn add_tap_script_sig(
        &self,
        p: &mut Self::Psbt,
        input: usize,
        xonly: &[u8; 32],
        leaf_hash: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<(), Error>;
}
