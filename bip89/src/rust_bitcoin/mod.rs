//! `RustBitcoin`, the `BitcoinBackend` over rust-miniscript, rust-bitcoin's
//! `bitcoin_hashes` and libsecp256k1. Zero and infinity are mapped explicitly
//! because libsecp256k1 refuses them while the trait models them as valid
//! inputs and outputs. The descriptor is a `tr()` descriptor over multipath
//! extended keys, the template is the same descriptor over base keys, and the
//! PSBT carries bundles and proofs in the spec's proprietary fields. BIP322
//! signing and verification use the `bip322` crate.

use crate::{
    accumulator::tree::Proof,
    backend::{BitcoinBackend, Output, Sha256Engine, Sha512Engine, Xpub},
    bundle::Bundle,
    scalar::scalar_is_zero,
    Error,
};
use bip322::Verification;
use miniscript::{
    bitcoin::{
        consensus::encode::{deserialize, serialize},
        hashes::{sha256, sha512, Hash, HashEngine},
        secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey},
        Address, Network, PrivateKey, Witness,
    },
    DescriptorPublicKey,
};

mod descriptor;
mod psbt;

pub use miniscript;
pub use psbt::{PREFIX, SUBTYPE_PROOF, SUBTYPE_TWEAK};

/// The backend built on rust-miniscript and rust-bitcoin's dependencies.
pub struct RustBitcoin {
    secp: Secp256k1<All>,
}

impl RustBitcoin {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }
}

impl Default for RustBitcoin {
    fn default() -> Self {
        Self::new()
    }
}

/// The single-key taproot address of `key`, with no script tree.
fn taproot_address(secp: &Secp256k1<All>, key: &PublicKey) -> Address {
    // BIP322 only reads the address script, so the network is irrelevant
    Address::p2tr(secp, key.x_only_public_key().0, None, Network::Bitcoin)
}

/// A streaming SHA-256 engine backed by `bitcoin_hashes`.
pub struct Sha256(sha256::HashEngine);

impl Sha256Engine for Sha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.input(data);
    }

    fn finalize(self) -> [u8; 32] {
        sha256::Hash::from_engine(self.0).to_byte_array()
    }
}

/// A streaming SHA-512 engine backed by `bitcoin_hashes`.
pub struct Sha512(sha512::HashEngine);

impl Sha512Engine for Sha512 {
    fn update(&mut self, data: &[u8]) {
        self.0.input(data);
    }

    fn finalize(self) -> [u8; 64] {
        sha512::Hash::from_engine(self.0).to_byte_array()
    }
}

impl BitcoinBackend for RustBitcoin {
    type Sha256 = Sha256;
    type Sha512 = Sha512;
    type Descriptor = miniscript::Descriptor<DescriptorPublicKey>;
    type Template = miniscript::Descriptor<miniscript::bitcoin::PublicKey>;
    type Psbt = miniscript::bitcoin::Psbt;

    fn sha256(&self) -> Self::Sha256 {
        Sha256(Default::default())
    }

    fn sha512(&self) -> Self::Sha512 {
        Sha512(Default::default())
    }

    fn point_is_valid(&self, p: &[u8; 33]) -> bool {
        PublicKey::from_slice(p).is_ok()
    }

    fn point_add(&self, a: &[u8; 33], b: &[u8; 33]) -> Option<[u8; 33]> {
        let (Ok(a), Ok(b)) = (PublicKey::from_slice(a), PublicKey::from_slice(b)) else {
            return None;
        };
        match a.combine(&b) {
            Ok(sum) => Some(sum.serialize()),
            // the points are opposite, the sum is the point at infinity
            Err(_) => None,
        }
    }

    fn point_mul(&self, p: &[u8; 33], k: &[u8; 32]) -> Option<[u8; 33]> {
        if scalar_is_zero(k) {
            return None;
        }
        let (Ok(point), Ok(scalar)) = (PublicKey::from_slice(p), Scalar::from_be_bytes(*k)) else {
            return None;
        };
        match point.mul_tweak(&self.secp, &scalar) {
            Ok(result) => Some(result.serialize()),
            Err(_) => None,
        }
    }

    fn base_mul(&self, k: &[u8; 32]) -> Option<[u8; 33]> {
        match SecretKey::from_slice(k) {
            Ok(sk) => Some(PublicKey::from_secret_key(&self.secp, &sk).serialize()),
            // zero or out of range
            Err(_) => None,
        }
    }

    fn scalar_add(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        if scalar_is_zero(a) {
            return *b;
        }
        if scalar_is_zero(b) {
            return *a;
        }
        let (Ok(sk), Ok(tweak)) = (SecretKey::from_slice(a), Scalar::from_be_bytes(*b)) else {
            return [0u8; 32];
        };
        match sk.add_tweak(&tweak) {
            Ok(sum) => sum.secret_bytes(),
            // the sum is n
            Err(_) => [0u8; 32],
        }
    }

    fn scalar_mul(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        if scalar_is_zero(a) || scalar_is_zero(b) {
            return [0u8; 32];
        }
        let (Ok(sk), Ok(tweak)) = (SecretKey::from_slice(a), Scalar::from_be_bytes(*b)) else {
            return [0u8; 32];
        };
        match sk.mul_tweak(&tweak) {
            Ok(product) => product.secret_bytes(),
            Err(_) => [0u8; 32],
        }
    }

    fn bip322_sign(&self, secret: &[u8; 32], message: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let sk = SecretKey::from_slice(secret).map_err(|_| Error::SecretKey)?;
        let address = taproot_address(&self.secp, &PublicKey::from_secret_key(&self.secp, &sk));
        let private_key = PrivateKey::new(sk, Network::Bitcoin);
        let witness = bip322::sign_simple(&address, message, &[private_key], None)
            .map_err(|_| Error::SecretKey)?;
        Ok(serialize(&witness))
    }

    fn bip322_verify(&self, key: &[u8; 33], message: &[u8; 32], signature: &[u8]) -> bool {
        let (Ok(key), Ok(witness)) = (
            PublicKey::from_slice(key),
            deserialize::<Witness>(signature),
        ) else {
            return false;
        };
        let address = taproot_address(&self.secp, &key);
        matches!(
            bip322::verify_simple(&address, message, witness),
            Ok(Verification::Valid { .. })
        )
    }

    fn descriptor_policy(&self, d: &Self::Descriptor) -> Vec<u8> {
        d.to_string().into_bytes()
    }

    fn descriptor_template(&self, d: &Self::Descriptor) -> Result<Vec<u8>, Error> {
        Ok(descriptor::template(d)?.to_string().into_bytes())
    }

    fn descriptor_xpubs(&self, d: &Self::Descriptor) -> Result<Vec<Xpub>, Error> {
        descriptor::xpubs(d)
    }

    fn template_bytes(&self, t: &Self::Template) -> Vec<u8> {
        t.to_string().into_bytes()
    }

    fn template_base_keys(&self, t: &Self::Template) -> Vec<[u8; 33]> {
        descriptor::base_keys(t)
    }

    fn template_script_pubkey(
        &self,
        t: &Self::Template,
        tweaked: &[([u8; 33], [u8; 33])],
    ) -> Result<Vec<u8>, Error> {
        Ok(descriptor::tweak_template(t, tweaked)?
            .script_pubkey()
            .to_bytes())
    }

    fn template_leaf_hashes(
        &self,
        t: &Self::Template,
        tweaked: &[([u8; 33], [u8; 33])],
        key: &[u8; 33],
    ) -> Result<Vec<[u8; 32]>, Error> {
        descriptor::leaf_hashes(t, tweaked, key)
    }

    fn input_count(&self, p: &Self::Psbt) -> usize {
        p.unsigned_tx.input.len()
    }

    fn output_count(&self, p: &Self::Psbt) -> usize {
        p.unsigned_tx.output.len()
    }

    fn spent_output(&self, p: &Self::Psbt, input: usize) -> Result<Output, Error> {
        psbt::spent_output(p, input)
    }

    fn output(&self, p: &Self::Psbt, output: usize) -> Result<Output, Error> {
        let out = p.unsigned_tx.output.get(output).ok_or(Error::Psbt)?;
        Ok(Output {
            script_pubkey: out.script_pubkey.to_bytes(),
            value: out.value.to_sat(),
        })
    }

    fn input_bundle(&self, p: &Self::Psbt, input: usize) -> Result<Option<Bundle>, Error> {
        match psbt::entry(&p.inputs, p.unsigned_tx.input.len(), input) {
            Ok(inp) => psbt::read_bundle(&inp.proprietary),
            Err(_) => Ok(None),
        }
    }

    fn set_input_bundle(
        &self,
        p: &mut Self::Psbt,
        input: usize,
        bundle: &Bundle,
    ) -> Result<(), Error> {
        let count = p.unsigned_tx.input.len();
        let inp = psbt::entry_mut(&mut p.inputs, count, input)?;
        psbt::write_bundle(&mut inp.proprietary, bundle);
        Ok(())
    }

    fn output_bundle(&self, p: &Self::Psbt, output: usize) -> Result<Option<Bundle>, Error> {
        match psbt::entry(&p.outputs, p.unsigned_tx.output.len(), output) {
            Ok(out) => psbt::read_bundle(&out.proprietary),
            Err(_) => Ok(None),
        }
    }

    fn set_output_bundle(
        &self,
        p: &mut Self::Psbt,
        output: usize,
        bundle: &Bundle,
    ) -> Result<(), Error> {
        let count = p.unsigned_tx.output.len();
        let out = psbt::entry_mut(&mut p.outputs, count, output)?;
        psbt::write_bundle(&mut out.proprietary, bundle);
        Ok(())
    }

    fn output_proof(&self, p: &Self::Psbt, output: usize) -> Result<Option<Proof>, Error> {
        match psbt::entry(&p.outputs, p.unsigned_tx.output.len(), output) {
            Ok(out) => psbt::read_proof(&out.proprietary),
            Err(_) => Ok(None),
        }
    }

    fn set_output_proof(
        &self,
        p: &mut Self::Psbt,
        output: usize,
        proof: &Proof,
    ) -> Result<(), Error> {
        let count = p.unsigned_tx.output.len();
        let out = psbt::entry_mut(&mut p.outputs, count, output)?;
        psbt::write_proof(&mut out.proprietary, proof);
        Ok(())
    }

    fn tap_leaf_sighash(
        &self,
        p: &Self::Psbt,
        input: usize,
        leaf_hash: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        psbt::tap_leaf_sighash(p, input, leaf_hash)
    }

    fn add_tap_script_sig(
        &self,
        p: &mut Self::Psbt,
        input: usize,
        xonly: &[u8; 32],
        leaf_hash: &[u8; 32],
        sig: &[u8; 64],
    ) -> Result<(), Error> {
        psbt::add_tap_script_sig(p, input, xonly, leaf_hash, sig)
    }
}
