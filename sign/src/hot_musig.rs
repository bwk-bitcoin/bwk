//! Transaction-independent hot nonces. The application owns allocation and durable
//! burning: delete persisted secret state before consuming a session for signing.
//! Restoring or copying exported bytes cannot revoke previous external copies.

use std::collections::BTreeSet;

use bwk_descriptor::wallet::{WalletDescriptor, WalletDescriptorExt};
use bwk_musig::{nonce_gen_with_rand, rust_bitcoin::RustBitcoin, SecNonce};
use bwk_psbt::musig::{set_musig_input_pub_nonce, MusigPubNonce};
use miniscript::bitcoin::{
    bip32::Fingerprint,
    hashes::{sha256, Hash, HashEngine},
    Psbt,
};

use crate::{
    error::Error,
    hot_signer::{fresh_rand, wipe},
    musig::{expression_slots, slot_infos, MusigSessionId, MusigSessionKey, SlotInfo},
};

pub const MAX_HOT_MUSIG_INPUTS: u8 = 8;
const VERSION: u8 = 1;
const ID_OFFSET: usize = 1;
const POLICY_OFFSET: usize = ID_OFFSET + 32;
const OWNER_OFFSET: usize = POLICY_OFFSET + 32;
const COVERAGE_OFFSET: usize = OWNER_OFFSET + 4;
const ROOT_OFFSET: usize = COVERAGE_OFFSET + 1;
const ENCODED_LEN: usize = ROOT_OFFSET + 32;

/// Secret root and binding, never cloned or printed. One round-two call consumes
/// the whole value, including on failure. Every creation has a fresh root even
/// when the caller reuses an ID. The application owns same-ID replacement.
pub struct HotMusigSession {
    root: [u8; 32],
    id: MusigSessionId,
    owner: MusigSessionKey,
    max_inputs: u8,
}

/// Plaintext export for application encryption, erased when dropped. Neither
/// this type nor the session implements Clone or Debug. Do not log its bytes.
pub struct HotMusigSessionBytes(Vec<u8>);

impl HotMusigSessionBytes {
    /// Takes ownership of decrypted bytes, including malformed payloads.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for HotMusigSessionBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// A public prefetch nonce with its stable expression occurrence and input slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotMusigPubNonce {
    pub input_index: usize,
    pub expression_index: usize,
    pub nonce: MusigPubNonce,
}

impl HotMusigSession {
    pub(crate) fn create(
        descriptor: &WalletDescriptor,
        fingerprint: Fingerprint,
        id: MusigSessionId,
        max_inputs: u8,
    ) -> Result<Self, Error> {
        let mut session = Self {
            root: [0; 32],
            id,
            owner: MusigSessionKey::new(descriptor, fingerprint),
            max_inputs,
        };
        fresh_rand(&mut session.root)?;
        session.validate(descriptor, fingerprint)?;
        Ok(session)
    }

    pub fn id(&self) -> MusigSessionId {
        self.id
    }

    /// Absolute input positions `0..max_inputs`, not the count of owned inputs.
    pub fn max_inputs(&self) -> u8 {
        self.max_inputs
    }

    /// Consumes the root into plaintext bytes. Encrypt before persistence.
    pub fn encode(self) -> HotMusigSessionBytes {
        let mut bytes = Vec::with_capacity(ENCODED_LEN);
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.id.0);
        bytes.extend_from_slice(&self.owner.policy);
        bytes.extend_from_slice(self.owner.fingerprint.as_bytes());
        bytes.push(self.max_inputs);
        bytes.extend_from_slice(&self.root);
        HotMusigSessionBytes(bytes)
    }

    /// Validates format, nonzero root, coverage, canonical policy and expected
    /// fingerprint. Actual private-key ownership is checked again at signing.
    /// Both success and failure erase the supplied plaintext bytes.
    pub fn decode(
        bytes: HotMusigSessionBytes,
        descriptor: &WalletDescriptor,
        fingerprint: Fingerprint,
    ) -> Result<Self, Error> {
        let bytes = bytes.as_bytes();
        if bytes.len() != ENCODED_LEN || bytes[0] != VERSION {
            return Err(Error::MusigSession);
        }
        let mut session = Self {
            root: [0; 32],
            id: MusigSessionId([0; 32]),
            owner: MusigSessionKey::new(descriptor, fingerprint),
            max_inputs: bytes[COVERAGE_OFFSET],
        };
        session
            .id
            .0
            .copy_from_slice(&bytes[ID_OFFSET..POLICY_OFFSET]);
        if bytes[POLICY_OFFSET..OWNER_OFFSET] != session.owner.policy
            || bytes[OWNER_OFFSET..COVERAGE_OFFSET] != fingerprint.as_bytes()[..]
        {
            return Err(Error::MusigSession);
        }
        session.root.copy_from_slice(&bytes[ROOT_OFFSET..]);
        session.validate(descriptor, fingerprint)?;
        Ok(session)
    }

    pub(crate) fn validate(
        &self,
        descriptor: &WalletDescriptor,
        fingerprint: Fingerprint,
    ) -> Result<(), Error> {
        if self.owner != MusigSessionKey::new(descriptor, fingerprint)
            || !(1..=MAX_HOT_MUSIG_INPUTS).contains(&self.max_inputs)
            || self.root == [0; 32]
        {
            return Err(Error::MusigSession);
        }
        Ok(())
    }

    /// Prefetch every owned expression for all covered input positions at one
    /// public keychain and derivation index. Any publicly derivable index is
    /// supported; the actual participant public key also binds BIP-327 NonceGen.
    pub fn public_nonces(
        &self,
        descriptor: &WalletDescriptor,
        keychain: usize,
        derivation_index: u32,
    ) -> Result<Vec<HotMusigPubNonce>, Error> {
        self.validate(descriptor, self.owner.fingerprint)?;
        let paths = descriptor
            .single_paths()
            .map_err(|_| Error::DerivationPath)?;
        let definite = paths
            .get(keychain)
            .ok_or(Error::DerivationPath)?
            .derive_at(derivation_index)
            .map_err(|_| Error::DerivationPath)?;
        let mut nonces = Vec::new();
        for input_index in 0..usize::from(self.max_inputs) {
            for info in expression_slots(input_index, &definite)? {
                if info.signer.0 == self.owner.fingerprint {
                    let (_, pubnonce) = self.nonce(&info)?;
                    nonces.push(HotMusigPubNonce {
                        input_index,
                        expression_index: info.expression_index,
                        nonce: Self::public_nonce(&info, pubnonce),
                    });
                }
            }
        }
        if nonces.is_empty() {
            return Err(Error::InputNotOwned);
        }
        Ok(nonces)
    }

    /// Publish selected PSBT slots without a mnemonic. The caller must durably
    /// allocate this session to this attempt first and never recycle allocations.
    /// Existing differing own nonces are rejected; no PSBT changes on failure.
    pub fn publish_nonces(
        &self,
        psbt: &mut Psbt,
        descriptor: &WalletDescriptor,
    ) -> Result<(), Error> {
        let own = self.slot_infos(psbt, descriptor)?;
        let mut published = psbt.clone();
        for info in own {
            let (_, pubnonce) = self.nonce(&info)?;
            if info
                .pub_nonce(&psbt.inputs[info.slot.input_index])?
                .is_some_and(|present| present != pubnonce)
            {
                return Err(Error::MusigSession);
            }
            set_musig_input_pub_nonce(
                &mut published.inputs[info.slot.input_index],
                &Self::public_nonce(&info, pubnonce),
            );
        }
        *psbt = published;
        Ok(())
    }

    pub(crate) fn slot_infos(
        &self,
        psbt: &Psbt,
        descriptor: &WalletDescriptor,
    ) -> Result<Vec<SlotInfo>, Error> {
        self.validate(descriptor, self.owner.fingerprint)?;
        let own: Vec<_> = slot_infos(psbt, descriptor)?
            .into_iter()
            .filter(|info| info.signer.0 == self.owner.fingerprint)
            .collect();
        if own.is_empty() {
            return Err(Error::InputNotOwned);
        }
        let mut unique = BTreeSet::new();
        for info in &own {
            if info.slot.input_index >= usize::from(self.max_inputs) || !unique.insert(info.slot) {
                return Err(Error::MusigSession);
            }
        }
        Ok(own)
    }

    pub(crate) fn nonce(
        &self,
        info: &SlotInfo,
    ) -> Result<(SecNonce<RustBitcoin>, [u8; 66]), Error> {
        let mut engine = sha256::Hash::engine();
        engine.input(b"bwk/hot-musig-session/nonce/v1");
        engine.input(&self.root);
        engine.input(&self.id.0);
        engine.input(&self.owner.policy);
        engine.input(self.owner.fingerprint.as_bytes());
        engine.input(&(info.slot.input_index as u64).to_le_bytes());
        engine.input(&(info.expression_index as u64).to_le_bytes());
        let mut rand = sha256::Hash::from_engine(engine).to_byte_array();
        // Omit the aggregate, secret key and message so locked publication and
        // regeneration use exactly the same BIP-327 inputs for every spend path.
        let generated = nonce_gen_with_rand(
            &RustBitcoin,
            &rand,
            None,
            &info.slot.participant.serialize(),
            None,
            None,
            None,
        );
        wipe(&mut rand);
        Ok(generated?)
    }

    fn public_nonce(info: &SlotInfo, nonce: [u8; 66]) -> MusigPubNonce {
        MusigPubNonce {
            participant: info.slot.participant,
            aggregate: info.slot.aggregate,
            leaf_hash: info.slot.leaf_hash,
            nonce,
        }
    }
}

impl Drop for HotMusigSession {
    fn drop(&mut self) {
        wipe(&mut self.root);
    }
}
