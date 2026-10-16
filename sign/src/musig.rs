//! MuSig2 signing sessions, round detection, status and the finalizer role.

#![allow(dead_code, unused_variables)]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bwk_descriptor::wallet::WalletDescriptor;
use bwk_musig::{rust_bitcoin::RustBitcoin, SecNonce};
use miniscript::bitcoin::{bip32::Fingerprint, secp256k1::PublicKey, taproot::TapLeafHash, Psbt};

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigSessionId(pub [u8; 32]);

/// One (input, participant, aggregate, leaf) a signer contributes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MusigSlot {
    pub input_index: usize,
    pub participant: PublicKey,
    pub aggregate: PublicKey,
    pub leaf_hash: Option<TapLeafHash>,
}

struct PendingNonce {
    secnonce: SecNonce<RustBitcoin>,
    pubnonce: [u8; 66],
    sighash: [u8; 32],
}

struct MusigSession {
    nonces: BTreeMap<MusigSlot, PendingNonce>,
}

/// In-memory session store; clones share it.
#[derive(Clone, Default)]
pub struct MusigSessionStore(Arc<Mutex<BTreeMap<MusigSessionId, MusigSession>>>);

impl MusigSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.lock().expect("poisoned").is_empty()
    }

    pub fn clear(&self) {
        self.0.lock().expect("poisoned").clear();
    }
}

/// Never prints a nonce.
impl std::fmt::Debug for MusigSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MusigSessionStore {{ sessions: {} }}", self.len())
    }
}

pub fn session_id(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<MusigSessionId, Error> {
    todo!()
}

/// Every musig slot of the PSBT, rebuilt from `descriptor`.
pub fn musig_slots(psbt: &Psbt, descriptor: &WalletDescriptor) -> Result<Vec<MusigSlot>, Error> {
    todo!()
}

/// The slots whose participant derives from `fingerprint`.
pub fn own_slots(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<Vec<MusigSlot>, Error> {
    todo!()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MusigRound {
    /// No musig input.
    NotMusig,
    /// Some 0x1b missing.
    Nonces,
    /// Every 0x1b present, some 0x1c missing.
    PartialSigs,
    /// Every 0x1c present: the finalizer can aggregate.
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusigCosignerStatus {
    pub fingerprint: Fingerprint,
    pub nonces: u32,
    pub partial_sigs: u32,
    pub expected: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MusigStatus {
    pub round: MusigRound,
    pub cosigners: Vec<MusigCosignerStatus>,
}

pub fn musig_status(psbt: &Psbt, descriptor: &WalletDescriptor) -> Result<MusigStatus, Error> {
    todo!()
}

/// Verifies every partial sig, aggregates each complete slot into tap_key_sig or
/// tap_script_sigs; the count aggregated.
pub fn aggregate_partial_sigs(
    psbt: &mut Psbt,
    descriptor: &WalletDescriptor,
) -> Result<usize, Error> {
    todo!()
}

/// The BIP-341 sighash a slot signs (default sighash type).
pub fn slot_sighash(psbt: &Psbt, slot: &MusigSlot) -> Result<[u8; 32], Error> {
    todo!()
}

#[cfg(test)]
mod tests {
    use crate::musig::MusigSessionStore;

    #[test]
    fn session_store_clones_share_state() {
        let store = MusigSessionStore::new();
        let clone = store.clone();
        assert!(store.is_empty());
        assert_eq!(clone.len(), store.len());
        clone.clear();
        assert!(store.is_empty());
        assert!(clone.is_empty());
        assert_eq!(format!("{store:?}"), "MusigSessionStore { sessions: 0 }");
    }
}
