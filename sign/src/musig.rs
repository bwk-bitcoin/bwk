//! MuSig2 signing sessions, round detection, status and the finalizer role.
//!
//! Slots are rebuilt from the registered descriptor, never from the PSBT 0x1a:
//! one per (input, participant, aggregate, leaf), limited to the leaves present in
//! the input's `tap_scripts` and to a key path whose 0x1a the input carries.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use bwk_descriptor::{
    musig::musig_descriptor_to_string,
    wallet::{WalletDefiniteDescriptor, WalletDescriptor, WalletDescriptorExt},
};
use bwk_keys::musig::{DefiniteMusigAggregate, Error as KeyError};
use bwk_musig::{
    nonce_agg, partial_agg, partial_verify, rust_bitcoin::RustBitcoin, KeyAgg, SecNonce,
};
use bwk_psbt::musig::{musig_input_partial_sig, musig_input_participants, musig_input_pub_nonce};
use miniscript::{
    bitcoin::{
        bip32::{ChildNumber, DerivationPath, Fingerprint},
        consensus::encode::serialize,
        hashes::{sha256, Hash, HashEngine},
        psbt::Input,
        secp256k1::{schnorr, Message, PublicKey, Secp256k1},
        sighash::{Prevouts, SighashCache, TapSighashType},
        taproot::{self, LeafVersion, TapLeafHash, TapNodeHash},
        Psbt, TxOut,
    },
    Descriptor,
};

use crate::{error::Error, hot_signer::account_path};

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

/// A round-1 nonce waiting for round 2. Never cloned, printed or serialized.
pub(crate) struct PendingNonce {
    pub(crate) secnonce: SecNonce<RustBitcoin>,
    pub(crate) pubnonce: [u8; 66],
    pub(crate) sighash: [u8; 32],
}

pub(crate) struct MusigSession {
    pub(crate) id: MusigSessionId,
    pub(crate) nonces: BTreeMap<MusigSlot, PendingNonce>,
}

/// Where a session is kept: sha256 of the policy text, and the signer
/// fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MusigSessionKey {
    policy: [u8; 32],
    fingerprint: Fingerprint,
}

impl MusigSessionKey {
    pub(crate) fn new(descriptor: &WalletDescriptor, fingerprint: Fingerprint) -> Self {
        let policy = musig_descriptor_to_string(descriptor, false);
        Self {
            policy: sha256::Hash::hash(policy.as_bytes()).to_byte_array(),
            fingerprint,
        }
    }
}

/// In-memory session store; clones share it. It keeps at most one session per
/// (policy, signer fingerprint): a round 1 replaces the older one and drops its
/// secret nonces, so only the PSBT signed last with a wallet can finish round 2.
#[derive(Clone, Default)]
pub struct MusigSessionStore(Arc<Mutex<BTreeMap<MusigSessionKey, MusigSession>>>);

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

    /// Replaces any previous session under `key`.
    pub(crate) fn insert(&self, key: MusigSessionKey, session: MusigSession) {
        self.0.lock().expect("poisoned").insert(key, session);
    }

    /// Removes the session under `key`, handed out only when it is `id`: the
    /// store never hands one out and keeps it.
    pub(crate) fn take(&self, key: &MusigSessionKey, id: &MusigSessionId) -> Option<MusigSession> {
        self.0
            .lock()
            .expect("poisoned")
            .remove(key)
            .filter(|session| session.id == *id)
    }
}

/// Never prints a nonce.
impl std::fmt::Debug for MusigSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MusigSessionStore {{ sessions: {} }}", self.len())
    }
}

/// A slot with what signing or aggregating it needs.
pub(crate) struct SlotInfo {
    pub(crate) slot: MusigSlot,
    pub(crate) agg: DefiniteMusigAggregate,
    /// The descriptor's merkle root, for the key path taptweak.
    pub(crate) merkle_root: Option<TapNodeHash>,
    /// Master fingerprint and full path of the participant's cosigner key.
    pub(crate) signer: (Fingerprint, DerivationPath),
}

impl SlotInfo {
    pub(crate) fn key_path(&self) -> bool {
        self.slot.leaf_hash.is_none()
    }

    /// KeyAgg with the tweaks of the key signed for.
    pub(crate) fn key_agg(&self) -> Result<KeyAgg<RustBitcoin>, Error> {
        let key_agg = if self.key_path() {
            self.agg.key_path_key_agg(self.merkle_root)
        } else {
            self.agg.key_agg()
        };
        key_agg.map_err(|e| match e {
            KeyError::Aggregation(e) => Error::Musig(e),
            _ => Error::DerivationPath,
        })
    }

    pub(crate) fn pub_nonce(&self, input: &Input) -> Result<Option<[u8; 66]>, Error> {
        self.participant_nonce(input, self.slot.participant)
    }

    /// The 0x1b of `participant` for this slot's aggregate and leaf.
    pub(crate) fn participant_nonce(
        &self,
        input: &Input,
        participant: PublicKey,
    ) -> Result<Option<[u8; 66]>, Error> {
        Ok(musig_input_pub_nonce(
            input,
            participant,
            self.slot.aggregate,
            self.slot.leaf_hash,
        )?)
    }

    pub(crate) fn partial_sig(&self, input: &Input) -> Result<Option<[u8; 32]>, Error> {
        Ok(musig_input_partial_sig(
            input,
            self.slot.participant,
            self.slot.aggregate,
            self.slot.leaf_hash,
        )?)
    }

    /// Every participant's 0x1b in KeyAgg order; `MusigNonces` when one is missing.
    pub(crate) fn all_nonces(&self, input: &Input) -> Result<Vec<[u8; 66]>, Error> {
        self.agg
            .participants()
            .iter()
            .map(|participant| {
                self.participant_nonce(input, *participant)?
                    .ok_or(Error::MusigNonces)
            })
            .collect()
    }
}

/// sha256 over the unsigned transaction, every spent output, the policy text and
/// `fingerprint`: a change to any of them between the rounds changes the id.
pub fn session_id(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<MusigSessionId, Error> {
    let mut engine = sha256::Hash::engine();
    engine.input(&serialize(&psbt.unsigned_tx));
    for input in &psbt.inputs {
        let spent = input
            .witness_utxo
            .as_ref()
            .ok_or(Error::MissingWitnessUtxo)?;
        engine.input(&serialize(spent));
    }
    engine.input(musig_descriptor_to_string(descriptor, false).as_bytes());
    engine.input(fingerprint.as_bytes());
    Ok(MusigSessionId(
        sha256::Hash::from_engine(engine).to_byte_array(),
    ))
}

/// Every musig slot of the PSBT, rebuilt from `descriptor`.
pub fn musig_slots(psbt: &Psbt, descriptor: &WalletDescriptor) -> Result<Vec<MusigSlot>, Error> {
    Ok(slot_infos(psbt, descriptor)?
        .into_iter()
        .map(|info| info.slot)
        .collect())
}

/// The slots whose participant derives from `fingerprint`.
pub fn own_slots(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<Vec<MusigSlot>, Error> {
    Ok(slot_infos(psbt, descriptor)?
        .into_iter()
        .filter(|info| info.signer.0 == fingerprint)
        .map(|info| info.slot)
        .collect())
}

/// One slot per (input, participant, aggregate, leaf) the PSBT asks for.
pub(crate) fn slot_infos(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
) -> Result<Vec<SlotInfo>, Error> {
    let single_paths = descriptor
        .single_paths()
        .map_err(|_| Error::DerivationPath)?;
    let mut slots = Vec::new();
    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let Some(spent) = &input.witness_utxo else {
            continue;
        };
        let Some(definite) = input_descriptor(input, spent, &single_paths)? else {
            continue;
        };
        input_slots(input_index, input, &definite, &mut slots)?;
    }
    Ok(slots)
}

/// The descriptor derived at the input's (change, index), found from its
/// `tap_key_origins` and checked against the spent script; None when not ours.
fn input_descriptor(
    input: &Input,
    spent: &TxOut,
    single_paths: &[WalletDescriptor],
) -> Result<Option<WalletDefiniteDescriptor>, Error> {
    let candidates: BTreeSet<(bool, u32)> = input
        .tap_key_origins
        .values()
        .filter_map(|(_, (_, path))| account_path(path).ok())
        .filter(|(_, index)| ChildNumber::from_normal_idx(*index).is_ok())
        .collect();
    for (change, index) in candidates {
        let Some(single) = single_paths.get(usize::from(change)) else {
            continue;
        };
        let definite = single.derive_at(index).map_err(|_| Error::DerivationPath)?;
        if definite.script_pubkey() == spent.script_pubkey {
            return Ok(Some(definite));
        }
    }
    Ok(None)
}

/// The key path slots (when the input carries the internal aggregate's 0x1a) and
/// the script path slots of the leaves in `tap_scripts`.
fn input_slots(
    input_index: usize,
    input: &Input,
    definite: &WalletDefiniteDescriptor,
    slots: &mut Vec<SlotInfo>,
) -> Result<(), Error> {
    let Descriptor::Tr(tr) = definite else {
        return Ok(());
    };
    let merkle_root = tr.spend_info().merkle_root();
    if let Some(agg) = tr.internal_key().as_musig() {
        if musig_input_participants(input, agg.aggregate())?.is_some() {
            let key_agg = agg
                .key_path_key_agg(merkle_root)
                .map_err(|_| Error::DerivationPath)?;
            let output_key =
                PublicKey::from_slice(&key_agg.output_key()).map_err(|_| Error::DerivationPath)?;
            push_slots(input_index, agg, output_key, None, merkle_root, slots)?;
        }
    }
    let asked: BTreeSet<TapLeafHash> = input
        .tap_scripts
        .values()
        .map(|(script, version)| TapLeafHash::from_script(script, *version))
        .collect();
    for (_, ms) in tr.iter_scripts() {
        let leaf_hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);
        if !asked.contains(&leaf_hash) {
            continue;
        }
        for agg in ms.iter_pk().filter_map(|key| key.as_musig().cloned()) {
            let key = agg.key();
            push_slots(input_index, &agg, key, Some(leaf_hash), merkle_root, slots)?;
        }
    }
    Ok(())
}

/// One slot per participant of `agg`, signing for `aggregate`.
fn push_slots(
    input_index: usize,
    agg: &DefiniteMusigAggregate,
    aggregate: PublicKey,
    leaf_hash: Option<TapLeafHash>,
    merkle_root: Option<TapNodeHash>,
    infos: &mut Vec<SlotInfo>,
) -> Result<(), Error> {
    let secp = Secp256k1::verification_only();
    for participant in agg.participants() {
        let mut signer = None;
        for cosigner in agg.cosigners() {
            let key = cosigner
                .derive_public_key(&secp)
                .map_err(|_| Error::DerivationPath)?;
            if key.inner == *participant {
                let path = cosigner
                    .full_derivation_path()
                    .ok_or(Error::DerivationPath)?;
                signer = Some((cosigner.master_fingerprint(), path));
                break;
            }
        }
        let signer = signer.ok_or(Error::DerivationPath)?;
        infos.push(SlotInfo {
            slot: MusigSlot {
                input_index,
                participant: *participant,
                aggregate,
                leaf_hash,
            },
            agg: agg.clone(),
            merkle_root,
            signer,
        });
    }
    Ok(())
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
    let infos = slot_infos(psbt, descriptor)?;
    let mut cosigners: Vec<MusigCosignerStatus> = vec![];
    let (mut nonces, mut partial_sigs) = (0, 0);
    for info in &infos {
        let input = &psbt.inputs[info.slot.input_index];
        let has_nonce = info.pub_nonce(input)?.is_some();
        let has_partial_sig = info.partial_sig(input)?.is_some();
        let fingerprint = info.signer.0;
        let position = match cosigners.iter().position(|c| c.fingerprint == fingerprint) {
            Some(position) => position,
            None => {
                cosigners.push(MusigCosignerStatus {
                    fingerprint,
                    nonces: 0,
                    partial_sigs: 0,
                    expected: 0,
                });
                cosigners.len() - 1
            }
        };
        let status = &mut cosigners[position];
        status.expected += 1;
        status.nonces += u32::from(has_nonce);
        status.partial_sigs += u32::from(has_partial_sig);
        nonces += usize::from(has_nonce);
        partial_sigs += usize::from(has_partial_sig);
    }
    let round = match infos.len() {
        0 => MusigRound::NotMusig,
        n if nonces < n => MusigRound::Nonces,
        n if partial_sigs < n => MusigRound::PartialSigs,
        _ => MusigRound::Ready,
    };
    Ok(MusigStatus { round, cosigners })
}

/// Verifies every partial sig, aggregates each complete slot into tap_key_sig or
/// tap_script_sigs; the count aggregated.
pub fn aggregate_partial_sigs(
    psbt: &mut Psbt,
    descriptor: &WalletDescriptor,
) -> Result<usize, Error> {
    let mut groups: BTreeMap<(usize, PublicKey, Option<TapLeafHash>), Vec<SlotInfo>> =
        BTreeMap::new();
    for info in slot_infos(psbt, descriptor)? {
        let slot = info.slot;
        groups
            .entry((slot.input_index, slot.aggregate, slot.leaf_hash))
            .or_default()
            .push(info);
    }
    let secp = Secp256k1::verification_only();
    let mut aggregated = 0;
    for group in groups.values() {
        let input = &psbt.inputs[group[0].slot.input_index];
        let Some(partial_sigs) = group
            .iter()
            .map(|info| info.partial_sig(input))
            .collect::<Result<Option<Vec<_>>, _>>()?
        else {
            continue;
        };
        let signature = aggregate_group(psbt, group, &partial_sigs)?;
        let first = &group[0].slot;
        let message = Message::from_digest(slot_sighash(psbt, first)?);
        let aggregate = first.aggregate.x_only_public_key().0;
        secp.verify_schnorr(&signature, &message, &aggregate)
            .map_err(|_| Error::MusigPartialSig(first.input_index))?;
        let signature = taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        };
        let input = &mut psbt.inputs[first.input_index];
        match first.leaf_hash {
            None => input.tap_key_sig = Some(signature),
            Some(leaf_hash) => {
                input
                    .tap_script_sigs
                    .insert((aggregate, leaf_hash), signature);
            }
        }
        aggregated += 1;
    }
    Ok(aggregated)
}

/// Checks each partial sig of one (input, aggregate, leaf), in KeyAgg order, and
/// aggregates them.
fn aggregate_group(
    psbt: &Psbt,
    group: &[SlotInfo],
    partial_sigs: &[[u8; 32]],
) -> Result<schnorr::Signature, Error> {
    let first = &group[0];
    let input_index = first.slot.input_index;
    let input = &psbt.inputs[input_index];
    let pubnonces = first.all_nonces(input)?;
    let aggnonce = nonce_agg(&RustBitcoin, &pubnonces)?;
    let key_agg = first.key_agg()?;
    let sighash = slot_sighash(psbt, &first.slot)?;
    // `group` and `pubnonces` both follow the KeyAgg order.
    for ((info, partial_sig), pubnonce) in group.iter().zip(partial_sigs).zip(&pubnonces) {
        let valid = partial_verify(
            &RustBitcoin,
            partial_sig,
            pubnonce,
            &info.slot.participant.serialize(),
            &key_agg,
            &aggnonce,
            &sighash,
        );
        if !valid {
            return Err(Error::MusigPartialSig(input_index));
        }
    }
    let signature = partial_agg(&RustBitcoin, &key_agg, &aggnonce, &sighash, partial_sigs)
        .map_err(|_| Error::MusigPartialSig(input_index))?;
    schnorr::Signature::from_slice(&signature).map_err(|_| Error::MusigPartialSig(input_index))
}

/// The BIP-341 sighash a slot signs (default sighash type).
pub fn slot_sighash(psbt: &Psbt, slot: &MusigSlot) -> Result<[u8; 32], Error> {
    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().ok_or(Error::MissingWitnessUtxo))
        .collect::<Result<Vec<_>, _>>()?;
    let input = psbt.inputs.get(slot.input_index).ok_or(Error::InputIndex)?;
    if let Some(sighash_type) = input.sighash_type {
        if sighash_type.taproot_hash_ty() != Ok(TapSighashType::Default) {
            return Err(Error::SighashFail);
        }
    }
    let prevouts = Prevouts::All(&prevouts);
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = match slot.leaf_hash {
        None => cache
            .taproot_key_spend_signature_hash(slot.input_index, &prevouts, TapSighashType::Default)
            .map_err(|_| Error::InsanePrevouts)?,
        Some(leaf_hash) => cache
            .taproot_script_spend_signature_hash(
                slot.input_index,
                &prevouts,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|_| Error::InsaneTaptreeInfo)?,
    };
    Ok(sighash.to_byte_array())
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
