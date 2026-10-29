//! Durable host allocation and manager attribution for cached QR MuSig signing.
//!
//! The consumer must supply an exclusively owned durable Store. Noop backends,
//! shared writers, rollback, restored snapshots and deleting used IDs are not
//! supported: they can make an allocated public nonce available a second time.
//! Store::flush must commit all prior writes before returning success. The host
//! never accesses a backend directly. Record codecs can be used with RamStore.

use std::collections::BTreeSet;

use bwk_descriptor::{
    musig::{musig_descriptor_to_string, parse_musig_descriptor},
    wallet::{WalletDescriptor, WalletDescriptorExt},
};
use bwk_musig::{nonce_agg, partial_verify, rust_bitcoin::RustBitcoin};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::musig::{
    set_musig_input_partial_sig, set_musig_input_pub_nonce, MusigPartialSig, MusigPubNonce,
};
use bwk_qr_protocol::{
    decode, encode_request, encode_response, request, response, Message, Request as QrRequest,
    RequestId as QrRequestId, Response as QrResponse,
};
use miniscript::bitcoin::{bip32::Fingerprint, hashes::Hash, secp256k1::PublicKey, Psbt};

use crate::{
    error::Error as SigningError,
    identity::SignerId,
    manager::{Error as ManagerError, SigningManager},
    musig::{expression_slots, slot_infos, slot_sighash, SlotInfo},
    protocol::{RequestId, Response},
    qr_musig::allocation_binding,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("QR MuSig host: {0}")]
    Invalid(&'static str),
    #[error("QR MuSig store: {0}")]
    Store(PersistError),
    #[error("QR MuSig signing: {0}")]
    Signing(SigningError),
    #[error("QR MuSig manager: {0}")]
    Manager(ManagerError),
    #[error("QR MuSig peer refused: {0}")]
    Peer(String),
}

/// Allocation is permanent even if dispatch, cancellation or signing fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrMusigHostState {
    Preparing,
    Prepared,
    Allocated {
        attempt_id: [u8; 32],
        binding: [u8; 32],
        /// Descriptor-ordered participant nonces, pinned before signing.
        transcript: Option<Vec<Vec<[u8; 66]>>>,
    },
    Consumed {
        attempt_id: [u8; 32],
        binding: [u8; 32],
        transcript: Vec<Vec<[u8; 66]>>,
    },
}

#[derive(Debug, Clone)]
pub struct QrMusigHostRecord {
    signer: SignerId,
    fingerprint: Fingerprint,
    preparation: request::PrepareMusig,
    prepared: Option<response::MusigPrepared>,
    state: QrMusigHostState,
}

/// RamStore value encoder; no backend or key layout is imposed on the caller.
pub fn encode_host_record(record: &QrMusigHostRecord) -> Result<Vec<u8>, PersistError> {
    record
        .encode()
        .map_err(|error| PersistError::Serde(error.to_string()))
}

pub fn decode_host_record(bytes: &[u8]) -> Result<QrMusigHostRecord, PersistError> {
    QrMusigHostRecord::decode(bytes).map_err(|error| PersistError::Serde(error.to_string()))
}

impl QrMusigHostRecord {
    pub fn state(&self) -> &QrMusigHostState {
        &self.state
    }

    pub fn preparation(&self) -> &request::PrepareMusig {
        &self.preparation
    }

    pub fn prepared(&self) -> Option<&response::MusigPrepared> {
        self.prepared.as_ref()
    }

    fn descriptor(&self) -> Result<WalletDescriptor, Error> {
        match &self.preparation.descriptor.descriptor {
            Some(request::DescriptorBody::Bip380(text)) => parse_musig_descriptor(text)
                .map_err(|_| Error::Invalid("invalid stored descriptor")),
            _ => Err(Error::Invalid(
                "preparation requires a full BIP-380 descriptor",
            )),
        }
    }

    /// Public data only. Length-prefixed fields use little endian u32 lengths.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"QMH1".to_vec();
        put_bytes(&mut bytes, self.signer.as_str().as_bytes())?;
        bytes.extend_from_slice(self.fingerprint.as_bytes());
        let preparation = encode_request(&QrRequest {
            id: QrRequestId([0; 2]),
            body: request::Body::PrepareMusig(self.preparation.clone()),
        })
        .map_err(|_| Error::Invalid("cannot encode preparation"))?;
        put_bytes(&mut bytes, &preparation)?;
        let prepared = match &self.prepared {
            Some(prepared) => encode_response(&QrResponse {
                id: QrRequestId([0; 2]),
                body: response::Body::MusigPrepared(prepared.clone()),
            })
            .map_err(|_| Error::Invalid("cannot encode prepared response"))?,
            None => Vec::new(),
        };
        put_bytes(&mut bytes, &prepared)?;
        match &self.state {
            QrMusigHostState::Preparing => bytes.push(0),
            QrMusigHostState::Prepared => bytes.push(1),
            QrMusigHostState::Allocated {
                attempt_id,
                binding,
                transcript,
            } => {
                bytes.push(2);
                bytes.extend_from_slice(attempt_id);
                bytes.extend_from_slice(binding);
                put_transcript(&mut bytes, transcript.as_deref())?;
            }
            QrMusigHostState::Consumed {
                attempt_id,
                binding,
                transcript,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(attempt_id);
                bytes.extend_from_slice(binding);
                put_transcript(&mut bytes, Some(transcript))?;
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = RecordReader(bytes);
        if reader.take(4)? != b"QMH1" {
            return Err(Error::Invalid("invalid host record version"));
        }
        let signer = SignerId::new(
            std::str::from_utf8(reader.bytes()?)
                .map_err(|_| Error::Invalid("invalid stored signer"))?,
        );
        let fingerprint = Fingerprint::from(reader.array::<4>()?);
        let preparation = match decode(reader.bytes()?) {
            Ok(Message::Request(QrRequest {
                body: request::Body::PrepareMusig(value),
                ..
            })) => value,
            _ => return Err(Error::Invalid("invalid stored preparation")),
        };
        let prepared_bytes = reader.bytes()?;
        let prepared = if prepared_bytes.is_empty() {
            None
        } else {
            match decode(prepared_bytes) {
                Ok(Message::Response(QrResponse {
                    body: response::Body::MusigPrepared(value),
                    ..
                })) => Some(value),
                _ => return Err(Error::Invalid("invalid stored prepared response")),
            }
        };
        let state = match reader.array::<1>()?[0] {
            0 => QrMusigHostState::Preparing,
            1 => QrMusigHostState::Prepared,
            2 => QrMusigHostState::Allocated {
                attempt_id: reader.array()?,
                binding: reader.array()?,
                transcript: reader.transcript()?,
            },
            3 => QrMusigHostState::Consumed {
                attempt_id: reader.array()?,
                binding: reader.array()?,
                transcript: reader
                    .transcript()?
                    .ok_or(Error::Invalid("missing consumed transcript"))?,
            },
            _ => return Err(Error::Invalid("invalid host state")),
        };
        if !reader.0.is_empty() {
            return Err(Error::Invalid("trailing host record bytes"));
        }
        let record = Self {
            signer,
            fingerprint,
            preparation,
            prepared,
            state,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), Error> {
        let descriptor = self.descriptor()?;
        preparation_slots(&self.preparation, &descriptor, self.fingerprint)?;
        match (&self.state, &self.prepared) {
            (QrMusigHostState::Preparing, None) => Ok(()),
            (QrMusigHostState::Preparing, Some(_)) | (_, None) => {
                Err(Error::Invalid("inconsistent host state"))
            }
            (_, Some(prepared)) => validate_prepared(self, &descriptor, prepared),
        }
    }
}

#[derive(Clone)]
struct Pending {
    signer: SignerId,
    outer: Option<RequestId>,
    request: QrRequest,
}

pub enum QrMusigHostResponse {
    Prepared(response::MusigPrepared),
    Signed(Psbt),
}

/// One outstanding manager request per host. Lost pending state can be retried
/// from the durable record, but never allocated to another attempt.
pub struct QrMusigHost<S: Store<Key = [u8; 32], Value = QrMusigHostRecord>> {
    store: S,
    pending: Option<Pending>,
}

impl<S: Store<Key = [u8; 32], Value = QrMusigHostRecord>> QrMusigHost<S> {
    /// The caller guarantees exclusive durable storage without rollback. The
    /// Store trait cannot detect NoopBackend or an externally restored snapshot.
    pub fn from_store(store: S) -> Result<Self, Error> {
        for (id, record) in store.iter().map_err(Error::Store)? {
            if id != record.preparation.session_id {
                return Err(Error::Invalid("host record key mismatch"));
            }
            record.validate()?;
        }
        Ok(Self {
            store,
            pending: None,
        })
    }

    pub fn record(&self, session_id: &[u8; 32]) -> Result<Option<QrMusigHostRecord>, Error> {
        self.store.get(session_id).map_err(Error::Store)
    }

    /// No transaction is accepted or bound during preparation. Only the cache
    /// capability enables this operation; ordinary MuSig support is insufficient.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_request(
        &mut self,
        signer: SignerId,
        capabilities: response::Capabilities,
        id: QrRequestId,
        descriptor: &WalletDescriptor,
        fingerprint: Fingerprint,
        preparation: request::PrepareMusig,
    ) -> Result<Vec<u8>, Error> {
        self.require_idle(capabilities)?;
        let record = QrMusigHostRecord {
            signer: signer.clone(),
            fingerprint,
            preparation: preparation.clone(),
            prepared: None,
            state: QrMusigHostState::Preparing,
        };
        if musig_descriptor_to_string(&record.descriptor()?, false)
            != musig_descriptor_to_string(descriptor, false)
        {
            return Err(Error::Invalid("preparation policy mismatch"));
        }
        record.validate()?;
        match self
            .store
            .get(&preparation.session_id)
            .map_err(Error::Store)?
        {
            Some(existing)
                if existing.signer == signer
                    && existing.fingerprint == fingerprint
                    && existing.preparation == preparation
                    && matches!(
                        existing.state,
                        QrMusigHostState::Preparing | QrMusigHostState::Prepared
                    ) => {}
            Some(_) => return Err(Error::Invalid("cache ID already used")),
            None => {
                self.store
                    .insert(preparation.session_id, record)
                    .map_err(Error::Store)?;
            }
        }
        self.publish(
            signer,
            QrRequest {
                id,
                body: request::Body::PrepareMusig(preparation),
            },
        )
    }

    /// Permanently allocates the prepared cache before returning wire bytes.
    /// Retries must keep the transaction, attempt and exact selected own slots.
    #[allow(clippy::too_many_arguments)]
    pub fn allocate_sign_request(
        &mut self,
        signer: SignerId,
        capabilities: response::Capabilities,
        id: QrRequestId,
        session_id: [u8; 32],
        attempt_id: [u8; 32],
        psbt: &Psbt,
    ) -> Result<Vec<u8>, Error> {
        self.require_idle(capabilities)?;
        let mut record = self
            .store
            .get(&session_id)
            .map_err(Error::Store)?
            .ok_or(Error::Invalid("unknown cache ID"))?;
        if record.signer != signer {
            return Err(Error::Invalid("wrong cache owner"));
        }
        let descriptor = record.descriptor()?;
        let binding = allocation_binding(psbt, &descriptor, record.fingerprint, attempt_id)
            .map_err(Error::Signing)?;
        let infos = selected_own_slots(psbt, &descriptor, &record)?;
        validate_own_nonces(psbt, &record, &infos, false)?;
        for info in &infos {
            if info
                .partial_sig(&psbt.inputs[info.slot.input_index])
                .map_err(Error::Signing)?
                .is_some()
            {
                return Err(Error::Invalid("own partial signature already present"));
            }
        }
        // Cached own nonces count toward the first complete transcript, even
        // when this request asks the peer to insert them in round one.
        let mut with_own = psbt.clone();
        insert_own_nonces(&mut with_own, &record, &infos)?;
        let transcript = complete_transcript(&with_own, &infos)?;
        let pinned = match &record.state {
            QrMusigHostState::Prepared => transcript,
            QrMusigHostState::Allocated {
                attempt_id: old_attempt,
                binding: old_binding,
                transcript: old,
            } if *old_attempt == attempt_id && *old_binding == binding => match (old, transcript) {
                (Some(old), Some(current)) if *old == current => Some(current),
                (None, current) => current,
                _ => return Err(Error::Invalid("participant nonce transcript changed")),
            },
            _ => return Err(Error::Invalid("cache is not available for this attempt")),
        };
        record.state = QrMusigHostState::Allocated {
            attempt_id,
            binding,
            transcript: pinned,
        };
        self.store
            .insert(session_id, record)
            .map_err(Error::Store)?;
        self.publish(
            signer,
            QrRequest {
                id,
                body: request::Body::SignMusig(request::SignMusig {
                    session_id,
                    attempt_id,
                    psbt: psbt.serialize(),
                }),
            },
        )
    }

    fn require_idle(&self, capabilities: response::Capabilities) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Invalid("another QR request is outstanding"));
        }
        if !capabilities.supports_musig_cache() {
            return Err(Error::Invalid(
                "peer does not advertise MuSig cache support",
            ));
        }
        Ok(())
    }

    fn publish(&mut self, signer: SignerId, request: QrRequest) -> Result<Vec<u8>, Error> {
        let bytes =
            encode_request(&request).map_err(|_| Error::Invalid("cannot encode QR request"))?;
        // Required even on retries: failed RamStore flushes leave changed RAM.
        self.store.flush().map_err(Error::Store)?;
        self.pending = Some(Pending {
            signer,
            outer: None,
            request,
        });
        Ok(bytes)
    }

    /// Use after sending crafted bytes through SigningManager::raw yourself.
    pub fn bind_outer_request(&mut self, request: RequestId) -> Result<(), Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Invalid("no pending QR request"))?;
        if pending.outer.is_some() {
            return Err(Error::Invalid("outer request already bound"));
        }
        pending.outer = Some(request);
        Ok(())
    }

    /// Sends the pending wire request through the real manager Raw path, then
    /// binds the outer ID returned by raw. Responses are accepted only afterward.
    pub fn submit_pending(&mut self, manager: &dyn SigningManager) -> Result<RequestId, Error> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(Error::Invalid("no pending QR request"))?;
        if pending.outer.is_some() {
            return Err(Error::Invalid("pending request already submitted"));
        }
        let bytes = encode_request(&pending.request)
            .map_err(|_| Error::Invalid("cannot encode QR request"))?;
        self.store.flush().map_err(Error::Store)?;
        let outer = manager
            .raw(&pending.signer, bytes)
            .map_err(Error::Manager)?;
        self.bind_outer_request(outer)?;
        Ok(outer)
    }

    /// Only abandons response attribution. Allocations and tombstones stay put.
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }

    pub fn accept_response(&mut self, response: &Response) -> Result<QrMusigHostResponse, Error> {
        let pending = self
            .pending
            .clone()
            .ok_or(Error::Invalid("no pending QR request"))?;
        let outer = pending
            .outer
            .ok_or(Error::Invalid("outer request not bound"))?;
        if response.request_id() != Some(outer) || response.signer() != Some(&pending.signer) {
            return Err(Error::Invalid("manager response attribution mismatch"));
        }
        let payload = match response {
            Response::Raw { payload, .. } => payload,
            Response::Error { message, .. } => return Err(Error::Peer(message.clone())),
            _ => return Err(Error::Invalid("expected manager Raw response")),
        };
        let qr = match decode(payload) {
            Ok(Message::Response(value)) => value,
            _ => return Err(Error::Invalid("invalid QR response")),
        };
        if qr.id != pending.request.id
            || qr.body.message_type() != pending.request.body.message_type()
        {
            return Err(Error::Invalid("QR response attribution mismatch"));
        }
        let accepted = match (&pending.request.body, qr.body) {
            (request::Body::PrepareMusig(preparation), response::Body::MusigPrepared(prepared)) => {
                self.accept_prepared(preparation, prepared)?
            }
            (request::Body::SignMusig(signing), response::Body::MusigSigned(signed)) => {
                self.accept_signed(signing, signed)?
            }
            (_, response::Body::Error(error)) => return Err(Error::Peer(error.message)),
            _ => return Err(Error::Invalid("wrong QR operation response")),
        };
        self.store.flush().map_err(Error::Store)?;
        self.pending = None;
        Ok(accepted)
    }

    fn accept_prepared(
        &mut self,
        preparation: &request::PrepareMusig,
        prepared: response::MusigPrepared,
    ) -> Result<QrMusigHostResponse, Error> {
        let mut record = self
            .store
            .get(&preparation.session_id)
            .map_err(Error::Store)?
            .ok_or(Error::Invalid("missing preparation record"))?;
        if record.preparation != *preparation
            || !matches!(
                record.state,
                QrMusigHostState::Preparing | QrMusigHostState::Prepared
            )
        {
            return Err(Error::Invalid("preparation no longer available"));
        }
        validate_prepared(&record, &record.descriptor()?, &prepared)?;
        if record.prepared.as_ref().is_some_and(|old| *old != prepared) {
            return Err(Error::Invalid("prepared public nonces changed"));
        }
        record.prepared = Some(prepared.clone());
        record.state = QrMusigHostState::Prepared;
        self.store
            .insert(preparation.session_id, record)
            .map_err(Error::Store)?;
        Ok(QrMusigHostResponse::Prepared(prepared))
    }

    fn accept_signed(
        &mut self,
        signing: &request::SignMusig,
        signed: response::MusigSigned,
    ) -> Result<QrMusigHostResponse, Error> {
        if signing.session_id != signed.session_id || signing.attempt_id != signed.attempt_id {
            return Err(Error::Invalid("signing session or attempt mismatch"));
        }
        let mut record = self
            .store
            .get(&signing.session_id)
            .map_err(Error::Store)?
            .ok_or(Error::Invalid("missing allocation record"))?;
        let descriptor = record.descriptor()?;
        let original = Psbt::deserialize(&signing.psbt)
            .map_err(|_| Error::Invalid("invalid original PSBT"))?;
        let returned =
            Psbt::deserialize(&signed.psbt).map_err(|_| Error::Invalid("invalid returned PSBT"))?;
        let binding = allocation_binding(
            &original,
            &descriptor,
            record.fingerprint,
            signing.attempt_id,
        )
        .map_err(Error::Signing)?;
        let pinned = match &record.state {
            QrMusigHostState::Allocated {
                attempt_id,
                binding: old,
                transcript,
            } if *attempt_id == signing.attempt_id && *old == binding => transcript.clone(),
            // Retrying acceptance after a failed flush must still cross a barrier.
            QrMusigHostState::Consumed {
                attempt_id,
                binding: old,
                transcript,
            } if *attempt_id == signing.attempt_id && *old == binding => Some(transcript.clone()),
            _ => return Err(Error::Invalid("signing allocation mismatch")),
        };
        let infos = selected_own_slots(&original, &descriptor, &record)?;
        validate_own_nonces(&returned, &record, &infos, true)?;
        let transcript = complete_transcript(&returned, &infos)?;
        if pinned
            .as_ref()
            .is_some_and(|old| Some(old) != transcript.as_ref())
        {
            return Err(Error::Invalid("returned participant transcript changed"));
        }
        let consumed = validate_returned_psbt(&original, &returned, &record, &infos)?;
        record.state = if consumed {
            QrMusigHostState::Consumed {
                attempt_id: signing.attempt_id,
                binding,
                transcript: transcript
                    .ok_or(Error::Invalid("partial signature without complete nonces"))?,
            }
        } else {
            if matches!(record.state, QrMusigHostState::Consumed { .. }) {
                return Err(Error::Invalid("consumed cache cannot return to allocated"));
            }
            QrMusigHostState::Allocated {
                attempt_id: signing.attempt_id,
                binding,
                transcript,
            }
        };
        self.store
            .insert(signing.session_id, record)
            .map_err(Error::Store)?;
        Ok(QrMusigHostResponse::Signed(returned))
    }
}

fn preparation_slots(
    preparation: &request::PrepareMusig,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<Vec<(request::MusigDerivation, SlotInfo)>, Error> {
    preparation
        .validate()
        .map_err(|_| Error::Invalid("invalid preparation bounds"))?;
    let paths = descriptor
        .single_paths()
        .map_err(|_| Error::Invalid("invalid descriptor paths"))?;
    let mut result = Vec::new();
    for (position, derivation) in preparation.derivations.iter().enumerate() {
        if preparation.derivations[..position].contains(derivation) {
            return Err(Error::Invalid("duplicate preparation derivation"));
        }
        let single = paths
            .get(derivation.keychain as usize)
            .ok_or(Error::Invalid("unknown keychain"))?;
        let definite = single
            .derive_at(derivation.index)
            .map_err(|_| Error::Invalid("invalid derivation index"))?;
        let mut owned = false;
        for input in 0..preparation.max_inputs {
            for info in expression_slots(input as usize, &definite).map_err(Error::Signing)? {
                if info.signer.0 == fingerprint {
                    owned = true;
                    result.push((*derivation, info));
                }
            }
        }
        if !owned {
            return Err(Error::Invalid("derivation has no own MuSig expressions"));
        }
    }
    Ok(result)
}

fn matches_nonce(nonce: &response::MusigNonce, info: &SlotInfo) -> bool {
    nonce.input_index as usize == info.slot.input_index
        && nonce.expression_index as usize == info.expression_index
        && nonce.participant.0 == info.slot.participant.serialize()
        && nonce.aggregate.0 == info.slot.aggregate.serialize()
        && nonce.leaf_hash == info.slot.leaf_hash.map(|hash| hash.to_byte_array())
}

fn validate_prepared(
    record: &QrMusigHostRecord,
    descriptor: &WalletDescriptor,
    prepared: &response::MusigPrepared,
) -> Result<(), Error> {
    prepared
        .validate()
        .map_err(|_| Error::Invalid("invalid prepared response"))?;
    if prepared.session_id != record.preparation.session_id
        || prepared.max_inputs != record.preparation.max_inputs
    {
        return Err(Error::Invalid("prepared session or coverage mismatch"));
    }
    let expected = preparation_slots(&record.preparation, descriptor, record.fingerprint)?;
    if prepared.nonces.len() != expected.len() {
        return Err(Error::Invalid("incomplete advertised nonce set"));
    }
    for (derivation, info) in &expected {
        let matching: Vec<_> = prepared
            .nonces
            .iter()
            .filter(|nonce| nonce.derivation == *derivation && matches_nonce(nonce, info))
            .collect();
        if matching.len() != 1 {
            return Err(Error::Invalid(
                "wrong or duplicate advertised nonce attribution",
            ));
        }
        validate_nonce(&matching[0].nonce)?;
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8; 66]) -> Result<(), Error> {
    PublicKey::from_slice(&nonce[..33]).map_err(|_| Error::Invalid("invalid public nonce"))?;
    PublicKey::from_slice(&nonce[33..]).map_err(|_| Error::Invalid("invalid public nonce"))?;
    Ok(())
}

fn selected_own_slots(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    record: &QrMusigHostRecord,
) -> Result<Vec<SlotInfo>, Error> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(Error::Invalid("PSBT map count mismatch"));
    }
    let infos: Vec<_> = slot_infos(psbt, descriptor)
        .map_err(Error::Signing)?
        .into_iter()
        .filter(|info| info.signer.0 == record.fingerprint)
        .collect();
    if infos.is_empty() {
        return Err(Error::Invalid("no selected own MuSig slots"));
    }
    let mut unique = BTreeSet::new();
    for info in &infos {
        if !unique.insert(info.slot) {
            return Err(Error::Invalid("selected own slot appears more than once"));
        }
        advertised_nonce(record, info)?;
    }
    Ok(infos)
}

fn advertised_nonce(record: &QrMusigHostRecord, info: &SlotInfo) -> Result<[u8; 66], Error> {
    let prepared = record
        .prepared
        .as_ref()
        .ok_or(Error::Invalid("cache not prepared"))?;
    let mut matches = prepared
        .nonces
        .iter()
        .filter(|nonce| matches_nonce(nonce, info));
    let nonce = matches
        .next()
        .ok_or(Error::Invalid("selected slot outside prepared coverage"))?;
    if matches.next().is_some() {
        return Err(Error::Invalid("ambiguous prepared nonce"));
    }
    Ok(nonce.nonce)
}

fn validate_own_nonces(
    psbt: &Psbt,
    record: &QrMusigHostRecord,
    infos: &[SlotInfo],
    required: bool,
) -> Result<(), Error> {
    for info in infos {
        let input = psbt
            .inputs
            .get(info.slot.input_index)
            .ok_or(Error::Invalid("missing returned input"))?;
        match info.pub_nonce(input).map_err(Error::Signing)? {
            Some(nonce) if nonce == advertised_nonce(record, info)? => {}
            None if !required => {}
            _ => return Err(Error::Invalid("own public nonce mismatch")),
        }
    }
    Ok(())
}

fn insert_own_nonces(
    psbt: &mut Psbt,
    record: &QrMusigHostRecord,
    infos: &[SlotInfo],
) -> Result<(), Error> {
    for info in infos {
        set_musig_input_pub_nonce(
            &mut psbt.inputs[info.slot.input_index],
            &MusigPubNonce {
                participant: info.slot.participant,
                aggregate: info.slot.aggregate,
                leaf_hash: info.slot.leaf_hash,
                nonce: advertised_nonce(record, info)?,
            },
        );
    }
    Ok(())
}

fn complete_transcript(
    psbt: &Psbt,
    infos: &[SlotInfo],
) -> Result<Option<Vec<Vec<[u8; 66]>>>, Error> {
    let mut transcript = Vec::new();
    let mut complete = true;
    for info in infos {
        let input = &psbt.inputs[info.slot.input_index];
        let mut nonces = Vec::new();
        for participant in info.agg.participants() {
            match info
                .participant_nonce(input, *participant)
                .map_err(Error::Signing)?
            {
                Some(nonce) => {
                    validate_nonce(&nonce)?;
                    nonces.push(nonce);
                }
                None => complete = false,
            }
        }
        transcript.push(nonces);
    }
    Ok(if complete { Some(transcript) } else { None })
}

fn validate_returned_psbt(
    original: &Psbt,
    returned: &Psbt,
    record: &QrMusigHostRecord,
    infos: &[SlotInfo],
) -> Result<bool, Error> {
    if original.inputs.len() != returned.inputs.len() {
        return Err(Error::Invalid("returned input count changed"));
    }
    let mut expected = original.clone();
    insert_own_nonces(&mut expected, record, infos)?;
    let mut consumed = false;
    for info in infos {
        let input = &returned.inputs[info.slot.input_index];
        if let Some(signature) = info.partial_sig(input).map_err(Error::Signing)? {
            let nonces = info.all_nonces(input).map_err(Error::Signing)?;
            let aggregate_nonce = nonce_agg(&RustBitcoin, &nonces)
                .map_err(|error| Error::Signing(SigningError::Musig(error)))?;
            let key_agg = info.key_agg().map_err(Error::Signing)?;
            let sighash = slot_sighash(original, &info.slot).map_err(Error::Signing)?;
            if !partial_verify(
                &RustBitcoin,
                &signature,
                &advertised_nonce(record, info)?,
                &info.slot.participant.serialize(),
                &key_agg,
                &aggregate_nonce,
                &sighash,
            ) {
                return Err(Error::Invalid("invalid returned partial signature"));
            }
            set_musig_input_partial_sig(
                &mut expected.inputs[info.slot.input_index],
                &MusigPartialSig {
                    participant: info.slot.participant,
                    aggregate: info.slot.aggregate,
                    leaf_hash: info.slot.leaf_hash,
                    signature,
                },
            );
            consumed = true;
        }
    }
    // Includes all proprietary attempt markers, other participants' fields,
    // outputs and global maps: no arbitrary metadata from the peer is merged.
    if expected != *returned {
        return Err(Error::Invalid("unexpected returned PSBT changes"));
    }
    Ok(consumed)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| Error::Invalid("host record field too large"))?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_transcript(output: &mut Vec<u8>, transcript: Option<&[Vec<[u8; 66]>]>) -> Result<(), Error> {
    match transcript {
        None => output.push(0),
        Some(groups) => {
            output.push(1);
            output.extend_from_slice(
                &u32::try_from(groups.len())
                    .map_err(|_| Error::Invalid("transcript too large"))?
                    .to_le_bytes(),
            );
            for group in groups {
                let bytes: Vec<_> = group
                    .iter()
                    .flat_map(|nonce| nonce.iter().copied())
                    .collect();
                put_bytes(output, &bytes)?;
            }
        }
    }
    Ok(())
}

struct RecordReader<'a>(&'a [u8]);

impl<'a> RecordReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::Invalid("truncated host record"));
        }
        let (bytes, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Invalid("truncated host field"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = u32::from_le_bytes(self.array()?) as usize;
        self.take(len)
    }

    fn transcript(&mut self) -> Result<Option<Vec<Vec<[u8; 66]>>>, Error> {
        match self.array::<1>()?[0] {
            0 => Ok(None),
            1 => {
                let count = u32::from_le_bytes(self.array()?) as usize;
                if count > self.0.len() / 4 {
                    return Err(Error::Invalid("invalid transcript group count"));
                }
                if count == 0 {
                    return Err(Error::Invalid("empty stored transcript"));
                }
                let mut groups = Vec::new();
                for _ in 0..count {
                    let bytes = self.bytes()?;
                    if bytes.is_empty() || bytes.len() % 66 != 0 {
                        return Err(Error::Invalid("invalid stored transcript"));
                    }
                    let mut nonces = Vec::new();
                    for chunk in bytes.chunks_exact(66) {
                        let nonce = chunk
                            .try_into()
                            .map_err(|_| Error::Invalid("invalid stored nonce"))?;
                        validate_nonce(&nonce)?;
                        nonces.push(nonce);
                    }
                    groups.push(nonces);
                }
                Ok(Some(groups))
            }
            _ => Err(Error::Invalid("invalid transcript marker")),
        }
    }
}

#[cfg(test)]
#[path = "qr_musig_host_tests.rs"]
mod tests;
