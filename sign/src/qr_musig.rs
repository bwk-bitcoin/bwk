//! Durable hot QR MuSig peer. The caller must exclusively own the supplied store,
//! whose successful flush must be durable. No NoopBackend, rollback, backup restore,
//! concurrent writer or copied live store is safe. Keep burned IDs permanently.
//! The cipher must provide authenticated encryption, not an identity transform.

use std::{collections::BTreeSet, str::FromStr, sync::Arc};

use bwk_descriptor::{descriptor::Descriptor, wallet::WalletDescriptor};
use bwk_persist::{cipher::Cipher, storage::Store, PersistError};
use bwk_qr_protocol::{
    request::{self, DescriptorBody, PrepareMusig, SignMusig},
    response::{self, MusigNonce, MusigPrepared, MusigSigned},
    types::PublicKey,
    Message, Request as QrRequest, RequestId as QrRequestId, Response as QrResponse,
    REQUEST_ID_LEN,
};
use miniscript::bitcoin::{
    bip32::Fingerprint,
    hashes::{sha256, Hash, HashEngine},
    Psbt,
};

use crate::{
    error::Error as SignError,
    hot_musig::{HotMusigSession, HotMusigSessionBytes},
    hot_signer::HotSigner,
    musig::{session_id, slot_infos, slot_sighash, MusigSessionId, SlotInfo},
    protocol::{Request, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Sign(#[from] SignError),
    #[error("{0}")]
    Persist(#[from] PersistError),
    #[error("invalid or unsupported QR request: {0}")]
    Request(String),
}

/// Cloneable store values contain only encrypted secret exports and public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrMusigPeerRecord {
    Prepared {
        request: PrepareMusig,
        encrypted_export: Vec<u8>,
    },
    Allocated {
        request: PrepareMusig,
        encrypted_export: Vec<u8>,
        binding: [u8; 32],
        transcript: Option<[u8; 32]>,
    },
    Burned,
}

/// Owns the signer and the exclusively held, caller-selected typed store.
/// Neither the peer nor its live store may be cloned or restored to older state.
pub struct QrMusigPeer<S: Store<Key = [u8; 32], Value = QrMusigPeerRecord>> {
    signer: HotSigner,
    store: S,
    cipher: Arc<dyn Cipher>,
    failed_burn: Option<[u8; 32]>,
}

impl<S: Store<Key = [u8; 32], Value = QrMusigPeerRecord>> QrMusigPeer<S> {
    pub fn from_store(signer: HotSigner, store: S, cipher: Arc<dyn Cipher>) -> Self {
        Self {
            signer,
            store,
            cipher,
            failed_burn: None,
        }
    }

    pub fn prepare(&mut self, request: PrepareMusig) -> Result<MusigPrepared, Error> {
        self.available()?;
        let descriptor = preparation_descriptor(&request)?;
        let session = match self.store.get(&request.session_id)? {
            None => self.prepare_record(&request, &descriptor)?,
            Some(QrMusigPeerRecord::Prepared {
                request: previous,
                encrypted_export,
            }) if previous == request => {
                self.open_session(&request, &descriptor, &encrypted_export)?
            }
            Some(_) => return Err(SignError::MusigSession.into()),
        };
        let response = prepared_response(&session, &request, &descriptor)?;
        // RAM may already contain a write from an earlier failed flush.
        self.store.flush()?;
        Ok(response)
    }

    fn prepare_record(
        &mut self,
        request: &PrepareMusig,
        descriptor: &WalletDescriptor,
    ) -> Result<HotMusigSession, Error> {
        let session = self.signer.create_musig_session(
            descriptor,
            MusigSessionId(request.session_id),
            request.max_inputs,
        )?;
        // Validate every requested derivation before reserving the ID.
        prepared_response(&session, request, descriptor)?;
        let plain = session.encode();
        let encrypted_export = self.cipher.seal(plain.as_bytes())?;
        let session = HotMusigSession::decode(plain, descriptor, self.signer.fingerprint())?;
        self.store.insert(
            request.session_id,
            QrMusigPeerRecord::Prepared {
                request: request.clone(),
                encrypted_export,
            },
        )?;
        Ok(session)
    }

    fn open_session(
        &self,
        request: &PrepareMusig,
        descriptor: &WalletDescriptor,
        encrypted_export: &[u8],
    ) -> Result<HotMusigSession, Error> {
        let plain = HotMusigSessionBytes::from_bytes(self.cipher.open(encrypted_export)?);
        let session = HotMusigSession::decode(plain, descriptor, self.signer.fingerprint())?;
        if session.id().0 != request.session_id || session.max_inputs() != request.max_inputs {
            return Err(SignError::MusigSession.into());
        }
        Ok(session)
    }

    /// Incomplete transcripts return only nonces. A complete transcript consumes
    /// the entire root after a durable tombstone; even identical retries refuse.
    pub fn sign(&mut self, request: SignMusig) -> Result<MusigSigned, Error> {
        self.available()?;
        let mut psbt =
            Psbt::deserialize(&request.psbt).map_err(|error| Error::Request(error.to_string()))?;
        let record = self.store.get(&request.session_id)?;
        let (preparation, encrypted_export, previous_binding, previous_transcript) = match record {
            Some(QrMusigPeerRecord::Prepared {
                request,
                encrypted_export,
            }) => (request, encrypted_export, None, None),
            Some(QrMusigPeerRecord::Allocated {
                request,
                encrypted_export,
                binding,
                transcript,
            }) => (request, encrypted_export, Some(binding), transcript),
            _ => return Err(SignError::MusigSession.into()),
        };
        if preparation.session_id != request.session_id {
            return Err(SignError::MusigSession.into());
        }
        let descriptor = preparation_descriptor(&preparation)?;
        let binding = allocation_binding(
            &psbt,
            &descriptor,
            self.signer.fingerprint(),
            request.attempt_id,
        )?;
        if previous_binding.is_some_and(|previous| previous != binding) {
            return Err(SignError::MusigSession.into());
        }
        let session = self.open_session(&preparation, &descriptor, &encrypted_export)?;
        validate_advertised_slots(&session, &preparation, &descriptor, &psbt)?;
        self.store.insert(
            request.session_id,
            QrMusigPeerRecord::Allocated {
                request: preparation.clone(),
                encrypted_export: encrypted_export.clone(),
                binding,
                transcript: previous_transcript,
            },
        )?;
        self.store.flush()?;
        session.publish_nonces(&mut psbt, &descriptor)?;
        let transcript = participant_transcript(&session.slot_infos(&psbt, &descriptor)?, &psbt)?;
        if previous_transcript.is_some() && previous_transcript != transcript {
            return Err(SignError::MusigSession.into());
        }
        if let Some(transcript) = transcript {
            self.store.insert(
                request.session_id,
                QrMusigPeerRecord::Allocated {
                    request: preparation,
                    encrypted_export,
                    binding,
                    transcript: Some(transcript),
                },
            )?;
            self.store.flush()?;
            // A failed burn must never leave this instance able to sign again.
            self.failed_burn = Some(request.session_id);
            self.store
                .insert(request.session_id, QrMusigPeerRecord::Burned)?;
            self.store.flush()?;
            self.failed_burn = None;
            self.signer
                .sign_musig_session(&mut psbt, &descriptor, session)?;
        }
        self.store.flush()?;
        Ok(MusigSigned {
            session_id: request.session_id,
            attempt_id: request.attempt_id,
            psbt: psbt.serialize(),
        })
    }

    fn available(&mut self) -> Result<(), Error> {
        if let Some(id) = self.failed_burn {
            self.store.insert(id, QrMusigPeerRecord::Burned)?;
            self.store.flush()?;
            return Err(SignError::MusigSession.into());
        }
        Ok(())
    }

    /// Unsupported operations return explicit wire errors, never ordinary signing.
    pub fn handle(&mut self, request: QrRequest) -> QrResponse {
        let message_type = request.body.message_type();
        let result = match request.body {
            request::Body::PrepareMusig(body) => {
                self.prepare(body).map(response::Body::MusigPrepared)
            }
            request::Body::SignMusig(body) => self.sign(body).map(response::Body::MusigSigned),
            _ => Err(Error::Request("unsupported operation".to_string())),
        };
        let body = match result {
            Ok(body) => body,
            Err(error) => response::Body::Error(response::ErrorBody {
                message_type,
                error: match &error {
                    Error::Request(_) => response::Error::MalformedRequest,
                    // Persistence is retryable and does not consume the session:
                    // 0x0D would tell the caller to restart the whole attempt.
                    Error::Persist(_) => response::Error::InternalError,
                    Error::Sign(_) => response::Error::MusigSession,
                },
                message: error.to_string(),
            }),
        };
        QrResponse {
            id: request.id,
            body,
        }
    }

    /// Echoes both outer routing fields and the decoded inner QR request ID.
    pub fn handle_remote(&mut self, request: Request) -> Response {
        let outer_id = request.request_id();
        let outer_signer = request.signer().cloned();
        let Request::Raw {
            request,
            signer,
            payload,
        } = request
        else {
            return Response::Error {
                request: Some(outer_id),
                signer: outer_signer,
                message: "QR MuSig peer requires Raw".to_string(),
            };
        };
        let inner = match bwk_qr_protocol::decode(&payload) {
            Ok(Message::Request(inner)) => inner,
            Ok(Message::Response(_)) => {
                return Response::error(request, signer, "expected QR request");
            }
            Err(error) => return Response::error(request, signer, format!("{error:?}")),
        };
        match bwk_qr_protocol::encode_response(&self.handle(inner)) {
            Ok(payload) => Response::Raw {
                request,
                signer,
                payload,
            },
            Err(error) => Response::error(request, signer, format!("{error:?}")),
        }
    }
}

fn preparation_descriptor(request: &PrepareMusig) -> Result<WalletDescriptor, Error> {
    request.validate().map_err(|_| SignError::MusigSession)?;
    match &request.descriptor.descriptor {
        Some(DescriptorBody::Bip380(text)) => Descriptor::from_str(text)
            .map_err(|error| Error::Request(error.to_string()))?
            .into_miniscript()
            .map_err(|error| Error::Request(error.to_string())),
        _ => Err(Error::Request(
            "full BIP380 descriptor required".to_string(),
        )),
    }
}

fn prepared_response(
    session: &HotMusigSession,
    request: &PrepareMusig,
    descriptor: &WalletDescriptor,
) -> Result<MusigPrepared, Error> {
    let mut nonces = Vec::new();
    for derivation in &request.derivations {
        for nonce in
            session.public_nonces(descriptor, derivation.keychain as usize, derivation.index)?
        {
            nonces.push(MusigNonce {
                derivation: *derivation,
                input_index: u32::try_from(nonce.input_index)
                    .map_err(|_| SignError::MusigSession)?,
                expression_index: u32::try_from(nonce.expression_index)
                    .map_err(|_| SignError::MusigSession)?,
                participant: PublicKey(nonce.nonce.participant.serialize()),
                aggregate: PublicKey(nonce.nonce.aggregate.serialize()),
                leaf_hash: nonce.nonce.leaf_hash.map(|hash| hash.to_byte_array()),
                nonce: nonce.nonce.nonce,
            });
        }
    }
    let prepared = MusigPrepared {
        session_id: request.session_id,
        max_inputs: request.max_inputs,
        nonces,
    };
    prepared.validate().map_err(|_| SignError::MusigSession)?;
    Ok(prepared)
}

fn validate_advertised_slots(
    session: &HotMusigSession,
    request: &PrepareMusig,
    descriptor: &WalletDescriptor,
    psbt: &Psbt,
) -> Result<(), Error> {
    let advertised = prepared_response(session, request, descriptor)?;
    for info in session.slot_infos(psbt, descriptor)? {
        if !advertised.nonces.iter().any(|nonce| {
            nonce.input_index as usize == info.slot.input_index
                && nonce.expression_index as usize == info.expression_index
                && nonce.participant.0 == info.slot.participant.serialize()
                && nonce.aggregate.0 == info.slot.aggregate.serialize()
                && nonce.leaf_hash == info.slot.leaf_hash.map(|hash| hash.to_byte_array())
        }) {
            return Err(SignError::MusigSession.into());
        }
    }
    Ok(())
}

/// Binds the transaction plus canonical selected own slots, not PSBT nonce fields.
/// Shared with the host so both sides allocate exactly the same attempt.
pub(crate) fn allocation_binding(
    psbt: &Psbt,
    descriptor: &WalletDescriptor,
    fingerprint: Fingerprint,
    attempt_id: [u8; 32],
) -> Result<[u8; 32], SignError> {
    let mut own: Vec<_> = slot_infos(psbt, descriptor)?
        .into_iter()
        .filter(|info| info.signer.0 == fingerprint)
        .collect();
    own.sort_by_key(|info| (info.slot, info.expression_index));
    if own.is_empty() {
        return Err(SignError::MusigSession);
    }
    let mut engine = sha256::Hash::engine();
    engine.input(b"bwk/qr-musig/allocation/v1");
    engine.input(&session_id(psbt, descriptor, fingerprint)?.0);
    engine.input(&attempt_id);
    engine.input(&(own.len() as u64).to_le_bytes());
    let mut unique = BTreeSet::new();
    for info in own {
        if !unique.insert(info.slot) {
            return Err(SignError::MusigSession);
        }
        hash_slot(&mut engine, &info);
        engine.input(&slot_sighash(psbt, &info.slot)?);
        engine.input(info.signer.0.as_bytes());
        engine.input(&(info.signer.1.len() as u64).to_le_bytes());
        for child in info.signer.1.as_ref() {
            engine.input(&u32::from(*child).to_le_bytes());
        }
        engine.input(&(info.agg.participants().len() as u64).to_le_bytes());
        for participant in info.agg.participants() {
            engine.input(&participant.serialize());
        }
    }
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

fn hash_slot(engine: &mut sha256::HashEngine, info: &SlotInfo) {
    engine.input(&(info.slot.input_index as u64).to_le_bytes());
    engine.input(&(info.expression_index as u64).to_le_bytes());
    engine.input(&info.slot.participant.serialize());
    engine.input(&info.slot.aggregate.serialize());
    match info.slot.leaf_hash {
        Some(hash) => {
            engine.input(&[1]);
            engine.input(hash.as_byte_array());
        }
        None => engine.input(&[0]),
    }
    match info.merkle_root {
        Some(hash) => {
            engine.input(&[1]);
            engine.input(hash.as_byte_array());
        }
        None => engine.input(&[0]),
    }
}

fn participant_transcript(own: &[SlotInfo], psbt: &Psbt) -> Result<Option<[u8; 32]>, SignError> {
    let mut ordered: Vec<_> = own.iter().collect();
    ordered.sort_by_key(|info| (info.slot, info.expression_index));
    let mut engine = sha256::Hash::engine();
    engine.input(b"bwk/qr-musig/transcript/v1");
    engine.input(&(ordered.len() as u64).to_le_bytes());
    let mut complete = true;
    for info in ordered {
        hash_slot(&mut engine, info);
        engine.input(&(info.agg.participants().len() as u64).to_le_bytes());
        for participant in info.agg.participants() {
            engine.input(&participant.serialize());
            match info.participant_nonce(&psbt.inputs[info.slot.input_index], *participant)? {
                Some(nonce) => engine.input(&nonce),
                None => complete = false,
            }
        }
    }
    Ok(complete.then(|| sha256::Hash::from_engine(engine).to_byte_array()))
}

/// Value encoder for a caller's RamStore. Only the already encrypted export is encoded.
pub fn encode_record(record: &QrMusigPeerRecord) -> Result<Vec<u8>, PersistError> {
    let (tag, request, encrypted_export, allocation) = match record {
        QrMusigPeerRecord::Prepared {
            request,
            encrypted_export,
        } => (1, request, encrypted_export, None),
        QrMusigPeerRecord::Allocated {
            request,
            encrypted_export,
            binding,
            transcript,
        } => (2, request, encrypted_export, Some((binding, transcript))),
        QrMusigPeerRecord::Burned => return Ok(vec![1, 3]),
    };
    preparation_descriptor(request).map_err(|_| corrupt_record())?;
    if encrypted_export.is_empty() {
        return Err(corrupt_record());
    }
    let wire = bwk_qr_protocol::encode_request(&QrRequest {
        id: QrRequestId([0; REQUEST_ID_LEN]),
        body: request::Body::PrepareMusig(request.clone()),
    })
    .map_err(|error| PersistError::Serde(format!("{error:?}")))?;
    let mut bytes = vec![1, tag];
    put_bytes(&mut bytes, &wire)?;
    put_bytes(&mut bytes, encrypted_export)?;
    if let Some((binding, transcript)) = allocation {
        bytes.extend_from_slice(binding);
        match transcript {
            Some(hash) => {
                bytes.push(1);
                bytes.extend_from_slice(hash);
            }
            None => bytes.push(0),
        }
    }
    Ok(bytes)
}

/// Rejects corrupt records instead of treating them as missing, reusable IDs.
pub fn decode_record(mut bytes: &[u8]) -> Result<QrMusigPeerRecord, PersistError> {
    if take(&mut bytes, 1)? != [1] {
        return Err(corrupt_record());
    }
    let tag = take(&mut bytes, 1)?[0];
    if tag == 3 {
        if !bytes.is_empty() {
            return Err(corrupt_record());
        }
        return Ok(QrMusigPeerRecord::Burned);
    }
    let wire = take_bytes(&mut bytes)?;
    let request = match bwk_qr_protocol::decode(wire).map_err(|_| corrupt_record())? {
        Message::Request(QrRequest {
            body: request::Body::PrepareMusig(request),
            ..
        }) => request,
        _ => return Err(corrupt_record()),
    };
    preparation_descriptor(&request).map_err(|_| corrupt_record())?;
    let encrypted_export = take_bytes(&mut bytes)?.to_vec();
    if encrypted_export.is_empty() {
        return Err(corrupt_record());
    }
    let record = match tag {
        1 => QrMusigPeerRecord::Prepared {
            request,
            encrypted_export,
        },
        2 => {
            let binding = take(&mut bytes, 32)?
                .try_into()
                .map_err(|_| corrupt_record())?;
            let transcript = match take(&mut bytes, 1)?[0] {
                0 => None,
                1 => Some(
                    take(&mut bytes, 32)?
                        .try_into()
                        .map_err(|_| corrupt_record())?,
                ),
                _ => return Err(corrupt_record()),
            };
            QrMusigPeerRecord::Allocated {
                request,
                encrypted_export,
                binding,
                transcript,
            }
        }
        _ => return Err(corrupt_record()),
    };
    if !bytes.is_empty() {
        return Err(corrupt_record());
    }
    Ok(record)
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), PersistError> {
    let len = u32::try_from(bytes.len()).map_err(|_| corrupt_record())?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8], PersistError> {
    if bytes.len() < len {
        return Err(corrupt_record());
    }
    let (value, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(value)
}

fn take_bytes<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], PersistError> {
    let len = u32::from_le_bytes(take(bytes, 4)?.try_into().map_err(|_| corrupt_record())?);
    take(bytes, len as usize)
}

fn corrupt_record() -> PersistError {
    PersistError::Serde("invalid QR MuSig peer record".to_string())
}
