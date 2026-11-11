//! Coordinator side of QR MuSig signing on nonce cache sessions
//! (`bip-nonce-cache/BIP-DRAFT.md`): it issues a signer's public nonces with Nonce
//! Preparation, places them as the PSBT's 0x1b from the descriptor, names the
//! session with `PSBT_GLOBAL_NONCE_CACHE_SESSION` and sends an ordinary Signing
//! request. Without a session, it sends the same PSBT twice: once for the
//! signer's public nonces, once every participant's nonce is in for its partial
//! signatures.
//!
//! Records hold public data only. The host never accesses a backend directly;
//! record codecs can be used with RamStore.

use std::collections::BTreeMap;

use bwk_descriptor::{musig::parse_musig_descriptor, wallet::WalletDescriptor};
use bwk_musig::{nonce_agg, partial_verify, rust_bitcoin::RustBitcoin};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::{
    musig::{
        musig_input_partial_sigs, musig_input_pub_nonce, musig_input_pub_nonces,
        set_musig_input_partial_sig, set_musig_input_pub_nonce, MusigPartialSig, MusigPubNonce,
    },
    nonce_cache::{nonce_cache_session, set_nonce_cache_session, NonceCacheSession},
};
use bwk_qr_protocol::{
    decode, encode_request, request, response, types, Message, Request as QrRequest,
    RequestId as QrRequestId, SignResponseKind,
};
use miniscript::bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint},
    ecdsa,
    hashes::Hash,
    secp256k1::{PublicKey, XOnlyPublicKey},
    taproot::{self, TapLeafHash},
    Psbt,
};

use crate::{
    error::Error as SigningError,
    identity::SignerId,
    manager::{Error as ManagerError, SigningManager},
    musig::{slot_infos, slot_sighash, MusigSlot, SlotInfo},
    nonce_cache::SESSION_ID_LEN,
    protocol::{RequestId, Response},
};

const RECORD_MAGIC: &[u8; 4] = b"QMH2";
/// Get Info capability bit 3: the signer is a BIP-327 MuSig2 participant.
const MUSIG_CAPABILITY: u32 = 1 << 3;
const PUB_NONCE_LEN: usize = 66;

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

/// What to issue: the nonces of key expression indexes `start..=end` for the inputs
/// `0..max_inputs`, for the signer's key at `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuance {
    pub path: DerivationPath,
    pub max_inputs: u8,
    pub start: u32,
    pub end: u32,
}

/// Where an issued nonce sits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoncePosition {
    pub path: DerivationPath,
    pub key_expression_index: u32,
    pub input_index: u32,
}

/// The public nonces a signer issued for one session, stored under its
/// `session_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMusigHostRecord {
    signer: SignerId,
    fingerprint: Fingerprint,
    /// None until the signer answers a first issuance.
    session_ref: Option<[u8; SESSION_ID_LEN]>,
    nonces: BTreeMap<NoncePosition, [u8; PUB_NONCE_LEN]>,
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
    pub fn signer(&self) -> &SignerId {
        &self.signer
    }

    pub fn session_ref(&self) -> Option<[u8; SESSION_ID_LEN]> {
        self.session_ref
    }

    pub fn nonces(&self) -> &BTreeMap<NoncePosition, [u8; PUB_NONCE_LEN]> {
        &self.nonces
    }

    /// Length-prefixed fields use little endian u32 lengths, integers are little
    /// endian.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = RECORD_MAGIC.to_vec();
        put_bytes(&mut bytes, self.signer.as_str().as_bytes())?;
        bytes.extend_from_slice(self.fingerprint.as_bytes());
        match self.session_ref {
            Some(session_ref) => {
                bytes.push(1);
                bytes.extend_from_slice(&session_ref);
            }
            None => bytes.push(0),
        }
        put_len(&mut bytes, self.nonces.len())?;
        for (position, nonce) in &self.nonces {
            put_len(&mut bytes, position.path.len())?;
            for child in &position.path {
                bytes.extend_from_slice(&u32::from(*child).to_le_bytes());
            }
            bytes.extend_from_slice(&position.key_expression_index.to_le_bytes());
            bytes.extend_from_slice(&position.input_index.to_le_bytes());
            bytes.extend_from_slice(nonce);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = RecordReader(bytes);
        if reader.take(RECORD_MAGIC.len())? != RECORD_MAGIC {
            return Err(Error::Invalid("invalid host record version"));
        }
        let signer = SignerId::new(
            std::str::from_utf8(reader.bytes()?)
                .map_err(|_| Error::Invalid("invalid stored signer"))?,
        );
        let fingerprint = Fingerprint::from(reader.array::<4>()?);
        let session_ref = match reader.array::<1>()?[0] {
            0 => None,
            1 => Some(reader.array()?),
            _ => return Err(Error::Invalid("invalid session reference marker")),
        };
        let mut nonces = BTreeMap::new();
        for _ in 0..reader.len()? {
            let path = (0..reader.len()?)
                .map(|_| Ok(ChildNumber::from(reader.u32()?)))
                .collect::<Result<Vec<_>, Error>>()?;
            let position = NoncePosition {
                path: DerivationPath::from(path),
                key_expression_index: reader.u32()?,
                input_index: reader.u32()?,
            };
            let nonce = reader.array()?;
            validate_nonce(&nonce)?;
            if nonces.insert(position, nonce).is_some() {
                return Err(Error::Invalid("duplicate stored nonce"));
            }
        }
        if !reader.0.is_empty() {
            return Err(Error::Invalid("trailing host record bytes"));
        }
        Ok(Self {
            signer,
            fingerprint,
            session_ref,
            nonces,
        })
    }
}

#[derive(Clone)]
struct Pending {
    signer: SignerId,
    /// None for a Signing request without a nonce cache session.
    session_id: Option<[u8; SESSION_ID_LEN]>,
    outer: Option<RequestId>,
    request: QrRequest,
}

pub enum QrMusigHostResponse {
    Prepared(response::NoncesPrepared),
    /// Round 1 without a session: the PSBT with the signer's public nonces.
    PubNonces(Psbt),
    Signed(Psbt),
}

/// One outstanding manager request per host.
pub struct QrMusigHost<S: Store<Key = [u8; SESSION_ID_LEN], Value = QrMusigHostRecord>> {
    store: S,
    pending: Option<Pending>,
}

impl<S: Store<Key = [u8; SESSION_ID_LEN], Value = QrMusigHostRecord>> QrMusigHost<S> {
    pub fn from_store(store: S) -> Self {
        Self {
            store,
            pending: None,
        }
    }

    pub fn record(
        &self,
        session_id: &[u8; SESSION_ID_LEN],
    ) -> Result<Option<QrMusigHostRecord>, Error> {
        self.store.get(session_id).map_err(Error::Store)
    }

    /// Issues `issuance` in a new session of `signer`, under a random `session_id`
    /// returned with the wire bytes.
    pub fn issue_request(
        &mut self,
        signer: SignerId,
        capabilities: response::Capabilities,
        id: QrRequestId,
        fingerprint: Fingerprint,
        issuance: Issuance,
    ) -> Result<([u8; SESSION_ID_LEN], Vec<u8>), Error> {
        self.require_idle()?;
        require_capability(capabilities, response::Capabilities::NONCE_CACHE)?;
        let session_id = self.new_session_id()?;
        let record = QrMusigHostRecord {
            signer: signer.clone(),
            fingerprint,
            session_ref: None,
            nonces: BTreeMap::new(),
        };
        self.store
            .insert(session_id, record)
            .map_err(Error::Store)?;
        let bytes = self.publish(
            signer,
            Some(session_id),
            id,
            prepare_body(session_id, None, issuance),
        )?;
        Ok((session_id, bytes))
    }

    /// Issues `issuance` in a session this host already holds, naming it by its
    /// reference so the signer refuses rather than answer from another secret.
    pub fn extend_request(
        &mut self,
        capabilities: response::Capabilities,
        id: QrRequestId,
        session_id: [u8; SESSION_ID_LEN],
        issuance: Issuance,
    ) -> Result<Vec<u8>, Error> {
        self.require_idle()?;
        require_capability(capabilities, response::Capabilities::NONCE_CACHE)?;
        let record = self.existing(&session_id)?;
        let body = prepare_body(session_id, record.session_ref, issuance);
        self.publish(record.signer, Some(session_id), id, body)
    }

    /// Places the session's nonces as the 0x1b of every slot of the signer in
    /// `psbt`, at its input and key expression index, names the session and builds
    /// the Signing request. `descriptors` carry full BIP-380 bodies. `want_kind` is
    /// only a preference: either reply kind is accepted.
    pub fn sign_request(
        &mut self,
        capabilities: response::Capabilities,
        id: QrRequestId,
        session_id: [u8; SESSION_ID_LEN],
        descriptors: Vec<request::Descriptor>,
        psbt: &Psbt,
        want_kind: Option<SignResponseKind>,
    ) -> Result<Vec<u8>, Error> {
        self.require_idle()?;
        require_capability(capabilities, response::Capabilities::NONCE_CACHE)?;
        let record = self.existing(&session_id)?;
        let session_ref = record
            .session_ref
            .ok_or(Error::Invalid("session not issued yet"))?;
        let mut psbt = psbt.clone();
        let mut placed = 0;
        for descriptor in &descriptors {
            placed += place_nonces(&mut psbt, descriptor, &record)?;
        }
        if placed == 0 {
            return Err(Error::Invalid("no MuSig slot of the signer"));
        }
        set_nonce_cache_session(
            &mut psbt,
            NonceCacheSession {
                session_id,
                session_ref,
            },
        );
        let body = request::Body::Sign(request::Sign {
            descriptors,
            psbt: psbt.serialize(),
            want_kind,
        });
        self.publish(record.signer, Some(session_id), id, body)
    }

    /// Builds a Signing request for `psbt` without a nonce cache session: round 1
    /// while the signer's 0x1b are missing, round 2 once every participant's are
    /// in. `descriptors` carry full BIP-380 bodies, and either reply kind is
    /// accepted.
    pub fn two_round_request(
        &mut self,
        signer: SignerId,
        capabilities: response::Capabilities,
        id: QrRequestId,
        descriptors: Vec<request::Descriptor>,
        psbt: &Psbt,
        want_kind: Option<SignResponseKind>,
    ) -> Result<Vec<u8>, Error> {
        self.require_idle()?;
        require_capability(capabilities, MUSIG_CAPABILITY)?;
        if nonce_cache_session(psbt)
            .map_err(|_| Error::Invalid("invalid nonce cache session field"))?
            .is_some()
        {
            return Err(Error::Invalid("PSBT names a nonce cache session"));
        }
        for descriptor in &descriptors {
            wallet_descriptor(descriptor)?;
        }
        let body = request::Body::Sign(request::Sign {
            descriptors,
            psbt: psbt.serialize(),
            want_kind,
        });
        self.publish(signer, None, id, body)
    }

    fn existing(&self, session_id: &[u8; SESSION_ID_LEN]) -> Result<QrMusigHostRecord, Error> {
        self.store
            .get(session_id)
            .map_err(Error::Store)?
            .ok_or(Error::Invalid("unknown session"))
    }

    fn new_session_id(&self) -> Result<[u8; SESSION_ID_LEN], Error> {
        loop {
            let mut session_id = [0; SESSION_ID_LEN];
            getrandom::getrandom(&mut session_id)
                .map_err(|_| Error::Invalid("no randomness for a session id"))?;
            if !self.store.contains_key(&session_id).map_err(Error::Store)? {
                return Ok(session_id);
            }
        }
    }

    fn require_idle(&self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Invalid("another QR request is outstanding"));
        }
        Ok(())
    }

    fn publish(
        &mut self,
        signer: SignerId,
        session_id: Option<[u8; SESSION_ID_LEN]>,
        id: QrRequestId,
        body: request::Body,
    ) -> Result<Vec<u8>, Error> {
        let request = QrRequest { id, body };
        let bytes =
            encode_request(&request).map_err(|_| Error::Invalid("cannot encode QR request"))?;
        // Required even on retries: failed RamStore flushes leave changed RAM.
        self.store.flush().map_err(Error::Store)?;
        self.pending = Some(Pending {
            signer,
            session_id,
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

    /// Only abandons response attribution; the records stay put.
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }

    /// A refusal for a session missing, consumed or mismatched on the signer drops
    /// the session: its nonces can no longer sign.
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
            (
                request::Body::PrepareNonces(preparation),
                response::Body::NoncesPrepared(prepared),
            ) => self.accept_prepared(preparation, prepared)?,
            (request::Body::Sign(signing), response::Body::Signed(signed)) => {
                self.accept_signed(pending.session_id, signing, signed)?
            }
            (_, response::Body::Error(error)) => return self.refused(pending.session_id, error),
            _ => return Err(Error::Invalid("wrong QR operation response")),
        };
        self.store.flush().map_err(Error::Store)?;
        self.pending = None;
        Ok(accepted)
    }

    fn refused(
        &mut self,
        session_id: Option<[u8; SESSION_ID_LEN]>,
        error: response::ErrorBody,
    ) -> Result<QrMusigHostResponse, Error> {
        if let (Some(session_id), response::Error::MusigSession) = (session_id, error.error) {
            self.store.remove(&session_id).map_err(Error::Store)?;
        }
        self.store.flush().map_err(Error::Store)?;
        self.pending = None;
        Err(Error::Peer(error.message))
    }

    fn accept_prepared(
        &mut self,
        preparation: &request::PrepareNonces,
        prepared: response::NoncesPrepared,
    ) -> Result<QrMusigHostResponse, Error> {
        prepared
            .validate()
            .map_err(|_| Error::Invalid("invalid prepared response"))?;
        if prepared.session_id != preparation.session_id
            || prepared.max_inputs != preparation.max_inputs
            || prepared.start != preparation.start
            || prepared.end != preparation.end
        {
            return Err(Error::Invalid(
                "prepared response does not echo the request",
            ));
        }
        let mut record = self.existing(&preparation.session_id)?;
        if record
            .session_ref
            .is_some_and(|session_ref| session_ref != prepared.session_ref)
        {
            return Err(Error::Invalid("session reference changed"));
        }
        let path = DerivationPath::from(&preparation.derivation_path);
        let max_inputs = u32::from(prepared.max_inputs);
        for (entry, nonce) in (0..).zip(&prepared.nonces) {
            validate_nonce(nonce)?;
            let position = NoncePosition {
                path: path.clone(),
                key_expression_index: prepared.start + entry / max_inputs,
                input_index: entry % max_inputs,
            };
            if record
                .nonces
                .insert(position, *nonce)
                .is_some_and(|previous| previous != *nonce)
            {
                return Err(Error::Invalid("issued nonce changed"));
            }
        }
        record.session_ref = Some(prepared.session_ref);
        self.store
            .insert(preparation.session_id, record)
            .map_err(Error::Store)?;
        Ok(QrMusigHostResponse::Prepared(prepared))
    }

    /// The signer deleted the session before answering, so the host drops it too.
    /// Without a session, the reply is round 1 when it adds public nonces.
    fn accept_signed(
        &mut self,
        session_id: Option<[u8; SESSION_ID_LEN]>,
        signing: &request::Sign,
        signed: response::Signed,
    ) -> Result<QrMusigHostResponse, Error> {
        let original = Psbt::deserialize(&signing.psbt)
            .map_err(|_| Error::Invalid("invalid original PSBT"))?;
        let returned = match signed {
            response::Signed::Psbt(bytes) => {
                let returned = Psbt::deserialize(&bytes)
                    .map_err(|_| Error::Invalid("invalid returned PSBT"))?;
                if returned.unsigned_tx != original.unsigned_tx {
                    return Err(Error::Invalid("returned PSBT spends another transaction"));
                }
                returned
            }
            response::Signed::Signatures(entries) => merge_signatures(original.clone(), &entries)?,
        };
        let descriptors = signing
            .descriptors
            .iter()
            .map(wallet_descriptor)
            .collect::<Result<Vec<_>, _>>()?;
        match session_id {
            Some(session_id) => {
                verify_partial_sigs(&original, &returned, &descriptors)?;
                self.store.remove(&session_id).map_err(Error::Store)?;
                Ok(QrMusigHostResponse::Signed(returned))
            }
            None if nonce_count(&returned)? == nonce_count(&original)? => {
                verify_partial_sigs(&original, &returned, &descriptors)?;
                Ok(QrMusigHostResponse::Signed(returned))
            }
            None => {
                verify_pub_nonces(&original, &returned, &descriptors)?;
                Ok(QrMusigHostResponse::PubNonces(returned))
            }
        }
    }
}

fn require_capability(capabilities: response::Capabilities, flag: u32) -> Result<(), Error> {
    if capabilities.0 & flag == 0 {
        return Err(Error::Invalid("peer does not advertise the capability"));
    }
    Ok(())
}

/// The PSBT sent with every entry of a signatures-only reply set: ordinary
/// signatures, MuSig2 public nonces as 0x1b and partial signatures as 0x1c. A
/// public nonce entry must not change a 0x1b already there. Silent payment entries are refused (the host sends no
/// silent payment output), and entries of an unknown kind are skipped.
fn merge_signatures(mut psbt: Psbt, entries: &[response::SignatureEntry]) -> Result<Psbt, Error> {
    for entry in entries {
        match entry {
            response::SignatureEntry::Unknown { .. } => {}
            response::SignatureEntry::SpEcdhShare { .. }
            | response::SignatureEntry::SpDleqProof { .. } => {
                return Err(Error::Invalid("unexpected silent payment entry"));
            }
            _ => merge_signature(&mut psbt, entry)?,
        }
    }
    Ok(psbt)
}

fn merge_signature(psbt: &mut Psbt, entry: &response::SignatureEntry) -> Result<(), Error> {
    let index = entry
        .input_index()
        .ok_or(Error::Invalid("unexpected global entry"))? as usize;
    let input = psbt
        .inputs
        .get_mut(index)
        .ok_or(Error::Invalid("signature for an unknown input"))?;
    match entry {
        response::SignatureEntry::Ecdsa {
            public_key,
            signature,
            ..
        } => {
            let signature = ecdsa::Signature::from_slice(signature)
                .map_err(|_| Error::Invalid("invalid ECDSA signature"))?;
            input.partial_sigs.insert(
                miniscript::bitcoin::PublicKey::new(key(public_key)?),
                signature,
            );
        }
        response::SignatureEntry::TapKey { signature, .. } => {
            input.tap_key_sig = Some(taproot_signature(signature)?);
        }
        response::SignatureEntry::TapScript {
            xonly_public_key,
            tap_leaf_hash,
            signature,
            ..
        } => {
            let xonly = XOnlyPublicKey::from_slice(xonly_public_key)
                .map_err(|_| Error::Invalid("invalid x-only key"))?;
            input.tap_script_sigs.insert(
                (xonly, TapLeafHash::from_byte_array(*tap_leaf_hash)),
                taproot_signature(signature)?,
            );
        }
        response::SignatureEntry::MusigPubNonce {
            participant,
            aggregate,
            leaf_hash,
            nonce,
            ..
        } => {
            let pub_nonce = MusigPubNonce {
                participant: key(participant)?,
                aggregate: key(aggregate)?,
                leaf_hash: leaf_hash.map(TapLeafHash::from_byte_array),
                nonce: *nonce,
            };
            let placed = musig_input_pub_nonce(
                input,
                pub_nonce.participant,
                pub_nonce.aggregate,
                pub_nonce.leaf_hash,
            )
            .map_err(|_| Error::Invalid("invalid public nonce field"))?;
            match placed {
                Some(placed) if placed != *nonce => {
                    return Err(Error::Invalid("returned public nonce changed"));
                }
                Some(_) => {}
                None => {
                    validate_nonce(nonce)?;
                    set_musig_input_pub_nonce(input, &pub_nonce);
                }
            }
        }
        response::SignatureEntry::MusigPartialSig {
            participant,
            aggregate,
            leaf_hash,
            signature,
            ..
        } => set_musig_input_partial_sig(
            input,
            &MusigPartialSig {
                participant: key(participant)?,
                aggregate: key(aggregate)?,
                leaf_hash: leaf_hash.map(TapLeafHash::from_byte_array),
                signature: *signature,
            },
        ),
        response::SignatureEntry::SpEcdhShare { .. }
        | response::SignatureEntry::SpDleqProof { .. }
        | response::SignatureEntry::Unknown { .. } => {
            return Err(Error::Invalid("unexpected signature entry"))
        }
    }
    Ok(())
}

fn key(key: &types::PublicKey) -> Result<PublicKey, Error> {
    PublicKey::from_slice(&key.0).map_err(|_| Error::Invalid("invalid public key"))
}

fn taproot_signature(signature: &[u8]) -> Result<taproot::Signature, Error> {
    taproot::Signature::from_slice(signature)
        .map_err(|_| Error::Invalid("invalid taproot signature"))
}

fn prepare_body(
    session_id: [u8; SESSION_ID_LEN],
    session_ref: Option<[u8; SESSION_ID_LEN]>,
    issuance: Issuance,
) -> request::Body {
    request::Body::PrepareNonces(request::PrepareNonces {
        session_id,
        session_ref,
        max_inputs: issuance.max_inputs,
        derivation_path: (&issuance.path).into(),
        start: issuance.start,
        end: issuance.end,
    })
}

/// Sets the issued nonce of every slot of the record's signer in `descriptor`; the
/// count set.
fn place_nonces(
    psbt: &mut Psbt,
    descriptor: &request::Descriptor,
    record: &QrMusigHostRecord,
) -> Result<usize, Error> {
    let descriptor = wallet_descriptor(descriptor)?;
    let own: Vec<_> = slot_infos(psbt, &descriptor)
        .map_err(Error::Signing)?
        .into_iter()
        .filter(|info| info.signer.0 == record.fingerprint)
        .collect();
    for info in &own {
        let position = NoncePosition {
            path: info.signer.1.clone(),
            key_expression_index: u32::try_from(info.key_expression_index)
                .map_err(|_| Error::Invalid("key expression index out of range"))?,
            input_index: u32::try_from(info.slot.input_index)
                .map_err(|_| Error::Invalid("input index out of range"))?,
        };
        let nonce = *record
            .nonces
            .get(&position)
            .ok_or(Error::Invalid("no issued nonce for a slot of the signer"))?;
        let input = &mut psbt.inputs[info.slot.input_index];
        if info
            .pub_nonce(input)
            .map_err(Error::Signing)?
            .is_some_and(|present| present != nonce)
        {
            return Err(Error::Invalid(
                "another public nonce of the signer is present",
            ));
        }
        set_musig_input_pub_nonce(
            input,
            &MusigPubNonce {
                participant: info.slot.participant,
                aggregate: info.slot.aggregate,
                leaf_hash: info.slot.leaf_hash,
                nonce,
            },
        );
    }
    Ok(own.len())
}

fn wallet_descriptor(descriptor: &request::Descriptor) -> Result<WalletDescriptor, Error> {
    let Some(request::DescriptorBody::Bip380(text)) = &descriptor.descriptor else {
        return Err(Error::Invalid("signing requires a full BIP-380 descriptor"));
    };
    parse_musig_descriptor(text).map_err(|_| Error::Invalid("invalid descriptor"))
}

/// Every slot of `descriptors` in `psbt`.
fn descriptor_slots(psbt: &Psbt, descriptors: &[WalletDescriptor]) -> Result<Vec<SlotInfo>, Error> {
    let mut slots = Vec::new();
    for descriptor in descriptors {
        slots.extend(slot_infos(psbt, descriptor).map_err(Error::Signing)?);
    }
    Ok(slots)
}

fn invalid_field(_: bwk_psbt::musig::Error) -> Error {
    Error::Invalid("invalid MuSig2 field")
}

fn nonce_count(psbt: &Psbt) -> Result<usize, Error> {
    psbt.inputs.iter().try_fold(0, |count, input| {
        Ok(count + musig_input_pub_nonces(input).map_err(invalid_field)?.len())
    })
}

/// A round 1 reply: `returned` keeps every 0x1b `sent` carries, adds only valid
/// 0x1b of slots of `descriptors`, and no signature of any kind.
fn verify_pub_nonces(
    sent: &Psbt,
    returned: &Psbt,
    descriptors: &[WalletDescriptor],
) -> Result<(), Error> {
    let slots = descriptor_slots(sent, descriptors)?;
    for (input_index, (sent_input, input)) in sent.inputs.iter().zip(&returned.inputs).enumerate() {
        let sent_nonces = musig_input_pub_nonces(sent_input).map_err(invalid_field)?;
        let nonces = musig_input_pub_nonces(input).map_err(invalid_field)?;
        if sent_nonces.iter().any(|nonce| !nonces.contains(nonce)) {
            return Err(Error::Invalid("returned public nonces changed"));
        }
        for nonce in nonces.iter().filter(|nonce| !sent_nonces.contains(nonce)) {
            let slot = MusigSlot {
                input_index,
                participant: nonce.participant,
                aggregate: nonce.aggregate,
                leaf_hash: nonce.leaf_hash,
            };
            if !slots.iter().any(|info| info.slot == slot) {
                return Err(Error::Invalid("public nonce for an unknown slot"));
            }
            validate_nonce(&nonce.nonce)?;
        }
        if musig_input_partial_sigs(input).map_err(invalid_field)?
            != musig_input_partial_sigs(sent_input).map_err(invalid_field)?
            || input.partial_sigs != sent_input.partial_sigs
            || input.tap_key_sig != sent_input.tap_key_sig
            || input.tap_script_sigs != sent_input.tap_script_sigs
        {
            return Err(Error::Invalid("public nonce reply carries a signature"));
        }
    }
    Ok(())
}

/// Every 0x1b of `returned` must be one `sent` carries, and every 0x1c a valid
/// BIP-327 partial signature against them, for a slot of `descriptors`.
fn verify_partial_sigs(
    sent: &Psbt,
    returned: &Psbt,
    descriptors: &[WalletDescriptor],
) -> Result<(), Error> {
    let slots = descriptor_slots(sent, descriptors)?;
    for (input_index, (sent_input, input)) in sent.inputs.iter().zip(&returned.inputs).enumerate() {
        if musig_input_pub_nonces(input).map_err(invalid_field)?
            != musig_input_pub_nonces(sent_input).map_err(invalid_field)?
        {
            return Err(Error::Invalid("returned public nonces changed"));
        }
        for sig in musig_input_partial_sigs(input).map_err(invalid_field)? {
            let slot = MusigSlot {
                input_index,
                participant: sig.participant,
                aggregate: sig.aggregate,
                leaf_hash: sig.leaf_hash,
            };
            let info = slots
                .iter()
                .find(|info| info.slot == slot)
                .ok_or(Error::Invalid("partial signature for an unknown slot"))?;
            verify_partial_sig(sent, info, &sig.signature)?;
        }
    }
    Ok(())
}

/// BIP-327 PartialSigVerify of `signature` for `info`, with the nonces of `psbt`.
fn verify_partial_sig(psbt: &Psbt, info: &SlotInfo, signature: &[u8; 32]) -> Result<(), Error> {
    let input = &psbt.inputs[info.slot.input_index];
    let pubnonce = info
        .pub_nonce(input)
        .map_err(Error::Signing)?
        .ok_or(Error::Invalid("partial signature without its public nonce"))?;
    let aggnonce = nonce_agg(
        &RustBitcoin,
        &info.all_nonces(input).map_err(Error::Signing)?,
    )
    .map_err(|error| Error::Signing(SigningError::Musig(error)))?;
    let key_agg = info.key_agg().map_err(Error::Signing)?;
    let sighash = slot_sighash(psbt, &info.slot).map_err(Error::Signing)?;
    if !partial_verify(
        &RustBitcoin,
        signature,
        &pubnonce,
        &info.slot.participant.serialize(),
        &key_agg,
        &aggnonce,
        &sighash,
    ) {
        return Err(Error::Invalid("invalid partial signature"));
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8; PUB_NONCE_LEN]) -> Result<(), Error> {
    PublicKey::from_slice(&nonce[..33]).map_err(|_| Error::Invalid("invalid public nonce"))?;
    PublicKey::from_slice(&nonce[33..]).map_err(|_| Error::Invalid("invalid public nonce"))?;
    Ok(())
}

fn put_len(output: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    let len = u32::try_from(len).map_err(|_| Error::Invalid("host record field too large"))?;
    output.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    put_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
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

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn len(&mut self) -> Result<usize, Error> {
        Ok(self.u32()? as usize)
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = self.len()?;
        self.take(len)
    }
}

#[cfg(test)]
#[path = "qr_musig_host_tests.rs"]
mod tests;
