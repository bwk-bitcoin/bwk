//! Hot QR MuSig peer on nonce cache sessions (`bip-nonce-cache/BIP-DRAFT.md`): it
//! issues public nonces with Nonce Preparation, and signs in one round a Signing
//! PSBT that names one of its sessions in `PSBT_GLOBAL_NONCE_CACHE_SESSION`.
//!
//! The session secrets live only in the caller's session store, and registered
//! descriptors in its registry store. The peer must own both exclusively, and their
//! successful flush must be durable.

use std::str::FromStr;

use bwk_descriptor::{
    descriptor::Descriptor,
    musig::{musig_descriptor_to_string, parse_musig_descriptor},
    wallet::WalletDescriptor,
};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::{
    nonce_cache::{nonce_cache_session, nonce_cache_session_v2, NonceCacheSession},
    PsbtV2,
};
use bwk_qr_protocol::{
    request::{self, DescriptorBody, PrepareNonces, RegisterDescriptor, Sign},
    response::{self, NoncesPrepared, Registration, Signed},
    Message, Request as QrRequest, Response as QrResponse,
};
use miniscript::bitcoin::{bip32::DerivationPath, Psbt};

use crate::{
    error::Error as SignError,
    hot_signer::{wipe, HotSigner},
    nonce_cache::{SessionSecret, SECRET_LEN, SESSION_ID_LEN},
    protocol::{Request, Response},
};

/// The most sessions the peer keeps: storing one more evicts the oldest.
pub const MAX_SESSIONS: usize = 16;
const SEQUENCE_LEN: usize = 8;
const RECORD_LEN: usize = SEQUENCE_LEN + SECRET_LEN;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Sign(#[from] SignError),
    #[error("{0}")]
    Persist(#[from] PersistError),
    #[error("invalid or unsupported QR request: {0}")]
    Request(String),
    #[error("descriptor alias {0} is registered with another descriptor")]
    AlreadyRegistered(String),
}

/// A session, stored under its `session_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMusigPeerRecord {
    /// Creation order, to evict the oldest session.
    sequence: u64,
    secret: SessionSecret,
}

/// Owns the signer and the exclusively held, caller-selected typed stores: the
/// sessions by `session_id`, and the registered descriptors by alias, with no limit
/// on their count.
pub struct QrMusigPeer<S, R>
where
    S: Store<Key = [u8; SESSION_ID_LEN], Value = QrMusigPeerRecord>,
    R: Store<Key = String, Value = WalletDescriptor>,
{
    signer: HotSigner,
    store: S,
    registry: R,
}

impl<S, R> QrMusigPeer<S, R>
where
    S: Store<Key = [u8; SESSION_ID_LEN], Value = QrMusigPeerRecord>,
    R: Store<Key = String, Value = WalletDescriptor>,
{
    pub fn from_store(signer: HotSigner, store: S, registry: R) -> Self {
        Self {
            signer,
            store,
            registry,
        }
    }

    /// Stores the body under its alias, or only reports whether the alias is
    /// registered when there is no body. The same descriptor again succeeds, another
    /// one under a registered alias is refused. No proof of registration is issued.
    pub fn register(&mut self, request: RegisterDescriptor) -> Result<Registration, Error> {
        let alias = request.descriptor_alias;
        let registered = match &request.descriptor {
            None => self.registry.get(&alias)?.is_some(),
            Some(body) => {
                let descriptor = body_descriptor(body)?;
                match self.registry.get(&alias)? {
                    Some(stored) if stored == descriptor => {}
                    Some(_) => return Err(Error::AlreadyRegistered(alias)),
                    None => {
                        self.registry.insert(alias.clone(), descriptor)?;
                    }
                }
                // Also retries a flush an earlier call failed.
                self.registry.flush()?;
                true
            }
        };
        Ok(Registration {
            descriptor_alias: alias,
            registered: Some(registered),
            stored: Some(registered),
            proof: None,
        })
    }

    /// Issues the nonces of the session holding `session_id`, creating it when
    /// absent and the request carries no reference. The session is durable before
    /// the nonces are returned.
    pub fn prepare(&mut self, request: PrepareNonces) -> Result<NoncesPrepared, Error> {
        request
            .validate()
            .map_err(|error| Error::Request(error.to_string()))?;
        let secret = self.session(request.session_id, request.session_ref)?;
        let path = DerivationPath::from(&request.derivation_path);
        let public_key = self.signer.public_key_at(&path).serialize();
        let mut sk = self.signer.private_key_at(&path);
        let mut secret_key = sk.secret_bytes();
        sk.non_secure_erase();
        let nonces = (request.start..=request.end)
            .flat_map(|j| (0..u32::from(request.max_inputs)).map(move |i| (i, j)))
            .map(|(i, j)| {
                let (_, pubnonce) = secret.nonce(i, j, &secret_key, &public_key)?;
                Ok(pubnonce)
            })
            .collect::<Result<Vec<_>, SignError>>();
        wipe(&mut secret_key);
        let nonces = nonces?;
        // Also retries a flush an earlier call failed.
        self.store.flush()?;
        Ok(NoncesPrepared {
            session_id: request.session_id,
            session_ref: secret.session_ref(),
            max_inputs: request.max_inputs,
            start: request.start,
            end: request.end,
            nonces,
        })
    }

    fn session(
        &mut self,
        session_id: [u8; SESSION_ID_LEN],
        session_ref: Option<[u8; SESSION_ID_LEN]>,
    ) -> Result<SessionSecret, Error> {
        match (self.store.get(&session_id)?, session_ref) {
            (Some(record), None) => Ok(record.secret),
            (Some(record), Some(session_ref)) if record.secret.session_ref() == session_ref => {
                Ok(record.secret)
            }
            (None, None) => self.create_session(session_id),
            _ => Err(SignError::MusigSession.into()),
        }
    }

    fn create_session(&mut self, session_id: [u8; SESSION_ID_LEN]) -> Result<SessionSecret, Error> {
        let records: Vec<_> = self.store.iter()?.collect();
        let sequence = records
            .iter()
            .map(|(_, record)| record.sequence + 1)
            .max()
            .unwrap_or(0);
        if records.len() >= MAX_SESSIONS {
            if let Some((oldest, _)) = records.iter().min_by_key(|(_, record)| record.sequence) {
                self.store.remove(oldest)?;
            }
        }
        let secret = SessionSecret::random()?;
        self.store.insert(
            session_id,
            QrMusigPeerRecord {
                sequence,
                secret: secret.clone(),
            },
        )?;
        Ok(secret)
    }

    /// Signs with the session the PSBT names, then deletes it durably before the
    /// signed PSBT leaves: a failed deletion releases nothing.
    pub fn sign(&mut self, request: Sign) -> Result<Signed, Error> {
        let mut psbt = SigningPsbt::deserialize(&request.psbt)?;
        let session = psbt
            .session()?
            .ok_or_else(|| Error::Request("no nonce cache session".to_string()))?;
        if request.descriptors.is_empty() {
            return Err(Error::Request("no descriptor".to_string()));
        }
        let record = self
            .store
            .get(&session.session_id)?
            .ok_or(SignError::MusigSession)?;
        if record.secret.session_ref() != session.session_ref {
            return Err(SignError::MusigSession.into());
        }
        for descriptor in &request.descriptors {
            let descriptor = signing_descriptor(descriptor)?;
            psbt.sign(&self.signer, &descriptor, &record.secret)?;
        }
        let signed = psbt.serialize()?;
        self.store.remove(&session.session_id)?;
        self.store.flush()?;
        Ok(Signed::Psbt(signed))
    }

    /// Unsupported operations return explicit wire errors, never ordinary signing.
    pub fn handle(&mut self, request: QrRequest) -> QrResponse {
        let message_type = request.body.message_type();
        let result = match request.body {
            request::Body::PrepareNonces(body) => {
                self.prepare(body).map(response::Body::NoncesPrepared)
            }
            request::Body::Sign(body) => self.sign(body).map(response::Body::Signed),
            request::Body::RegisterDescriptor(body) => {
                self.register(body).map(response::Body::Registration)
            }
            _ => Err(Error::Request("unsupported operation".to_string())),
        };
        let body = match result {
            Ok(body) => body,
            Err(error) => response::Body::Error(response::ErrorBody {
                message_type,
                error: wire_error(&error),
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

/// A Signing PSBT, kept in the version it came in so the reply uses it too.
enum SigningPsbt {
    V0(Psbt),
    V2(PsbtV2),
}

impl SigningPsbt {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        match Psbt::deserialize(bytes) {
            Ok(psbt) => Ok(Self::V0(psbt)),
            Err(_) => PsbtV2::deserialize(bytes)
                .map(Self::V2)
                .map_err(|error| Error::Request(error.to_string())),
        }
    }

    fn session(&self) -> Result<Option<NonceCacheSession>, Error> {
        match self {
            Self::V0(psbt) => nonce_cache_session(psbt),
            Self::V2(psbt) => nonce_cache_session_v2(psbt),
        }
        .map_err(|error| Error::Request(error.to_string()))
    }

    fn sign(
        &mut self,
        signer: &HotSigner,
        descriptor: &WalletDescriptor,
        secret: &SessionSecret,
    ) -> Result<(), SignError> {
        match self {
            Self::V0(psbt) => signer.sign_nonce_cache(psbt, descriptor, secret),
            Self::V2(psbt) => signer.sign_nonce_cache_v2(psbt, descriptor, secret),
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, SignError> {
        match self {
            Self::V0(psbt) => Ok(psbt.serialize()),
            Self::V2(psbt) => psbt.serialize().map_err(|_| SignError::PsbtV2),
        }
    }
}

fn wire_error(error: &Error) -> response::Error {
    match error {
        Error::Request(_) => response::Error::MalformedRequest,
        // Persistence is retryable and does not consume the session.
        Error::Persist(_) => response::Error::InternalError,
        Error::Sign(SignError::MusigSession) => response::Error::MusigSession,
        Error::Sign(SignError::InputNotOwned) => response::Error::NothingToSign,
        Error::Sign(_) => response::Error::InvalidPsbt,
        Error::AlreadyRegistered(_) => response::Error::AlreadyRegistered,
    }
}

fn signing_descriptor(descriptor: &request::Descriptor) -> Result<WalletDescriptor, Error> {
    let body = descriptor
        .descriptor
        .as_ref()
        .ok_or_else(|| Error::Request("a descriptor body is required".to_string()))?;
    body_descriptor(body)
}

/// The wallet descriptor of a BIP-380 or BIP-388 body: both forms of one
/// descriptor give equal values.
fn body_descriptor(body: &DescriptorBody) -> Result<WalletDescriptor, Error> {
    let text = match body {
        DescriptorBody::Bip380(text) => text.clone(),
        DescriptorBody::Bip388 { keys, policy } => bip388_descriptor(keys, policy)?,
        DescriptorBody::SpKeys(_) => {
            return Err(Error::Request(
                "a BIP-380 or BIP-388 descriptor body is required".to_string(),
            ))
        }
    };
    Descriptor::from_str(&text)
        .map_err(|error| Error::Request(error.to_string()))?
        .into_miniscript()
        .map_err(|error| Error::Request(error.to_string()))
}

/// The BIP-380 text of a BIP-388 wallet policy: `/**` expands to `/<0;1>/*`, and
/// each `@i` becomes `keys[i]`. Every key must be used.
fn bip388_descriptor(keys: &[String], policy: &str) -> Result<String, Error> {
    let policy = policy.replace("/**", "/<0;1>/*");
    let mut used = vec![false; keys.len()];
    let mut text = String::with_capacity(policy.len());
    let mut rest = policy.as_str();
    while let Some(at) = rest.find('@') {
        text.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let key = rest[..digits]
            .parse::<usize>()
            .ok()
            .filter(|index| *index < keys.len())
            .ok_or_else(|| Error::Request("invalid BIP-388 key placeholder".to_string()))?;
        used[key] = true;
        text.push_str(&keys[key]);
        rest = &rest[digits..];
    }
    text.push_str(rest);
    if used.contains(&false) {
        return Err(Error::Request("unused BIP-388 key".to_string()));
    }
    Ok(text)
}

/// Registry value encoder for a caller's RamStore: the BIP-390 text with its
/// checksum.
pub fn encode_registered(descriptor: &WalletDescriptor) -> Vec<u8> {
    musig_descriptor_to_string(descriptor, true).into_bytes()
}

pub fn decode_registered(bytes: &[u8]) -> Result<WalletDescriptor, PersistError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PersistError::Serde("invalid registered descriptor".to_string()))?;
    parse_musig_descriptor(text).map_err(|error| PersistError::Serde(error.to_string()))
}

/// Value encoder for a caller's RamStore: the creation order (8 bytes little
/// endian) then the secret (32 bytes).
pub fn encode_record(record: &QrMusigPeerRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(RECORD_LEN);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(record.secret.as_bytes());
    bytes
}

pub fn decode_record(bytes: &[u8]) -> Result<QrMusigPeerRecord, PersistError> {
    if bytes.len() != RECORD_LEN {
        return Err(PersistError::Serde(
            "invalid QR MuSig peer record".to_string(),
        ));
    }
    let (sequence, secret) = bytes.split_at(SEQUENCE_LEN);
    let mut sequence_bytes = [0; SEQUENCE_LEN];
    sequence_bytes.copy_from_slice(sequence);
    let mut secret_bytes = [0; SECRET_LEN];
    secret_bytes.copy_from_slice(secret);
    let record = QrMusigPeerRecord {
        sequence: u64::from_le_bytes(sequence_bytes),
        secret: SessionSecret::from_bytes(secret_bytes),
    };
    wipe(&mut secret_bytes);
    Ok(record)
}
