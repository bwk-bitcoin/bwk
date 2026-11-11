#![cfg(feature = "musig")]

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{Arc, Mutex},
};

use bwk_descriptor::{
    descriptor::Descriptor,
    updater::update_input,
    wallet::{WalletDescriptor, WalletDescriptorExt},
};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::{
    musig::{
        musig_input_partial_sigs, musig_input_pub_nonce, musig_input_pub_nonces,
        set_musig_input_partial_sig, set_musig_input_pub_nonce, MusigPubNonce,
    },
    nonce_cache::{
        nonce_cache_session, nonce_cache_session_v2, set_nonce_cache_session, NonceCacheSession,
    },
    PsbtV2,
};
use bwk_qr_protocol::{
    encode_response,
    request::{
        self, Descriptor as QrDescriptor, DescriptorBody, PrepareNonces, RegisterDescriptor, Sign,
    },
    response::{self, Registration},
    types, Message, Request as QrRequest, RequestId as QrRequestId, Response as QrResponse,
    SignResponseKind,
};
use bwk_sign::{
    error::Error as SignError,
    hot_signer::HotSigner,
    identity::SignerId,
    musig::{aggregate_partial_sigs, slot_infos},
    protocol::{Request, RequestId, Response},
    qr_musig::{
        decode_record, decode_registered, encode_record, encode_registered, Error, QrMusigPeer,
        QrMusigPeerRecord, MAX_SESSIONS,
    },
    qr_musig_host::{Issuance, QrMusigHost, QrMusigHostRecord, QrMusigHostResponse},
};
use miniscript::bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Xpriv},
    hashes::Hash,
    transaction::Version,
    Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

struct Persistence<K, V> {
    committed: BTreeMap<K, V>,
    flushes: usize,
    fail_at: BTreeSet<usize>,
}

impl<K, V> Default for Persistence<K, V> {
    fn default() -> Self {
        Self {
            committed: BTreeMap::new(),
            flushes: 0,
            fail_at: BTreeSet::new(),
        }
    }
}

struct TestStore<K, V> {
    ram: BTreeMap<K, V>,
    persistence: Arc<Mutex<Persistence<K, V>>>,
}

impl<K: Ord + Clone, V: Clone> TestStore<K, V> {
    fn open(persistence: &Arc<Mutex<Persistence<K, V>>>) -> Self {
        let ram = persistence.lock().unwrap().committed.clone();
        Self {
            ram,
            persistence: Arc::clone(persistence),
        }
    }
}

impl<K: Ord + Clone, V: Clone> Store for TestStore<K, V> {
    type Key = K;
    type Value = V;

    fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, PersistError> {
        Ok(self.ram.get(key).cloned())
    }

    fn len(&self) -> Result<usize, PersistError> {
        Ok(self.ram.len())
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = (Self::Key, Self::Value)> + '_>, PersistError> {
        Ok(Box::new(
            self.ram
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        ))
    }

    fn insert(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, PersistError> {
        Ok(self.ram.insert(key, value))
    }

    fn remove(&mut self, key: &Self::Key) -> Result<Option<Self::Value>, PersistError> {
        Ok(self.ram.remove(key))
    }

    fn modify<F: FnOnce(&mut Self::Value)>(
        &mut self,
        key: &Self::Key,
        f: F,
    ) -> Result<bool, PersistError> {
        match self.ram.get_mut(key) {
            Some(value) => {
                f(value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn flush(&mut self) -> Result<(), PersistError> {
        let mut persistence = self.persistence.lock().unwrap();
        persistence.flushes += 1;
        let flush = persistence.flushes;
        if persistence.fail_at.remove(&flush) {
            return Err(PersistError::Io("injected flush failure".to_string()));
        }
        persistence.committed = self.ram.clone();
        Ok(())
    }
}

type PeerPersistence = Arc<Mutex<Persistence<[u8; 4], QrMusigPeerRecord>>>;
type RegistryPersistence = Arc<Mutex<Persistence<String, WalletDescriptor>>>;
type Peer = QrMusigPeer<TestStore<[u8; 4], QrMusigPeerRecord>, TestStore<String, WalletDescriptor>>;

/// `tr(musig(a2,b2)/<0;1>/*,pk(musig(a3,b3)/<0;1>/*))`: the peer signs for `a`,
/// whose key expression index is 0 at the role 2 path and 1 at the role 3 path.
struct Fixture {
    peer: Peer,
    persistence: PeerPersistence,
    registry: RegistryPersistence,
    host: QrMusigHost<TestStore<[u8; 4], QrMusigHostRecord>>,
    a: HotSigner,
    b: HotSigner,
    text: String,
    descriptor: WalletDescriptor,
}

impl Fixture {
    fn descriptors(&self) -> Vec<QrDescriptor> {
        vec![QrDescriptor {
            alias: "peer".to_string(),
            descriptor: Some(DescriptorBody::Bip380(self.text.clone())),
            proof: None,
        }]
    }

    /// Sends `bytes` from the host to the peer, and the answer back.
    fn exchange(&mut self, bytes: Vec<u8>) -> QrMusigHostResponse {
        let outer = RequestId::new(1);
        self.host.bind_outer_request(outer).unwrap();
        let response = self.peer.handle_remote(Request::Raw {
            request: outer,
            signer: signer_id(),
            payload: bytes,
        });
        self.host.accept_response(&response).unwrap()
    }

    /// Issues a session for both of `a`'s key expressions over `max_inputs` inputs.
    fn issue(&mut self, max_inputs: u8) -> [u8; 4] {
        let (session_id, bytes) = self
            .host
            .issue_request(
                signer_id(),
                capabilities(),
                QrRequestId([1, 1]),
                self.a.fingerprint(),
                issuance(2, max_inputs, 0),
            )
            .unwrap();
        self.exchange(bytes);
        let bytes = self
            .host
            .extend_request(
                capabilities(),
                QrRequestId([1, 2]),
                session_id,
                issuance(3, max_inputs, 1),
            )
            .unwrap();
        self.exchange(bytes);
        session_id
    }

    /// The Signing request the host builds for `psbt` with `session_id`.
    fn signing(&mut self, session_id: [u8; 4], psbt: &Psbt) -> Sign {
        let bytes = self
            .host
            .sign_request(
                capabilities(),
                QrRequestId([2, 1]),
                session_id,
                self.descriptors(),
                psbt,
                Some(SignResponseKind::Psbt),
            )
            .unwrap();
        self.host.cancel_pending();
        let Message::Request(QrRequest {
            body: request::Body::Sign(signing),
            ..
        }) = bwk_qr_protocol::decode(&bytes).unwrap()
        else {
            panic!("not a Signing request");
        };
        signing
    }

    /// A two-input spend where `b` already ran its round one.
    fn psbt(&self) -> Psbt {
        let mut psbt = spend(&self.descriptor, &[3, 3]);
        self.b.inner_sign(&mut psbt, &self.descriptor).unwrap();
        psbt
    }

    fn committed(&self) -> BTreeMap<[u8; 4], QrMusigPeerRecord> {
        self.persistence.lock().unwrap().committed.clone()
    }
}

fn signer_id() -> SignerId {
    SignerId::new("qr")
}

fn capabilities() -> response::Capabilities {
    response::Capabilities(response::Capabilities::NONCE_CACHE)
}

fn role_path(role: u32) -> DerivationPath {
    DerivationPath::from_str(&format!("m/87'/1'/0'/{role}")).unwrap()
}

fn issuance(role: u32, max_inputs: u8, key_expression_index: u32) -> Issuance {
    Issuance {
        path: role_path(role),
        max_inputs,
        start: key_expression_index,
        end: key_expression_index,
    }
}

fn signer(seed: u8) -> HotSigner {
    HotSigner::new_from_xpriv(
        Network::Regtest,
        Xpriv::new_master(Network::Regtest, &[seed; 32]).unwrap(),
    )
}

fn peer(persistence: &PeerPersistence, registry: &RegistryPersistence) -> Peer {
    QrMusigPeer::from_store(
        signer(1),
        TestStore::open(persistence),
        TestStore::open(registry),
    )
}

fn fixture() -> Fixture {
    let a = signer(1);
    let b = signer(2);
    let aggregate = |role| {
        format!(
            "musig({},{})/<0;1>/*",
            a.xpub(&role_path(role)),
            b.xpub(&role_path(role))
        )
    };
    let text = format!("tr({},pk({}))", aggregate(2), aggregate(3));
    let descriptor = Descriptor::from_str(&text)
        .unwrap()
        .into_miniscript()
        .unwrap();
    let persistence = PeerPersistence::default();
    let registry = RegistryPersistence::default();
    Fixture {
        peer: peer(&persistence, &registry),
        persistence,
        registry,
        host: QrMusigHost::from_store(TestStore::open(&Default::default())),
        a,
        b,
        text,
        descriptor,
    }
}

fn spend(descriptor: &WalletDescriptor, indexes: &[u32]) -> Psbt {
    let receive = descriptor.single_paths().unwrap()[0].clone();
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: (0..indexes.len())
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    vout: vout as u32,
                    ..OutPoint::null()
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(150_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    for (position, index) in indexes.iter().enumerate() {
        let definite = receive.derive_at(*index).unwrap();
        psbt.inputs[position].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: definite.script_pubkey(),
        });
        update_input(&mut psbt, position, &definite).unwrap();
    }
    psbt
}

fn preparation(session_id: [u8; 4], session_ref: Option<[u8; 4]>) -> PrepareNonces {
    PrepareNonces {
        session_id,
        session_ref,
        max_inputs: 2,
        derivation_path: (&role_path(2)).into(),
        start: 0,
        end: 1,
    }
}

fn signed_psbt(signed: response::Signed) -> Psbt {
    let response::Signed::Psbt(bytes) = signed else {
        panic!("not a signed PSBT");
    };
    Psbt::deserialize(&bytes).unwrap()
}

fn assert_session_refusal<T: std::fmt::Debug>(result: Result<T, Error>) {
    assert!(
        matches!(result, Err(Error::Sign(SignError::MusigSession))),
        "{result:?}"
    );
}

fn fail_after(persistence: &PeerPersistence, after: usize) {
    let mut persistence = persistence.lock().unwrap();
    let at = persistence.flushes + after;
    persistence.fail_at.insert(at);
}

#[test]
fn preparation_retries_return_the_same_nonces_and_reference() {
    let mut f = fixture();
    let prepared = f.peer.prepare(preparation([1; 4], None)).unwrap();
    assert_eq!(prepared.session_id, [1; 4]);
    assert_eq!(prepared.max_inputs, 2);
    assert_eq!((prepared.start, prepared.end), (0, 1));
    assert_eq!(prepared.nonces.len(), 4);
    assert_eq!(
        prepared.nonces.iter().collect::<BTreeSet<_>>().len(),
        4,
        "every (i, j) gets its own nonce"
    );
    assert_eq!(f.peer.prepare(preparation([1; 4], None)).unwrap(), prepared);
    assert_eq!(
        f.peer
            .prepare(preparation([1; 4], Some(prepared.session_ref)))
            .unwrap(),
        prepared
    );
    assert_eq!(f.committed().len(), 1);
    f.peer = peer(&f.persistence, &f.registry);
    assert_eq!(f.peer.prepare(preparation([1; 4], None)).unwrap(), prepared);

    let other = f.peer.prepare(preparation([2; 4], None)).unwrap();
    assert_ne!(other.session_ref, prepared.session_ref);
    assert!(other
        .nonces
        .iter()
        .all(|nonce| !prepared.nonces.contains(nonce)));
}

#[test]
fn reference_mismatch_and_unknown_session_are_refused_without_creating() {
    let mut f = fixture();
    let prepared = f.peer.prepare(preparation([1; 4], None)).unwrap();
    let mut wrong = prepared.session_ref;
    wrong[0] ^= 1;
    assert_session_refusal(f.peer.prepare(preparation([1; 4], Some(wrong))));
    assert_session_refusal(
        f.peer
            .prepare(preparation([2; 4], Some(prepared.session_ref))),
    );
    assert_eq!(f.committed().keys().collect::<Vec<_>>(), vec![&[1; 4]]);
    assert_eq!(f.peer.prepare(preparation([1; 4], None)).unwrap(), prepared);
}

#[test]
fn oldest_session_is_evicted() {
    let mut f = fixture();
    let first = f.peer.prepare(preparation([0; 4], None)).unwrap();
    for id in 1..=MAX_SESSIONS as u8 {
        f.peer.prepare(preparation([id; 4], None)).unwrap();
    }
    let committed = f.committed();
    assert_eq!(committed.len(), MAX_SESSIONS);
    assert!(!committed.contains_key(&[0; 4]));
    assert!(committed.contains_key(&[1; 4]));
    assert_session_refusal(f.peer.prepare(preparation([0; 4], Some(first.session_ref))));
    let recreated = f.peer.prepare(preparation([0; 4], None)).unwrap();
    assert_ne!(recreated.session_ref, first.session_ref);
    assert!(!f.committed().contains_key(&[1; 4]));
}

#[test]
fn issuance_flush_failure_releases_nothing_and_retries() {
    let mut f = fixture();
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.prepare(preparation([1; 4], None)),
        Err(Error::Persist(_))
    ));
    assert!(f.committed().is_empty());
    let prepared = f.peer.prepare(preparation([1; 4], None)).unwrap();
    assert_eq!(f.committed().len(), 1);
    f.peer = peer(&f.persistence, &f.registry);
    assert_eq!(f.peer.prepare(preparation([1; 4], None)).unwrap(), prepared);
}

#[test]
fn one_round_signing_through_the_host() {
    let mut f = fixture();
    let session_id = f.issue(2);
    assert_eq!(
        f.host.record(&session_id).unwrap().unwrap().nonces().len(),
        4
    );
    let psbt = f.psbt();
    let bytes = f
        .host
        .sign_request(
            capabilities(),
            QrRequestId([2, 1]),
            session_id,
            f.descriptors(),
            &psbt,
            Some(SignResponseKind::Psbt),
        )
        .unwrap();
    let QrMusigHostResponse::Signed(mut signed) = f.exchange(bytes) else {
        panic!("not a signed response");
    };
    assert!(f.host.record(&session_id).unwrap().is_none());
    assert!(!f.committed().contains_key(&session_id));
    for input in &signed.inputs {
        assert_eq!(musig_input_partial_sigs(input).unwrap().len(), 2);
    }
    f.b.inner_sign(&mut signed, &f.descriptor).unwrap();
    assert_eq!(
        aggregate_partial_sigs(&mut signed, &f.descriptor).unwrap(),
        4
    );
}

#[test]
fn signed_session_is_deleted_and_refuses_a_replay() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    f.peer.sign(signing.clone()).unwrap();
    assert!(f.committed().is_empty());
    assert_session_refusal(f.peer.sign(signing.clone()));
    f.peer = peer(&f.persistence, &f.registry);
    assert_session_refusal(f.peer.sign(signing));
}

#[test]
fn psbt_v2_is_signed_and_answered_as_v2() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    let v0 = Psbt::deserialize(&signing.psbt).unwrap();
    let v2 = PsbtV2::from_bitcoin_psbt(v0.clone()).unwrap();
    assert_eq!(
        nonce_cache_session_v2(&v2).unwrap(),
        nonce_cache_session(&v0).unwrap()
    );
    let signed = f
        .peer
        .sign(Sign {
            psbt: v2.serialize().unwrap(),
            ..signing
        })
        .unwrap();
    let response::Signed::Psbt(bytes) = signed else {
        panic!("not a signed PSBT");
    };
    let signed = PsbtV2::deserialize(&bytes).unwrap();
    assert_eq!(signed.unsigned_tx().unwrap(), v2.unsigned_tx().unwrap());
    for input in &signed.inputs {
        assert_eq!(musig_input_partial_sigs(&input.psbt).unwrap().len(), 2);
    }
    assert!(!f.committed().contains_key(&session_id));
}

/// The fixture descriptor as a BIP-388 wallet policy.
fn bip388_descriptors(f: &Fixture, policy: &str) -> Vec<QrDescriptor> {
    let keys = [(&f.a, 2), (&f.b, 2), (&f.a, 3), (&f.b, 3)]
        .into_iter()
        .map(|(signer, role)| signer.xpub(&role_path(role)).to_string())
        .collect();
    vec![QrDescriptor {
        alias: "peer".to_string(),
        descriptor: Some(DescriptorBody::Bip388 {
            keys,
            policy: policy.to_string(),
        }),
        proof: None,
    }]
}

#[test]
fn bip388_body_resolves_to_the_bip380_descriptor() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    for policy in [
        "tr(musig(@0,@1)/**,pk(musig(@2,@4)/**))",
        "tr(musig(@0,@1)/**,pk(musig(@2,@2)/**))",
    ] {
        let refused = f.peer.sign(Sign {
            descriptors: bip388_descriptors(&f, policy),
            ..signing.clone()
        });
        assert!(matches!(refused, Err(Error::Request(_))), "{policy}");
    }
    assert!(f.committed().contains_key(&session_id));
    let signed = signed_psbt(
        f.peer
            .sign(Sign {
                descriptors: bip388_descriptors(&f, "tr(musig(@0,@1)/**,pk(musig(@2,@3)/<0;1>/*))"),
                ..signing
            })
            .unwrap(),
    );
    for input in &signed.inputs {
        assert_eq!(musig_input_partial_sigs(input).unwrap().len(), 2);
    }
}

/// The reply of a signer answering `entries` to the pending Signing request.
fn signatures_reply(entries: Vec<response::SignatureEntry>) -> Response {
    Response::Raw {
        request: RequestId::new(1),
        signer: signer_id(),
        payload: encode_response(&QrResponse {
            id: QrRequestId([2, 1]),
            body: response::Body::Signed(response::Signed::Signatures(entries)),
        })
        .unwrap(),
    }
}

#[test]
fn host_merges_a_signatures_only_reply() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let psbt = f.psbt();
    let bytes = f
        .host
        .sign_request(
            capabilities(),
            QrRequestId([2, 1]),
            session_id,
            f.descriptors(),
            &psbt,
            Some(SignResponseKind::Signatures),
        )
        .unwrap();
    f.host.bind_outer_request(RequestId::new(1)).unwrap();
    let Message::Request(QrRequest {
        body: request::Body::Sign(signing),
        ..
    }) = bwk_qr_protocol::decode(&bytes).unwrap()
    else {
        panic!("not a Signing request");
    };
    assert_eq!(signing.want_kind, Some(SignResponseKind::Signatures));
    let signed = signed_psbt(f.peer.sign(signing).unwrap());
    let mut entries = vec![response::SignatureEntry::Unknown {
        input_index: 0,
        kind: 0x7f,
        fields: vec![1, 2, 3],
    }];
    for (input_index, input) in signed.inputs.iter().enumerate() {
        for sig in musig_input_partial_sigs(input).unwrap() {
            entries.push(response::SignatureEntry::MusigPartialSig {
                input_index: input_index as u32,
                participant: types::PublicKey(sig.participant.serialize()),
                aggregate: types::PublicKey(sig.aggregate.serialize()),
                leaf_hash: sig.leaf_hash.map(|hash| hash.to_byte_array()),
                signature: sig.signature,
            });
        }
    }
    assert_eq!(entries.len(), 5);

    let mut unplaced = entries.clone();
    let response::SignatureEntry::MusigPartialSig {
        participant,
        aggregate,
        leaf_hash,
        ..
    } = entries[1].clone()
    else {
        panic!("not a partial signature");
    };
    unplaced.push(response::SignatureEntry::MusigPubNonce {
        input_index: 0,
        participant,
        aggregate,
        leaf_hash,
        nonce: [2; 66],
    });
    assert!(f.host.accept_response(&signatures_reply(unplaced)).is_err());
    let mut silent_payment = entries.clone();
    silent_payment.push(response::SignatureEntry::SpEcdhShare {
        scope: response::SpScope::Global,
        scan_key: participant,
        share: aggregate,
    });
    assert!(f
        .host
        .accept_response(&signatures_reply(silent_payment))
        .is_err());
    let mut unknown_input = entries.clone();
    unknown_input.push(response::SignatureEntry::TapKey {
        input_index: 9,
        signature: vec![1; 64],
    });
    assert!(f
        .host
        .accept_response(&signatures_reply(unknown_input))
        .is_err());
    assert!(f.host.record(&session_id).unwrap().is_some());

    let QrMusigHostResponse::Signed(merged) =
        f.host.accept_response(&signatures_reply(entries)).unwrap()
    else {
        panic!("not a signed response");
    };
    assert_eq!(merged, signed);
    assert!(f.host.record(&session_id).unwrap().is_none());
}

/// The reply of a signer answering `psbt` to the pending Signing request.
fn psbt_reply(psbt: &Psbt) -> Response {
    Response::Raw {
        request: RequestId::new(1),
        signer: signer_id(),
        payload: encode_response(&QrResponse {
            id: QrRequestId([2, 1]),
            body: response::Body::Signed(response::Signed::Psbt(psbt.serialize())),
        })
        .unwrap(),
    }
}

#[test]
fn host_rejects_a_reply_failing_partial_signature_verification() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let psbt = f.psbt();
    let bytes = f
        .host
        .sign_request(
            capabilities(),
            QrRequestId([2, 1]),
            session_id,
            f.descriptors(),
            &psbt,
            None,
        )
        .unwrap();
    f.host.bind_outer_request(RequestId::new(1)).unwrap();
    let Message::Request(QrRequest {
        body: request::Body::Sign(signing),
        ..
    }) = bwk_qr_protocol::decode(&bytes).unwrap()
    else {
        panic!("not a Signing request");
    };
    let signed = signed_psbt(f.peer.sign(signing).unwrap());
    let sig = musig_input_partial_sigs(&signed.inputs[1]).unwrap()[0];

    let mut tampered = signed.clone();
    let mut bad = sig;
    bad.signature[31] ^= 1;
    set_musig_input_partial_sig(&mut tampered.inputs[1], &bad);
    assert!(f.host.accept_response(&psbt_reply(&tampered)).is_err());
    assert!(f
        .host
        .accept_response(&signatures_reply(vec![
            response::SignatureEntry::MusigPartialSig {
                input_index: 1,
                participant: types::PublicKey(bad.participant.serialize()),
                aggregate: types::PublicKey(bad.aggregate.serialize()),
                leaf_hash: bad.leaf_hash.map(|hash| hash.to_byte_array()),
                signature: bad.signature,
            }
        ]))
        .is_err());
    let mut moved = signed.clone();
    moved.inputs[0] = signed.inputs[1].clone();
    assert!(f.host.accept_response(&psbt_reply(&moved)).is_err());
    let mut other_nonce = signed.clone();
    let nonce = musig_input_pub_nonces(&signed.inputs[0]).unwrap()[0];
    set_musig_input_pub_nonce(
        &mut other_nonce.inputs[0],
        &MusigPubNonce {
            nonce: musig_input_pub_nonces(&signed.inputs[1]).unwrap()[0].nonce,
            ..nonce
        },
    );
    assert!(f.host.accept_response(&psbt_reply(&other_nonce)).is_err());
    assert!(f.host.record(&session_id).unwrap().is_some());

    let QrMusigHostResponse::Signed(accepted) =
        f.host.accept_response(&psbt_reply(&signed)).unwrap()
    else {
        panic!("not a signed response");
    };
    assert_eq!(accepted, signed);
    assert!(f.host.record(&session_id).unwrap().is_none());
}

fn registration(alias: &str, descriptor: Option<DescriptorBody>) -> RegisterDescriptor {
    RegisterDescriptor {
        descriptor_alias: alias.to_string(),
        descriptor,
    }
}

fn bip380_body(f: &Fixture) -> DescriptorBody {
    DescriptorBody::Bip380(f.text.clone())
}

fn bip388_body(f: &Fixture, policy: &str) -> DescriptorBody {
    bip388_descriptors(f, policy).remove(0).descriptor.unwrap()
}

fn assert_registration(registration: Registration, alias: &str, registered: bool) {
    assert_eq!(
        registration,
        Registration {
            descriptor_alias: alias.to_string(),
            registered: Some(registered),
            stored: Some(registered),
            proof: None,
        }
    );
}

#[test]
fn register_stores_the_alias_and_answers_its_status() {
    let mut f = fixture();
    assert_registration(
        f.peer.register(registration("peer", None)).unwrap(),
        "peer",
        false,
    );
    assert!(f.registry.lock().unwrap().committed.is_empty());

    let body = bip380_body(&f);
    assert_registration(
        f.peer
            .register(registration("peer", Some(body.clone())))
            .unwrap(),
        "peer",
        true,
    );
    assert_eq!(f.registry.lock().unwrap().committed["peer"], f.descriptor);
    assert_registration(
        f.peer.register(registration("peer", Some(body))).unwrap(),
        "peer",
        true,
    );
    let same = bip388_body(&f, "tr(musig(@0,@1)/**,pk(musig(@2,@3)/**))");
    assert_registration(
        f.peer.register(registration("peer", Some(same))).unwrap(),
        "peer",
        true,
    );
    let other = bip388_body(&f, "tr(musig(@2,@3)/**,pk(musig(@0,@1)/**))");
    assert!(matches!(
        f.peer.register(registration("peer", Some(other.clone()))),
        Err(Error::AlreadyRegistered(alias)) if alias == "peer"
    ));
    assert_eq!(f.registry.lock().unwrap().committed["peer"], f.descriptor);
    assert_registration(
        f.peer.register(registration("other", Some(other))).unwrap(),
        "other",
        true,
    );

    f.peer = peer(&f.persistence, &f.registry);
    assert_registration(
        f.peer.register(registration("peer", None)).unwrap(),
        "peer",
        true,
    );
    assert_registration(
        f.peer.register(registration("unknown", None)).unwrap(),
        "unknown",
        false,
    );
}

#[test]
fn another_descriptor_under_a_registered_alias_is_the_already_registered_error() {
    let mut f = fixture();
    f.peer
        .register(registration("peer", Some(bip380_body(&f))))
        .unwrap();
    let refused = f.peer.handle(QrRequest {
        id: QrRequestId([4, 4]),
        body: request::Body::RegisterDescriptor(registration(
            "peer",
            Some(bip388_body(&f, "tr(musig(@2,@3)/**,pk(musig(@0,@1)/**))")),
        )),
    });
    assert_eq!(refused.id, QrRequestId([4, 4]));
    assert!(matches!(
        refused.body,
        response::Body::Error(response::ErrorBody {
            error: response::Error::AlreadyRegistered,
            ..
        })
    ));
    let status = f.peer.handle(QrRequest {
        id: QrRequestId([4, 5]),
        body: request::Body::RegisterDescriptor(registration("peer", None)),
    });
    assert!(matches!(
        status.body,
        response::Body::Registration(Registration {
            registered: Some(true),
            ..
        })
    ));
}

#[test]
fn registered_descriptor_codec_roundtrips() {
    let f = fixture();
    let bytes = encode_registered(&f.descriptor);
    assert_eq!(decode_registered(&bytes).unwrap(), f.descriptor);
    assert!(decode_registered(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_registered(&[0xff]).is_err());
}

fn with_descriptors(signing: &Sign, descriptors: Vec<QrDescriptor>) -> Sign {
    Sign {
        descriptors,
        ..signing.clone()
    }
}

fn entry(alias: &str, descriptor: Option<DescriptorBody>) -> QrDescriptor {
    QrDescriptor {
        alias: alias.to_string(),
        descriptor,
        proof: Some(vec![0xde, 0xad]),
    }
}

#[test]
fn signing_resolves_registered_aliases_and_ignores_proofs() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());

    let unknown = with_descriptors(&signing, vec![entry("peer", None)]);
    assert!(matches!(
        f.peer.sign(unknown.clone()),
        Err(Error::UnknownAlias(alias)) if alias == "peer"
    ));
    let refused = f.peer.handle(QrRequest {
        id: QrRequestId([6, 6]),
        body: request::Body::Sign(unknown),
    });
    assert!(matches!(
        refused.body,
        response::Body::Error(response::ErrorBody {
            error: response::Error::UnknownDescriptorAlias,
            ..
        })
    ));

    f.peer
        .register(registration("peer", Some(bip380_body(&f))))
        .unwrap();
    let other = bip388_body(&f, "tr(musig(@2,@3)/**,pk(musig(@0,@1)/**))");
    let mismatch = with_descriptors(&signing, vec![entry("peer", Some(other))]);
    assert!(matches!(
        f.peer.sign(mismatch),
        Err(Error::AlreadyRegistered(alias)) if alias == "peer"
    ));
    assert!(f.committed().contains_key(&session_id));

    let same = bip388_body(&f, "tr(musig(@0,@1)/**,pk(musig(@2,@3)/**))");
    let matching = with_descriptors(&signing, vec![entry("peer", Some(same))]);
    let signed = signed_psbt(f.peer.sign(matching).unwrap());
    assert_eq!(
        musig_input_partial_sigs(&signed.inputs[0]).unwrap().len(),
        2
    );

    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    let alias_only = with_descriptors(&signing, vec![entry("peer", None)]);
    let signed = signed_psbt(f.peer.sign(alias_only).unwrap());
    assert_eq!(
        musig_input_partial_sigs(&signed.inputs[0]).unwrap().len(),
        2
    );

    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    let body_only = with_descriptors(&signing, vec![entry("unregistered", Some(bip380_body(&f)))]);
    let signed = signed_psbt(f.peer.sign(body_only).unwrap());
    assert_eq!(
        musig_input_partial_sigs(&signed.inputs[0]).unwrap().len(),
        2
    );
    assert!(!f
        .registry
        .lock()
        .unwrap()
        .committed
        .contains_key("unregistered"));
}

#[test]
fn signing_refusals_keep_the_session() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    let psbt = Psbt::deserialize(&signing.psbt).unwrap();
    let with = |psbt: &Psbt| Sign {
        psbt: psbt.serialize(),
        ..signing.clone()
    };

    let mut unnamed = psbt.clone();
    unnamed.unknown.clear();
    assert!(matches!(
        f.peer.sign(with(&unnamed)),
        Err(Error::Request(_))
    ));

    let mut wrong_ref = psbt.clone();
    set_nonce_cache_session(
        &mut wrong_ref,
        NonceCacheSession {
            session_id,
            session_ref: [0; 4],
        },
    );
    assert_session_refusal(f.peer.sign(with(&wrong_ref)));

    let mut swapped = psbt.clone();
    let own: Vec<_> = slot_infos(&psbt, &f.descriptor)
        .unwrap()
        .into_iter()
        .filter(|info| info.signer.0 == f.a.fingerprint())
        .collect();
    let first = &own[0].slot;
    let first = musig_input_pub_nonce(
        &psbt.inputs[first.input_index],
        first.participant,
        first.aggregate,
        first.leaf_hash,
    )
    .unwrap()
    .unwrap();
    let second = &own[1];
    set_musig_input_pub_nonce(
        &mut swapped.inputs[second.slot.input_index],
        &MusigPubNonce {
            participant: second.slot.participant,
            aggregate: second.slot.aggregate,
            leaf_hash: second.slot.leaf_hash,
            nonce: first,
        },
    );
    assert_session_refusal(f.peer.sign(with(&swapped)));

    let mut no_descriptor = signing.clone();
    no_descriptor.descriptors.clear();
    assert!(matches!(f.peer.sign(no_descriptor), Err(Error::Request(_))));

    assert!(f.committed().contains_key(&session_id));
    f.peer.sign(signing).unwrap();
    assert!(f.committed().is_empty());
}

#[test]
fn failed_deletion_releases_nothing() {
    let mut f = fixture();
    let session_id = f.issue(2);
    let signing = f.signing(session_id, &f.psbt());
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.sign(signing.clone()),
        Err(Error::Persist(_))
    ));
    assert_session_refusal(f.peer.sign(signing.clone()));
    // No signature left, so the session the disk still holds is safe to use.
    assert!(f.committed().contains_key(&session_id));
    f.peer = peer(&f.persistence, &f.registry);
    let signed = signed_psbt(f.peer.sign(signing).unwrap());
    assert_eq!(
        musig_input_partial_sigs(&signed.inputs[0]).unwrap().len(),
        2
    );
    assert!(f.committed().is_empty());
}

#[test]
fn record_codec_roundtrips_and_rejects_truncation_and_trailing_bytes() {
    let mut f = fixture();
    f.peer.prepare(preparation([1; 4], None)).unwrap();
    f.peer.prepare(preparation([2; 4], None)).unwrap();
    for record in f.committed().values() {
        let bytes = encode_record(record);
        assert_eq!(bytes.len(), 40);
        assert_eq!(&decode_record(&bytes).unwrap(), record);
        for len in 0..bytes.len() {
            assert!(decode_record(&bytes[..len]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_record(&trailing).is_err());
    }
    assert_eq!(
        format!("{:?}", f.committed()[&[1; 4]]),
        "QrMusigPeerRecord { sequence: 0, secret: SessionSecret(..) }"
    );
}

#[test]
fn raw_handler_preserves_both_request_ids_and_signer_and_reports_errors() {
    let mut f = fixture();
    let inner = QrRequest {
        id: QrRequestId([7, 9]),
        body: request::Body::PrepareNonces(preparation([1; 4], None)),
    };
    let request = RequestId::new(76);
    let response = f.peer.handle_remote(Request::Raw {
        request,
        signer: signer_id(),
        payload: bwk_qr_protocol::encode_request(&inner).unwrap(),
    });
    let Response::Raw {
        request: returned,
        signer: returned_signer,
        payload,
    } = response
    else {
        panic!("not a Raw response");
    };
    assert_eq!(returned, request);
    assert_eq!(returned_signer, signer_id());
    let Message::Response(response) = bwk_qr_protocol::decode(&payload).unwrap() else {
        panic!("not a QR response");
    };
    assert_eq!(response.id, inner.id);
    assert!(matches!(response.body, response::Body::NoncesPrepared(_)));

    let mut unknown = preparation([3; 4], None);
    unknown.session_ref = Some([0; 4]);
    let refused = f.peer.handle(QrRequest {
        id: inner.id,
        body: request::Body::PrepareNonces(unknown),
    });
    assert_eq!(refused.id, inner.id);
    assert!(matches!(
        refused.body,
        response::Body::Error(response::ErrorBody {
            error: response::Error::MusigSession,
            ..
        })
    ));
    let unsupported_inner = f.peer.handle(QrRequest {
        id: inner.id,
        body: request::Body::GetKeys(request::GetKeys { keys: Vec::new() }),
    });
    assert!(matches!(
        unsupported_inner.body,
        response::Body::Error(response::ErrorBody {
            error: response::Error::MalformedRequest,
            ..
        })
    ));
    let malformed = f.peer.handle_remote(Request::Raw {
        request,
        signer: signer_id(),
        payload: vec![0],
    });
    assert!(matches!(
        malformed,
        Response::Error { request: Some(id), signer: Some(who), .. }
            if id == request && who == signer_id()
    ));
    let unsupported = f.peer.handle_remote(Request::Info {
        request,
        signer: signer_id(),
    });
    assert!(matches!(unsupported, Response::Error { request: Some(id), .. } if id == request));
}
