use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bwk_descriptor::{
    musig::parse_musig_descriptor,
    updater::update_input,
    wallet::{WalletDescriptor, WalletDescriptorExt},
};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::{
    musig::{musig_input_pub_nonce, set_musig_input_pub_nonce, MusigPubNonce},
    nonce_cache::{nonce_cache_session, NonceCacheSession},
};
use bwk_qr_protocol::{
    decode, encode_response, request, response, Message, Request as QrRequest,
    RequestId as QrRequestId, Response as QrResponse, SignResponseKind,
};
use crossbeam::channel;
use miniscript::bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint},
    transaction::Version,
    Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use crate::{
    hot_signer::HotSigner,
    identity::SignerId,
    manager::SigningManager,
    musig::{slot_infos, SlotInfo},
    nonce_cache::SessionSecret,
    protocol::{Request, RequestId, Response},
    qr_musig_host::{
        Error, Issuance, NoncePosition, QrMusigHost, QrMusigHostRecord, QrMusigHostResponse,
    },
    remote_manager::RemoteManager,
};

const ORDINARY_MUSIG_CAPABILITY: u32 = 1 << 3;
const COSIGNER_PATH: &str = "m/87'/1'/0'/2";

#[derive(Default)]
struct Disk {
    rows: BTreeMap<[u8; 4], QrMusigHostRecord>,
    fail: bool,
    flushes: usize,
}

#[derive(Default)]
struct TestStore {
    ram: BTreeMap<[u8; 4], QrMusigHostRecord>,
    disk: Arc<Mutex<Disk>>,
}

impl Store for TestStore {
    type Key = [u8; 4];
    type Value = QrMusigHostRecord;

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
            self.ram.iter().map(|(key, value)| (*key, value.clone())),
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
        update: F,
    ) -> Result<bool, PersistError> {
        match self.ram.get_mut(key) {
            Some(value) => {
                update(value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn flush(&mut self) -> Result<(), PersistError> {
        let mut disk = self.disk.lock().unwrap();
        disk.flushes += 1;
        if disk.fail {
            return Err(PersistError::Io("injected flush failure".into()));
        }
        disk.rows = self.ram.clone();
        Ok(())
    }
}

/// `tr(musig(first,second)/<0;1>/*)`, with the first signer as the device.
struct Fixture {
    device: HotSigner,
    secret: SessionSecret,
    descriptor_text: String,
    descriptor: WalletDescriptor,
}

impl Fixture {
    fn fingerprint(&self) -> Fingerprint {
        self.device.fingerprint()
    }

    fn descriptors(&self) -> Vec<request::Descriptor> {
        vec![request::Descriptor {
            alias: "fixture".into(),
            descriptor: Some(request::DescriptorBody::Bip380(
                self.descriptor_text.clone(),
            )),
            proof: None,
        }]
    }

    /// The nonces the device issues for `issuance`, in wire order.
    fn nonces(&self, issuance: &Issuance) -> Vec<[u8; 66]> {
        let secret_key = self.device.private_key_at(&issuance.path).secret_bytes();
        let public_key = self.device.public_key_at(&issuance.path).serialize();
        let mut nonces = Vec::new();
        for j in issuance.start..=issuance.end {
            for i in 0..u32::from(issuance.max_inputs) {
                let (_, nonce) = self.secret.nonce(i, j, &secret_key, &public_key).unwrap();
                nonces.push(nonce);
            }
        }
        nonces
    }

    fn prepared(&self, session_id: [u8; 4], issuance: &Issuance) -> response::NoncesPrepared {
        response::NoncesPrepared {
            session_id,
            session_ref: self.secret.session_ref(),
            max_inputs: issuance.max_inputs,
            start: issuance.start,
            end: issuance.end,
            nonces: self.nonces(issuance),
        }
    }

    /// The slots of the device in `psbt`.
    fn own_slots(&self, psbt: &Psbt) -> Vec<SlotInfo> {
        slot_infos(psbt, &self.descriptor)
            .unwrap()
            .into_iter()
            .filter(|info| info.signer.0 == self.fingerprint())
            .collect()
    }
}

fn fixture() -> Fixture {
    let device = HotSigner::new_from_mnemonics(Network::Regtest,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let second = HotSigner::new_from_mnemonics(
        Network::Regtest,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .unwrap();
    let path = DerivationPath::from_str(COSIGNER_PATH).unwrap();
    let descriptor_text = format!(
        "tr(musig({},{})/<0;1>/*)",
        device.xpub(&path),
        second.xpub(&path)
    );
    let descriptor = parse_musig_descriptor(&descriptor_text).unwrap();
    Fixture {
        device,
        secret: SessionSecret::from_bytes([5; 32]),
        descriptor_text,
        descriptor,
    }
}

fn issuance(max_inputs: u8) -> Issuance {
    Issuance {
        path: DerivationPath::from_str(COSIGNER_PATH).unwrap(),
        max_inputs,
        start: 0,
        end: 0,
    }
}

/// Spends the receive coins at `indexes`.
fn spend(descriptor: &WalletDescriptor, indexes: &[u32]) -> Psbt {
    let receive = descriptor.single_paths().unwrap()[0].clone();
    let tx = Transaction {
        version: Version::TWO,
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

fn capabilities() -> response::Capabilities {
    response::Capabilities(response::Capabilities::NONCE_CACHE)
}

fn raw_response(outer: RequestId, id: QrRequestId, body: response::Body) -> Response {
    Response::Raw {
        request: outer,
        signer: SignerId::new("qr"),
        payload: encode_response(&QrResponse { id, body }).unwrap(),
    }
}

fn issue(
    host: &mut QrMusigHost<TestStore>,
    fixture: &Fixture,
    max_inputs: u8,
) -> ([u8; 4], Vec<u8>) {
    host.issue_request(
        SignerId::new("qr"),
        capabilities(),
        QrRequestId([1, 2]),
        fixture.fingerprint(),
        issuance(max_inputs),
    )
    .unwrap()
}

/// Issues a session of `max_inputs` inputs and accepts the device's answer.
fn issued(host: &mut QrMusigHost<TestStore>, fixture: &Fixture, max_inputs: u8) -> [u8; 4] {
    let (session_id, _) = issue(host, fixture, max_inputs);
    host.bind_outer_request(RequestId::new(7)).unwrap();
    let prepared = fixture.prepared(session_id, &issuance(max_inputs));
    assert!(matches!(
        host.accept_response(&raw_response(
            RequestId::new(7),
            QrRequestId([1, 2]),
            response::Body::NoncesPrepared(prepared)
        ))
        .unwrap(),
        QrMusigHostResponse::Prepared(_)
    ));
    session_id
}

/// The Signing request the host built.
fn sent_signing(bytes: &[u8]) -> request::Sign {
    let Ok(Message::Request(QrRequest {
        body: request::Body::Sign(signing),
        ..
    })) = decode(bytes)
    else {
        panic!("not a Signing request");
    };
    signing
}

#[test]
fn raw_manager_attribution_and_record_roundtrip() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let (session_id, bytes) = issue(&mut host, &fixture, 1);
    let Ok(Message::Request(QrRequest {
        body: request::Body::PrepareNonces(preparation),
        ..
    })) = decode(&bytes)
    else {
        panic!("not a Nonce Preparation request");
    };
    assert_eq!(preparation.session_id, session_id);
    assert_eq!(preparation.session_ref, None);
    assert_eq!(
        DerivationPath::from(&preparation.derivation_path),
        DerivationPath::from_str(COSIGNER_PATH).unwrap()
    );
    let (mut manager, outbound, inbound) = RemoteManager::pair();
    let (sender, receiver) = channel::unbounded();
    manager.subscribe(sender);
    assert!(matches!(
        outbound.recv().unwrap(),
        Request::ListSigners { .. }
    ));
    let outer = host.submit_pending(&manager).unwrap();
    assert_eq!(
        outbound.recv().unwrap(),
        Request::Raw {
            request: outer,
            signer: SignerId::new("qr"),
            payload: bytes,
        }
    );
    let response = raw_response(
        outer,
        QrRequestId([1, 2]),
        response::Body::NoncesPrepared(fixture.prepared(session_id, &issuance(1))),
    );
    let mut wrong = response.clone();
    if let Response::Raw { request, .. } = &mut wrong {
        *request = RequestId::new(999);
    }
    assert!(host.accept_response(&wrong).is_err());
    let mut wrong = response.clone();
    if let Response::Raw { signer, .. } = &mut wrong {
        *signer = SignerId::new("other");
    }
    assert!(host.accept_response(&wrong).is_err());
    inbound.send(response).unwrap();
    let delivered = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(matches!(
        host.accept_response(&delivered).unwrap(),
        QrMusigHostResponse::Prepared(_)
    ));
    let record = host.record(&session_id).unwrap().unwrap();
    assert_eq!(record.session_ref(), Some(fixture.secret.session_ref()));
    assert_eq!(
        record.nonces().keys().cloned().collect::<Vec<_>>(),
        vec![NoncePosition {
            path: DerivationPath::from_str(COSIGNER_PATH).unwrap(),
            key_expression_index: 0,
            input_index: 0,
        }]
    );
    let bytes = record.encode().unwrap();
    let decoded = QrMusigHostRecord::decode(&bytes).unwrap();
    assert_eq!(decoded, record);
    for len in 0..bytes.len() {
        assert!(QrMusigHostRecord::decode(&bytes[..len]).is_err());
    }
    let mut corrupt = bytes;
    corrupt.push(0);
    assert!(QrMusigHostRecord::decode(&corrupt).is_err());
}

#[test]
fn generic_musig_capability_does_not_enable_the_cache() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    assert!(host
        .issue_request(
            SignerId::new("qr"),
            response::Capabilities(ORDINARY_MUSIG_CAPABILITY),
            QrRequestId([1, 2]),
            fixture.fingerprint(),
            issuance(1),
        )
        .is_err());
    assert!(host.store.ram.is_empty());
}

#[test]
fn extension_sends_the_session_reference_and_keeps_issued_nonces() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let session_id = issued(&mut host, &fixture, 1);
    let wider = issuance(2);
    let bytes = host
        .extend_request(
            capabilities(),
            QrRequestId([3, 4]),
            session_id,
            wider.clone(),
        )
        .unwrap();
    let Ok(Message::Request(QrRequest {
        body: request::Body::PrepareNonces(preparation),
        ..
    })) = decode(&bytes)
    else {
        panic!("not a Nonce Preparation request");
    };
    assert_eq!(preparation.session_ref, Some(fixture.secret.session_ref()));
    host.bind_outer_request(RequestId::new(8)).unwrap();

    let mut changed = fixture.prepared(session_id, &wider);
    changed.nonces.swap(0, 1);
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(8),
            QrRequestId([3, 4]),
            response::Body::NoncesPrepared(changed)
        ))
        .is_err());
    let mut other_session = fixture.prepared(session_id, &wider);
    other_session.session_ref = [0; 4];
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(8),
            QrRequestId([3, 4]),
            response::Body::NoncesPrepared(other_session)
        ))
        .is_err());
    let mut wrong_echo = fixture.prepared(session_id, &wider);
    wrong_echo.max_inputs = 1;
    wrong_echo.nonces.truncate(1);
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(8),
            QrRequestId([3, 4]),
            response::Body::NoncesPrepared(wrong_echo)
        ))
        .is_err());
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(8),
            QrRequestId([9, 9]),
            response::Body::NoncesPrepared(fixture.prepared(session_id, &wider))
        ))
        .is_err());
    assert_eq!(host.record(&session_id).unwrap().unwrap().nonces().len(), 1);

    host.accept_response(&raw_response(
        RequestId::new(8),
        QrRequestId([3, 4]),
        response::Body::NoncesPrepared(fixture.prepared(session_id, &wider)),
    ))
    .unwrap();
    assert_eq!(host.record(&session_id).unwrap().unwrap().nonces().len(), 2);
}

#[test]
fn sign_request_places_nonces_at_their_positions_and_names_the_session() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let session_id = issued(&mut host, &fixture, 2);
    let psbt = spend(&fixture.descriptor, &[3, 4]);
    let bytes = host
        .sign_request(
            capabilities(),
            QrRequestId([5, 6]),
            session_id,
            fixture.descriptors(),
            &psbt,
            Some(SignResponseKind::Psbt),
        )
        .unwrap();
    let signing = sent_signing(&bytes);
    assert_eq!(signing.descriptors, fixture.descriptors());
    assert_eq!(signing.want_kind, Some(SignResponseKind::Psbt));
    let sent = Psbt::deserialize(&signing.psbt).unwrap();
    assert_eq!(sent.unsigned_tx, psbt.unsigned_tx);
    assert_eq!(
        nonce_cache_session(&sent).unwrap(),
        Some(NonceCacheSession {
            session_id,
            session_ref: fixture.secret.session_ref(),
        })
    );
    let issued = fixture.nonces(&issuance(2));
    let own = fixture.own_slots(&sent);
    assert_eq!(own.len(), 2);
    for info in own {
        assert_eq!(info.key_expression_index, 0);
        assert_eq!(
            info.pub_nonce(&sent.inputs[info.slot.input_index]).unwrap(),
            Some(issued[info.slot.input_index])
        );
    }
}

#[test]
fn sign_request_refuses_unissued_slots_and_other_nonces() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let (pending, _) = issue(&mut host, &fixture, 1);
    host.cancel_pending();
    let psbt = spend(&fixture.descriptor, &[3]);
    let sign = |host: &mut QrMusigHost<TestStore>, session_id, psbt: &Psbt| {
        host.sign_request(
            capabilities(),
            QrRequestId([5, 6]),
            session_id,
            fixture.descriptors(),
            psbt,
            Some(SignResponseKind::Psbt),
        )
    };
    assert!(sign(&mut host, pending, &psbt).is_err());
    let session_id = issued(&mut host, &fixture, 1);
    assert!(sign(&mut host, [0xee; 4], &psbt).is_err());
    assert!(sign(&mut host, session_id, &spend(&fixture.descriptor, &[3, 4])).is_err());

    let mut other = psbt.clone();
    let info = &fixture.own_slots(&psbt)[0];
    let mut nonce = fixture.nonces(&issuance(1))[0];
    nonce.swap(1, 34);
    set_musig_input_pub_nonce(
        &mut other.inputs[0],
        &MusigPubNonce {
            participant: info.slot.participant,
            aggregate: info.slot.aggregate,
            leaf_hash: info.slot.leaf_hash,
            nonce,
        },
    );
    assert!(sign(&mut host, session_id, &other).is_err());
    assert!(host.pending.is_none());
    assert!(sign(&mut host, session_id, &psbt).is_ok());
}

#[test]
fn signed_response_drops_the_session_and_must_spend_the_same_transaction() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let session_id = issued(&mut host, &fixture, 1);
    let psbt = spend(&fixture.descriptor, &[3]);
    let bytes = host
        .sign_request(
            capabilities(),
            QrRequestId([5, 6]),
            session_id,
            fixture.descriptors(),
            &psbt,
            Some(SignResponseKind::Psbt),
        )
        .unwrap();
    host.bind_outer_request(RequestId::new(9)).unwrap();
    let sent = Psbt::deserialize(&sent_signing(&bytes).psbt).unwrap();
    let mut other = sent.clone();
    other.unsigned_tx.output[0].value = Amount::from_sat(1);
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(9),
            QrRequestId([5, 6]),
            response::Body::Signed(response::Signed::Psbt(other.serialize()))
        ))
        .is_err());
    assert!(host
        .accept_response(&raw_response(
            RequestId::new(9),
            QrRequestId([5, 6]),
            response::Body::Signed(response::Signed::Signatures(Vec::new()))
        ))
        .is_err());
    assert!(host.record(&session_id).unwrap().is_some());
    let QrMusigHostResponse::Signed(returned) = host
        .accept_response(&raw_response(
            RequestId::new(9),
            QrRequestId([5, 6]),
            response::Body::Signed(response::Signed::Psbt(sent.serialize())),
        ))
        .unwrap()
    else {
        panic!("not a signed response");
    };
    assert_eq!(returned, sent);
    assert!(host.record(&session_id).unwrap().is_none());
    assert!(host.store.disk.lock().unwrap().rows.is_empty());
}

#[test]
fn session_refusal_drops_the_session_and_other_refusals_keep_it() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let session_id = issued(&mut host, &fixture, 1);
    let psbt = spend(&fixture.descriptor, &[3]);
    let refuse = |host: &mut QrMusigHost<TestStore>, error| {
        host.sign_request(
            capabilities(),
            QrRequestId([5, 6]),
            session_id,
            fixture.descriptors(),
            &psbt,
            Some(SignResponseKind::Psbt),
        )
        .unwrap();
        host.bind_outer_request(RequestId::new(9)).unwrap();
        host.accept_response(&raw_response(
            RequestId::new(9),
            QrRequestId([5, 6]),
            response::Body::Error(response::ErrorBody {
                message_type: bwk_qr_protocol::MessageType::Signing,
                error,
                message: "refused".into(),
            }),
        ))
    };
    assert!(matches!(
        refuse(&mut host, response::Error::UserDeclined),
        Err(Error::Peer(_))
    ));
    assert!(host.pending.is_none());
    assert!(host.record(&session_id).unwrap().is_some());
    assert!(matches!(
        refuse(&mut host, response::Error::MusigSession),
        Err(Error::Peer(_))
    ));
    assert!(host.record(&session_id).unwrap().is_none());
    assert!(!host
        .store
        .disk
        .lock()
        .unwrap()
        .rows
        .contains_key(&session_id));
}

#[test]
fn response_acceptance_retry_flushes_changed_ram_again() {
    let fixture = fixture();
    let store = TestStore::default();
    let disk = store.disk.clone();
    let mut host = QrMusigHost::from_store(store);
    let (session_id, _) = issue(&mut host, &fixture, 1);
    host.bind_outer_request(RequestId::new(7)).unwrap();
    let response = raw_response(
        RequestId::new(7),
        QrRequestId([1, 2]),
        response::Body::NoncesPrepared(fixture.prepared(session_id, &issuance(1))),
    );
    disk.lock().unwrap().fail = true;
    assert!(host.accept_response(&response).is_err());
    assert!(host
        .record(&session_id)
        .unwrap()
        .unwrap()
        .session_ref()
        .is_some());
    assert_eq!(disk.lock().unwrap().rows[&session_id].session_ref(), None);
    let flushes = disk.lock().unwrap().flushes;
    assert!(host.accept_response(&response).is_err());
    assert_eq!(disk.lock().unwrap().flushes, flushes + 1);
    disk.lock().unwrap().fail = false;
    assert!(host.accept_response(&response).is_ok());
    assert_eq!(
        disk.lock().unwrap().rows[&session_id].session_ref(),
        Some(fixture.secret.session_ref())
    );
}

#[test]
fn placed_nonce_matches_the_device_nonce_for_the_slot() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default());
    let session_id = issued(&mut host, &fixture, 1);
    let psbt = spend(&fixture.descriptor, &[3]);
    let bytes = host
        .sign_request(
            capabilities(),
            QrRequestId([5, 6]),
            session_id,
            fixture.descriptors(),
            &psbt,
            Some(SignResponseKind::Psbt),
        )
        .unwrap();
    let sent = Psbt::deserialize(&sent_signing(&bytes).psbt).unwrap();
    let info = &fixture.own_slots(&sent)[0];
    let secret_key = fixture.device.private_key_at(&info.signer.1).secret_bytes();
    let (_, expected) = fixture
        .secret
        .nonce(0, 0, &secret_key, &info.slot.participant.serialize())
        .unwrap();
    assert_eq!(
        musig_input_pub_nonce(
            &sent.inputs[0],
            info.slot.participant,
            info.slot.aggregate,
            info.slot.leaf_hash
        )
        .unwrap(),
        Some(expected)
    );
}
