use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bwk_descriptor::{
    musig::parse_musig_descriptor,
    wallet::{WalletDescriptor, WalletDescriptorExt},
};
use bwk_persist::{storage::Store, PersistError};
use bwk_psbt::musig::{set_musig_input_participants, set_musig_input_pub_nonce, MusigPubNonce};
use bwk_qr_protocol::{
    encode_response, request, response, types, RequestId as QrRequestId, Response as QrResponse,
};
use crossbeam::channel;
use miniscript::bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction::Version,
    Amount, Network, Psbt, Transaction, TxIn, TxOut,
};

use crate::{
    hot_signer::HotSigner,
    identity::SignerId,
    manager::SigningManager,
    musig::expression_slots,
    protocol::{Request, RequestId, Response},
    qr_musig_host::{QrMusigHost, QrMusigHostRecord, QrMusigHostResponse, QrMusigHostState},
    remote_manager::RemoteManager,
};

const ORDINARY_MUSIG_CAPABILITY: u32 = 1 << 3;

#[derive(Default)]
struct Disk {
    rows: BTreeMap<[u8; 32], QrMusigHostRecord>,
    fail: bool,
    flushes: usize,
}

#[derive(Default)]
struct TestStore {
    ram: BTreeMap<[u8; 32], QrMusigHostRecord>,
    disk: Arc<Mutex<Disk>>,
}

impl Store for TestStore {
    type Key = [u8; 32];
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

struct Fixture {
    descriptor: WalletDescriptor,
    fingerprint: Fingerprint,
    preparation: request::PrepareMusig,
    prepared: response::MusigPrepared,
    psbt: Psbt,
}

fn fixture() -> Fixture {
    let first = HotSigner::new_from_mnemonics(Network::Regtest,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let second = HotSigner::new_from_mnemonics(
        Network::Regtest,
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
    )
    .unwrap();
    let path = DerivationPath::from_str("m/87'/1'/0'/2").unwrap();
    let text = format!(
        "tr(musig({}/<0;1>/*,{}/<0;1>/*))",
        first.xpub(&path),
        second.xpub(&path)
    );
    let descriptor = parse_musig_descriptor(&text).unwrap();
    let definite = descriptor.single_paths().unwrap()[0].derive_at(0).unwrap();
    let infos = expression_slots(0, &definite).unwrap();
    let own = infos
        .iter()
        .find(|info| info.signer.0 == first.fingerprint())
        .unwrap();
    let key =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[3; 32]).unwrap());
    let mut nonce = [0; 66];
    nonce[..33].copy_from_slice(&key.serialize());
    nonce[33..].copy_from_slice(&key.serialize());
    let derivation = request::MusigDerivation {
        keychain: 0,
        index: 0,
    };
    let preparation = request::PrepareMusig {
        descriptor: request::Descriptor {
            alias: "fixture".into(),
            descriptor: Some(request::DescriptorBody::Bip380(text)),
            proof: None,
        },
        session_id: [1; 32],
        max_inputs: 1,
        derivations: vec![derivation],
    };
    let prepared = response::MusigPrepared {
        session_id: preparation.session_id,
        max_inputs: 1,
        nonces: vec![response::MusigNonce {
            derivation,
            input_index: 0,
            expression_index: own.expression_index as u32,
            participant: types::PublicKey(own.slot.participant.serialize()),
            aggregate: types::PublicKey(own.slot.aggregate.serialize()),
            leaf_hash: None,
            nonce,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![],
    })
    .unwrap();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: definite.script_pubkey(),
    });
    psbt.inputs[0].tap_key_origins.insert(
        own.slot.participant.x_only_public_key().0,
        (vec![], own.signer.clone()),
    );
    set_musig_input_participants(
        &mut psbt.inputs[0],
        own.agg.aggregate(),
        own.agg.participants(),
    );
    Fixture {
        descriptor,
        fingerprint: first.fingerprint(),
        preparation,
        prepared,
        psbt,
    }
}

fn prepare(host: &mut QrMusigHost<TestStore>, fixture: &Fixture) -> Vec<u8> {
    host.prepare_request(
        SignerId::new("qr"),
        response::Capabilities(response::Capabilities::MUSIG_CACHE),
        QrRequestId([1, 2]),
        &fixture.descriptor,
        fixture.fingerprint,
        fixture.preparation.clone(),
    )
    .unwrap()
}

fn prepared_response(fixture: &Fixture, outer: RequestId) -> Response {
    Response::Raw {
        request: outer,
        signer: SignerId::new("qr"),
        payload: encode_response(&QrResponse {
            id: QrRequestId([1, 2]),
            body: response::Body::MusigPrepared(fixture.prepared.clone()),
        })
        .unwrap(),
    }
}

fn prepare_complete(host: &mut QrMusigHost<TestStore>, fixture: &Fixture) {
    prepare(host, fixture);
    host.bind_outer_request(RequestId::new(7)).unwrap();
    assert!(matches!(
        host.accept_response(&prepared_response(fixture, RequestId::new(7)))
            .unwrap(),
        QrMusigHostResponse::Prepared(_)
    ));
}

#[test]
fn raw_manager_attribution_and_record_roundtrip() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default()).unwrap();
    let bytes = prepare(&mut host, &fixture);
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
    let response = prepared_response(&fixture, outer);
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
    let record = host.record(&[1; 32]).unwrap().unwrap();
    let bytes = record.encode().unwrap();
    let decoded = QrMusigHostRecord::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.state(), &QrMusigHostState::Prepared);
    let mut corrupt = bytes;
    corrupt.push(0);
    assert!(QrMusigHostRecord::decode(&corrupt).is_err());
}

#[test]
fn failed_preparation_flush_requires_successful_retry_barrier() {
    let fixture = fixture();
    let store = TestStore::default();
    let disk = store.disk.clone();
    let mut host = QrMusigHost::from_store(store).unwrap();
    disk.lock().unwrap().fail = true;
    let attempt = |host: &mut QrMusigHost<TestStore>| {
        host.prepare_request(
            SignerId::new("qr"),
            response::Capabilities(response::Capabilities::MUSIG_CACHE),
            QrRequestId([1, 2]),
            &fixture.descriptor,
            fixture.fingerprint,
            fixture.preparation.clone(),
        )
    };
    assert!(attempt(&mut host).is_err());
    assert!(disk.lock().unwrap().rows.is_empty());
    assert!(attempt(&mut host).is_err());
    assert_eq!(disk.lock().unwrap().flushes, 2);
    disk.lock().unwrap().fail = false;
    assert!(attempt(&mut host).is_ok());
    assert_eq!(disk.lock().unwrap().flushes, 3);
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Preparing
    ));
}

#[test]
fn first_sign_request_allocates_even_when_flush_fails() {
    let fixture = fixture();
    let store = TestStore::default();
    let disk = store.disk.clone();
    let mut host = QrMusigHost::from_store(store).unwrap();
    prepare_complete(&mut host, &fixture);
    let allocate = |host: &mut QrMusigHost<TestStore>, attempt_id| {
        host.allocate_sign_request(
            SignerId::new("qr"),
            response::Capabilities(response::Capabilities::MUSIG_CACHE),
            QrRequestId([3, 4]),
            [1; 32],
            attempt_id,
            &fixture.psbt,
        )
    };
    disk.lock().unwrap().fail = true;
    assert!(allocate(&mut host, [2; 32]).is_err());
    assert!(matches!(
        host.record(&[1; 32]).unwrap().unwrap().state(),
        QrMusigHostState::Allocated { .. }
    ));
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Prepared
    ));
    assert!(allocate(&mut host, [3; 32]).is_err());
    assert!(allocate(&mut host, [2; 32]).is_err());
    disk.lock().unwrap().fail = false;
    assert!(allocate(&mut host, [2; 32]).is_ok());
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Allocated { .. }
    ));
    host.cancel_pending();
    assert!(allocate(&mut host, [3; 32]).is_err());
    let restored = TestStore {
        ram: disk.lock().unwrap().rows.clone(),
        disk: disk.clone(),
    };
    let mut host = QrMusigHost::from_store(restored).unwrap();
    assert!(allocate(&mut host, [3; 32]).is_err());
    assert!(allocate(&mut host, [2; 32]).is_ok());
}

#[test]
fn generic_musig_capability_does_not_enable_cache() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default()).unwrap();
    assert!(host
        .prepare_request(
            SignerId::new("qr"),
            response::Capabilities(ORDINARY_MUSIG_CAPABILITY),
            QrRequestId([1, 2]),
            &fixture.descriptor,
            fixture.fingerprint,
            fixture.preparation
        )
        .is_err());
    assert!(host.record(&[1; 32]).unwrap().is_none());
}

fn round_one_response(fixture: &Fixture, psbt: &Psbt) -> Response {
    let mut returned = psbt.clone();
    let nonce = &fixture.prepared.nonces[0];
    set_musig_input_pub_nonce(
        &mut returned.inputs[0],
        &MusigPubNonce {
            participant: PublicKey::from_slice(&nonce.participant.0).unwrap(),
            aggregate: PublicKey::from_slice(&nonce.aggregate.0).unwrap(),
            leaf_hash: None,
            nonce: nonce.nonce,
        },
    );
    Response::Raw {
        request: RequestId::new(8),
        signer: SignerId::new("qr"),
        payload: encode_response(&QrResponse {
            id: QrRequestId([3, 4]),
            body: response::Body::MusigSigned(response::MusigSigned {
                session_id: [1; 32],
                attempt_id: [2; 32],
                psbt: returned.serialize(),
            }),
        })
        .unwrap(),
    }
}

#[test]
fn round_one_response_keeps_allocation_and_rejects_metadata_changes() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default()).unwrap();
    prepare_complete(&mut host, &fixture);
    host.allocate_sign_request(
        SignerId::new("qr"),
        response::Capabilities(response::Capabilities::MUSIG_CACHE),
        QrRequestId([3, 4]),
        [1; 32],
        [2; 32],
        &fixture.psbt,
    )
    .unwrap();
    host.bind_outer_request(RequestId::new(8)).unwrap();
    let mut modified = fixture.psbt.clone();
    modified.version = 1;
    assert!(host
        .accept_response(&round_one_response(&fixture, &modified))
        .is_err());
    let mut modified = fixture.psbt.clone();
    modified.unsigned_tx.version = Version::ONE;
    assert!(host
        .accept_response(&round_one_response(&fixture, &modified))
        .is_err());
    let response = round_one_response(&fixture, &fixture.psbt);
    assert!(matches!(
        host.accept_response(&response).unwrap(),
        QrMusigHostResponse::Signed(_)
    ));
    assert!(matches!(
        host.record(&[1; 32]).unwrap().unwrap().state(),
        QrMusigHostState::Allocated {
            transcript: None,
            ..
        }
    ));
    assert!(host.accept_response(&response).is_err());
}

#[test]
fn prepared_response_rejects_inner_id_and_incomplete_or_foreign_attribution() {
    let fixture = fixture();
    let mut host = QrMusigHost::from_store(TestStore::default()).unwrap();
    prepare(&mut host, &fixture);
    host.bind_outer_request(RequestId::new(7)).unwrap();
    let wrong_inner = Response::Raw {
        request: RequestId::new(7),
        signer: SignerId::new("qr"),
        payload: encode_response(&QrResponse {
            id: QrRequestId([9, 9]),
            body: response::Body::MusigPrepared(fixture.prepared.clone()),
        })
        .unwrap(),
    };
    assert!(host.accept_response(&wrong_inner).is_err());
    let mut foreign = fixture.prepared.clone();
    foreign.nonces[0].expression_index += 1;
    let wrong_expression = Response::Raw {
        request: RequestId::new(7),
        signer: SignerId::new("qr"),
        payload: encode_response(&QrResponse {
            id: QrRequestId([1, 2]),
            body: response::Body::MusigPrepared(foreign),
        })
        .unwrap(),
    };
    assert!(host.accept_response(&wrong_expression).is_err());
    assert!(host
        .accept_response(&Response::Signed {
            request: RequestId::new(7),
            signer: SignerId::new("qr"),
            psbt: fixture.psbt.serialize(),
        })
        .is_err());
    assert!(host
        .accept_response(&Response::error(
            RequestId::new(7),
            SignerId::new("qr"),
            "refused"
        ))
        .is_err());
    assert!(matches!(
        host.record(&[1; 32]).unwrap().unwrap().state(),
        QrMusigHostState::Preparing
    ));
    assert!(host
        .accept_response(&prepared_response(&fixture, RequestId::new(7)))
        .is_ok());
}

#[test]
fn first_complete_transcript_is_pinned_before_dispatch() {
    let fixture = fixture();
    let store = TestStore::default();
    let disk = store.disk.clone();
    let mut host = QrMusigHost::from_store(store).unwrap();
    prepare_complete(&mut host, &fixture);
    let definite = fixture.descriptor.single_paths().unwrap()[0]
        .derive_at(0)
        .unwrap();
    let infos = expression_slots(0, &definite).unwrap();
    let foreign = infos
        .iter()
        .find(|info| info.signer.0 != fixture.fingerprint)
        .unwrap();
    let nonce = fixture.prepared.nonces[0].nonce;
    let mut complete = fixture.psbt.clone();
    set_musig_input_pub_nonce(
        &mut complete.inputs[0],
        &MusigPubNonce {
            participant: foreign.slot.participant,
            aggregate: foreign.slot.aggregate,
            leaf_hash: None,
            nonce,
        },
    );
    let allocate = |host: &mut QrMusigHost<TestStore>, psbt: &Psbt| {
        host.allocate_sign_request(
            SignerId::new("qr"),
            response::Capabilities(response::Capabilities::MUSIG_CACHE),
            QrRequestId([3, 4]),
            [1; 32],
            [2; 32],
            psbt,
        )
    };
    allocate(&mut host, &complete).unwrap();
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Allocated {
            transcript: Some(_),
            ..
        }
    ));
    host.cancel_pending();
    assert!(allocate(&mut host, &fixture.psbt).is_err());
    let key =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[4; 32]).unwrap());
    let mut changed = nonce;
    changed[..33].copy_from_slice(&key.serialize());
    let mut changed_psbt = complete.clone();
    set_musig_input_pub_nonce(
        &mut changed_psbt.inputs[0],
        &MusigPubNonce {
            participant: foreign.slot.participant,
            aggregate: foreign.slot.aggregate,
            leaf_hash: None,
            nonce: changed,
        },
    );
    assert!(allocate(&mut host, &changed_psbt).is_err());
    assert!(allocate(&mut host, &complete).is_ok());
}

#[test]
fn response_acceptance_retry_flushes_changed_ram_again() {
    let fixture = fixture();
    let store = TestStore::default();
    let disk = store.disk.clone();
    let mut host = QrMusigHost::from_store(store).unwrap();
    prepare(&mut host, &fixture);
    host.bind_outer_request(RequestId::new(7)).unwrap();
    let response = prepared_response(&fixture, RequestId::new(7));
    disk.lock().unwrap().fail = true;
    assert!(host.accept_response(&response).is_err());
    assert!(matches!(
        host.record(&[1; 32]).unwrap().unwrap().state(),
        QrMusigHostState::Prepared
    ));
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Preparing
    ));
    let flushes = disk.lock().unwrap().flushes;
    assert!(host.accept_response(&response).is_err());
    assert_eq!(disk.lock().unwrap().flushes, flushes + 1);
    disk.lock().unwrap().fail = false;
    assert!(host.accept_response(&response).is_ok());
    assert!(matches!(
        disk.lock().unwrap().rows[&[1; 32]].state(),
        QrMusigHostState::Prepared
    ));
}
