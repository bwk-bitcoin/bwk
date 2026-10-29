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
use bwk_persist::{cipher::Cipher, storage::Store, PersistError};
use bwk_psbt::musig::{
    musig_input_partial_sigs, musig_input_pub_nonces, set_musig_input_pub_nonce,
};
use bwk_qr_protocol::{
    request::{
        self, Descriptor as QrDescriptor, DescriptorBody, MusigDerivation, PrepareMusig, SignMusig,
    },
    response, Message, Request as QrRequest, RequestId as QrRequestId,
};
use bwk_sign::{
    hot_musig::{HotMusigSession, HotMusigSessionBytes},
    hot_signer::HotSigner,
    identity::SignerId,
    musig::{aggregate_partial_sigs, session_id, MusigSessionId},
    protocol::{Request, RequestId, Response},
    qr_musig::{decode_record, encode_record, Error, QrMusigPeer, QrMusigPeerRecord},
};
use miniscript::bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Xpriv},
    hashes::{sha256, Hash},
    transaction::Version,
    Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

// Deterministic test cipher only. Consumers must supply authenticated encryption.
#[derive(Debug)]
struct TestCipher;

impl Cipher for TestCipher {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, PersistError> {
        let mut sealed = sha256::Hash::hash(plain).to_byte_array().to_vec();
        sealed.extend(plain.iter().map(|byte| byte ^ 0xa5));
        Ok(sealed)
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, PersistError> {
        if sealed.len() < 32 {
            return Err(PersistError::Cipher("short test ciphertext".to_string()));
        }
        let plain: Vec<_> = sealed[32..].iter().map(|byte| byte ^ 0xa5).collect();
        if sha256::Hash::hash(&plain).as_byte_array() != &sealed[..32] {
            return Err(PersistError::Cipher("corrupt test ciphertext".to_string()));
        }
        Ok(plain)
    }

    fn extension(&self) -> &str {
        "test"
    }
}

#[derive(Default)]
struct Persistence {
    committed: BTreeMap<[u8; 32], QrMusigPeerRecord>,
    flushes: usize,
    fail_at: BTreeSet<usize>,
}

struct TestStore {
    ram: BTreeMap<[u8; 32], QrMusigPeerRecord>,
    persistence: Arc<Mutex<Persistence>>,
}

impl TestStore {
    fn open(persistence: Arc<Mutex<Persistence>>) -> Self {
        let ram = persistence.lock().unwrap().committed.clone();
        Self { ram, persistence }
    }
}

impl Store for TestStore {
    type Key = [u8; 32];
    type Value = QrMusigPeerRecord;

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

struct Fixture {
    peer: QrMusigPeer<TestStore>,
    persistence: Arc<Mutex<Persistence>>,
    other: HotSigner,
    descriptor: WalletDescriptor,
    preparation: PrepareMusig,
    psbt: Psbt,
}

fn signer(seed: u8) -> HotSigner {
    HotSigner::new_from_xpriv(
        Network::Regtest,
        Xpriv::new_master(Network::Regtest, &[seed; 32]).unwrap(),
    )
}

fn fixture() -> Fixture {
    let a = signer(1);
    let b = signer(2);
    let aggregate = |role| {
        let path = DerivationPath::from_str(&format!("m/87'/1'/0'/{role}")).unwrap();
        format!("musig({},{})/<0;1>/*", a.xpub(&path), b.xpub(&path))
    };
    let text = format!("tr({},pk({}))", aggregate(2), aggregate(3));
    let descriptor = Descriptor::from_str(&text)
        .unwrap()
        .into_miniscript()
        .unwrap();
    let preparation = PrepareMusig {
        descriptor: QrDescriptor {
            alias: "peer".to_string(),
            descriptor: Some(DescriptorBody::Bip380(text)),
            proof: None,
        },
        session_id: [11; 32],
        max_inputs: 2,
        derivations: vec![
            MusigDerivation {
                keychain: 0,
                index: 3,
            },
            MusigDerivation {
                keychain: 1,
                index: 3,
            },
        ],
    };
    let psbt = spend(&descriptor, 0, &[3, 3]);
    let persistence = Arc::new(Mutex::new(Persistence::default()));
    let peer = peer(a, &persistence);
    Fixture {
        peer,
        persistence,
        other: b,
        descriptor,
        preparation,
        psbt,
    }
}

fn peer(signer: HotSigner, persistence: &Arc<Mutex<Persistence>>) -> QrMusigPeer<TestStore> {
    QrMusigPeer::from_store(
        signer,
        TestStore::open(Arc::clone(persistence)),
        Arc::new(TestCipher),
    )
}

fn spend(descriptor: &WalletDescriptor, keychain: usize, indexes: &[u32]) -> Psbt {
    let single = descriptor.single_paths().unwrap()[keychain].clone();
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: indexes
            .iter()
            .map(|_| TxIn {
                previous_output: OutPoint::null(),
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
        psbt.unsigned_tx.input[position].previous_output.vout = position as u32;
        let definite = single.derive_at(*index).unwrap();
        psbt.inputs[position].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: definite.script_pubkey(),
        });
        update_input(&mut psbt, position, &definite).unwrap();
    }
    psbt
}

fn signing(preparation: &PrepareMusig, psbt: &Psbt) -> SignMusig {
    SignMusig {
        session_id: preparation.session_id,
        attempt_id: [22; 32],
        psbt: psbt.serialize(),
    }
}

fn other_session(fixture: &Fixture) -> HotMusigSession {
    fixture
        .other
        .create_musig_session(&fixture.descriptor, MusigSessionId([33; 32]), 2)
        .unwrap()
}

fn fail_after(persistence: &Arc<Mutex<Persistence>>, after: usize) {
    let mut persistence = persistence.lock().unwrap();
    let at = persistence.flushes + after;
    persistence.fail_at.insert(at);
}

fn committed(fixture: &Fixture) -> QrMusigPeerRecord {
    fixture.persistence.lock().unwrap().committed[&fixture.preparation.session_id].clone()
}

fn assert_session_refusal(result: Result<response::MusigSigned, Error>) {
    assert!(matches!(
        result,
        Err(Error::Sign(
            bwk_sign::error::Error::MusigSession | bwk_sign::error::Error::SighashFail
        ))
    ));
}

#[test]
fn preparation_has_no_transaction_and_retries_publish_identical_nonces() {
    let mut f = fixture();
    let prepared = f.peer.prepare(f.preparation.clone()).unwrap();
    assert_eq!(prepared.session_id, [11; 32]);
    assert_eq!(prepared.max_inputs, 2);
    assert_eq!(prepared.nonces.len(), 8);
    assert_eq!(f.peer.prepare(f.preparation.clone()).unwrap(), prepared);
    let record = committed(&f);
    let QrMusigPeerRecord::Prepared {
        request,
        encrypted_export,
    } = &record
    else {
        panic!()
    };
    assert_eq!(request, &f.preparation);
    let plain = TestCipher.open(encrypted_export).unwrap();
    let encoded = encode_record(&record).unwrap();
    assert!(!encoded.windows(plain.len()).any(|window| window == plain));
    assert!(!encoded
        .windows(32)
        .any(|window| window == &plain[plain.len() - 32..]));
    let reopened = HotMusigSession::decode(
        HotMusigSessionBytes::from_bytes(plain),
        &f.descriptor,
        signer(1).fingerprint(),
    )
    .unwrap();
    assert_eq!(reopened.id().0, [11; 32]);
    let mut changed = f.preparation.clone();
    changed.max_inputs = 1;
    assert!(f.peer.prepare(changed).is_err());
    assert_eq!(committed(&f), record);
    drop(f.peer);
    f.peer = peer(signer(1), &f.persistence);
    assert_eq!(f.peer.prepare(f.preparation).unwrap(), prepared);
}

#[test]
fn advertised_nonces_match_real_partials_and_consumption_burns_the_root() {
    for keychain in [0, 1] {
        let mut f = fixture();
        f.psbt = spend(&f.descriptor, keychain, &[3, 3]);
        let prepared = f.peer.prepare(f.preparation.clone()).unwrap();
        let first = f.peer.sign(signing(&f.preparation, &f.psbt)).unwrap();
        let mut published = Psbt::deserialize(&first.psbt).unwrap();
        assert_eq!(first.attempt_id, [22; 32]);
        for (index, input) in published.inputs.iter().enumerate() {
            assert!(musig_input_partial_sigs(input).unwrap().is_empty());
            let nonces = musig_input_pub_nonces(input).unwrap();
            assert_eq!(nonces.len(), 2);
            for nonce in nonces {
                assert!(prepared.nonces.iter().any(|advertised| {
                    advertised.derivation.keychain == keychain as u32
                        && advertised.input_index == index as u32
                        && advertised.participant.0 == nonce.participant.serialize()
                        && advertised.aggregate.0 == nonce.aggregate.serialize()
                        && advertised.leaf_hash == nonce.leaf_hash.map(|hash| hash.to_byte_array())
                        && advertised.nonce == nonce.nonce
                }));
            }
        }
        assert_eq!(
            f.peer.sign(signing(&f.preparation, &f.psbt)).unwrap(),
            first
        );
        let other = other_session(&f);
        other.publish_nonces(&mut published, &f.descriptor).unwrap();
        let request = signing(&f.preparation, &published);
        let signed = f.peer.sign(request.clone()).unwrap();
        assert_eq!(committed(&f), QrMusigPeerRecord::Burned);
        let mut signed_psbt = Psbt::deserialize(&signed.psbt).unwrap();
        assert_eq!(
            musig_input_partial_sigs(&signed_psbt.inputs[0])
                .unwrap()
                .len(),
            2
        );
        f.other
            .sign_musig_session(&mut signed_psbt, &f.descriptor, other)
            .unwrap();
        assert_eq!(
            aggregate_partial_sigs(&mut signed_psbt, &f.descriptor).unwrap(),
            4
        );
        assert_session_refusal(f.peer.sign(request.clone()));
        assert!(f.peer.prepare(f.preparation.clone()).is_err());
        drop(f.peer);
        f.peer = peer(signer(1), &f.persistence);
        assert_session_refusal(f.peer.sign(request));
        assert!(f.peer.prepare(f.preparation).is_err());
    }
}

#[test]
fn allocation_rejects_attempt_transaction_sighash_and_slot_changes() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    f.peer.sign(signing(&f.preparation, &f.psbt)).unwrap();
    let allocated = committed(&f);
    let mut attempt = signing(&f.preparation, &f.psbt);
    attempt.attempt_id = [23; 32];
    assert_session_refusal(f.peer.sign(attempt));
    let mut changed_tx = f.psbt.clone();
    changed_tx.unsigned_tx.output[0].value = Amount::from_sat(149_999);
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &changed_tx)));
    let mut changed_sighash = f.psbt.clone();
    changed_sighash.inputs[0].sighash_type =
        Some(miniscript::bitcoin::sighash::TapSighashType::All.into());
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &changed_sighash)));
    let mut changed_slots = f.psbt.clone();
    changed_slots.inputs[0].tap_scripts.clear();
    let fingerprint = signer(1).fingerprint();
    assert_eq!(
        session_id(&f.psbt, &f.descriptor, fingerprint).unwrap(),
        session_id(&changed_slots, &f.descriptor, fingerprint).unwrap()
    );
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &changed_slots)));
    assert_eq!(committed(&f), allocated);
}

#[test]
fn missing_session_and_unadvertised_derivation_never_sign() {
    let mut f = fixture();
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &f.psbt)));
    f.peer.prepare(f.preparation.clone()).unwrap();
    let outside = spend(&f.descriptor, 0, &[4]);
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &outside)));
    let mut lost_peer = peer(signer(1), &Arc::new(Mutex::new(Persistence::default())));
    assert_session_refusal(lost_peer.sign(signing(&f.preparation, &f.psbt)));
}

#[test]
fn own_nonce_substitution_refuses_without_burning() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let first = f.peer.sign(signing(&f.preparation, &f.psbt)).unwrap();
    let mut published = Psbt::deserialize(&first.psbt).unwrap();
    let fresh = signer(1)
        .create_musig_session(&f.descriptor, MusigSessionId([44; 32]), 2)
        .unwrap();
    let replacement = fresh.public_nonces(&f.descriptor, 0, 3).unwrap().remove(0);
    set_musig_input_pub_nonce(&mut published.inputs[0], &replacement.nonce);
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &published)));
    assert!(matches!(
        committed(&f),
        QrMusigPeerRecord::Allocated {
            transcript: None,
            ..
        }
    ));
}

#[test]
fn preparation_failure_retries_flush_existing_root_before_publication() {
    let mut f = fixture();
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.prepare(f.preparation.clone()),
        Err(Error::Persist(_))
    ));
    assert!(f.persistence.lock().unwrap().committed.is_empty());
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.prepare(f.preparation.clone()),
        Err(Error::Persist(_))
    ));
    let prepared = f.peer.prepare(f.preparation.clone()).unwrap();
    assert_eq!(f.persistence.lock().unwrap().flushes, 3);
    let record = committed(&f);
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.prepare(f.preparation.clone()),
        Err(Error::Persist(_))
    ));
    assert_eq!(committed(&f), record);
    assert_eq!(f.peer.prepare(f.preparation).unwrap(), prepared);
}

#[test]
fn allocation_failure_retries_flush_and_cannot_change_attempt() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    fail_after(&f.persistence, 1);
    let request = signing(&f.preparation, &f.psbt);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    assert!(matches!(committed(&f), QrMusigPeerRecord::Prepared { .. }));
    let mut changed = request.clone();
    changed.attempt_id = [99; 32];
    assert_session_refusal(f.peer.sign(changed));
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    let published = f.peer.sign(request.clone()).unwrap();
    assert!(matches!(committed(&f), QrMusigPeerRecord::Allocated { .. }));
    assert_eq!(f.peer.sign(request.clone()).unwrap(), published);
    drop(f.peer);
    f.peer = peer(signer(1), &f.persistence);
    assert_eq!(f.peer.sign(request).unwrap(), published);
}

#[test]
fn failed_publication_barrier_is_required_again_for_identical_round_one() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let request = signing(&f.preparation, &f.psbt);
    fail_after(&f.persistence, 2);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    fail_after(&f.persistence, 1);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    let published = f.peer.sign(request.clone()).unwrap();
    assert_eq!(f.peer.sign(request).unwrap(), published);
}

#[test]
fn complete_transcript_is_pinned_in_keyagg_order_across_flush_failure() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let other = other_session(&f);
    other.publish_nonces(&mut f.psbt, &f.descriptor).unwrap();
    let request = signing(&f.preparation, &f.psbt);
    fail_after(&f.persistence, 2);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    let replacement = f
        .other
        .create_musig_session(&f.descriptor, MusigSessionId([55; 32]), 2)
        .unwrap();
    let nonce = replacement
        .public_nonces(&f.descriptor, 0, 3)
        .unwrap()
        .remove(0);
    let mut changed = f.psbt.clone();
    set_musig_input_pub_nonce(&mut changed.inputs[0], &nonce.nonce);
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &changed)));
    let incomplete = spend(&f.descriptor, 0, &[3, 3]);
    assert_session_refusal(f.peer.sign(signing(&f.preparation, &incomplete)));
    assert!(matches!(
        committed(&f),
        QrMusigPeerRecord::Allocated {
            transcript: Some(_),
            ..
        }
    ));
    drop(f.peer);
    f.peer = peer(signer(1), &f.persistence);
    f.peer.sign(request).unwrap();
    assert_eq!(committed(&f), QrMusigPeerRecord::Burned);
}

#[test]
fn burn_flush_failure_drops_root_and_refuses_every_signing_retry() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let other = other_session(&f);
    other.publish_nonces(&mut f.psbt, &f.descriptor).unwrap();
    let request = signing(&f.preparation, &f.psbt);
    fail_after(&f.persistence, 3);
    assert!(matches!(
        f.peer.sign(request.clone()),
        Err(Error::Persist(_))
    ));
    assert!(matches!(
        committed(&f),
        QrMusigPeerRecord::Allocated {
            transcript: Some(_),
            ..
        }
    ));
    assert_session_refusal(f.peer.sign(request.clone()));
    assert_eq!(committed(&f), QrMusigPeerRecord::Burned);
    assert_session_refusal(f.peer.sign(request.clone()));
    assert!(f.peer.prepare(f.preparation.clone()).is_err());
    drop(f.peer);
    f.peer = peer(signer(1), &f.persistence);
    assert_session_refusal(f.peer.sign(request));
    assert!(f.peer.prepare(f.preparation).is_err());
}

#[test]
fn cryptographic_failure_after_burn_never_restores_the_export() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let other = other_session(&f);
    other.publish_nonces(&mut f.psbt, &f.descriptor).unwrap();
    let mut nonce = other
        .public_nonces(&f.descriptor, 0, 3)
        .unwrap()
        .remove(0)
        .nonce;
    nonce.nonce = [0xff; 66];
    set_musig_input_pub_nonce(&mut f.psbt.inputs[0], &nonce);
    let request = signing(&f.preparation, &f.psbt);
    assert!(f.peer.sign(request.clone()).is_err());
    assert_eq!(committed(&f), QrMusigPeerRecord::Burned);
    assert_session_refusal(f.peer.sign(request));
}

#[test]
fn record_codec_roundtrips_each_state_and_rejects_truncation_and_trailing_bytes() {
    let mut f = fixture();
    f.peer.prepare(f.preparation.clone()).unwrap();
    let prepared = committed(&f);
    f.peer.sign(signing(&f.preparation, &f.psbt)).unwrap();
    let allocated = committed(&f);
    let mut pinned = allocated.clone();
    if let QrMusigPeerRecord::Allocated { transcript, .. } = &mut pinned {
        *transcript = Some([0x77; 32]);
    }
    for record in [prepared, allocated, pinned, QrMusigPeerRecord::Burned] {
        let bytes = encode_record(&record).unwrap();
        assert_eq!(decode_record(&bytes).unwrap(), record);
        for len in 0..bytes.len() {
            assert!(decode_record(&bytes[..len]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_record(&trailing).is_err());
    }
}

#[test]
fn raw_handler_preserves_both_request_ids_and_signer_and_reports_errors() {
    let mut f = fixture();
    let inner = QrRequest {
        id: QrRequestId([7, 9]),
        body: request::Body::PrepareMusig(f.preparation.clone()),
    };
    let signer = SignerId::new("qr-peer");
    let request = RequestId::new(76);
    let raw = Request::Raw {
        request,
        signer: signer.clone(),
        payload: bwk_qr_protocol::encode_request(&inner).unwrap(),
    };
    let response = f.peer.handle_remote(raw);
    let Response::Raw {
        request: returned,
        signer: returned_signer,
        payload,
    } = response
    else {
        panic!()
    };
    assert_eq!(returned, request);
    assert_eq!(returned_signer, signer);
    let Message::Response(response) = bwk_qr_protocol::decode(&payload).unwrap() else {
        panic!()
    };
    assert_eq!(response.id, inner.id);
    assert!(matches!(response.body, response::Body::MusigPrepared(_)));
    let qr_sign = QrRequest {
        id: QrRequestId([8, 0]),
        body: request::Body::SignMusig(signing(&f.preparation, &f.psbt)),
    };
    let signed = f.peer.handle_remote(Request::Raw {
        request: RequestId::new(77),
        signer: signer.clone(),
        payload: bwk_qr_protocol::encode_request(&qr_sign).unwrap(),
    });
    let Response::Raw {
        request: sign_id,
        signer: who,
        payload,
    } = signed
    else {
        panic!()
    };
    assert_eq!(sign_id, RequestId::new(77));
    assert_eq!(who, signer);
    let Message::Response(signed) = bwk_qr_protocol::decode(&payload).unwrap() else {
        panic!()
    };
    assert_eq!(signed.id, qr_sign.id);
    let response::Body::MusigSigned(signed) = signed.body else {
        panic!()
    };
    assert_eq!(signed.session_id, [11; 32]);
    assert_eq!(signed.attempt_id, [22; 32]);
    let refused = f.peer.handle(QrRequest {
        id: inner.id,
        body: request::Body::SignMusig(SignMusig {
            session_id: [0; 32],
            attempt_id: [0; 32],
            psbt: f.psbt.serialize(),
        }),
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
    assert_eq!(unsupported_inner.id, inner.id);
    assert!(matches!(
        unsupported_inner.body,
        response::Body::Error(response::ErrorBody {
            error: response::Error::MalformedRequest,
            ..
        })
    ));
    let malformed = f.peer.handle_remote(Request::Raw {
        request,
        signer: signer.clone(),
        payload: vec![0],
    });
    assert!(matches!(
        malformed,
        Response::Error { request: Some(id), signer: Some(who), .. }
            if id == request && who == signer
    ));
    let unsupported = f.peer.handle_remote(Request::Info { request, signer });
    assert!(matches!(unsupported, Response::Error { request: Some(id), .. } if id == request));
}
