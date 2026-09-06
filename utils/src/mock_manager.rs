//! Mock far end for `bwk_sign::remote_manager::RemoteManager`.
//!
//! This is the reference implementation of the far end of the remote signing
//! protocol: silent and bwk-dart both need to speak the same protocol from
//! C++ and Dart, and neither can implement a Rust trait across its FFI
//! boundary, so both will port this exact request/response loop rather than
//! design their own. It signs with a real `HotSigner`, so every
//! `Response::Signed` it returns carries a signature that is valid on chain,
//! not a placeholder. It is also what bwk's own regtest end-to-end tests sign
//! with, in place of a hardware wallet or a plugin.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crossbeam::channel;

use bwk_sign::{
    hot_signer::HotSigner,
    identity::{SignerId, SignerInfo, SignerState},
    protocol::{Request, Response},
    remote_manager::RemoteManager,
};

/// Handle to the background thread answering the remote signing protocol on
/// behalf of a set of real [`HotSigner`]s. Dropping it stops the thread.
pub struct MockRemote {
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    fail_next: Arc<Mutex<Option<String>>>,
}

impl MockRemote {
    /// Makes the next request answer with a `Response::Error` carrying that
    /// request's id, regardless of what it asked for. The fault-injection
    /// hook the negative tests need.
    pub fn fail_next(&self, message: impl Into<String>) {
        *self.fail_next.lock().expect("poisoned") = Some(message.into());
    }
}

impl Drop for MockRemote {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawns a mock far end backed by one real [`HotSigner`] per mnemonic and
/// returns the [`RemoteManager`] paired with it. Two entries built from the
/// same mnemonic get distinct [`SignerId`]s sharing one fingerprint, the same
/// way two hardware devices holding the same seed would.
pub fn spawn(network: bitcoin::Network, mnemonics: &[&str]) -> (RemoteManager, MockRemote) {
    let (manager, requests, responses) = RemoteManager::pair();

    let signers: BTreeMap<SignerId, HotSigner> = mnemonics
        .iter()
        .enumerate()
        .map(|(n, mnemonic)| {
            let signer = HotSigner::new_from_mnemonics(network, mnemonic).expect("valid mnemonic");
            let id = SignerId::new(format!("mock:{}:{n}", signer.fingerprint()));
            (id, signer)
        })
        .collect();

    let shutdown = Arc::new(AtomicBool::new(false));
    let fail_next = Arc::new(Mutex::new(None));

    let handle = {
        let shutdown = shutdown.clone();
        let fail_next = fail_next.clone();
        thread::spawn(move || responder_loop(signers, requests, responses, shutdown, fail_next))
    };

    (
        manager,
        MockRemote {
            handle: Some(handle),
            shutdown,
            fail_next,
        },
    )
}

fn responder_loop(
    mut signers: BTreeMap<SignerId, HotSigner>,
    requests: channel::Receiver<Request>,
    responses: channel::Sender<Response>,
    shutdown: Arc<AtomicBool>,
    fail_next: Arc<Mutex<Option<String>>>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        let request = match requests.recv_timeout(Duration::from_millis(200)) {
            Ok(request) => request,
            Err(channel::RecvTimeoutError::Timeout) => continue,
            Err(channel::RecvTimeoutError::Disconnected) => break,
        };

        let response = match fail_next.lock().expect("poisoned").take() {
            Some(message) => Response::Error {
                request: Some(request.request_id()),
                signer: request.signer().cloned(),
                message,
            },
            None => handle_request(&mut signers, request),
        };

        if responses.send(response).is_err() {
            break;
        }
    }
}

fn signer_infos(signers: &BTreeMap<SignerId, HotSigner>) -> Vec<SignerInfo> {
    signers
        .iter()
        .map(|(id, hot)| {
            SignerInfo::new(
                id.clone(),
                hot.fingerprint(),
                id.to_string(),
                SignerState::Ready,
            )
        })
        .collect()
}

fn handle_request(signers: &mut BTreeMap<SignerId, HotSigner>, request: Request) -> Response {
    match request {
        Request::ListSigners { request } => Response::Signers {
            request,
            signers: signer_infos(signers),
        },
        Request::SetPolling { .. } => Response::SignersChanged {
            signers: signer_infos(signers),
        },
        Request::Init { request, signer } => Response::Initialized { request, signer },
        Request::Info { request, signer } => {
            let Some(hot) = signers.get(&signer) else {
                return Response::error(request, signer, "unknown signer");
            };
            let info = BTreeMap::from([
                ("kind".to_string(), "mock".to_string()),
                ("fingerprint".to_string(), hot.fingerprint().to_string()),
            ]);
            Response::Info {
                request,
                signer,
                info,
            }
        }
        Request::GetXpub {
            request,
            signer,
            path,
            ..
        } => {
            let Some(hot) = signers.get(&signer) else {
                return Response::error(request, signer, "unknown signer");
            };
            Response::Xpub {
                request,
                signer,
                xpub: hot.xpub(&path),
            }
        }
        Request::IsDescriptorRegistered {
            request,
            signer,
            descriptor,
        } => {
            let Some(hot) = signers.get(&signer) else {
                return Response::error(request, signer, "unknown signer");
            };
            let registered = hot.descriptors().contains(&descriptor);
            Response::DescriptorIsRegistered {
                request,
                signer,
                registered,
            }
        }
        Request::RegisterDescriptor {
            request,
            signer,
            descriptor,
        } => {
            let Some(hot) = signers.get_mut(&signer) else {
                return Response::error(request, signer, "unknown signer");
            };
            if descriptor.is_sp() {
                return Response::error(request, signer, "sp() descriptors are not signable yet");
            }
            hot.inner_register_descriptor(descriptor);
            Response::DescriptorRegistered {
                request,
                signer,
                registered: true,
            }
        }
        Request::Sign {
            request,
            signer,
            descriptor,
            psbt,
        } => {
            let Some(hot) = signers.get(&signer) else {
                return Response::error(request, signer, "unknown signer");
            };
            let Ok(mut psbt) = bitcoin::Psbt::deserialize(&psbt) else {
                return Response::error(request, signer, "psbt is not deserializable");
            };
            let Some(inner) = descriptor.as_miniscript() else {
                return Response::error(request, signer, "sp() descriptors are not signable yet");
            };
            match hot.inner_sign(&mut psbt, inner) {
                Ok(()) => Response::Signed {
                    request,
                    signer,
                    psbt: psbt.serialize(),
                },
                Err(e) => Response::error(request, signer, e.to_string()),
            }
        }
        Request::Raw {
            request,
            signer,
            payload,
        } => Response::Raw {
            request,
            signer,
            payload,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        str::FromStr,
        time::{Duration, Instant},
    };

    use crossbeam::channel;

    use bwk_sign::{
        bwk_descriptor::{
            derivator::SpkDerivator,
            descriptor::{wpkh, Descriptor},
            sp_descriptor::SpDescriptor,
        },
        hot_signer::HotSigner,
        identity::{SignerId, SignerState},
        manager::SigningManager,
        miniscript::{bitcoin::bip32::DerivationPath, psbt::PsbtExt},
        protocol::{RequestId, Response},
        remote_manager::RemoteManager,
    };

    use crate::{
        mock_manager::spawn,
        test::{funding_tx, random_output},
    };

    const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MNEMONIC_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn recv(rx: &channel::Receiver<Response>) -> Response {
        rx.recv_timeout(Duration::from_secs(2)).unwrap()
    }

    fn subscribe(manager: &mut RemoteManager) -> channel::Receiver<Response> {
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        rx
    }

    #[test]
    fn lists_its_signers() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A, MNEMONIC_B]);
        let rx = subscribe(&mut manager);

        let signers = match recv(&rx) {
            Response::Signers { signers, .. } => signers,
            other => panic!("expected Signers, got {other:?}"),
        };
        assert_eq!(signers.len(), 2);
        assert!(signers.iter().all(|s| s.state == SignerState::Ready));

        let ids: BTreeSet<_> = signers.iter().map(|s| s.id.clone()).collect();
        assert_eq!(ids.len(), 2);
        let fingerprints: BTreeSet<_> = signers.iter().map(|s| s.fingerprint).collect();
        assert_eq!(fingerprints.len(), 2);
    }

    #[test]
    fn two_signers_one_mnemonic() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A, MNEMONIC_A]);
        let rx = subscribe(&mut manager);

        let signers = match recv(&rx) {
            Response::Signers { signers, .. } => signers,
            other => panic!("expected Signers, got {other:?}"),
        };
        assert_eq!(signers.len(), 2);
        let ids: BTreeSet<_> = signers.iter().map(|s| s.id.clone()).collect();
        assert_eq!(ids.len(), 2);
        assert_eq!(signers[0].fingerprint, signers[1].fingerprint);
    }

    fn first_signer(rx: &channel::Receiver<Response>) -> SignerId {
        match recv(rx) {
            Response::Signers { signers, .. } => signers[0].id.clone(),
            other => panic!("expected Signers, got {other:?}"),
        }
    }

    /// The BIP84 account path `m/84'/1'/0'`: `wpkh` takes the account-level
    /// xpub and derives the `<0;1>/*` receive/change branches itself.
    fn account_path() -> DerivationPath {
        DerivationPath::from_str("m/84'/1'/0'").unwrap()
    }

    fn wpkh_descriptor(hot: &HotSigner) -> Descriptor {
        wpkh(hot.xpub(&account_path())).into()
    }

    #[test]
    fn registers_a_descriptor() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let signer = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC_A).unwrap();
        let descriptor = wpkh_descriptor(&signer);

        let request = manager
            .register_descriptor(&id, descriptor.clone())
            .unwrap();
        match recv(&rx) {
            Response::DescriptorRegistered {
                request: req,
                registered,
                ..
            } => {
                assert_eq!(req, request);
                assert!(registered);
            }
            other => panic!("expected DescriptorRegistered, got {other:?}"),
        }

        let request = manager
            .is_descriptor_registered(&id, descriptor.clone())
            .unwrap();
        match recv(&rx) {
            Response::DescriptorIsRegistered {
                request: req,
                registered,
                ..
            } => {
                assert_eq!(req, request);
                assert!(registered);
            }
            other => panic!("expected DescriptorIsRegistered, got {other:?}"),
        }
    }

    /// Registers a `wpkh` descriptor, funds one of its addresses, spends it
    /// through the mock and returns the signed (not finalized) PSBT.
    fn sign_test_psbt() -> bitcoin::Psbt {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let signer = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC_A).unwrap();
        let descriptor = wpkh_descriptor(&signer);
        manager
            .register_descriptor(&id, descriptor.clone())
            .unwrap();
        let _ = recv(&rx);

        let derivator = SpkDerivator::new(
            descriptor.as_miniscript().unwrap().clone(),
            bitcoin::Network::Regtest,
        )
        .unwrap();
        let spk = derivator.receive_spk_at(0);
        let deriv_path = DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap();
        let pubkey = signer.public_key_at(&deriv_path);

        let funding = funding_tx(spk.clone(), 1.0);
        let vout = funding
            .output
            .iter()
            .position(|o| o.script_pubkey == spk)
            .unwrap();
        let outpoint = bitcoin::OutPoint::new(funding.compute_txid(), vout as u32);

        // A single input: `PsbtExt::finalize_inp_mut` still runs a full
        // interpreter check that needs every input's prevout, so extra
        // unsigned inputs (as `spending_tx` would add) would make even the
        // one we did sign fail to finalize.
        let spend = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ZERO,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![random_output()],
        };
        let mut psbt = bitcoin::Psbt::from_unsigned_tx(spend).unwrap();
        psbt.inputs[0].witness_utxo = Some(funding.output[vout].clone());
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), deriv_path));

        let request = manager.sign(&id, descriptor, psbt.serialize()).unwrap();
        match recv(&rx) {
            Response::Signed {
                request: req, psbt, ..
            } => {
                assert_eq!(req, request);
                bitcoin::Psbt::deserialize(&psbt).unwrap()
            }
            other => panic!("expected Signed, got {other:?}"),
        }
    }

    #[test]
    fn signs_a_real_psbt() {
        let psbt = sign_test_psbt();
        assert!(!psbt.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn signature_is_valid() {
        let mut psbt = sign_test_psbt();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        PsbtExt::finalize_inp_mut(&mut psbt, &secp, 0).unwrap();
    }

    #[test]
    fn unknown_signer_answers_with_an_error() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let _ = recv(&rx);

        let unknown = SignerId::new("mock:deadbeef:99");
        let request = manager.info(&unknown).unwrap();
        match recv(&rx) {
            Response::Error {
                request: req,
                signer,
                ..
            } => {
                assert_eq!(req, Some(request));
                assert_eq!(signer, Some(unknown));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn bad_psbt_answers_with_an_error() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let signer = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC_A).unwrap();
        let descriptor = wpkh_descriptor(&signer);

        let request = manager.sign(&id, descriptor, vec![0xff; 8]).unwrap();
        match recv(&rx) {
            Response::Error { request: req, .. } => assert_eq!(req, Some(request)),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn sp_descriptor_answers_with_an_error() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let scan =
            bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[0x09; 64]).unwrap();
        let spend =
            bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Regtest, &[0x0a; 64]).unwrap();
        let spend_xpub = bitcoin::bip32::Xpub::from_priv(&secp, &spend);
        let descriptor: Descriptor = SpDescriptor::from_str(&format!(
            "sp([deadbeef/352h/1h/0h]{scan}/0h,{spend_xpub}/0h)"
        ))
        .unwrap()
        .into();

        let request = manager.register_descriptor(&id, descriptor).unwrap();
        match recv(&rx) {
            Response::Error { request: req, .. } => assert_eq!(req, Some(request)),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn every_request_gets_exactly_one_response() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let signer = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC_A).unwrap();
        let descriptor = wpkh_descriptor(&signer);

        let ids: Vec<RequestId> = vec![
            manager.init(&id).unwrap(),
            manager.info(&id).unwrap(),
            manager
                .get_xpub(&id, DerivationPath::master(), false)
                .unwrap(),
            manager
                .register_descriptor(&id, descriptor.clone())
                .unwrap(),
            manager
                .is_descriptor_registered(&id, descriptor.clone())
                .unwrap(),
            manager.sign(&id, descriptor, vec![0xff; 8]).unwrap(),
            manager.raw(&id, vec![1, 2, 3]).unwrap(),
        ];

        let mut seen = BTreeSet::new();
        for _ in 0..ids.len() {
            let response = recv(&rx);
            let req = response.request_id().unwrap();
            assert!(seen.insert(req), "request id {req} answered twice");
        }
        for id in &ids {
            assert!(seen.contains(id), "request id {id} never answered");
        }
        assert_eq!(seen.len(), ids.len());
    }

    #[test]
    fn fail_next_injects_one_error() {
        let (mut manager, mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        mock.fail_next("boom");
        let request = manager.info(&id).unwrap();
        match recv(&rx) {
            Response::Error {
                request: req,
                message,
                ..
            } => {
                assert_eq!(req, Some(request));
                assert_eq!(message, "boom");
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let request = manager.info(&id).unwrap();
        match recv(&rx) {
            Response::Info { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[test]
    fn raw_echoes_the_payload() {
        let (mut manager, _mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let rx = subscribe(&mut manager);
        let id = first_signer(&rx);

        let request = manager.raw(&id, vec![1, 2, 3]).unwrap();
        match recv(&rx) {
            Response::Raw {
                request: req,
                payload,
                ..
            } => {
                assert_eq!(req, request);
                assert_eq!(payload, vec![1, 2, 3]);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn drop_stops_the_responder() {
        let (mut manager, mock) = spawn(bitcoin::Network::Regtest, &[MNEMONIC_A]);
        let _rx = subscribe(&mut manager);

        let start = Instant::now();
        drop(mock);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
