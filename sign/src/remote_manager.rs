//! A [`SigningManager`] that is nothing but a channel pair: it turns every
//! trait call into a [`Request`] pushed onto an outbound channel and forwards
//! every [`Response`] arriving on an inbound channel to the subscriber.
//!
//! This is bwk's plugin boundary for an out-of-tree signer that cannot
//! implement a Rust trait (silent and bwk-dart both forbid Rust types
//! crossing their FFI boundary): the consumer only needs to exchange two
//! enums over two channels, on whatever thread or event loop it already has.
//!
//! # Far-end contract
//!
//! Read every [`Request`] from the receiver returned by [`RemoteManager::pair`]
//! and answer with a [`Response`] carrying the same [`RequestId`]. Push
//! [`Response::SignersChanged`] whenever the signer list changes, even
//! unprompted. Use [`Response::unsolicited_error`] for anything nobody asked
//! for. `bwk-utils`'s mock manager is a worked example of the far end.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crossbeam::channel;

use miniscript::bitcoin::bip32::DerivationPath;

use bwk_descriptor::descriptor::Descriptor;

use crate::{
    identity::{SignerId, SignerInfo},
    manager::{self, SigningManager},
    protocol::{Request, RequestId, RequestIdSource, Response},
};

/// A [`SigningManager`] backed by a channel pair rather than local key
/// material: every operation becomes a [`Request`] sent to a remote back
/// end, and every answer arrives later as a [`Response`] on the subscribed
/// channel.
///
/// `signers()` reads a local cache kept up to date by a background forwarder
/// thread from [`Response::Signers`] and [`Response::SignersChanged`]; it
/// never blocks and may be briefly stale, most notably right after
/// `subscribe` until the first `ListSigners` answer arrives. A blocking
/// `signers()` would violate the [`SigningManager`] contract, and the
/// staleness resolves itself the moment the far end answers.
pub struct RemoteManager {
    to_remote: channel::Sender<Request>,
    from_remote: Option<channel::Receiver<Response>>,
    signers: Arc<Mutex<Vec<SignerInfo>>>,
    subscriber: Arc<Mutex<Option<channel::Sender<Response>>>>,
    requests: RequestIdSource,
    polling: AtomicBool,
    forwarder: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl RemoteManager {
    pub fn new(
        to_remote: channel::Sender<Request>,
        from_remote: channel::Receiver<Response>,
    ) -> Self {
        Self {
            to_remote,
            from_remote: Some(from_remote),
            signers: Arc::new(Mutex::new(Vec::new())),
            subscriber: Arc::new(Mutex::new(None)),
            requests: RequestIdSource::new(),
            polling: AtomicBool::new(false),
            forwarder: None,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Builds a `RemoteManager` together with the two channel ends its far
    /// end answers on.
    ///
    /// bwk holds the returned `RemoteManager` and drives it through
    /// [`SigningManager`] like any other manager. The consumer holds the
    /// returned [`channel::Receiver<Request>`] and
    /// [`channel::Sender<Response>`] and answers requests however it likes.
    pub fn pair() -> (
        RemoteManager,
        channel::Receiver<Request>,
        channel::Sender<Response>,
    ) {
        let (to_remote, remote_rx) = channel::unbounded();
        let (remote_tx, from_remote) = channel::unbounded();
        (
            RemoteManager::new(to_remote, from_remote),
            remote_rx,
            remote_tx,
        )
    }

    fn require_subscriber(&self) -> Result<(), manager::Error> {
        if self.subscriber.lock().expect("poisoned").is_some() {
            Ok(())
        } else {
            Err(manager::Error::NoSubscriber)
        }
    }

    fn spawn_forwarder(&mut self) {
        if self.forwarder.is_some() {
            return;
        }
        let Some(from_remote) = self.from_remote.take() else {
            return;
        };
        let subscriber = self.subscriber.clone();
        let signers = self.signers.clone();
        let shutdown = self.shutdown.clone();
        let handle = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                match from_remote.recv_timeout(Duration::from_millis(200)) {
                    Ok(response) => {
                        match &response {
                            Response::Signers { signers: list, .. }
                            | Response::SignersChanged { signers: list } => {
                                *signers.lock().expect("poisoned") = list.clone();
                            }
                            _ => {}
                        }
                        let sender = subscriber.lock().expect("poisoned").clone();
                        if let Some(sender) = sender {
                            if sender.send(response).is_err() {
                                break;
                            }
                        }
                    }
                    Err(channel::RecvTimeoutError::Timeout) => continue,
                    Err(channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
        self.forwarder = Some(handle);
    }
}

impl SigningManager for RemoteManager {
    fn signers(&self) -> Vec<SignerInfo> {
        self.signers.lock().expect("poisoned").clone()
    }

    fn subscribe(&mut self, sender: channel::Sender<Response>) {
        *self.subscriber.lock().expect("poisoned") = Some(sender);
        self.spawn_forwarder();
        let request = self.requests.next();
        let _ = self.to_remote.send(Request::ListSigners { request });
    }

    fn set_polling(&mut self, enabled: bool) {
        if enabled {
            if !self.polling.swap(true, Ordering::SeqCst) {
                let request = self.requests.next();
                let _ = self.to_remote.send(Request::SetPolling {
                    request,
                    enabled: true,
                });
            }
        } else if self.polling.swap(false, Ordering::SeqCst) {
            let request = self.requests.next();
            let _ = self.to_remote.send(Request::SetPolling {
                request,
                enabled: false,
            });
        }
    }

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::Init {
                request,
                signer: signer.clone(),
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn info(&self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::Info {
                request,
                signer: signer.clone(),
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: DerivationPath,
        display: bool,
    ) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::GetXpub {
                request,
                signer: signer.clone(),
                path,
                display,
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::IsDescriptorRegistered {
                request,
                signer: signer.clone(),
                descriptor,
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::RegisterDescriptor {
                request,
                signer: signer.clone(),
                descriptor,
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let request = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::Sign {
                request,
                signer: signer.clone(),
                descriptor,
                psbt,
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(request)
    }

    fn raw(&self, signer: &SignerId, request: Vec<u8>) -> Result<RequestId, manager::Error> {
        self.require_subscriber()?;
        let req = self.requests.next();
        // The far end owns the signer list; an unknown id comes back as a
        // Response::Error carrying this request id.
        self.to_remote
            .send(Request::Raw {
                request: req,
                signer: signer.clone(),
                payload: request,
            })
            .map_err(|_| manager::Error::Disconnected)?;
        Ok(req)
    }
}

impl Drop for RemoteManager {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let (dead_tx, _) = channel::unbounded();
        drop(std::mem::replace(&mut self.to_remote, dead_tx));
        if let Some(handle) = self.forwarder.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        str::FromStr,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    use crossbeam::channel;

    use miniscript::bitcoin::{
        self,
        bip32::{self, DerivationPath},
        secp256k1::Secp256k1,
    };

    use bwk_descriptor::descriptor::Descriptor;

    use crate::{
        identity::{SignerId, SignerInfo, SignerState},
        manager::{self, SigningManager},
        protocol::{Request, Response},
        remote_manager::RemoteManager,
    };

    fn signer_id() -> SignerId {
        SignerId::new("remote-1")
    }

    fn signer_info(id: &str) -> SignerInfo {
        SignerInfo::new(
            SignerId::new(id),
            bip32::Fingerprint::from([0x01, 0x02, 0x03, 0x04]),
            "wallet".to_string(),
            SignerState::Ready,
        )
    }

    fn descriptor() -> Descriptor {
        let secp = Secp256k1::new();
        let xpriv = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x13; 64]).unwrap();
        let xpub = bip32::Xpub::from_priv(&secp, &xpriv);
        let s = format!("wpkh([deadbeef/84h/1h/0h]{xpub}/<0;1>/*)");
        Descriptor::from_str(&s).unwrap()
    }

    fn recv<T>(receiver: &channel::Receiver<T>) -> T {
        receiver.recv_timeout(Duration::from_secs(1)).unwrap()
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn request_reaches_the_far_end() {
        let (mut manager, far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        let request = manager.info(&signer_id()).unwrap();
        match recv(&far_requests) {
            Request::Info {
                request: req,
                signer,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, signer_id());
            }
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[test]
    fn response_reaches_the_subscriber() {
        let (mut manager, far_requests, far_responses) = RemoteManager::pair();
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        let request = manager.info(&signer_id()).unwrap();
        let _ = recv(&far_requests);
        far_responses
            .send(Response::Info {
                request,
                signer: signer_id(),
                info: Default::default(),
            })
            .unwrap();

        match recv(&rx) {
            Response::Info { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[test]
    fn every_operation_round_trips() {
        let (mut manager, far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        let id = signer_id();
        let mut ids = Vec::new();

        let request = manager.init(&id).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::Init { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Init, got {other:?}"),
        }

        let request = manager.info(&id).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::Info { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Info, got {other:?}"),
        }

        let request = manager
            .get_xpub(&id, DerivationPath::master(), false)
            .unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::GetXpub { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected GetXpub, got {other:?}"),
        }

        let request = manager.is_descriptor_registered(&id, descriptor()).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::IsDescriptorRegistered { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected IsDescriptorRegistered, got {other:?}"),
        }

        let request = manager.register_descriptor(&id, descriptor()).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::RegisterDescriptor { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected RegisterDescriptor, got {other:?}"),
        }

        let request = manager.sign(&id, descriptor(), vec![1, 2, 3]).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::Sign { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Sign, got {other:?}"),
        }

        let request = manager.raw(&id, vec![4, 5, 6]).unwrap();
        ids.push(request);
        match recv(&far_requests) {
            Request::Raw { request: req, .. } => assert_eq!(req, request),
            other => panic!("expected Raw, got {other:?}"),
        }

        manager.set_polling(true);
        match recv(&far_requests) {
            Request::SetPolling { enabled, .. } => assert!(enabled),
            other => panic!("expected SetPolling, got {other:?}"),
        }

        for pair in ids.windows(2) {
            assert!(pair[0] < pair[1]);
        }
    }

    #[test]
    fn signers_reads_the_cache() {
        let (mut manager, far_requests, far_responses) = RemoteManager::pair();
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);

        assert!(manager.signers().is_empty());

        let request = match recv(&far_requests) {
            Request::ListSigners { request } => request,
            other => panic!("expected ListSigners, got {other:?}"),
        };
        let list = vec![signer_info("a"), signer_info("b")];
        far_responses
            .send(Response::Signers {
                request,
                signers: list.clone(),
            })
            .unwrap();
        let _ = recv(&rx);

        let deadline = Instant::now() + Duration::from_secs(1);
        while manager.signers().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(manager.signers(), list);
    }

    #[test]
    fn signers_changed_updates_the_cache() {
        let (mut manager, far_requests, far_responses) = RemoteManager::pair();
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        let list = vec![signer_info("x")];
        far_responses
            .send(Response::SignersChanged {
                signers: list.clone(),
            })
            .unwrap();

        match recv(&rx) {
            Response::SignersChanged { signers } => assert_eq!(signers, list),
            other => panic!("expected SignersChanged, got {other:?}"),
        }

        let deadline = Instant::now() + Duration::from_secs(1);
        while manager.signers().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(manager.signers(), list);
    }

    #[test]
    fn unsolicited_error_is_forwarded() {
        let (mut manager, far_requests, far_responses) = RemoteManager::pair();
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        far_responses
            .send(Response::unsolicited_error("far end lost the device"))
            .unwrap();

        let response = recv(&rx);
        assert_eq!(response.request_id(), None);
        assert!(response.is_error());
    }

    #[test]
    fn unknown_signer_is_not_rejected_locally() {
        let (mut manager, far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        assert!(manager.signers().is_empty());
        let id = SignerId::new("never-seen");
        let request = manager.info(&id).unwrap();
        match recv(&far_requests) {
            Request::Info {
                request: req,
                signer,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, id);
            }
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[test]
    fn no_subscriber_errors() {
        let (mut manager, _far_requests, _far_responses) = RemoteManager::pair();
        let id = signer_id();
        assert_eq!(manager.init(&id), Err(manager::Error::NoSubscriber));
        assert_eq!(manager.info(&id), Err(manager::Error::NoSubscriber));
        assert_eq!(
            manager.get_xpub(&id, DerivationPath::master(), false),
            Err(manager::Error::NoSubscriber)
        );
        assert_eq!(
            manager.is_descriptor_registered(&id, descriptor()),
            Err(manager::Error::NoSubscriber)
        );
        assert_eq!(
            manager.register_descriptor(&id, descriptor()),
            Err(manager::Error::NoSubscriber)
        );
        assert_eq!(
            manager.sign(&id, descriptor(), vec![]),
            Err(manager::Error::NoSubscriber)
        );
        assert_eq!(manager.raw(&id, vec![]), Err(manager::Error::NoSubscriber));
    }

    #[test]
    fn disconnected_far_end_errors() {
        let (mut manager, far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        drop(far_requests);

        assert_eq!(
            manager.info(&signer_id()),
            Err(manager::Error::Disconnected)
        );
    }

    #[test]
    fn drop_joins_the_forwarder() {
        let (mut manager, _far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);

        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let handle = thread::spawn(move || {
            drop(manager);
            done_clone.store(true, Ordering::SeqCst);
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while !done.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "drop did not join in time");
            thread::sleep(Duration::from_millis(10));
        }
        handle.join().unwrap();
    }

    #[test]
    fn manager_is_send_and_sync() {
        assert_send_sync::<RemoteManager>();
        assert_send_sync::<Box<dyn SigningManager>>();
    }

    #[test]
    fn set_polling_is_idempotent() {
        let (mut manager, far_requests, _far_responses) = RemoteManager::pair();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = recv(&far_requests); // ListSigners sent by subscribe

        manager.set_polling(true);
        manager.set_polling(true);
        let _ = recv(&far_requests); // the single SetPolling request

        assert!(far_requests.try_recv().is_err());
    }
}
