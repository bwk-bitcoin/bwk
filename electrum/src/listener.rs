//! The scan loop: what an [`ElectrumScanner`](crate::scanner::ElectrumScanner)
//! does with one Electrum connection.
//!
//! It subscribes to the watched scripthashes, folds every status, history and
//! transaction the server reports into the coin store, and grows the watch
//! window as the address store moves its tip. It records reported confirmation
//! heights as pending claims and stops there: nothing here reads a header,
//! verifies a proof or promotes a claim. That is the reconciler's half, and it
//! runs against the validated chain over its own connection.

use std::{
    collections::BTreeMap,
    ops::ControlFlow,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
};

use bwk_backoff::Backoff;
use bwk_descriptor::derivator::SpkDerivator;
use bwk_persist::storage::Store;
use miniscript::bitcoin::{ScriptBuf, Txid};

use crate::{
    address_store::AddressTip,
    client::{CoinRequest, CoinResponse},
    coin_store::CoinStore,
    fanout::Fanout,
    notification::{Notification, TxListenerNotif},
    profile::ScanProfile,
    tx_listener,
    worker::IDLE_BACKOFF_MS,
};

/// Keychain discriminants stored in the statuses value `(status, keychain,
/// index)`, shared by the writer here and the reader
/// (`ElectrumScanner::from_stores`).
pub const STATUS_KEYCHAIN_RECEIVE: u32 = 0;
pub const STATUS_KEYCHAIN_CHANGE: u32 = 1;

/// Woken after each batch of scanned state the listener folded, so every
/// reconciler on this scanner runs its pass without polling the stores.
pub type ScanListeners = Arc<Fanout<()>>;

// On a dead channel the listener bails out and hands `$statuses` back to the
// caller (so a later restart can reuse it), mirroring the normal return paths.
macro_rules! send_notif {
    ($notification:expr, $request:expr, $statuses:expr, $msg:expr) => {
        let res = $notification.send($msg.into());
        if res.is_err() {
            // stop detached client
            let _ = $request.send(CoinRequest::Stop);
            return $statuses;
        }
    };
}

macro_rules! send_electrum {
    ($request:expr, $notification:expr, $statuses:expr, $msg:expr) => {
        if $request.send($msg).is_err() {
            send_notif!($notification, $request, $statuses, TxListenerNotif::Stopped);
            return $statuses;
        }
    };
}

/// Drive one Electrum connection until `stop_request` is set or the connection
/// dies, folding everything the server reports into `coin_store`. Returns the
/// statuses store so the next listener can reuse it.
#[allow(clippy::too_many_arguments)]
pub fn listen_txs<P>(
    coin_store: Arc<Mutex<CoinStore<P>>>,
    derivator: SpkDerivator,
    notification: mpsc::Sender<Notification>,
    address_tip: mpsc::Receiver<AddressTip>,
    stop_request: Arc<AtomicBool>,
    request: mpsc::Sender<CoinRequest>,
    response: mpsc::Receiver<CoinResponse>,
    mut statuses: P::StatusesStore,
    scan_listeners: ScanListeners,
) -> P::StatusesStore
where
    P: ScanProfile,
{
    log::info!("listen_txs(): started");
    send_notif!(notification, request, statuses, TxListenerNotif::Started);

    let initial_keys: Vec<ScriptBuf> = match statuses.keys() {
        Ok(it) => it.collect(),
        Err(e) => {
            log::error!("listen_txs(): statuses keys: {e}");
            Vec::new()
        }
    };
    if !initial_keys.is_empty() {
        send_electrum!(
            request,
            notification,
            statuses,
            CoinRequest::Subscribe(initial_keys)
        );
    }

    refresh_unconfirmed_history(&coin_store, &request);

    let mut backoff = Backoff::new_ms(IDLE_BACKOFF_MS);
    loop {
        // stop request from consumer side
        if stop_request.load(Ordering::Relaxed) {
            send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
            let _ = request.send(CoinRequest::Stop);
            return statuses;
        }

        let mut received = false;

        // listen for AddressTip update
        match address_tip.try_recv() {
            Ok(tip) => {
                log::debug!("listen_txs() receive {tip:?}");
                received = true;
                if handle_address_tip::<P>(tip, &derivator, &mut statuses, &request, &notification)
                    .is_break()
                {
                    return statuses;
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    log::error!("listen_txs(): address store disconnected");
                    send_notif!(
                        notification,
                        request,
                        statuses,
                        TxListenerNotif::Error(tx_listener::Error::AddressStoreDisconnected)
                    );
                    // FIXME: what should we do there?
                    // it's AddressStore being dropped, but she should keep upating
                    // the actual spk set even if it cannot grow anymore
                }
            },
        }

        // listen for response
        match response.try_recv() {
            Ok(rsp) => {
                log::debug!("listen_txs() receive {}", rsp.summary());
                received = true;
                match rsp {
                    CoinResponse::Status(elct_status) => {
                        if handle_status_response(
                            elct_status,
                            &mut statuses,
                            &coin_store,
                            &request,
                            &notification,
                        )
                        .is_break()
                        {
                            return statuses;
                        }
                        scan_listeners.notify(());
                    }
                    CoinResponse::History(map) => {
                        if handle_history_response_msg(map, &coin_store, &request, &notification)
                            .is_break()
                        {
                            return statuses;
                        }
                        scan_listeners.notify(());
                    }
                    CoinResponse::Txs(txs) => {
                        coin_store
                            .lock()
                            .expect("poisoned")
                            .handle_txs_response(txs);
                        scan_listeners.notify(());
                    }
                    CoinResponse::TxMerkle { txid, height, .. } => {
                        // Proof fetching rides the validator's own connection;
                        // nothing here ever asks for one.
                        log::warn!("listen_txs(): unsolicited TxMerkle for {txid}@{height}");
                    }
                    CoinResponse::Stopped => {
                        send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                        let _ = request.send(CoinRequest::Stop);
                        return statuses;
                    }
                    CoinResponse::Error(e) => {
                        send_notif!(
                            notification,
                            request,
                            statuses,
                            TxListenerNotif::Error(e.into())
                        );
                    }
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    // NOTE: here the electrum client is dropped, we cannot continue
                    log::error!("listen_txs() electrum client stopped unexpectedly");
                    send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                    let _ = request.send(CoinRequest::Stop);
                    return statuses;
                }
            },
        }

        if received {
            continue;
        }
        backoff.snooze();
    }
}

fn flush_statuses<S: Store>(statuses: &mut S) {
    if let Err(e) = statuses.flush() {
        log::error!("listen_txs(): statuses flush: {e}");
    }
}

/// Replicate the `send_electrum!`/`send_notif!` failure path: tell the consumer
/// the listener stopped, and if even that fails, ask the client to stop. Returns
/// `Break` so the caller can end the listener thread.
fn signal_stopped(
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    if notification.send(TxListenerNotif::Stopped.into()).is_err() {
        let _ = request.send(CoinRequest::Stop);
    }
    ControlFlow::Break(())
}

/// Grow the watched spk set for an `AddressTip`: register the new receive/change
/// gaps in `statuses`, then subscribe to them. `Break` ends the listener thread.
fn handle_address_tip<P: ScanProfile>(
    tip: AddressTip,
    derivator: &SpkDerivator,
    statuses: &mut P::StatusesStore,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let AddressTip { recv, change } = tip;
    let mut sub = vec![];
    // `recv` is the tip the loop below stops before, so the highest index it
    // ever inserts is `recv - 1`. Testing `recv` itself never matches and the
    // rescan runs on every tip.
    let r_spk = derivator.receive_at(recv.saturating_sub(1)).script_pubkey();
    if !statuses.contains_key(&r_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..recv {
            let spk = derivator.receive_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_RECEIVE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    let c_spk = derivator
        .change_at(change.saturating_sub(1))
        .script_pubkey();
    if !statuses.contains_key(&c_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..change {
            let spk = derivator.change_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_CHANGE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    if !sub.is_empty() {
        flush_statuses(statuses);
        if request.send(CoinRequest::Subscribe(sub)).is_err() {
            return signal_stopped(request, notification);
        }
    }
    ControlFlow::Continue(())
}

/// Fold an Electrum `Status` response: diff against the local statuses, request
/// history for changed-non-empty scripthashes, clear the cleared ones, and flush
/// if any local status changed. `Break` ends the listener thread.
fn handle_status_response<P: ScanProfile>(
    elct_status: BTreeMap<ScriptBuf, Option<String>>,
    statuses: &mut P::StatusesStore,
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut history = vec![];
    let mut dirty = false;
    for (spk, status) in elct_status {
        match statuses.get(&spk) {
            Ok(Some((s, _, _))) => {
                // status is registered
                if s != status {
                    // status changed
                    if status.is_some() {
                        // not empty: ask for tx changes
                        history.push(spk.clone());
                    } else {
                        // Some(_) -> None: clear coin_store
                        let mut store = coin_store.lock().expect("poisoned");
                        let mut map = BTreeMap::new();
                        map.insert(spk.clone(), vec![]);
                        let _ = store.handle_history_response(map);
                        store.generate();
                    }
                    // record the local status change
                    let new_status = status.clone();
                    match statuses.modify(&spk, |v| v.0 = new_status.clone()) {
                        Ok(true) => dirty = true,
                        Ok(false) => {
                            // race-free under single-listener thread:
                            // we just observed the entry above
                        }
                        Err(e) => {
                            log::error!("listen_txs(): statuses modify: {e}");
                        }
                    }
                }
            }
            Ok(None) => {
                // not registered: previous behaviour was an
                // `entry(spk).and_modify(...)`, which is a no-op
                // for vacant entries. Preserve that, only the
                // history-side effect remains.
                if status.is_some() {
                    history.push(spk);
                } else {
                    let mut store = coin_store.lock().expect("poisoned");
                    let mut map = BTreeMap::new();
                    map.insert(spk.clone(), vec![]);
                    let _ = store.handle_history_response(map);
                }
            }
            Err(e) => {
                log::error!("listen_txs(): statuses get: {e}");
            }
        }
    }
    if !history.is_empty() {
        let hist = CoinRequest::History(history);
        log::debug!("listen_txs() send {}", hist.summary());
        if request.send(hist).is_err() {
            return signal_stopped(request, notification);
        }
    }
    if dirty {
        flush_statuses(statuses);
    }
    ControlFlow::Continue(())
}

/// Fold a `History` response into the coin store, fetch any missing txs, and
/// record the reported heights as pending claims. `Break` ends the listener
/// thread.
fn handle_history_response_msg<P: ScanProfile>(
    map: BTreeMap<ScriptBuf, Vec<(Txid, Option<u64>)>>,
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut store = coin_store.lock().expect("poisoned");
    let outcome = store.handle_history_response(map);
    if !outcome.missing_txs.is_empty()
        && request.send(CoinRequest::Txs(outcome.missing_txs)).is_err()
    {
        return signal_stopped(request, notification);
    }
    let pending_changed = store.record_reported_heights(&outcome.reported);
    if outcome.height_updated {
        store.tx_store_mut().persist();
        store.generate();
    }
    drop(store);
    if pending_changed || outcome.height_updated {
        let _ = notification.send(Notification::PaymentHistoryUpdated);
    }
    ControlFlow::Continue(())
}

/// On listener (re)connect, force a `History` refresh for every spk that
/// owns a still-`Inclusion::Unconfirmed` tx. `pending_claims` is an
/// in-memory cache a restart wipes, and the resubscribed status matches the
/// persisted `StatusesStore`, so no status-diff `History` fires on its own;
/// without this a tx already confirmed at some height would stay Unconfirmed
/// until an unrelated status change. The server re-reports the height, which
/// `record_reported_heights` turns back into a claim.
fn refresh_unconfirmed_history<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    electrum_req: &mpsc::Sender<CoinRequest>,
) {
    let spks = coin_store
        .lock()
        .expect("poisoned")
        .spks_with_unconfirmed_txs();
    if !spks.is_empty() {
        let _ = electrum_req.send(CoinRequest::History(spks));
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use crate::{
        client::{CoinRequest, CoinResponse},
        coin_store::{CoinEntry, CoinStore},
        config::ScannerConfig,
        fanout::Fanout,
        label_store::LabelStore,
        listener::{listen_txs, refresh_unconfirmed_history},
        notification::{Notification, TxListenerNotif},
        profile::{
            decode_status_key, decode_status_value, encode_account_key, encode_account_value,
            encode_status_key, encode_status_value, DefaultBackend, RamProfile,
        },
        scanner::ElectrumScanner,
        tx_store::{Inclusion, TxStore},
    };
    use bwk_coin::CoinStatus;
    use bwk_descriptor::{derivator::SpkDerivator, descriptor::wpkh};
    use bwk_persist::backend::{noop::NoopBackend, PersistenceBackend};
    use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
    use bwk_utils::test::{funding_tx, setup_logger, spending_tx};
    use miniscript::{
        bitcoin::{self, bip32::DerivationPath, Network, OutPoint},
        Descriptor, DescriptorPublicKey,
    };
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        str::FromStr,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc::{self, TryRecvError},
            Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    /// A fresh wpkh descriptor and its derivator, for a store no test shares.
    fn throwaway_descriptor() -> (Descriptor<DescriptorPublicKey>, SpkDerivator) {
        let network = Network::Regtest;
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(network, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let descriptor = wpkh(xpub);
        let derivator = SpkDerivator::new(descriptor.clone(), network).unwrap();
        (descriptor, derivator)
    }

    /// A scanner's coin store with no listener attached, for driving the
    /// listener helpers directly.
    fn bare_coin_store() -> (Arc<Mutex<CoinStore>>, SpkDerivator) {
        let (descriptor, _) = throwaway_descriptor();
        let config = ScannerConfig::new(
            descriptor,
            PathBuf::default(),
            String::new(),
            "bare".into(),
            Network::Regtest,
            None,
        );
        let scanner = ElectrumScanner::try_new(config).unwrap();
        (scanner.coin_store().clone(), scanner.derivator())
    }

    struct CoinStoreMock {
        pub store: Arc<Mutex<CoinStore>>,
        pub notif: mpsc::Receiver<Notification>,
        pub request: mpsc::Receiver<CoinRequest>,
        pub response: mpsc::Sender<CoinResponse>,
        pub listener: JoinHandle<()>,
        pub stop: Arc<AtomicBool>,
        pub derivator: SpkDerivator,
    }

    impl Drop for CoinStoreMock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    impl CoinStoreMock {
        fn new(recv_tip: u32, change_tip: u32, look_ahead: u32) -> Self {
            let (notif_sender, notif_recv) = mpsc::channel();
            let (tip_sender, tip_receiver) = mpsc::channel();
            let (req_sender, req_receiver) = mpsc::channel();
            let (resp_sender, resp_receiver) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let (descriptor, derivator) = throwaway_descriptor();
            let tx_store = TxStore::new();
            let label_store = Arc::new(Mutex::new(LabelStore::new()));
            let mock_backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
            let account_store = Arc::new(Mutex::new(bwk_persist::storage::ram::RamStore::empty(
                mock_backend.clone(),
                bwk_persist::ACCOUNT_STORE_KEY,
                encode_account_key,
                encode_account_value,
            )));
            let statuses_store = bwk_persist::storage::ram::RamStore::open(
                mock_backend,
                bwk_persist::STATUSES_STORE_KEY,
                encode_status_key,
                decode_status_key,
                encode_status_value,
                decode_status_value,
            )
            .expect("open statuses RamStore");
            let coin_store = Arc::new(Mutex::new(CoinStore::new(
                bitcoin::Network::Regtest,
                descriptor.clone(),
                notif_sender.clone(),
                recv_tip,
                change_tip,
                look_ahead,
                tx_store,
                label_store,
                account_store,
            )));
            coin_store.lock().expect("poisoned").init(tip_sender);
            let store = coin_store.clone();
            let cloned_stop = stop.clone();
            let cloned_derivator = derivator.clone();

            let listener_handle = thread::spawn(move || {
                listen_txs::<RamProfile<DefaultBackend>>(
                    coin_store,
                    cloned_derivator,
                    notif_sender,
                    tip_receiver,
                    stop,
                    req_sender,
                    resp_receiver,
                    statuses_store,
                    Arc::new(Fanout::default()),
                );
            });

            CoinStoreMock {
                store,
                notif: notif_recv,
                request: req_receiver,
                response: resp_sender,
                listener: listener_handle,
                stop: cloned_stop,
                derivator,
            }
        }

        fn coins(&mut self) -> BTreeMap<OutPoint, CoinEntry> {
            self.store.lock().expect("poisoned").coins()
        }

        fn stop(&self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn simple_start_stop() {
        setup_logger();
        let mock = CoinStoreMock::new(0, 0, 20);
        thread::sleep(Duration::from_millis(10));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));
        mock.stop();
        thread::sleep(Duration::from_secs(1));
        assert!(mock.listener.is_finished());
    }

    fn simple_recv() -> (bitcoin::Transaction, CoinStoreMock) {
        setup_logger();
        let look_ahead = 5;
        let mut mock = CoinStoreMock::new(0, 0, look_ahead);
        thread::sleep(Duration::from_millis(500));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));

        let mut init_spks = vec![];
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.receive_spk_at(i);
            init_spks.push(spk);
        }
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.change_spk_at(i);
            init_spks.push(spk);
        }

        // receive initial subscriptions
        if let Ok(CoinRequest::Subscribe(v)) = mock.request.try_recv() {
            // NOTE: we expect (tip + 1 + look_ahead )
            assert_eq!(v.len(), 12);
            for spk in &init_spks {
                assert!(v.contains(spk));
            }
        } else {
            panic!()
        }

        // electrum server send spks statuses (None)
        let statuses: BTreeMap<_, _> = init_spks.clone().into_iter().map(|s| (s, None)).collect();
        mock.response.send(CoinResponse::Status(statuses)).unwrap();

        thread::sleep(Duration::from_millis(100));

        assert!(mock.coins().is_empty());

        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_unco".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        let tx_0 = funding_tx(spk_recv_0.clone(), 0.1);

        // server must send history response
        let mut history = BTreeMap::new();
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), None)]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_0.compute_txid()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_0.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);

        // NOTE: the coin is now confirmed

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_conf".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(1))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // NOTE: coin_store already have the tx it should not ask it
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // The server reports inclusion at height 1. `insert_history`
        // resets the entry to `Unconfirmed`, then `record_reported_heights`
        // queues the claim in `pending_claims`. The scan never promotes it:
        // that is the reconciler's job, against the validated chain. The
        // derived coin height therefore stays None and the status stays
        // Unconfirmed.
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);
        (tx_0, mock)
    }

    #[test]
    fn recv_and_spend() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // spend this coin
        let outpoint = mock.coins().pop_first().unwrap().0;
        let tx_1 = spending_tx(outpoint);

        // NOTE: the coin is now spent

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_spent".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(
            spk_recv_0.clone(),
            vec![(tx_0.compute_txid(), Some(1)), (tx_1.compute_txid(), None)],
        );
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request only for tx_1
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_1.compute_txid()]);
        } else {
            panic!()
        }

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_1.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.status(), CoinStatus::Spent);
    }

    #[test]
    fn simple_reorg() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // NOTE: the coin is now spent we can reorg it

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_reorg".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // NOTE: confirmation height is changed to 2
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(2))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server do not receive a tx request as the store already go the tx
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // the store still contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // The server reorgs the entry to height 2. The reported-height
        // change drives `insert_history` to reset the entry to
        // `Inclusion::Unconfirmed` (this is the demotion path, owned by
        // history, not by the reconciler). `record_reported_heights` then
        // queues the claim at height 2, and the scan stops there, so the
        // entry stays Unconfirmed and the derived coin height is None.
        assert_eq!(coin.height(), None);
    }

    // After a restart `pending_claims` (a non-persisted cache) is empty while a
    // confirmed tx sits `Unconfirmed`. The reconnect refresh must issue a
    // `History` for that tx's spk so the server re-reports its height and the
    // claim is rebuilt.
    #[test]
    fn reconnect_refreshes_history_for_unconfirmed_spk() {
        use crate::tx_store::TxEntry;

        let (coin_store, deriv) = bare_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        {
            let mut store = coin_store.lock().unwrap();
            store.tx_store_mut().update(TxEntry::for_test(tx));
            store
                .tx_store_mut()
                .update_inclusion(&txid, Inclusion::Unconfirmed);
            store.generate();
            // As after a restart: the in-memory pending-claims cache is empty.
            assert!(store.pending_claims_snapshot().is_empty());
        }

        let (req_tx, req_rx) = mpsc::channel();
        refresh_unconfirmed_history(&coin_store, &req_tx);

        match req_rx.try_recv() {
            Ok(CoinRequest::History(spks)) => assert!(
                spks.contains(&spk),
                "History must cover the spk owning the Unconfirmed tx"
            ),
            other => panic!("expected History for the unconfirmed spk, got {other:?}"),
        }
    }
}
