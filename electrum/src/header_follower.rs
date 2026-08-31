//! Keeping a wallet's header validator on the endpoint its scanners watch.
//!
//! A wallet pairs its scanners with one [`HeaderStore`]: either the one it
//! opened for itself, or one handed in and shared with other wallets.
//! [`HeaderFollower`] holds that store along with which of the two it is, and
//! runs the pass that keeps it pointed at the endpoint the scanners talk to:
//! reconnect when that moves, idle when nothing carries an endpoint any more,
//! and ask the [`Reconciler`]s again for the proofs the dropped merkle client
//! will never answer.
//!
//! Only the wallet that opened the store starts or idles it: a borrowed one is
//! the opener's to bring up and take down. Reconnecting is not gated that way,
//! a dead socket is visible only to the wallet that hit it, and a shared store
//! left on it stalls every wallet's promotions.

use std::{
    path::PathBuf,
    sync::{mpsc, Arc},
};

use bwk_persist::PersistenceKind;
use miniscript::bitcoin::Network;

use crate::{
    config::{Endpoint, HEADERS_FILENAME},
    header_store::{HeaderStore, StartError},
    notification::Notification,
    profile::{OpenScanFromBackend, ScanProfile},
    reconcile::Reconciler,
};

/// A wallet's handle on the validated header chain.
pub struct HeaderFollower<P: ScanProfile> {
    store: Arc<HeaderStore<P::HeaderStore>>,
    /// Whether this wallet opened the store, and so may start and idle it.
    owned: bool,
    /// The endpoint the store follows, `None` while it is idle.
    target: Option<Endpoint>,
    notification: mpsc::Sender<Notification>,
}

impl<P: ScanProfile> HeaderFollower<P> {
    /// Borrow a store opened elsewhere. The wallet promotes against it like
    /// any other, but leaves its connection alone.
    pub fn borrowed(
        store: Arc<HeaderStore<P::HeaderStore>>,
        notification: mpsc::Sender<Notification>,
    ) -> Self {
        Self {
            store,
            owned: false,
            target: None,
            notification,
        }
    }

    /// The store itself, to register on and to reconcile against.
    pub fn store(&self) -> &Arc<HeaderStore<P::HeaderStore>> {
        &self.store
    }
}

impl<P: OpenScanFromBackend> HeaderFollower<P> {
    /// Open this wallet's own store: online against `endpoint` when there is
    /// one, idle otherwise. Headers are always binary-backed, at
    /// [`HEADERS_FILENAME`] under `account_dir`, whenever the wallet persists
    /// at all. `min_height` snaps the initial backfill down to the retarget
    /// boundary at or below it, for a wallet that knows how far back its
    /// history reaches.
    ///
    /// A configured endpoint that cannot be reached is a [`StartError`]:
    /// header-sync progress gates `Verified` state, so a degraded store must
    /// fail loud rather than open silently worker-less.
    pub fn open(
        endpoint: Option<Endpoint>,
        network: Network,
        persistence: Option<PersistenceKind>,
        account_dir: PathBuf,
        min_height: Option<u32>,
        notification: mpsc::Sender<Notification>,
    ) -> Result<Self, StartError> {
        let path = persistence
            .is_some()
            .then(|| account_dir.join(HEADERS_FILENAME));
        let (url, port) = match &endpoint {
            Some(e) => (e.url().map(str::to_string), e.port()),
            None => (None, None),
        };
        let store = HeaderStore::start_or_open(url, port, network, path, min_height)?;
        Ok(Self {
            store,
            owned: true,
            target: endpoint,
            notification,
        })
    }

    /// Point the store at `target`, reconnecting when that moved or its worker
    /// is gone, and idling it when `target` is `None`. A no-op while it already
    /// follows `target`: reconnecting drops the merkle client along with every
    /// proof request in flight on it.
    pub fn follow<'a>(
        &mut self,
        target: Option<Endpoint>,
        reconcilers: impl IntoIterator<Item = &'a Reconciler<P>>,
    ) {
        if !self.owned {
            return;
        }
        let Some(target) = target else {
            self.stop();
            return;
        };
        if self.target.as_ref() == Some(&target) && self.store.running() {
            return;
        }
        self.reconnect(target, reconcilers);
    }

    /// Reconnect to `target` whatever the store believes it follows: the caller
    /// noticed the socket is dead, which the store cannot see by itself. Not
    /// gated on ownership (see the module doc); the proofs another wallet had
    /// in flight on the dropped merkle client resolve as
    /// [`MerkleOutcome::Failed`](crate::header_store::MerkleOutcome::Failed),
    /// so its own pass asks again.
    pub fn reconnect<'a>(
        &mut self,
        target: Endpoint,
        reconcilers: impl IntoIterator<Item = &'a Reconciler<P>>,
    ) {
        let Some((url, port)) = target.server() else {
            self.stop();
            return;
        };
        let restarted = self.store.restart(url.to_string(), port);
        if let Err(e) = restarted {
            log::error!("HeaderFollower::reconnect(): header store restart failed: {e}");
            let _ = self.notification.send(Notification::HeaderStoreRestart);
            return;
        }
        self.target = Some(target);
        // The merkle client is a fresh connection: whatever was queued on the
        // dead one never gets an answer, so ask again.
        for reconciler in reconcilers {
            reconciler.requeue_confirmed_unverified();
        }
    }

    /// Idle the store. Forgets the followed endpoint, so a later
    /// [`follow`](Self::follow) reconnects even against the same server.
    pub fn stop(&mut self) {
        if !self.owned {
            return;
        }
        self.store.stop();
        self.target = None;
    }
}
