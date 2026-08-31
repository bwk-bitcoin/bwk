//! Fanning one event out to a set of registered listeners.
//!
//! Registration is a push and there is no deregister to call: a send to a
//! listener whose receiver is gone fails, and that is what prunes it. A
//! listener that outlives its channel (a thread restarting on a fresh one)
//! keeps its [`ListenerId`] and registers under it again, so the store does
//! not keep the channel it left behind.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Mutex,
};

static NEXT_LISTENER_ID: AtomicU64 = AtomicU64::new(0);

/// Addresses one registration, so an event can reach a single listener instead
/// of all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerId(u64);

impl ListenerId {
    #[allow(clippy::should_implement_trait)]
    pub fn next() -> Self {
        Self(NEXT_LISTENER_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// The senders an event is fanned out to.
#[derive(Debug)]
pub struct Fanout<T> {
    listeners: Mutex<Vec<(ListenerId, mpsc::Sender<T>)>>,
}

impl<T> Default for Fanout<T> {
    fn default() -> Self {
        Self {
            listeners: Mutex::new(Vec::new()),
        }
    }
}

impl<T> Fanout<T> {
    /// Register a fresh channel. Drop the returned receiver to deregister.
    pub fn register(&self) -> mpsc::Receiver<T> {
        self.register_as(ListenerId::next())
    }

    /// Register a fresh channel under `id`, replacing whatever was registered
    /// there.
    pub fn register_as(&self, id: ListenerId) -> mpsc::Receiver<T> {
        let (tx, rx) = mpsc::channel();
        let mut listeners = self.listeners.lock().expect("poisoned");
        listeners.retain(|(other, _)| *other != id);
        listeners.push((id, tx));
        rx
    }

    /// Register a listener that already owns its channel.
    pub fn register_sender(&self, sender: mpsc::Sender<T>) {
        self.listeners
            .lock()
            .expect("poisoned")
            .push((ListenerId::next(), sender));
    }

    /// Fan a freshly built event out to every listener, for events that cannot
    /// be cloned.
    pub fn notify_with(&self, event: impl Fn() -> T) {
        let mut listeners = self.listeners.lock().expect("poisoned");
        listeners.retain(|(_, tx)| tx.send(event()).is_ok());
    }

    /// Send to `id` alone. Unknown or gone, the event is dropped: it was
    /// addressed to that listener and to nobody else.
    pub fn notify_one(&self, id: ListenerId, event: T) {
        let mut listeners = self.listeners.lock().expect("poisoned");
        let Some(pos) = listeners.iter().position(|(other, _)| *other == id) else {
            return;
        };
        if listeners[pos].1.send(event).is_err() {
            listeners.remove(pos);
        }
    }

    #[cfg(test)]
    pub fn listener_count(&self) -> usize {
        self.listeners.lock().expect("poisoned").len()
    }
}

impl<T: Clone> Fanout<T> {
    /// Fan `event` out to every listener.
    pub fn notify(&self, event: T) {
        self.notify_with(|| event.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use crate::fanout::{Fanout, ListenerId};

    #[test]
    fn notify_reaches_every_listener_and_prunes_the_gone_ones() {
        let fanout = Fanout::<u32>::default();
        let alive = fanout.register();
        let gone = fanout.register();
        drop(gone);

        fanout.notify(7);

        assert_eq!(alive.try_recv(), Ok(7));
        assert_eq!(fanout.listener_count(), 1);
    }

    #[test]
    fn notify_one_reaches_only_the_addressed_listener() {
        let fanout = Fanout::<u32>::default();
        let id = ListenerId::next();
        let addressed = fanout.register_as(id);
        let other = fanout.register();

        fanout.notify_one(id, 7);

        assert_eq!(addressed.try_recv(), Ok(7));
        assert_eq!(other.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn registering_under_a_known_id_replaces_its_channel() {
        let fanout = Fanout::<u32>::default();
        let id = ListenerId::next();
        let stale = fanout.register_as(id);
        let fresh = fanout.register_as(id);

        fanout.notify_one(id, 7);

        assert_eq!(fresh.try_recv(), Ok(7));
        assert_eq!(stale.try_recv(), Err(mpsc::TryRecvError::Disconnected));
        assert_eq!(fanout.listener_count(), 1);
    }

    #[test]
    fn notify_with_builds_one_event_per_listener() {
        let fanout = Fanout::<String>::default();
        let first = fanout.register();
        let second = fanout.register();

        fanout.notify_with(|| "tick".to_string());

        assert_eq!(first.try_recv().as_deref(), Ok("tick"));
        assert_eq!(second.try_recv().as_deref(), Ok("tick"));
    }
}
