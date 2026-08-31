//! The background thread a type runs, from start to join.
//!
//! Stopping only signals the thread and parks its handle: a caller asking for a
//! stop must not block on the connection it is winding down. The parked handles
//! are joined by [`Worker::join`], which the owner's `Drop` calls. That join is
//! not optional: these threads hold `Arc` clones of the persistence backend, so
//! without it the DirLock on the account directory outlives its owner and
//! refuses a reopen.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

/// Ceiling of the sleep a worker loop backs off to while it has nothing to do.
pub const IDLE_BACKOFF_MS: u64 = 20;

/// One background thread with its stop flag, plus the handles of the threads
/// told to stop and not joined yet.
#[derive(Debug, Default)]
pub struct Worker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    winding_down: Vec<JoinHandle<()>>,
}

impl Worker {
    /// True while the thread this worker started is alive.
    pub fn running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// True once that thread has exited on its own, before a
    /// [`stop`](Self::stop) reclaimed its handle.
    pub fn finished(&self) -> bool {
        self.handle.as_ref().is_some_and(JoinHandle::is_finished)
    }

    /// Spawn `run` under a fresh stop flag, handed to it so it can return once
    /// asked to. A handle left by a previous run is parked, so starting over a
    /// thread still alive leaks it: the caller stops it first.
    pub fn start(&mut self, run: impl FnOnce(Arc<AtomicBool>) + Send + 'static) {
        if let Some(handle) = self.handle.take() {
            self.winding_down.push(handle);
        }
        self.reap();
        self.stop = Arc::new(AtomicBool::new(false));
        let stop = self.stop.clone();
        self.handle = Some(thread::spawn(move || run(stop)));
    }

    /// Signal the thread to end without blocking. Its handle is parked for
    /// [`join`](Self::join).
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            self.winding_down.push(handle);
        }
        self.reap();
    }

    /// Signal the thread to end and block until it, and every parked one, has
    /// exited.
    ///
    /// A handle for the calling thread is dropped rather than joined. A worker
    /// can hold the last reference to the type that owns it (through a `Weak`
    /// it upgrades while it works), so it can end up running that owner's
    /// `Drop`, and joining itself there aborts with `Resource deadlock
    /// avoided`. Such a thread is on its way out anyway.
    pub fn join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let current = thread::current().id();
        if let Some(handle) = self.handle.take() {
            if handle.thread().id() != current {
                let _ = handle.join();
            }
        }
        for handle in std::mem::take(&mut self.winding_down) {
            if handle.thread().id() != current {
                let _ = handle.join();
            }
        }
    }

    /// Drop the handles of parked threads that already exited, so repeated
    /// stop and start does not accumulate them.
    fn reap(&mut self) {
        let (done, running) = std::mem::take(&mut self.winding_down)
            .into_iter()
            .partition(JoinHandle::is_finished);
        self.winding_down = running;
        for handle in done {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{atomic::Ordering, mpsc, Arc},
        thread,
        time::Duration,
    };

    use crate::worker::Worker;

    /// A stopped thread must see the flag it was started under, and a restart
    /// must run under a fresh one rather than exit on the previous stop.
    #[test]
    fn a_restart_runs_under_a_fresh_stop_flag() {
        let mut worker = Worker::default();
        let (tx, rx) = mpsc::channel();
        let sender = tx.clone();
        worker.start(move |stop| {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
            let _ = sender.send("first stopped");
        });
        worker.stop();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok("first stopped"));

        worker.start(move |stop| {
            let _ = tx.send(if stop.load(Ordering::Relaxed) {
                "second started stopped"
            } else {
                "second started running"
            });
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok("second started running")
        );
        worker.join();
        assert!(!worker.running());
    }

    /// A worker that ends up running its owner's `Drop` joins itself, which
    /// aborts the process with `Resource deadlock avoided`. `join` must skip
    /// the calling thread instead.
    #[test]
    fn joining_from_inside_the_worker_thread_does_not_deadlock() {
        let worker = Arc::new(std::sync::Mutex::new(Worker::default()));
        let (done, finished) = mpsc::channel();
        let inner = worker.clone();
        worker.lock().expect("poisoned").start(move |_| {
            inner.lock().expect("poisoned").join();
            let _ = done.send("survived");
        });
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(5)),
            Ok("survived")
        );
        worker.lock().expect("poisoned").join();
    }

    /// A stop parks the running thread instead of blocking on it, a restart
    /// keeps a thread still winding down parked, and `join` drains the list.
    #[test]
    fn a_stop_then_start_leaks_no_thread() {
        let mut worker = Worker::default();
        let (release, held) = mpsc::channel();
        let (exited, exits) = mpsc::channel();
        let first_exited = exited.clone();
        worker.start(move |_| {
            let _ = held.recv();
            let _ = first_exited.send("first");
        });

        worker.stop();
        assert!(!worker.running());
        assert_eq!(worker.winding_down.len(), 1);

        worker.start(move |stop| {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
            let _ = exited.send("second");
        });
        // The first thread ignores the stop flag, so the restart must keep its
        // handle rather than reap a thread that is still alive.
        assert_eq!(worker.winding_down.len(), 1);
        assert!(worker.running());

        release.send(()).expect("the first thread is waiting on it");
        assert_eq!(exits.recv_timeout(Duration::from_secs(5)), Ok("first"));

        worker.join();
        assert_eq!(exits.recv_timeout(Duration::from_secs(5)), Ok("second"));
        assert!(worker.winding_down.is_empty());
        assert!(!worker.running());
    }
}
