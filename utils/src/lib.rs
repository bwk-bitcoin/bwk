#[cfg(feature = "test")]
pub mod mock_manager;
#[cfg(feature = "test")]
pub mod test;

#[cfg(target_os = "android")]
use std::io;

#[cfg(feature = "ureq")]
pub mod ureq_resolver {
    use std::{
        collections::HashMap,
        fmt,
        net::SocketAddr,
        sync::{mpsc, Arc, Mutex},
        thread::{self, JoinHandle},
        time::Duration,
    };

    #[derive(Clone)]
    struct CacheEntry {
        uri: ureq::http::Uri,
        addrs: Vec<SocketAddr>,
    }

    pub struct RefreshingResolver<R = ureq::unversioned::resolver::DefaultResolver> {
        inner: Arc<R>,
        entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
        miss_lock: Arc<Mutex<()>>,
        shutdown: Option<mpsc::Sender<()>>,
        handle: Option<JoinHandle<()>>,
    }

    impl RefreshingResolver {
        pub fn new(refresh_interval: Duration, resolve_timeout: Duration) -> Self {
            Self::with_resolver(
                ureq::unversioned::resolver::DefaultResolver::default(),
                refresh_interval,
                resolve_timeout,
            )
        }
    }

    impl<R> RefreshingResolver<R>
    where
        R: ureq::unversioned::resolver::Resolver + Send + Sync + 'static,
    {
        fn with_resolver(inner: R, refresh_interval: Duration, resolve_timeout: Duration) -> Self {
            let entries = Arc::new(Mutex::new(HashMap::<String, CacheEntry>::new()));
            let miss_lock = Arc::new(Mutex::new(()));
            let inner = Arc::new(inner);
            let refresh_entries = Arc::clone(&entries);
            let refresh_inner = Arc::clone(&inner);
            let (shutdown_tx, shutdown_rx) = mpsc::channel();
            let handle = thread::spawn(move || {
                refresh_loop(
                    refresh_inner,
                    refresh_entries,
                    refresh_interval,
                    resolve_timeout,
                    shutdown_rx,
                )
            });
            Self {
                inner,
                entries,
                miss_lock,
                shutdown: Some(shutdown_tx),
                handle: Some(handle),
            }
        }

        fn key(uri: &ureq::http::Uri) -> Result<String, ureq::Error> {
            let scheme = uri.scheme().ok_or(ureq::Error::HostNotFound)?;
            let authority = uri.authority().ok_or(ureq::Error::HostNotFound)?;
            ureq::unversioned::resolver::DefaultResolver::host_and_port(scheme, authority)
                .ok_or(ureq::Error::HostNotFound)
        }

        fn addrs_from_slice(
            addrs: &[SocketAddr],
        ) -> ureq::unversioned::resolver::ResolvedSocketAddrs {
            let mut result = ureq::unversioned::resolver::ArrayVec::from_fn(|_| {
                SocketAddr::from(([0, 0, 0, 0], 0))
            });
            for addr in addrs {
                result.push(*addr);
            }
            result
        }
    }

    impl<R> fmt::Debug for RefreshingResolver<R>
    where
        R: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RefreshingResolver")
                .field("inner", &self.inner)
                .finish_non_exhaustive()
        }
    }

    impl<R> ureq::unversioned::resolver::Resolver for RefreshingResolver<R>
    where
        R: ureq::unversioned::resolver::Resolver + Send + Sync + 'static,
    {
        fn resolve(
            &self,
            uri: &ureq::http::Uri,
            config: &ureq::config::Config,
            timeout: ureq::unversioned::transport::NextTimeout,
        ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
            let key = Self::key(uri)?;
            if let Some(entry) = self.entries.lock().expect("poisoned").get(&key) {
                return Ok(Self::addrs_from_slice(&entry.addrs));
            }

            let _guard = self.miss_lock.lock().expect("poisoned");
            if let Some(entry) = self.entries.lock().expect("poisoned").get(&key) {
                return Ok(Self::addrs_from_slice(&entry.addrs));
            }

            let addrs = self.inner.resolve(uri, config, timeout)?;
            self.entries.lock().expect("poisoned").insert(
                key,
                CacheEntry {
                    uri: uri.clone(),
                    addrs: addrs.iter().copied().collect(),
                },
            );
            Ok(addrs)
        }
    }

    impl<R> Drop for RefreshingResolver<R> {
        fn drop(&mut self) {
            self.shutdown.take();
            if let Some(handle) = self.handle.take() {
                handle.join().expect("DNS refresh worker panicked");
            }
        }
    }

    fn refresh_loop<R>(
        resolver: Arc<R>,
        entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
        interval: Duration,
        resolve_timeout: Duration,
        shutdown: mpsc::Receiver<()>,
    ) where
        R: ureq::unversioned::resolver::Resolver,
    {
        loop {
            match shutdown.recv_timeout(interval) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            let cached = entries
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(key, entry)| (key.clone(), entry.uri.clone(), entry.addrs.clone()))
                .collect::<Vec<_>>();

            for (key, uri, old_addrs) in cached {
                match shutdown.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                let Ok(addrs) = resolver.resolve(
                    &uri,
                    &ureq::config::Config::default(),
                    timeout(resolve_timeout),
                ) else {
                    continue;
                };
                let addrs = addrs.iter().copied().collect::<Vec<_>>();
                if addrs == old_addrs {
                    continue;
                }
                if let Some(entry) = entries.lock().expect("poisoned").get_mut(&key) {
                    entry.addrs = addrs;
                }
            }
        }
    }

    fn timeout(resolve_timeout: Duration) -> ureq::unversioned::transport::NextTimeout {
        ureq::unversioned::transport::NextTimeout {
            after: ureq::unversioned::transport::time::Duration::Exact(resolve_timeout),
            reason: ureq::Timeout::Resolve,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };

        use ureq::unversioned::resolver::Resolver;

        #[derive(Clone, Debug)]
        struct CountingResolver {
            calls: Arc<AtomicU64>,
        }

        impl ureq::unversioned::resolver::Resolver for CountingResolver {
            fn resolve(
                &self,
                uri: &ureq::http::Uri,
                _config: &ureq::config::Config,
                _timeout: ureq::unversioned::transport::NextTimeout,
            ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                let port = uri
                    .authority()
                    .and_then(|authority| authority.port_u16())
                    .unwrap_or(80);
                let mut addrs = self.empty();
                addrs.push(SocketAddr::from(([127, 0, 0, 1], port)));
                Ok(addrs)
            }
        }

        #[test]
        fn addrs_from_slice_keeps_cached_addresses() {
            let addrs = [SocketAddr::from(([127, 0, 0, 1], 80))];

            let cached = RefreshingResolver::<ureq::unversioned::resolver::DefaultResolver>::addrs_from_slice(&addrs);

            assert_eq!(cached.iter().copied().collect::<Vec<_>>(), addrs);
        }

        #[test]
        fn key_uses_authority_port() {
            let default_port: ureq::http::Uri = "http://example.com/a".parse().unwrap();
            let explicit_port: ureq::http::Uri = "http://example.com:8080/a".parse().unwrap();

            assert_ne!(
                RefreshingResolver::<ureq::unversioned::resolver::DefaultResolver>::key(
                    &default_port,
                )
                .unwrap(),
                RefreshingResolver::<ureq::unversioned::resolver::DefaultResolver>::key(
                    &explicit_port,
                )
                .unwrap()
            );
        }

        #[test]
        fn resolve_caches_after_first_lookup() {
            let calls = Arc::new(AtomicU64::new(0));
            let resolver = RefreshingResolver::with_resolver(
                CountingResolver {
                    calls: Arc::clone(&calls),
                },
                Duration::from_secs(60),
                Duration::from_secs(5),
            );
            let first: ureq::http::Uri = "http://example.com/a".parse().unwrap();
            let second: ureq::http::Uri = "http://example.com/b".parse().unwrap();

            resolver
                .resolve(
                    &first,
                    &ureq::config::Config::default(),
                    timeout(Duration::from_secs(5)),
                )
                .unwrap();
            resolver
                .resolve(
                    &second,
                    &ureq::config::Config::default(),
                    timeout(Duration::from_secs(5)),
                )
                .unwrap();

            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn concurrent_first_resolve_is_single_lookup() {
            let calls = Arc::new(AtomicU64::new(0));
            let resolver = Arc::new(RefreshingResolver::with_resolver(
                CountingResolver {
                    calls: Arc::clone(&calls),
                },
                Duration::from_secs(60),
                Duration::from_secs(5),
            ));
            let uri: ureq::http::Uri = "http://example.com/a".parse().unwrap();
            let mut threads = Vec::new();

            for _ in 0..8 {
                let resolver = Arc::clone(&resolver);
                let uri = uri.clone();
                threads.push(thread::spawn(move || {
                    resolver
                        .resolve(
                            &uri,
                            &ureq::config::Config::default(),
                            timeout(Duration::from_secs(5)),
                        )
                        .unwrap();
                }));
            }

            for thread in threads {
                thread.join().unwrap();
            }

            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn drop_stops_background_refresh() {
            let calls = Arc::new(AtomicU64::new(0));
            let resolver = RefreshingResolver::with_resolver(
                CountingResolver {
                    calls: Arc::clone(&calls),
                },
                Duration::from_millis(10),
                Duration::from_secs(5),
            );
            let uri: ureq::http::Uri = "http://example.com/a".parse().unwrap();

            resolver
                .resolve(
                    &uri,
                    &ureq::config::Config::default(),
                    timeout(Duration::from_secs(5)),
                )
                .unwrap();
            std::thread::sleep(Duration::from_millis(30));
            drop(resolver);

            let after_drop = calls.load(Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(30));

            assert_eq!(calls.load(Ordering::Relaxed), after_drop);
        }
    }
}

#[cfg(target_os = "android")]
pub fn android_root_certs() -> io::Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    for entry in std::fs::read_dir("/system/etc/security/cacerts")? {
        certs.push(std::fs::read(entry?.path())?);
    }

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "android cert store is empty",
        ));
    }

    Ok(certs)
}

pub fn short_string(s: String, len: usize) -> String {
    assert!(len > 6);
    let separator = if len % 2 != 0 { "." } else { ".." };
    let head = (len - 2).div_ceil(2);
    let tail = head;
    if s.len() <= head + tail + 2 {
        // No need to truncate if string is short
        return s.to_string();
    }
    format!("{}{separator}{}", &s[..head], &s[s.len() - tail..])
}
