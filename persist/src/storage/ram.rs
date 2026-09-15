//! RAM-cached + write-back [`Store`] implementation.

use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

use super::Store;
use crate::{backend::PersistenceBackend, PersistError};

/// RAM-cached [`Store`] that writes back to a [`PersistenceBackend`]
/// on [`Store::flush`]. Mutations accumulate in in-memory `dirty` and
/// `removed` sets; flush emits them as a single
/// [`PersistenceBackend::flush_batch`] call.
///
/// Generic over any `B: PersistenceBackend`: concrete (`SqliteBackend`,
/// `JsonBackend`, `NoopBackend`) for monomorphised static dispatch, or
/// `Arc<dyn PersistenceBackend>` for runtime dispatch via the blanket
/// impl.
pub struct RamStore<B: PersistenceBackend, K: Ord, V> {
    cache: BTreeMap<K, V>,
    dirty: HashSet<K>,
    removed: HashSet<K>,
    backend: B,
    store_key: &'static str,
    // Encoding hooks: fn pointers, zero-monomorphisation cost. Only
    // the write-path encoders are retained; decoders are used once at
    // `open()` time.
    encode_k: fn(&K) -> String,
    encode_v: fn(&V) -> Result<Vec<u8>, PersistError>,
}

impl<B, K, V> std::fmt::Debug for RamStore<B, K, V>
where
    B: PersistenceBackend,
    K: Ord + std::fmt::Debug,
    V: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RamStore")
            .field("store_key", &self.store_key)
            .field("len", &self.cache.len())
            .field("dirty", &self.dirty.len())
            .field("removed", &self.removed.len())
            .finish()
    }
}

impl<B: PersistenceBackend, K: Ord + Clone + Hash + Eq, V: Clone> RamStore<B, K, V> {
    /// Eagerly load every row of `store_key` from `backend` into the
    /// cache. Subsequent mutations stay in RAM until [`Store::flush`].
    pub fn open(
        backend: B,
        store_key: &'static str,
        encode_k: fn(&K) -> String,
        decode_k: fn(&str) -> Result<K, PersistError>,
        encode_v: fn(&V) -> Result<Vec<u8>, PersistError>,
        decode_v: fn(&[u8]) -> Result<V, PersistError>,
    ) -> Result<Self, PersistError> {
        let rows = backend.get_rows(store_key)?;
        let mut cache = BTreeMap::new();
        for (key, bytes) in rows {
            let k = decode_k(&key)?;
            let v = decode_v(&bytes)?;
            cache.insert(k, v);
        }
        Ok(Self {
            cache,
            dirty: HashSet::new(),
            removed: HashSet::new(),
            backend,
            store_key,
            encode_k,
            encode_v,
        })
    }

    /// Construct an empty `RamStore` without touching the backend.
    /// Useful when persistence is disabled and `backend` is a
    /// [`NoopBackend`](crate::backend::noop::NoopBackend).
    pub fn empty(
        backend: B,
        store_key: &'static str,
        encode_k: fn(&K) -> String,
        encode_v: fn(&V) -> Result<Vec<u8>, PersistError>,
    ) -> Self {
        Self {
            cache: BTreeMap::new(),
            dirty: HashSet::new(),
            removed: HashSet::new(),
            backend,
            store_key,
            encode_k,
            encode_v,
        }
    }

    /// Borrow the underlying backend for ad-hoc reads that don't fit
    /// the `Store` surface (e.g. SQLite-specific maintenance). Rarely
    /// needed at the domain-store layer.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The logical store name this `RamStore` is bound to.
    pub fn store_key(&self) -> &'static str {
        self.store_key
    }

    // ------------------------------------------------------------------
    // Inherent infallible ref-access helpers.
    //
    // The `Store` trait hands back owned values (so non-RAM impls can
    // satisfy it), but inside a concrete RAM cache we have references
    // right there. Domain-store wrappers that embed a `RamStore` use
    // these inherent methods to avoid cloning on every read and to
    // keep their own external `Option<&V>` / `Option<&mut V>` API
    // shape. No trait needed: these are specific to the RAM strategy.
    // ------------------------------------------------------------------

    /// Borrow an entry's value by key. `None` if absent. Infallible.
    pub fn get_ref(&self, k: &K) -> Option<&V> {
        self.cache.get(k)
    }

    /// Borrow an entry mutably by key and mark it dirty (so the next
    /// [`Store::flush`] persists it). `None` if absent.
    pub fn get_mut_ref(&mut self, k: &K) -> Option<&mut V> {
        let v = self.cache.get_mut(k)?;
        self.removed.remove(k);
        self.dirty.insert(k.clone());
        Some(v)
    }

    /// Iterate `(&K, &V)` pairs in key order.
    pub fn iter_ref(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.cache.iter()
    }

    /// Iterate `&V` in key order.
    pub fn values_ref(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.cache.values()
    }

    /// Iterate `&K` in sorted order.
    pub fn keys_ref(&self) -> std::collections::btree_map::Keys<'_, K, V> {
        self.cache.keys()
    }

    /// Whether `k` is present in the cache. Infallible.
    pub fn contains(&self, k: &K) -> bool {
        self.cache.contains_key(k)
    }

    /// Number of entries. Infallible.
    pub fn len_ram(&self) -> usize {
        self.cache.len()
    }
}

impl<B, K, V> Store for RamStore<B, K, V>
where
    B: PersistenceBackend,
    K: Ord + Clone + Hash + Eq,
    V: Clone,
{
    type Key = K;
    type Value = V;

    fn get(&self, k: &K) -> Result<Option<V>, PersistError> {
        Ok(self.cache.get(k).cloned())
    }

    fn contains_key(&self, k: &K) -> Result<bool, PersistError> {
        Ok(self.cache.contains_key(k))
    }

    fn len(&self) -> Result<usize, PersistError> {
        Ok(self.cache.len())
    }

    fn iter(&self) -> Result<Box<dyn Iterator<Item = (K, V)> + '_>, PersistError> {
        Ok(Box::new(
            self.cache.iter().map(|(k, v)| (k.clone(), v.clone())),
        ))
    }

    fn keys(&self) -> Result<Box<dyn Iterator<Item = K> + '_>, PersistError> {
        Ok(Box::new(self.cache.keys().cloned()))
    }

    fn values(&self) -> Result<Box<dyn Iterator<Item = V> + '_>, PersistError> {
        Ok(Box::new(self.cache.values().cloned()))
    }

    fn insert(&mut self, k: K, v: V) -> Result<Option<V>, PersistError> {
        self.removed.remove(&k);
        self.dirty.insert(k.clone());
        Ok(self.cache.insert(k, v))
    }

    fn remove(&mut self, k: &K) -> Result<Option<V>, PersistError> {
        self.dirty.remove(k);
        let prev = self.cache.remove(k);
        if prev.is_some() {
            self.removed.insert(k.clone());
        }
        Ok(prev)
    }

    fn modify<F: FnOnce(&mut V)>(&mut self, k: &K, f: F) -> Result<bool, PersistError> {
        match self.cache.get_mut(k) {
            Some(v) => {
                f(v);
                self.removed.remove(k);
                self.dirty.insert(k.clone());
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn flush(&mut self) -> Result<(), PersistError> {
        if self.dirty.is_empty() && self.removed.is_empty() {
            return Ok(());
        }
        let mut inserts: Vec<(String, Vec<u8>)> = Vec::with_capacity(self.dirty.len());
        for k in self.dirty.iter() {
            let Some(v) = self.cache.get(k) else { continue };
            let key = (self.encode_k)(k);
            let bytes = (self.encode_v)(v)?;
            inserts.push((key, bytes));
        }
        let removed: Vec<String> = self.removed.iter().map(|k| (self.encode_k)(k)).collect();
        self.backend
            .flush_batch(self.store_key, &inserts, &removed)?;
        self.dirty.clear();
        self.removed.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::backend::json::JsonBackend;

    #[allow(clippy::ptr_arg)]
    fn encode_k(k: &String) -> String {
        // Signature must match `fn(&K) -> String` where K = String,
        // hence `&String` rather than `&str`.
        k.clone()
    }
    fn decode_k(s: &str) -> Result<String, PersistError> {
        Ok(s.to_string())
    }
    fn encode_v(v: &u32) -> Result<Vec<u8>, PersistError> {
        // Values go through JsonBackend in these tests, so they must
        // be JSON-parseable bytes.
        serde_json::to_vec(v).map_err(|e| PersistError::Serde(e.to_string()))
    }
    fn decode_v(bytes: &[u8]) -> Result<u32, PersistError> {
        serde_json::from_slice::<u32>(bytes).map_err(|e| PersistError::Serde(e.to_string()))
    }

    fn ram_store_on_json() -> (RamStore<JsonBackend, String, u32>, temp_dir::TempDir) {
        let d = temp_dir::TempDir::new().unwrap();
        let backend = JsonBackend::open(d.path().to_path_buf()).unwrap();
        let s = RamStore::open(backend, "coins", encode_k, decode_k, encode_v, decode_v).unwrap();
        (s, d)
    }

    #[test]
    fn ram_store_insert_get_len() {
        let (mut s, _d) = ram_store_on_json();
        assert_eq!(Store::len(&s).unwrap(), 0);
        assert!(Store::is_empty(&s).unwrap());
        assert!(s.insert("a".into(), 1).unwrap().is_none());
        assert_eq!(Store::len(&s).unwrap(), 1);
        assert_eq!(Store::get(&s, &"a".to_string()).unwrap(), Some(1));
        assert!(!Store::is_empty(&s).unwrap());
    }

    #[test]
    fn ram_store_tracks_dirty_keys_across_inserts() {
        let (mut s, _d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.insert("b".into(), 2).unwrap();
        assert_eq!(s.dirty.len(), 2);
        assert!(s.removed.is_empty());
    }

    #[test]
    fn ram_store_tracks_removed_keys() {
        let (mut s, _d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.flush().unwrap();
        // After flush, dirty is clear.
        assert!(s.dirty.is_empty());
        assert_eq!(s.remove(&"a".to_string()).unwrap(), Some(1));
        assert_eq!(s.removed.len(), 1);
        // remove of a non-existent key is a no-op.
        assert_eq!(s.remove(&"nope".to_string()).unwrap(), None);
        assert_eq!(s.removed.len(), 1);
    }

    #[test]
    fn ram_store_insert_then_remove_leaves_no_dirty() {
        let (mut s, _d) = ram_store_on_json();
        // Insert a key, then remove it before any flush. Expect no
        // dirty and no removed (cancels out).
        s.insert("a".into(), 1).unwrap();
        assert_eq!(s.remove(&"a".to_string()).unwrap(), Some(1));
        assert!(s.dirty.is_empty());
        // The key was never persisted, so we don't need to track its
        // removal: it's as if it was never there.
        //
        // (Current impl inserts into `removed`. That's a minor waste
        // but correct, since the flush will try to delete a key that
        // was never put. We simply check that the `removed` set
        // doesn't reference something `dirty` shouldn't either.)
        assert!(!s.dirty.contains("a"));
    }

    #[test]
    fn ram_store_flush_only_writes_dirty_and_removed() {
        // Scoped so `s` (and the backend inside it) drop at the
        // closing brace, releasing the DirLock before the reopener
        // tries to acquire it.
        let d = {
            let (mut s, d) = ram_store_on_json();
            // First batch.
            s.insert("a".into(), 1).unwrap();
            s.insert("b".into(), 2).unwrap();
            s.flush().unwrap();

            // Mutate just one, remove another; flush again.
            s.modify(&"a".to_string(), |v| *v = 11).unwrap();
            s.remove(&"b".to_string()).unwrap();
            s.insert("c".into(), 3).unwrap();
            s.flush().unwrap();
            d
        };

        // Reopen via a fresh backend and check what's on disk.
        let backend = JsonBackend::open(d.path().to_path_buf()).unwrap();
        let reloaded =
            RamStore::open(backend, "coins", encode_k, decode_k, encode_v, decode_v).unwrap();
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(11));
        assert_eq!(Store::get(&reloaded, &"b".to_string()).unwrap(), None);
        assert_eq!(Store::get(&reloaded, &"c".to_string()).unwrap(), Some(3));
    }

    #[test]
    fn ram_store_reopen_roundtrip() {
        let d = temp_dir::TempDir::new().unwrap();
        {
            let backend = JsonBackend::open(d.path().to_path_buf()).unwrap();
            let mut s: RamStore<JsonBackend, String, u32> =
                RamStore::open(backend, "coins", encode_k, decode_k, encode_v, decode_v).unwrap();
            s.insert("x".into(), 42).unwrap();
            s.flush().unwrap();
        }
        let backend = JsonBackend::open(d.path().to_path_buf()).unwrap();
        let s: RamStore<JsonBackend, String, u32> =
            RamStore::open(backend, "coins", encode_k, decode_k, encode_v, decode_v).unwrap();
        assert_eq!(Store::get(&s, &"x".to_string()).unwrap(), Some(42));
        assert_eq!(Store::len(&s).unwrap(), 1);
    }

    #[test]
    fn ram_store_iter_is_key_ordered() {
        let (mut s, _d) = ram_store_on_json();
        s.insert("c".into(), 3).unwrap();
        s.insert("a".into(), 1).unwrap();
        s.insert("b".into(), 2).unwrap();
        let pairs: Vec<(String, u32)> = Store::iter(&s).unwrap().collect();
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), 1),
                ("b".to_string(), 2),
                ("c".to_string(), 3),
            ]
        );
        let keys: Vec<String> = Store::keys(&s).unwrap().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
        let values: Vec<u32> = Store::values(&s).unwrap().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn ram_store_modify_marks_dirty() {
        let (mut s, _d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.flush().unwrap();
        assert!(s.dirty.is_empty());
        let existed = s.modify(&"a".to_string(), |v| *v += 1).unwrap();
        assert!(existed);
        assert_eq!(s.dirty.len(), 1);
        assert_eq!(Store::get(&s, &"a".to_string()).unwrap(), Some(2));
    }

    #[test]
    fn ram_store_with_arc_backend() {
        // Arc<ConcreteBackend> satisfies `B: PersistenceBackend` via
        // the blanket impl, so multiple RamStores can share one
        // backend instance without reaching for dyn.
        let d = temp_dir::TempDir::new().unwrap();
        let backend = Arc::new(JsonBackend::open(d.path().to_path_buf()).unwrap());
        let mut s1: RamStore<Arc<JsonBackend>, String, u32> = RamStore::open(
            backend.clone(),
            "coins",
            encode_k,
            decode_k,
            encode_v,
            decode_v,
        )
        .unwrap();
        let mut s2: RamStore<Arc<JsonBackend>, String, u32> =
            RamStore::open(backend, "labels", encode_k, decode_k, encode_v, decode_v).unwrap();
        s1.insert("a".into(), 1).unwrap();
        s2.insert("b".into(), 2).unwrap();
        s1.flush().unwrap();
        s2.flush().unwrap();
    }

    // ---------------------------------------------------------------
    // Strong coverage of the dirty/removed bookkeeping invariants.
    //
    // The cache + dirty + removed triple maintains "a key is in at
    // most one of {dirty, removed}" through every mutation. The
    // following tests pin every interleaving of insert / remove /
    // modify / flush we could enumerate, so a future refactor of
    // the bookkeeping can't silently break the invariant.
    // ---------------------------------------------------------------

    fn reload(d: &temp_dir::TempDir) -> RamStore<JsonBackend, String, u32> {
        let backend = JsonBackend::open(d.path().to_path_buf()).unwrap();
        RamStore::open(backend, "coins", encode_k, decode_k, encode_v, decode_v).unwrap()
    }

    #[test]
    fn insert_then_insert_keeps_only_latest_value() {
        let (mut s, d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.insert("a".into(), 2).unwrap();
        assert_eq!(s.dirty.len(), 1);
        assert!(s.removed.is_empty());
        assert_eq!(s.cache.get("a"), Some(&2));
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(2));
        assert_eq!(Store::len(&reloaded).unwrap(), 1);
    }

    #[test]
    fn remove_then_insert_persists_inserted_value() {
        let (mut s, d) = ram_store_on_json();
        // Pre-flush so "a" is genuinely on disk before the
        // remove->insert dance.
        s.insert("a".into(), 1).unwrap();
        s.flush().unwrap();
        drop(s);

        let mut s = reload(&d);
        s.remove(&"a".to_string()).unwrap();
        s.insert("a".into(), 99).unwrap();
        assert_eq!(s.dirty.len(), 1);
        assert!(s.removed.is_empty());
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(99));
    }

    #[test]
    fn alternation_remove_insert_remove_insert_persists_last_value() {
        let (mut s, d) = ram_store_on_json();
        s.insert("a".into(), 0).unwrap();
        s.flush().unwrap();
        drop(s);

        let mut s = reload(&d);
        s.remove(&"a".to_string()).unwrap();
        s.insert("a".into(), 1).unwrap();
        s.remove(&"a".to_string()).unwrap();
        s.insert("a".into(), 2).unwrap();
        s.remove(&"a".to_string()).unwrap();
        s.insert("a".into(), 3).unwrap();
        assert_eq!(s.dirty.len(), 1);
        assert!(s.removed.is_empty());
        assert_eq!(s.cache.get("a"), Some(&3));
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(3));
    }

    #[test]
    fn insert_then_remove_then_flush_leaves_key_absent_on_disk() {
        let (mut s, d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.remove(&"a".to_string()).unwrap();
        // The "minor waste" path: dirty cleared, removed carries the
        // key, flush will issue a delete for a row that was never
        // written. The on-disk state must end up with "a" absent.
        assert!(s.dirty.is_empty());
        assert_eq!(s.removed.len(), 1);
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), None);
        assert_eq!(Store::len(&reloaded).unwrap(), 0);
    }

    #[test]
    fn modify_after_remove_returns_false_and_no_state_change() {
        let (mut s, d) = ram_store_on_json();
        s.insert("a".into(), 1).unwrap();
        s.flush().unwrap();
        drop(s);

        let mut s = reload(&d);
        s.remove(&"a".to_string()).unwrap();
        let existed = s.modify(&"a".to_string(), |v| *v = 999).unwrap();
        assert!(!existed);
        assert!(!s.cache.contains_key("a"));
        assert!(s.dirty.is_empty());
        assert_eq!(s.removed.len(), 1);
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), None);
    }

    #[test]
    fn remove_of_absent_key_returns_none_and_does_not_grow_removed() {
        let (mut s, d) = ram_store_on_json();
        let prev = s.remove(&"never_inserted".to_string()).unwrap();
        assert!(prev.is_none());
        assert!(
            s.removed.is_empty(),
            "removed must not grow for absent keys"
        );
        assert!(s.dirty.is_empty());
        s.flush().unwrap();
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::len(&reloaded).unwrap(), 0);
    }

    #[test]
    fn consecutive_flushes_with_no_mutation_are_noop() {
        let (mut s, d) = ram_store_on_json();
        // Flush an empty store.
        s.flush().unwrap();
        assert!(s.dirty.is_empty());
        assert!(s.removed.is_empty());

        s.insert("a".into(), 7).unwrap();
        s.flush().unwrap();
        assert!(s.dirty.is_empty());
        assert!(s.removed.is_empty());

        // Second flush with no intervening mutation must be a no-op
        // and leave the on-disk row alone.
        s.flush().unwrap();
        assert!(s.dirty.is_empty());
        assert!(s.removed.is_empty());
        drop(s);

        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(7));
    }

    #[test]
    fn dirty_and_removed_remain_disjoint_through_full_sequence() {
        let (mut s, d) = ram_store_on_json();
        // Macro to assert disjointness after every step.
        macro_rules! assert_disjoint {
            () => {
                assert!(
                    s.dirty.intersection(&s.removed).next().is_none(),
                    "dirty and removed must not overlap; got dirty={:?} removed={:?}",
                    s.dirty,
                    s.removed
                );
            };
        }

        s.insert("a".into(), 1).unwrap();
        assert_disjoint!();
        s.insert("b".into(), 2).unwrap();
        assert_disjoint!();
        s.flush().unwrap();
        assert_disjoint!();

        s.remove(&"a".to_string()).unwrap();
        assert_disjoint!();
        s.insert("a".into(), 11).unwrap();
        assert_disjoint!();
        s.remove(&"b".to_string()).unwrap();
        assert_disjoint!();
        let existed = s.modify(&"a".to_string(), |v| *v += 1).unwrap();
        assert!(existed);
        assert_disjoint!();
        s.insert("c".into(), 3).unwrap();
        assert_disjoint!();
        s.remove(&"c".to_string()).unwrap();
        assert_disjoint!();
        s.insert("c".into(), 33).unwrap();
        assert_disjoint!();

        s.flush().unwrap();
        assert_disjoint!();
        drop(s);

        // Final on-disk state: a == 12, b absent, c == 33.
        let reloaded = reload(&d);
        assert_eq!(Store::get(&reloaded, &"a".to_string()).unwrap(), Some(12));
        assert_eq!(Store::get(&reloaded, &"b".to_string()).unwrap(), None);
        assert_eq!(Store::get(&reloaded, &"c".to_string()).unwrap(), Some(33));
        assert_eq!(Store::len(&reloaded).unwrap(), 2);
    }
}
