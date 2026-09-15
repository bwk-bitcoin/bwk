//! Storage layer: typed `(Key, Value)` stores layered over a
//! [`PersistenceBackend`](crate::backend::PersistenceBackend).
//!
//! The [`Store`] trait is the shared surface every caching / write-back /
//! write-through strategy exposes. The only concrete impl today is
//! [`RamStore`](ram::RamStore), a RAM-cached + write-back implementation generic over
//! any backend; future strategies (DB-per-op, online) satisfy the same
//! trait without changing callers.

use crate::PersistError;

pub mod ram;

/// A typed keyed store over `(Key, Value)` entries.
///
/// Implementations choose their storage strategy: the [`RamStore`](ram::RamStore)
/// provided here is a RAM-cached + write-back impl parameterised on a
/// [`PersistenceBackend`](crate::backend::PersistenceBackend). Future impls
/// could back a network service, a DB query-per-op strategy, or an LRU
/// layer. They'd satisfy the same trait without callers changing.
///
/// Every method returns `Result` so strategies whose reads can fail
/// (DB, online) are expressible without a later surface change;
/// today's RAM impl always returns `Ok(_)` on read paths.
pub trait Store {
    type Key: Ord + Clone;
    type Value: Clone;

    // Queries -----------------------------------------------------------------

    /// Fetch the value for `k`, or `Ok(None)` if absent.
    fn get(&self, k: &Self::Key) -> Result<Option<Self::Value>, PersistError>;

    /// Return whether `k` is present.
    fn contains_key(&self, k: &Self::Key) -> Result<bool, PersistError> {
        self.get(k).map(|v| v.is_some())
    }

    /// Number of entries.
    fn len(&self) -> Result<usize, PersistError>;

    /// Whether the store has no entries.
    fn is_empty(&self) -> Result<bool, PersistError> {
        self.len().map(|n| n == 0)
    }

    // Iteration ---------------------------------------------------------------

    /// Iterate every entry, ordered by key. Items are owned so non-RAM
    /// strategies don't need to hand out refs into storage they don't
    /// hold.
    #[allow(clippy::type_complexity)]
    fn iter(&self)
        -> Result<Box<dyn Iterator<Item = (Self::Key, Self::Value)> + '_>, PersistError>;

    /// Iterate keys. Default maps over [`Self::iter`]; impls override
    /// if they can skip value materialisation.
    fn keys(&self) -> Result<Box<dyn Iterator<Item = Self::Key> + '_>, PersistError> {
        Ok(Box::new(self.iter()?.map(|(k, _)| k)))
    }

    /// Iterate values. Default maps over [`Self::iter`].
    fn values(&self) -> Result<Box<dyn Iterator<Item = Self::Value> + '_>, PersistError> {
        Ok(Box::new(self.iter()?.map(|(_, v)| v)))
    }

    // Mutation ----------------------------------------------------------------

    /// Insert `(k, v)`, overwriting any existing value. Returns the
    /// previous value if any.
    fn insert(&mut self, k: Self::Key, v: Self::Value)
        -> Result<Option<Self::Value>, PersistError>;

    /// Remove `k`'s value. Returns the removed value if any.
    fn remove(&mut self, k: &Self::Key) -> Result<Option<Self::Value>, PersistError>;

    /// Mutate the value at `k` in place. For a RAM impl this is a
    /// mutable borrow plus dirty mark. For a write-through DB impl
    /// it's effectively get -> apply `f` -> put. Returns `true` if the
    /// key existed (`f` ran), `false` if absent.
    fn modify<F: FnOnce(&mut Self::Value)>(
        &mut self,
        k: &Self::Key,
        f: F,
    ) -> Result<bool, PersistError>;

    /// Flush any pending in-memory changes through to the underlying
    /// storage. A pure write-through impl treats this as a no-op; a
    /// write-back impl (like [`RamStore`](ram::RamStore)) emits the accumulated
    /// dirty / removed sets.
    fn flush(&mut self) -> Result<(), PersistError>;
}
