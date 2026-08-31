//! Storage profile for `bwk_sp::Account`.
//!
//! Names the two SP-specific stores (coins / SP txs). Labels are
//! stored through [`bwk::bwk_electrum::label_store::LabelStore`] directly: silent-payment label
//! keys are a strict subset of bwk's `LabelKey` (no `Address` variant
//! is ever produced by SP code paths), so a separate type would just
//! duplicate the encode/decode plumbing.

use std::marker::PhantomData;

use bitcoin::{OutPoint, Txid};
use bwk::{
    bwk_electrum::profile::DefaultBackend,
    persist::{PersistenceBackend, RamStore, Store},
};

use crate::account::{coin_store::SpCoinEntry, tx_store::SpTxEntry};

/// Names the two SP-specific stores.
pub trait SpStorageProfile: 'static + Send + Sync {
    type CoinStore: Store<Key = OutPoint, Value = SpCoinEntry> + Send + Sync + 'static;
    type SpTxStore: Store<Key = Txid, Value = SpTxEntry> + Send + Sync + 'static;
}

/// RAM-cached, write-back profile for SP: every store is a
/// [`RamStore<B, K, V>`] over some [`PersistenceBackend`].
pub struct SpRamProfile<B: PersistenceBackend = DefaultBackend>(PhantomData<B>);

impl<B: PersistenceBackend> std::fmt::Debug for SpRamProfile<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpRamProfile")
    }
}

impl<B: PersistenceBackend + Clone + 'static> SpStorageProfile for SpRamProfile<B> {
    type CoinStore = RamStore<B, OutPoint, SpCoinEntry>;
    type SpTxStore = RamStore<B, Txid, SpTxEntry>;
}
