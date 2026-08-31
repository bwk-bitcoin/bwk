//! The wallet half of the storage profile.
//!
//! [`bwk_electrum::profile::ScanProfile`] declares the stores scanning needs.
//! This adds the one only a wallet has: where hot signers are kept.

use std::sync::Arc;

use bwk_electrum::profile::{
    decode_status_key, decode_status_value, encode_status_key, encode_status_value,
    open_ram_stores, DefaultBackend, RamProfile, ScanProfile,
};
use bwk_persist::{PersistError, PersistenceBackend, RamStore, Store};
use bwk_sign::{
    signing_manager::{
        decode_fingerprint, decode_json_signer, encode_fingerprint, encode_json_signer,
    },
    JsonSigner,
};
use miniscript::bitcoin::{bip32, block::Header};

/// A [`ScanProfile`] that also stores signers.
pub trait StorageProfile: ScanProfile {
    type SignerStore: Store<Key = bip32::Fingerprint, Value = JsonSigner> + Send + Sync + 'static;
}

impl<B: PersistenceBackend + Clone + 'static> StorageProfile for RamProfile<B> {
    type SignerStore = RamStore<B, bip32::Fingerprint, JsonSigner>;
}

/// The scanning stores plus the signer store.
pub struct Stores<P: StorageProfile> {
    pub tx: P::TxStore,
    pub label: P::LabelStore,
    pub statuses: P::StatusesStore,
    pub account: P::AccountStore,
    pub signers: P::SignerStore,
}

/// Reopens the statuses store from the backend, the fallback an account takes
/// when a panicked listener could not hand its own store back.
pub type ReopenStatuses<P> =
    Arc<dyn Fn() -> Result<<P as ScanProfile>::StatusesStore, PersistError> + Send + Sync>;

/// Profiles that can open their full store bundle from a pair of backends.
///
/// `secrets_backend` only carries hot-signer material. Under
/// [`bwk_persist::PersistenceKind::Sqlite`] the caller passes
/// [`bwk_persist::NoopBackend`] so signer state never reaches the database;
/// otherwise both arguments are the same handle.
pub trait OpenFromBackend:
    StorageProfile<HeaderStore = RamStore<DefaultBackend, u32, [u8; Header::SIZE]>> + Sized
{
    fn open(
        backend: Arc<dyn PersistenceBackend>,
        secrets_backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Stores<Self>, PersistError>;

    /// Reopen just the statuses store, the recovery path when a panicked
    /// listener thread cannot hand its store back.
    fn open_statuses(
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self::StatusesStore, PersistError>;
}

impl OpenFromBackend for RamProfile<DefaultBackend> {
    fn open(
        backend: Arc<dyn PersistenceBackend>,
        secrets_backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Stores<Self>, PersistError> {
        let ram = open_ram_stores(backend)?;
        Ok(Stores {
            tx: ram.tx,
            label: ram.label,
            statuses: ram.statuses,
            account: ram.account,
            signers: RamStore::open(
                secrets_backend,
                bwk_persist::SIGNERS_STORE_KEY,
                encode_fingerprint,
                decode_fingerprint,
                encode_json_signer,
                decode_json_signer,
            )?,
        })
    }

    fn open_statuses(
        backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Self::StatusesStore, PersistError> {
        RamStore::open(
            backend,
            bwk_persist::STATUSES_STORE_KEY,
            encode_status_key,
            decode_status_key,
            encode_status_value,
            decode_status_value,
        )
    }
}
