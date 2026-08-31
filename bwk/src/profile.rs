//! The wallet half of the storage profile.
//!
//! [`bwk_electrum::profile::ScanProfile`] declares the stores scanning needs.
//! This adds the one only a wallet has: where hot signers are kept.

use std::sync::Arc;

use bwk_electrum::profile::{
    DefaultBackend, OpenScanFromBackend, RamProfile, ScanProfile, ScanStores,
};
use bwk_persist::{PersistError, PersistenceBackend, RamStore, Store};
use bwk_sign::{
    signing_manager::{
        decode_fingerprint, decode_json_signer, encode_fingerprint, encode_json_signer,
    },
    JsonSigner,
};
use miniscript::bitcoin::bip32;

/// A [`ScanProfile`] that also stores signers.
pub trait StorageProfile: ScanProfile {
    type SignerStore: Store<Key = bip32::Fingerprint, Value = JsonSigner> + Send + Sync + 'static;
}

impl<B: PersistenceBackend + Clone + 'static> StorageProfile for RamProfile<B> {
    type SignerStore = RamStore<B, bip32::Fingerprint, JsonSigner>;
}

/// The scanning stores plus the signer store.
pub struct Stores<P: StorageProfile> {
    pub scan: ScanStores<P>,
    pub signers: P::SignerStore,
}

/// Profiles that can open their full store bundle from a pair of backends.
///
/// `secrets_backend` only carries hot-signer material. Under
/// [`bwk_persist::PersistenceKind::Sqlite`] the caller passes
/// [`bwk_persist::NoopBackend`] so signer state never reaches the database;
/// otherwise both arguments are the same handle.
pub trait OpenFromBackend: StorageProfile + OpenScanFromBackend {
    fn open(
        backend: Arc<dyn PersistenceBackend>,
        secrets_backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Stores<Self>, PersistError>;
}

impl OpenFromBackend for RamProfile<DefaultBackend> {
    fn open(
        backend: Arc<dyn PersistenceBackend>,
        secrets_backend: Arc<dyn PersistenceBackend>,
    ) -> Result<Stores<Self>, PersistError> {
        Ok(Stores {
            scan: <Self as OpenScanFromBackend>::open(backend)?,
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
}
