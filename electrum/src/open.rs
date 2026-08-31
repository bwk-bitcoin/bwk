//! Opening a scan's stores from disk.

use bwk_descriptor::derivator;
use bwk_persist::PersistError;

use crate::header_store::StartError;

/// Why opening a scan's stores failed. A store that cannot be opened is
/// reported rather than skipped: an account silently opening empty, or with a
/// worker-less header store, hides data loss behind a working wallet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("account name must not be empty")]
    EmptyAccount,
    #[error("failed to open the scan stores: {0}")]
    Persist(#[from] PersistError),
    #[error("failed to start the header store: {0}")]
    HeaderStore(#[from] StartError),
    #[error("the scan cannot derive from this descriptor: {0}")]
    Descriptor(#[from] derivator::Error),
}
