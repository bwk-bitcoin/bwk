//! Errors the transaction listener surfaces through its notifications.

use crate::client::CoinError;

/// Why the transaction listener could not go on, reported through
/// [`TxListenerNotif::Error`](crate::notification::TxListenerNotif::Error).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to create electrum client: {0}")]
    Client(#[from] crate::client::Error),
    #[error(transparent)]
    Coin(#[from] CoinError),
    #[error("address store disconnected")]
    AddressStoreDisconnected,
    #[error("statuses store unavailable")]
    StatusesUnavailable,
}
