//! Events the scanner reports, and the errors it surfaces.

#[cfg(feature = "sp")]
use miniscript::bitcoin::OutPoint;
use miniscript::bitcoin::Txid;

use bwk_persist::PersistError;

use crate::{client::CoinError, header_store::InvalidCause};

/// Notifications sent by an Account to signal events.
#[derive(Debug)]
pub enum Notification {
    Electrum(TxListenerNotif),
    AddressTipChanged,
    CoinUpdate,
    PaymentHistoryUpdated,
    InvalidElectrumConfig,
    InvalidLookAhead,
    Stopped,
    Error(Error),
    /// A chain-tip-advance (CTA) pass mutated tx state in response to a
    /// HeaderStore update.
    HeaderStoreUpdated,
    HeaderProgress(crate::header_store::HeaderProgressEvent),
    /// A merkle proof failed verification, or the header store itself
    /// failed validation; the affected entry was refused promotion.
    ValidationFailed(ValidationFailure),
    #[cfg(feature = "sp")]
    Sp(SpNotification),
}

/// Silent Payments notification variants (behind `sp` feature).
#[cfg(feature = "sp")]
#[derive(Debug, Clone)]
pub enum SpNotification {
    /// Scanner is starting
    StartingScan,
    /// Scan has started
    ScanStarted { start: u32, end: u32 },
    /// Scanner failed to start
    FailStartScanning { message: String },
    /// Scan failed during scanning
    FailScan { message: String },
    /// Scanner is stopping
    StoppingScan,
    /// Scanner has stopped
    ScanStopped,
    /// Receive (output) scan progress update
    ScanReceiveProgress { current: u32, end: u32 },
    /// Spend (input) sweep progress update
    ScanSpendProgress { current: u32, end: u32 },
    /// Scan completed successfully
    ScanCompleted,
    /// A new output was found
    NewOutput(OutPoint),
    /// An output was spent
    OutputSpent(OutPoint),
    /// Broadcast completed and local state was updated
    Broadcasted { txid: Txid },
    /// Broadcast failed before local state was updated
    FailBroadcast { message: String },
    /// Continuous mode: at chain tip, waiting for new blocks
    WaitingForBlocks { tip_height: u32 },
    /// Continuous mode: new block(s) detected
    NewBlocksDetected { from_height: u32, to_height: u32 },
}

#[derive(Debug, Clone)]
pub enum ValidationFailure {
    /// Merkle proof for a tx at a height did not verify against the header.
    MerkleProof { txid: Txid, height: u32 },
    /// The header store rejected its own replay validation.
    HeaderStore(InvalidCause),
}

impl From<TxListenerNotif> for Notification {
    fn from(value: TxListenerNotif) -> Self {
        Notification::Electrum(value)
    }
}

impl From<Error> for Notification {
    fn from(value: Error) -> Self {
        Self::Error(value)
    }
}

#[cfg(feature = "sp")]
impl From<SpNotification> for Notification {
    fn from(sp: SpNotification) -> Self {
        Notification::Sp(sp)
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    CreatePool,
    JoinPool,
    InvalidOutPoint,
    CoinMissing,
    InvalidDenomination,
    RelayMissing,
    WrongElectrumConfig,
    PoolMissing,
    WrongKeyType,
    Satisfaction,
    HeaderStoreRestart,
}

/// Error returned when opening a scan's stores from disk.
#[derive(Debug)]
pub enum OpenError {
    /// The config carried an empty account name.
    EmptyAccount,
    /// The persistence backend could not be built or the store bundle
    /// could not be read (e.g. the account directory is already locked,
    /// or a stored blob failed to decode).
    Persist(PersistError),
    /// The configured Electrum endpoint could not be reached while building
    /// the account's [`HeaderStore`](crate::header_store::HeaderStore). Fails
    /// loud rather than silently opening a worker-less store.
    HeaderStore(crate::header_store::StartError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::EmptyAccount => write!(f, "account name must not be empty"),
            OpenError::Persist(e) => write!(f, "{e}"),
            OpenError::HeaderStore(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<PersistError> for OpenError {
    fn from(e: PersistError) -> Self {
        OpenError::Persist(e)
    }
}

impl From<crate::header_store::StartError> for OpenError {
    fn from(e: crate::header_store::StartError) -> Self {
        OpenError::HeaderStore(e)
    }
}

/// Represents notifications related to transaction listeners.
#[derive(Debug)]
pub enum TxListenerNotif {
    Started,
    Connected(String),
    Error(TxListenerError),
    Stopped,
}

/// Errors surfaced through [`TxListenerNotif::Error`].
#[derive(Debug, thiserror::Error)]
pub enum TxListenerError {
    #[error("failed to create electrum client: {0}")]
    Client(#[from] crate::client::Error),
    #[error(transparent)]
    Coin(#[from] CoinError),
    #[error("address store disconnected")]
    AddressStoreDisconnected,
    #[error("statuses store unavailable")]
    StatusesUnavailable,
}
