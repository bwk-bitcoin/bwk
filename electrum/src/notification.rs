//! Events the scanner reports, and the errors it surfaces.

use std::sync::{mpsc, Arc, Mutex};

use miniscript::bitcoin::{Amount, OutPoint, Txid};
#[cfg(feature = "sp")]
use miniscript::{Descriptor, MiniscriptKey};

use crate::{header_store::InvalidCause, tx_listener};

/// The notification channel of a scanner, shared by every store and thread it
/// owns, so [`set`](NotificationSender::set) redirects them all at once.
#[derive(Debug, Clone)]
pub struct NotificationSender(Arc<Mutex<mpsc::Sender<Notification>>>);

impl NotificationSender {
    pub fn send(&self, notification: Notification) -> Result<(), mpsc::SendError<Notification>> {
        self.0.lock().expect("poisoned").send(notification)
    }

    pub fn set(&self, sender: mpsc::Sender<Notification>) {
        *self.0.lock().expect("poisoned") = sender;
    }
}

impl From<mpsc::Sender<Notification>> for NotificationSender {
    fn from(sender: mpsc::Sender<Notification>) -> Self {
        Self(Arc::new(Mutex::new(sender)))
    }
}

/// Notifications sent by an Account to signal events.
#[derive(Debug)]
pub enum Notification {
    Electrum(TxListenerNotif),
    AddressTipChanged,
    CoinUpdate,
    /// `outpoint` entered the coin store of the scanner named `account`.
    CoinReceived {
        account: String,
        outpoint: OutPoint,
        amount: Amount,
        height: Option<u64>,
    },
    /// A coin of the scanner named `account` turned `Spent`/`BeingSpend`, or
    /// left its coin store while unspent.
    CoinSpent {
        account: String,
        outpoint: OutPoint,
    },
    PaymentHistoryUpdated,
    InvalidElectrumConfig,
    InvalidLookAhead,
    /// The header store could not be restarted against its endpoint, so the
    /// chain it promotes against stops advancing.
    HeaderStoreRestart,
    /// A chain-tip-advance (CTA) pass mutated tx state in response to a
    /// HeaderStore update.
    HeaderStoreUpdated,
    HeaderProgress(crate::header_store::HeaderProgressEvent),
    /// The header store's merkle client ended, so no inclusion proof is
    /// fetched any more; confirmed entries stay unverified until the store
    /// is restarted.
    MerkleFetchStopped,
    /// A merkle proof failed verification, or the header store itself
    /// failed validation; the affected entry was refused promotion.
    ValidationFailed(ValidationFailure),
    #[cfg(feature = "sp")]
    Sp(SpNotification),
}

/// The script type of a BIP32 sub-account of a Silent Payments account, read
/// from its descriptor.
#[cfg(feature = "sp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAccountKind {
    /// A `wpkh(..)` descriptor.
    Segwit,
    /// A `tr(..)` descriptor.
    Taproot,
    /// Any other descriptor.
    Other,
}

#[cfg(feature = "sp")]
impl<Pk: MiniscriptKey> From<&Descriptor<Pk>> for SubAccountKind {
    fn from(descriptor: &Descriptor<Pk>) -> Self {
        match descriptor {
            Descriptor::Wpkh(_) => Self::Segwit,
            Descriptor::Tr(_) => Self::Taproot,
            _ => Self::Other,
        }
    }
}

/// Where a coin lives inside a composite Silent Payments account.
#[cfg(feature = "sp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinOrigin {
    /// The Silent Payments main account.
    Sp,
    /// An embedded BIP32 sub-account.
    SubAccount {
        /// Its position among the account's sub-account scanners.
        index: usize,
        kind: SubAccountKind,
    },
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
    /// Scanner has stopped, or a scan was cancelled before reaching its end.
    /// Carries the receive and spend frontiers persisted at that point, `None`
    /// for a frontier never recorded.
    ScanStopped {
        last_scanned: Option<u32>,
        last_spend: Option<u32>,
    },
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
    /// The chain reorganized above `fork_height`: what the scan recorded above
    /// it was rolled back and is scanned again
    Reorg { fork_height: u32 },
    /// `outpoint` entered the coin store of the sub-account at `origin`.
    SubAccountCoinReceived {
        origin: CoinOrigin,
        outpoint: OutPoint,
        amount: Amount,
        height: Option<u64>,
    },
    /// A coin of the sub-account at `origin` turned `Spent`/`BeingSpend`, or
    /// left its coin store while unspent.
    SubAccountCoinSpent {
        origin: CoinOrigin,
        outpoint: OutPoint,
    },
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

#[cfg(feature = "sp")]
impl From<SpNotification> for Notification {
    fn from(sp: SpNotification) -> Self {
        Notification::Sp(sp)
    }
}

/// Represents notifications related to transaction listeners.
#[derive(Debug)]
pub enum TxListenerNotif {
    Started,
    Connected(String),
    Error(tx_listener::Error),
    /// The listener exited on a requested stop.
    Stopped,
    /// The connection dropped: the listener has exited and does not reconnect,
    /// restarting it is the consumer's call.
    Disconnected,
}

#[cfg(all(test, feature = "sp"))]
mod tests {
    use std::str::FromStr;

    use miniscript::{Descriptor, DescriptorPublicKey};

    use crate::notification::SubAccountKind;

    const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn kind_of(descriptor: &str) -> SubAccountKind {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor).unwrap();
        SubAccountKind::from(&descriptor)
    }

    #[test]
    fn sub_account_kind_from_descriptor() {
        assert_eq!(kind_of(&format!("wpkh({KEY})")), SubAccountKind::Segwit);
        assert_eq!(kind_of(&format!("tr({KEY})")), SubAccountKind::Taproot);
        assert_eq!(kind_of(&format!("pkh({KEY})")), SubAccountKind::Other);
        assert_eq!(kind_of(&format!("sh(wpkh({KEY}))")), SubAccountKind::Other);
    }
}
