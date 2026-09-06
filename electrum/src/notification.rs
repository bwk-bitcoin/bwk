//! Events the scanner reports, and the errors it surfaces.

use std::collections::BTreeMap;

use bwk_sign::{
    bwk_keys::keys::OXpub,
    identity::{SignerId, SignerInfo},
    protocol::RequestId,
};
#[cfg(feature = "sp")]
use miniscript::bitcoin::OutPoint;
use miniscript::bitcoin::Txid;

use crate::{header_store::InvalidCause, tx_listener};

/// Notifications sent by an Account to signal events.
#[derive(Debug)]
pub enum Notification {
    Electrum(TxListenerNotif),
    AddressTipChanged,
    CoinUpdate,
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
    Signer(SignerNotification),
    #[cfg(feature = "sp")]
    Sp(SpNotification),
}

/// Results and events from every attached signing manager. Not feature
/// gated: every account has managers, even a watch-only one with none
/// attached.
#[derive(Debug)]
pub enum SignerNotification {
    ManagerAttached {
        manager: String,
    },
    ManagerDetached {
        manager: String,
    },
    Signers(Vec<SignerInfo>),
    Initialized {
        request: RequestId,
        signer: SignerId,
    },
    Info {
        request: RequestId,
        signer: SignerId,
        info: BTreeMap<String, String>,
    },
    Xpub {
        request: RequestId,
        signer: SignerId,
        xpub: OXpub,
    },
    DescriptorIsRegistered {
        request: RequestId,
        signer: SignerId,
        registered: bool,
    },
    DescriptorRegistered {
        request: RequestId,
        signer: SignerId,
        registered: bool,
    },
    /// The bytes may or may not be fully signed: an updated PSBT is simply
    /// recorded, not combined or verified here. Emitted when no verifier is
    /// installed on the pump (e.g. `bwk::account::Account`, which has no
    /// BIP375 validator).
    PsbtUpdated {
        request: RequestId,
        signer: SignerId,
        psbt: Vec<u8>,
    },
    /// A signed PSBT that passed the installed verifier.
    PsbtVerified {
        request: RequestId,
        signer: SignerId,
        psbt: Vec<u8>,
    },
    /// A signed PSBT that failed the installed verifier. Deliberately carries
    /// no PSBT bytes: a signer-tampered PSBT must not be routable into
    /// finalize by a consumer that missed the reason.
    PsbtVerificationFailed {
        request: RequestId,
        signer: SignerId,
        reason: String,
    },
    Raw {
        request: RequestId,
        signer: SignerId,
        payload: Vec<u8>,
    },
    Error {
        request: Option<RequestId>,
        signer: Option<SignerId>,
        message: String,
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

#[cfg(feature = "sp")]
impl From<SpNotification> for Notification {
    fn from(sp: SpNotification) -> Self {
        Notification::Sp(sp)
    }
}

impl From<SignerNotification> for Notification {
    fn from(n: SignerNotification) -> Self {
        Notification::Signer(n)
    }
}

/// Represents notifications related to transaction listeners.
#[derive(Debug)]
pub enum TxListenerNotif {
    Started,
    Connected(String),
    Error(tx_listener::Error),
    Stopped,
}
