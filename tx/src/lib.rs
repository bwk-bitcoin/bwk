pub mod coin_selection;
pub mod descr_fingerprint;
pub mod error;
mod psbt_sp;
pub mod recipient;
pub mod template;
pub mod transaction;
pub mod tx_builder;

pub use coin_selection::{CoinCandidate, CoinSelector, DefaultCoinSelector};
pub use descr_fingerprint::DescrFingerprint;
pub use error::Error;
pub use recipient::{
    ChangeRecipientProvider, FinalizationContext, LocalTipUpdater, PsbtOutputInfo, Recipient,
    RecipientProvider, SpPartialSecretProvider,
};
pub use template::{TxOutputSpec, TxRequest, TxRequestError, TxSimulation};
pub use transaction::{
    estimated_weight_raw, process_fees, Amount, Drain, FeeResult, Fees, TransactionResult,
    TxTemplate, Warning,
};
pub use tx_builder::TxBuilder;

pub const DUST_AMOUNT: u64 = 5_000;
