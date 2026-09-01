//! Main Account orchestrator for Silent Payment wallets.
//!
//! The `Account` struct ties together all components of a Silent Payment wallet:
//! - SpReceiver for key management and address derivation
//! - Blindbit oracle access for blockchain data
//! - Stores for coins, transactions, labels, and scan state
//! - Background scanning thread for continuous blockchain monitoring

pub mod coin_store;
pub mod config;
pub mod recipient;
pub mod tx_store;
pub mod unified;

#[cfg(feature = "mnemonic")]
use {
    crate::{
        account::{
            coin_store::{
                CoinState, KeyedBip32Source, MergedCoinSource, SpCoinEntry, SpCoinSource,
                SpCoinStore,
            },
            config::Config,
            recipient::{SpChangeRecipientProvider, SpSecretProvider},
            tx_store::{SpTxEntry, SpTxStore},
        },
        blindbit::{self, InfoResponse},
        core::utils::common::SilentPaymentAddress,
        receiver::{bip39, SpReceiver},
        scan::{state::ScanState, ScanRuntimeConfig, ScanRuntimeConfigError},
        LabelKey,
    },
    bitcoin::{
        hashes::Hash,
        secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache},
        taproot::Signature,
        Amount, Network, OutPoint, ScriptBuf, TapSighashType, TxOut, Txid,
    },
    bwk::{
        label_store::LabelStore,
        persist::{ConfigStore, NoopConfigStore},
    },
    miniscript::psbt::PsbtExt,
    std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
        sync::{atomic::AtomicBool, mpsc, Arc, Mutex},
        thread::{self, JoinHandle},
    },
};

// Type Aliases

#[cfg(feature = "mnemonic")]
/// Type alias for the tuple of stores returned by create_or_load_stores.
type Stores = (
    Arc<Mutex<SpCoinStore>>,
    Arc<Mutex<LabelStore>>,
    Arc<Mutex<SpTxStore>>,
    Arc<Mutex<ScanState>>,
);

// AccountError

#[cfg(feature = "mnemonic")]
/// Errors that can occur in Account operations.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("either mnemonic or scan_sk must be provided")]
    MissingKeys,
    #[error("blindbit_url is required")]
    MissingBlindbitUrl,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(bip39::Error),
    #[error("invalid scan_sk hex: {0}")]
    ScanSkHex(hex::FromHexError),
    #[error("invalid scan_sk: {0}")]
    InvalidScanSk(bitcoin::secp256k1::Error),
    #[error("invalid spend_key hex: {0}")]
    SpendKeyHex(hex::FromHexError),
    #[error("invalid spend_key: {0}")]
    InvalidSpendKey(bitcoin::secp256k1::Error),
    #[error("spend_key must be 32 or 33 bytes")]
    SpendKeyLength,
    #[error("spend_key is required when using scan_sk")]
    MissingSpendKey,
    #[error("failed to create SpReceiver: {0}")]
    SpReceiver(crate::receiver::error::Error),
    #[error("scan failed: {0}")]
    Scan(crate::receiver::error::Error),
    // String is deliberate: foreign backend errors are surfaced as text, not typed.
    #[error("network error: {0}")]
    Network(String),
    #[error("signing failed: no keys")]
    NoKeys,
    #[error("scanner already running")]
    ScannerAlreadyRunning,
    #[error("failed to finalize psbt: {0:?}")]
    Finalize(Vec<miniscript::psbt::Error>),
    #[error("signing error: {0}")]
    Signing(crate::receiver::error::Error),
    #[error("failed to generate aux randomness: {0}")]
    AuxRand(getrandom::Error),
    #[error("sighash computation failed: {0}")]
    Sighash(bitcoin::sighash::TaprootError),
    #[error("invalid input tweak: {0}")]
    Tweak(bitcoin::secp256k1::Error),
    #[error("no electrum endpoint configured")]
    NoElectrumEndpoint,
    #[error("broadcast error: {0}")]
    Broadcast(#[from] bwk::bwk_electrum::client::Error),
    #[error("failed to open account store: {0}")]
    Open(#[from] bwk::OpenError),
    #[error("failed to start header store: {0}")]
    HeaderStart(#[from] bwk::header_store::StartError),
    #[error("persistence error: {0}")]
    Persist(#[from] bwk::persist::PersistError),
    #[error("invalid scan runtime config: {0}")]
    ScanRuntimeConfig(#[from] ScanRuntimeConfigError),
    #[error("input coin not found: {0}")]
    MissingInputCoin(OutPoint),
    #[error("BIP32 input is not owned by a sub-account: {0}")]
    InputNotOwned(OutPoint),
    #[error("silent payment derivation failed: {0}")]
    SilentPayment(#[from] crate::core::error::Error),
}

#[cfg(feature = "mnemonic")]
struct SpendAnalysis {
    sp_inputs: Vec<OutPoint>,
    sub_accounts: BTreeSet<usize>,
    sp_change: u64,
}

#[cfg(feature = "mnemonic")]
struct SubAccountSpendRecorder {
    scripts: BTreeSet<ScriptBuf>,
    recorder: bwk::account::SpendRecorder,
}

#[cfg(feature = "mnemonic")]
struct BroadcastWorker<P: crate::profile::SpStorageProfile> {
    tx: bitcoin::Transaction,
    url: String,
    port: u16,
    sp_receiver: SpReceiver,
    coin_store: Arc<Mutex<SpCoinStore<P>>>,
    tx_store: Arc<Mutex<SpTxStore<P>>>,
    sub_accounts: Vec<SubAccountSpendRecorder>,
    sender: mpsc::Sender<Notification>,
}

#[cfg(feature = "mnemonic")]
fn p2tr_output_key(script: &ScriptBuf) -> Option<XOnlyPublicKey> {
    script
        .is_p2tr()
        .then(|| XOnlyPublicKey::from_slice(&script.as_bytes()[2..34]).ok())
        .flatten()
}

// Re-use unified Notification from bwk
#[cfg(feature = "mnemonic")]
pub use bwk::{Notification, SpNotification};

#[cfg(feature = "mnemonic")]
fn forward_header_progress(
    header_store: &Arc<bwk::header_store::HeaderStore>,
    sender: mpsc::Sender<Notification>,
) {
    let rx = header_store.register_progress();
    thread::spawn(move || {
        for event in rx {
            if sender.send(Notification::HeaderProgress(event)).is_err() {
                break;
            }
        }
    });
}

#[cfg(feature = "mnemonic")]
impl<P: crate::profile::SpStorageProfile> BroadcastWorker<P> {
    fn run(self) {
        let result = self.run_inner();
        let notification = match result {
            Ok(txid) => SpNotification::Broadcasted { txid },
            Err(e) => SpNotification::FailBroadcast {
                message: e.to_string(),
            },
        };
        let _ = self.sender.send(Notification::Sp(notification));
    }

    fn run_inner(&self) -> Result<Txid, AccountError> {
        let analysis = analyze_unconfirmed_spend(
            &self.sp_receiver,
            &self.coin_store,
            &self.sub_accounts,
            &self.tx,
        )?;
        let mut client = bwk::bwk_electrum::client::Client::new(&self.url, self.port)?;
        client.broadcast_tx(&self.tx)?;
        Ok(apply_unconfirmed_spend(
            &self.coin_store,
            &self.tx_store,
            &self.sub_accounts,
            &self.sender,
            &self.tx,
            analysis,
        ))
    }
}

#[cfg(feature = "mnemonic")]
fn analyze_unconfirmed_spend<P: crate::profile::SpStorageProfile>(
    sp_receiver: &SpReceiver,
    coin_store: &Arc<Mutex<SpCoinStore<P>>>,
    sub_accounts: &[SubAccountSpendRecorder],
    tx: &bitcoin::Transaction,
) -> Result<SpendAnalysis, AccountError> {
    let sp_coins = coin_store.lock().expect("poisoned");
    let mut sp_inputs = Vec::new();
    let mut owned_sub_accounts = BTreeSet::new();
    let mut prevouts = Vec::with_capacity(tx.input.len());

    for input in &tx.input {
        let outpoint = input.previous_output;
        if let Some(coin) = sp_coins.get(&outpoint) {
            sp_inputs.push(outpoint);
            prevouts.push(TxOut {
                value: coin.amount(),
                script_pubkey: coin.script().clone(),
            });
            continue;
        }

        let coin = sub_accounts
            .iter()
            .find_map(|sub| sub.recorder.get_coin(&outpoint))
            .ok_or(AccountError::MissingInputCoin(outpoint))?;
        let owners: Vec<_> = sub_accounts
            .iter()
            .enumerate()
            .filter_map(|(index, sub)| {
                sub.scripts
                    .contains(&coin.txout.script_pubkey)
                    .then_some(index)
            })
            .collect();
        if owners.is_empty() {
            return Err(AccountError::InputNotOwned(outpoint));
        }
        owned_sub_accounts.extend(owners);
        prevouts.push(coin.txout);
    }
    drop(sp_coins);

    for output in &tx.output {
        owned_sub_accounts.extend(sub_accounts.iter().enumerate().filter_map(|(index, sub)| {
            sub.scripts.contains(&output.script_pubkey).then_some(index)
        }));
    }

    let sp_change = sp_owned_output_value(sp_receiver, tx, &prevouts)?;
    Ok(SpendAnalysis {
        sp_inputs,
        sub_accounts: owned_sub_accounts,
        sp_change,
    })
}

#[cfg(feature = "mnemonic")]
fn sp_owned_output_value(
    sp_receiver: &SpReceiver,
    tx: &bitcoin::Transaction,
    prevouts: &[TxOut],
) -> Result<u64, AccountError> {
    let outputs: Vec<_> = tx
        .output
        .iter()
        .filter_map(|output| p2tr_output_key(&output.script_pubkey))
        .collect();
    if outputs.is_empty() {
        return Ok(0);
    }

    let input_pubkeys: Vec<PublicKey> = tx
        .input
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| crate::core::receiving::eligible_input_pubkey(input, prevout))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    if input_pubkeys.is_empty() {
        return Ok(0);
    }
    let outpoints: Vec<_> = tx
        .input
        .iter()
        .map(|input| {
            (
                input.previous_output.txid.to_string(),
                input.previous_output.vout,
            )
        })
        .collect();
    let input_refs: Vec<_> = input_pubkeys.iter().collect();
    let tweak = crate::core::receiving::calculate_tweak_data(&input_refs, &outpoints)?;
    let shared_secret =
        crate::core::receiving::calculate_ecdh_shared_secret(&tweak, &sp_receiver.get_scan_key());
    let owned = sp_receiver
        .receiver
        .scan_transaction(&shared_secret, outputs.clone())?;
    let owned_keys: BTreeSet<XOnlyPublicKey> = owned
        .values()
        .flat_map(|outputs| outputs.keys().copied())
        .collect();

    Ok(tx
        .output
        .iter()
        .filter_map(|output| {
            p2tr_output_key(&output.script_pubkey)
                .filter(|key| owned_keys.contains(key))
                .map(|_| output.value.to_sat())
        })
        .sum())
}

#[cfg(feature = "mnemonic")]
fn apply_unconfirmed_spend<P: crate::profile::SpStorageProfile>(
    coin_store: &Arc<Mutex<SpCoinStore<P>>>,
    tx_store: &Arc<Mutex<SpTxStore<P>>>,
    sub_accounts: &[SubAccountSpendRecorder],
    sender: &mpsc::Sender<Notification>,
    tx: &bitcoin::Transaction,
    analysis: SpendAnalysis,
) -> Txid {
    let txid = tx.compute_txid();
    let has_sp_inputs = !analysis.sp_inputs.is_empty();
    if !analysis.sp_inputs.is_empty() {
        let mut coins = coin_store.lock().expect("poisoned");
        for outpoint in analysis.sp_inputs {
            coins.mark_spent(&outpoint, txid.to_byte_array());
            let _ = sender.send(Notification::Sp(SpNotification::OutputSpent(outpoint)));
        }
        coins.persist();
    }
    if has_sp_inputs || analysis.sp_change > 0 {
        let mut txs = tx_store.lock().expect("poisoned");
        let mut entry = txs
            .get(&txid)
            .unwrap_or_else(|| SpTxEntry::with_tx(txid, tx.clone()));
        if entry.tx.is_none() {
            entry.tx = Some(tx.clone());
        }
        entry.change = analysis.sp_change;
        txs.insert(entry);
        txs.persist();
    }
    for index in analysis.sub_accounts {
        sub_accounts[index].recorder.record_unconfirmed_spend(tx);
    }
    txid
}

// ScanMode

#[cfg(feature = "mnemonic")]
/// Scan mode for the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    /// One-shot scan: scan from last position to current chain tip, then return.
    /// If already at tip, returns immediately.
    #[default]
    OneShot,
    /// Continuous watch mode: scan to tip, then keep watching for new blocks.
    /// Runs in background until explicitly stopped via `stop_scan()`.
    Continuous,
}

// PaymentType

// Payment history is produced by the generic aggregator in `bwk::history`;
// callers receive `bwk::coin_store::Payment`. See `Account::payment_history`.

// Account

#[cfg(feature = "mnemonic")]
/// Main orchestrator for a Silent Payment wallet account. Generic
/// over any [`crate::profile::SpStorageProfile`]; defaults to
/// [`crate::profile::SpRamProfile<DefaultBackend>`].
pub struct Account<
    P: crate::profile::SpStorageProfile = crate::profile::SpRamProfile<
        crate::profile::DefaultBackend,
    >,
> {
    pub(crate) sp_receiver: SpReceiver,
    pub(crate) agent: Arc<ureq::Agent>,
    pub(crate) coin_store: Arc<Mutex<SpCoinStore<P>>>,
    label_store: Arc<Mutex<LabelStore>>,
    pub(crate) tx_store: Arc<Mutex<SpTxStore<P>>>,
    pub(crate) scan_state: Arc<Mutex<ScanState>>,
    pub(crate) config: Config,
    pub(crate) scan_runtime: ScanRuntimeConfig,
    /// Persistence sink for `config`. [`NoopConfigStore`] by default.
    /// Consumers wire whatever shape suits them, a
    /// [`bwk::persist::FileConfigStore`] for file-backed persistence, a
    /// [`bwk::persist::CallbackConfigStore`] to bridge save/load through
    /// host-supplied closures, or any other [`ConfigStore`] impl.
    config_store: Arc<dyn ConfigStore<Config>>,
    pub(crate) sender: mpsc::Sender<Notification>,
    receiver: Option<mpsc::Receiver<Notification>>,
    pub(crate) scanner_handle: Option<JoinHandle<()>>,
    pub(crate) broadcast_handle: Option<JoinHandle<()>>,
    pub(crate) scanner_stop: Arc<AtomicBool>,
    // Sub-accounts use the default bwk RAM profile, independent of sp's P.
    sub_accounts: Vec<bwk::Account>,
    /// Shared HeaderStore handle every BIP32 sub-account's chain-tip-advance
    /// pass reads from.
    pub(crate) header_store: Arc<bwk::header_store::HeaderStore>,
    /// Electrum endpoint the shared HeaderStore currently follows, if any
    /// (the first sub-account descriptor carrying one). Used by
    /// `start_electrum` and `set_electrum_settings` to decide whether to
    /// restart it; cleared by `stop_electrum`.
    header_store_endpoint: Option<(String, u16)>,
}

// Constructors are tied to the default SpRamProfile because they open
// concrete on-disk RamStore instances.
#[cfg(feature = "mnemonic")]
impl Account<crate::profile::SpRamProfile<crate::profile::DefaultBackend>> {
    // Constructors

    /// Create a new Account from configuration.
    ///
    /// Validates the config, creates the SpReceiver, initializes or loads stores,
    /// and prepares the notification channel.
    ///
    /// # Errors
    ///
    /// Returns a configuration error if:
    /// - Neither mnemonic nor scan_sk is provided ([`AccountError::MissingKeys`])
    /// - blindbit_url is empty ([`AccountError::MissingBlindbitUrl`])
    pub fn new(config: Config) -> Result<Self, AccountError> {
        Self::with_runtime_config(config, ScanRuntimeConfig::default())
    }

    pub fn with_runtime_config(
        config: Config,
        scan_runtime: ScanRuntimeConfig,
    ) -> Result<Self, AccountError> {
        Self::with_config_store_and_runtime_config(
            config,
            Arc::new(NoopConfigStore::<Config>::default()),
            scan_runtime,
        )
    }

    /// Like [`Account::new`] but with an explicit config store
    /// ([`bwk::persist::FileConfigStore`] for file-backed,
    /// [`bwk::persist::CallbackConfigStore`] to bridge through
    /// caller-supplied closures, or any other [`ConfigStore`]).
    pub fn with_config_store(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, AccountError> {
        Self::with_config_store_and_runtime_config(
            config,
            config_store,
            ScanRuntimeConfig::default(),
        )
    }

    pub fn with_config_store_and_runtime_config(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
        scan_runtime: ScanRuntimeConfig,
    ) -> Result<Self, AccountError> {
        let header_store = Self::build_header_store(&config)?;
        Self::with_config_store_and_header_store(config, config_store, header_store, scan_runtime)
    }

    /// Like [`Account::with_config_store`] but sharing an existing
    /// [`bwk::header_store::HeaderStore`] handle across every BIP32
    /// sub-account instead of building one.
    pub fn with_header_store(
        config: Config,
        header_store: Arc<bwk::header_store::HeaderStore>,
    ) -> Result<Self, AccountError> {
        Self::with_header_store_and_runtime_config(
            config,
            header_store,
            ScanRuntimeConfig::default(),
        )
    }

    pub fn with_header_store_and_runtime_config(
        config: Config,
        header_store: Arc<bwk::header_store::HeaderStore>,
        scan_runtime: ScanRuntimeConfig,
    ) -> Result<Self, AccountError> {
        Self::with_config_store_and_header_store(
            config,
            Arc::new(NoopConfigStore::<Config>::default()),
            header_store,
            scan_runtime,
        )
    }

    fn with_config_store_and_header_store(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
        header_store: Arc<bwk::header_store::HeaderStore>,
        scan_runtime: ScanRuntimeConfig,
    ) -> Result<Self, AccountError> {
        // Validate config
        if config.mnemonic.is_none() && config.scan_sk.is_none() {
            return Err(AccountError::MissingKeys);
        }
        if config.blindbit_url.is_empty() {
            return Err(AccountError::MissingBlindbitUrl);
        }

        // Create SpReceiver
        let sp_receiver = Self::create_sp_receiver(&config)?;

        let agent = Arc::new(
            blindbit::agent_with_fetch_concurrency(scan_runtime.fetch_concurrency())
                .map_err(|e| AccountError::Network(e.to_string()))?,
        );

        // Create notification channel
        let (sender, receiver) = mpsc::channel();

        // Create/load stores
        let (coin_store, label_store, tx_store, scan_state) = Self::create_or_load_stores(&config)?;

        let header_store_endpoint = Self::header_store_endpoint(&config);
        forward_header_progress(&header_store, sender.clone());

        // Create sub-accounts from config descriptors
        let sub_accounts = config
            .descriptors
            .iter()
            .enumerate()
            .map(|(i, sub_cfg)| {
                let bwk_config = bwk::Config {
                    data_dir: config.account_dir(),
                    dir_name: format!("{}-sub-{}", config.account_name, i),
                    account: format!("{}-sub-{}", config.account_name, i),
                    electrum_url: sub_cfg.electrum_url.clone(),
                    electrum_port: sub_cfg.electrum_port,
                    offline: if sub_cfg.electrum_url.is_none() {
                        Some(true)
                    } else {
                        None
                    },
                    network: config.network,
                    look_ahead: 20,
                    mnemonic: sub_cfg.mnemonic.clone().or_else(|| config.mnemonic.clone()),
                    descriptor: sub_cfg.descriptor.clone(),
                    persist: config.persist,
                    skip_labels: true,
                    persist_kind: config.persist_kind,
                };
                bwk::Account::try_new_with_sender_and_header_store(
                    bwk_config,
                    header_store.clone(),
                    sender.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Account {
            sp_receiver,
            agent,
            coin_store,
            label_store,
            tx_store,
            scan_state,
            config,
            scan_runtime,
            config_store,
            sender,
            receiver: Some(receiver),
            scanner_handle: None,
            broadcast_handle: None,
            scanner_stop: Arc::new(AtomicBool::new(false)),
            sub_accounts,
            header_store,
            header_store_endpoint,
        })
    }

    /// Create account from mnemonic (convenience constructor).
    ///
    /// This is a convenience wrapper around `Config::new()` + `Account::new()`.
    ///
    /// # Arguments
    /// * `account_name` - Name of the account
    /// * `network` - Bitcoin network (mainnet, testnet, signet)
    /// * `mnemonic` - BIP39 mnemonic phrase
    /// * `blindbit_url` - URL of the Blindbit backend
    /// * `data_dir` - Directory for storing account data
    pub fn from_mnemonic(
        account_name: String,
        network: Network,
        mnemonic: &str,
        blindbit_url: String,
        data_dir: std::path::PathBuf,
    ) -> Result<Self, AccountError> {
        let config = Config::new(
            account_name,
            network,
            mnemonic.to_string(),
            blindbit_url,
            data_dir,
        );
        Self::new(config)
    }

    /// Load an existing Account from configuration.
    ///
    /// Same as `new()` but prioritizes loading existing data from files.
    pub fn load(config: Config) -> Result<Self, AccountError> {
        // For now, load behaves the same as new since stores
        // already prioritize loading from files when persist=true
        Self::new(config)
    }

    /// Create SpReceiver from config.
    fn create_sp_receiver(config: &Config) -> Result<SpReceiver, AccountError> {
        if let Some(ref mnemonic) = config.mnemonic {
            let mnemonic =
                bip39::Mnemonic::parse(mnemonic).map_err(AccountError::InvalidMnemonic)?;
            SpReceiver::new_from_mnemonic(mnemonic, config.network)
                .map_err(AccountError::SpReceiver)
        } else if let Some(ref scan_sk_hex) = config.scan_sk {
            // Create from raw keys
            let scan_sk_bytes = hex::decode(scan_sk_hex).map_err(AccountError::ScanSkHex)?;
            let scan_sk = bitcoin::secp256k1::SecretKey::from_slice(&scan_sk_bytes)
                .map_err(AccountError::InvalidScanSk)?;

            let spend_key = if let Some(ref spend_key_hex) = config.spend_key {
                let spend_key_bytes =
                    hex::decode(spend_key_hex).map_err(AccountError::SpendKeyHex)?;

                if spend_key_bytes.len() == 32 {
                    // Secret key
                    let sk = bitcoin::secp256k1::SecretKey::from_slice(&spend_key_bytes)
                        .map_err(AccountError::InvalidSpendKey)?;
                    crate::receiver::SpendKey::Secret(sk)
                } else if spend_key_bytes.len() == 33 {
                    // Public key
                    let pk = bitcoin::secp256k1::PublicKey::from_slice(&spend_key_bytes)
                        .map_err(AccountError::InvalidSpendKey)?;
                    crate::receiver::SpendKey::Public(pk)
                } else {
                    return Err(AccountError::SpendKeyLength);
                }
            } else {
                return Err(AccountError::MissingSpendKey);
            };

            SpReceiver::new(scan_sk, spend_key, config.network).map_err(AccountError::SpReceiver)
        } else {
            Err(AccountError::MissingKeys)
        }
    }

    // (see the free `create_backend` helper below for the backend
    // constructor: it's pure w.r.t. `P`.)

    /// Create or load stores based on config.persist + persist_kind.
    ///
    /// Builds a single backend ([`bwk::persist::JsonBackend`] or
    /// [`bwk::persist::SqliteBackend`]) from the config and threads it into
    /// every store. JSON layout is byte-for-byte equivalent to the
    /// pre-backend layout (one `{store}.json` file per store name).
    fn create_or_load_stores(config: &Config) -> Result<Stores, AccountError> {
        let birthday = config
            .birthday_height
            .unwrap_or_else(|| config.min_birthday_height());

        let backend: Arc<dyn bwk::persist::PersistenceBackend> = bwk::persist::build_backend(
            config.persist.then_some(config.persist_kind),
            config.account_dir(),
        )?;

        let coin_store =
            SpCoinStore::load_from_backend(backend.clone(), crate::account::coin_store::STORE_KEY)?;
        let label_store =
            LabelStore::load_from_backend(backend.clone(), bwk::persist::LABELS_STORE_KEY)?;
        let tx_store =
            SpTxStore::load_from_backend(backend.clone(), crate::account::tx_store::STORE_KEY)?;
        let scan_state = ScanState::load_from_backend(birthday, backend)?;

        Ok((
            Arc::new(Mutex::new(coin_store)),
            Arc::new(Mutex::new(label_store)),
            Arc::new(Mutex::new(tx_store)),
            Arc::new(Mutex::new(scan_state)),
        ))
    }

    /// The electrum endpoint that drives the shared HeaderStore: the first
    /// configured sub-account descriptor carrying one.
    fn header_store_endpoint(config: &Config) -> Option<(String, u16)> {
        config
            .electrum_endpoint()
            .map(|(url, port)| (url.to_string(), port))
    }

    /// Build the shared HeaderStore for this account's BIP32 sub-accounts:
    /// online against [`Self::header_store_endpoint`] when one is
    /// configured, file-backed/in-memory (idle) otherwise. Fails loud if a
    /// configured endpoint cannot be reached rather than silently opening a
    /// worker-less store.
    fn build_header_store(
        config: &Config,
    ) -> Result<Arc<bwk::header_store::HeaderStore>, AccountError> {
        let path = config
            .persist
            .then(|| config.account_dir().join(bwk::config::HEADERS_FILENAME));
        let (url, port) = Self::header_store_endpoint(config).unzip();
        // Backfill from the birthday so the worker covers the scan range, whose
        // confirmation block times the scanner reads from this store.
        Ok(bwk::header_store::HeaderStore::start_or_open(
            url,
            port,
            config.network,
            path,
            Some(config.min_birthday_height()),
        )?)
    }
}

// Generic accessors and operations, available for any `P: SpStorageProfile`.
#[cfg(feature = "mnemonic")]
impl<P: crate::profile::SpStorageProfile> Account<P> {
    /// Returns the account name.
    pub fn name(&self) -> &str {
        &self.config.account_name
    }

    /// Returns the network.
    pub fn network(&self) -> Network {
        self.config.network
    }

    /// Returns a clone of the config.
    pub fn get_config(&self) -> Config {
        self.config.clone()
    }

    /// Returns the Silent Payment address for this account.
    pub fn sp_address(&self) -> SilentPaymentAddress {
        self.sp_receiver.get_receiving_address()
    }

    /// Returns a reference to the SpReceiver for advanced operations.
    pub fn sp_receiver(&self) -> &SpReceiver {
        &self.sp_receiver
    }

    /// Takes the notification receiver (can only be called once).
    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.receiver.take()
    } // Coin & Balance Methods

    /// Returns a clone of all coins in the store.
    pub fn coins(&self) -> BTreeMap<OutPoint, SpCoinEntry> {
        self.coin_store.lock().expect("poisoned").coins().clone()
    }

    /// Returns a coin entry by outpoint if it exists.
    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<SpCoinEntry> {
        self.coin_store.lock().expect("poisoned").get(outpoint)
    }

    /// Seed one synthetic unspent owned outpoint so a benchmark's spend (input)
    /// sweep has an owned coin to scan for. Without one, the scan's spend phase
    /// short-circuits on an empty owned set and measures nothing; the fake
    /// txid/blockheight never matches a real spent filter, so the coin survives
    /// the whole range. Bench-only, not part of the wallet API.
    #[cfg(feature = "bench")]
    pub fn seed_synthetic_owned_coin(&self) {
        use bitcoin::hashes::Hash;
        self.coin_store.lock().expect("poisoned").insert(
            bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([0u8; 32]),
                vout: 0,
            },
            crate::receiver::OwnedOutput {
                blockheight: bitcoin::absolute::Height::from_consensus(
                    self.config.birthday_height.unwrap_or(0),
                )
                .expect("valid bench height"),
                tweak: [0u8; 32],
                amount: bitcoin::Amount::from_sat(1),
                script: bitcoin::ScriptBuf::new(),
                label: None,
                spend_status: crate::receiver::OutputSpendStatus::Unspent,
            },
        );
    }

    /// Returns spendable coins and balance summary.
    pub fn spendable_coins(&self) -> CoinState {
        self.coin_store.lock().expect("poisoned").spendable_coins()
    }

    /// Returns the total spendable balance in satoshis.
    pub fn balance(&self) -> u64 {
        self.spendable_coins().confirmed_balance
    } // Transaction History

    /// Returns all transaction entries.
    pub fn tx_history(&self) -> Vec<SpTxEntry> {
        self.tx_store.lock().expect("poisoned").transactions()
    }

    /// Returns a unified payment history across the SP store and every
    /// sub-account, de-duplicated per txid by the generic aggregator. Direction
    /// and amount are derived from additive input/output ownership, so change
    /// nets out and a tx that spends no SP coin produces no spurious SP entry.
    pub fn payment_history(&self) -> Vec<bwk::coin_store::Payment> {
        let mut sources: Vec<&dyn bwk::history::AccountHistory> =
            vec![self as &dyn bwk::history::AccountHistory];
        for sub in &self.sub_accounts {
            sources.push(sub as &dyn bwk::history::AccountHistory);
        }
        bwk::history::aggregate_payments(sources)
    } // Labels

    /// Update the label for a coin.
    pub fn update_coin_label(&self, outpoint: OutPoint, label: String) {
        let mut store = self.label_store.lock().expect("poisoned");
        let value = (!label.is_empty()).then_some(label);
        store.edit(LabelKey::OutPoint(outpoint), value);
        store.persist();
    }

    /// Update the label for a transaction.
    pub fn update_tx_label(&self, txid: Txid, label: String) {
        let mut store = self.label_store.lock().expect("poisoned");
        let value = (!label.is_empty()).then_some(label);
        store.edit(LabelKey::Transaction(txid), value);
        store.persist();
    }

    /// Get the label for a coin.
    pub fn get_coin_label(&self, outpoint: &OutPoint) -> Option<String> {
        self.label_store
            .lock()
            .expect("poisoned")
            .outpoint(*outpoint)
    } // Scanning

    /// Get the current block height from the backend.
    pub fn block_height(&self) -> Result<u32, AccountError> {
        blindbit::block_height(&self.agent, &self.config.blindbit_url)
            .map(|h| h.to_consensus_u32())
            .map_err(|e| AccountError::Network(e.to_string()))
    }

    /// Check if the backend is online and reachable.
    pub fn backend_online(&self) -> bool {
        self.block_height().is_ok()
    }

    /// Returns the Blindbit server URL.
    pub fn blindbit_url(&self) -> &str {
        &self.config.blindbit_url
    }

    /// Update the Blindbit server URL.
    pub fn set_blindbit_url(&mut self, url: String) {
        self.config.blindbit_url = url;
        if self.config.persist {
            self.persist_config();
        }
    }

    /// Push the current config to the configured [`ConfigStore`].
    ///
    /// Under [`bwk::persist::PersistenceKind::Sqlite`] the saved view has
    /// signer material stripped via [`Config::for_persistence`].
    fn persist_config(&self) {
        if let Err(e) = self.config_store.save(&self.config.for_persistence()) {
            log::warn!("config save failed: {e}");
        }
    }

    // Sub-accounts

    /// Add a standard wallet sub-account (segwit, taproot, etc.).
    pub fn add_sub_account(&mut self, account: bwk::Account) {
        self.sub_accounts.push(account);
    }

    /// Returns a reference to the embedded sub-accounts.
    pub fn sub_accounts(&self) -> &[bwk::Account] {
        &self.sub_accounts
    }

    /// Returns a mutable reference to the embedded sub-accounts.
    pub fn sub_accounts_mut(&mut self) -> &mut [bwk::Account] {
        &mut self.sub_accounts
    }

    /// Derive the BIP32 master xpriv from this account's mnemonic, if available.
    pub(crate) fn sp_master_xpriv(
        &self,
    ) -> Option<(bitcoin::bip32::Fingerprint, bitcoin::bip32::Xpriv)> {
        let mnemonic_str = self.config.mnemonic.as_ref()?;
        let mnemonic = bip39::Mnemonic::from_str(mnemonic_str).ok()?;
        let seed = mnemonic.to_seed("");
        let xpriv = bitcoin::bip32::Xpriv::new_master(self.config.network, &seed).ok()?;
        let secp = Secp256k1::new();
        let fg = xpriv.fingerprint(&secp);
        Some((fg, xpriv))
    }

    /// Stop electrum on all sub-accounts. Every sub-account is now offline,
    /// so idle the shared `HeaderStore` too instead of leaving its worker
    /// running against a connection none of them use anymore. Clears the
    /// tracked endpoint so a later `start_electrum`/`set_electrum_settings`
    /// call restarts the store even against the same endpoint as before.
    pub fn stop_electrum(&mut self) {
        for sub in &mut self.sub_accounts {
            sub.stop_electrum();
        }
        self.header_store.stop();
        self.header_store_endpoint = None;
    }

    /// Start electrum on all sub-accounts, restarting the shared
    /// `HeaderStore` against the first sub-account endpoint if it isn't
    /// already following it (e.g. after a prior `stop_electrum`).
    pub fn start_electrum(&mut self) {
        for sub in &mut self.sub_accounts {
            sub.start_electrum();
        }
        let endpoint = self.sub_accounts.iter().find_map(|a| {
            let config = a.get_config();
            config.electrum_url.zip(config.electrum_port)
        });
        self.follow_header_store_endpoint(endpoint);
    }

    /// Set electrum URL and port on all sub-accounts without writing to file.
    pub fn set_electrum_settings(&mut self, url: Option<String>, port: Option<u16>) {
        for sub in &mut self.sub_accounts {
            sub.set_electrum_config(url.clone(), port);
        }
        self.follow_header_store_endpoint(url.zip(port));
    }

    /// Point the shared `HeaderStore` at `endpoint`: restart its worker
    /// against a new endpoint, or idle it when every sub-account went
    /// offline. No-op when already following `endpoint`.
    fn follow_header_store_endpoint(&mut self, endpoint: Option<(String, u16)>) {
        if endpoint == self.header_store_endpoint {
            return;
        }
        match endpoint.clone() {
            Some((url, port)) => match self.header_store.restart(url, port) {
                Ok(()) => self.header_store_endpoint = endpoint,
                Err(e) => log::warn!("sp::Account: header store restart failed: {e}"),
            },
            None => {
                self.header_store.stop();
                self.header_store_endpoint = endpoint;
            }
        }
    }

    /// Total balance across SP and all sub-accounts.
    pub fn total_balance(&self) -> u64 {
        let sp_balance = self.balance();
        let bip32_balance: u64 = self.sub_accounts.iter().map(|a| a.balance().0).sum();
        sp_balance + bip32_balance
    }

    /// All coins from the SP account and every sub-account, keyed by outpoint.
    ///
    /// Spent and being-spent coins are included; filter by
    /// [`UnifiedCoin::spendable`](crate::account::unified::UnifiedCoin::spendable) to keep only
    /// live UTXOs.
    pub fn all_coins(&self) -> BTreeMap<OutPoint, crate::account::unified::UnifiedCoin> {
        use crate::account::unified::{CoinOrigin, UnifiedCoin};
        let mut out: BTreeMap<OutPoint, UnifiedCoin> = BTreeMap::new();

        for (outpoint, entry) in self.coins() {
            out.insert(
                outpoint,
                UnifiedCoin {
                    origin: CoinOrigin::Sp,
                    outpoint,
                    amount: Amount::from_sat(entry.amount_sat()),
                    height: Some(entry.height()),
                    spendable: entry.is_spendable(),
                    label: self.get_coin_label(&outpoint),
                },
            );
        }

        for (sub_idx, sub) in self.sub_accounts.iter().enumerate() {
            for (outpoint, entry) in sub.coins() {
                let spendable = !matches!(
                    entry.status(),
                    bwk_coin::CoinStatus::Spent | bwk_coin::CoinStatus::BeingSpend,
                );
                out.insert(
                    outpoint,
                    UnifiedCoin {
                        origin: CoinOrigin::SubAccount(sub_idx),
                        outpoint,
                        amount: entry.coin.txout.value,
                        height: entry.height().map(|h| h as u32),
                        spendable,
                        label: self.get_coin_label(&outpoint),
                    },
                );
            }
        }

        out
    }

    /// Build a configured `TxBuilder` from a [`bwk_tx::TxRequest`].
    ///
    /// The returned builder has the request's outputs added, fee policy set,
    /// and inputs selected per the rules: manual outpoints when supplied,
    /// drain when any output sets `max`, otherwise auto-select.
    pub fn tx_builder_from_request(
        &self,
        request: &bwk_tx::TxRequest,
    ) -> Result<bwk_tx::TxBuilder, bwk_tx::TxRequestError> {
        use crate::{account::recipient::SpRecipientAddress, receiver::RecipientAddress};
        use bwk_tx::{Amount as BwkAmount, TxRequestError};

        let network = self.network();

        let mut has_max = false;
        let mut max_addr: Option<RecipientAddress> = None;
        let mut recipients: Vec<SpRecipientAddress> = Vec::new();

        for output in &request.outputs {
            let addr = RecipientAddress::try_from(output.address.clone()).map_err(|e| {
                TxRequestError::InvalidAddress {
                    address: output.address.clone(),
                    source: Box::new(e),
                }
            })?;
            if output.max {
                if has_max {
                    return Err(TxRequestError::MultipleMaxOutputs);
                }
                has_max = true;
                max_addr = Some(addr);
            } else {
                recipients.push(SpRecipientAddress::new(addr, output.amount, network));
            }
        }

        let feerate_msats_vb = (request.fee_rate.max(1.0) * 1000.0) as u64;
        let mut builder = self.tx_builder();
        builder = if request.fee > 0 {
            builder.fee(request.fee)
        } else {
            builder.feerate(feerate_msats_vb)
        };

        for recip in recipients {
            builder.add_output(recip);
        }
        if has_max {
            let mut recip = SpRecipientAddress::new(max_addr.unwrap(), 0, network);
            recip.amount = BwkAmount::Max(None);
            builder.add_output(recip);
        }

        // Caller-specified inputs are pre-added (this bypasses auto-selection).
        // When none are given, leave the template inputs empty: the builder's
        // registered coin selector + source auto-select on simulate()/generate()
        // (Value outputs select for the target; a Max output sweeps all coins).
        if !request.input_outpoints.is_empty() {
            let sp_coins = self.coins();
            for outpoint in &request.input_outpoints {
                if let Some(entry) = sp_coins.get(outpoint) {
                    if !entry.is_spendable() {
                        return Err(TxRequestError::CoinNotSpendable(*outpoint));
                    }
                    builder.add_input(sp_coin_entry_to_coin(*outpoint, entry));
                    continue;
                }
                let mut found = false;
                for sub in self.sub_accounts() {
                    if let Some(entry) = sub.coins().get(outpoint) {
                        if matches!(
                            entry.status(),
                            bwk_coin::CoinStatus::Spent | bwk_coin::CoinStatus::BeingSpend
                        ) {
                            return Err(TxRequestError::CoinNotSpendable(*outpoint));
                        }
                        builder.add_input(entry.coin.clone());
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(TxRequestError::CoinNotFound(*outpoint));
                }
            }
        }

        Ok(builder)
    }

    /// Simulate a transaction described by a [`bwk_tx::TxRequest`].
    pub fn simulate(
        &self,
        request: &bwk_tx::TxRequest,
    ) -> Result<bwk_tx::TxSimulation, bwk_tx::TxRequestError> {
        let builder = self.tx_builder_from_request(request)?;
        // Inputs auto-selected from the builder's registered selector/source
        // when the request did not specify input_outpoints.
        let mut result = builder.simulate();
        if let Some(err) = result.error.take() {
            return Err(err.into());
        }
        let weight = bwk_tx::transaction::tx_estimated_weight(&result.tx_template);
        let input_total: bitcoin::Amount = result
            .tx_template
            .inputs
            .iter()
            .map(|c| c.txout.value)
            .sum();
        let fee = result.fees.unwrap_or(bitcoin::Amount::ZERO);
        let output_total = input_total
            .checked_sub(fee)
            .unwrap_or(bitcoin::Amount::ZERO);
        let selected_outpoints = result
            .tx_template
            .inputs
            .iter()
            .map(|c| c.outpoint)
            .collect();
        Ok(bwk_tx::TxSimulation {
            fee,
            weight,
            input_total,
            output_total,
            selected_outpoints,
        })
    }

    /// Build an unsigned PSBT from a [`bwk_tx::TxRequest`].
    pub fn prepare(
        &self,
        request: &bwk_tx::TxRequest,
    ) -> Result<bitcoin::Psbt, bwk_tx::TxRequestError> {
        let mut builder = self.tx_builder_from_request(request)?;
        builder.generate().map_err(Into::into)
    }

    /// SP spendable summary plus every sub-account's spendable summary, summed.
    pub fn all_spendable_coins(&self) -> crate::account::unified::SpendableSummary {
        use crate::account::unified::SpendableSummary;
        let sp = self.spendable_coins();
        let mut summary = SpendableSummary {
            confirmed_count: sp.confirmed_coins as u64,
            confirmed_balance: Amount::from_sat(sp.confirmed_balance),
            unconfirmed_count: sp.unconfirmed_coins as u64,
            unconfirmed_balance: Amount::from_sat(sp.unconfirmed_balance),
        };
        for sub in &self.sub_accounts {
            let s = sub.spendable_coins();
            summary.confirmed_count += s.confirmed_coins as u64;
            summary.confirmed_balance += Amount::from_sat(s.confirmed_balance);
            summary.unconfirmed_count += s.unconfirmed_coins as u64;
            summary.unconfirmed_balance += Amount::from_sat(s.unconfirmed_balance);
        }
        summary
    }
    // Transaction Building

    /// Check if this account can sign transactions.
    ///
    /// Returns true if we have the spend secret key.
    pub fn can_sign(&self) -> bool {
        self.sp_receiver.try_get_secret_spend_key().is_ok()
    }

    /// Returns a [`TxBuilder`] pre-configured with this account's coin source,
    /// change provider, and SP partial secret provider.
    ///
    /// Usage mirrors [`bwk::Account::tx_builder()`]:
    /// ```ignore
    /// let mut builder = account.tx_builder();
    /// builder.add_output(SpRecipient::new(sp_addr, 50_000, network));
    /// builder.feerate(1000);
    /// let mut psbt = builder.generate()?;
    /// account.sign_psbt(&mut psbt)?;
    /// ```
    pub fn tx_builder(&self) -> bwk_tx::TxBuilder {
        let change_addr = self.sp_receiver.receiver.get_change_address();
        let change_provider = Box::new(SpChangeRecipientProvider::new(
            change_addr,
            self.config.network,
        ));

        let sp_source = SpCoinSource::new(self.coin_store.clone());

        // Collect master xprivs from SP account and all sub-accounts for BIP32 key derivation
        let mut all_xprivs = std::collections::BTreeMap::new();
        if let Some((fg, xpriv)) = self.sp_master_xpriv() {
            all_xprivs.insert(fg, xpriv);
        }
        for sub in &self.sub_accounts {
            all_xprivs.extend(sub.master_xprivs());
        }

        let sp_provider = Box::new(SpSecretProvider::new(
            self.coin_store.clone(),
            self.sp_receiver.clone(),
            all_xprivs.clone(),
        ));

        // Merge coin sources from all sub-accounts, enriching BIP32 coins
        // with their secret keys for SP partial secret computation.
        let bip32_sources: Vec<Box<dyn bwk_coin::CoinSource>> = self
            .sub_accounts
            .iter()
            .map(|a| {
                Box::new(KeyedBip32Source::new(
                    Box::new(a.coin_source()),
                    a.master_xprivs(),
                )) as Box<dyn bwk_coin::CoinSource>
            })
            .collect();
        let merged_source = Box::new(MergedCoinSource::new(sp_source, bip32_sources));

        bwk_tx::TxBuilder::new(change_provider)
            .coin_source(merged_source)
            .sp_provider(sp_provider)
    }

    /// Sign all inputs in a PSBT, both SP and BIP32 (segwit/taproot).
    ///
    /// 1. Signs SP inputs using `b_spend + tweak` (no taproot tweak).
    /// 2. Signs BIP32 inputs via sub-account SigningManagers.
    ///
    /// # Errors
    /// * `AccountError::NoKeys` if this account has no spend secret key
    /// * `AccountError::Transaction` on signing failure
    pub fn sign_psbt(&self, psbt: &mut bitcoin::Psbt) -> Result<(), AccountError> {
        // Sign SP inputs
        if self.can_sign() {
            self.sign_sp_inputs(psbt)?;
        }

        // Sign BIP32 inputs via sub-account SigningManagers
        for sub in &self.sub_accounts {
            sub.sign_psbt(psbt);
        }

        Ok(())
    }

    /// Sign all inputs and finalize the PSBT into a broadcast-ready transaction.
    ///
    /// 1. Signs SP inputs (`b_spend + tweak`).
    /// 2. Signs BIP32 inputs via sub-account SigningManagers.
    /// 3. Finalizes all inputs (builds witnesses) and extracts the transaction.
    pub fn sign_and_finalize(
        &self,
        psbt: &mut bitcoin::Psbt,
    ) -> Result<bitcoin::Transaction, AccountError> {
        self.sign_psbt(psbt)?;
        Self::finalize(psbt)
    }

    /// Broadcast a signed spend in the background. Completion is reported via
    /// `SpNotification::Broadcasted` or `SpNotification::FailBroadcast`.
    pub fn broadcast(&mut self, tx: bitcoin::Transaction) {
        if let Some(handle) = self.broadcast_handle.take() {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                self.broadcast_handle = Some(handle);
                let _ = self
                    .sender
                    .send(Notification::Sp(SpNotification::FailBroadcast {
                        message: "broadcast already running".to_string(),
                    }));
                return;
            }
        }
        let Some((url, port)) = self.config.electrum_endpoint() else {
            let _ = self
                .sender
                .send(Notification::Sp(SpNotification::FailBroadcast {
                    message: AccountError::NoElectrumEndpoint.to_string(),
                }));
            return;
        };

        let worker = BroadcastWorker {
            tx,
            url: url.to_string(),
            port,
            sp_receiver: self.sp_receiver.clone(),
            coin_store: self.coin_store.clone(),
            tx_store: self.tx_store.clone(),
            sub_accounts: self.sub_account_spend_recorders(),
            sender: self.sender.clone(),
        };
        self.broadcast_handle = Some(thread::spawn(move || worker.run()));
    }

    /// Inject a just-broadcast spend into local state as unconfirmed.
    ///
    /// Resolves every input from wallet stores, derives owned SP outputs, and
    /// then records the transaction in each relevant store.
    pub fn record_unconfirmed_spend(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<Txid, AccountError> {
        let sub_accounts = self.sub_account_spend_recorders();
        let analysis =
            analyze_unconfirmed_spend(&self.sp_receiver, &self.coin_store, &sub_accounts, tx)?;
        Ok(apply_unconfirmed_spend(
            &self.coin_store,
            &self.tx_store,
            &sub_accounts,
            &self.sender,
            tx,
            analysis,
        ))
    }

    fn sub_account_spend_recorders(&self) -> Vec<SubAccountSpendRecorder> {
        self.sub_accounts
            .iter()
            .map(|account| {
                let recorder = account.spend_recorder();
                SubAccountSpendRecorder {
                    scripts: recorder.address_scripts(),
                    recorder,
                }
            })
            .collect()
    }

    /// Finalize a signed PSBT into a broadcast-ready transaction.
    fn finalize(psbt: &mut bitcoin::Psbt) -> Result<bitcoin::Transaction, AccountError> {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        PsbtExt::finalize_mut(psbt, &secp).map_err(AccountError::Finalize)?;
        Ok(psbt.clone().extract_tx_unchecked_fee_rate())
    }

    /// Sign only the SP inputs in a PSBT.
    ///
    /// For each input whose outpoint is found in this account's coin store,
    /// computes the signing key (`b_spend + tweak`) and produces a Schnorr
    /// signature stored in `tap_key_sig`.
    ///
    /// Source: adapted from cygnet3/spdk's silent-payment input signing.
    /// See `sp/NOTICE`.
    fn sign_sp_inputs(&self, psbt: &mut bitcoin::Psbt) -> Result<(), AccountError> {
        let b_spend = self
            .sp_receiver
            .try_get_secret_spend_key()
            .map_err(AccountError::Signing)?;

        let secp = Secp256k1::new();
        let hash_ty = TapSighashType::Default;

        let prevouts: Vec<bitcoin::TxOut> = psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .clone()
                    .expect("PSBT input must have witness_utxo")
            })
            .collect();

        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let coin_store = self.coin_store.lock().expect("poisoned");

        let mut aux_rand = [0u8; 32];
        getrandom::getrandom(&mut aux_rand).map_err(AccountError::AuxRand)?;

        for (i, input) in psbt.unsigned_tx.input.iter().enumerate() {
            let Some(entry) = coin_store.get(&input.previous_output) else {
                // Not an SP input, skip
                continue;
            };

            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), hash_ty)
                .map_err(AccountError::Sighash)?;

            let msg = Message::from_digest(sighash.to_byte_array());
            let tweak = SecretKey::from_slice(entry.tweak()).map_err(AccountError::Tweak)?;
            let sk = b_spend
                .add_tweak(&tweak.into())
                .map_err(AccountError::Tweak)?;

            let keypair = Keypair::from_secret_key(&secp, &sk);
            // SP outputs use dangerous_assume_tweaked(): no taproot tweak on the
            // output key, so sign with the untweaked keypair directly.
            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

            psbt.inputs[i].tap_key_sig = Some(Signature {
                signature: sig,
                sighash_type: hash_ty,
            });
        }

        Ok(())
    } // Persistence

    /// Persist all stores to disk.
    ///
    /// This runs from `Drop`; a poisoned lock here would otherwise
    /// double-panic and abort the process. Recover the guard and
    /// persist best-effort instead.
    pub fn persist(&self) {
        self.coin_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .persist();
        self.label_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .persist();
        self.tx_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .persist();
        self.scan_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .persist();
    }

    /// Aggregated view of every address this wallet owns, across
    /// every BIP32 sub-account plus the SP-derived taproot spks the
    /// SP coin store has seen. Each entry is tagged with the name
    /// of the account it belongs to (BIP32 sub-account name, or
    /// this SP account's name for SP-derived spks). Useful to:
    ///   - list all owned addresses in a UI;
    ///   - sanity-check before exporting / sending: refuse to expose
    ///     or self-target an address whose status is `Used` /
    ///     `Reused`.
    pub fn owned_addresses(&self) -> Vec<OwnedAddress> {
        let mut out: Vec<OwnedAddress> = Vec::new();

        for sub in &self.sub_accounts {
            let name = sub.name();
            for e in sub.address_entries() {
                out.push(OwnedAddress {
                    address: e.value(),
                    account_name: name.clone(),
                    source: AddressSource::Bip32(e.account(), e.index()),
                    status: e.status(),
                    funding_txids: e.funding_txids().clone(),
                    spending_txids: e.spending_txids().clone(),
                });
            }
        }

        let sp_name = self.name().to_string();
        let network = self.config.network;
        let sp_entries = self
            .coin_store
            .lock()
            .expect("poisoned")
            .addresses_with_status();
        for e in sp_entries {
            let address = bitcoin::Address::from_script(&e.script, network)
                .map(|a| a.to_string())
                .unwrap_or_else(|_| e.script.to_hex_string());
            // SP-derived spks have exactly one funding tx by
            // construction (per-output tweak makes them unique). If
            // the set is somehow empty, fall back to Unknown rather
            // than silently dropping the entry.
            let source = match e.funding_txids.iter().next().copied() {
                Some(txid) => AddressSource::SilentPayment(txid),
                None => AddressSource::Unknown,
            };
            out.push(OwnedAddress {
                address,
                account_name: sp_name.clone(),
                source,
                status: e.status,
                funding_txids: e.funding_txids,
                spending_txids: e.spending_txids,
            });
        }

        out
    }

    /// Sanity-check API: look `address` up in the wallet's
    /// aggregated owned-address view. Returns the entry with status
    /// and funding/spending txids if it belongs to this wallet, or
    /// `None` otherwise. Compares by canonical bech32/bech32m string.
    ///
    /// Consumer policy decides what to do with a `Used` / `Reused`
    /// hit (typical: refuse to re-export or self-target). The wallet
    /// just answers "is this mine, and if so what's its status".
    pub fn lookup_owned_address(&self, address: &str) -> Option<OwnedAddress> {
        self.owned_addresses()
            .into_iter()
            .find(|o| o.address == address)
    }
}

#[cfg(feature = "mnemonic")]
/// Provenance of an [`OwnedAddress`].
///
/// SP-derived spks have exactly one funding tx by protocol design
/// (each output's per-tweak ensures uniqueness), so
/// [`AddressSource::SilentPayment`] carries that single funding txid.
/// BIP32 sub-account addresses carry their keychain (receive vs
/// change) and derivation index. [`AddressSource::Unknown`] is a
/// defensive fallback for cases where neither shape applies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AddressSource {
    SilentPayment(bitcoin::Txid),
    Bip32(bwk_coin::KeyChain, u32),
    Unknown,
}

#[cfg(feature = "mnemonic")]
/// One address the wallet owns, aggregated across sub-accounts
/// (BIP32) and the SP wallet. `account_name` identifies the
/// originating keychain, see [`bwk::Account::name`] /
/// [`crate::Account::name`]. `source` carries the per-spk provenance
/// (see [`AddressSource`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OwnedAddress {
    pub address: String,
    pub account_name: String,
    pub source: AddressSource,
    pub status: bwk::address_store::AddressStatus,
    pub funding_txids: std::collections::BTreeSet<bitcoin::Txid>,
    pub spending_txids: std::collections::BTreeSet<bitcoin::Txid>,
}

#[cfg(feature = "mnemonic")]
impl<P: crate::profile::SpStorageProfile> Drop for Account<P> {
    fn drop(&mut self) {
        self.stop_scan();
        if let Some(handle) = self.broadcast_handle.take() {
            let _ = handle.join();
        }
        self.persist();
    }
}

#[cfg(feature = "mnemonic")]
/// Get backend info without an Account.
///
/// If the URL already has a scheme, uses it directly. Otherwise tries `http://` then `https://`.
/// Returns the `InfoResponse` and the URL that worked.
pub fn backend_info(blindbit_url: String) -> Result<(InfoResponse, String), AccountError> {
    let try_url = |url: &str| -> Result<InfoResponse, AccountError> {
        let agent = blindbit::agent().map_err(|e| AccountError::Network(e.to_string()))?;
        blindbit::info(&agent, url).map_err(|e| AccountError::Network(e.to_string()))
    };

    // If a scheme is already present, use as-is.
    if blindbit_url.starts_with("https://") || blindbit_url.starts_with("http://") {
        let info = try_url(&blindbit_url)?;
        return Ok((info, blindbit_url));
    }

    // No scheme: try http:// then https://.
    let http_url = format!("http://{blindbit_url}");
    if let Ok(info) = try_url(&http_url) {
        return Ok((info, http_url));
    }

    let https_url = format!("https://{blindbit_url}");
    let info = try_url(&https_url)?;
    Ok((info, https_url))
}

#[cfg(feature = "mnemonic")]
/// Get block height without an Account.
pub fn backend_block_height(blindbit_url: String) -> Result<u32, AccountError> {
    let agent = blindbit::agent().map_err(|e| AccountError::Network(e.to_string()))?;
    blindbit::block_height(&agent, &blindbit_url)
        .map(|h| h.to_consensus_u32())
        .map_err(|e| AccountError::Network(e.to_string()))
}

#[cfg(feature = "mnemonic")]
/// Build a [`bwk_coin::Coin`] from an SP outpoint + entry, suitable for
/// `TxBuilder::add_input`. The taproot key-spend satisfaction weight
/// ([`bwk_coin::TAPROOT_KEYSPEND_SATISFACTION_WU`]) is used because SP outputs
/// are always single-key taproot.
pub fn sp_coin_entry_to_coin(outpoint: OutPoint, entry: &SpCoinEntry) -> bwk_coin::Coin {
    bwk_coin::Coin {
        txout: bitcoin::TxOut {
            value: entry.amount(),
            script_pubkey: entry.script().clone(),
        },
        outpoint,
        height: Some(entry.height() as u64),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        status: bwk_coin::CoinStatus::Confirmed,
        label: None,
        satisfaction_size: bwk_coin::TAPROOT_KEYSPEND_SATISFACTION_WU,
        spend_info: bwk_coin::CoinSpendInfo::Sp {
            derivation: bitcoin::bip32::DerivationPath::default(),
            tweak: *entry.tweak(),
        },
    }
}

// Tests

#[cfg(test)]
pub(crate) mod mnemonic_probe {
    use std::fmt::{Debug, Display};

    /// Not bip39 words, so they can only reach a message by leaking from the input.
    pub const UNKNOWN_MNEMONIC: &str = "zzalpha zzbravo zzcharlie zzdelta zzecho zzfoxtrot zzgolf zzhotel zzindia zzjuliett zzkilo zzlima";

    /// A valid bip39 vector with its last word swapped: english words, wrong checksum.
    pub const BAD_CHECKSUM_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank zoo";

    /// A downstream consumer writes these renders to a persistent log.
    pub fn assert_no_word_leak<E: Display + Debug>(err: &E, mnemonic: &str) {
        for rendered in [err.to_string(), format!("{err:?}")] {
            for word in mnemonic.split_whitespace() {
                assert!(!rendered.contains(word), "leaked `{word}` in `{rendered}`");
            }
        }
    }
}

#[cfg(all(test, feature = "mnemonic"))]
mod tests {
    use super::*;
    use crate::receiver::OwnedOutput;
    use bitcoin::{absolute::Height, hashes::hash160, secp256k1::Parity};
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config::new(
            "test-account".to_string(),
            Network::Signet,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-sp-account-test"),
        ).enable_persist(false)
    }

    #[test]
    fn test_account_error_display() {
        let err = AccountError::MissingBlindbitUrl;
        assert!(err.to_string().contains("blindbit_url"));

        let err = AccountError::Scan(crate::receiver::error::Error::SeedDerivation);
        assert!(err.to_string().contains("scan failed"));

        let err = AccountError::Network("network error".to_string());
        assert!(err.to_string().contains("network error"));

        let err = AccountError::NoKeys;
        assert!(err.to_string().contains("no keys"));

        let err = AccountError::ScannerAlreadyRunning;
        assert!(err.to_string().contains("already running"));
    }

    #[test]
    fn rerecord_unconfirmed_spend_preserves_tx_metadata() {
        let account = Account::new(test_config()).unwrap();
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let previous_body = bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let txid = tx.compute_txid();
        let mut entry = SpTxEntry::with_tx(txid, previous_body.clone());
        entry.fee = Some(2);
        entry.height = Some(3);
        entry.timestamp = Some(4);
        entry.label = Some("label".to_string());
        account.tx_store.lock().expect("poisoned").insert(entry);

        apply_unconfirmed_spend(
            &account.coin_store,
            &account.tx_store,
            &[],
            &account.sender,
            &tx,
            SpendAnalysis {
                sp_inputs: Vec::new(),
                sub_accounts: BTreeSet::new(),
                sp_change: 5,
            },
        );

        let entry = account
            .tx_store
            .lock()
            .expect("poisoned")
            .get(&txid)
            .unwrap();
        assert_eq!(entry.tx, Some(previous_body));
        assert_eq!(entry.fee, Some(2));
        assert_eq!(entry.height, Some(3));
        assert_eq!(entry.timestamp, Some(4));
        assert_eq!(entry.label.as_deref(), Some("label"));
        assert_eq!(entry.change, 5);
    }

    #[test]
    fn extracts_bip352_eligible_input_pubkeys() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = secret.public_key(&secp);
        let pubkey_bytes = pubkey.serialize();
        let pubkey_hash = hash160::Hash::hash(&pubkey_bytes);
        let txout = |script_pubkey| TxOut {
            value: Amount::from_sat(1),
            script_pubkey,
        };
        let txin = |script_sig, witness| bitcoin::TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: bitcoin::Sequence::ZERO,
            witness,
        };

        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend(pubkey_hash.as_byte_array());
        p2pkh.extend([0x88, 0xac]);
        let mut script_sig = vec![1, 0];
        script_sig.extend(pubkey_bytes);
        let input = txin(ScriptBuf::from_bytes(script_sig), bitcoin::Witness::new());
        assert_eq!(
            crate::core::receiving::eligible_input_pubkey(
                &input,
                &txout(ScriptBuf::from_bytes(p2pkh)),
            )
            .unwrap(),
            Some(pubkey)
        );

        let mut p2wpkh = vec![0, 0x14];
        p2wpkh.extend(pubkey_hash.as_byte_array());
        let witness = bitcoin::Witness::from_slice(&[vec![0; 64], pubkey_bytes.to_vec()]);
        let input = txin(ScriptBuf::new(), witness.clone());
        assert_eq!(
            crate::core::receiving::eligible_input_pubkey(
                &input,
                &txout(ScriptBuf::from_bytes(p2wpkh.clone())),
            )
            .unwrap(),
            Some(pubkey)
        );

        let redeem_hash = hash160::Hash::hash(&p2wpkh);
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend(redeem_hash.as_byte_array());
        p2sh.push(0x87);
        let mut script_sig = vec![22];
        script_sig.extend(p2wpkh);
        let input = txin(ScriptBuf::from_bytes(script_sig), witness);
        assert_eq!(
            crate::core::receiving::eligible_input_pubkey(
                &input,
                &txout(ScriptBuf::from_bytes(p2sh)),
            )
            .unwrap(),
            Some(pubkey)
        );

        let (xonly, _) = pubkey.x_only_public_key();
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend(xonly.serialize());
        let input = txin(
            ScriptBuf::new(),
            bitcoin::Witness::from_slice(&[vec![0; 64]]),
        );
        assert_eq!(
            crate::core::receiving::eligible_input_pubkey(
                &input,
                &txout(ScriptBuf::from_bytes(p2tr.clone())),
            )
            .unwrap(),
            Some(PublicKey::from_x_only_public_key(xonly, Parity::Even))
        );

        let script_path = txin(
            ScriptBuf::new(),
            bitcoin::Witness::from_slice(&[vec![0; 64], vec![0x51], vec![0; 33]]),
        );
        assert_eq!(
            crate::core::receiving::eligible_input_pubkey(
                &script_path,
                &txout(ScriptBuf::from_bytes(p2tr)),
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn test_notification_variants() {
        let notif = Notification::Sp(SpNotification::StartingScan);
        assert!(matches!(
            notif,
            Notification::Sp(SpNotification::StartingScan)
        ));

        let notif = Notification::Sp(SpNotification::FailStartScanning {
            message: "test error".to_string(),
        });
        if let Notification::Sp(SpNotification::FailStartScanning { message }) = notif {
            assert_eq!(message, "test error");
        } else {
            panic!("expected FailStartScanning");
        }

        let notif = Notification::Sp(SpNotification::FailScan {
            message: "scan error".to_string(),
        });
        if let Notification::Sp(SpNotification::FailScan { message }) = notif {
            assert_eq!(message, "scan error");
        } else {
            panic!("expected FailScan");
        }

        let notif = Notification::Sp(SpNotification::StoppingScan);
        assert!(matches!(
            notif,
            Notification::Sp(SpNotification::StoppingScan)
        ));

        let notif = Notification::Sp(SpNotification::ScanStopped);
        assert!(matches!(
            notif,
            Notification::Sp(SpNotification::ScanStopped)
        ));

        let notif = Notification::Sp(SpNotification::ScanReceiveProgress {
            current: 100,
            end: 200,
        });
        if let Notification::Sp(SpNotification::ScanReceiveProgress { current, end }) = notif {
            assert_eq!(current, 100);
            assert_eq!(end, 200);
        } else {
            panic!("expected ScanReceiveProgress");
        }

        let notif = Notification::Sp(SpNotification::ScanCompleted);
        assert!(matches!(
            notif,
            Notification::Sp(SpNotification::ScanCompleted)
        ));
    }

    #[test]
    fn test_config_validation_no_keys() {
        let mut config = test_config();
        config.mnemonic = None;
        config.scan_sk = None;

        let result = Account::new(config);
        assert!(matches!(result, Err(AccountError::MissingKeys)));
    }

    #[test]
    fn test_config_validation_no_blindbit_url() {
        let mut config = test_config();
        config.blindbit_url = String::new();

        let result = Account::new(config);
        assert!(matches!(result, Err(AccountError::MissingBlindbitUrl)));
    }

    #[test]
    fn test_from_mnemonic_invalid_mnemonic() {
        let result = Account::from_mnemonic(
            "test-account".to_string(),
            Network::Signet,
            "invalid mnemonic words",
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-sp-test-from-mnemonic"),
        );
        assert!(matches!(result, Err(AccountError::InvalidMnemonic(_))));
    }

    #[test]
    fn unknown_word_error_hides_mnemonic_words() {
        let result = Account::from_mnemonic(
            "test-account".to_string(),
            Network::Signet,
            mnemonic_probe::UNKNOWN_MNEMONIC,
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-sp-test-unknown-word"),
        );

        // `Account` is not `Debug`, so `unwrap_err` is not available here.
        let Err(err) = result else {
            panic!("expected an error");
        };
        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::UNKNOWN_MNEMONIC);
        assert_eq!(
            err.to_string(),
            "invalid mnemonic: mnemonic contains an unknown word (word 0)"
        );
        assert_eq!(format!("{err:?}"), "InvalidMnemonic(UnknownWord(0))");
    }

    #[test]
    fn checksum_error_hides_mnemonic_words() {
        let result = Account::from_mnemonic(
            "test-account".to_string(),
            Network::Signet,
            mnemonic_probe::BAD_CHECKSUM_MNEMONIC,
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-sp-test-bad-checksum"),
        );

        let Err(err) = result else {
            panic!("expected an error");
        };
        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::BAD_CHECKSUM_MNEMONIC);
        assert_eq!(
            err.to_string(),
            "invalid mnemonic: the mnemonic has an invalid checksum"
        );
        assert_eq!(format!("{err:?}"), "InvalidMnemonic(InvalidChecksum)");
    }

    #[test]
    fn test_from_mnemonic_empty_blindbit_url() {
        let result = Account::from_mnemonic(
            "test-account".to_string(),
            Network::Signet,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            String::new(),
            PathBuf::from("/tmp/bwk-sp-test-from-mnemonic-2"),
        );
        assert!(matches!(result, Err(AccountError::MissingBlindbitUrl)));
    }

    // Note: Full Account creation tests require a working blindbit backend
    // which is not available in unit tests. Integration tests would test
    // the full flow.

    // with_header_store: shares one HeaderStore across sub-accounts

    fn offline_sub_account_config(mnemonic: &str, network: Network) -> config::SubAccountConfig {
        use bwk_sign::{bwk_descriptor, HotSigner};
        use miniscript::bitcoin::bip32::ChildNumber;

        let signer = HotSigner::new_from_mnemonics(network, mnemonic).unwrap();
        let path =
            bwk_descriptor::wpkh_path(network, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        let xpub = signer.xpub(&path);
        let descriptor = bwk_descriptor::SpkDerivator::new_wpkh(xpub, network)
            .unwrap()
            .descriptor();
        config::SubAccountConfig {
            descriptor,
            mnemonic: None,
            electrum_url: None,
            electrum_port: None,
        }
    }

    #[test]
    fn with_header_store_shares_one_instance_across_sub_accounts() {
        let mut config = test_config();
        let mnemonic = config
            .mnemonic
            .clone()
            .expect("test_config carries a mnemonic");
        config.descriptors = vec![
            offline_sub_account_config(&mnemonic, config.network),
            offline_sub_account_config(&mnemonic, config.network),
        ];

        let shared = bwk::header_store::HeaderStore::new_in_memory(config.network);
        let account =
            Account::with_header_store(config, shared.clone()).expect("with_header_store");

        assert!(Arc::ptr_eq(&account.header_store, &shared));
        assert_eq!(account.sub_accounts().len(), 2);
        for sub in account.sub_accounts() {
            assert!(Arc::ptr_eq(sub.header_store(), &shared));
        }
    }

    // owned_addresses: aggregate view across BIP32 subs + SP

    fn build_offline_segwit_sub(name: &str) -> bwk::Account {
        use bip39::Mnemonic;
        use bwk_sign::{bwk_descriptor, HotSigner};
        use miniscript::bitcoin::bip32::ChildNumber;

        let network = bitcoin::Network::Regtest;
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(network, &mnemo.to_string()).unwrap();
        let path =
            bwk_descriptor::wpkh_path(network, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
        let xpub = signer.xpub(&path);
        let descriptor = bwk_descriptor::SpkDerivator::new_wpkh(xpub, network)
            .unwrap()
            .descriptor();
        bwk::Account::new(bwk::Config {
            data_dir: std::path::PathBuf::new(),
            dir_name: String::new(),
            account: name.to_string(),
            electrum_url: None,
            electrum_port: None,
            offline: Some(true),
            network,
            look_ahead: 5,
            mnemonic: Some(mnemo.to_string()),
            descriptor,
            persist: false,
            skip_labels: true,
            persist_kind: bwk::persist::PersistenceKind::default(),
        })
    }

    /// Build a syntactically valid p2tr scriptPubKey from a fixed
    /// 32-byte x-only key, suitable for seeding `SpCoinStore` in
    /// tests where we don't actually scan a chain.
    fn fake_tr_spk(seed: u8) -> bitcoin::ScriptBuf {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let (xonly, _parity) = sk.public_key(&secp).x_only_public_key();
        let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly);
        bitcoin::Address::p2tr_tweaked(tweaked, bitcoin::Network::Regtest).script_pubkey()
    }

    fn fake_sp_owned(spk: bitcoin::ScriptBuf, seed: u8) -> OwnedOutput {
        OwnedOutput {
            blockheight: Height::from_consensus(100).unwrap(),
            tweak: [seed; 32],
            amount: bitcoin::Amount::from_sat(10_000),
            script: spk,
            label: None,
            spend_status: crate::receiver::OutputSpendStatus::Unspent,
        }
    }

    #[test]
    fn owned_addresses_empty_for_fresh_account() {
        let account = Account::new(test_config()).expect("Account::new");
        // No sub-accounts, no SP coins, nothing to aggregate.
        assert!(account.owned_addresses().is_empty());
    }

    #[test]
    fn owned_addresses_includes_bip32_sub_accounts() {
        let mut account = Account::new(test_config()).expect("Account::new");
        let sub_name = "sub-segwit-0".to_string();
        account.add_sub_account(build_offline_segwit_sub(&sub_name));

        let owned = account.owned_addresses();
        // Sub-accounts populate look_ahead receive + look_ahead change
        // entries on construction (via CoinStore::generate). At least
        // one of them must show up tagged with the sub's name.
        assert!(
            !owned.is_empty(),
            "sub-account address entries should be visible in owned_addresses"
        );
        assert!(
            owned.iter().all(|o| o.account_name == sub_name),
            "every aggregated entry should carry the sub-account's name"
        );
        // BIP32-derived entries carry their keychain + index via
        // AddressSource::Bip32; SP-only variants must not appear.
        assert!(
            owned
                .iter()
                .all(|o| matches!(o.source, AddressSource::Bip32(_, _))),
            "every aggregated entry should carry AddressSource::Bip32"
        );
        // No SP coins were inserted, so nothing should be tagged with
        // the SP account's own name.
        assert!(owned.iter().all(|o| o.account_name != account.name()));
    }

    #[test]
    fn owned_addresses_includes_sp_received() {
        let account = Account::new(test_config()).expect("Account::new");
        let spk = fake_tr_spk(7);
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xAB; 32]),
            vout: 0,
        };
        account
            .coin_store
            .lock()
            .expect("poisoned")
            .insert(outpoint, fake_sp_owned(spk.clone(), 7));

        let owned = account.owned_addresses();
        assert_eq!(owned.len(), 1, "only the SP coin should show up");
        let entry = &owned[0];
        assert_eq!(entry.account_name, account.name());
        assert_eq!(entry.status, bwk::address_store::AddressStatus::Used);
        assert_eq!(entry.funding_txids.len(), 1);
        assert!(entry.funding_txids.contains(&outpoint.txid));
        assert!(entry.spending_txids.is_empty());
        // SP-derived spk: source must be SilentPayment(funding_txid).
        match entry.source {
            AddressSource::SilentPayment(txid) => assert_eq!(txid, outpoint.txid),
            ref other => panic!("expected SilentPayment source, got {other:?}"),
        }
        // Canonical form of the spk matches what the consumer would
        // see via Address::from_script.
        let expected = bitcoin::Address::from_script(&spk, bitcoin::Network::Signet)
            .unwrap()
            .to_string();
        assert_eq!(entry.address, expected);
    }

    // lookup_owned_address: sanity-check API for export / send paths

    #[test]
    fn lookup_returns_none_for_unknown_address() {
        let mut account = Account::new(test_config()).expect("Account::new");
        account.add_sub_account(build_offline_segwit_sub("sub-segwit-0"));
        // A signet bech32 address that the wallet definitely doesn't own.
        let unknown = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        assert!(account.lookup_owned_address(unknown).is_none());
    }

    #[test]
    fn lookup_returns_entry_for_owned_bip32_address() {
        let mut account = Account::new(test_config()).expect("Account::new");
        account.add_sub_account(build_offline_segwit_sub("sub-segwit-0"));

        // Pick any address the sub generated at construction time,
        // look it up by canonical string, and check we get it back.
        let sample = account
            .sub_accounts()
            .iter()
            .flat_map(|s| s.address_entries())
            .next()
            .expect("sub-account has entries");
        let canonical = sample.value();

        let hit = account
            .lookup_owned_address(&canonical)
            .expect("address should be owned");
        assert_eq!(hit.address, canonical);
        assert_eq!(hit.account_name, "sub-segwit-0");
    }

    #[test]
    fn lookup_returns_entry_for_sp_received_spk() {
        let account = Account::new(test_config()).expect("Account::new");
        let spk = fake_tr_spk(13);
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xCD; 32]),
            vout: 1,
        };
        account
            .coin_store
            .lock()
            .expect("poisoned")
            .insert(outpoint, fake_sp_owned(spk.clone(), 13));

        let canonical = bitcoin::Address::from_script(&spk, bitcoin::Network::Signet)
            .unwrap()
            .to_string();
        let hit = account
            .lookup_owned_address(&canonical)
            .expect("SP-derived spk should be owned");
        assert_eq!(hit.account_name, account.name());
        assert_eq!(hit.status, bwk::address_store::AddressStatus::Used);
        assert!(hit.funding_txids.contains(&outpoint.txid));
    }
}

#[cfg(feature = "mnemonic")]
impl<P: crate::profile::SpStorageProfile> bwk::history::AccountHistory for Account<P> {
    fn tx_contributions(
        &self,
    ) -> std::collections::BTreeMap<bitcoin::Txid, bwk::history::TxContribution> {
        use bitcoin::hashes::Hash;
        use std::collections::BTreeMap;

        let mut map: BTreeMap<bitcoin::Txid, bwk::history::TxContribution> = BTreeMap::new();

        // Ownership comes from the coin store: a coin is an output we own (its
        // funding txid), and a coin marked `Spent { txid, .. }` is an input we
        // own in that spending txid.
        {
            let coin_store = self.coin_store.lock().expect("poisoned");
            for entry in coin_store.coins().values() {
                let op = entry.outpoint();
                let received = map.entry(op.txid).or_default();
                received.owned_out = received.owned_out.saturating_add(entry.amount_sat());
                received.owned_vouts.insert(op.vout);
                if received.height.is_none() {
                    received.height = Some(entry.height() as u64);
                }
                received.status = received
                    .status
                    .merge(bwk::coin_store::PaymentStatus::Verified);
                if let crate::receiver::OutputSpendStatus::Spent { txid, .. } = entry.status() {
                    let spent_in = bitcoin::Txid::from_byte_array(*txid);
                    let spent = map.entry(spent_in).or_default();
                    spent.owned_in = spent.owned_in.saturating_add(entry.amount_sat());
                }
            }
        }

        // The tx store carries the full tx, the confirmation height/time, and an
        // optional label for the transactions we know about (our sends and the
        // receives recorded by the scanner).
        {
            let tx_store = self.tx_store.lock().expect("poisoned");
            for e in tx_store.transactions() {
                let c = map.entry(e.txid).or_default();
                if let Some(h) = e.height {
                    c.height = Some(h as u64);
                    c.status = c.status.merge(bwk::coin_store::PaymentStatus::Verified);
                }
                if c.timestamp.is_none() {
                    c.timestamp = e.timestamp;
                }
                if c.tx.is_none() {
                    c.tx = e.tx.clone();
                }
                // Our own send's SP change nets the amount while unconfirmed.
                // Once the scan records the real change coin, `owned_out` is set
                // from it above, so the recorded value is no longer applied.
                if e.change > 0 && c.owned_out == 0 {
                    c.owned_out = e.change;
                }
            }
        }

        {
            let labels = self.label_store.lock().expect("poisoned");
            for (txid, c) in map.iter_mut() {
                if c.label.is_none() {
                    // The tx label if set, else a label on any owned coin of
                    // this tx (set through update_coin_label).
                    c.label = labels.transaction(*txid).or_else(|| {
                        c.owned_vouts
                            .iter()
                            .find_map(|vout| labels.outpoint(OutPoint::new(*txid, *vout)))
                    });
                }
            }
        }
        map
    }
}
