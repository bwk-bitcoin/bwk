//! Configuration for Silent Payment accounts.
//!
//! The `Config` struct holds all settings needed to create and operate
//! a silent payment wallet account.

use std::{
    fs,
    path::{Path, PathBuf},
};

use bitcoin::{bip32::ChildNumber, Network};
use bwk::{
    bwk_electrum::config::Endpoint,
    miniscript::{Descriptor, DescriptorPublicKey},
};
use bwk_sign::{bwk_descriptor, HotSigner};
use serde::{Deserialize, Serialize};

/// Default filename a [`bwk::persist::FileConfigStore`] uses for an
/// SP account's config. Consumers are free to choose another path
/// when constructing the store.
pub const CONFIG_FILENAME: &str = "config.json";

/// Configuration for a Silent Payment account.
///
/// Contains identity information, keys, backend URLs, and persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Identity
    /// Account name (used for directory naming)
    pub account_name: String,
    /// Bitcoin network (mainnet, testnet, signet, regtest)
    pub network: Network,

    // Keys (one of mnemonic or scan_sk must be set)
    /// BIP39 mnemonic phrase (for hot wallet)
    pub mnemonic: Option<String>,
    /// Hex-encoded scan secret key (for signing device mode)
    pub scan_sk: Option<String>,
    /// Hex-encoded spend key (secret or public, depending on mode)
    pub spend_key: Option<String>,

    // Backend
    /// Blindbit server URL for chain data
    pub blindbit_url: String,
    /// Electrum server used to broadcast spends (blindbit is read-only).
    /// Private so [`Endpoint`] stays the only way to move it, see
    /// [`Endpoint::set`].
    #[serde(flatten)]
    endpoint: Endpoint,

    // Persistence
    /// Base directory for account data
    pub data_dir: PathBuf,
    /// Whether to persist data to disk (not serialized)
    #[serde(skip)]
    pub persist: bool,
    /// Which on-disk backend to use when `persist` is true.
    ///
    /// `Json` (default): byte-for-byte compatible with the pre-backend
    /// layout. `Sqlite`: single `account.sqlite` file per account;
    /// signer material (mnemonic / scan_sk / spend_key) is stripped from
    /// everything written to disk and must be re-supplied on the next run.
    #[serde(skip)]
    pub persist_kind: bwk::persist::PersistenceKind,

    // Scanning
    /// Minimum output value in satoshis to consider (dust filter)
    pub dust_limit: Option<u64>,
    /// Block height to start scanning from (skip earlier blocks)
    pub birthday_height: Option<u32>,

    // Sub-accounts
    /// Optional descriptors for embedded standard wallets (segwit, taproot, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptors: Vec<SubAccountConfig>,
}

/// Configuration for an embedded standard wallet sub-account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAccountConfig {
    /// Miniscript descriptor (e.g. wpkh or tr)
    pub descriptor: Descriptor<DescriptorPublicKey>,
    /// Optional mnemonic used to sign this sub-account.
    ///
    /// When absent, [`Account`](crate::Account) uses the parent SP config's
    /// mnemonic. This field is only needed for externally supplied sub-account
    /// mnemonics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// Electrum server this sub-account watches, offline while unset.
    #[serde(flatten)]
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Copy)]
enum SubAccountKind {
    Segwit,
    Taproot,
}

impl Config {
    // Constructors

    /// Create a new Config from a mnemonic phrase.
    ///
    /// This is the standard constructor for hot wallets where the mnemonic
    /// is stored in memory.
    pub fn new(
        account_name: String,
        network: Network,
        mnemonic: String,
        blindbit_url: String,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            account_name,
            network,
            mnemonic: Some(mnemonic),
            scan_sk: None,
            spend_key: None,
            blindbit_url,
            endpoint: Endpoint::default(),
            data_dir,
            persist: true,
            persist_kind: bwk::persist::PersistenceKind::default(),
            dust_limit: None,
            birthday_height: None,
            descriptors: Vec::new(),
        }
    }

    /// Create a new Config from raw keys.
    ///
    /// This constructor is used for signing device mode where only the
    /// scan secret key is available locally, and the spend key may be
    /// either a secret key (hot) or public key (watch-only).
    ///
    /// # Errors
    ///
    /// Returns a key-validation error if:
    /// - `scan_sk` is not exactly 64 hex characters ([`ConfigError::ScanSkLength`])
    /// - `spend_key` is not exactly 64 or 66 hex characters ([`ConfigError::SpendKeyLength`])
    /// - Either key contains invalid hex characters ([`ConfigError::ScanSkHex`] /
    ///   [`ConfigError::SpendKeyHex`])
    pub fn from_keys(
        account_name: String,
        network: Network,
        scan_sk: String,
        spend_key: String,
        blindbit_url: String,
        data_dir: PathBuf,
    ) -> Result<Self, ConfigError> {
        // Validate scan_sk is valid hex (64 chars = 32 bytes secret key)
        if scan_sk.len() != 64 {
            return Err(ConfigError::ScanSkLength);
        }
        hex::decode(&scan_sk).map_err(ConfigError::ScanSkHex)?;

        // Validate spend_key is valid hex (64 chars = secret key, 66 chars = compressed pubkey)
        if spend_key.len() != 64 && spend_key.len() != 66 {
            return Err(ConfigError::SpendKeyLength);
        }
        hex::decode(&spend_key).map_err(ConfigError::SpendKeyHex)?;

        Ok(Self {
            account_name,
            network,
            mnemonic: None,
            scan_sk: Some(scan_sk),
            spend_key: Some(spend_key),
            blindbit_url,
            endpoint: Endpoint::default(),
            data_dir,
            persist: true,
            persist_kind: bwk::persist::PersistenceKind::default(),
            dust_limit: None,
            birthday_height: None,
            descriptors: Vec::new(),
        })
    }

    // Sanitization

    /// Sanitize all config values, clamping or fixing invalid fields.
    pub fn sanitize(&mut self) {
        // Birthday height
        let min = self.min_birthday_height();
        match self.birthday_height {
            Some(h) if h < min => self.birthday_height = Some(min),
            None => self.birthday_height = Some(min),
            _ => {}
        }
    }

    /// Returns the minimum valid birthday height for this config's network.
    /// Taproot activation height for mainnet, 1 for test networks.
    pub fn min_birthday_height(&self) -> u32 {
        match self.network {
            Network::Bitcoin => 709_632,
            _ => 1,
        }
    } // Getters

    /// Returns the account name.
    pub fn account_name(&self) -> &str {
        &self.account_name
    }

    /// Returns the network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the Blindbit server URL.
    pub fn blindbit_url(&self) -> &str {
        &self.blindbit_url
    } // Mutators (setters)

    /// Set the Blindbit server URL.
    pub fn set_blindbit_url(&mut self, url: String) {
        self.blindbit_url = url;
    }

    /// The Electrum server this account broadcasts through.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Set the Electrum server endpoint used to broadcast spends, see
    /// [`Endpoint::set`].
    pub fn set_electrum_endpoint(&mut self, url: String, port: u16) {
        self.endpoint.set(Some(url), Some(port));
    }

    /// Forget the Electrum endpoint, see [`Endpoint::clear`].
    pub fn clear_electrum_endpoint(&mut self) {
        self.endpoint.clear();
    }

    /// Set the dust limit in satoshis.
    pub fn set_dust_limit(&mut self, limit: Option<u64>) {
        self.dust_limit = limit;
    }

    /// Set the birthday height for initial scanning.
    pub fn set_birthday_height(&mut self, height: Option<u32>) {
        self.birthday_height = height;
    }

    /// Add a default embedded BIP84 (P2WPKH) sub-account derived from this
    /// config's mnemonic at account index 0.
    pub fn add_default_segwit_sub_account(&mut self) -> Result<(), ConfigError> {
        let mnemonic = self.mnemonic.clone().ok_or(ConfigError::MissingMnemonic)?;
        self.add_sub_account_from_mnemonic(&mnemonic, SubAccountKind::Segwit, None)
    }

    /// Add a default embedded BIP86 (P2TR) sub-account derived from this
    /// config's mnemonic at account index 0.
    pub fn add_default_taproot_sub_account(&mut self) -> Result<(), ConfigError> {
        let mnemonic = self.mnemonic.clone().ok_or(ConfigError::MissingMnemonic)?;
        self.add_sub_account_from_mnemonic(&mnemonic, SubAccountKind::Taproot, None)
    }

    /// Add an embedded BIP84 (P2WPKH) sub-account derived from an external
    /// mnemonic at account index 0.
    pub fn add_segwit_sub_account_from_mnemonic(
        &mut self,
        mnemonic: &str,
    ) -> Result<(), ConfigError> {
        self.add_sub_account_from_mnemonic(
            mnemonic,
            SubAccountKind::Segwit,
            Some(mnemonic.to_string()),
        )
    }

    /// Add an embedded BIP86 (P2TR) sub-account derived from an external
    /// mnemonic at account index 0.
    pub fn add_taproot_sub_account_from_mnemonic(
        &mut self,
        mnemonic: &str,
    ) -> Result<(), ConfigError> {
        self.add_sub_account_from_mnemonic(
            mnemonic,
            SubAccountKind::Taproot,
            Some(mnemonic.to_string()),
        )
    }

    fn add_sub_account_from_mnemonic(
        &mut self,
        mnemonic: &str,
        kind: SubAccountKind,
        sub_account_mnemonic: Option<String>,
    ) -> Result<(), ConfigError> {
        let signer =
            HotSigner::new_from_mnemonics(self.network, mnemonic).map_err(ConfigError::Signer)?;
        let account = ChildNumber::from_hardened_idx(0).expect("hardcoded account index");
        let descriptor = match kind {
            SubAccountKind::Segwit => {
                let path = bwk_descriptor::wpkh_path(self.network, account)
                    .map_err(ConfigError::DescriptorPath)?;
                bwk_descriptor::SpkDerivator::new_wpkh(signer.xpub(&path), self.network)
                    .map_err(ConfigError::Derivator)?
                    .descriptor()
            }
            SubAccountKind::Taproot => {
                let path = bwk_descriptor::tr_path(self.network, account)
                    .map_err(ConfigError::DescriptorPath)?;
                bwk_descriptor::SpkDerivator::new_tr(signer.xpub(&path), self.network)
                    .map_err(ConfigError::Derivator)?
                    .descriptor()
            }
        };

        self.push_descriptor_maybe(descriptor, sub_account_mnemonic);
        Ok(())
    }

    fn push_descriptor_maybe(
        &mut self,
        descriptor: Descriptor<DescriptorPublicKey>,
        mnemonic: Option<String>,
    ) {
        if self
            .descriptors
            .iter()
            .any(|sub| sub.descriptor == descriptor)
        {
            return;
        }
        self.descriptors.push(SubAccountConfig {
            descriptor,
            mnemonic,
            endpoint: Endpoint::default(),
        });
    }

    /// Enable or disable persistence (builder pattern).
    pub fn enable_persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    /// Select the on-disk backend (JSON default, or SQLite).
    ///
    /// Under [`bwk::persist::PersistenceKind::Sqlite`], signer material
    /// (mnemonic / scan_sk / spend_key) is stripped from everything
    /// written to disk and must be re-supplied on the next run.
    pub fn with_persist_kind(mut self, kind: bwk::persist::PersistenceKind) -> Self {
        self.persist_kind = kind;
        self
    }

    /// Whether this config is configured to keep signer material out of
    /// on-disk writes.
    pub fn excludes_signer_data(&self) -> bool {
        matches!(self.persist_kind, bwk::persist::PersistenceKind::Sqlite)
    } // Path helpers

    /// Returns the account-specific data directory.
    ///
    /// Format: `{data_dir}/{account_name}/`
    pub fn account_dir(&self) -> PathBuf {
        self.data_dir.join(&self.account_name)
    }

    /// Delete an account's data directory recursively.
    ///
    /// Must only be called when no `Account` instance is using this directory.
    pub fn delete_account_dir(data_dir: &Path, account_name: &str) -> Result<(), ConfigError> {
        let dir = data_dir.join(account_name);
        fs::remove_dir_all(&dir)
            .map_err(|e| ConfigError::Io(format!("failed to remove {}: {}", dir.display(), e)))
    }

    /// View of this config that's safe to persist to disk.
    ///
    /// Under [`bwk::persist::PersistenceKind::Sqlite`] all signer
    /// material (mnemonic, scan_sk, spend_key) is stripped so it never
    /// lands on disk; under [`bwk::persist::PersistenceKind::Json`]
    /// (default) the config is returned unchanged. Used by `Account`
    /// when handing config to a [`bwk::persist::ConfigStore`].
    pub fn for_persistence(&self) -> Config {
        if self.excludes_signer_data() {
            let mut stripped = self.clone();
            stripped.mnemonic = None;
            stripped.scan_sk = None;
            stripped.spend_key = None;
            for descriptor in &mut stripped.descriptors {
                descriptor.mnemonic = None;
            }
            stripped
        } else {
            self.clone()
        }
    }
}

/// Errors that can occur when loading or parsing Config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("scan_sk must be 64 hex chars")]
    ScanSkLength,
    #[error("spend_key must be 64 or 66 hex chars")]
    SpendKeyLength,
    #[error("scan_sk is not valid hex: {0}")]
    ScanSkHex(hex::FromHexError),
    #[error("spend_key is not valid hex: {0}")]
    SpendKeyHex(hex::FromHexError),
    #[error("missing mnemonic")]
    MissingMnemonic,
    #[error("signer error: {0}")]
    Signer(bwk_sign::Error),
    #[error("descriptor path error: {0}")]
    DescriptorPath(#[source] bwk_descriptor::descriptor::Error),
    #[error("derivator error: {0}")]
    Derivator(#[source] bwk_descriptor::derivator::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::mnemonic_probe;
    use std::path::Path;

    fn test_config() -> Config {
        Config::new(
            "alice".to_string(),
            Network::Signet,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
    }

    #[test]
    fn test_config_new_valid() {
        let config = test_config();

        assert_eq!(config.account_name, "alice");
        assert_eq!(config.network, Network::Signet);
        assert!(config.mnemonic.is_some());
        assert!(config.scan_sk.is_none());
        assert!(config.spend_key.is_none());
        assert_eq!(config.blindbit_url, "https://blindbit.example.com");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/bwk-test"));
        assert!(config.persist); // Default is true
        assert!(config.dust_limit.is_none());
        assert!(config.birthday_height.is_none());
    }

    #[test]
    fn set_electrum_endpoint_keeps_hostname() {
        let mut config = test_config();

        config.set_electrum_endpoint("electrum.pythcoiner.dev".to_string(), 50001);

        assert_eq!(config.endpoint().url(), Some("electrum.pythcoiner.dev"));
    }

    #[test]
    fn test_add_default_segwit_sub_account() {
        let mut config = test_config();

        config
            .add_default_segwit_sub_account()
            .expect("segwit sub-account descriptor");

        assert_eq!(config.descriptors.len(), 1);
        assert!(config.descriptors[0]
            .descriptor
            .to_string()
            .starts_with("wpkh("));
        assert!(config.descriptors[0].mnemonic.is_none());
        assert!(config.descriptors[0].endpoint.server().is_none());
    }

    #[test]
    fn test_add_default_taproot_sub_account() {
        let mut config = test_config();

        config
            .add_default_taproot_sub_account()
            .expect("taproot sub-account descriptor");

        assert_eq!(config.descriptors.len(), 1);
        assert!(config.descriptors[0]
            .descriptor
            .to_string()
            .starts_with("tr("));
        assert!(config.descriptors[0].mnemonic.is_none());
        assert!(config.descriptors[0].endpoint.server().is_none());
    }

    #[test]
    fn test_default_sub_account_helpers_are_idempotent() {
        let mut config = test_config();

        config
            .add_default_segwit_sub_account()
            .expect("first segwit insert");
        config
            .add_default_taproot_sub_account()
            .expect("first taproot insert");
        config
            .add_default_segwit_sub_account()
            .expect("second segwit insert");
        config
            .add_default_taproot_sub_account()
            .expect("second taproot insert");

        assert_eq!(config.descriptors.len(), 2);
    }

    #[test]
    fn test_default_sub_account_helpers_require_mnemonic() {
        let mut config = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
        .expect("valid keys");

        assert!(matches!(
            config.add_default_segwit_sub_account(),
            Err(ConfigError::MissingMnemonic)
        ));
        assert!(matches!(
            config.add_default_taproot_sub_account(),
            Err(ConfigError::MissingMnemonic)
        ));
        assert!(config.descriptors.is_empty());
    }

    #[test]
    fn test_external_mnemonic_sub_account_helpers_store_signer_material() {
        let mut config = test_config();
        let external_mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";

        config
            .add_segwit_sub_account_from_mnemonic(external_mnemonic)
            .expect("external segwit descriptor");
        config
            .add_taproot_sub_account_from_mnemonic(external_mnemonic)
            .expect("external taproot descriptor");

        assert_eq!(config.descriptors.len(), 2);
        assert!(config.descriptors[0]
            .descriptor
            .to_string()
            .starts_with("wpkh("));
        assert!(config.descriptors[1]
            .descriptor
            .to_string()
            .starts_with("tr("));
        assert!(config
            .descriptors
            .iter()
            .all(|sub| sub.mnemonic.as_deref() == Some(external_mnemonic)));
    }

    #[test]
    fn unknown_word_error_hides_mnemonic_words() {
        let mut config = test_config();

        let err = config
            .add_taproot_sub_account_from_mnemonic(mnemonic_probe::UNKNOWN_MNEMONIC)
            .unwrap_err();

        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::UNKNOWN_MNEMONIC);
        assert_eq!(err.to_string(), "signer error: Fail to create derivator");
        assert_eq!(format!("{err:?}"), "Signer(Derivator)");
    }

    #[test]
    fn checksum_error_hides_mnemonic_words() {
        let mut config = test_config();

        let err = config
            .add_taproot_sub_account_from_mnemonic(mnemonic_probe::BAD_CHECKSUM_MNEMONIC)
            .unwrap_err();

        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::BAD_CHECKSUM_MNEMONIC);
        assert_eq!(err.to_string(), "signer error: Fail to create derivator");
        assert_eq!(format!("{err:?}"), "Signer(Derivator)");
    }

    #[test]
    fn test_config_from_keys_valid() {
        let config = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
        .expect("valid keys");

        assert_eq!(config.account_name, "bob");
        assert_eq!(config.network, Network::Bitcoin);
        assert!(config.mnemonic.is_none());
        assert!(config.scan_sk.is_some());
        assert!(config.spend_key.is_some());
        assert!(config.persist);
    }

    #[test]
    fn test_config_from_keys_with_pubkey() {
        // 66 hex chars = compressed public key (33 bytes)
        let config = Config::from_keys(
            "watch".to_string(),
            Network::Signet,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "02fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
        .expect("valid keys with pubkey");

        assert_eq!(
            config.spend_key,
            Some("02fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string())
        );
    }

    #[test]
    fn test_config_from_keys_scan_sk_wrong_length() {
        let result = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "0123456789abcdef".to_string(), // Too short (16 chars instead of 64)
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(matches!(result, Err(ConfigError::ScanSkLength)));
    }

    #[test]
    fn test_config_from_keys_scan_sk_invalid_hex() {
        let result = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "zzzz456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(), // Invalid hex
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(matches!(result, Err(ConfigError::ScanSkHex(_))));
    }

    #[test]
    fn test_config_from_keys_spend_key_wrong_length() {
        let result = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "fedcba98765432".to_string(), // Too short (14 chars instead of 64 or 66)
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(matches!(result, Err(ConfigError::SpendKeyLength)));
    }

    #[test]
    fn test_config_from_keys_spend_key_invalid_hex() {
        let result = Config::from_keys(
            "bob".to_string(),
            Network::Bitcoin,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            "ggggba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(), // Invalid hex
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(matches!(result, Err(ConfigError::SpendKeyHex(_))));
    }

    #[test]
    fn test_config_paths() {
        let config = Config::new(
            "alice".to_string(),
            Network::Signet,
            "test mnemonic".to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/test"),
        );

        assert_eq!(config.account_dir(), Path::new("/tmp/test/alice"));
        assert_eq!(
            config.account_dir().join(CONFIG_FILENAME),
            Path::new("/tmp/test/alice/config.json")
        );
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = test_config();

        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let loaded: Config = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(config.account_name, loaded.account_name);
        assert_eq!(config.network, loaded.network);
        assert_eq!(config.mnemonic, loaded.mnemonic);
        assert_eq!(config.blindbit_url, loaded.blindbit_url);
        assert_eq!(config.data_dir, loaded.data_dir);
        // persist is skipped during serialization, so it won't roundtrip
        assert!(!loaded.persist); // Default for bool is false
    }

    #[test]
    fn test_config_setters() {
        let mut config = test_config();

        config.set_blindbit_url("https://new-url.com".to_string());
        assert_eq!(config.blindbit_url(), "https://new-url.com");

        config.set_dust_limit(Some(546));
        assert_eq!(config.dust_limit, Some(546));

        config.set_birthday_height(Some(850000));
        assert_eq!(config.birthday_height, Some(850000));
    }

    #[test]
    fn test_config_enable_persist_builder() {
        let config = test_config().enable_persist(false);
        assert!(!config.persist);

        let config = config.enable_persist(true);
        assert!(config.persist);
    }

    #[test]
    fn test_config_getters() {
        let config = test_config();

        assert_eq!(config.account_name(), "alice");
        assert_eq!(config.network(), Network::Signet);
        assert_eq!(config.blindbit_url(), "https://blindbit.example.com");
    }

    #[test]
    fn test_config_round_trips_through_file_store() {
        use bwk::persist::{ConfigStore, FileConfigStore};
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-config-test");
        let _ = fs::remove_dir_all(&temp_dir);

        let config = Config::new(
            "test-account".to_string(),
            Network::Signet,
            "test mnemonic phrase".to_string(),
            "https://blindbit.example.com".to_string(),
            temp_dir.clone(),
        );

        let store: FileConfigStore<Config> =
            FileConfigStore::new(config.account_dir().join(CONFIG_FILENAME));
        store.save(&config.for_persistence()).unwrap();
        let loaded = store.load().unwrap().expect("config persisted");

        assert_eq!(config.account_name, loaded.account_name);
        assert_eq!(config.network, loaded.network);
        assert_eq!(config.mnemonic, loaded.mnemonic);
        assert_eq!(config.blindbit_url, loaded.blindbit_url);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_file_store_load_returns_none_when_missing() {
        use bwk::persist::{ConfigStore, FileConfigStore};

        let store: FileConfigStore<Config> =
            FileConfigStore::new(PathBuf::from("/nonexistent/path/config.json"));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_for_persistence_under_sqlite_strips_all_signer_material() {
        let unique_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let unique_scan_sk =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let unique_spend_key =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string();

        let mut config = Config::new(
            "alice".to_string(),
            Network::Signet,
            unique_mnemonic.clone(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp"),
        );
        config.scan_sk = Some(unique_scan_sk.clone());
        config.spend_key = Some(unique_spend_key.clone());
        config
            .add_segwit_sub_account_from_mnemonic(&unique_mnemonic)
            .expect("external sub-account");
        config.persist_kind = bwk::persist::PersistenceKind::Sqlite;

        let view = config.for_persistence();
        assert!(view.mnemonic.is_none());
        assert!(view.scan_sk.is_none());
        assert!(view.spend_key.is_none());
        assert!(view.descriptors.iter().all(|sub| sub.mnemonic.is_none()));

        let serialized = serde_json::to_string_pretty(&view).unwrap();
        for needle in [&unique_mnemonic, &unique_scan_sk, &unique_spend_key] {
            assert!(
                !serialized.contains(needle),
                "{needle:?} must not appear in serialized form under SQLite mode: {serialized}"
            );
        }
    }

    #[test]
    fn test_for_persistence_under_json_preserves_mnemonic() {
        let unique_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let config = Config::new(
            "alice".to_string(),
            Network::Signet,
            unique_mnemonic.clone(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp"),
        );

        let view = config.for_persistence();
        assert_eq!(view.mnemonic, Some(unique_mnemonic.clone()));

        let serialized = serde_json::to_string_pretty(&view).unwrap();
        assert!(
            serialized.contains(&unique_mnemonic),
            "mnemonic must appear under default JSON mode"
        );
    }

    /// bwk-persist builds the sqlite backend only under its own feature, so
    /// bwk-sp has to forward it or `PersistenceKind::Sqlite` is unreachable
    /// from here whatever the caller asks for.
    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_backend_is_reachable_under_the_feature() {
        let dir = std::env::temp_dir().join("bwk-sp-sqlite-feature");
        let _ = std::fs::remove_dir_all(&dir);

        let backend =
            bwk::persist::build_backend(Some(bwk::persist::PersistenceKind::Sqlite), dir.clone());
        assert!(backend.is_ok(), "{:?}", backend.err());

        // The backend holds the account-dir lock until it drops.
        drop(backend);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_config_error_display() {
        // Test Io error variant
        let err = ConfigError::Io("file not found".to_string());
        let msg = err.to_string();
        assert!(msg.contains("io error"));
        assert!(msg.contains("file not found"));

        // Test Parse error variant
        let err = ConfigError::Parse("invalid json".to_string());
        let msg = err.to_string();
        assert!(msg.contains("parse error"));
        assert!(msg.contains("invalid json"));

        // Test a key-validation error variant
        let err = ConfigError::ScanSkLength;
        let msg = err.to_string();
        assert!(msg.contains("scan_sk must be 64 hex chars"));
    }
}
