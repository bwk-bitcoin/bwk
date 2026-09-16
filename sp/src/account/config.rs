//! Configuration for Silent Payment accounts.
//!
//! The `Config` struct holds all settings needed to create and operate
//! a silent payment wallet account.

use std::{
    fs,
    path::{Path, PathBuf},
};

use bitcoin::{bip32::ChildNumber, secp256k1::Secp256k1, Network, NetworkKind};
use bwk::bwk_electrum::{config::Endpoint, raw_client::CertificateCheck};
use bwk_sign::{
    bwk_descriptor::{
        self,
        descriptor::Descriptor,
        sp_descriptor::SpDescriptor,
        sp_key::{SpKey, SpSpendKey},
    },
    hot_signer::HotSigner,
};
use serde::{Deserialize, Serialize};

use crate::receiver;

mod sp_descriptor_serde {
    use std::str::FromStr;

    use bwk_sign::bwk_descriptor::sp_descriptor::SpDescriptor;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(descriptor: &SpDescriptor, s: S) -> Result<S::Ok, S::Error> {
        descriptor.to_string().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SpDescriptor, D::Error> {
        let s = String::deserialize(d)?;
        SpDescriptor::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Default filename a [`bwk::persist::config_store::FileConfigStore`] uses for an
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

    // Keys
    /// BIP39 mnemonic phrase (for hot wallet). Construction parameter only;
    /// never persisted.
    #[serde(skip)]
    pub mnemonic: Option<String>,
    /// BIP392 `sp()` descriptor holding the scan key and spend key; the sole
    /// source of truth for this account's silent-payment key material.
    #[serde(with = "sp_descriptor_serde")]
    pub descriptor: SpDescriptor,

    // Backend
    /// Blindbit server URL for chain data
    pub blindbit_url: String,
    /// Electrum server used to broadcast spends (blindbit is read-only), and
    /// the certificate policy to reach it under. Private so [`Endpoint`] stays
    /// the only way to move it, see [`Endpoint::set`].
    #[serde(flatten)]
    endpoint: Endpoint,

    // Persistence
    /// Base directory for account data
    pub data_dir: PathBuf,
    /// Which backend keeps this account's data, `None` for in-memory only.
    ///
    /// `Json`: byte-for-byte compatible with the pre-backend layout.
    /// `Sqlite`: single `account.sqlite` file per account.
    pub persistence: Option<bwk::persist::PersistenceKind>,

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
    /// Descriptor for this sub-account: a miniscript descriptor (e.g. wpkh
    /// or tr) or a BIP392 `sp()` silent-payment descriptor.
    pub descriptor: Descriptor,
    /// Optional mnemonic used to sign this sub-account.
    ///
    /// When absent, [`Account`](crate::account::Account) uses the parent SP
    /// config's mnemonic. This field is only needed for externally supplied
    /// sub-account mnemonics. Construction parameter only; never persisted.
    #[serde(skip)]
    pub mnemonic: Option<String>,
    /// Electrum server this sub-account watches (offline while unset), and the
    /// certificate policy to reach it under. Its own: a policy the SP account
    /// picked for its server says nothing about this one.
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
    /// is stored in memory. Derives the account's `sp()` descriptor from the
    /// mnemonic at the BIP352 paths.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Signer`] if the mnemonic is invalid.
    pub fn new(
        account_name: String,
        network: Network,
        mnemonic: String,
        blindbit_url: String,
        data_dir: PathBuf,
    ) -> Result<Self, ConfigError> {
        let descriptor = Self::derive_descriptor(network, &mnemonic)?;
        Ok(Self {
            account_name,
            network,
            mnemonic: Some(mnemonic),
            descriptor,
            blindbit_url,
            endpoint: Endpoint::default(),
            data_dir,
            persistence: Some(bwk::persist::PersistenceKind::default()),
            dust_limit: None,
            birthday_height: None,
            descriptors: Vec::new(),
        })
    }

    /// Create a new watch-only Config from an already-parsed BIP392 `sp()`
    /// descriptor.
    ///
    /// This is the constructor for watch-only wallets: a descriptor such as
    /// `sp(scan_priv,spend_pub)` carries every key the account needs, with no
    /// mnemonic and no spend secret key held in memory.
    pub fn from_descriptor(
        account_name: String,
        network: Network,
        descriptor: SpDescriptor,
        blindbit_url: String,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            account_name,
            network,
            mnemonic: None,
            descriptor,
            blindbit_url,
            endpoint: Endpoint::default(),
            data_dir,
            persistence: Some(bwk::persist::PersistenceKind::default()),
            dust_limit: None,
            birthday_height: None,
            descriptors: Vec::new(),
        }
    }

    fn derive_descriptor(network: Network, mnemonic: &str) -> Result<SpDescriptor, ConfigError> {
        let signer =
            HotSigner::new_from_mnemonics(network, mnemonic).map_err(ConfigError::Signer)?;
        let account = ChildNumber::from_hardened_idx(0).expect("hardcoded account index");
        Ok(SpDescriptor::Packed {
            origin: None,
            key: SpKey::Spend(SpSpendKey {
                scan_key: signer.private_key_at(&receiver::scan_path(network, account)),
                spend_key: signer.private_key_at(&receiver::spend_path(network, account)),
                network: NetworkKind::from(network),
            }),
        })
    }

    // Sanitization

    /// Sanitize all config values, clamping or fixing invalid fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MnemonicDescriptorMismatch`] if a mnemonic is
    /// set and it does not derive this config's `sp()` descriptor.
    pub fn sanitize(&mut self) -> Result<(), ConfigError> {
        // Birthday height
        let min = self.min_birthday_height();
        match self.birthday_height {
            Some(h) if h < min => self.birthday_height = Some(min),
            None => self.birthday_height = Some(min),
            _ => {}
        }

        self.check_mnemonic_matches_descriptor()
    }

    /// Verify that `self.mnemonic`, when present, derives the same BIP352
    /// scan and spend keys as `self.descriptor`. Watch-only configs (no
    /// mnemonic) are always valid.
    fn check_mnemonic_matches_descriptor(&self) -> Result<(), ConfigError> {
        let Some(mnemonic) = self.mnemonic.as_deref() else {
            return Ok(());
        };

        let signer =
            HotSigner::new_from_mnemonics(self.network, mnemonic).map_err(ConfigError::Signer)?;
        let account = ChildNumber::from_hardened_idx(0).expect("hardcoded account index");
        let secp = Secp256k1::new();

        let derived_scan = signer.private_key_at(&receiver::scan_path(self.network, account));
        let derived_spend = signer.private_key_at(&receiver::spend_path(self.network, account));

        let expected_scan = self
            .descriptor
            .scan_secret_key(&secp)
            .map_err(ConfigError::Descriptor)?;
        let expected_spend_pk = self
            .descriptor
            .spend_public_key(&secp)
            .map_err(ConfigError::Descriptor)?;

        if derived_scan != expected_scan || derived_spend.public_key(&secp) != expected_spend_pk {
            return Err(ConfigError::MnemonicDescriptorMismatch);
        }
        Ok(())
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

    /// The Electrum server this account broadcasts through, with the
    /// certificate policy it connects under.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Set the Electrum server endpoint used to broadcast spends, see
    /// [`Endpoint::set`] for what that does to the certificate policy.
    pub fn set_electrum_endpoint(&mut self, url: String, port: u16) {
        self.endpoint.set(Some(url), Some(port));
    }

    /// Forget the Electrum endpoint, see [`Endpoint::clear`].
    pub fn clear_electrum_endpoint(&mut self) {
        self.endpoint.clear();
    }

    /// Connect under `check`, see [`Endpoint::set_certificate_check`].
    pub fn set_certificate_check(&mut self, check: CertificateCheck) {
        self.endpoint.set_certificate_check(check);
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
                let path = bwk_descriptor::descriptor::wpkh_path(self.network, account)
                    .map_err(ConfigError::DescriptorPath)?;
                bwk_descriptor::derivator::SpkDerivator::new_wpkh(signer.xpub(&path), self.network)
                    .map_err(ConfigError::Derivator)?
                    .descriptor()
            }
            SubAccountKind::Taproot => {
                let path = bwk_descriptor::descriptor::tr_path(self.network, account)
                    .map_err(ConfigError::DescriptorPath)?;
                bwk_descriptor::derivator::SpkDerivator::new_tr(signer.xpub(&path), self.network)
                    .map_err(ConfigError::Derivator)?
                    .descriptor()
            }
        };

        self.push_descriptor_maybe(descriptor.into(), sub_account_mnemonic);
        Ok(())
    }

    fn push_descriptor_maybe(&mut self, descriptor: Descriptor, mnemonic: Option<String>) {
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

    /// Select the backend that keeps this account's data, `None` for
    /// in-memory only (builder pattern).
    pub fn with_persistence(mut self, persistence: Option<bwk::persist::PersistenceKind>) -> Self {
        self.persistence = persistence;
        self
    }

    // Path helpers

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
}

/// Errors that can occur when loading or parsing Config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("missing mnemonic")]
    MissingMnemonic,
    #[error("signer error: {0}")]
    Signer(bwk_sign::error::Error),
    #[error("descriptor path error: {0}")]
    DescriptorPath(#[source] bwk_descriptor::descriptor::Error),
    #[error("derivator error: {0}")]
    Derivator(#[source] bwk_descriptor::derivator::Error),
    #[error("descriptor error: {0}")]
    Descriptor(#[source] bwk_descriptor::sp_descriptor::Error),
    #[error("mnemonic does not derive the configured sp() descriptor")]
    MnemonicDescriptorMismatch,
}

#[cfg(test)]
mod tests {
    use std::{path::Path, str::FromStr};

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    use super::*;
    use crate::account::mnemonic_probe;

    const MISMATCHED_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon about";

    fn test_config() -> Config {
        Config::new(
            "alice".to_string(),
            Network::Signet,
            TEST_MNEMONIC.to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
        .unwrap()
    }

    fn watch_only_descriptor() -> SpDescriptor {
        let secp = Secp256k1::new();
        SpDescriptor::Packed {
            origin: None,
            key: SpKey::Scan(bwk_descriptor::sp_key::SpScanKey {
                scan_key: SecretKey::from_slice(&[0x11; 32]).unwrap(),
                spend_key: PublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&[0x22; 32]).unwrap(),
                ),
                network: NetworkKind::Test,
            }),
        }
    }

    /// Build the `sp(scan_priv,spend_priv)` split form of the descriptor
    /// for `mnemonic`, so the spend key is a secret rather than a packed key.
    fn split_descriptor_from_mnemonic(network: Network, mnemonic: &str) -> SpDescriptor {
        let signer = HotSigner::new_from_mnemonics(network, mnemonic).unwrap();
        let account = ChildNumber::from_hardened_idx(0).unwrap();
        let scan_sk = signer.private_key_at(&receiver::scan_path(network, account));
        let spend_sk = signer.private_key_at(&receiver::spend_path(network, account));
        let network_kind = NetworkKind::from(network);
        let scan_wif = bitcoin::PrivateKey::new(scan_sk, network_kind).to_wif();
        let spend_wif = bitcoin::PrivateKey::new(spend_sk, network_kind).to_wif();
        SpDescriptor::from_str(&format!("sp({scan_wif},{spend_wif})")).unwrap()
    }

    #[test]
    fn sanitize_accepts_matching_pair() {
        let mut config = test_config();
        assert!(config.sanitize().is_ok());
    }

    #[test]
    fn sanitize_accepts_watch_only() {
        let mut config = Config::from_descriptor(
            "watch".to_string(),
            Network::Signet,
            watch_only_descriptor(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(config.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_mismatched_mnemonic() {
        let mut config = test_config();
        config.mnemonic = Some(MISMATCHED_MNEMONIC.to_string());

        assert!(matches!(
            config.sanitize(),
            Err(ConfigError::MnemonicDescriptorMismatch)
        ));
    }

    #[test]
    fn sanitize_accepts_signer_form_descriptor() {
        let network = Network::Signet;
        let descriptor = split_descriptor_from_mnemonic(network, TEST_MNEMONIC);
        let mut config = Config::from_descriptor(
            "alice".to_string(),
            network,
            descriptor,
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );
        config.mnemonic = Some(TEST_MNEMONIC.to_string());

        assert!(config.sanitize().is_ok());
    }

    #[test]
    fn sanitize_rejects_wrong_network_derivation() {
        let mut config = Config::new(
            "alice".to_string(),
            Network::Regtest,
            TEST_MNEMONIC.to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        )
        .unwrap();
        config.network = Network::Bitcoin;

        assert!(matches!(
            config.sanitize(),
            Err(ConfigError::MnemonicDescriptorMismatch)
        ));
    }

    #[test]
    fn mismatch_error_hides_mnemonic_words() {
        let mut config = test_config();
        config.mnemonic = Some(MISMATCHED_MNEMONIC.to_string());
        let err = config.sanitize().unwrap_err();
        mnemonic_probe::assert_no_word_leak(&err, TEST_MNEMONIC);
        mnemonic_probe::assert_no_word_leak(&err, MISMATCHED_MNEMONIC);

        let mut unknown_config = test_config();
        unknown_config.mnemonic = Some(mnemonic_probe::UNKNOWN_MNEMONIC.to_string());
        let err = unknown_config.sanitize().unwrap_err();
        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::UNKNOWN_MNEMONIC);

        let mut checksum_config = test_config();
        checksum_config.mnemonic = Some(mnemonic_probe::BAD_CHECKSUM_MNEMONIC.to_string());
        let err = checksum_config.sanitize().unwrap_err();
        mnemonic_probe::assert_no_word_leak(&err, mnemonic_probe::BAD_CHECKSUM_MNEMONIC);
    }

    #[test]
    fn test_config_new_valid() {
        let config = test_config();

        assert_eq!(config.account_name, "alice");
        assert_eq!(config.network, Network::Signet);
        assert!(config.mnemonic.is_some());
        assert!(!config.descriptor.is_watch_only(&Secp256k1::new()).unwrap());
        assert_eq!(config.blindbit_url, "https://blindbit.example.com");
        assert_eq!(config.data_dir, PathBuf::from("/tmp/bwk-test"));
        assert!(config.persistence.is_some()); // Default is on
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
    fn clearing_the_endpoint_puts_the_certificate_choice_back() {
        let mut config = test_config();
        config.set_electrum_endpoint("self.signed.lan".to_string(), 50002);
        config.set_certificate_check(CertificateCheck::DangerAcceptInvalid);

        config.clear_electrum_endpoint();

        assert!(config.endpoint().server().is_none());
        assert_eq!(
            config.endpoint().certificate_check(),
            CertificateCheck::Validate
        );
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
    fn push_descriptor_maybe_deduplicates() {
        let mut config = test_config();

        config.add_default_segwit_sub_account().unwrap();
        config.add_default_segwit_sub_account().unwrap();

        assert_eq!(config.descriptors.len(), 1);
    }

    #[test]
    fn sub_account_config_serde_is_a_bare_string() {
        let mut config = test_config();
        config.add_default_segwit_sub_account().unwrap();

        let json = serde_json::to_value(&config).unwrap();
        let descriptor_value = &json["descriptors"][0]["descriptor"];
        assert_eq!(
            descriptor_value.as_str().unwrap(),
            config.descriptors[0].descriptor.to_string()
        );
    }

    #[test]
    fn sub_account_config_deserializes_a_pre_change_file() {
        let mut config = test_config();
        config.add_default_segwit_sub_account().unwrap();
        let descriptor_str = config.descriptors[0].descriptor.to_string();
        let sp_descriptor_str = config.descriptor.to_string();

        let json = format!(
            r#"{{
                "account_name": "alice",
                "network": "signet",
                "descriptor": "{sp_descriptor_str}",
                "blindbit_url": "https://blindbit.example.com",
                "certificate_check": "validate",
                "data_dir": "/tmp/bwk-test",
                "persistence": "json",
                "dust_limit": null,
                "birthday_height": null,
                "descriptors": [
                    {{
                        "descriptor": "{descriptor_str}",
                        "certificate_check": "validate"
                    }}
                ]
            }}"#
        );

        let loaded: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.descriptors.len(), 1);
        assert!(matches!(
            loaded.descriptors[0].descriptor,
            Descriptor::Miniscript(_)
        ));
        assert_eq!(loaded.descriptors[0].descriptor.to_string(), descriptor_str);
    }

    #[test]
    fn test_default_sub_account_helpers_require_mnemonic() {
        let mut config = Config::from_descriptor(
            "bob".to_string(),
            Network::Bitcoin,
            watch_only_descriptor(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

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
    fn from_descriptor_needs_no_mnemonic() {
        let descriptor = watch_only_descriptor();
        let config = Config::from_descriptor(
            "watch".to_string(),
            Network::Signet,
            descriptor.clone(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/bwk-test"),
        );

        assert!(config.mnemonic.is_none());
        let roundtrip: SpDescriptor = config.descriptor.to_string().parse().unwrap();
        assert_eq!(roundtrip, descriptor);
    }

    #[test]
    fn new_derives_descriptor_from_mnemonic() {
        let network = Network::Signet;
        let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).unwrap();
        let account = ChildNumber::from_hardened_idx(0).unwrap();
        let expected_scan = signer.private_key_at(&receiver::scan_path(network, account));
        let expected_spend = signer.private_key_at(&receiver::spend_path(network, account));
        let secp = Secp256k1::new();

        let config = test_config();

        assert_eq!(
            config.descriptor.scan_secret_key(&secp).unwrap(),
            expected_scan
        );
        assert_eq!(
            config.descriptor.spend_public_key(&secp).unwrap(),
            PublicKey::from_secret_key(&secp, &expected_spend)
        );
    }

    #[test]
    fn test_config_paths() {
        let config = Config::new(
            "alice".to_string(),
            Network::Signet,
            TEST_MNEMONIC.to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp/test"),
        )
        .unwrap();

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
        assert!(loaded.mnemonic.is_none());
        assert_eq!(config.descriptor, loaded.descriptor);
        assert_eq!(config.blindbit_url, loaded.blindbit_url);
        assert_eq!(config.data_dir, loaded.data_dir);
        assert_eq!(config.persistence, loaded.persistence);
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
    fn test_config_with_persistence_builder() {
        let config = test_config().with_persistence(None);
        assert!(config.persistence.is_none());

        let config = config.with_persistence(Some(bwk::persist::PersistenceKind::Json));
        assert_eq!(
            config.persistence,
            Some(bwk::persist::PersistenceKind::Json)
        );
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
        use bwk::persist::config_store::{ConfigStore, FileConfigStore};
        use std::env;

        let temp_dir = env::temp_dir().join("bwk-sp-config-test");
        let _ = fs::remove_dir_all(&temp_dir);

        let config = Config::new(
            "test-account".to_string(),
            Network::Signet,
            TEST_MNEMONIC.to_string(),
            "https://blindbit.example.com".to_string(),
            temp_dir.clone(),
        )
        .unwrap();

        let store: FileConfigStore<Config> =
            FileConfigStore::new(config.account_dir().join(CONFIG_FILENAME));
        store.save(&config).unwrap();
        let loaded = store.load().unwrap().expect("config persisted");

        assert_eq!(config.account_name, loaded.account_name);
        assert_eq!(config.network, loaded.network);
        assert!(loaded.mnemonic.is_none());
        assert_eq!(config.descriptor, loaded.descriptor);
        assert_eq!(config.blindbit_url, loaded.blindbit_url);
        assert_eq!(config.persistence, loaded.persistence);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_file_store_load_returns_none_when_missing() {
        use bwk::persist::config_store::{ConfigStore, FileConfigStore};

        let store: FileConfigStore<Config> =
            FileConfigStore::new(PathBuf::from("/nonexistent/path/config.json"));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn mnemonic_never_serialized() {
        let config = Config::new(
            "alice".to_string(),
            Network::Signet,
            TEST_MNEMONIC.to_string(),
            "https://blindbit.example.com".to_string(),
            PathBuf::from("/tmp"),
        )
        .unwrap();

        let serialized = serde_json::to_string_pretty(&config).unwrap();
        assert!(
            !serialized.contains(TEST_MNEMONIC),
            "mnemonic must never appear in serialized form: {serialized}"
        );
        assert!(serialized.contains(&config.descriptor.to_string()));
    }

    #[test]
    fn sub_account_mnemonic_never_serialized() {
        let mut config = test_config();
        let sub_account_mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        config
            .add_segwit_sub_account_from_mnemonic(sub_account_mnemonic)
            .unwrap();

        let serialized = serde_json::to_string_pretty(&config).unwrap();
        assert!(
            !serialized.contains(sub_account_mnemonic),
            "sub-account mnemonic must never appear in serialized form: {serialized}"
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
        let err = ConfigError::MissingMnemonic;
        let msg = err.to_string();
        assert!(msg.contains("missing mnemonic"));
    }
}
