use std::{path::PathBuf, str::FromStr};

use bwk_descriptor::descriptor::ScriptType;
use bwk_electrum::config::ScannerConfig;
use bwk_persist::PersistenceKind;
use bwk_sign::hot_signer::HotSigner;
use miniscript::{bitcoin, Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

/// The directory `datadir` hangs its subdirectory off: the home directory on
/// Linux, the platform's config location on macOS and Windows.
///
/// `None` when the variable it reads is unset or empty.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn base_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
    }

    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(|home| PathBuf::from(home).join("Library/Application Support"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .filter(|appdata| !appdata.is_empty())
            .map(PathBuf::from)
    }
}

/// Filename used by [`bwk_persist::FileConfigStore`].
///
/// Lives on `Config` for backwards-compat with existing on-disk layouts;
/// one could build its `FileConfigStore` path as
/// `config.scanner.account_dir().join(Config::CONFIG_FILENAME)`.
pub const CONFIG_FILENAME: &str = "config.json";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const BASE_DIR_VAR_MISSING: &str = "HOME is unset or empty";
#[cfg(target_os = "windows")]
const BASE_DIR_VAR_MISSING: &str = "APPDATA is unset or empty";

/// Returns the OS-specific data directory under `dir_name`.
///
/// Supported targets are desktop Linux, macOS and Windows, and nothing else.
/// A desktop session always sets the variable [`base_dir`] reads, so the
/// `expect` cannot fire there; off those targets, or outside a user session,
/// this is the wrong entry point. Every other consumer (mobile, embedded, a
/// daemon) computes its data path natively and passes it as `data_dir` to
/// [`Config::new`] instead of calling this.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn datadir(dir_name: &str) -> PathBuf {
    let mut dir = base_dir().expect(BASE_DIR_VAR_MISSING);
    dir.push(dir_name);

    maybe_create_dir(&dir);

    dir
}

/// Creates a directory if it does not exist.
pub fn maybe_create_dir(dir: &PathBuf) {
    if !dir.exists() {
        #[cfg(unix)]
        {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;

            let mut builder = DirBuilder::new();
            builder.mode(0o700).recursive(true).create(dir).unwrap();
        }

        #[cfg(not(unix))]
        std::fs::create_dir_all(dir).unwrap();
    }
}

/// Represents the configuration settings for the application.
///
/// Everything the scanner needs lives in [`Config::scanner`]; this struct adds
/// only the wallet-level settings. The scanner half is flattened on the wire,
/// so the serialized shape stays flat.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(flatten)]
    pub scanner: ScannerConfig,
    pub mnemonic: Option<String>,
}

impl Config {
    /// Creates a new `Config` instance with the specified descriptor.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - A string representing the mnemonic words.
    /// * `account` - A string representing the account name.
    /// * `network` - the bitcoin network for this config.
    ///
    /// # Returns
    ///
    /// A `Config` instance initialized with the provided descriptor.
    pub fn new(
        mnemonic: Option<String>,
        account: String,
        network: bitcoin::Network,
        script: ScriptType,
        data_dir: PathBuf,
        dir_name: String,
        persistence: Option<PersistenceKind>,
    ) -> Option<Config> {
        let descriptor = match script {
            ScriptType::Segwit(_) | ScriptType::Taproot(_) => {
                if let Some(mnemo) = &mnemonic {
                    let signer = HotSigner::new_from_mnemonics(network, mnemo).unwrap();
                    script.to_descriptor(network, |d| signer.xpub(&d)).unwrap()
                } else {
                    return None;
                }
            }
            ScriptType::Descriptor(descriptor) => *descriptor,
        };
        Some(Config {
            scanner: ScannerConfig::new(
                descriptor,
                data_dir,
                dir_name,
                account,
                network,
                persistence,
            ),
            mnemonic,
        })
    }

    /// View of this config that's safe to persist to disk.
    ///
    /// Under [`PersistenceKind::Sqlite`] the mnemonic is stripped so it
    /// never lands on disk; under [`PersistenceKind::Json`] (default)
    /// the config is returned unchanged. Used by `Account` when handing
    /// config to a [`bwk_persist::ConfigStore`].
    pub fn for_persistence(&self) -> Config {
        if self.excludes_signer_data() {
            let mut stripped = self.clone();
            stripped.mnemonic = None;
            stripped
        } else {
            self.clone()
        }
    }

    /// Select how this account persists, `None` disabling it entirely.
    ///
    /// Under [`PersistenceKind::Sqlite`], signer material (mnemonic / any
    /// private key) is never written to disk: not to `config.json`, not to
    /// the SQLite file, not to `.signers`. See [`bwk_persist`] for the
    /// full rule. Callers must re-supply the seed on the next run.
    pub fn with_persistence(mut self, persistence: Option<PersistenceKind>) -> Self {
        self.scanner.persistence = persistence;
        self
    }

    /// Is this config configured to keep signer material out of on-disk
    /// writes?
    pub fn excludes_signer_data(&self) -> bool {
        matches!(self.scanner.persistence, Some(PersistenceKind::Sqlite))
    }

    /// Sets the Electrum url. A different url resets the certificate policy,
    /// see [`ScannerConfig::set_electrum`](bwk_electrum::config::ScannerConfig::set_electrum).
    pub fn set_electrum_url(&mut self, url: String) {
        let port = self.scanner.endpoint().port();
        self.scanner.set_electrum(Some(url), port);
    }
    /// Sets the Electrum port from a string. A different port resets the
    /// certificate policy, see
    /// [`ScannerConfig::set_electrum`](bwk_electrum::config::ScannerConfig::set_electrum).
    pub fn set_electrum_port(&mut self, port: String) {
        let url = self.scanner.endpoint().url().map(str::to_string);
        self.scanner.set_electrum(url, port.parse::<u16>().ok());
    }
    /// Sets the look-ahead value from a string.
    pub fn set_look_ahead(&mut self, look_ahead: String) {
        if let Ok(la) = look_ahead.parse::<u32>() {
            self.scanner.look_ahead = la;
        }
    }
    /// Sets the mnemonic.
    pub fn set_mnemonic(&mut self, mnemonic: String) {
        self.mnemonic = Some(mnemonic);
    }
}

/// Checks if the provided descriptor string is valid.
///
/// # Arguments
///
/// * `descriptor` - A string representing the descriptor to validate.
pub fn is_descriptor_valid(descriptor: String) -> bool {
    Descriptor::<DescriptorPublicKey>::from_str(&descriptor).is_ok()
}

#[cfg(test)]
pub mod tests {
    use bwk_persist::{ConfigStore, FileConfigStore};
    use miniscript::bitcoin::bip32::ChildNumber;

    use super::*;

    #[test]
    fn config_round_trips_through_file_store() {
        let temp = temp_dir::TempDir::new().unwrap();
        let path = temp.child("storage");
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        let cfg = Config::new(
            Some(mnemonic.to_string()),
            "my_account".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path.clone(),
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();

        let store: FileConfigStore<Config> =
            FileConfigStore::new(cfg.scanner.account_dir().join(CONFIG_FILENAME));
        store.save(&cfg.for_persistence()).unwrap();
        let cfg2 = store.load().unwrap().expect("config persisted");
        assert_eq!(cfg.scanner.account, cfg2.scanner.account);
        assert_eq!(cfg2.scanner.account, "my_account");
    }

    #[test]
    fn set_electrum_url_sets_hostname() {
        let temp = temp_dir::TempDir::new().unwrap();
        let path = temp.child("storage");
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        let mut cfg = Config::new(
            Some(mnemonic.to_string()),
            "my_account".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();

        cfg.set_electrum_url("electrum.pythcoiner.dev".to_string());

        assert_eq!(
            cfg.scanner.endpoint().url(),
            Some("electrum.pythcoiner.dev")
        );
    }

    /// `scanner` is flattened, so the on-disk object must stay flat: no
    /// `scanner` key, every scanner field at the top level.
    #[test]
    fn config_json_stays_flat() {
        let temp = temp_dir::TempDir::new().unwrap();
        let path = temp.child("storage");
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let mut cfg = Config::new(
            Some(mnemonic.clone()),
            "alice".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();
        cfg.set_electrum_url("electrum.pythcoiner.dev".to_string());
        cfg.set_electrum_port("50002".to_string());

        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let expected = r#"{
  "account": "alice",
  "electrum_url": "electrum.pythcoiner.dev",
  "electrum_port": 50002,
  "certificate_check": "validate",
  "stay_offline": false,
  "network": "regtest",
  "look_ahead": 20,
  "descriptor": "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)#gwycrcrh",
  "persistence": "json",
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}"#;
        assert_eq!(json, expected);

        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scanner.account, "alice");
        assert_eq!(back.scanner.network, bitcoin::Network::Regtest);
        assert_eq!(back.scanner.look_ahead, 20);
        assert_eq!(back.scanner.descriptor, cfg.scanner.descriptor);
        assert_eq!(back.scanner.endpoint().port(), Some(50002));
        assert_eq!(back.scanner.persistence, Some(PersistenceKind::Json));
        assert_eq!(back.mnemonic, Some(mnemonic));
    }

    #[test]
    fn for_persistence_under_sqlite_strips_mnemonic() {
        let temp = temp_dir::TempDir::new().unwrap();
        let path = temp.child("storage");
        let unique = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let mut cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path.clone(),
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();
        cfg.scanner.persistence = Some(PersistenceKind::Sqlite);

        let view = cfg.for_persistence();
        assert!(
            view.mnemonic.is_none(),
            "mnemonic must be stripped under SQLite"
        );
        let serialized = serde_json::to_string_pretty(&view).unwrap();
        assert!(
            !serialized.contains(&unique),
            "mnemonic must not appear in serialized form under SQLite mode: {serialized}"
        );
    }

    #[test]
    fn for_persistence_under_json_preserves_mnemonic() {
        let temp = temp_dir::TempDir::new().unwrap();
        let path = temp.child("storage");
        let unique = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path.clone(),
            "wallet".to_string(),
            Some(PersistenceKind::Json),
        )
        .unwrap();

        let view = cfg.for_persistence();
        assert_eq!(view.mnemonic, Some(unique.clone()));
        let serialized = serde_json::to_string_pretty(&view).unwrap();
        assert!(
            serialized.contains(&unique),
            "mnemonic must appear in serialized form under JSON mode (default)"
        );
    }
}
