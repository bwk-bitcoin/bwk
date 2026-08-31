//! Configuration for the scanner half of a wallet.
//!
//! This is what an `ElectrumScanner` needs to watch a descriptor: where to
//! store its data, which server to talk to and how far to look ahead.
//! Wallet-level settings such as a mnemonic live in the consumer's own config.

use std::{path::PathBuf, sync::Arc};

use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

use bwk_descriptor::{derivator, descriptor::DescriptorDerivator};
use bwk_persist::{PersistError, PersistenceBackend, PersistenceKind};

/// Filename for the binary header cache under [`ScannerConfig::account_dir`].
/// Headers are always binary-backed, independent of `persistence`.
pub const HEADERS_FILENAME: &str = "headers.bin";

/// An Electrum server to talk to. The url and the port only ever move
/// together, through [`Endpoint::set`] or [`Endpoint::clear`]: a scan can
/// reach a server only once both halves name the same one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    #[serde(
        rename = "electrum_url",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    url: Option<String>,
    #[serde(
        rename = "electrum_port",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    port: Option<u16>,
}

impl Endpoint {
    /// Point at `url`/`port`.
    pub fn set(&mut self, url: Option<String>, port: Option<u16>) {
        self.url = url;
        self.port = port;
    }

    /// Forget the server.
    pub fn clear(&mut self) {
        self.set(None, None);
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The server to reach, `None` while either half is unset.
    pub fn server(&self) -> Option<(&str, u16)> {
        self.url.as_deref().zip(self.port)
    }

    /// This endpoint while it names a server, `None` otherwise.
    pub fn configured(&self) -> Option<&Self> {
        self.server().is_some().then_some(self)
    }
}

/// The derivation indexes reached on each keychain.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tip {
    pub receive: u32,
    pub change: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScannerConfig {
    #[serde(skip)]
    pub data_dir: PathBuf,
    #[serde(skip)]
    pub dir_name: String,
    pub account: String,
    /// Private so the url and the port only ever move together, see
    /// [`Endpoint`].
    #[serde(flatten)]
    endpoint: Endpoint,
    /// The consumer's intent: `true` keeps the scan from connecting on the
    /// next open. Unrelated to whether a connection is currently up.
    #[serde(default)]
    pub stay_offline: bool,
    pub network: miniscript::bitcoin::Network,
    pub look_ahead: u32,
    pub descriptor: Descriptor<DescriptorPublicKey>,
    /// Which backend keeps this account's data, `None` for in-memory only.
    pub persistence: Option<PersistenceKind>,
}

impl ScannerConfig {
    /// A scanner watching `descriptor`, with the defaults for everything the
    /// caller has no opinion on: online, no server pinned, 20 addresses of
    /// look-ahead.
    pub fn new(
        descriptor: Descriptor<DescriptorPublicKey>,
        data_dir: PathBuf,
        dir_name: String,
        account: String,
        network: miniscript::bitcoin::Network,
        persistence: Option<PersistenceKind>,
    ) -> Self {
        Self {
            data_dir,
            dir_name,
            account,
            endpoint: Endpoint::default(),
            stay_offline: false,
            network,
            look_ahead: 20,
            descriptor,
            persistence,
        }
    }

    /// Check the descriptor is one the scan can derive from: multipath,
    /// unhardened, wildcarded and on `network`. Callers run it before opening
    /// any store, so a descriptor the derivator rejects errors out instead of
    /// panicking once the coin store is built.
    pub fn validate_descriptor(&self) -> Result<(), derivator::Error> {
        self.descriptor.spk_derivator(self.network).map(|_| ())
    }

    /// Open the persistence backend this config selects, rooted at
    /// [`ScannerConfig::account_dir`]. `NoopBackend` when `persistence` is
    /// `None`.
    pub fn build_backend(&self) -> Result<Arc<dyn PersistenceBackend>, PersistError> {
        bwk_persist::build_backend(self.persistence, self.account_dir())
    }

    pub fn set_stay_offline(&mut self, stay_offline: bool) {
        self.stay_offline = stay_offline;
    }

    /// Point the scan at `url`/`port`, see [`Endpoint::set`].
    pub fn set_electrum(&mut self, url: Option<String>, port: Option<u16>) {
        self.endpoint.set(url, port);
    }

    /// Watch `endpoint`, url and port together.
    pub fn set_endpoint(&mut self, endpoint: Endpoint) {
        self.endpoint = endpoint;
    }

    /// The server this scan watches from, unset while none is configured. Says
    /// nothing about [`stay_offline`](Self::stay_offline), the intent to not
    /// connect at all.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Where this account's files (or SQLite DB) live.
    pub fn account_dir(&self) -> PathBuf {
        let mut dir = self.data_dir.clone();
        dir.push(&self.dir_name);
        dir.push(&self.account);
        dir
    }

    pub fn stay_offline(&self) -> bool {
        self.stay_offline
    }
}
