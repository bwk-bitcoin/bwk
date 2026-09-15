//! Configuration for the scanner half of a wallet.
//!
//! This is what an `ElectrumScanner` needs to watch a descriptor: where to
//! store its data, which server to talk to and how far to look ahead.
//! Wallet-level settings such as a mnemonic live in the consumer's own config.

use std::{path::PathBuf, sync::Arc};

use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

use bwk_descriptor::{derivator, descriptor::DescriptorDerivator};
use bwk_persist::{backend::PersistenceBackend, PersistError, PersistenceKind};

use crate::raw_client::CertificateCheck;

/// Filename for the binary header cache under [`ScannerConfig::account_dir`].
/// Headers are always binary-backed, independent of `persistence`.
pub const HEADERS_FILENAME: &str = "headers.bin";

/// Unused addresses watched past the generated tip, for a caller with no
/// opinion of its own.
pub const DEFAULT_LOOK_AHEAD: u32 = 20;

/// An Electrum server to talk to, with the certificate policy to connect
/// under. The two travel together: a policy picked to reach one self-signed
/// server says nothing about the next one, so every path that moves the
/// endpoint goes through [`Endpoint::set`] or [`Endpoint::clear`].
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
    /// Whether the server TLS certificate is verified.
    /// [`CertificateCheck::DangerAcceptInvalid`] skips the chain of trust, the
    /// expiry and the hostname, so any party on the network path can
    /// impersonate the server. Only pick it to reach a self-signed or onion
    /// server.
    certificate_check: CertificateCheck,
}

impl Endpoint {
    /// Point at `url`/`port`.
    ///
    /// A different endpoint resets
    /// [`certificate_check`](Self::certificate_check) to
    /// [`CertificateCheck::Validate`]: a choice made to reach one self-signed
    /// server must not silently carry over to another.
    pub fn set(&mut self, url: Option<String>, port: Option<u16>) {
        if (&self.url, self.port) != (&url, port) {
            self.certificate_check = CertificateCheck::Validate;
        }
        self.url = url;
        self.port = port;
    }

    /// Forget the server, putting the certificate policy back to validating so
    /// it cannot outlive the server it was chosen for.
    pub fn clear(&mut self) {
        self.set(None, None);
    }

    /// Connect under `check`. Set the server first: pointing at another one
    /// afterwards puts this back to [`CertificateCheck::Validate`].
    pub fn set_certificate_check(&mut self, check: CertificateCheck) {
        self.certificate_check = check;
    }

    /// Take `other`'s certificate policy, but only while both name the same
    /// server: a policy picked to reach one self-signed server says nothing
    /// about another.
    pub fn adopt_certificate_check(&mut self, other: &Endpoint) {
        if self.server().is_some() && self.server() == other.server() {
            self.certificate_check = other.certificate_check;
        }
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn certificate_check(&self) -> CertificateCheck {
        self.certificate_check
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
    /// Private so [`Endpoint`] stays the only way to move the server, which is
    /// what keeps the certificate policy tied to the server it was picked for.
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
    /// caller has no opinion on: online, no server pinned,
    /// [`DEFAULT_LOOK_AHEAD`] addresses of look-ahead.
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
            look_ahead: DEFAULT_LOOK_AHEAD,
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

    /// Point the scan at `url`/`port`, see [`Endpoint::set`] for what that
    /// does to the certificate policy.
    pub fn set_electrum(&mut self, url: Option<String>, port: Option<u16>) {
        self.endpoint.set(url, port);
    }

    /// Connect under `check`, see [`Endpoint::set_certificate_check`].
    pub fn set_certificate_check(&mut self, check: CertificateCheck) {
        self.endpoint.set_certificate_check(check);
    }

    /// Watch `endpoint`, server and policy together. Taking the pair whole is
    /// what keeps them consistent: the policy was picked for that server.
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

#[cfg(test)]
mod tests {
    use bwk_descriptor::descriptor::wpkh;
    use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
    use miniscript::bitcoin::{bip32::DerivationPath, Network};
    use std::{path::PathBuf, str::FromStr};

    use crate::{
        config::{Endpoint, ScannerConfig},
        raw_client::CertificateCheck,
    };

    fn config() -> ScannerConfig {
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        ScannerConfig::new(
            wpkh(xpub),
            PathBuf::default(),
            String::new(),
            "test".into(),
            Network::Regtest,
            None,
        )
    }

    #[test]
    fn the_certificate_choice_survives_a_round_trip() {
        let mut config = config();
        config.set_certificate_check(CertificateCheck::DangerAcceptInvalid);
        let encoded = serde_json::to_string(&config).unwrap();
        let decoded: ScannerConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            decoded.endpoint().certificate_check(),
            CertificateCheck::DangerAcceptInvalid
        );
    }

    #[test]
    fn a_config_without_the_key_fails_to_parse() {
        let mut value: serde_json::Value = serde_json::to_value(config()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("certificate_check")
            .unwrap();
        assert!(serde_json::from_value::<ScannerConfig>(value).is_err());
    }

    /// A change made to an endpoint, and the policy it must leave behind.
    type ResetCase = (&'static str, fn(&mut Endpoint), CertificateCheck);

    #[test]
    fn a_new_endpoint_resets_the_certificate_choice() {
        let cases: [ResetCase; 4] = [
            // Same endpoint again: the choice is the consumer's, keep it.
            (
                "same server",
                |e| e.set(Some("self.signed.lan".into()), Some(50002)),
                CertificateCheck::DangerAcceptInvalid,
            ),
            (
                "another url",
                |e| e.set(Some("electrum.example.com".into()), Some(50002)),
                CertificateCheck::Validate,
            ),
            (
                "another port",
                |e| e.set(Some("self.signed.lan".into()), Some(50001)),
                CertificateCheck::Validate,
            ),
            ("cleared", |e| e.clear(), CertificateCheck::Validate),
        ];

        for (case, change, expected) in cases {
            let mut endpoint = Endpoint::default();
            endpoint.set(Some("self.signed.lan".into()), Some(50002));
            endpoint.set_certificate_check(CertificateCheck::DangerAcceptInvalid);

            change(&mut endpoint);

            assert_eq!(endpoint.certificate_check(), expected, "{case}");
        }
    }

    #[test]
    fn a_policy_only_travels_between_endpoints_on_the_same_server() {
        let mut source = Endpoint::default();
        source.set(Some("self.signed.lan".into()), Some(50002));
        source.set_certificate_check(CertificateCheck::DangerAcceptInvalid);

        let mut same = Endpoint::default();
        same.set(Some("self.signed.lan".into()), Some(50002));
        same.adopt_certificate_check(&source);
        assert_eq!(
            same.certificate_check(),
            CertificateCheck::DangerAcceptInvalid
        );

        let mut other = Endpoint::default();
        other.set(Some("electrum.example.com".into()), Some(50002));
        other.adopt_certificate_check(&source);
        assert_eq!(other.certificate_check(), CertificateCheck::Validate);

        let mut unconfigured = Endpoint::default();
        unconfigured.adopt_certificate_check(&source);
        assert_eq!(unconfigured.certificate_check(), CertificateCheck::Validate);
    }
}
