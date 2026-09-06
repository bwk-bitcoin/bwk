use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

use crossbeam::channel;

use bwk_descriptor::descriptor::Descriptor;

use miniscript::{
    bitcoin::{
        self,
        bip32::{self, DerivationPath},
    },
    DescriptorPublicKey,
};

use crate::{
    error,
    hot_signer::HotSigner,
    identity::{SignerId, SignerInfo, SignerState},
    manager,
    protocol::{self, RequestId, RequestIdSource, Response},
    signer::{Signer, SignerNotif},
};

#[derive(Debug, Clone)]
pub enum Error {
    ParsePsbt,
}

/// Duplicated from `bwk_utils::short_string` rather than depending on
/// `bwk-utils`, which would create a dependency cycle (`bwk-utils` depends on
/// `bwk-sign`). Covered by a test asserting the two agree so the duplication
/// cannot drift silently.
fn short_string(s: String, len: usize) -> String {
    assert!(len > 6);
    let separator = if len % 2 != 0 { "." } else { ".." };
    let head = (len - 2).div_ceil(2);
    let tail = head;
    if s.len() <= head + tail + 2 {
        return s.to_string();
    }
    format!("{}{separator}{}", &s[..head], &s[s.len() - tail..])
}

fn mint_id(counter: &AtomicU64, fingerprint: &bip32::Fingerprint) -> SignerId {
    let n = counter.fetch_add(1, Ordering::Relaxed);
    SignerId::new(format!("hot:{fingerprint}:{n}"))
}

enum ParsedPsbt {
    V0(bitcoin::Psbt),
    V2(bwk_psbt::PsbtV2),
}

impl ParsedPsbt {
    fn parse(bytes: &[u8]) -> Result<Self, manager::Error> {
        match bwk_psbt::PsbtV2::deserialize(bytes) {
            Ok(psbt) => Ok(Self::V2(psbt)),
            Err(_) => bitcoin::Psbt::deserialize(bytes)
                .map(Self::V0)
                .map_err(|_| manager::Error::Psbt),
        }
    }

    fn sign(
        self,
        hot: &HotSigner,
        descriptor: &miniscript::Descriptor<DescriptorPublicKey>,
    ) -> Result<Vec<u8>, error::Error> {
        match self {
            Self::V0(mut psbt) => {
                hot.inner_sign(&mut psbt, descriptor)?;
                Ok(psbt.serialize())
            }
            Self::V2(mut psbt) => {
                hot.sign_v2(&mut psbt, descriptor)?;
                psbt.serialize().map_err(|_| error::Error::PsbtV2)
            }
        }
    }
}

/// A manager for hot (BIP32, in-memory) signers, implementing
/// [`manager::SigningManager`].
///
/// Hot signing is CPU-bound and needs no IO, so every trait method here does
/// its work inline before returning: there is no in-flight request table and
/// no worker thread. The `RequestId`/[`Response`] contract is still honored,
/// though, so a caller written against a truly asynchronous back end (a
/// hardware device, a remote signer) works unmodified against this one.
pub struct HotManager {
    receiver: channel::Receiver<SignerNotif>,
    sender: channel::Sender<SignerNotif>,
    bip32_signers: BTreeMap<SignerId, HotSigner>,
    next_hot: AtomicU64,
    requests: RequestIdSource,
    subscriber: Option<channel::Sender<Response>>,
}

impl std::fmt::Debug for HotManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotManager")
            .field("bip32_signers", &self.bip32_signers)
            .finish()
    }
}

impl Default for HotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HotManager {
    /// In-memory only (no persistence).
    pub fn new() -> Self {
        let (sender, receiver) = channel::unbounded();
        Self {
            receiver,
            sender,
            bip32_signers: BTreeMap::new(),
            next_hot: AtomicU64::new(0),
            requests: RequestIdSource::new(),
            subscriber: None,
        }
    }

    /// Polls for a new signer notification.
    ///
    /// # Returns
    /// An `Option<SignerNotif>` which is `Some` if a notification is available,
    /// or `None` if there are no new notifications.
    pub fn poll(&self) -> Option<SignerNotif> {
        self.receiver.try_recv().ok()
    }

    fn mint_hot_id(&self, fingerprint: &bip32::Fingerprint) -> SignerId {
        mint_id(&self.next_hot, fingerprint)
    }

    /// Registers a fully constructed hot signer: initializes its
    /// notification channel, mints a [`SignerId`] and inserts it. Returns
    /// the freshly minted id.
    pub fn add_bip32_signer(&mut self, mut signer: HotSigner) -> SignerId {
        signer.init(self.sender.clone());
        let id = self.mint_hot_id(&signer.fingerprint());
        self.bip32_signers.insert(id.clone(), signer);
        id
    }

    /// Returns whether any loaded hot signer holds `fingerprint`. The map is
    /// keyed by [`SignerId`], not by fingerprint, so this scans the values.
    pub fn has_bip32_signer(&self, fingerprint: &bip32::Fingerprint) -> bool {
        self.bip32_signers
            .values()
            .any(|s| s.fingerprint() == *fingerprint)
    }

    /// Creates a new hot signer with a generated mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    pub fn new_bip32_signer(&mut self, network: bitcoin::Network) -> SignerId {
        let mnemomic = bip39::Mnemonic::generate(12).unwrap();
        self.new_bip32_signer_from_mnemonic(network, mnemomic.to_string())
    }

    /// Creates a new hot signer from a given mnemonic.
    ///
    /// # Parameters
    /// - `network`: The network for which the hot signer is created.
    /// - `mnemonic`: The mnemonic used to create the hot signer.
    pub fn new_bip32_signer_from_mnemonic(
        &mut self,
        network: bitcoin::Network,
        mnemonic: String,
    ) -> SignerId {
        let signer = HotSigner::new_from_mnemonics(network, &mnemonic).unwrap();
        self.add_bip32_signer(signer)
    }

    pub fn register_bip32_descriptor(&mut self, descriptor: Descriptor) {
        for signer in self.bip32_signers.values_mut() {
            signer.inner_register_descriptor(descriptor.clone());
        }
    }

    /// Signs `psbt` with every loaded hot signer, in place.
    pub fn sign_with_all_hot_signers(&self, psbt: &mut bitcoin::Psbt) {
        for signer in self.bip32_signers.values() {
            signer.sign(psbt);
        }
    }

    fn require_subscriber(&self) -> Result<channel::Sender<Response>, manager::Error> {
        self.subscriber.clone().ok_or(manager::Error::NoSubscriber)
    }
}

impl manager::SigningManager for HotManager {
    fn signers(&self) -> Vec<SignerInfo> {
        let mut result: Vec<SignerInfo> = self
            .bip32_signers
            .iter()
            .map(|(id, hot)| {
                let wallet_name = hot
                    .descriptors()
                    .first()
                    .map(|d| short_string(d.to_string(), 18))
                    .unwrap_or_else(|| hot.fingerprint().to_string());
                SignerInfo::new(
                    id.clone(),
                    hot.fingerprint(),
                    wallet_name,
                    SignerState::Ready,
                )
            })
            .collect();
        result.sort();
        result
    }

    fn subscribe(&mut self, sender: channel::Sender<Response>) {
        let list = self.signers();
        let _ = sender.send(Response::SignersChanged { signers: list });
        self.subscriber = Some(sender);
    }

    fn set_polling(&mut self, _enabled: bool) {
        // The hot manager has no device discovery, so there is nothing to
        // turn on or off.
    }

    fn init(&mut self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        if !self.bip32_signers.contains_key(signer) {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        }
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        let _ = sender.send(Response::Initialized {
            request,
            signer: signer.clone(),
        });
        Ok(request)
    }

    fn info(&self, signer: &SignerId) -> Result<RequestId, manager::Error> {
        let Some(hot) = self.bip32_signers.get(signer) else {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        };
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        // Hot signers answer inline; there is no IO to wait on, so the
        // response is built straight from `hot` rather than by pushing a
        // notif and popping it back off the shared SignerNotif channel,
        // which other signers also write to and which never fully drains
        // (see HotSigner::init's own Info notif).
        let _ = sender.send(Response::Info {
            request,
            signer: signer.clone(),
            info: protocol::info_map(hot.info_value()),
        });
        Ok(request)
    }

    fn get_xpub(
        &self,
        signer: &SignerId,
        path: DerivationPath,
        _display: bool,
    ) -> Result<RequestId, manager::Error> {
        let Some(hot) = self.bip32_signers.get(signer) else {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        };
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        // Hot signers have no display step and no IO, so the xpub is read
        // straight off `hot` instead of round-tripping through the shared
        // SignerNotif channel (see the comment in `info` above).
        let _ = sender.send(Response::Xpub {
            request,
            signer: signer.clone(),
            xpub: hot.xpub(&path),
        });
        Ok(request)
    }

    fn is_descriptor_registered(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        let Some(hot) = self.bip32_signers.get(signer) else {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        };
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        let registered = hot.descriptors().contains(&descriptor);
        let _ = sender.send(Response::DescriptorIsRegistered {
            request,
            signer: signer.clone(),
            registered,
        });
        Ok(request)
    }

    fn register_descriptor(
        &mut self,
        signer: &SignerId,
        descriptor: Descriptor,
    ) -> Result<RequestId, manager::Error> {
        if !self.bip32_signers.contains_key(signer) {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        }
        let sender = self.require_subscriber()?;
        let request = self.requests.next();
        let hot = self.bip32_signers.get_mut(signer).expect("checked above");
        hot.inner_register_descriptor(descriptor);
        let _ = sender.send(Response::DescriptorRegistered {
            request,
            signer: signer.clone(),
            registered: true,
        });
        Ok(request)
    }

    fn sign(
        &self,
        signer: &SignerId,
        descriptor: Descriptor,
        psbt: Vec<u8>,
    ) -> Result<RequestId, manager::Error> {
        let Some(hot) = self.bip32_signers.get(signer) else {
            return Err(manager::Error::UnknownSigner(signer.clone()));
        };
        let sender = self.require_subscriber()?;
        let parsed = ParsedPsbt::parse(&psbt)?;
        let request = self.requests.next();
        match descriptor.as_miniscript() {
            Some(inner) => match parsed.sign(hot, inner) {
                Ok(signed) => {
                    let _ = sender.send(Response::Signed {
                        request,
                        signer: signer.clone(),
                        psbt: signed,
                    });
                }
                Err(e) => {
                    let _ = sender.send(Response::error(request, signer.clone(), e.to_string()));
                }
            },
            None => {
                let _ = sender.send(Response::error(
                    request,
                    signer.clone(),
                    "silent payment descriptors are not signable yet",
                ));
            }
        }
        Ok(request)
    }

    fn raw(&self, signer: &SignerId, _request: Vec<u8>) -> Result<RequestId, manager::Error> {
        if self.bip32_signers.contains_key(signer) {
            Err(manager::Error::Unsupported(signer.clone()))
        } else {
            Err(manager::Error::UnknownSigner(signer.clone()))
        }
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use std::{collections::BTreeSet, str::FromStr};

    use bip32::Fingerprint;
    use bwk_descriptor::{derivator::SpkDerivator, descriptor::wpkh, sp_descriptor::SpDescriptor};
    use bwk_utils::test::{random_output, txid};
    use miniscript::bitcoin::{
        absolute::LockTime, secp256k1::Secp256k1, transaction::Version, Amount, ScriptBuf, TxIn,
        TxOut,
    };

    use super::*;
    use crate::{hot_signer::deriv_path, manager::SigningManager};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_manager_bip32_signer() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        if let SignerNotif::Info(fg, _info) = manager.poll().unwrap() {
            assert_eq!(fg, Fingerprint::from_str("73c5da0a").unwrap());
        } else {
            panic!("expect info");
        }
    }

    #[test]
    fn short_string_matches_bwk_utils() {
        let xpub = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        assert_eq!(
            short_string(xpub.to_string(), 18),
            bwk_utils::short_string(xpub.to_string(), 18)
        );
        assert_eq!(
            short_string("abc".to_string(), 18),
            bwk_utils::short_string("abc".to_string(), 18)
        );
    }

    #[test]
    fn manager_is_in_memory_only() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        assert_eq!(manager.signers().len(), 1);
        drop(manager);

        let manager = HotManager::new();
        assert!(manager.signers().is_empty());
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn manager_is_send_and_sync() {
        assert_send_sync::<HotManager>();
    }

    fn sp_descriptor(fingerprint: &str) -> Descriptor {
        let secp = Secp256k1::new();
        let scan = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x11; 64]).unwrap();
        let spend_xpriv = bip32::Xpriv::new_master(bitcoin::Network::Testnet, &[0x12; 64]).unwrap();
        let spend_xpub = bip32::Xpub::from_priv(&secp, &spend_xpriv);
        let s = format!("sp([{fingerprint}/352h/0h/0h]{scan}/0h,{spend_xpub}/0h)");
        SpDescriptor::from_str(&s).unwrap().into()
    }

    fn base_psbt() -> bitcoin::Psbt {
        let txin = TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        let txout = random_output();
        let tx = bitcoin::Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };
        bitcoin::Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn two_signers_one_fingerprint() {
        let mut manager = HotManager::new();
        let signer_a = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC).unwrap();
        let signer_b = HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, MNEMONIC).unwrap();
        let id_a = manager.add_bip32_signer(signer_a);
        let id_b = manager.add_bip32_signer(signer_b);
        assert_ne!(id_a, id_b);

        let infos = manager.signers();
        assert_eq!(infos.len(), 2);
        let fingerprints: BTreeSet<_> = infos.iter().map(|i| i.fingerprint).collect();
        assert_eq!(fingerprints.len(), 1);
        let ids: BTreeSet<_> = infos.iter().map(|i| i.id.clone()).collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn signers_are_ready() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        for info in manager.signers() {
            assert_eq!(info.state, SignerState::Ready);
            assert_eq!(info.state_detail, "");
        }
    }

    #[test]
    fn subscribe_pushes_the_signer_list() {
        let mut manager = HotManager::new();
        manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        match rx.recv().unwrap() {
            Response::SignersChanged { signers } => assert_eq!(signers, manager.signers()),
            other => panic!("expected SignersChanged, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signer_id_errors() {
        let mut manager = HotManager::new();
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let id = SignerId::new("nope");
        assert_eq!(manager.info(&id), Err(manager::Error::UnknownSigner(id)));
    }

    #[test]
    fn no_subscriber_errors() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        assert_eq!(manager.info(&id), Err(manager::Error::NoSubscriber));
    }

    fn sign_wpkh_psbt(serialize: fn(bitcoin::Psbt) -> Vec<u8>) -> Vec<u8> {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let account_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let descriptor: Descriptor = wpkh(hot.xpub(&account_path)).into();

        manager
            .register_descriptor(&id, descriptor.clone())
            .unwrap();
        let _ = rx.recv().unwrap(); // DescriptorRegistered

        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let pubkey = hot.public_key_at(&deriv_p);
        let fingerprint = hot.fingerprint();
        let derivator = SpkDerivator::new(
            descriptor.as_miniscript().unwrap().clone(),
            bitcoin::Network::Regtest,
        )
        .unwrap();

        let mut psbt = base_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, (fingerprint, deriv_p));

        let request = manager.sign(&id, descriptor, serialize(psbt)).unwrap();
        match rx.recv().unwrap() {
            Response::Signed {
                request: req,
                signer,
                psbt,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, id);
                psbt
            }
            other => panic!("expected Signed, got {other:?}"),
        }
    }

    #[test]
    fn sign_produces_a_signed_psbt() {
        let signed = sign_wpkh_psbt(|psbt| psbt.serialize());
        let signed = bitcoin::Psbt::deserialize(&signed).unwrap();
        assert!(!signed.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn sign_produces_a_signed_psbt_v2() {
        let signed = sign_wpkh_psbt(|psbt| {
            bwk_psbt::PsbtV2::from_bitcoin_psbt(psbt)
                .unwrap()
                .serialize()
                .unwrap()
        });
        let signed = bwk_psbt::PsbtV2::deserialize(&signed).unwrap();
        assert!(!signed.inputs[0].psbt.partial_sigs.is_empty());
    }

    #[test]
    fn sign_rejects_a_bad_psbt() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, _rx) = channel::unbounded();
        manager.subscribe(tx);
        let deriv_p = deriv_path(&(false, 0)).unwrap();
        let hot = manager.bip32_signers.get(&id).unwrap();
        let descriptor: Descriptor = wpkh(hot.xpub(&deriv_p)).into();

        assert_eq!(
            manager.sign(&id, descriptor, vec![0xff; 8]),
            Err(manager::Error::Psbt)
        );
    }

    #[test]
    fn sign_with_sp_descriptor_reports_an_error() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let fingerprint = manager.bip32_signers.get(&id).unwrap().fingerprint();
        let descriptor = sp_descriptor(&fingerprint.to_string());
        let psbt = base_psbt();

        let request = manager.sign(&id, descriptor, psbt.serialize()).unwrap();
        match rx.recv().unwrap() {
            Response::Error {
                request: req,
                signer,
                ..
            } => {
                assert_eq!(req, Some(request));
                assert_eq!(signer, Some(id));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn get_xpub_does_not_cross_contaminate_between_hot_signers() {
        const OTHER_MNEMONIC: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let mut manager = HotManager::new();
        let mnemonic_a =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        let mnemonic_b = manager
            .new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, OTHER_MNEMONIC.to_string());
        let (tx, rx) = channel::unbounded();
        manager.subscribe(tx);
        let _ = rx.recv().unwrap(); // SignersChanged

        let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
        let hot_a = manager.bip32_signers.get(&mnemonic_a).unwrap();
        let expected_a = hot_a.xpub(&path);
        let hot_b = manager.bip32_signers.get(&mnemonic_b).unwrap();
        let expected_b = hot_b.xpub(&path);
        assert_ne!(expected_a, expected_b);

        // Two prior queries against signer A (mirroring one hot signer's
        // own init() notif plus one info() call) used to leave the shared
        // SignerNotif channel with a backlog that a later, unrelated call
        // could pop instead of its own answer.
        manager.info(&mnemonic_a).unwrap();
        let _ = rx.recv().unwrap();
        manager.get_xpub(&mnemonic_a, path.clone(), false).unwrap();
        let _ = rx.recv().unwrap();

        let request = manager.get_xpub(&mnemonic_b, path, false).unwrap();
        match rx.recv().unwrap() {
            Response::Xpub {
                request: req,
                signer,
                xpub,
            } => {
                assert_eq!(req, request);
                assert_eq!(signer, mnemonic_b);
                assert_eq!(xpub, expected_b);
            }
            other => panic!("expected Xpub, got {other:?}"),
        }
    }

    #[test]
    fn raw_is_unsupported() {
        let mut manager = HotManager::new();
        let id =
            manager.new_bip32_signer_from_mnemonic(bitcoin::Network::Regtest, MNEMONIC.to_string());
        assert_eq!(
            manager.raw(&id, vec![]),
            Err(manager::Error::Unsupported(id))
        );
    }
}
