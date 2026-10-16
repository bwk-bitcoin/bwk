use std::{collections::BTreeSet, str::FromStr};

use crossbeam::channel;

#[cfg(feature = "musig")]
use crate::musig::{
    self, MusigSession, MusigSessionId, MusigSessionKey, MusigSessionStore, PendingNonce, SlotInfo,
};
use crate::{
    error::Error,
    send,
    signer::{Signer, SignerNotif},
};
use bwk_descriptor::{
    derivator::SpkDerivator,
    descriptor::{tr, tr_path, wpkh, wpkh_path, Descriptor},
    wallet::{WalletDescriptor, WalletDescriptorExt},
};
#[cfg(feature = "musig")]
use bwk_keys::musig::MusigKey;
use bwk_keys::{
    derivator::KeyDerivator,
    keys::{OXpriv, OXpub},
};
#[cfg(feature = "musig")]
use bwk_musig::{nonce_gen_with_rand, partial_sign, rust_bitcoin::RustBitcoin};
#[cfg(feature = "musig")]
use bwk_psbt::musig::{
    set_musig_input_partial_sig, set_musig_input_pub_nonce, MusigPartialSig, MusigPubNonce,
};
use bwk_psbt::PsbtV2;
#[cfg(feature = "musig")]
use miniscript::ForEachKey;
use miniscript::{
    bitcoin::{bip32::ChildNumber, hashes::Hash, key::TapTweak},
    psbt::PsbtExt,
};
use serde::{Deserialize, Serialize};
use {
    bip39,
    miniscript::{
        bitcoin::{
            self,
            bip32::{self, DerivationPath},
            ecdsa,
            psbt::Input,
            secp256k1::{self, All, Message},
            sighash, EcdsaSighashType, NetworkKind, Psbt,
        },
        DescriptorPublicKey,
    },
};

impl Signer for HotSigner {
    fn init(&mut self, channel: channel::Sender<SignerNotif>) {
        self.sender = Some(channel);
        self.info();
    }

    fn info(&self) {
        send!(self, Info(self.info_value()));
    }

    fn get_xpub(&self, deriv: DerivationPath, _display: bool) {
        let xpub = self.xpub(&deriv);
        send!(self, Xpub(xpub));
    }

    fn is_descriptor_registered(&self, descriptor: Descriptor) {
        let registered = self.descriptors.contains(&descriptor);
        send!(self, DescriptorRegistered(descriptor, registered));
    }

    fn register_descriptor(&mut self, descriptor: Descriptor) {
        let Some(inner) = descriptor.as_miniscript() else {
            send!(self, Error(Error::SpDescriptor));
            return;
        };
        let wrong_network = inner.plain_keys().iter().any(|k| match k {
            DescriptorPublicKey::Single(_) => true,
            DescriptorPublicKey::XPub(key) => match (self.network, key.xkey.network) {
                (bitcoin::Network::Bitcoin, NetworkKind::Main) => false,
                (bitcoin::Network::Bitcoin, NetworkKind::Test) => true,
                (_, NetworkKind::Main) => true,
                _ => false,
            },
            DescriptorPublicKey::MultiXPub(key) => match (self.network, key.xkey.network) {
                (bitcoin::Network::Bitcoin, NetworkKind::Main) => false,
                (bitcoin::Network::Bitcoin, NetworkKind::Test) => true,
                (_, NetworkKind::Main) => true,
                _ => false,
            },
        });
        if wrong_network {
            send!(self, Error(Error::DescriptorNetwork));
            return;
        }
        #[cfg(feature = "musig")]
        if self.reuses_participant_key(inner) {
            send!(self, Error(Error::MusigParticipantReuse));
            return;
        }
        self.descriptors.insert(descriptor.clone());
        send!(self, DescriptorRegistered(descriptor, true));
    }

    fn sign_with_descriptor(&self, mut psbt: Psbt, descriptor: Descriptor) {
        let Some(inner) = descriptor.as_miniscript() else {
            send!(self, Error(Error::SpDescriptor));
            return;
        };
        if self.descriptors.contains(&descriptor) {
            if let Err(e) = self.inner_sign(&mut psbt, inner) {
                send!(self, Error(e));
            } else {
                send!(self, Signed(psbt));
            }
        } else {
            send!(self, Error(Error::UnregisteredDescriptor));
        };
    }
}

/// A struct that represents a hot signer for Bitcoin transactions.
///
/// This struct is responsible for managing the private keys and generating
/// addresses for receiving and change. It can create signatures for transactions
/// using the provided private keys.
#[derive(Debug, Clone)]
pub struct HotSigner {
    derivator: KeyDerivator,
    descriptors: BTreeSet<Descriptor>,
    network: bitcoin::Network,
    sender: Option<channel::Sender<SignerNotif>>,
    #[cfg(feature = "musig")]
    musig_sessions: MusigSessionStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSigner {
    mnemonic: bip39::Mnemonic,
    descriptors: BTreeSet<String>,
    network: bitcoin::Network,
}

impl HotSigner {
    pub fn to_json(&self) -> Option<JsonSigner> {
        let descriptors = self.descriptors.iter().map(|d| d.to_string()).collect();
        self.mnemonic().as_ref().map(|mnemonic| JsonSigner {
            mnemonic: mnemonic.clone(),
            descriptors,
            network: self.network,
        })
    }
    pub fn from_json(json: JsonSigner) -> Self {
        let mut signer = HotSigner::new_from_mnemonics(json.network, &json.mnemonic.to_string())
            .expect("valid signer");
        #[allow(clippy::mutable_key_type)]
        let descriptors = json
            .descriptors
            .into_iter()
            .filter_map(|d| Descriptor::from_str(&d).ok())
            .collect();
        signer.descriptors = descriptors;
        signer
    }
    /// Create a new [`HotSigner`] instance from the provided Xpriv key.
    ///
    /// # Arguments
    /// * `network` - The Bitcoin network (e.g., Bitcoin, Testnet, Signet, Regtest).
    /// * `xpriv` - The extended private key that the signer will use.
    ///
    /// # Returns
    /// A new instance of [`HotSigner`].
    pub fn new_from_xpriv(network: bitcoin::Network, xpriv: bip32::Xpriv) -> Self {
        let derivator = KeyDerivator::new_from_xpriv(xpriv);

        HotSigner {
            derivator,
            descriptors: BTreeSet::new(),
            network,
            sender: None,
            #[cfg(feature = "musig")]
            musig_sessions: MusigSessionStore::new(),
        }
    }

    /// Create a new [`HotSigner`] instance from a mnemonic phrase.
    ///
    /// # Arguments
    /// * `network` - The Bitcoin network (e.g., Bitcoin, Testnet, Signet, Regtest).
    /// * `mnemonic` - A string representing the mnemonic phrase used to generate the keys.
    ///
    /// # Returns
    /// A result containing a new instance of [`HotSigner`] or an error if the mnemonic is invalid.
    pub fn new_from_mnemonics(network: bitcoin::Network, mnemonic: &str) -> Result<Self, Error> {
        let derivator =
            KeyDerivator::new_from_mnemonic_str(network, mnemonic).map_err(|_| Error::Derivator)?;
        Ok(HotSigner {
            derivator,
            descriptors: BTreeSet::new(),
            network,
            sender: None,
            #[cfg(feature = "musig")]
            musig_sessions: MusigSessionStore::new(),
        })
    }

    /// Create a new [`HotSigner`] instance with a Taproot descriptor from a mnemonic phrase.
    ///
    /// This method initializes a signer from the provided mnemonic and automatically registers
    /// a Taproot (P2TR) descriptor using the BIP86 derivation path at account index 0.
    ///
    /// # Arguments
    /// * `network` - The Bitcoin network (e.g., Bitcoin, Testnet, Signet, Regtest).
    /// * `mnemonic` - A string representing the mnemonic phrase used to generate the keys.
    ///
    /// # Returns
    /// A result containing a new instance of [`HotSigner`] with a registered Taproot descriptor,
    /// or an error if the mnemonic is invalid or the derivation path cannot be constructed.
    pub fn new_taproot_from_mnemonics(
        network: bitcoin::Network,
        mnemonic: &str,
    ) -> Result<Self, Error> {
        let mut signer = Self::new_from_mnemonics(network, mnemonic)?;
        let deriv = tr_path(
            network,
            ChildNumber::from_hardened_idx(0).expect("hardcoded child number"),
        )
        .map_err(|_| Error::DerivationPath)?;
        let oxpub = signer.xpub(&deriv);
        let descriptor = tr(oxpub);
        signer.register_descriptor(descriptor.into());
        Ok(signer)
    }

    /// Create a new [`HotSigner`] instance with a native SegWit descriptor from a mnemonic phrase.
    ///
    /// This method initializes a signer from the provided mnemonic and automatically registers
    /// a Witness Public Key Hash (P2WPKH) descriptor using the BIP84 derivation path at account index 0.
    ///
    /// # Arguments
    /// * `network` - The Bitcoin network (e.g., Bitcoin, Testnet, Signet, Regtest).
    /// * `mnemonic` - A string representing the mnemonic phrase used to generate the keys.
    ///
    /// # Returns
    /// A result containing a new instance of [`HotSigner`] with a registered WPKH descriptor,
    /// or an error if the mnemonic is invalid or the derivation path cannot be constructed.
    pub fn new_wpkh_from_mnemonics(
        network: bitcoin::Network,
        mnemonic: &str,
    ) -> Result<Self, Error> {
        let mut signer = Self::new_from_mnemonics(network, mnemonic)?;
        let deriv = wpkh_path(
            network,
            ChildNumber::from_hardened_idx(0).expect("hardcoded child number"),
        )
        .map_err(|_| Error::DerivationPath)?;
        let oxpub = signer.xpub(&deriv);
        let descriptor = wpkh(oxpub);
        signer.register_descriptor(descriptor.into());
        Ok(signer)
    }

    /// Generate a new signer and it's private key.
    /// Note: generating a private key by this way is not safe enough
    ///   to use on mainnet, so we decide to forbid usage of this method on mainnet.
    ///   This method will panic if `network` have [`Network::Bitcoin`] value.
    pub fn new(network: bitcoin::Network) -> Result<Self, Error> {
        // Should not be used on mainnet
        assert_ne!(network, bitcoin::Network::Bitcoin);
        let mnemonic = bip39::Mnemonic::generate(12).expect("12 words must not fail");

        let derivator =
            KeyDerivator::new_from_mnemonic(network, mnemonic).map_err(|_| Error::Derivator)?;
        Ok(HotSigner {
            derivator,
            descriptors: BTreeSet::new(),
            network,
            sender: None,
            #[cfg(feature = "musig")]
            musig_sessions: MusigSessionStore::new(),
        })
    }

    /// Shares `sessions` with this signer, so a signer rebuilt per call keeps them.
    #[cfg(feature = "musig")]
    pub fn set_musig_sessions(&mut self, sessions: MusigSessionStore) {
        self.musig_sessions = sessions;
    }

    #[cfg(feature = "musig")]
    pub fn musig_sessions(&self) -> MusigSessionStore {
        self.musig_sessions.clone()
    }

    /// Registers a descriptor for the signer.
    ///
    /// This function adds the given descriptor to the signer's internal set of
    /// descriptors if it is not already registered.
    ///
    /// # Arguments
    /// * `descriptor` - The descriptor to be registered.
    pub fn inner_register_descriptor(&mut self, descriptor: Descriptor) {
        if !self.descriptors.contains(&descriptor) {
            self.descriptors.insert(descriptor);
        }
    }

    /// Retrieves the extended private key at the specified derivation path.
    ///
    /// # Arguments
    /// * `path` - The derivation path for which to retrieve the extended private key.
    ///
    /// # Returns
    /// An instance of `OXpriv` containing the origin fingerprint and the derived
    /// extended private key.
    pub fn xpriv(&self, path: &DerivationPath) -> OXpriv {
        self.derivator.xpriv_at(path)
    }

    /// Retrieves the extended public key at the specified derivation path.
    ///
    /// # Arguments
    /// * `path` - The derivation path for which to retrieve the extended public key.
    ///
    /// # Returns
    /// An instance of `OXpub` containing the origin fingerprint and the derived
    /// extended public key.
    pub fn xpub(&self, path: &DerivationPath) -> OXpub {
        self.derivator.xpub_at(path)
    }

    /// The payload [`Signer::info`] reports for this signer.
    pub fn info_value(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// Retrieves the private key at the specified derivation path from the master_xpriv.
    ///
    /// # Arguments
    /// * `path` - The derivation path for which to retrieve the private key.
    ///
    /// # Returns
    /// The private key as a [`secp256k1::SecretKey`]. The MuSig2 and taproot
    /// signing paths wipe the key they hold with `non_secure_erase`; a
    /// `SecretKey` is `Copy`, so that wipes only their own copy, not the
    /// extended keys of the derivation nor copies a move left behind.
    pub fn private_key_at(&self, path: &DerivationPath) -> secp256k1::SecretKey {
        self.derivator.secret_key_at(path)
    }

    /// Retrieves the public key at the specified derivation path from the master_xpriv.
    ///
    /// # Arguments
    /// * `path` - The derivation path for which to retrieve the public key.
    ///
    /// # Returns
    /// The public key as a [`secp256k1::PublicKey`].
    pub fn public_key_at(&self, path: &DerivationPath) -> secp256k1::PublicKey {
        self.derivator.public_key_at(path)
    }

    pub fn sign(&self, psbt: &mut Psbt) {
        for descr in &self.descriptors {
            let Some(descr) = descr.as_miniscript() else {
                continue;
            };
            match self.inner_sign(psbt, descr) {
                Ok(()) => {}
                // A descriptor that signs no input simply doesn't apply to
                // this PSBT (normal in multi-account signing), not a failure.
                Err(Error::SigningInfo) => {
                    log::debug!("signer: descriptor matched no input");
                }
                Err(e) => log::warn!("fail to sign: {e:?}"),
            }
        }
    }

    pub fn sign_v2(&self, psbt: &mut PsbtV2, descriptor: &WalletDescriptor) -> Result<(), Error> {
        let mut v0 = validated_v0(psbt)?;
        self.inner_sign(&mut v0, descriptor)?;
        set_v0_maps(psbt, v0);
        psbt.tx_modifiable = Some(bwk_psbt::TxModifiable::none());
        Ok(())
    }

    pub fn finalize(
        &self,
        psbt: &mut Psbt,
    ) -> Result<bitcoin::Transaction, Vec<miniscript::psbt::Error>> {
        PsbtExt::finalize_mut(psbt, self.secp())?;
        Ok(Psbt::extract_tx_unchecked_fee_rate(psbt.clone()))
    }

    pub fn finalize_v2(&self, psbt: &mut PsbtV2) -> Result<bitcoin::Transaction, Error> {
        let mut v0 = validated_v0(psbt)?;
        PsbtExt::finalize_mut(&mut v0, self.secp()).map_err(|_| Error::SigningInfo)?;
        let tx = Psbt::extract_tx_unchecked_fee_rate(v0.clone());
        set_v0_maps(psbt, v0);
        Ok(tx)
    }

    #[cfg(not(feature = "musig"))]
    pub fn inner_sign(&self, psbt: &mut Psbt, descriptor: &WalletDescriptor) -> Result<(), Error> {
        self.sign_ordinary(psbt, descriptor, &KeyPaths::default())
    }

    /// One MuSig2 round per call when this signer has a musig slot, see
    /// [`crate::musig`]; ordinary signing otherwise.
    #[cfg(feature = "musig")]
    pub fn inner_sign(&self, psbt: &mut Psbt, descriptor: &WalletDescriptor) -> Result<(), Error> {
        let participant_paths = KeyPaths::participants(
            self.miniscript_descriptors().chain([descriptor]),
            self.fingerprint(),
        );
        let own = self.own_slot_infos(musig::slot_infos(psbt, descriptor)?);
        if own.is_empty() {
            return self.sign_ordinary(psbt, descriptor, &participant_paths);
        }
        let key = MusigSessionKey::new(descriptor, self.fingerprint());
        let id = musig::session_id(psbt, descriptor, self.fingerprint())?;
        let mut present = 0;
        for info in &own {
            if info
                .pub_nonce(&psbt.inputs[info.slot.input_index])?
                .is_some()
            {
                present += 1;
            }
        }
        match present {
            0 => self.musig_round_one(psbt, key, id, &own),
            n if n == own.len() => {
                self.musig_round_two(psbt, descriptor, key, id, &own, &participant_paths)
            }
            _ => {
                self.musig_sessions.take(&key, &id);
                Err(Error::MusigSession)
            }
        }
    }

    /// The registered descriptors that are not silent payment ones.
    #[cfg(feature = "musig")]
    fn miniscript_descriptors(&self) -> impl Iterator<Item = &WalletDescriptor> {
        self.descriptors
            .iter()
            .filter_map(Descriptor::as_miniscript)
    }

    /// True when `descriptor` uses one of this signer's musig() participant keys
    /// as a plain key, or makes a participant of a key a registered descriptor
    /// (or `descriptor` itself) uses as a plain key.
    #[cfg(feature = "musig")]
    fn reuses_participant_key(&self, descriptor: &WalletDescriptor) -> bool {
        let fingerprint = self.fingerprint();
        let all = || self.miniscript_descriptors().chain([descriptor]);
        KeyPaths::plain([descriptor], fingerprint)
            .overlaps(&KeyPaths::participants(all(), fingerprint))
            || KeyPaths::participants([descriptor], fingerprint)
                .overlaps(&KeyPaths::plain(all(), fingerprint))
    }

    /// The slots whose participant is a key of this signer (a fingerprint
    /// collision is not ours).
    #[cfg(feature = "musig")]
    fn own_slot_infos(&self, slots: Vec<SlotInfo>) -> Vec<SlotInfo> {
        slots
            .into_iter()
            .filter(|info| {
                info.signer.0 == self.fingerprint()
                    && self.public_key_at(&info.signer.1) == info.slot.participant
            })
            .collect()
    }

    /// Round 1: a fresh nonce per own slot, bound to its sighash; only the 0x1b
    /// are added, and the session replaces any older one under `key`.
    #[cfg(feature = "musig")]
    fn musig_round_one(
        &self,
        psbt: &mut Psbt,
        key: MusigSessionKey,
        id: MusigSessionId,
        own: &[SlotInfo],
    ) -> Result<(), Error> {
        let mut session = MusigSession {
            id,
            nonces: Default::default(),
        };
        for info in own {
            let sighash = musig::slot_sighash(psbt, &info.slot)?;
            let key_agg = info.key_agg()?;
            let mut rand = [0u8; 32];
            fresh_rand(&mut rand)?;
            let mut sk = self.private_key_at(&info.signer.1);
            let mut secret_key = sk.secret_bytes();
            sk.non_secure_erase();
            let generated = nonce_gen_with_rand(
                &RustBitcoin,
                &rand,
                Some(&key_agg),
                &info.slot.participant.serialize(),
                Some(&secret_key),
                Some(&sighash),
                None,
            );
            wipe(&mut rand);
            wipe(&mut secret_key);
            let (secnonce, pubnonce) = generated?;
            session.nonces.insert(
                info.slot,
                PendingNonce {
                    secnonce,
                    pubnonce,
                    sighash,
                },
            );
        }
        for (slot, pending) in &session.nonces {
            let nonce = MusigPubNonce {
                participant: slot.participant,
                aggregate: slot.aggregate,
                leaf_hash: slot.leaf_hash,
                nonce: pending.pubnonce,
            };
            set_musig_input_pub_nonce(&mut psbt.inputs[slot.input_index], &nonce);
        }
        self.musig_sessions.insert(key, session);
        Ok(())
    }

    /// Round 2: the ordinary keys sign a copy first, so their failure keeps the
    /// session; then the session leaves the store, so any later failure erases it
    /// (the host restarts round 1), and the 0x1c are written once it is dropped.
    /// The PSBT is only changed on success.
    #[cfg(feature = "musig")]
    fn musig_round_two(
        &self,
        psbt: &mut Psbt,
        descriptor: &WalletDescriptor,
        key: MusigSessionKey,
        id: MusigSessionId,
        own: &[SlotInfo],
        participant_paths: &KeyPaths,
    ) -> Result<(), Error> {
        let mut signed = psbt.clone();
        match self.sign_ordinary(&mut signed, descriptor, participant_paths) {
            Ok(()) | Err(Error::SigningInfo) => {}
            Err(e) => return Err(e),
        }
        let session = self
            .musig_sessions
            .take(&key, &id)
            .ok_or(Error::MusigSession)?;
        let partial_sigs = self.musig_partial_sigs(psbt, session, own)?;
        for sig in &partial_sigs {
            set_musig_input_partial_sig(&mut signed.inputs[sig.input_index], &sig.partial_sig);
        }
        *psbt = signed;
        Ok(())
    }

    /// Checks the session against the PSBT and signs every own slot, consuming
    /// the session's secret nonces.
    #[cfg(feature = "musig")]
    fn musig_partial_sigs(
        &self,
        psbt: &Psbt,
        mut session: MusigSession,
        own: &[SlotInfo],
    ) -> Result<Vec<InputPartialSig>, Error> {
        if session.nonces.len() != own.len() {
            return Err(Error::MusigSession);
        }
        let mut partial_sigs = Vec::with_capacity(own.len());
        for info in own {
            let slot = &info.slot;
            let pending = session.nonces.remove(slot).ok_or(Error::MusigSession)?;
            let input = &psbt.inputs[slot.input_index];
            if musig::slot_sighash(psbt, slot)? != pending.sighash
                || info.pub_nonce(input)? != Some(pending.pubnonce)
            {
                return Err(Error::MusigSession);
            }
            let aggnonce = bwk_musig::nonce_agg(&RustBitcoin, &info.all_nonces(input)?)?;
            let key_agg = info.key_agg()?;
            let mut sk = self.private_key_at(&info.signer.1);
            let mut secret_key = sk.secret_bytes();
            sk.non_secure_erase();
            let signature = partial_sign(
                &RustBitcoin,
                pending.secnonce,
                &secret_key,
                &key_agg,
                &aggnonce,
                &pending.sighash,
            );
            wipe(&mut secret_key);
            let signature = signature?;
            partial_sigs.push(InputPartialSig {
                input_index: slot.input_index,
                partial_sig: MusigPartialSig {
                    participant: slot.participant,
                    aggregate: slot.aggregate,
                    leaf_hash: slot.leaf_hash,
                    signature,
                },
            });
        }
        Ok(partial_sigs)
    }

    /// Segwit, taproot key path and taproot script path signing, skipping the
    /// musig participant keys.
    fn sign_ordinary(
        &self,
        psbt: &mut Psbt,
        descriptor: &WalletDescriptor,
        participant_paths: &KeyPaths,
    ) -> Result<(), Error> {
        let mut cache = sighash::SighashCache::new(psbt.unsigned_tx.clone());
        let derivator = SpkDerivator::new(descriptor.clone(), self.network).unwrap();
        let mut signed_any = false;
        for index in 0..psbt.inputs.len() {
            match (
                !psbt.inputs[index].bip32_derivation.is_empty(),
                psbt.inputs[index].tap_internal_key.is_some(),
                !psbt.inputs[index].tap_key_origins.is_empty(),
            ) {
                (true, false, false) => {
                    match self.sign_input_segwit(psbt, index, &derivator, &mut cache) {
                        Ok(()) => signed_any = true,
                        Err(Error::SpkNotMatch) => continue,
                        Err(e) => return Err(e),
                    }
                }
                (false, false, true) => {
                    match self.sign_input_taptree(
                        psbt,
                        index,
                        &derivator,
                        &mut cache,
                        participant_paths,
                    ) {
                        Ok(()) => signed_any = true,
                        Err(Error::SpkNotMatch) => continue,
                        Err(e) => return Err(e),
                    }
                }
                (false, true, true) => {
                    let mut input_signed = false;
                    match self.sign_input_tapkey(
                        psbt,
                        index,
                        &derivator,
                        &mut cache,
                        participant_paths,
                    ) {
                        Ok(()) => input_signed = true,
                        Err(Error::SpkNotMatch | Error::NotTapKey) => {}
                        Err(e) => return Err(e),
                    }
                    match self.sign_input_taptree(
                        psbt,
                        index,
                        &derivator,
                        &mut cache,
                        participant_paths,
                    ) {
                        Ok(()) => input_signed = true,
                        Err(Error::SpkNotMatch | Error::NotTapTree) => {}
                        Err(e) => return Err(e),
                    }
                    if input_signed {
                        signed_any = true;
                    }
                }
                (false, false, false) => continue,
                _ => return Err(Error::MixedSigningInfo),
            }
        }

        if !signed_any {
            return Err(Error::SigningInfo);
        }

        Ok(())
    }

    fn has_witness_utxo(psbt: &Psbt, index: usize) -> Result<(), Error> {
        if psbt
            .inputs
            .get(index)
            .ok_or(Error::InputIndex)?
            .witness_utxo
            .is_none()
        {
            Err(Error::MissingWitnessUtxo)?
        } else {
            Ok(())
        }
    }

    fn sign_input_segwit(
        &self,
        psbt: &mut Psbt,
        index: usize,
        derivator: &SpkDerivator,
        cache: &mut sighash::SighashCache<bitcoin::Transaction>,
    ) -> Result<(), Error> {
        Self::has_witness_utxo(psbt, index)?;
        let sighash = self.segwit_hash(psbt, index, cache)?;
        let input = psbt.inputs.get_mut(index).expect("already checked");
        if input.bip32_derivation.is_empty() {
            return Err(Error::NotSegwit);
        }
        let mut derivation_paths = vec![];
        input.bip32_derivation.iter().for_each(|(_, (fg, deriv))| {
            if *fg == self.fingerprint() {
                derivation_paths.push(deriv.clone());
            }
        });
        if derivation_paths.is_empty() {
            return Err(Error::SpkNotMatch);
        }
        self.inner_sign_input_segwit(sighash, input, derivation_paths, derivator)?;
        Ok(())
    }

    fn segwit_hash(
        &self,
        psbt: &Psbt,
        index: usize,
        cache: &mut sighash::SighashCache<bitcoin::Transaction>,
    ) -> Result<Message, Error> {
        let input = psbt.inputs.get(index).ok_or(Error::InputIndex)?;
        if input.bip32_derivation.is_empty() {
            return Err(Error::NotSegwit);
        }
        let (hash, sighash_type) = psbt.sighash_ecdsa(index, cache).map_err(|e| {
            log::error!("Fail to generate sig hash: {e}");
            Error::SighashFail
        })?;
        if sighash_type != EcdsaSighashType::All {
            // FIXME: we support only sighash ALL for now
            return Err(Error::SighashFail);
        }
        Ok(hash)
    }

    pub fn inner_sign_input_segwit(
        &self,
        hash: Message,
        input: &mut Input,
        deriv: Vec<DerivationPath>,
        derivator: &SpkDerivator,
    ) -> Result<(), Error> {
        for d in &deriv {
            let signing_key = self.private_key_at(d);
            let pubkey = self.public_key_at(d);

            if !input.bip32_derivation.contains_key(&pubkey) {
                // NOTE: this can happen in case of fingerprint collision
                continue;
            }

            if let Some(wit) = &input.witness_utxo {
                let ap = account_path(d)?;
                let expected_spk = match ap.0 {
                    false => derivator.receive_at(ap.1),
                    true => derivator.change_at(ap.1),
                }
                .script_pubkey();
                if wit.script_pubkey != expected_spk {
                    Err(Error::SpkNotMatch)
                } else {
                    Ok(())
                }
            } else {
                Err(Error::MissingWitnessUtxo)
            }?;

            // Grind the nonce until the signature serializes to its full
            // fixed-size low-R, low-S form (32-byte R with the high bit clear,
            // 32-byte S, a 70-byte DER body). Plain low-R signing still lets R or
            // S land below 32 bytes now and then, shaving a byte off the witness
            // and making the transaction vsize nondeterministic, which flakes
            // size and fee assertions. Forcing the maximal form keeps vsize stable.
            let signature = {
                let mut counter: u32 = 0;
                loop {
                    let mut noncedata = [0u8; 32];
                    noncedata[..4].copy_from_slice(&counter.to_le_bytes());
                    let sig =
                        self.secp()
                            .sign_ecdsa_with_noncedata(&hash, &signing_key, &noncedata);
                    if sig.serialize_der().len() == 70 {
                        break sig;
                    }
                    counter = counter.wrapping_add(1);
                }
            };

            self.secp()
                .verify_ecdsa(&hash, &signature, &pubkey)
                .map_err(|_| Error::InvalidSignature)?;

            let signature = ecdsa::Signature {
                signature,
                // NOTE: we only allow SigHash ALL for now
                sighash_type: EcdsaSighashType::All,
            };
            input.partial_sigs.insert(pubkey.into(), signature);
        }

        Ok(())
    }

    fn sign_input_tapkey(
        &self,
        psbt: &mut Psbt,
        index: usize,
        derivator: &SpkDerivator,
        cache: &mut sighash::SighashCache<bitcoin::Transaction>,
        participant_paths: &KeyPaths,
    ) -> Result<(), Error> {
        Self::has_witness_utxo(psbt, index)?;
        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .filter_map(|psbt_in| psbt_in.witness_utxo.clone())
            .collect();

        // NOTE: only support for SIGHASH_ALL for now
        let sighash_type = sighash::TapSighashType::Default;
        let prevouts = sighash::Prevouts::All(&prevouts);

        let input = psbt.inputs.get_mut(index).ok_or(Error::InputIndex)?;

        // Sign
        if let Some(ref int_key) = input.tap_internal_key {
            if let Some((_, (fg, der_path))) = input.tap_key_origins.get(int_key) {
                if *fg != self.fingerprint() || participant_paths.contains(der_path) {
                    return Err(Error::SpkNotMatch);
                }

                // Check the spk matches
                if let Some(wit) = &input.witness_utxo {
                    let ap = account_path(der_path)?;
                    let expected_spk = match ap.0 {
                        false => derivator.receive_at(ap.1),
                        true => derivator.change_at(ap.1),
                    }
                    .script_pubkey();
                    if wit.script_pubkey != expected_spk {
                        Err(Error::SpkNotMatch)
                    } else {
                        Ok(())
                    }
                } else {
                    Err(Error::MissingWitnessUtxo)
                }?;

                // Then sign
                let sighash = cache
                    .taproot_key_spend_signature_hash(index, &prevouts, sighash_type)
                    .map_err(|_| Error::InsanePrevouts)?;
                let sighash =
                    secp256k1::Message::from_digest_slice(&sighash.as_raw_hash().to_byte_array())
                        .expect("Sighash is always 32 bytes.");
                let mut sk = self.private_key_at(der_path);
                let mut keypair = secp256k1::Keypair::from_secret_key(self.secp(), &sk);
                sk.non_secure_erase();
                if keypair.x_only_public_key().0 != *int_key {
                    keypair.non_secure_erase();
                    return Err(Error::InternalKeyNotMatch);
                }
                #[allow(deprecated)]
                let mut tweaked = keypair
                    .tap_tweak(self.secp(), input.tap_merkle_root)
                    .to_inner();
                keypair.non_secure_erase();
                let signature = self.secp().sign_schnorr_no_aux_rand(&sighash, &tweaked);
                tweaked.non_secure_erase();
                let sig = bitcoin::taproot::Signature {
                    signature,
                    sighash_type,
                };
                input.tap_key_sig = Some(sig);
                return Ok(());
            }
        }
        Err(Error::NotTapKey)
    }

    #[allow(unused)]
    fn sign_input_taptree(
        &self,
        psbt: &mut Psbt,
        index: usize,
        derivator: &SpkDerivator,
        cache: &mut sighash::SighashCache<bitcoin::Transaction>,
        participant_paths: &KeyPaths,
    ) -> Result<(), Error> {
        Self::has_witness_utxo(psbt, index)?;
        let prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .filter_map(|psbt_in| psbt_in.witness_utxo.clone())
            .collect();

        // NOTE: only support for SIGHASH_ALL for now
        let sighash_type = sighash::TapSighashType::Default;
        let prevouts = sighash::Prevouts::All(&prevouts);

        let input = psbt.inputs.get_mut(index).ok_or(Error::InputIndex)?;
        let mut signed_any = false;
        for (pubkey, (leaf_hashes, (fg, der_path))) in &input.tap_key_origins {
            if *fg != self.fingerprint() || participant_paths.contains(der_path) {
                continue;
            }
            let mut sk = self.private_key_at(der_path);
            let mut keypair = secp256k1::Keypair::from_secret_key(self.secp(), &sk);
            sk.non_secure_erase();
            if keypair.x_only_public_key().0 != *pubkey {
                // NOTE: a fingerprint collision, or an origin that does not derive
                // its key
                keypair.non_secure_erase();
                continue;
            }

            for leaf_hash in leaf_hashes {
                let sighash = match cache.taproot_script_spend_signature_hash(
                    index,
                    &prevouts,
                    *leaf_hash,
                    sighash_type,
                ) {
                    Ok(sighash) => sighash,
                    Err(_) => {
                        keypair.non_secure_erase();
                        return Err(Error::InsaneTaptreeInfo);
                    }
                };
                let sighash = secp256k1::Message::from_digest_slice(sighash.as_byte_array())
                    .expect("Sighash is always 32 bytes.");
                let signature = self.secp().sign_schnorr_no_aux_rand(&sighash, &keypair);
                let sig = bitcoin::taproot::Signature {
                    signature,
                    sighash_type,
                };
                input.tap_script_sigs.insert((*pubkey, *leaf_hash), sig);
                signed_any = true;
            }
            keypair.non_secure_erase();
        }
        if signed_any {
            Ok(())
        } else {
            Err(Error::SpkNotMatch)
        }
    }

    /// Returns the [`Fingerprint`] of this [`HotSigner`].
    pub fn fingerprint(&self) -> bip32::Fingerprint {
        self.derivator.fingerprint()
    }

    /// Returns the master extended private key.
    pub fn master_xpriv(&self) -> bip32::Xpriv {
        self.derivator.master_xpriv()
    }

    /// Return the secp context of this signer
    pub fn secp(&self) -> &secp256k1::Secp256k1<All> {
        self.derivator.secp()
    }

    /// Returns a copy of the mnemonic if not None
    #[allow(unused)]
    fn mnemonic(&self) -> Option<bip39::Mnemonic> {
        self.derivator.mnemonic()
    }

    pub fn descriptors(&self) -> Vec<Descriptor> {
        self.descriptors.clone().into_iter().collect()
    }

    /// Get the taproot receive address and secret key at a given derivation index.
    ///
    /// This is a convenience method for tests that need to fund a taproot address
    /// and later sign transactions with the corresponding key.
    ///
    /// # Arguments
    /// * `index` - The derivation index (0, 1, 2, ...)
    ///
    /// # Returns
    /// A tuple of (Address, SecretKey) for the receive address at the given index.
    ///
    /// # Panics
    /// Panics if no taproot descriptor is registered or if derivation fails.
    #[cfg(feature = "test")]
    pub fn taproot_receive_address_and_key(
        &self,
        index: u32,
    ) -> (bitcoin::Address, secp256k1::SecretKey) {
        use bwk_descriptor::derivator::SpkDerivator;

        // Find a taproot descriptor
        let descriptor = self
            .descriptors
            .iter()
            .filter_map(|d| d.as_miniscript())
            .find(|d| matches!(d, miniscript::Descriptor::Tr(_)))
            .expect("no taproot descriptor registered");
        let derivator = SpkDerivator::new(descriptor.clone(), self.network)
            .expect("failed to create derivator");

        // Build the derivation path for the receive address
        let base_path = tr_path(
            self.network,
            ChildNumber::from_hardened_idx(0).expect("child number"),
        )
        .expect("tr_path");
        let base_path = base_path.child(ChildNumber::from_normal_idx(0).expect("child number"));
        let path = base_path.child(ChildNumber::from_normal_idx(index).expect("child number"));

        let address = derivator.receive_at(index);
        let secret_key = self.private_key_at(&path);

        (address, secret_key)
    }

    /// Get the native SegWit (P2WPKH) receive address and secret key at a given derivation index.
    ///
    /// This is a convenience method for tests that need to fund a P2WPKH address
    /// and later sign transactions with the corresponding key.
    ///
    /// # Arguments
    /// * `index` - The derivation index (0, 1, 2, ...)
    ///
    /// # Returns
    /// A tuple of (Address, SecretKey) for the receive address at the given index.
    ///
    /// # Panics
    /// Panics if no P2WPKH descriptor is registered or if derivation fails.
    #[cfg(feature = "test")]
    pub fn wpkh_receive_address_and_key(
        &self,
        index: u32,
    ) -> (bitcoin::Address, secp256k1::SecretKey) {
        use bwk_descriptor::derivator::SpkDerivator;

        // Find a wpkh descriptor
        let descriptor = self
            .descriptors
            .iter()
            .filter_map(|d| d.as_miniscript())
            .find(|d| matches!(d, miniscript::Descriptor::Wpkh(_)))
            .expect("no wpkh descriptor registered");
        let derivator = SpkDerivator::new(descriptor.clone(), self.network)
            .expect("failed to create derivator");

        // Build the derivation path for the receive address (BIP84)
        let base_path = wpkh_path(
            self.network,
            ChildNumber::from_hardened_idx(0).expect("child number"),
        )
        .expect("wpkh_path");
        let base_path = base_path.child(ChildNumber::from_normal_idx(0).expect("child number"));
        let path = base_path.child(ChildNumber::from_normal_idx(index).expect("child number"));

        let address = derivator.receive_at(index);
        let secret_key = self.private_key_at(&path);

        (address, secret_key)
    }

    /// Sign a Silent Payment input using tweak-based key derivation.
    ///
    /// The signing key is derived as: `signing_key = b_spend + tweak`
    /// where `b_spend` is derived from the mnemonic using the provided derivation path.
    ///
    /// # Arguments
    /// * `psbt` - The PSBT containing the transaction to sign
    /// * `input_index` - The index of the input to sign
    /// * `derivation` - The derivation path to derive b_spend from the master key
    /// * `tweak` - The 32-byte tweak scalar for this specific output
    /// * `aux_rand` - 32 bytes of auxiliary randomness for Schnorr signing
    #[cfg(feature = "sp")]
    pub fn sign_sp_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        derivation: &bip32::DerivationPath,
        tweak: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<(), Error> {
        let b_spend = self.derivator.secret_key_at(derivation);
        sign_sp_input(&b_spend, tweak, psbt, input_index, aux_rand)
    }
}

/// Compute taproot sighash for key-spend or script-spend.
// Source: relocated from cygnet3/spdk's SP signing path. See `sp/NOTICE`.
#[cfg(feature = "sp")]
fn taproot_sighash<
    T: std::ops::Deref<Target = bitcoin::Transaction> + std::borrow::Borrow<bitcoin::Transaction>,
>(
    hash_ty: bitcoin::TapSighashType,
    prevouts: &[bitcoin::TxOut],
    input_index: usize,
    cache: &mut sighash::SighashCache<T>,
    tapleaf_hash: Option<bitcoin::TapLeafHash>,
) -> Result<Message, Error> {
    let prevouts = sighash::Prevouts::All(prevouts);

    let sighash = match tapleaf_hash {
        Some(leaf_hash) => cache
            .taproot_script_spend_signature_hash(input_index, &prevouts, leaf_hash, hash_ty)
            .map_err(|_| Error::SpSigning)?,
        None => cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, hash_ty)
            .map_err(|_| Error::SpSigning)?,
    };
    let msg = Message::from_digest(*sighash.as_raw_hash().as_byte_array());
    Ok(msg)
}

/// Sign a single taproot input using SP tweak-based key derivation.
/// signing_key = b_spend + tweak
// Source: relocated from cygnet3/spdk's SP signing path. See `sp/NOTICE`.
#[cfg(feature = "sp")]
fn sign_sp_input(
    b_spend: &secp256k1::SecretKey,
    tweak: &[u8; 32],
    psbt: &mut Psbt,
    input_index: usize,
    aux_rand: &[u8; 32],
) -> Result<(), Error> {
    let psbt_tweak = bwk_psbt::sp::sp_input_tweak(&psbt.inputs[input_index])
        .map_err(|_| Error::SpSigning)?
        .ok_or(Error::SpSigning)?;
    if &psbt_tweak != tweak {
        return Err(Error::SpSigning);
    }

    let unsigned_tx = &psbt.unsigned_tx;

    // Collect all prevouts from PSBT inputs
    let prevouts: Vec<bitcoin::TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().ok_or(Error::SpSigning))
        .collect::<Result<Vec<_>, Error>>()?;

    let secp = secp256k1::Secp256k1::signing_only();
    let hash_ty = bitcoin::TapSighashType::Default;

    let mut cache = sighash::SighashCache::new(unsigned_tx);
    let msg = taproot_sighash(hash_ty, &prevouts, input_index, &mut cache, None)?;

    // Derive signing key: b_spend + tweak
    let tweak_sk = secp256k1::SecretKey::from_slice(tweak).map_err(|_| Error::SpSigning)?;
    let mut sk = b_spend
        .add_tweak(&tweak_sk.into())
        .map_err(|_| Error::SpSigning)?;
    let (output_key, parity) = sk.x_only_public_key(&secp);
    let script = &prevouts[input_index].script_pubkey;
    if !script.is_p2tr() || script.as_bytes().get(2..) != Some(output_key.serialize().as_ref()) {
        return Err(Error::SpSigning);
    }
    if parity == secp256k1::Parity::Odd {
        sk = sk.negate();
    }
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);

    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

    let signature = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: hash_ty,
    };

    psbt.inputs[input_index].tap_key_sig = Some(signature);

    Ok(())
}

/// Paths of this signer's keys in descriptors, with whether the key is ranged:
/// the musig() cosigners (participants) or the keys outside any musig().
/// The ordinary pass never signs with a participant key of any registered
/// descriptor, whatever the PSBT or the descriptor being signed claims. A key
/// derived under a cosigner that is not itself a participant, like
/// `A/<1024;1025>/*` next to `musig(A,B)/<512;513>/*`, is still signed.
#[derive(Default)]
pub(crate) struct KeyPaths(Vec<(DerivationPath, bool)>);

impl KeyPaths {
    /// The paths of this signer's musig() cosigners in `descriptors`.
    #[cfg(feature = "musig")]
    fn participants<'a>(
        descriptors: impl IntoIterator<Item = &'a WalletDescriptor>,
        fingerprint: bip32::Fingerprint,
    ) -> Self {
        Self::collect(descriptors, fingerprint, |key| match key {
            MusigKey::Musig(agg) => agg.cosigners().iter().collect(),
            MusigKey::Plain(_) => Vec::new(),
        })
    }

    /// The paths of this signer's keys outside any musig() in `descriptors`.
    #[cfg(feature = "musig")]
    fn plain<'a>(
        descriptors: impl IntoIterator<Item = &'a WalletDescriptor>,
        fingerprint: bip32::Fingerprint,
    ) -> Self {
        Self::collect(descriptors, fingerprint, |key| match key {
            MusigKey::Plain(key) => vec![key],
            MusigKey::Musig(_) => Vec::new(),
        })
    }

    #[cfg(feature = "musig")]
    fn collect<'a>(
        descriptors: impl IntoIterator<Item = &'a WalletDescriptor>,
        fingerprint: bip32::Fingerprint,
        keys: impl Fn(&MusigKey) -> Vec<&DescriptorPublicKey>,
    ) -> Self {
        let mut paths = Vec::new();
        for descriptor in descriptors {
            descriptor.for_each_key(|key| {
                for key in keys(key) {
                    if key.master_fingerprint() == fingerprint {
                        let ranged = key.has_wildcard();
                        paths.extend(
                            key.full_derivation_paths()
                                .into_iter()
                                .map(|path| (path, ranged)),
                        );
                    }
                }
                true
            });
        }
        Self(paths)
    }

    /// True when `path` is exactly one of these key paths: the key's own path
    /// when not ranged, the key at a derivation index when ranged.
    fn contains(&self, path: &DerivationPath) -> bool {
        self.0
            .iter()
            .any(|(key, ranged)| derives(key, *ranged, path))
    }

    /// True when a key of `self` and a key of `other` can be the same key.
    #[cfg(feature = "musig")]
    fn overlaps(&self, other: &KeyPaths) -> bool {
        self.0.iter().any(|(path, ranged)| {
            other
                .0
                .iter()
                .any(|(other_path, other_ranged)| match (ranged, other_ranged) {
                    (false, false) | (true, true) => path == other_path,
                    (true, false) => derives(path, true, other_path),
                    (false, true) => derives(other_path, true, path),
                })
        })
    }
}

/// True when `path` is the key at `key`: `key` itself when not ranged, `key`
/// at a normal derivation index when ranged.
fn derives(key: &DerivationPath, ranged: bool, path: &DerivationPath) -> bool {
    let (key, path) = (key.as_ref(), path.as_ref());
    match ranged {
        false => path == key,
        true => path.len() == key.len() + 1 && path.starts_with(key) && path[key.len()].is_normal(),
    }
}

/// A 0x1c to write on input `input_index`.
#[cfg(feature = "musig")]
struct InputPartialSig {
    input_index: usize,
    partial_sig: MusigPartialSig,
}

/// Fills `rand` from the OS for one nonce, in place so no copy is left to wipe.
/// A failure is `MusigSession`: the host restarts round 1.
#[cfg(feature = "musig")]
fn fresh_rand(rand: &mut [u8; 32]) -> Result<(), Error> {
    getrandom::getrandom(rand).map_err(|e| {
        log::error!("musig: no randomness for a nonce: {e}");
        Error::MusigSession
    })
}

/// Zeroes a secret with volatile writes, which the compiler cannot drop as dead
/// stores.
#[cfg(feature = "musig")]
fn wipe(secret: &mut [u8; 32]) {
    for byte in secret.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn has_sp_output(psbt: &PsbtV2) -> Result<bool, Error> {
    psbt.outputs
        .iter()
        .try_fold(false, |found, output| {
            bwk_psbt::sp::sp_v0_output(&output.psbt).map(|info| found || info.is_some())
        })
        .map_err(|_| Error::PsbtV2)
}

fn validated_v0(psbt: &PsbtV2) -> Result<Psbt, Error> {
    if has_sp_output(psbt)? {
        return Err(Error::PsbtV2);
    }
    psbt.validate().map_err(|_| Error::PsbtV2)?;
    psbt.clone().into_bitcoin_psbt().map_err(|_| Error::PsbtV2)
}

fn set_v0_maps(psbt: &mut PsbtV2, v0: Psbt) {
    for (input, v0_input) in psbt.inputs.iter_mut().zip(v0.inputs) {
        input.psbt = v0_input;
    }
    for (output, v0_output) in psbt.outputs.iter_mut().zip(v0.outputs) {
        output.psbt = v0_output;
    }
}

/// Converts a tuple containing an account type and an index into a derivation path.
///
/// # Arguments
/// * `path` - A tuple where the first element is a `bool` telling change from receive,
///   and the second element is a `u32` representing the index.
///
/// # Returns
/// A result containing the derived [`DerivationPath`] or an error if the conversion fails.
pub fn deriv_path(path: &(bool /* is_change */, u32)) -> Result<DerivationPath, Error> {
    let account_u32: u32 = path.0.into();
    DerivationPath::from_str(&format!("m/{}/{}", account_u32, path.1))
        .map_err(|_| Error::DerivationPath)
}

/// Converts a derivation path into a tuple containing an account type and an index.
///
/// # Arguments
/// * `path` - A reference to a [`DerivationPath`] that contains the account type and index.
///
/// # Returns
/// A result containing a tuple of the change flag as `bool` and the index as `u32`.
/// Returns an error if the derivation path does not have the expected length.
pub fn account_path(path: &DerivationPath) -> Result<(bool /* is_change */, u32), Error> {
    let mut path = path.to_u32_vec();
    #[allow(clippy::comparison_chain)]
    if path.len() < 2 {
        return Err(Error::DerivationPath);
    } else if path.len() > 2 {
        path = path[path.len() - 2..path.len()].to_vec();
    }
    if path.is_empty() {
        return Err(Error::DerivationPath);
    }
    let is_change = match path[0] {
        0 => false,
        1 => true,
        _ => {
            return Err(Error::DerivationPath);
        }
    };
    Ok((is_change, path[1]))
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bwk_descriptor::{
        derivator::SpkDerivator,
        descriptor::{tr, wpkh},
        sp_descriptor::SpDescriptor,
        wallet::to_wallet,
    };
    use bwk_utils::test::{random_output, setup_logger, txid};
    use crossbeam::channel;
    use miniscript::bitcoin::{
        absolute::Height,
        taproot::{LeafVersion, TapLeafHash},
        Amount, ScriptBuf, TxIn, Witness,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn hot_signer_is_send_and_sync() {
        assert_send_sync::<HotSigner>();
    }

    #[test]
    fn test_create_hot_signer_from_xpriv() {
        let network = Network::Testnet;
        let xpriv =
            bip32::Xpriv::new_master(network, &bip39::Mnemonic::generate(12).unwrap().to_seed(""))
                .unwrap();
        let signer = HotSigner::new_from_xpriv(network, xpriv);
        assert_eq!(signer.network, network);
    }

    #[test]
    fn test_create_hot_signer_from_mnemonic() {
        let network = Network::Testnet;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let signer = HotSigner::new_from_mnemonics(network, mnemonic).unwrap();
        assert_eq!(signer.network, network);
    }

    /// Not bip39 words, so they can only reach a message by leaking from the input.
    const UNKNOWN_MNEMONIC: &str = "zzalpha zzbravo zzcharlie zzdelta zzecho zzfoxtrot zzgolf zzhotel zzindia zzjuliett zzkilo zzlima";

    /// A valid bip39 vector with its last word swapped: english words, wrong checksum.
    const BAD_CHECKSUM_MNEMONIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank zoo";

    /// A downstream consumer writes these renders to a persistent log.
    fn assert_no_word_leak(err: &Error, mnemonic: &str) {
        for rendered in [err.to_string(), format!("{err:?}")] {
            for word in mnemonic.split_whitespace() {
                assert!(!rendered.contains(word), "leaked `{word}` in `{rendered}`");
            }
        }
    }

    #[test]
    fn unknown_word_error_hides_mnemonic_words() {
        for err in [
            HotSigner::new_from_mnemonics(Network::Signet, UNKNOWN_MNEMONIC).unwrap_err(),
            HotSigner::new_taproot_from_mnemonics(Network::Signet, UNKNOWN_MNEMONIC).unwrap_err(),
        ] {
            assert_no_word_leak(&err, UNKNOWN_MNEMONIC);
            assert_eq!(err.to_string(), "Fail to create derivator");
            assert_eq!(format!("{err:?}"), "Derivator");
        }
    }

    #[test]
    fn checksum_error_hides_mnemonic_words() {
        for err in [
            HotSigner::new_from_mnemonics(Network::Signet, BAD_CHECKSUM_MNEMONIC).unwrap_err(),
            HotSigner::new_taproot_from_mnemonics(Network::Signet, BAD_CHECKSUM_MNEMONIC)
                .unwrap_err(),
        ] {
            assert_no_word_leak(&err, BAD_CHECKSUM_MNEMONIC);
            assert_eq!(err.to_string(), "Fail to create derivator");
            assert_eq!(format!("{err:?}"), "Derivator");
        }
    }

    #[test]
    fn test_sign_transaction() {
        setup_logger();
        let network = Network::Testnet;
        let xpriv =
            bip32::Xpriv::new_master(network, &bip39::Mnemonic::generate(12).unwrap().to_seed(""))
                .unwrap();
        let signer = HotSigner::new_from_xpriv(network, xpriv);
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(wpkh(xpub));

        let txin = TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: Witness::new(),
        };

        let txout = random_output();

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![txin],
            output: vec![txout],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let pubkey = signer.public_key_at(&deriv_p);

        // there is no signature
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // try to sign the tx
        let err = signer.inner_sign(&mut psbt, &descriptor).unwrap_err();
        assert_eq!(err, Error::SigningInfo);

        // there is no signature as bip32_derivation is missing
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // add a wrong derivation path
        let w_deriv = &(true, 0);
        let w_deriv_path = deriv_path(w_deriv).unwrap();
        psbt.inputs
            .get_mut(0)
            .unwrap()
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), w_deriv_path));

        // try to sign the tx
        let res = signer.inner_sign(&mut psbt, &descriptor);

        // witness_utxo is missing
        assert_eq!(res, Err(Error::MissingWitnessUtxo));

        // there is no signature
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();

        // add spent TxOut
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });

        // try to sign the tx
        signer.inner_sign(&mut psbt, &descriptor).unwrap();

        // there is no signature as bip32_derivation is wrong and the public key
        // do not match only the fingerprint
        assert!(psbt.inputs[0].partial_sigs.is_empty());

        // cleanup deriv path map
        psbt.inputs[0].bip32_derivation.clear();

        // add the bip32 deriv
        psbt.inputs
            .get_mut(0)
            .unwrap()
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), deriv_p));

        // sign the tx
        signer.inner_sign(&mut psbt, &descriptor).unwrap();

        // signature was added
        assert!(!psbt.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn sign_v2_clears_modifiable_flags() {
        let network = Network::Regtest;
        let signer = new_signer(network);
        let derivation_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        let descriptor = to_wallet(wpkh(signer.xpub(&derivation_path)));
        let derivator = SpkDerivator::new(descriptor.clone(), network).unwrap();
        let mut psbt = base_psbt();
        let deriv = (false, 0);
        let derivation_path = deriv_path(&deriv).unwrap();
        psbt.inputs[0].bip32_derivation.insert(
            signer.public_key_at(&derivation_path),
            (signer.fingerprint(), derivation_path),
        );
        let mut missing_witness = PsbtV2::from_bitcoin_psbt(psbt.clone()).unwrap();
        assert_eq!(
            signer.sign_v2(&mut missing_witness, &descriptor),
            Err(Error::MissingWitnessUtxo)
        );

        psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        let mut psbt = PsbtV2::from_bitcoin_psbt(psbt).unwrap();
        psbt.tx_modifiable = Some(
            bwk_psbt::TxModifiable::try_from(
                bwk_psbt::TxModifiable::INPUTS | bwk_psbt::TxModifiable::OUTPUTS,
            )
            .unwrap(),
        );
        signer.sign_v2(&mut psbt, &descriptor).unwrap();

        assert_eq!(psbt.tx_modifiable.unwrap().bits(), 0);
        assert!(!psbt.inputs[0].psbt.partial_sigs.is_empty());
    }

    #[test]
    fn sign_v2_rejects_unverified_silent_payment_output() {
        let network = Network::Regtest;
        let signer = new_signer(network);
        let account_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        let descriptor = to_wallet(wpkh(signer.xpub(&account_path)));
        let derivator = SpkDerivator::new(descriptor.clone(), network).unwrap();
        let derivation_path = deriv_path(&(false, 0)).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let attacker = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[8; 32]).unwrap(),
        );
        let attacker_script =
            ScriptBuf::new_p2tr_tweaked(attacker.x_only_public_key().0.dangerous_assume_tweaked());
        let mut psbt = base_psbt();
        psbt.unsigned_tx.output[0].script_pubkey = attacker_script;
        let pubkey = signer.public_key_at(&derivation_path);
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), derivation_path));
        psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(0),
        });
        let mut psbt = PsbtV2::from_bitcoin_psbt(psbt).unwrap();
        let scan_key = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[9; 32]).unwrap(),
        );
        let spend_key = secp256k1::PublicKey::from_secret_key(
            &secp,
            &secp256k1::SecretKey::from_slice(&[10; 32]).unwrap(),
        );
        bwk_psbt::sp::set_sp_v0_output(&mut psbt.outputs[0].psbt, scan_key, spend_key, None);
        psbt.tx_modifiable = Some(bwk_psbt::TxModifiable::none());

        let result = signer.sign_v2(&mut psbt, &descriptor);

        assert_eq!(
            (result, psbt.inputs[0].psbt.partial_sigs.is_empty()),
            (Err(Error::PsbtV2), true)
        );
    }

    #[test]
    fn sign_v2_rejects_foreign_taproot_without_mutating() {
        let network = Network::Regtest;
        let signer = new_signer(network);
        let foreign = new_signer(network);
        let account_path = DerivationPath::from_str("m/86'/0'/0'/0").unwrap();
        let descriptor = to_wallet(tr(signer.xpub(&account_path)));
        let derivator = SpkDerivator::new(descriptor.clone(), network).unwrap();
        let deriv = deriv_path(&(false, 0)).unwrap();
        let internal_key = signer.public_key_at(&deriv).x_only_public_key().0;
        let mut psbt = base_psbt();
        psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(0),
        });
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_key_origins
            .insert(internal_key, (Vec::new(), (foreign.fingerprint(), deriv)));

        let mut psbt = PsbtV2::from_bitcoin_psbt(psbt).unwrap();
        psbt.tx_modifiable =
            Some(bwk_psbt::TxModifiable::try_from(bwk_psbt::TxModifiable::INPUTS).unwrap());
        let before = psbt.clone();

        assert_eq!(
            signer.sign_v2(&mut psbt, &descriptor),
            Err(Error::SigningInfo)
        );
        assert_eq!(psbt, before);
    }

    #[test]
    fn sign_v2_rejects_mixed_metadata() {
        let network = Network::Regtest;
        let signer = new_signer(network);
        let account_path = DerivationPath::from_str("m/86'/0'/0'/0").unwrap();
        let descriptor = to_wallet(tr(signer.xpub(&account_path)));
        let derivator = SpkDerivator::new(descriptor.clone(), network).unwrap();
        let deriv = deriv_path(&(false, 0)).unwrap();
        let pubkey = signer.public_key_at(&deriv);
        let internal_key = pubkey.x_only_public_key().0;
        let mut psbt = base_psbt();
        psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(0),
        });
        psbt.inputs[0]
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), deriv.clone()));
        psbt.inputs[0].tap_internal_key = Some(internal_key);
        psbt.inputs[0]
            .tap_key_origins
            .insert(internal_key, (Vec::new(), (signer.fingerprint(), deriv)));
        let mut psbt = PsbtV2::from_bitcoin_psbt(psbt).unwrap();

        assert_eq!(
            signer.sign_v2(&mut psbt, &descriptor),
            Err(Error::MixedSigningInfo)
        );
    }

    // Notification Signer tests

    struct MockSender {
        receiver: channel::Receiver<SignerNotif>,
    }

    impl MockSender {
        fn new() -> (channel::Sender<SignerNotif>, Self) {
            let (sender, receiver) = channel::unbounded();
            (sender, MockSender { receiver })
        }
    }

    #[test]
    fn test_signer_init() {
        let (sender, mock) = MockSender::new();
        let mut signer = HotSigner::new_from_xpriv(
            Network::Regtest,
            bip32::Xpriv::new_master(
                Network::Regtest,
                &bip39::Mnemonic::generate(12).unwrap().to_seed(""),
            )
            .unwrap(),
        );
        signer.init(sender);

        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Info(fg, _) => {
                assert_eq!(signer.fingerprint(), fg);
            }
            _ => panic!("Expected Info notification"),
        }
    }

    #[test]
    fn test_signer_info() {
        let (sender, mock) = MockSender::new();
        let mut signer = HotSigner::new_from_xpriv(
            Network::Regtest,
            bip32::Xpriv::new_master(
                Network::Regtest,
                &bip39::Mnemonic::generate(12).unwrap().to_seed(""),
            )
            .unwrap(),
        );
        signer.init(sender);
        signer.info();

        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Info(fg, _) => {
                assert_eq!(signer.fingerprint(), fg);
            }
            _ => panic!("Expected Info notification"),
        }
    }

    #[test]
    fn test_signer_get_xpub() {
        let (sender, mock) = MockSender::new();
        let mut signer = HotSigner::new_from_xpriv(
            Network::Regtest,
            bip32::Xpriv::new_master(
                Network::Regtest,
                &bip39::Mnemonic::generate(12).unwrap().to_seed(""),
            )
            .unwrap(),
        );
        signer.init(sender);
        let derivation_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        signer.get_xpub(derivation_path, false);

        // first notif in info
        let _ = mock.receiver.recv().unwrap();

        // second is expected to be xpub
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Xpub(fg, _) => {
                assert_eq!(signer.fingerprint(), fg);
            }
            _ => panic!("Expected Xpub notification"),
        }
    }

    #[test]
    fn test_signer_is_descriptor_registered() {
        let (sender, mock) = MockSender::new();
        let mut signer = HotSigner::new_from_xpriv(
            Network::Regtest,
            bip32::Xpriv::new_master(
                Network::Regtest,
                &bip39::Mnemonic::generate(12).unwrap().to_seed(""),
            )
            .unwrap(),
        );
        signer.init(sender);
        // info notif
        let _ = mock.receiver.recv();
        let descriptor: Descriptor =
            wpkh(signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/0").unwrap())).into();

        signer.is_descriptor_registered(descriptor.clone());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::DescriptorRegistered(fg, desc, false) => {
                assert_eq!(signer.fingerprint(), fg);
                assert_eq!(desc, descriptor);
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }

        signer.register_descriptor(descriptor.clone());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::DescriptorRegistered(fg, desc, true) => {
                assert_eq!(signer.fingerprint(), fg);
                assert_eq!(desc, descriptor);
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }

        signer.is_descriptor_registered(descriptor.clone());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::DescriptorRegistered(fg, desc, true) => {
                assert_eq!(signer.fingerprint(), fg);
                assert_eq!(desc, descriptor);
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }
    }

    #[test]
    fn test_signer_sign_segwit() {
        let (sender, mock) = MockSender::new();
        let mut signer = HotSigner::new_from_xpriv(
            Network::Regtest,
            bip32::Xpriv::new_master(
                Network::Regtest,
                &bip39::Mnemonic::generate(12).unwrap().to_seed(""),
            )
            .unwrap(),
        );
        let derivation_path = DerivationPath::from_str("m/84'/0'/0'/0").unwrap();
        let descriptor = to_wallet(wpkh(signer.xpub(&derivation_path)));

        signer.init(sender);
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Info(fg, _) => {
                assert_eq!(signer.fingerprint(), fg);
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }

        signer.register_descriptor(descriptor.clone().into());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::DescriptorRegistered(fg, desc, true) => {
                assert_eq!(signer.fingerprint(), fg);
                assert_eq!(desc, Descriptor::from(descriptor.clone()));
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }

        let txin = TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: Witness::new(),
        };

        let txout = random_output();

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![txin],
            output: vec![txout],
        };

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();

        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let pubkey = signer.public_key_at(&deriv_p);

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();

        // add spent TxOut
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });

        // add the bip32 deriv
        psbt.inputs
            .get_mut(0)
            .unwrap()
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), deriv_p));

        signer.sign_with_descriptor(psbt, descriptor.into());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Signed(fg, psbt) => {
                assert_eq!(signer.fingerprint(), fg);
                assert!(!psbt.inputs[0].partial_sigs.is_empty());
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }
    }

    fn base_psbt() -> Psbt {
        let txin = TxIn {
            previous_output: bitcoin::OutPoint {
                txid: txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: Witness::new(),
        };
        let txout = random_output();
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![txin],
            output: vec![txout],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    fn new_signer(network: Network) -> HotSigner {
        HotSigner::new_from_xpriv(
            network,
            bip32::Xpriv::new_master(network, &bip39::Mnemonic::generate(12).unwrap().to_seed(""))
                .unwrap(),
        )
    }

    #[test]
    fn segwit_input_with_foreign_fingerprint_is_not_signed() {
        let network = Network::Testnet;
        let signer = new_signer(network);
        let other_signer = new_signer(network);
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(wpkh(xpub));

        let mut psbt = base_psbt();
        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let pubkey = signer.public_key_at(&deriv_p);

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        psbt.inputs
            .get_mut(0)
            .unwrap()
            .bip32_derivation
            .insert(pubkey, (other_signer.fingerprint(), deriv_p));

        let err = signer.inner_sign(&mut psbt, &descriptor).unwrap_err();
        assert_eq!(err, Error::SigningInfo);
        assert!(psbt.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn taproot_input_with_foreign_key_origin_is_not_signed() {
        let network = Network::Testnet;
        let signer = new_signer(network);
        let other_signer = new_signer(network);
        let xpub = signer.xpub(&DerivationPath::from_str("m/86'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(tr(xpub));

        let mut psbt = base_psbt();
        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();
        let sk = signer.private_key_at(&deriv_p);
        let keypair = secp256k1::Keypair::from_secret_key(signer.secp(), &sk);
        let internal_key = keypair.x_only_public_key().0;

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        psbt.inputs.get_mut(0).unwrap().tap_internal_key = Some(internal_key);
        psbt.inputs.get_mut(0).unwrap().tap_key_origins.insert(
            internal_key,
            (vec![], (other_signer.fingerprint(), deriv_p)),
        );

        let before = psbt.clone();
        let err = signer.inner_sign(&mut psbt, &descriptor).unwrap_err();
        assert_eq!(err, Error::SigningInfo);
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert_eq!(psbt, before);
    }

    #[test]
    fn taptree_input_with_no_matching_leaf_is_not_signed() {
        let network = Network::Testnet;
        let signer = new_signer(network);
        let other_signer = new_signer(network);
        let xpub = signer.xpub(&DerivationPath::from_str("m/86'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(tr(xpub));

        let mut psbt = base_psbt();
        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });

        let sk = other_signer.private_key_at(&deriv_p);
        let keypair = secp256k1::Keypair::from_secret_key(other_signer.secp(), &sk);
        let leaf_pubkey = keypair.x_only_public_key().0;
        let leaf_hash = TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        psbt.inputs.get_mut(0).unwrap().tap_key_origins.insert(
            leaf_pubkey,
            (vec![leaf_hash], (other_signer.fingerprint(), deriv_p)),
        );

        let err = signer.inner_sign(&mut psbt, &descriptor).unwrap_err();
        assert_eq!(err, Error::SigningInfo);
        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
    }

    #[test]
    fn mixed_segwit_and_taproot_metadata_is_rejected() {
        let network = Network::Testnet;
        let signer = new_signer(network);
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(wpkh(xpub));

        let mut psbt = base_psbt();
        let deriv_p = deriv_path(&(false, 0)).unwrap();
        let pubkey = signer.public_key_at(&deriv_p);
        psbt.inputs
            .get_mut(0)
            .unwrap()
            .bip32_derivation
            .insert(pubkey, (signer.fingerprint(), deriv_p.clone()));

        let sk = signer.private_key_at(&deriv_p);
        let keypair = secp256k1::Keypair::from_secret_key(signer.secp(), &sk);
        let leaf_pubkey = keypair.x_only_public_key().0;
        let leaf_hash = TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        psbt.inputs.get_mut(0).unwrap().tap_key_origins.insert(
            leaf_pubkey,
            (vec![leaf_hash], (signer.fingerprint(), deriv_p)),
        );

        let err = signer.inner_sign(&mut psbt, &descriptor).unwrap_err();
        assert_eq!(err, Error::MixedSigningInfo);
    }

    #[test]
    fn taproot_key_and_script_paths_are_both_attempted() {
        let network = Network::Testnet;
        let signer = new_signer(network);
        let other_signer = new_signer(network);
        let xpub = signer.xpub(&DerivationPath::from_str("m/86'/0'/0'/1'").unwrap());
        let descriptor = to_wallet(tr(xpub));

        let mut psbt = base_psbt();
        let deriv = &(false, 0);
        let deriv_p = deriv_path(deriv).unwrap();

        let sk_internal = other_signer.private_key_at(&deriv_p);
        let keypair_internal =
            secp256k1::Keypair::from_secret_key(other_signer.secp(), &sk_internal);
        let internal_key = keypair_internal.x_only_public_key().0;

        let leaf_deriv = deriv_path(&(false, 1)).unwrap();
        let sk_leaf = signer.private_key_at(&leaf_deriv);
        let keypair_leaf = secp256k1::Keypair::from_secret_key(signer.secp(), &sk_leaf);
        let leaf_pubkey = keypair_leaf.x_only_public_key().0;
        let leaf_hash = TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);

        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        psbt.inputs.get_mut(0).unwrap().witness_utxo = Some(bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: derivator.receive_spk_at(deriv.1),
        });
        psbt.inputs.get_mut(0).unwrap().tap_internal_key = Some(internal_key);
        psbt.inputs.get_mut(0).unwrap().tap_key_origins.insert(
            internal_key,
            (vec![], (other_signer.fingerprint(), deriv_p)),
        );
        psbt.inputs.get_mut(0).unwrap().tap_key_origins.insert(
            leaf_pubkey,
            (vec![leaf_hash], (signer.fingerprint(), leaf_deriv)),
        );

        signer.inner_sign(&mut psbt, &descriptor).unwrap();
        assert!(!psbt.inputs[0].tap_script_sigs.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    fn sp_descriptor(fingerprint: &str, spend_seed: u8) -> Descriptor {
        let secp = secp256k1::Secp256k1::new();
        let scan = bip32::Xpriv::new_master(Network::Testnet, &[0x09; 64]).unwrap();
        let spend_xpriv = bip32::Xpriv::new_master(Network::Testnet, &[spend_seed; 64]).unwrap();
        let spend_xpub = bip32::Xpub::from_priv(&secp, &spend_xpriv);
        let s = format!("sp([{fingerprint}/352h/0h/0h]{scan}/0h,{spend_xpub}/0h)");
        SpDescriptor::from_str(&s).unwrap().into()
    }

    #[test]
    fn hot_signer_registers_miniscript_descriptor() {
        let (sender, mock) = MockSender::new();
        let mut signer = new_signer(Network::Regtest);
        signer.init(sender);
        let _ = mock.receiver.recv();

        let descriptor: Descriptor =
            wpkh(signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/0").unwrap())).into();

        signer.register_descriptor(descriptor.clone());
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::DescriptorRegistered(_, desc, true) => assert_eq!(desc, descriptor),
            other => panic!("expected DescriptorRegistered, got {other:?}"),
        }
        assert!(signer.descriptors().contains(&descriptor));
    }

    #[test]
    fn hot_signer_rejects_sp_descriptor() {
        let (sender, mock) = MockSender::new();
        let mut signer = new_signer(Network::Regtest);
        let fingerprint = signer.fingerprint();
        signer.init(sender);
        let _ = mock.receiver.recv();

        let descriptor = sp_descriptor(&fingerprint.to_string(), 0x0a);

        signer.register_descriptor(descriptor);
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Error(_, Error::SpDescriptor) => {}
            other => panic!("expected Error(SpDescriptor), got {other:?}"),
        }
        assert!(signer.descriptors().is_empty());
    }

    #[test]
    fn hot_signer_sign_rejects_sp_descriptor() {
        let (sender, mock) = MockSender::new();
        let mut signer = new_signer(Network::Regtest);
        let fingerprint = signer.fingerprint();
        signer.init(sender);
        let _ = mock.receiver.recv();

        let descriptor = sp_descriptor(&fingerprint.to_string(), 0x0b);
        let psbt = base_psbt();

        signer.sign_with_descriptor(psbt, descriptor);
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Error(_, Error::SpDescriptor) => {}
            other => panic!("expected Error(SpDescriptor), got {other:?}"),
        }
        assert!(mock.receiver.try_recv().is_err());
    }

    #[test]
    fn json_signer_roundtrips_both_kinds() {
        let network = Network::Regtest;
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(network, &mnemonic.to_string()).unwrap();
        let miniscript_descriptor: Descriptor =
            wpkh(signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/0").unwrap())).into();
        let sp_descr = sp_descriptor(&signer.fingerprint().to_string(), 0x0c);

        let json = JsonSigner {
            mnemonic,
            descriptors: [miniscript_descriptor.to_string(), sp_descr.to_string()]
                .into_iter()
                .collect(),
            network,
        };

        let restored = HotSigner::from_json(json);
        let descriptors = restored.descriptors();
        assert!(descriptors.contains(&miniscript_descriptor));
        assert!(descriptors.contains(&sp_descr));
    }
}

#[cfg(all(test, feature = "test", feature = "musig"))]
mod musig_tests {
    use std::str::FromStr;

    use bwk_descriptor::{
        descriptor::Descriptor,
        updater::update_input,
        wallet::{WalletDescriptor, WalletDescriptorExt},
    };
    use bwk_musig::{rust_bitcoin::RustBitcoin, KeyAgg};
    use bwk_psbt::musig::{
        musig_input_partial_sig, musig_input_partial_sigs, musig_input_pub_nonces,
        remove_musig_input_pub_nonces, set_musig_input_partial_sig, set_musig_input_participants,
        MusigPartialSig,
    };
    use bwk_utils::test::{random_output, txid};
    use crossbeam::channel;
    use miniscript::{
        bitcoin::{
            absolute::{Height, LockTime},
            bip32::DerivationPath,
            hex::DisplayHex,
            secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey},
            taproot::{LeafVersion, TapLeafHash},
            transaction::Version,
            Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
            Witness,
        },
        psbt::PsbtExt,
    };

    use crate::{
        error::Error,
        hot_signer::HotSigner,
        musig::{aggregate_partial_sigs, musig_status, own_slots, MusigRound},
        signer::{Signer, SignerNotif},
    };

    const COSIGNER_PATH: &str = "m/87'/1'/0'/2";
    const PLAIN_PATH: &str = "m/86'/1'/0'";

    fn musig_signers(n: usize) -> Vec<HotSigner> {
        (0..n)
            .map(|_| HotSigner::new(Network::Regtest).unwrap())
            .collect()
    }

    fn cosigner(signer: &HotSigner) -> String {
        signer
            .xpub(&DerivationPath::from_str(COSIGNER_PATH).unwrap())
            .to_string()
    }

    fn plain(signer: &HotSigner) -> String {
        signer
            .xpub(&DerivationPath::from_str(PLAIN_PATH).unwrap())
            .to_string()
    }

    fn participant(signer: &HotSigner) -> PublicKey {
        signer.public_key_at(&DerivationPath::from_str(COSIGNER_PATH).unwrap())
    }

    fn register(signers: &mut [&mut HotSigner], text: &str) -> WalletDescriptor {
        let descriptor = Descriptor::from_str(text).unwrap();
        for signer in signers.iter_mut() {
            signer.inner_register_descriptor(descriptor.clone());
        }
        descriptor.into_miniscript().unwrap()
    }

    fn musig_psbt(descriptor: &WalletDescriptor, indexes: &[u32]) -> Psbt {
        let receive = descriptor.single_paths().unwrap()[0].clone();
        let input = indexes
            .iter()
            .enumerate()
            .map(|(vout, _)| TxIn {
                previous_output: OutPoint {
                    txid: txid(),
                    vout: vout as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            })
            .collect();
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::Blocks(Height::ZERO),
            input,
            output: vec![random_output()],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (position, index) in indexes.iter().enumerate() {
            let definite = receive.derive_at(*index).unwrap();
            psbt.inputs[position].witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: definite.script_pubkey(),
            });
            update_input(&mut psbt, position, &definite).unwrap();
        }
        psbt
    }

    /// The hash of the `position`-th leaf of the receive descriptor at `index`.
    fn leaf_hash(descriptor: &WalletDescriptor, index: u32, position: usize) -> TapLeafHash {
        let receive = descriptor.single_paths().unwrap()[0].clone();
        let miniscript::Descriptor::Tr(tr) = receive.derive_at(index).unwrap() else {
            panic!("not a tr() descriptor");
        };
        let (_, ms) = tr.iter_scripts().nth(position).unwrap();
        TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript)
    }

    fn keep_leaf(psbt: &mut Psbt, leaf_hash: TapLeafHash) {
        for input in &mut psbt.inputs {
            input.tap_scripts.retain(|_, (script, version)| {
                TapLeafHash::from_script(script, *version) == leaf_hash
            });
        }
    }

    /// Aggregates then runs the miniscript finalizer; the count aggregated.
    fn finalize(psbt: &mut Psbt, descriptor: &WalletDescriptor) -> usize {
        let aggregated = aggregate_partial_sigs(psbt, descriptor).unwrap();
        psbt.finalize_mut(&Secp256k1::verification_only()).unwrap();
        aggregated
    }

    fn round(psbt: &Psbt, descriptor: &WalletDescriptor) -> MusigRound {
        musig_status(psbt, descriptor).unwrap().round
    }

    fn partial_sig_count(psbt: &Psbt) -> usize {
        psbt.inputs
            .iter()
            .map(|input| musig_input_partial_sigs(input).unwrap().len())
            .sum()
    }

    fn two_of_two(a: &mut HotSigner, b: &mut HotSigner) -> WalletDescriptor {
        let text = format!("tr(musig({},{})/<0;1>/*)", cosigner(a), cosigner(b));
        register(&mut [a, b], &text)
    }

    /// `tr(musig(A,B)/<0;1>/*,pk(A_plain/<0;1>/*))`.
    fn key_path_and_plain_leaf(a: &mut HotSigner, b: &mut HotSigner) -> WalletDescriptor {
        let text = format!(
            "tr(musig({},{})/<0;1>/*,pk({}/<0;1>/*))",
            cosigner(a),
            cosigner(b),
            plain(a)
        );
        register(&mut [a, b], &text)
    }

    /// Both cosigners run round 1.
    fn both_round_one(psbt: &mut Psbt, d: &WalletDescriptor, a: &HotSigner, b: &HotSigner) {
        a.inner_sign(psbt, d).unwrap();
        b.inner_sign(psbt, d).unwrap();
    }

    #[test]
    fn musig_two_of_two_key_path_signs_in_two_rounds() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0, 1]);
        assert_eq!(round(&psbt, &d), MusigRound::Nonces);

        a.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(round(&psbt, &d), MusigRound::Nonces);
        b.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(round(&psbt, &d), MusigRound::PartialSigs);
        a.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(round(&psbt, &d), MusigRound::PartialSigs);
        b.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(round(&psbt, &d), MusigRound::Ready);

        let status = musig_status(&psbt, &d).unwrap();
        assert_eq!(status.cosigners.len(), 2);
        for cosigner in &status.cosigners {
            assert_eq!(
                (cosigner.nonces, cosigner.partial_sigs, cosigner.expected),
                (2, 2, 2)
            );
        }

        assert_eq!(finalize(&mut psbt, &d), 2);
        assert!(psbt.inputs.iter().all(|i| i.final_script_witness.is_some()));
    }

    #[test]
    fn musig_two_of_three_leaf_signs_between_two_hot_signers() {
        let [mut a, mut b, mut c]: [HotSigner; 3] = musig_signers(3).try_into().unwrap();
        let text = format!(
            "tr({}/<0;1>/*,{{pk(musig({},{})/<0;1>/*),{{pk(musig({},{})/<0;1>/*),pk(musig({},{})/<0;1>/*)}}}})",
            plain(&c),
            cosigner(&a),
            cosigner(&b),
            cosigner(&a),
            cosigner(&c),
            cosigner(&b),
            cosigner(&c),
        );
        let d = register(&mut [&mut a, &mut b, &mut c], &text);
        let mut psbt = musig_psbt(&d, &[0]);
        let ab_leaf = leaf_hash(&d, 0, 0);
        keep_leaf(&mut psbt, ab_leaf);

        assert_eq!(own_slots(&psbt, &d, a.fingerprint()).unwrap().len(), 1);
        assert_eq!(own_slots(&psbt, &d, b.fingerprint()).unwrap().len(), 1);
        assert!(own_slots(&psbt, &d, c.fingerprint()).unwrap().is_empty());

        both_round_one(&mut psbt, &d, &a, &b);
        a.inner_sign(&mut psbt, &d).unwrap();
        b.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(round(&psbt, &d), MusigRound::Ready);

        let input = &psbt.inputs[0];
        let nonces = musig_input_pub_nonces(input).unwrap();
        let partial_sigs = musig_input_partial_sigs(input).unwrap();
        assert_eq!(nonces.len(), 2);
        assert_eq!(partial_sigs.len(), 2);
        assert!(nonces.iter().all(|n| n.leaf_hash == Some(ab_leaf)));
        assert!(partial_sigs.iter().all(|s| s.leaf_hash == Some(ab_leaf)));
        assert!(input.tap_script_sigs.is_empty());

        assert_eq!(finalize(&mut psbt, &d), 1);
        assert!(psbt.inputs[0].final_script_witness.is_some());
    }

    #[test]
    fn round_one_adds_only_nonces() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = key_path_and_plain_leaf(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);

        assert_eq!(a.inner_sign(&mut psbt, &d), Ok(()));

        let own = own_slots(&psbt, &d, a.fingerprint()).unwrap();
        assert_eq!(own.len(), 1);
        assert_eq!(own[0].leaf_hash, None);
        let input = &psbt.inputs[0];
        let nonces = musig_input_pub_nonces(input).unwrap();
        assert_eq!(nonces.len(), 1);
        assert_eq!(nonces[0].participant, participant(&a));
        assert_eq!(nonces[0].aggregate, own[0].aggregate);
        assert_eq!(nonces[0].leaf_hash, None);
        assert!(musig_input_partial_sigs(input).unwrap().is_empty());
        assert!(input.tap_key_sig.is_none());
        assert!(input.tap_script_sigs.is_empty());
    }

    #[test]
    fn ordinary_keys_sign_in_round_two() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = key_path_and_plain_leaf(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);
        a.inner_sign(&mut psbt, &d).unwrap();
        b.inner_sign(&mut psbt, &d).unwrap();

        let plain_key = a
            .public_key_at(&DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap())
            .x_only_public_key()
            .0;
        let plain_leaf = leaf_hash(&d, 0, 0);
        let sigs = &psbt.inputs[0].tap_script_sigs;
        assert!(sigs.contains_key(&(plain_key, plain_leaf)));
        let participants: Vec<XOnlyPublicKey> = [participant(&a), participant(&b)]
            .iter()
            .map(|key| key.x_only_public_key().0)
            .collect();
        assert!(sigs.keys().all(|(key, _)| !participants.contains(key)));
        assert_eq!(partial_sig_count(&psbt), 2);
    }

    #[test]
    fn replayed_round_two_is_refused() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);
        let mut copy = psbt.clone();

        a.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(partial_sig_count(&psbt), 1);

        assert_eq!(a.inner_sign(&mut copy, &d), Err(Error::MusigSession));
        assert_eq!(partial_sig_count(&copy), 0);
    }

    #[test]
    fn tx_changed_between_rounds_is_refused() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);

        psbt.unsigned_tx.output[0].value += Amount::from_sat(1);
        assert_eq!(a.inner_sign(&mut psbt, &d), Err(Error::MusigSession));
        assert_eq!(partial_sig_count(&psbt), 0);
    }

    #[test]
    fn foreign_participants_field_is_ignored() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);

        let secp = Secp256k1::new();
        let random_key = SecretKey::new(&mut miniscript::bitcoin::secp256k1::rand::thread_rng())
            .public_key(&secp);
        let foreign = [participant(&a), random_key];
        let keys: Vec<[u8; 33]> = foreign.iter().map(PublicKey::serialize).collect();
        let foreign_agg = KeyAgg::sorted(&RustBitcoin, &keys).unwrap();
        let foreign_agg = PublicKey::from_slice(&foreign_agg.aggregate()).unwrap();
        set_musig_input_participants(&mut psbt.inputs[0], foreign_agg, &foreign);

        a.inner_sign(&mut psbt, &d).unwrap();

        let own = own_slots(&psbt, &d, a.fingerprint()).unwrap();
        let nonces = musig_input_pub_nonces(&psbt.inputs[0]).unwrap();
        let own_nonces = nonces
            .iter()
            .filter(|n| n.participant == participant(&a))
            .count();
        assert_eq!(own_nonces, own.len());
        assert_eq!(own.len(), 1);
        assert!(nonces.iter().all(|n| n.aggregate != foreign_agg));
    }

    #[test]
    fn partial_own_nonces_are_refused() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0, 1]);
        a.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(a.musig_sessions().len(), 1);

        assert_eq!(remove_musig_input_pub_nonces(&mut psbt.inputs[0]), 1);
        assert_eq!(a.inner_sign(&mut psbt, &d), Err(Error::MusigSession));
        assert!(a.musig_sessions().is_empty());
    }

    #[test]
    fn missing_cosigner_nonce_is_refused() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        a.inner_sign(&mut psbt, &d).unwrap();

        assert_eq!(a.inner_sign(&mut psbt, &d), Err(Error::MusigNonces));
        assert!(a.musig_sessions().is_empty());
        assert_eq!(partial_sig_count(&psbt), 0);
    }

    #[test]
    fn session_is_erased_after_round_two() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);
        assert_eq!(a.musig_sessions().len(), 1);

        a.inner_sign(&mut psbt, &d).unwrap();
        assert!(a.musig_sessions().is_empty());
        assert_eq!(b.musig_sessions().len(), 1);
    }

    #[test]
    fn rebuilt_signer_with_shared_store_completes_round_two() {
        let [mut a1, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a1, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a1, &b);

        let mut a2 = HotSigner::from_json(a1.to_json().unwrap());
        assert!(a2.musig_sessions().is_empty());
        a2.set_musig_sessions(a1.musig_sessions());
        a2.inner_sign(&mut psbt, &d).unwrap();

        assert!(a1.musig_sessions().is_empty());
        let own = own_slots(&psbt, &d, a1.fingerprint()).unwrap();
        let slot = own[0];
        let partial_sig = musig_input_partial_sig(
            &psbt.inputs[0],
            slot.participant,
            slot.aggregate,
            slot.leaf_hash,
        )
        .unwrap();
        assert!(partial_sig.is_some());
    }

    #[test]
    fn invalid_partial_sig_is_refused_by_aggregation() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);
        a.inner_sign(&mut psbt, &d).unwrap();
        b.inner_sign(&mut psbt, &d).unwrap();

        let slot = own_slots(&psbt, &d, b.fingerprint()).unwrap()[0];
        let mut signature = musig_input_partial_sig(
            &psbt.inputs[0],
            slot.participant,
            slot.aggregate,
            slot.leaf_hash,
        )
        .unwrap()
        .unwrap();
        signature[31] ^= 0x01;
        let flipped = MusigPartialSig {
            participant: slot.participant,
            aggregate: slot.aggregate,
            leaf_hash: slot.leaf_hash,
            signature,
        };
        set_musig_input_partial_sig(&mut psbt.inputs[0], &flipped);

        assert_eq!(
            aggregate_partial_sigs(&mut psbt, &d),
            Err(Error::MusigPartialSig(0))
        );
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn musig_status_reports_not_musig_for_plain_psbt() {
        let [mut a]: [HotSigner; 1] = musig_signers(1).try_into().unwrap();
        let text = format!("tr({}/<0;1>/*)", plain(&a));
        let d = register(&mut [&mut a], &text);
        let psbt = musig_psbt(&d, &[0]);

        let status = musig_status(&psbt, &d).unwrap();
        assert_eq!(status.round, MusigRound::NotMusig);
        assert!(status.cosigners.is_empty());
    }

    #[test]
    fn forged_script_origins_get_no_signature() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);

        let secp = Secp256k1::new();
        let random_key = || {
            SecretKey::new(&mut miniscript::bitcoin::secp256k1::rand::thread_rng())
                .x_only_public_key(&secp)
                .0
        };
        let foreign_leaf = TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        let participant_path = DerivationPath::from_str(COSIGNER_PATH).unwrap();
        let plain_path = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();
        let participant_key = participant(&a).x_only_public_key().0;
        let forged = [
            (random_key(), participant_path.clone()),
            (participant_key, participant_path),
            (random_key(), plain_path),
        ];
        for (key, path) in forged {
            psbt.inputs[0]
                .tap_key_origins
                .insert(key, (vec![foreign_leaf], (a.fingerprint(), path)));
        }

        a.inner_sign(&mut psbt, &d).unwrap();

        assert!(psbt.inputs[0].tap_script_sigs.is_empty());
        assert_eq!(partial_sig_count(&psbt), 1);
    }

    #[test]
    fn forged_key_path_gets_no_signature() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let text = format!(
            "tr(musig({}/<0;1>/*,{}/<0;1>/*))",
            cosigner(&a),
            cosigner(&b)
        );
        let d = register(&mut [&mut a, &mut b], &text);
        let mut psbt = musig_psbt(&d, &[0]);

        let path = DerivationPath::from_str(&format!("{COSIGNER_PATH}/0/0")).unwrap();
        let participant_key = a.public_key_at(&path).x_only_public_key().0;
        let input = &mut psbt.inputs[0];
        input.unknown.clear();
        input.tap_scripts.clear();
        input.tap_merkle_root = None;
        input.tap_internal_key = Some(participant_key);
        input.tap_key_origins = [(participant_key, (vec![], (a.fingerprint(), path)))]
            .into_iter()
            .collect();

        assert_eq!(a.inner_sign(&mut psbt, &d), Err(Error::SigningInfo));
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    /// `tr(plain(signer)/<0;1>/*)`, an account apart from the musig() one.
    fn plain_account(signers: &mut [&mut HotSigner]) -> (Descriptor, WalletDescriptor) {
        let text = format!("tr({}/<0;1>/*)", plain(signers[0]));
        let descriptor = Descriptor::from_str(&text).unwrap();
        let wallet = register(signers, &text);
        (descriptor, wallet)
    }

    /// Adds `participant(a)` at the cosigner path, for a leaf and as the
    /// internal key, on a copy of `psbt` each.
    fn forge_participant(psbt: &Psbt, a: &HotSigner) -> [Psbt; 2] {
        let participant_key = participant(a).x_only_public_key().0;
        let origin = (
            a.fingerprint(),
            DerivationPath::from_str(COSIGNER_PATH).unwrap(),
        );
        let foreign_leaf = TapLeafHash::from_script(&ScriptBuf::new(), LeafVersion::TapScript);
        let mut script_path = psbt.clone();
        script_path.inputs[0]
            .tap_key_origins
            .insert(participant_key, (vec![foreign_leaf], origin.clone()));
        let mut key_path = psbt.clone();
        let input = &mut key_path.inputs[0];
        input.tap_internal_key = Some(participant_key);
        input.tap_key_origins = [(participant_key, (vec![], origin))].into_iter().collect();
        [script_path, key_path]
    }

    fn assert_no_participant_sig(script_path: &Psbt, key_path: &Psbt, a: &HotSigner) {
        let participant_key = participant(a).x_only_public_key().0;
        assert!(script_path.inputs[0]
            .tap_script_sigs
            .keys()
            .all(|(key, _)| *key != participant_key));
        assert!(key_path.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn participant_origin_on_another_account_gets_no_signature() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        two_of_two(&mut a, &mut b);
        let (plain_descriptor, plain_wallet) = plain_account(&mut [&mut a]);
        let [mut script_path, mut key_path] =
            forge_participant(&musig_psbt(&plain_wallet, &[0]), &a);

        a.sign(&mut script_path);
        a.sign(&mut key_path);
        assert_no_participant_sig(&script_path, &key_path, &a);

        let (sender, receiver) = channel::unbounded();
        a.init(sender);
        let [script_path, key_path] = forge_participant(&musig_psbt(&plain_wallet, &[0]), &a);
        let mut signed = Vec::new();
        for psbt in [script_path, key_path] {
            a.sign_with_descriptor(psbt.clone(), plain_descriptor.clone());
            signed.push(match receiver.try_iter().last().unwrap() {
                SignerNotif::Signed(_, psbt) => psbt,
                SignerNotif::Error(_, _) => psbt,
                _ => panic!("expected Signed or Error"),
            });
        }
        assert_no_participant_sig(&signed[0], &signed[1], &a);
    }

    /// The last notification of `signer.register_descriptor(text)`.
    fn register_notif(
        signer: &mut HotSigner,
        receiver: &channel::Receiver<SignerNotif>,
        text: &str,
    ) -> SignerNotif {
        signer.register_descriptor(Descriptor::from_str(text).unwrap());
        receiver.try_iter().last().unwrap()
    }

    #[test]
    fn plain_reuse_of_a_participant_key_is_refused() {
        let [mut a, b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let (sender, receiver) = channel::unbounded();
        a.init(sender);
        let musig_text = format!(
            "tr(musig({}/<0;1>/*,{}/<0;1>/*))",
            cosigner(&a),
            cosigner(&b)
        );
        let plain_text = format!("tr({}/<0;1>/*)", cosigner(&a));
        let below_text = format!("tr({}/<1024;1025>/*)", cosigner(&a));

        for (first, second) in [(&musig_text, &plain_text), (&plain_text, &musig_text)] {
            let mut signer = a.clone();
            assert!(matches!(
                register_notif(&mut signer, &receiver, first),
                SignerNotif::DescriptorRegistered(_, _, true)
            ));
            assert!(matches!(
                register_notif(&mut signer, &receiver, second),
                SignerNotif::Error(_, Error::MusigParticipantReuse)
            ));
            assert_eq!(signer.descriptors().len(), 1);
        }

        let bare_text = format!("tr(musig({},{})/<0;1>/*)", cosigner(&a), cosigner(&b));
        assert!(matches!(
            register_notif(&mut a, &receiver, &bare_text),
            SignerNotif::DescriptorRegistered(_, _, true)
        ));
        assert!(matches!(
            register_notif(&mut a, &receiver, &below_text),
            SignerNotif::DescriptorRegistered(_, _, true)
        ));
    }

    #[test]
    fn recovery_leaf_under_a_participant_xpub_signs() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let text = format!(
            "tr(musig({},{})/<512;513>/*,and_v(v:pk({}/<1024;1025>/*),older(144)))",
            cosigner(&a),
            cosigner(&b),
            cosigner(&a)
        );
        let d = register(&mut [&mut a, &mut b], &text);
        let mut psbt = musig_psbt(&d, &[0]);
        let recovery_leaf = leaf_hash(&d, 0, 0);
        keep_leaf(&mut psbt, recovery_leaf);
        psbt.inputs[0].unknown.clear();
        let participant_key = participant(&a).x_only_public_key().0;
        psbt.inputs[0].tap_key_origins.insert(
            participant_key,
            (
                vec![recovery_leaf],
                (
                    a.fingerprint(),
                    DerivationPath::from_str(COSIGNER_PATH).unwrap(),
                ),
            ),
        );

        a.inner_sign(&mut psbt, &d).unwrap();

        let recovery_key = a
            .public_key_at(&DerivationPath::from_str(&format!("{COSIGNER_PATH}/1024/0")).unwrap())
            .x_only_public_key()
            .0;
        let sigs = &psbt.inputs[0].tap_script_sigs;
        assert_eq!(sigs.len(), 1);
        assert!(sigs.contains_key(&(recovery_key, recovery_leaf)));
    }

    #[test]
    fn ordinary_error_in_round_two_keeps_the_session() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        both_round_one(&mut psbt, &d, &a, &b);

        let mut mixed = psbt.clone();
        mixed.inputs[0].bip32_derivation.insert(
            participant(&a),
            (
                a.fingerprint(),
                DerivationPath::from_str(COSIGNER_PATH).unwrap(),
            ),
        );
        assert_eq!(a.inner_sign(&mut mixed, &d), Err(Error::MixedSigningInfo));
        assert_eq!(partial_sig_count(&mixed), 0);
        assert_eq!(a.musig_sessions().len(), 1);

        a.inner_sign(&mut psbt, &d).unwrap();
        assert_eq!(partial_sig_count(&psbt), 1);
    }

    #[test]
    fn round_one_replaces_the_wallet_session() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut first = musig_psbt(&d, &[0]);
        let mut second = musig_psbt(&d, &[1]);
        both_round_one(&mut first, &d, &a, &b);
        a.inner_sign(&mut second, &d).unwrap();
        assert_eq!(a.musig_sessions().len(), 1);

        assert_eq!(a.inner_sign(&mut first, &d), Err(Error::MusigSession));
        assert!(a.musig_sessions().is_empty());
        assert_eq!(partial_sig_count(&first), 0);
    }

    #[test]
    fn session_store_debug_hides_nonces() {
        let [mut a, mut b]: [HotSigner; 2] = musig_signers(2).try_into().unwrap();
        let d = two_of_two(&mut a, &mut b);
        let mut psbt = musig_psbt(&d, &[0]);
        a.inner_sign(&mut psbt, &d).unwrap();

        let nonce = musig_input_pub_nonces(&psbt.inputs[0]).unwrap()[0].nonce;
        let printed = format!("{:?}", a.musig_sessions());
        assert_eq!(printed, "MusigSessionStore { sessions: 1 }");
        assert!(!printed.contains(&nonce.to_lower_hex_string()));
        assert!(!format!("{a:?}").contains(&nonce.to_lower_hex_string()));
    }
}
