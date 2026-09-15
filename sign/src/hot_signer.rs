use std::{collections::BTreeSet, str::FromStr};

use crossbeam::channel;

use crate::{
    error::Error,
    send,
    signer::{Signer, SignerNotif},
};
use bwk_descriptor::{derivator::SpkDerivator, tr, tr_path, wpkh, wpkh_path};
use bwk_keys::{
    derivator::KeyDerivator,
    keys::{OXpriv, OXpub},
};
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
        Descriptor, DescriptorPublicKey, ForEachKey,
    },
};

impl Signer for HotSigner {
    fn init(&mut self, channel: channel::Sender<SignerNotif>) {
        self.sender = Some(channel);
        self.info();
    }

    fn info(&self) {
        send!(self, Info(serde_json::Value::Null));
    }

    fn get_xpub(&self, deriv: DerivationPath, _display: bool) {
        let xpub = self.xpub(&deriv);
        send!(self, Xpub(xpub));
    }

    fn is_descriptor_registered(&self, descriptor: Descriptor<DescriptorPublicKey>) {
        let registered = self.descriptors.contains(&descriptor);
        send!(self, DescriptorRegistered(descriptor, registered));
    }

    fn register_descriptor(&mut self, descriptor: Descriptor<DescriptorPublicKey>) {
        let wrong_network = descriptor.for_any_key(|k| match k {
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
        if !wrong_network {
            self.descriptors.insert(descriptor.clone());
        }
        if wrong_network {
            send!(self, Error(Error::DescriptorNetwork));
        } else {
            send!(self, DescriptorRegistered(descriptor, true));
        };
    }

    fn sign_with_descriptor(&self, mut psbt: Psbt, descriptor: Descriptor<DescriptorPublicKey>) {
        if self.descriptors.contains(&descriptor) {
            if let Err(e) = self.inner_sign(&mut psbt, &descriptor) {
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
    descriptors: BTreeSet<Descriptor<DescriptorPublicKey>>,
    network: bitcoin::Network,
    sender: Option<channel::Sender<SignerNotif>>,
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
        signer.register_descriptor(descriptor);
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
        signer.register_descriptor(descriptor);
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
        })
    }

    /// Registers a descriptor for the signer.
    ///
    /// This function adds the given descriptor to the signer's internal set of
    /// descriptors if it is not already registered.
    ///
    /// # Arguments
    /// * `descriptor` - The descriptor to be registered.
    pub fn inner_register_descriptor(&mut self, descriptor: Descriptor<DescriptorPublicKey>) {
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

    /// Retrieves the private key at the specified derivation path from the master_xpriv.
    ///
    /// # Arguments
    /// * `path` - The derivation path for which to retrieve the private key.
    ///
    /// # Returns
    /// The private key as a [`secp256k1::SecretKey`].
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

    pub fn finalize(
        &self,
        psbt: &mut Psbt,
    ) -> Result<bitcoin::Transaction, Vec<miniscript::psbt::Error>> {
        PsbtExt::finalize_mut(psbt, self.secp())?;
        Ok(Psbt::extract_tx_unchecked_fee_rate(psbt.clone()))
    }

    pub fn inner_sign(
        &self,
        psbt: &mut Psbt,
        descriptor: &Descriptor<DescriptorPublicKey>,
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
                    match self.sign_input_taptree(psbt, index, &derivator, &mut cache) {
                        Ok(()) => signed_any = true,
                        Err(Error::SpkNotMatch) => continue,
                        Err(e) => return Err(e),
                    }
                }
                (false, true, true) => {
                    match self.sign_input_tapkey(psbt, index, &derivator, &mut cache) {
                        Ok(()) => {}
                        Err(Error::SpkNotMatch) => continue,
                        Err(e) => return Err(e),
                    }
                    match self.sign_input_taptree(psbt, index, &derivator, &mut cache) {
                        Ok(()) => {}
                        Err(Error::SpkNotMatch) => continue,
                        Err(e) => return Err(e),
                    }
                    signed_any = true;
                }
                (false, false, false) => continue,
                _ => {
                    unreachable!()
                }
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
                if *fg == self.fingerprint() {
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
                    let sk = self.private_key_at(der_path);
                    let keypair = secp256k1::Keypair::from_secret_key(self.secp(), &sk);
                    if keypair.x_only_public_key().0 != *int_key {
                        return Err(Error::InternalKeyNotMatch);
                    }
                    #[allow(deprecated)]
                    let keypair = keypair
                        .tap_tweak(self.secp(), input.tap_merkle_root)
                        .to_inner();
                    let sighash = cache
                        .taproot_key_spend_signature_hash(index, &prevouts, sighash_type)
                        .map_err(|_| Error::InsanePrevouts)?;
                    let sighash = secp256k1::Message::from_digest_slice(
                        &sighash.as_raw_hash().to_byte_array(),
                    )
                    .expect("Sighash is always 32 bytes.");
                    let signature = self.secp().sign_schnorr_no_aux_rand(&sighash, &keypair);
                    let sig = bitcoin::taproot::Signature {
                        signature,
                        sighash_type,
                    };
                    input.tap_key_sig = Some(sig);
                }
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
        for (pubkey, (leaf_hashes, (fg, der_path))) in &input.tap_key_origins {
            if *fg != self.fingerprint() {
                continue;
            }

            for leaf_hash in leaf_hashes {
                let sk = self.private_key_at(der_path);
                let keypair = secp256k1::Keypair::from_secret_key(self.secp(), &sk);
                let sighash = cache
                    .taproot_script_spend_signature_hash(index, &prevouts, *leaf_hash, sighash_type)
                    .map_err(|_| Error::InsaneTaptreeInfo)?;
                let sighash = secp256k1::Message::from_digest_slice(sighash.as_byte_array())
                    .expect("Sighash is always 32 bytes.");
                let signature = self.secp().sign_schnorr_no_aux_rand(&sighash, &keypair);
                let sig = bitcoin::taproot::Signature {
                    signature,
                    sighash_type,
                };
                input.tap_script_sigs.insert((*pubkey, *leaf_hash), sig);
            }
        }
        Ok(())
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

    pub fn descriptors(&self) -> Vec<Descriptor<DescriptorPublicKey>> {
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
            .find(|d| matches!(d, Descriptor::Tr(_)))
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
            .find(|d| matches!(d, Descriptor::Wpkh(_)))
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
    let sk = b_spend
        .add_tweak(&tweak_sk.into())
        .map_err(|_| Error::SpSigning)?;
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);

    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);

    let signature = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: hash_ty,
    };

    psbt.inputs[input_index].tap_key_sig = Some(signature);

    Ok(())
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
    use bwk_descriptor::{derivator::SpkDerivator, descriptor::wpkh};
    use bwk_utils::test::{random_output, setup_logger, txid};
    use crossbeam::channel;
    use miniscript::bitcoin::{absolute::Height, Amount, ScriptBuf, TxIn, Witness};

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
        let descriptor = wpkh(xpub);

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
        let descriptor = wpkh(signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/0").unwrap()));

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
        let descriptor = wpkh(signer.xpub(&derivation_path));

        signer.init(sender);
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Info(fg, _) => {
                assert_eq!(signer.fingerprint(), fg);
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

        signer.sign_with_descriptor(psbt, descriptor);
        let notif = mock.receiver.recv().unwrap();
        match notif {
            SignerNotif::Signed(fg, psbt) => {
                assert_eq!(signer.fingerprint(), fg);
                assert!(!psbt.inputs[0].partial_sigs.is_empty());
            }
            _ => panic!("Expected DescriptorRegistered notification"),
        }
    }
}
