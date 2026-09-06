//! The receiving component of silent payments.
//!
//! For receiving, we use the [`Receiver`] struct.
//! This struct does not contain any private key information,
//! so as to avoid having access to secret data.
//!
//! After creating a [`Receiver`] object, you can call [`scan_transaction`](Receiver::scan_transaction),
//! to scan a specific transaction for outputs belonging to this receiver.
//! For this, you need to have calculated the `ecdh_shared_secret` beforehand.
//! To do so, you can use [`calculate_ecdh_shared_secret`](`crate::core::receiving::calculate_ecdh_shared_secret`) from the `utils` module.
//!
//! For a concrete example, have a look at the [test vectors](https://github.com/cygnet3/rust-silentpayments/blob/master/tests/vector_tests.rs).
//!
//! Source: adapted from SPDK's vendored `silentpayments` implementation,
//! originally imported from cygnet3/rust-silentpayments. See `sp/NOTICE`.
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

use crate::core::{
    error::Error,
    secp256k1::{
        ecdh::shared_secret_point, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
    },
    utils::{
        common::{calculate_P_n, calculate_t_n, Network, SilentPaymentAddress},
        hash::{calculate_input_hash, LabelHash},
    },
    SharedSecret, SpVersion,
};
use bitcoin::{
    hashes::{hash160, Hash},
    OutPoint, ScriptBuf, TxIn, TxOut,
};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{SerializeStruct, SerializeTuple},
    Deserialize, Deserializer, Serialize,
};

/// Calculate a transaction's BIP352 tweak data from its eligible input keys.
pub fn calculate_tweak_data(
    input_pubkeys: &[&PublicKey],
    outpoints: &[OutPoint],
) -> Result<PublicKey, Error> {
    let secp = Secp256k1::verification_only();
    let input_sum = PublicKey::combine_keys(input_pubkeys)?;
    let input_hash = calculate_input_hash(outpoints, input_sum)?;
    Ok(input_sum.mul_tweak(&secp, &input_hash)?)
}

fn compressed_pubkey(bytes: &[u8], key_hash: &[u8]) -> Option<PublicKey> {
    if bytes.len() != 33 || hash160::Hash::hash(bytes).as_byte_array() != key_hash {
        return None;
    }
    PublicKey::from_slice(bytes).ok()
}

/// Extract a BIP352-eligible public key from a finalized transaction input.
pub fn eligible_input_pubkey(input: &TxIn, prevout: &TxOut) -> Result<Option<PublicKey>, Error> {
    let spk = prevout.script_pubkey.as_bytes();
    let script_sig = input.script_sig.as_bytes();
    let witness: Vec<_> = input.witness.iter().collect();

    if prevout.script_pubkey.is_p2pkh() {
        if !witness.is_empty() || script_sig.is_empty() {
            return Err(Error::InvalidInput("invalid P2PKH spend".to_string()));
        }
        return Ok(script_sig
            .windows(33)
            .rev()
            .find_map(|bytes| compressed_pubkey(bytes, &spk[3..23])));
    }

    if prevout.script_pubkey.is_p2sh() {
        if script_sig.len() != 23 || script_sig[0] != 22 {
            return Ok(None);
        }
        let redeem_script = &script_sig[1..];
        if !ScriptBuf::from_bytes(redeem_script.to_vec()).is_p2wpkh()
            || hash160::Hash::hash(redeem_script).as_byte_array() != &spk[2..22]
        {
            return Ok(None);
        }
        let pubkey = witness
            .last()
            .and_then(|bytes| compressed_pubkey(bytes, &redeem_script[2..22]));
        return pubkey
            .map(Some)
            .ok_or_else(|| Error::InvalidInput("invalid P2SH-P2WPKH spend".to_string()));
    }

    if prevout.script_pubkey.is_p2wpkh() {
        if !script_sig.is_empty() {
            return Err(Error::InvalidInput(
                "non-empty P2WPKH scriptSig".to_string(),
            ));
        }
        let pubkey = witness
            .last()
            .and_then(|bytes| compressed_pubkey(bytes, &spk[2..22]));
        return pubkey
            .map(Some)
            .ok_or_else(|| Error::InvalidInput("invalid P2WPKH spend".to_string()));
    }

    if prevout.script_pubkey.is_p2tr() {
        if !script_sig.is_empty() {
            return Err(Error::InvalidInput("non-empty P2TR scriptSig".to_string()));
        }
        let has_annex = witness
            .last()
            .and_then(|item| item.first())
            .is_some_and(|byte| *byte == 0x50);
        let stack_len = witness.len() - usize::from(has_annex);
        if stack_len == 0 {
            return Err(Error::InvalidInput("empty P2TR witness".to_string()));
        }
        if stack_len != 1 {
            return Ok(None);
        }
        let xonly = XOnlyPublicKey::from_slice(&spk[2..34])?;
        return Ok(Some(PublicKey::from_x_only_public_key(xonly, Parity::Even)));
    }

    Ok(None)
}

/// A Silent payment receiving label.
#[derive(Eq, PartialEq, Clone)]
pub struct Label {
    s: Scalar,
}

impl Label {
    pub fn new(b_scan: SecretKey, m: u32) -> Label {
        Label {
            s: LabelHash::from_b_scan_and_m(b_scan, m).to_scalar(),
        }
    }

    pub fn as_inner(&self) -> &Scalar {
        &self.s
    }

    pub fn as_string(&self) -> String {
        hex::encode(self.as_inner().to_be_bytes())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl std::hash::Hash for Label {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = self.s.to_be_bytes();
        bytes.hash(state);
    }
}

impl From<Scalar> for Label {
    fn from(s: Scalar) -> Self {
        Label { s }
    }
}

impl TryFrom<String> for Label {
    type Error = Error;

    fn try_from(s: String) -> Result<Label, Self::Error> {
        Label::try_from(&s[..])
    }
}

impl TryFrom<&str> for Label {
    type Error = Error;

    fn try_from(s: &str) -> Result<Label, Self::Error> {
        // Is it valid hex?
        let bytes = hex::decode(s)?;
        // Is it 32B long?
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::LabelLength)?;
        // Is it on the curve? If yes, push it on our labels list
        Ok(Label::from(Scalar::from_be_bytes(bytes)?))
    }
}

impl From<Label> for Scalar {
    fn from(l: Label) -> Self {
        l.s
    }
}

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.as_string())
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: String = String::deserialize(deserializer)?;
        value.try_into().map_err(serde::de::Error::custom)
    }
}

/// A struct representing a silent payment recipient.
///
/// It can be used to scan for transaction outputs belonging to us by using the [`scan_transaction`](Receiver::scan_transaction) function.
/// It optionally supports labels, which it manages internally.
/// Labels can be added with [`add_label`](Receiver::add_label).
#[derive(Debug, Clone, PartialEq)]
pub struct Receiver {
    version: SpVersion,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    change_label: Label, // To be able to tell which label is the change
    labels: BTreeMap<PublicKey, Label>,
    pub network: Network,
}

struct SerializablePubkey([u8; 33]);

struct SerializableLabels(BTreeMap<PublicKey, Label>);

impl Serialize for SerializablePubkey {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for element in self.0.iter() {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SerializablePubkey {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SerializablePubkeyVisitor;

        impl<'de> Visitor<'de> for SerializablePubkeyVisitor {
            type Value = SerializablePubkey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of 33 bytes")
            }

            fn visit_seq<V>(
                self,
                mut seq: V,
            ) -> std::prelude::v1::Result<SerializablePubkey, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut arr = [0u8; 33];
                #[allow(clippy::needless_range_loop)]
                for i in 0..33 {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(SerializablePubkey(arr))
            }
        }

        deserializer.deserialize_tuple(33, SerializablePubkeyVisitor)
    }
}

impl Serialize for SerializableLabels {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pairs: Vec<(Label, SerializablePubkey)> = self
            .0
            .iter()
            .map(|(pubkey, label)| (label.to_owned(), SerializablePubkey(pubkey.serialize())))
            .collect();
        // Now serialize `pairs` as a vector of tuples
        pairs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerializableLabels {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs: Vec<(Label, SerializablePubkey)> = Deserialize::deserialize(deserializer)?;
        let mut labels: BTreeMap<PublicKey, Label> = BTreeMap::new();
        for (label, ser_pubkey) in pairs {
            let pubkey = PublicKey::from_slice(&ser_pubkey.0).map_err(de::Error::custom)?;
            labels.insert(pubkey, label);
        }
        Ok(SerializableLabels(labels))
    }
}

impl Serialize for Receiver {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Receiver", 5)?;
        state.serialize_field("version", &self.version.as_u8())?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field(
            "scan_pubkey",
            &SerializablePubkey(self.scan_pubkey.serialize()),
        )?;
        state.serialize_field(
            "spend_pubkey",
            &SerializablePubkey(self.spend_pubkey.serialize()),
        )?;
        state.serialize_field("change_label", &self.change_label)?;
        state.serialize_field("labels", &SerializableLabels(self.labels.clone()))?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ReceiverHelper {
    version: u8,
    network: Network,
    scan_pubkey: SerializablePubkey,
    spend_pubkey: SerializablePubkey,
    change_label: String,
    labels: SerializableLabels,
}

impl<'de> Deserialize<'de> for Receiver {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = ReceiverHelper::deserialize(deserializer)?;
        Ok(Receiver {
            version: SpVersion::try_from(helper.version).map_err(de::Error::custom)?,
            network: helper.network,
            scan_pubkey: PublicKey::from_slice(&helper.scan_pubkey.0).map_err(de::Error::custom)?,
            spend_pubkey: PublicKey::from_slice(&helper.spend_pubkey.0)
                .map_err(de::Error::custom)?,
            change_label: Label::try_from(helper.change_label).map_err(de::Error::custom)?,
            labels: helper.labels.0,
        })
    }
}

impl Receiver {
    pub fn new(
        version: SpVersion,
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        change_label: Label,
        network: Network,
    ) -> Result<Self, Error> {
        let labels = BTreeMap::new();

        let mut receiver = Receiver {
            version,
            scan_pubkey,
            spend_pubkey,
            change_label: change_label.clone(),
            labels,
            network,
        };

        // This checks that the change_label produces a valid key at each step
        receiver.add_label(change_label)?;

        Ok(receiver)
    }

    /// Takes a [Label] and adds it to the list of labels that this recipient uses.
    /// Returns a bool on success, [true] if the label was new, [false] if it already existed in our list.
    pub fn add_label(&mut self, label: Label) -> Result<bool, Error> {
        let secp = Secp256k1::signing_only();

        let m = SecretKey::from_slice(&label.as_inner().to_be_bytes())?;
        let mG = m.public_key(&secp);

        // check that the combined key with spend_key is valid
        mG.combine(&self.spend_pubkey)?;

        let old = self.labels.insert(mG, label);

        Ok(old.is_none())
    }

    /// Get the silent payment change address for this Receiver. This is the
    /// static address associated with the change label, as described
    /// in the BIP. Wallets can create silent payment-native change addresses
    /// by sending to this static change address, much like sending to a normal
    /// silent payment address.
    /// Important note: this address should never be shown to the user!
    pub fn get_change_address(&self) -> SilentPaymentAddress {
        let sk = SecretKey::from_slice(&self.change_label.as_inner().to_be_bytes())
            .expect("Unexpected invalid change label");
        let pk = sk.public_key(&Secp256k1::signing_only());
        let B_m = pk
            .combine(&self.spend_pubkey)
            .expect("Unexpected invalid pubkey");
        self.get_silent_payment_address(B_m)
    }

    /// Get the default, no-label silent payment address.
    pub fn get_receiving_address(&self) -> SilentPaymentAddress {
        self.get_silent_payment_address(self.spend_pubkey)
    }

    /// Scans a transaction for outputs belonging to us.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` - The ECDH shared secret between sender and recipient.
    /// * `pubkeys_to_check` - A [HashSet] of public keys of all (unspent) taproot output of the transaction.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] of labels to a map of outputs to key tweaks (since the same label may have been paid multiple times in one transaction). The key tweaks can be added to the wallet's spending private key to produce a key that can spend the utxo. A resulting [HashMap] of length 0 implies none of the outputs are owned by us.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * One of the public keys to scan can't be parsed into a valid x-only public key.
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn scan_transaction(
        &self,
        ecdh_shared_secret: SharedSecret,
        pubkeys_to_check: &[XOnlyPublicKey],
    ) -> Result<HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>>, Error> {
        let secp = crate::core::secp256k1::Secp256k1::new();

        let mut found: HashMap<Option<Label>, HashMap<XOnlyPublicKey, Scalar>> = HashMap::new();
        let mut n_found: u32 = 0;
        let mut n: u32 = 0;
        while n_found == n {
            let t_n: SecretKey = calculate_t_n(ecdh_shared_secret.as_inner(), n)?;
            let P_n: PublicKey = calculate_P_n(&self.spend_pubkey, t_n.into())?;
            let P_n_xonly = P_n.x_only_public_key().0;
            if pubkeys_to_check.iter().any(|p| p.eq(&P_n_xonly)) {
                n_found += 1;
                found.entry(None).or_default().insert(P_n_xonly, t_n.into());
            } else {
                // We subtract P_n from each outputs to check and see if match a public key in our label list
                'outer: for p in pubkeys_to_check {
                    let even_output = p.public_key(Parity::Even);
                    let odd_output = p.public_key(Parity::Odd);
                    let even_diff = even_output.combine(&P_n.negate(&secp))?;
                    let odd_diff = odd_output.combine(&P_n.negate(&secp))?;

                    for diff in [even_diff, odd_diff] {
                        if let Some(label) = self.labels.get(&diff) {
                            n_found += 1;
                            let t_n_label = t_n.add_tweak(label.as_inner())?;
                            found
                                .entry(Some(label.clone()))
                                .or_default()
                                .insert(*p, t_n_label.into());
                            break 'outer;
                        }
                    }
                }
            }
            n += 1;
        }
        Ok(found)
    }

    /// Get the possible ScriptPubKeys from a transaction's tweak data.
    /// Using the tweak data, this function will calculate the resulting script, given the assumption that this transaction is a payment to us.
    /// This Script can be useful for BIP158 block filters.
    ///
    /// # Arguments
    ///
    /// * `ecdh_shared_secret` - The ECDH shared secret between sender and recipient.
    ///
    /// # Returns
    ///
    /// If successful, the function returns a [Result] wrapping a [HashMap] that maps an optional [Label] to a Script as a 34-byte vector. The script has the following format: `OP_PUSHNUM_1 OP_PUSHBYTES_32 taproot_output`
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///
    /// * An error occurs during elliptic curve computation. This may happen if a sender is being malicious.
    pub fn get_spks_from_shared_secret(
        &self,
        ecdh_shared_secret: SharedSecret,
    ) -> Result<HashMap<Option<Label>, [u8; 34]>, Error> {
        let t_0: SecretKey = calculate_t_n(ecdh_shared_secret.as_inner(), 0)?;
        let P_0: PublicKey = calculate_P_n(&self.spend_pubkey, t_0.into())?;
        let output_key_bytes = P_0.x_only_public_key().0.serialize();

        let mut res = HashMap::new();

        let mut spk = [0u8; 34];
        // hardcoded opcode values for OP_PUSHNUM_1 and OP_PUSHBYTES_32
        spk[..2].copy_from_slice(&[0x51, 0x20]);
        spk[2..].copy_from_slice(&output_key_bytes);

        res.insert(None, spk);

        for (mG, label) in &self.labels {
            let B_m = mG.combine(&self.spend_pubkey)?;
            let P_m0 = calculate_P_n(&B_m, t_0.into())?;
            let output_key_bytes = P_m0.x_only_public_key().0.serialize();

            let mut spk = [0u8; 34];
            spk[..2].copy_from_slice(&[0x51, 0x20]);
            spk[2..].copy_from_slice(&output_key_bytes);

            res.insert(Some(label.clone()), spk);
        }
        Ok(res)
    }

    /// The precomputed spend points whose `k = 0` outputs are this receiver's
    /// candidate spks: the unlabeled spend pubkey first, then one
    /// `label_point + spend_pubkey` per registered label. These are constant
    /// across tweaks, so a scanner computes them once and reuses them for every
    /// tweak. The order matches [`get_spks_from_shared_secret`]'s output values.
    pub fn candidate_spend_points(&self) -> Result<Vec<PublicKey>, Error> {
        let mut points = Vec::with_capacity(1 + self.labels.len());
        points.push(self.spend_pubkey);
        for mG in self.labels.keys() {
            points.push(mG.combine(&self.spend_pubkey)?);
        }
        Ok(points)
    }

    /// The candidate output spks for one tweak, derived in a single native call.
    ///
    /// This is the fast-path equivalent of taking the values of
    /// [`get_spks_from_shared_secret`]: given the tweak (combined tweak `T`), the
    /// scan key, and the receiver's precomputed `spend_points` (from
    /// [`candidate_spend_points`](Receiver::candidate_spend_points)), it returns
    /// one 34-byte p2tr spk (`0x51 0x20 || xonly`) per spend point. It does the
    /// ECDH, derives `t_0`, and computes `t_0 * G` once for the whole batch.
    ///
    /// It runs in variable time over the scan key and must only be used for
    /// recipient scanning.
    pub fn candidate_output_spks(
        &self,
        tweak: &[u8; 33],
        scan_key: &SecretKey,
        spend_points: &[PublicKey],
    ) -> Result<Vec<[u8; 34]>, Error> {
        // The tweak is handed raw to the byte-FFI kernel, which validates it; a
        // malformed tweak surfaces as a `MalformedPubkey` -> `Error::MalformedTweak`.
        let scan_key = scan_key.secret_bytes();
        let spend_points: Vec<[u8; 33]> = spend_points.iter().map(|p| p.serialize()).collect();
        let xonly = secp256k1_spscan_sys::scan_spend_points(&scan_key, tweak, &spend_points)?;
        Ok(xonly
            .into_iter()
            .map(|xonly_bytes| {
                let mut spk = [0u8; 34];
                // hardcoded opcode values for OP_PUSHNUM_1 and OP_PUSHBYTES_32
                spk[..2].copy_from_slice(&[0x51, 0x20]);
                spk[2..].copy_from_slice(&xonly_bytes);
                spk
            })
            .collect())
    }

    /// The candidate output spks for a batch of tweaks, derived in a single
    /// native call. Returns one flat vector of 34-byte p2tr spks
    /// (`0x51 0x20 || xonly`), row-major by tweak: the spk for tweak `t`, spend
    /// point `s` of `n_spend = spend_points.len()` is at index `t * n_spend + s`
    /// (tweaks in `tweaks` order, spend points in `spend_points` order). This is
    /// the byte-identical batched equivalent of calling
    /// [`candidate_output_spks`](Receiver::candidate_output_spks) once per tweak
    /// and concatenating; the native call phases the work so per-chunk field
    /// inversions are batched.
    ///
    /// It runs in variable time over the scan key and must only be used for
    /// recipient scanning.
    pub fn candidate_output_spks_batch(
        &self,
        tweaks: &[[u8; 33]],
        scan_key: &SecretKey,
        spend_points: &[PublicKey],
    ) -> Result<Vec<[u8; 34]>, Error> {
        // Tweaks are handed raw to the byte-FFI kernel, which validates them; a
        // malformed tweak surfaces as a `MalformedPubkey` -> `Error::MalformedTweak`.
        let scan_key = scan_key.secret_bytes();
        let spend_points: Vec<[u8; 33]> = spend_points.iter().map(|p| p.serialize()).collect();
        let xonly =
            secp256k1_spscan_sys::scan_spend_points_batch(&scan_key, tweaks, &spend_points)?;
        Ok(xonly
            .into_iter()
            .map(|xonly_bytes| {
                let mut spk = [0u8; 34];
                // hardcoded opcode values for OP_PUSHNUM_1 and OP_PUSHBYTES_32
                spk[..2].copy_from_slice(&[0x51, 0x20]);
                spk[2..].copy_from_slice(&xonly_bytes);
                spk
            })
            .collect())
    }

    fn get_silent_payment_address(&self, m_pubkey: PublicKey) -> SilentPaymentAddress {
        SilentPaymentAddress::new(self.scan_pubkey, m_pubkey, self.network, SpVersion::V0)
            .expect("version is supported")
    }
}

/// Calculate the shared secret of a transaction.
///
/// # Arguments
///
/// * `tweak_data` - The tweak data from the block index.
/// * `b_scan` - The scan private key used by the wallet.
///
/// # Returns
///
/// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See [`Receiver::scan_transaction`].
pub fn calculate_ecdh_shared_secret(tweak_data: &PublicKey, b_scan: &SecretKey) -> SharedSecret {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;

    // Constant-time ECDH multiply (mainline secp256k1). The output point is
    // byte-identical to the fork's vartime multiply; only timing differs. The
    // hot candidate-spk scan path uses secp256k1_spscan-sys (own vartime kernel); this
    // recovery path runs only on a filter match, so const time is fine here.
    ss_bytes[1..].copy_from_slice(&shared_secret_point(tweak_data, b_scan));

    PublicKey::from_slice(&ss_bytes)
        .expect("guaranteed to be a point on the curve")
        .into()
}

#[cfg(test)]
mod tests {
    use crate::core::{
        receiving::{Label, Receiver},
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        utils::common::Network,
        SpVersion,
    };

    #[test]
    fn string_to_label_success() {
        let s: String =
            "8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b".to_owned();
        Label::try_from(s).unwrap();
    }

    #[test]
    fn receiver_serializes_labels_as_pairs() {
        let secp = Secp256k1::new();
        let scan_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let spend_key = SecretKey::from_slice(&[2; 32]).unwrap();
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_key);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_key);

        let change_label = Label::new(scan_key, 0);
        let receiver = Receiver::new(
            SpVersion::V0,
            scan_pubkey,
            spend_pubkey,
            change_label,
            Network::Regtest,
        )
        .unwrap();

        let value = serde_json::to_value(&receiver).unwrap();

        assert_eq!(value["version"], 0);
        let labels = value["labels"].as_array().unwrap();
        let first = labels[0].as_array().unwrap();
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn deserialize_label() {
        let s: String =
            "\"8e4bbee712779f746337cadf39e8b1eab8e8869dd40f2e3a7281113e858ffc0b\"".to_owned();

        let label: Label = serde_json::from_str(&s).unwrap();

        let label_str = serde_json::to_string(&label).unwrap();

        assert_eq!(label_str, s);
    }

    // Byte-identical equivalence: the batched candidate primitive must produce
    // exactly the same spks as calling the per-tweak primitive once per tweak.
    #[test]
    fn candidate_output_spks_batch_matches_per_tweak() {
        use crate::core::{
            receiving::Receiver,
            secp256k1::{PublicKey, Secp256k1, SecretKey},
            utils::common::Network,
            SpVersion,
        };
        use bitcoin_hashes::{sha256, Hash};

        let secp = Secp256k1::new();
        // Deterministic distinct valid keys derived by hashing a domain + counter.
        let key = |domain: &str, i: usize| -> SecretKey {
            let h = sha256::Hash::hash(format!("{domain}-{i}").as_bytes());
            SecretKey::from_slice(h.as_byte_array()).expect("hash is a valid seckey")
        };

        let scan_key = key("scan", 0);
        let spend_key = key("spend", 0);
        let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_key);
        let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_key);

        let change_label = Label::new(scan_key, 0);
        let mut receiver = Receiver::new(
            SpVersion::V0,
            scan_pubkey,
            spend_pubkey,
            change_label,
            Network::Regtest,
        )
        .unwrap();
        // Register a couple of extra labels so there is more than one spend point.
        receiver.add_label(Label::new(scan_key, 1)).unwrap();
        receiver.add_label(Label::new(scan_key, 2)).unwrap();
        let spend_points = receiver.candidate_spend_points().unwrap();
        let n_spend = spend_points.len();
        assert!(n_spend > 1);

        // Several sizes, exercising the K-lane lockstep tail (counts that are not
        // a multiple of the lane count) and crossing the native tweak-chunk (32)
        // and candidate sub-chunk (64) boundaries.
        for n_tweaks in [1usize, 5, 6, 7, 13, 33, 64, 70, 100] {
            let tweaks: Vec<[u8; 33]> = (0..n_tweaks)
                .map(|i| PublicKey::from_secret_key(&secp, &key("tweak", i)).serialize())
                .collect();

            let batched = receiver
                .candidate_output_spks_batch(&tweaks, &scan_key, &spend_points)
                .unwrap();
            assert_eq!(batched.len(), n_tweaks * n_spend);

            for (t, tweak) in tweaks.iter().enumerate() {
                let per_tweak = receiver
                    .candidate_output_spks(tweak, &scan_key, &spend_points)
                    .unwrap();
                assert_eq!(
                    &batched[t * n_spend..(t + 1) * n_spend],
                    per_tweak.as_slice()
                );
            }
        }
    }

    #[test]
    fn string_to_label_failure() {
        // Invalid characters
        let s: String = "deadbeef?:{+!&".to_owned();
        Label::try_from(s).unwrap_err();
        // Invalid length
        let s: String = "deadbee".to_owned();
        Label::try_from(s).unwrap_err();
        // Not 32B
        let s: String = "deadbeef".to_owned();
        Label::try_from(s).unwrap_err();
    }
}
