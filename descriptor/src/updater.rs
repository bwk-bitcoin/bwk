//! Fills PSBT inputs and outputs from a definite descriptor: miniscript's updater,
//! then under `musig` BIP-373 participants (in 0x1a, out 0x08) and every cosigner's
//! tap_key_origins with the aggregate's leaf hashes, as Bitcoin Core does.

#[cfg(feature = "musig")]
use std::collections::BTreeMap;

#[cfg(feature = "musig")]
use bwk_keys::musig::{DefiniteMusigAggregate, DefiniteMusigKey};
#[cfg(feature = "musig")]
use bwk_psbt::musig::{set_musig_input_participants, set_musig_output_participants};
use miniscript::{bitcoin::Psbt, psbt::PsbtExt};
#[cfg(feature = "musig")]
use miniscript::{
    bitcoin::{
        bip32::KeySource,
        psbt::{Input, Output},
        secp256k1::{Secp256k1, VerifyOnly, XOnlyPublicKey},
        taproot::{LeafVersion, TapLeafHash},
    },
    translate_hash_clone, DefiniteDescriptorKey, Descriptor, TranslateErr, TranslatePk, Translator,
};

#[cfg(feature = "musig")]
use crate::musig::DefiniteMusigDescriptor;
use crate::wallet::WalletDefiniteDescriptor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("miniscript update failed: {0}")]
    Miniscript(String),
    #[error("musig2 field: {0}")]
    Musig(String),
}

#[cfg(not(feature = "musig"))]
pub fn update_input(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    psbt.update_input_with_descriptor(index, descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(feature = "musig")]
pub fn update_input(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    let plain = to_plain_definite(descriptor)?;
    psbt.update_input_with_descriptor(index, &plain)
        .map_err(|e| Error::Miniscript(e.to_string()))?;
    add_musig_fields(&mut psbt.inputs[index], descriptor)
}

#[cfg(not(feature = "musig"))]
pub fn update_output(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    psbt.update_output_with_descriptor(index, descriptor)
        .map_err(|e| Error::Miniscript(e.to_string()))
}

#[cfg(feature = "musig")]
pub fn update_output(
    psbt: &mut Psbt,
    index: usize,
    descriptor: &WalletDefiniteDescriptor,
) -> Result<(), Error> {
    let plain = to_plain_definite(descriptor)?;
    psbt.update_output_with_descriptor(index, &plain)
        .map_err(|e| Error::Miniscript(e.to_string()))?;
    add_musig_fields(&mut psbt.outputs[index], descriptor)
}

#[cfg(feature = "musig")]
struct ToPlainDefinite;

#[cfg(feature = "musig")]
impl Translator<DefiniteMusigKey, DefiniteDescriptorKey, Error> for ToPlainDefinite {
    fn pk(&mut self, pk: &DefiniteMusigKey) -> Result<DefiniteDescriptorKey, Error> {
        pk.to_plain_definite()
            .map_err(|e| Error::Musig(e.to_string()))
    }
    translate_hash_clone!(DefiniteMusigKey, DefiniteDescriptorKey, Error);
}

/// Every key through `DefiniteMusigKey::to_plain_definite`.
#[cfg(feature = "musig")]
pub fn to_plain_definite(
    descriptor: &DefiniteMusigDescriptor,
) -> Result<miniscript::Descriptor<miniscript::DefiniteDescriptorKey>, Error> {
    descriptor
        .translate_pk(&mut ToPlainDefinite)
        .map_err(|e| match e {
            TranslateErr::TranslatorErr(e) => e,
            TranslateErr::OuterError(e) => Error::Musig(e.to_string()),
        })
}

#[cfg(feature = "musig")]
type TapKeyOrigins = BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>;

/// What the MuSig2 walk writes, on a PSBT input (0x1a) or output (0x08).
#[cfg(feature = "musig")]
trait MusigFields {
    fn set_participants(&mut self, aggregate: &DefiniteMusigAggregate);
    fn tap_key_origins(&mut self) -> &mut TapKeyOrigins;
}

#[cfg(feature = "musig")]
impl MusigFields for Input {
    fn set_participants(&mut self, aggregate: &DefiniteMusigAggregate) {
        set_musig_input_participants(self, aggregate.aggregate(), aggregate.participants());
    }

    fn tap_key_origins(&mut self) -> &mut TapKeyOrigins {
        &mut self.tap_key_origins
    }
}

#[cfg(feature = "musig")]
impl MusigFields for Output {
    fn set_participants(&mut self, aggregate: &DefiniteMusigAggregate) {
        set_musig_output_participants(self, aggregate.aggregate(), aggregate.participants());
    }

    fn tap_key_origins(&mut self) -> &mut TapKeyOrigins {
        &mut self.tap_key_origins
    }
}

/// Every musig() key of a `tr()`: its participants, and each cosigner's origin
/// with the hashes of the leaves the aggregate sits in. Only `tr()` holds musig().
#[cfg(feature = "musig")]
fn add_musig_fields<F: MusigFields>(
    item: &mut F,
    descriptor: &DefiniteMusigDescriptor,
) -> Result<(), Error> {
    let Descriptor::Tr(tr) = descriptor else {
        return Ok(());
    };
    let secp = Secp256k1::verification_only();
    if let Some(aggregate) = tr.internal_key().as_musig() {
        item.set_participants(aggregate);
        add_cosigner_origins(item.tap_key_origins(), aggregate, None, &secp)?;
    }
    for (_depth, ms) in tr.iter_scripts() {
        let leaf_hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);
        for key in ms.iter_pk() {
            if let Some(aggregate) = key.as_musig() {
                item.set_participants(aggregate);
                add_cosigner_origins(item.tap_key_origins(), aggregate, Some(leaf_hash), &secp)?;
            }
        }
    }
    for (leaf_hashes, _) in item.tap_key_origins().values_mut() {
        leaf_hashes.sort();
        leaf_hashes.dedup();
    }
    Ok(())
}

/// Each cosigner's own origin, plus `leaf` when given. An entry already there keeps
/// its origin and gains `leaf`.
#[cfg(feature = "musig")]
fn add_cosigner_origins(
    origins: &mut TapKeyOrigins,
    aggregate: &DefiniteMusigAggregate,
    leaf: Option<TapLeafHash>,
    secp: &Secp256k1<VerifyOnly>,
) -> Result<(), Error> {
    for cosigner in aggregate.cosigners() {
        let key = cosigner
            .derive_public_key(secp)
            .map_err(|e| Error::Musig(e.to_string()))?
            .inner
            .x_only_public_key()
            .0;
        let path = cosigner
            .full_derivation_path()
            .ok_or_else(|| Error::Musig("cosigner has no single derivation path".into()))?;
        let (leaf_hashes, _) = origins
            .entry(key)
            .or_insert_with(|| (vec![], (cosigner.master_fingerprint(), path)));
        if let Some(leaf) = leaf {
            if !leaf_hashes.contains(&leaf) {
                leaf_hashes.push(leaf);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[cfg(feature = "musig")]
    use bwk_keys::musig::{DefiniteMusigAggregate, MusigKey};
    #[cfg(feature = "musig")]
    use bwk_psbt::musig::{
        musig_input_participants, musig_input_participants_all, musig_output_participants,
        MusigParticipants,
    };
    #[cfg(feature = "musig")]
    use miniscript::bitcoin::{
        bip32::{Fingerprint, KeySource},
        secp256k1::{PublicKey, XOnlyPublicKey},
        taproot::TapLeafHash,
    };
    use miniscript::{
        bitcoin::{
            absolute,
            bip32::{DerivationPath, Xpriv, Xpub},
            secp256k1::Secp256k1,
            transaction, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
            TxOut, Witness,
        },
        psbt::PsbtExt,
        DescriptorPublicKey,
    };

    use crate::{
        descriptor::Descriptor,
        updater::{update_input, update_output},
        wallet::{to_wallet, WalletDefiniteDescriptor, WalletDescriptorExt},
    };

    const XPUB: &str = "tpubDDxT9mkZzWwkKwpGT5fY6iiM9muYTPkTx6Eig8dpHR7TChuGGCWYAHVmpW1ciido5RiFWwjzYsF1GZHkEHg2nrYp3zNtx3QQRkznyLhQ77x";
    const ORIGIN_PATH: &str = "m/87'/1'/0'/2";

    /// A cosigner xpub at `ORIGIN_PATH`, written with its origin.
    struct TestKey {
        text: String,
        #[cfg(feature = "musig")]
        fingerprint: Fingerprint,
        #[cfg(feature = "musig")]
        key: PublicKey,
        #[cfg(feature = "musig")]
        xpub: Xpub,
    }

    #[cfg(feature = "musig")]
    impl TestKey {
        fn origin(&self) -> KeySource {
            (
                self.fingerprint,
                DerivationPath::from_str(ORIGIN_PATH).unwrap(),
            )
        }

        /// The key at `/<path>/<index>` below the xpub.
        fn child(&self, path: u32, index: u32) -> PublicKey {
            let steps = DerivationPath::from_str(&format!("m/{path}/{index}")).unwrap();
            self.xpub
                .derive_pub(&Secp256k1::new(), &steps)
                .unwrap()
                .public_key
        }

        /// The origin of `child(path, index)`, from the master.
        fn child_origin(&self, path: u32, index: u32) -> KeySource {
            (
                self.fingerprint,
                DerivationPath::from_str(&format!("{ORIGIN_PATH}/{path}/{index}")).unwrap(),
            )
        }
    }

    fn test_key(seed: u8) -> TestKey {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Testnet, &[seed; 64]).unwrap();
        let path = DerivationPath::from_str(ORIGIN_PATH).unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap());
        let fingerprint = master.fingerprint(&secp);
        TestKey {
            text: format!("[{fingerprint}/87'/1'/0'/2]{xpub}"),
            #[cfg(feature = "musig")]
            fingerprint,
            #[cfg(feature = "musig")]
            key: xpub.public_key,
            #[cfg(feature = "musig")]
            xpub,
        }
    }

    /// `text` through `Descriptor`, multipath element `path`, at `index`.
    fn derive(text: &str, path: usize, index: u32) -> WalletDefiniteDescriptor {
        Descriptor::from_str(text)
            .unwrap()
            .into_miniscript()
            .unwrap()
            .single_paths()
            .unwrap()[path]
            .derive_at(index)
            .unwrap()
    }

    fn psbt_paying(spk: ScriptBuf) -> Psbt {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spk.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: spk,
        });
        psbt
    }

    #[cfg(feature = "musig")]
    fn xonly(key: PublicKey) -> XOnlyPublicKey {
        key.x_only_public_key().0
    }

    /// KeySort: by the 33-byte compressed encoding.
    #[cfg(feature = "musig")]
    fn key_sorted(keys: &[PublicKey]) -> Vec<PublicKey> {
        let mut keys = keys.to_vec();
        keys.sort_by_key(PublicKey::serialize);
        keys
    }

    #[cfg(feature = "musig")]
    fn internal_aggregate(descriptor: &WalletDefiniteDescriptor) -> &DefiniteMusigAggregate {
        let miniscript::Descriptor::Tr(tr) = descriptor else {
            panic!("not a tr() descriptor");
        };
        tr.internal_key().as_musig().unwrap()
    }

    /// The musig() aggregate of each leaf, in leaf order.
    #[cfg(feature = "musig")]
    fn leaf_aggregates(descriptor: &WalletDefiniteDescriptor) -> Vec<DefiniteMusigAggregate> {
        let miniscript::Descriptor::Tr(tr) = descriptor else {
            panic!("not a tr() descriptor");
        };
        tr.iter_scripts()
            .flat_map(|(_, ms)| ms.iter_pk())
            .filter_map(|key| key.as_musig().cloned())
            .collect()
    }

    /// The synthetic xpub fingerprint of the internal musig() key, before derivation.
    #[cfg(feature = "musig")]
    fn synthetic_fingerprint(text: &str) -> Fingerprint {
        let descriptor = Descriptor::from_str(text)
            .unwrap()
            .into_miniscript()
            .unwrap();
        let miniscript::Descriptor::Tr(tr) = descriptor else {
            panic!("not a tr() descriptor");
        };
        let MusigKey::Musig(aggregate) = tr.internal_key() else {
            panic!("internal key is not musig()");
        };
        aggregate.synthetic_fingerprint().unwrap()
    }

    #[test]
    fn update_input_matches_miniscript() {
        let plain = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&format!(
            "wpkh([9d69155f/84h/1h/0h]{XPUB}/0/*)"
        ))
        .unwrap();
        let plain_definite = plain.at_derivation_index(3).unwrap();
        let definite = to_wallet(plain).derive_at(3).unwrap();
        let spk = plain_definite.script_pubkey();

        let mut expected = psbt_paying(spk.clone());
        expected
            .update_input_with_descriptor(0, &plain_definite)
            .unwrap();
        expected
            .update_output_with_descriptor(0, &plain_definite)
            .unwrap();

        let mut psbt = psbt_paying(spk);
        update_input(&mut psbt, 0, &definite).unwrap();
        update_output(&mut psbt, 0, &definite).unwrap();

        assert!(!psbt.inputs[0].bip32_derivation.is_empty());
        assert!(psbt.inputs[0].witness_script.is_none());
        assert_eq!(psbt.inputs[0], expected.inputs[0]);
        assert_eq!(psbt.outputs[0], expected.outputs[0]);
    }

    #[test]
    fn plain_descriptor_gets_no_musig_fields() {
        let k = test_key(1);
        for text in [
            format!("tr({}/<0;1>/*)", k.text),
            format!("wpkh({}/<0;1>/*)", k.text),
        ] {
            let plain = miniscript::Descriptor::<DescriptorPublicKey>::from_str(&text)
                .unwrap()
                .into_single_descriptors()
                .unwrap()[0]
                .at_derivation_index(2)
                .unwrap();
            let definite = derive(&text, 0, 2);
            let spk = plain.script_pubkey();
            assert_eq!(definite.script_pubkey(), spk);

            let mut expected = psbt_paying(spk.clone());
            expected.update_input_with_descriptor(0, &plain).unwrap();
            expected.update_output_with_descriptor(0, &plain).unwrap();

            let mut psbt = psbt_paying(spk);
            update_input(&mut psbt, 0, &definite).unwrap();
            update_output(&mut psbt, 0, &definite).unwrap();

            assert_eq!(psbt.inputs[0], expected.inputs[0]);
            assert_eq!(psbt.outputs[0], expected.outputs[0]);
            assert!(psbt.inputs[0].unknown.is_empty());
            assert!(psbt.outputs[0].unknown.is_empty());
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn musig_key_path_input_gets_participants_and_origins() {
        let (a, b) = (test_key(1), test_key(2));
        let text = format!("tr(musig({},{})/<0;1>/*)", a.text, b.text);
        let definite = derive(&text, 0, 3);
        let aggregate = internal_aggregate(&definite);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_input(&mut psbt, 0, &definite).unwrap();
        let input = &psbt.inputs[0];

        let participants = key_sorted(&[a.key, b.key]);
        assert_eq!(aggregate.participants(), participants);
        assert_eq!(input.tap_internal_key, Some(xonly(aggregate.key())));
        assert_eq!(
            musig_input_participants(input, aggregate.aggregate()).unwrap(),
            Some(participants)
        );
        assert_eq!(musig_input_participants_all(input).unwrap().len(), 1);
        assert_eq!(input.tap_key_origins.len(), 3);
        assert_eq!(
            input.tap_key_origins[&xonly(aggregate.key())],
            (
                vec![],
                (
                    synthetic_fingerprint(&text),
                    DerivationPath::from_str("m/0/3").unwrap()
                )
            )
        );
        for key in [&a, &b] {
            assert_eq!(
                input.tap_key_origins[&xonly(key.key)],
                (vec![], key.origin())
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn musig_leaf_input_carries_leaf_hash_on_cosigners() {
        let (a, b, c) = (test_key(1), test_key(2), test_key(3));
        let text = format!(
            "tr({}/<0;1>/*,pk(musig({},{})/<0;1>/*))",
            c.text, a.text, b.text
        );
        let definite = derive(&text, 0, 4);
        let aggregate = &leaf_aggregates(&definite)[0];

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_input(&mut psbt, 0, &definite).unwrap();
        let input = &psbt.inputs[0];

        assert_eq!(input.tap_scripts.len(), 1);
        let (script, version) = input.tap_scripts.values().next().unwrap();
        let leaf_hash = TapLeafHash::from_script(script, *version);

        for key in [&a, &b] {
            assert_eq!(
                input.tap_key_origins[&xonly(key.key)],
                (vec![leaf_hash], key.origin())
            );
        }
        assert_eq!(
            input.tap_key_origins[&xonly(aggregate.key())],
            (vec![leaf_hash], aggregate.origin().unwrap().clone())
        );
        let (c_leaves, (c_fingerprint, _)) =
            &input.tap_key_origins[&input.tap_internal_key.unwrap()];
        assert!(c_leaves.is_empty());
        assert_eq!(*c_fingerprint, c.fingerprint);
        assert_eq!(
            musig_input_participants_all(input).unwrap(),
            vec![MusigParticipants {
                aggregate: aggregate.aggregate(),
                participants: key_sorted(&[a.key, b.key]),
            }]
        );
    }

    #[cfg(feature = "musig")]
    #[test]
    fn two_of_three_leaves_merge_cosigner_leaf_hashes() {
        let (a, b, c, d) = (test_key(1), test_key(2), test_key(3), test_key(4));
        let text = format!(
            "tr({}/<0;1>/*,{{pk(musig({},{})/<0;1>/*),{{pk(musig({},{})/<0;1>/*),pk(musig({},{})/<0;1>/*)}}}})",
            d.text, a.text, b.text, a.text, c.text, b.text, c.text
        );
        let definite = derive(&text, 0, 5);
        let aggregates = leaf_aggregates(&definite);
        assert_eq!(aggregates.len(), 3);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_input(&mut psbt, 0, &definite).unwrap();
        let input = &psbt.inputs[0];

        // miniscript writes the leaf hash of each derived aggregate.
        let leaf_hashes: Vec<TapLeafHash> = aggregates
            .iter()
            .map(|aggregate| {
                let (leaves, _) = &input.tap_key_origins[&xonly(aggregate.key())];
                assert_eq!(leaves.len(), 1);
                leaves[0]
            })
            .collect();
        let (ab, ac, bc) = (leaf_hashes[0], leaf_hashes[1], leaf_hashes[2]);
        assert!(ab != ac && ab != bc && ac != bc);

        let mut expected: Vec<MusigParticipants> = aggregates
            .iter()
            .map(|aggregate| MusigParticipants {
                aggregate: aggregate.aggregate(),
                participants: aggregate.participants().to_vec(),
            })
            .collect();
        expected.sort_by_key(|p| p.aggregate.serialize());
        let mut all = musig_input_participants_all(input).unwrap();
        all.sort_by_key(|p| p.aggregate.serialize());
        assert_eq!(all, expected);
        assert!(all[0].aggregate != all[1].aggregate && all[1].aggregate != all[2].aggregate);

        let sorted = |mut hashes: Vec<TapLeafHash>| {
            hashes.sort();
            hashes
        };
        for (key, leaves) in [
            (&a, sorted(vec![ab, ac])),
            (&b, sorted(vec![ab, bc])),
            (&c, sorted(vec![ac, bc])),
        ] {
            assert_eq!(
                input.tap_key_origins[&xonly(key.key)],
                (leaves, key.origin())
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn musig_output_gets_participants() {
        let (a, b) = (test_key(1), test_key(2));
        let text = format!("tr(musig({},{})/<0;1>/*)", a.text, b.text);
        let definite = derive(&text, 1, 1);
        let aggregate = internal_aggregate(&definite);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_output(&mut psbt, 0, &definite).unwrap();
        let output = &psbt.outputs[0];

        assert_eq!(
            musig_output_participants(output).unwrap(),
            vec![MusigParticipants {
                aggregate: aggregate.aggregate(),
                participants: key_sorted(&[a.key, b.key]),
            }]
        );
        assert_eq!(output.tap_internal_key, Some(xonly(aggregate.key())));
        assert_eq!(
            output.tap_key_origins[&xonly(aggregate.key())],
            (
                vec![],
                (
                    synthetic_fingerprint(&text),
                    DerivationPath::from_str("m/1/1").unwrap()
                )
            )
        );
        for key in [&a, &b] {
            assert_eq!(
                output.tap_key_origins[&xonly(key.key)],
                (vec![], key.origin())
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn derive_then_aggregate_input_gets_derived_cosigners() {
        let (a, b) = (test_key(1), test_key(2));
        let text = format!("tr(musig({}/<0;1>/*,{}/<0;1>/*))", a.text, b.text);
        let definite = derive(&text, 0, 7);
        let aggregate = internal_aggregate(&definite);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_input(&mut psbt, 0, &definite).unwrap();
        let input = &psbt.inputs[0];

        let participants = key_sorted(&[a.child(0, 7), b.child(0, 7)]);
        assert_eq!(aggregate.participants(), participants);
        assert_eq!(input.tap_internal_key, Some(xonly(aggregate.key())));
        assert_eq!(
            musig_input_participants_all(input).unwrap(),
            vec![MusigParticipants {
                aggregate: aggregate.aggregate(),
                participants,
            }]
        );
        for key in [&a, &b] {
            assert_eq!(
                input.tap_key_origins[&xonly(key.child(0, 7))],
                (vec![], key.child_origin(0, 7))
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn derive_then_aggregate_output_gets_derived_cosigners() {
        let (a, b) = (test_key(1), test_key(2));
        let text = format!("tr(musig({}/<0;1>/*,{}/<0;1>/*))", a.text, b.text);
        let definite = derive(&text, 1, 2);
        let aggregate = internal_aggregate(&definite);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_output(&mut psbt, 0, &definite).unwrap();
        let output = &psbt.outputs[0];

        assert_eq!(
            musig_output_participants(output).unwrap(),
            vec![MusigParticipants {
                aggregate: aggregate.aggregate(),
                participants: key_sorted(&[a.child(1, 2), b.child(1, 2)]),
            }]
        );
        for key in [&a, &b] {
            assert_eq!(
                output.tap_key_origins[&xonly(key.child(1, 2))],
                (vec![], key.child_origin(1, 2))
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn updater_is_idempotent() {
        let (a, b, c) = (test_key(1), test_key(2), test_key(3));
        let text = format!(
            "tr(musig({},{})/<0;1>/*,pk(musig({},{})/<0;1>/*))",
            a.text, b.text, a.text, c.text
        );
        let definite = derive(&text, 0, 6);

        let mut psbt = psbt_paying(definite.script_pubkey());
        update_input(&mut psbt, 0, &definite).unwrap();
        let once = psbt.inputs[0].clone();
        update_input(&mut psbt, 0, &definite).unwrap();

        assert_eq!(psbt.inputs[0], once);
        assert_eq!(musig_input_participants_all(&once).unwrap().len(), 2);
        assert_eq!(once.tap_key_origins[&xonly(a.key)].0.len(), 1);
    }
}
