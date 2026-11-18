//! Restricts a PSBT input filled by [`crate::updater::update_input`] to one spend
//! path of its tr() descriptor, before MuSig2 round 1.
//!
//! Every `tap_key_origins` entry stays, only the leaf hashes change: a Coldcard signs
//! an input only when its origins list every key of the wallet it enrolled (plain
//! keys, musig() aggregates and their participants).

use bwk_psbt::musig::PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS;
use miniscript::{
    bitcoin::{
        psbt::Input,
        secp256k1::PublicKey,
        taproot::{LeafVersion, TapLeafHash},
    },
    descriptor::Tr,
    Miniscript, Tap,
};

use crate::wallet::WalletDefiniteKey;

/// The key path of `tr` only: no leaf, every key origin with no leaf hash, and the
/// internal aggregate's 0x1a only.
pub fn restrict_input_to_key_path(input: &mut Input, tr: &Tr<WalletDefiniteKey>) {
    input.tap_scripts.clear();
    for (leaf_hashes, _) in input.tap_key_origins.values_mut() {
        leaf_hashes.clear();
    }
    keep_participants(
        input,
        tr.internal_key().as_musig().map(|agg| agg.aggregate()),
    );
}

/// The leaf `ms` only: its script, the 0x1a of its aggregates, and every key origin,
/// with the leaf's hash on its keys and no hash on the others.
pub fn restrict_input_to_leaf(input: &mut Input, ms: &Miniscript<WalletDefiniteKey, Tap>) {
    let hash = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);
    input
        .tap_scripts
        .retain(|_, (script, version)| TapLeafHash::from_script(script, *version) == hash);
    for (leaf_hashes, _) in input.tap_key_origins.values_mut() {
        leaf_hashes.retain(|leaf| *leaf == hash);
    }
    keep_participants(
        input,
        ms.iter_pk()
            .filter_map(|key| key.as_musig().map(|agg| agg.aggregate())),
    );
}

/// Drops every 0x1a entry whose aggregate is not one of `aggregates`.
fn keep_participants(input: &mut Input, aggregates: impl IntoIterator<Item = PublicKey>) {
    let kept: Vec<[u8; 33]> = aggregates
        .into_iter()
        .map(|aggregate| aggregate.serialize())
        .collect();
    input.unknown.retain(|key, _| {
        key.type_value != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS
            || kept.iter().any(|aggregate| key.key == aggregate[..])
    });
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr};

    use bwk_psbt::musig::musig_input_participants_all;
    use miniscript::{
        bitcoin::{
            absolute,
            bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
            psbt::Input,
            secp256k1::Secp256k1,
            taproot::{LeafVersion, TapLeafHash},
            transaction, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn,
            TxOut, Witness,
        },
        descriptor::Tr,
        Descriptor as MsDescriptor,
    };

    use crate::{
        descriptor::Descriptor,
        restrict::{restrict_input_to_key_path, restrict_input_to_leaf},
        updater::update_input,
        wallet::{WalletDefiniteKey, WalletDescriptorExt},
    };

    /// `[fp/87'/1'/0'/2]tpub` of the master of seed `byte`, and its fingerprint.
    fn key(byte: u8) -> (String, Fingerprint) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Testnet, &[byte; 64]).unwrap();
        let path = DerivationPath::from_str("m/87'/1'/0'/2").unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap());
        let fingerprint = master.fingerprint(&secp);
        (format!("[{fingerprint}/87'/1'/0'/2]{xpub}"), fingerprint)
    }

    /// The input spending receive index 0 of `text` as bwk's updater fills it, and
    /// that derived tr().
    fn input(text: &str) -> (Input, Tr<WalletDefiniteKey>) {
        let definite = Descriptor::from_str(text)
            .unwrap()
            .into_miniscript()
            .unwrap()
            .single_paths()
            .unwrap()[0]
            .derive_at(0)
            .unwrap();
        let spk = definite.script_pubkey();
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: spk,
        });
        update_input(&mut psbt, 0, &definite).unwrap();
        let MsDescriptor::Tr(tr) = definite else {
            panic!("expected tr()");
        };
        (psbt.inputs.remove(0), tr)
    }

    /// The fingerprints of the origins of `input` that list `leaf`, and of those
    /// with no leaf hash.
    fn origins_by_leaf(
        input: &Input,
        leaf: Option<TapLeafHash>,
    ) -> (BTreeSet<Fingerprint>, BTreeSet<Fingerprint>) {
        let mut with_leaf = BTreeSet::new();
        let mut without = BTreeSet::new();
        for (leaf_hashes, (fingerprint, _)) in input.tap_key_origins.values() {
            match leaf_hashes.as_slice() {
                [] => {
                    without.insert(*fingerprint);
                }
                [hash] if Some(*hash) == leaf => {
                    with_leaf.insert(*fingerprint);
                }
                other => panic!("unexpected leaf hashes {other:?}"),
            }
        }
        (with_leaf, without)
    }

    /// `tr(D,{pk(musig(A,B)),pk(musig(A,C))})`.
    fn two_leaves() -> (String, [Fingerprint; 4]) {
        let [(a, fa), (b, fb), (c, fc), (d, fd)] = [1, 2, 3, 4].map(key);
        let text =
            format!("tr({d}/<0;1>/*,{{pk(musig({a},{b})/<0;1>/*),pk(musig({a},{c})/<0;1>/*)}})");
        (text, [fa, fb, fc, fd])
    }

    #[test]
    fn leaf_keeps_every_origin() {
        let (text, [a, b, c, d]) = two_leaves();
        let (mut input, tr) = input(&text);
        let before = input.clone();
        assert_eq!(input.tap_scripts.len(), 2);
        assert_eq!(musig_input_participants_all(&input).unwrap().len(), 2);
        let (_, ms) = tr.iter_scripts().next().unwrap();
        let leaf = TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript);

        restrict_input_to_leaf(&mut input, ms);

        let kept: Vec<_> = input
            .tap_scripts
            .values()
            .map(|(script, version)| TapLeafHash::from_script(script, *version))
            .collect();
        assert_eq!(kept, vec![leaf]);
        assert_eq!(
            input.tap_key_origins.keys().collect::<Vec<_>>(),
            before.tap_key_origins.keys().collect::<Vec<_>>()
        );
        let (with_leaf, without) = origins_by_leaf(&input, Some(leaf));
        assert!(with_leaf.contains(&a) && with_leaf.contains(&b));
        assert!(without.contains(&c) && without.contains(&d));
        assert!(!with_leaf.contains(&c) && !with_leaf.contains(&d));
        let participants = musig_input_participants_all(&input).unwrap();
        assert_eq!(participants.len(), 1);
        assert_eq!(
            participants[0].aggregate,
            ms.iter_pk()
                .find_map(|k| k.as_musig().cloned())
                .unwrap()
                .aggregate()
        );
    }

    #[test]
    fn key_path_keeps_every_origin_without_leaf_hashes() {
        let (text, _) = two_leaves();
        let (mut input, tr) = input(&text);
        let before = input.clone();

        restrict_input_to_key_path(&mut input, &tr);

        assert!(input.tap_scripts.is_empty());
        assert_eq!(
            input.tap_key_origins.keys().collect::<Vec<_>>(),
            before.tap_key_origins.keys().collect::<Vec<_>>()
        );
        assert!(input
            .tap_key_origins
            .values()
            .all(|(leaf_hashes, _)| leaf_hashes.is_empty()));
        // D is plain: no aggregate left
        assert!(musig_input_participants_all(&input).unwrap().is_empty());
    }

    #[test]
    fn musig_key_path_keeps_the_internal_participants() {
        let [(a, _), (b, _), (c, fc)] = [1, 2, 3].map(key);
        let text = format!("tr(musig({a},{b})/<0;1>/*,pk({c}/<0;1>/*))");
        let (mut input, tr) = input(&text);

        restrict_input_to_key_path(&mut input, &tr);

        assert!(input.tap_scripts.is_empty());
        let (_, without) = origins_by_leaf(&input, None);
        assert!(without.contains(&fc));
        let participants = musig_input_participants_all(&input).unwrap();
        assert_eq!(participants.len(), 1);
        assert_eq!(
            participants[0].aggregate,
            tr.internal_key().as_musig().unwrap().aggregate()
        );
    }
}
