use std::{collections::BTreeSet, str::FromStr};

use miniscript::bitcoin::{
    absolute,
    bip32::{Xpriv, Xpub},
    hashes::Hash,
    relative,
    secp256k1::Secp256k1,
    transaction, BlockHash, Network, Sequence, Transaction, TxIn,
};

use crate::{
    descriptor::Descriptor,
    spend::{spend_variants, ChainContext, Confirmation, Error, Locks, Maturity, Path},
    wallet::{WalletDescriptor, WalletDescriptorExt},
};

fn keys() -> Vec<String> {
    let secp = Secp256k1::new();
    (1..=6)
        .map(|byte| {
            let key = Xpriv::new_master(Network::Testnet, &[byte; 32]).unwrap();
            format!(
                "[{}]{}/<0;1>/*",
                key.fingerprint(&secp),
                Xpub::from_priv(&secp, &key)
            )
        })
        .collect()
}

fn descriptor(text: &str) -> WalletDescriptor {
    Descriptor::from_str(text)
        .unwrap()
        .into_miniscript()
        .unwrap()
}

fn transaction(inputs: usize) -> Transaction {
    Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default(); inputs],
        output: vec![],
    }
}

fn locks(absolute: Option<u32>, relative: Option<u32>) -> Locks {
    Locks {
        absolute: absolute.map(absolute::LockTime::from_consensus),
        relative: relative.map(|value| relative::LockTime::from_consensus(value).unwrap()),
    }
}

fn context() -> ChainContext {
    ChainContext {
        tip: BlockHash::from_byte_array([1; 32]),
        height: 100,
        median_time_past: Some(500_001_024),
        confirmation: Confirmation::Confirmed {
            height: 99,
            previous_mtp: Some(500_000_000),
        },
    }
}

#[test]
fn immediate_and_delayed_signers_remain_separate() {
    let keys = keys();
    for wrapper in ["tr", "wsh", "shwsh", "sh"] {
        let script = format!("or_d(pk({}),and_v(v:pk({}),older(10)))", keys[0], keys[1]);
        let text = match wrapper {
            "tr" => format!("tr({},{} )", keys[2], script).replace(" ", ""),
            "wsh" => format!("wsh({script})"),
            "shwsh" => format!("sh(wsh({script}))"),
            _ => format!("sh({script})"),
        };
        let desc = descriptor(&text);
        let result = spend_variants(&desc, 0, 0).unwrap();
        assert_eq!(result.descriptor, desc);
        let alternatives: Vec<_> = result
            .variants
            .iter()
            .filter(|v| v.id.path != Path::Key)
            .collect();
        assert_eq!(alternatives.len(), 2);
        assert_eq!(alternatives[0].requirements.keys.len(), 1);
        assert_eq!(alternatives[1].requirements.keys.len(), 1);
        assert_ne!(
            alternatives[0].requirements.keys,
            alternatives[1].requirements.keys
        );
        assert_eq!(alternatives[0].requirements.locks, Locks::default());
        assert_eq!(alternatives[1].requirements.locks, locks(None, Some(10)));
        assert_eq!(
            alternatives[0].requirements.locks.maturity(None).unwrap(),
            Maturity::Mature
        );
        assert_eq!(
            alternatives[1].requirements.locks.maturity(None).unwrap(),
            Maturity::Unknown
        );
        assert!(alternatives.iter().all(|v| v.satisfaction_wu >= 67));
    }
}

#[test]
fn all_threshold_subsets_through_six_keys() {
    let keys = keys();
    for n in 1..=6 {
        for required in 1..=n {
            for taproot in [false, true] {
                let joined = keys[..n].join(",");
                let text = if taproot {
                    format!("tr({},multi_a({required},{joined}))", keys[5])
                } else {
                    format!("wsh(multi({required},{joined}))")
                };
                let result = spend_variants(&descriptor(&text), 0, 0).unwrap();
                let actual: BTreeSet<_> = result
                    .variants
                    .iter()
                    .filter(|v| v.id.path != Path::Key)
                    .map(|v| {
                        v.requirements
                            .keys
                            .iter()
                            .map(ToString::to_string)
                            .collect::<BTreeSet<_>>()
                    })
                    .collect();
                let expected: BTreeSet<_> = (0u32..(1 << n))
                    .filter(|bits| bits.count_ones() as usize == required)
                    .map(|bits| {
                        keys[..n]
                            .iter()
                            .enumerate()
                            .filter(|(index, _)| bits & (1 << index) != 0)
                            .map(|(_, key)| key.clone())
                            .collect::<BTreeSet<_>>()
                    })
                    .collect();
                assert_eq!(actual, expected, "{text}");
                if taproot {
                    let definite = descriptor(&text).single_paths().unwrap()[0]
                        .derive_at(0)
                        .unwrap();
                    let miniscript::Descriptor::Tr(tr) = definite else {
                        panic!("expected taproot")
                    };
                    let (_, ms) = tr.iter_scripts().next().unwrap();
                    let script = ms.encode();
                    let control = tr
                        .spend_info()
                        .control_block(&(
                            script.clone(),
                            miniscript::bitcoin::taproot::LeafVersion::TapScript,
                        ))
                        .unwrap();
                    let mut stack: Vec<Vec<u8>> = (0..n)
                        .map(|i| if i < required { vec![0; 65] } else { vec![] })
                        .collect();
                    stack.push(script.into_bytes());
                    stack.push(control.serialize());
                    let witness = miniscript::bitcoin::Witness::from_slice(&stack);
                    for variant in result.variants.iter().filter(|v| v.id.path != Path::Key) {
                        assert_eq!(variant.satisfaction_wu, witness.size() as u64);
                    }
                }
            }
        }
    }
}

#[test]
fn script_combinators_preserve_signer_alternatives() {
    let keys = keys();
    for (script, expected) in [
        (
            format!("and_v(v:pk({}),pk({}))", keys[0], keys[1]),
            vec![vec![0, 1]],
        ),
        (
            format!("or_b(pk({}),s:pk({}))", keys[0], keys[1]),
            vec![vec![0], vec![1]],
        ),
        (
            format!("or_i(pk({}),pk({}))", keys[0], keys[1]),
            vec![vec![0], vec![1]],
        ),
        (
            format!("andor(pk({}),pk({}),pk({}))", keys[0], keys[1], keys[2]),
            vec![vec![0, 1], vec![2]],
        ),
        (
            format!(
                "thresh(2,pk({}),s:pk({}),s:pk({}))",
                keys[0], keys[1], keys[2]
            ),
            vec![vec![0, 1], vec![0, 2], vec![1, 2]],
        ),
    ] {
        for text in [
            format!("tr({},{script})", keys[5]),
            format!("wsh({script})"),
        ] {
            let result = spend_variants(&descriptor(&text), 0, 0).unwrap();
            let actual: BTreeSet<BTreeSet<String>> = result
                .variants
                .iter()
                .filter(|v| v.id.path != Path::Key)
                .map(|v| {
                    v.requirements
                        .keys
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                })
                .collect();
            let expected: BTreeSet<BTreeSet<String>> = expected
                .iter()
                .map(|subset| subset.iter().map(|i| keys[*i].clone()).collect())
                .collect();
            assert_eq!(actual, expected, "{text}");
        }
    }
}

#[test]
fn ordinary_and_sortedmulti_descriptors() {
    let keys = keys();
    for text in [
        format!("pkh({})", keys[0]),
        format!("wpkh({})", keys[0]),
        format!("sh(wpkh({}))", keys[0]),
    ] {
        let exported = spend_variants(&descriptor(&text), 0, 0).unwrap();
        assert_eq!(exported.variants.len(), 1);
        assert_eq!(
            exported.variants[0].requirements.keys[0].to_string(),
            keys[0]
        );
        assert_eq!(exported.variants[0].requirements.locks, Locks::default());
        assert!(exported.variants[0].satisfaction_wu >= 107);
    }
    for text in [
        format!("wsh(sortedmulti(2,{}))", keys[..3].join(",")),
        format!("sh(sortedmulti(2,{}))", keys[..3].join(",")),
        format!("sh(wsh(sortedmulti(2,{})))", keys[..3].join(",")),
    ] {
        let exported = spend_variants(&descriptor(&text), 0, 0).unwrap();
        assert_eq!(exported.variants.len(), 3);
        assert!(exported
            .variants
            .iter()
            .all(|variant| variant.requirements.keys.len() == 2));
    }
}

#[test]
fn different_lock_alternatives_remain_separate() {
    let keys = keys();
    for (a, b) in [("after(100)", "after(200)"), ("older(10)", "older(20)")] {
        let text = format!(
            "tr({},or_i(and_v(v:pk({}),{a}),and_v(v:pk({}),{b})))",
            keys[0], keys[1], keys[2]
        );
        let result = spend_variants(&descriptor(&text), 0, 0).unwrap();
        assert_eq!(result.variants.len(), 3);
        assert_ne!(
            result.variants[1].requirements.locks,
            result.variants[2].requirements.locks
        );
    }
}

#[test]
fn lock_domains_and_nested_alternatives() {
    let keys = keys();
    for (fragment, expected) in [
        ("after(100)", locks(Some(100), None)),
        ("after(500000100)", locks(Some(500_000_100), None)),
        ("older(10)", locks(None, Some(10))),
        ("older(4194306)", locks(None, Some((1 << 22) | 2))),
        ("and_v(v:after(100),older(10))", locks(Some(100), Some(10))),
        (
            "and_v(v:after(500000100),older(4194306))",
            locks(Some(500_000_100), Some((1 << 22) | 2)),
        ),
    ] {
        let text = format!("tr({},and_v(v:pk({}),{fragment}))", keys[0], keys[1]);
        let result = spend_variants(&descriptor(&text), 0, 0).unwrap();
        assert_eq!(result.variants.len(), 2);
        assert_eq!(result.variants[1].requirements.locks, expected);
    }
    let text = format!(
        "tr({},or_i(and_v(v:pk({}),after(100)),and_v(v:pk({}),after(500000100))))",
        keys[0], keys[1], keys[2]
    );
    assert_eq!(
        spend_variants(&descriptor(&text), 0, 0)
            .unwrap()
            .variants
            .len(),
        3
    );
}

#[test]
fn path_ids_survive_derivation_and_are_policy_scoped() {
    let keys = keys();
    let desc = descriptor(&format!(
        "tr({},{{pk({}),and_v(v:pk({}),older(10))}})",
        keys[0], keys[1], keys[2]
    ));
    let first = spend_variants(&desc, 0, 0).unwrap();
    for keychain in 0..2 {
        for index in [0, 1, 1000] {
            let other = spend_variants(&desc, keychain, index).unwrap();
            assert_eq!(first, other);
        }
    }
    let changed = descriptor(&format!(
        "tr({},{{pk({}),and_v(v:pk({}),older(11))}})",
        keys[0], keys[1], keys[2]
    ));
    let changed = spend_variants(&changed, 0, 0).unwrap();
    assert_ne!(first.variants[0].id.policy, changed.variants[0].id.policy);
    assert_eq!(spend_variants(&desc, 2, 0), Err(Error::UnknownVariant));
}

#[test]
fn nums_paths_are_impossible_not_offline() {
    let keys = keys();
    let nums = bwk_keys::nums::bip341_nums();
    let desc = descriptor(&format!("tr({nums},{{pk({nums}),pk({})}})", keys[0]));
    let result = spend_variants(&desc, 0, 0).unwrap();
    assert_eq!(result.variants.len(), 1);
    assert_eq!(result.variants[0].id.path, Path::Leaf(1));
}

#[test]
fn all_hash_preimages_are_explicit() {
    let keys = keys();
    for (hash, value) in [
        ("sha256", "11".repeat(32)),
        ("hash256", "22".repeat(32)),
        ("ripemd160", "33".repeat(20)),
        ("hash160", "44".repeat(20)),
    ] {
        let desc = descriptor(&format!(
            "tr({},and_v(v:pk({}),{hash}({value})))",
            keys[0], keys[1]
        ));
        let result = spend_variants(&desc, 0, 0).unwrap();
        assert_eq!(result.variants[1].requirements.preimages.len(), 1);
        assert_eq!(result.variants[1].requirements.keys.len(), 1);
    }
}

#[test]
fn maturity_boundaries_and_missing_context() {
    for (requirements, expected) in [
        (locks(None, None), Maturity::Mature),
        (locks(Some(100), None), Maturity::Mature),
        (locks(Some(101), None), Maturity::Immature),
        (locks(Some(500_001_023), None), Maturity::Mature),
        (locks(Some(500_001_024), None), Maturity::Immature),
        (locks(None, Some(2)), Maturity::Mature),
        (locks(None, Some(3)), Maturity::Immature),
        (locks(None, Some((1 << 22) | 2)), Maturity::Mature),
        (locks(None, Some((1 << 22) | 3)), Maturity::Immature),
        (locks(Some(101), Some(2)), Maturity::Immature),
    ] {
        assert_eq!(requirements.maturity(Some(&context())).unwrap(), expected);
        assert_eq!(
            requirements.maturity(None).unwrap(),
            if requirements == Locks::default() {
                Maturity::Mature
            } else {
                Maturity::Unknown
            }
        );
    }
    let mut unknown = context();
    unknown.median_time_past = None;
    assert_eq!(
        locks(Some(500_001_024), None)
            .maturity(Some(&unknown))
            .unwrap(),
        Maturity::Unknown
    );
    assert_eq!(
        locks(None, Some((1 << 22) | 2))
            .maturity(Some(&unknown))
            .unwrap(),
        Maturity::Unknown
    );
    unknown.confirmation = Confirmation::Unknown;
    assert_eq!(
        locks(None, Some(1)).maturity(Some(&unknown)).unwrap(),
        Maturity::Unknown
    );
    assert_eq!(
        locks(Some(101), Some(1)).maturity(Some(&unknown)).unwrap(),
        Maturity::Immature
    );
    unknown.confirmation = Confirmation::Confirmed {
        height: 99,
        previous_mtp: None,
    };
    unknown.median_time_past = context().median_time_past;
    assert_eq!(
        locks(None, Some((1 << 22) | 2))
            .maturity(Some(&unknown))
            .unwrap(),
        Maturity::Unknown
    );
}

#[test]
fn unconfirmed_and_reorg_maturity() {
    let mut chain = context();
    let requirement = locks(None, Some(2));
    assert_eq!(
        requirement.maturity(Some(&chain)).unwrap(),
        Maturity::Mature
    );
    chain.tip = BlockHash::from_byte_array([2; 32]);
    chain.confirmation = Confirmation::Confirmed {
        height: 100,
        previous_mtp: Some(500_000_512),
    };
    assert_eq!(
        requirement.maturity(Some(&chain)).unwrap(),
        Maturity::Immature
    );
    assert_eq!(
        locks(None, Some((1 << 22) | 2))
            .maturity(Some(&chain))
            .unwrap(),
        Maturity::Immature
    );
    chain.confirmation = Confirmation::Unconfirmed;
    for sequence in [0, 1, 1 << 22, (1 << 22) | 1] {
        assert_eq!(
            locks(None, Some(sequence)).maturity(Some(&chain)).unwrap(),
            if sequence & 0xffff == 0 {
                Maturity::Mature
            } else {
                Maturity::Immature
            }
        );
    }
    chain.confirmation = Confirmation::Confirmed {
        height: 101,
        previous_mtp: None,
    };
    assert_eq!(
        requirement.maturity(Some(&chain)),
        Err(Error::ConfirmationAboveTip)
    );
}

#[test]
fn lock_compatibility_is_per_input() {
    let absolutes = [None, Some(100), Some(500_000_100)];
    let relatives = [None, Some(10), Some((1 << 22) | 2)];
    for a in absolutes {
        for b in absolutes {
            for r in relatives {
                for s in relatives {
                    let first = locks(a, r);
                    let second = locks(b, s);
                    let mut tx = transaction(2);
                    first.apply(&mut tx, 0).unwrap();
                    let before = tx.clone();
                    let conflict = matches!(
                        (a, b),
                        (Some(100), Some(500_000_100)) | (Some(500_000_100), Some(100))
                    );
                    if conflict {
                        assert_eq!(second.apply(&mut tx, 1), Err(Error::IncompatibleLocks));
                        assert_eq!(tx, before);
                    } else {
                        second.apply(&mut tx, 1).unwrap();
                        first.validate_transaction(&tx, 0).unwrap();
                        second.validate_transaction(&tx, 1).unwrap();
                        assert_eq!(tx.input[0], before.input[0]);
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_transaction_locks_are_rejected() {
    let mut tx = transaction(1);
    for requirement in [
        locks(Some(100), None),
        locks(None, Some(10)),
        locks(None, Some((1 << 22) | 2)),
    ] {
        assert_eq!(
            requirement.validate_transaction(&tx, 0),
            Err(Error::TransactionLocks)
        );
        assert_eq!(
            requirement.validate_transaction(&tx, 1),
            Err(Error::InputIndex)
        );
    }
    let requirement = locks(Some(100), Some(10));
    requirement.apply(&mut tx, 0).unwrap();
    assert_eq!(tx.version, transaction::Version::TWO);
    assert_eq!(tx.lock_time.to_consensus_u32(), 100);
    assert_eq!(tx.input[0].sequence.to_consensus_u32(), 10);
    for sequence in [
        Sequence::MAX,
        Sequence::from_consensus(9),
        Sequence::from_consensus((1 << 22) | 10),
    ] {
        let mut invalid = tx.clone();
        invalid.input[0].sequence = sequence;
        assert_eq!(
            requirement.validate_transaction(&invalid, 0),
            Err(Error::TransactionLocks)
        );
    }
    tx.version = transaction::Version::ONE;
    assert_eq!(
        requirement.validate_transaction(&tx, 0),
        Err(Error::TransactionLocks)
    );
}

#[test]
fn simple_weights_include_witness_framing() {
    let keys = keys();
    let desc = descriptor(&format!("tr({},pk({}))", keys[0], keys[1]));
    let result = spend_variants(&desc, 0, 0).unwrap();
    assert_eq!(result.variants[0].satisfaction_wu, 67);
    assert_eq!(result.variants[1].satisfaction_wu, 136);
    let definite = desc.single_paths().unwrap()[0].derive_at(0).unwrap();
    assert!(
        result.variants[1].satisfaction_wu >= definite.max_weight_to_satisfy().unwrap().to_wu()
    );
}

#[cfg(feature = "musig")]
mod restriction {
    use bwk_psbt::{musig::musig_input_participants_all, PsbtV2};
    use miniscript::bitcoin::{psbt::raw::ProprietaryKey, Amount, Psbt, TxOut};

    use crate::{
        spend::{
            restrict_variant, spend_variants,
            tests::{descriptor, keys, transaction},
            Error, Path,
        },
        updater::update_input,
        wallet::{WalletDescriptor, WalletDescriptorExt},
    };

    fn psbt(desc: &WalletDescriptor) -> Psbt {
        let mut psbt = Psbt::from_unsigned_tx(transaction(2)).unwrap();
        for index in 0..2 {
            let definite = desc.single_paths().unwrap()[0]
                .derive_at(index as u32)
                .unwrap();
            psbt.inputs[index].witness_utxo = Some(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: definite.script_pubkey(),
            });
            update_input(&mut psbt, index, &definite).unwrap();
        }
        let key = ProprietaryKey {
            prefix: b"test".to_vec(),
            subtype: 1,
            key: vec![2],
        };
        psbt.proprietary.insert(key.clone(), vec![3]);
        psbt.inputs[0].proprietary.insert(key, vec![4]);
        psbt
    }

    #[test]
    fn independent_choices_keep_metadata_and_roundtrip_v2() {
        let keys = keys();
        let desc = descriptor(&format!(
            "tr({},{{and_v(v:pk({}),older(10)),and_v(v:pk({}),after(100))}})",
            keys[0], keys[1], keys[2]
        ));
        let exported = spend_variants(&desc, 0, 0).unwrap();
        for first in &exported.variants {
            for second in &exported.variants {
                let mut psbt = psbt(&desc);
                let before = psbt.clone();
                restrict_variant(&desc, 0, 0, &first.id, &mut psbt, 0).unwrap();
                assert_eq!(psbt.inputs[1], before.inputs[1]);
                let first_input = psbt.inputs[0].clone();
                restrict_variant(&desc, 0, 1, &second.id, &mut psbt, 1).unwrap();
                assert_eq!(psbt.inputs[0], first_input);
                assert_eq!(psbt.proprietary, before.proprietary);
                assert_eq!(psbt.inputs[0].proprietary, before.inputs[0].proprietary);
                assert_eq!(
                    psbt.inputs[0].tap_key_origins.len(),
                    before.inputs[0].tap_key_origins.len()
                );
                assert_eq!(
                    psbt.inputs[0].tap_scripts.len(),
                    usize::from(first.id.path != Path::Key)
                );
                first
                    .requirements
                    .locks
                    .validate_transaction(&psbt.unsigned_tx, 0)
                    .unwrap();
                second
                    .requirements
                    .locks
                    .validate_transaction(&psbt.unsigned_tx, 1)
                    .unwrap();
                let v2 = PsbtV2::from_bitcoin_psbt(psbt.clone()).unwrap();
                let roundtrip = PsbtV2::deserialize(&v2.serialize().unwrap())
                    .unwrap()
                    .into_bitcoin_psbt()
                    .unwrap();
                assert_eq!(roundtrip, psbt);
            }
        }
    }

    #[test]
    fn selection_errors_do_not_mutate_psbt() {
        let keys = keys();
        let desc = descriptor(&format!(
            "tr({},{{and_v(v:pk({}),after(100)),and_v(v:pk({}),after(500000100))}})",
            keys[0], keys[1], keys[2]
        ));
        let variants = spend_variants(&desc, 0, 0).unwrap().variants;
        let mut psbt = psbt(&desc);
        restrict_variant(&desc, 0, 0, &variants[1].id, &mut psbt, 0).unwrap();
        let before = psbt.clone();
        assert_eq!(
            restrict_variant(&desc, 0, 1, &variants[2].id, &mut psbt, 1),
            Err(Error::IncompatibleLocks)
        );
        assert_eq!(psbt, before);
        assert_eq!(
            restrict_variant(&desc, 0, 2, &variants[1].id, &mut psbt, 1),
            Err(Error::InputMismatch)
        );
        assert_eq!(psbt, before);
        let mut unknown = variants[0].id.clone();
        unknown.alternative = 100;
        assert_eq!(
            restrict_variant(&desc, 0, 0, &unknown, &mut psbt, 0),
            Err(Error::UnknownVariant)
        );
        assert_eq!(psbt, before);
        psbt.inputs[0].final_script_witness = Some(miniscript::bitcoin::Witness::new());
        let signed = psbt.clone();
        assert_eq!(
            restrict_variant(&desc, 0, 1, &variants[0].id, &mut psbt, 1),
            Err(Error::AlreadySigned)
        );
        assert_eq!(psbt, signed);
    }

    #[test]
    fn musig_requirements_and_participants_are_preserved() {
        let keys = keys();
        let a = keys[0].replace("/<0;1>/*", "");
        let b = keys[1].replace("/<0;1>/*", "");
        let desc = descriptor(&format!("tr({},pk(musig({a},{b})/<0;1>/*))", keys[2]));
        let variants = spend_variants(&desc, 0, 0).unwrap().variants;
        assert_eq!(variants[1].requirements.keys.len(), 1);
        assert_eq!(variants[1].requirements.keys[0].plain_keys().len(), 2);
        let mut psbt = psbt(&desc);
        restrict_variant(&desc, 0, 0, &variants[1].id, &mut psbt, 0).unwrap();
        assert_eq!(
            musig_input_participants_all(&psbt.inputs[0]).unwrap().len(),
            1
        );
        restrict_variant(&desc, 0, 1, &variants[0].id, &mut psbt, 1).unwrap();
        assert!(musig_input_participants_all(&psbt.inputs[1])
            .unwrap()
            .is_empty());
    }
}
