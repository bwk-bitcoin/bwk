//! MuSig2 helpers for the Ledger Speculos and Coldcard simulator tests: the devices'
//! and hot signers' BIP-87 role keys, the bwk-bup descriptors, the spend PSBTs, the
//! PSBT handling of the two rounds and the check of the final signature.

use std::{collections::BTreeSet, sync::Arc};

use bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint, Xpub},
    hashes::Hash,
    key::{Secp256k1, XOnlyPublicKey},
    psbt::{Input, Psbt},
    secp256k1::{schnorr, Message, PublicKey, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
    Amount, Network, NetworkKind, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Witness,
};
use bwk_bup::{
    key_role::bip87_account_path,
    musig::{musig_key, musig_leaf},
    unspendable_internal_key, Bip87Account, KeyType, Locktime, OXpub, Path, Policy, PolicyType,
    Semantic, TapPosition,
};
use bwk_descriptor::{
    musig::musig_descriptor_to_string,
    updater::{update_input, update_output},
    wallet::{WalletDefiniteDescriptor, WalletDescriptor, WalletDescriptorExt},
};
use bwk_hwi::{
    ledger::{bitcoin_client::wallet::WalletPubKey, LedgerSimulator},
    utils::extract_keys_and_template,
    Error as HWIError, HWI,
};
use bwk_keys::{musig::MusigKey, nums::bip341_nums};
use bwk_psbt::musig::{
    musig_input_partial_sigs, musig_input_pub_nonces, remove_musig_input_partial_sigs,
    remove_musig_input_pub_nonces, set_musig_input_partial_sig, set_musig_input_pub_nonce,
    PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
};
use bwk_sign::{hot_signer::HotSigner, musig::aggregate_partial_sigs};
use miniscript::{descriptor::TapTree, psbt::PsbtExt, Descriptor};
use speculos::{Button, Speculos};

use crate::common::speculos::{connect_to, run_steps};

/// The name the policies are registered under on the Ledger.
pub const WALLET_NAME: &str = "musig";
const COIN_SATS: u64 = 100_000;
const SPEND_SATS: u64 = 90_000;
/// The fee of `offline_psbt`.
const OFFLINE_FEE: Amount = Amount::from_sat(1_000);

/// The role key `[fp/87'/1'/0'/R]tpub` of the BIP-87 account 0 whose xpub is `account`.
fn role_key(fingerprint: Fingerprint, account: Xpub, key_type: KeyType) -> OXpub {
    Bip87Account::new(
        fingerprint,
        bip87_account_path(NetworkKind::Test, 0),
        account,
    )
    .unwrap()
    .role_key(key_type, 0)
    .unwrap()
}

/// The screens of an xpub export the user approves (app 2.4.6 asks for `m/87'/1'/0'`).
pub const APPROVE_XPUB_STEPS: &[(&str, Button)] = &[
    ("Confirm public key", Button::Right),
    ("Path", Button::Right),
    ("Public key (1/3)", Button::Right),
    ("Public key (2/3)", Button::Right),
    ("Public key (3/3)", Button::Right),
    ("Approve public key", Button::Both),
];

/// The Ledger's BIP-87 cosigner role key `[fp/87'/1'/0'/2]tpub`. The app only exports
/// `m/87'/1'/0'` after the user approves it on screen.
pub fn ledger_role_key(sim: &Speculos) -> OXpub {
    let device = connect_to(sim).display_xpub(true).unwrap();
    let fingerprint = device.get_master_fingerprint().unwrap();
    let task = std::thread::spawn(move || device.get_extended_pubkey(&ledger_account_path()));
    run_steps(sim, APPROVE_XPUB_STEPS);
    cosigner_role_key(fingerprint, task.join().unwrap().unwrap())
}

/// `m/87'/1'/0'`, the BIP-87 account the Ledger's role key comes from.
pub fn ledger_account_path() -> DerivationPath {
    bip87_account_path(NetworkKind::Test, 0)
}

/// The cosigner role key of the account `xpub` at `ledger_account_path`.
pub fn cosigner_role_key(fingerprint: Fingerprint, xpub: Xpub) -> OXpub {
    role_key(fingerprint, xpub, KeyType::Cosigner)
}

/// The role key of a device at `m/87'/1'/0'` (fingerprint and xpub read from it).
pub fn device_key(device: &dyn HWI, key_type: KeyType) -> OXpub {
    let account = device
        .get_extended_pubkey(&bip87_account_path(NetworkKind::Test, 0))
        .unwrap();
    role_key(device.get_master_fingerprint().unwrap(), account, key_type)
}

/// A hot participant: its signer and its role key `[fp/87'/1'/0'/R]tpub`. Port of
/// `Participant` (sign/tests/musig_core_interop.rs:55-71 at af8cdf5).
pub struct HotParticipant {
    pub signer: HotSigner,
    pub key: OXpub,
}

impl HotParticipant {
    pub fn new(seed: &str, key_type: KeyType) -> Self {
        let signer = HotSigner::new_from_mnemonics(Network::Testnet, seed).unwrap();
        let account = signer.xpub(&bip87_account_path(NetworkKind::Test, 0));
        let key = role_key(signer.fingerprint(), account.xkey, key_type);
        Self { signer, key }
    }
}

/// `tr(musig(l,h)/<512;513>/*)`, compiled by bwk-bup from a 2-of-2 in the internal
/// key.
pub fn key_path_2of2(l: &OXpub, h: &OXpub) -> WalletDescriptor {
    let semantic = Semantic::Multi {
        keys: vec![l.clone(), h.clone()],
        threshold: 2,
    };
    let start = semantic.starting_index(&Locktime::None).unwrap();
    let path = Path::new(semantic, Locktime::None, TapPosition::InternalKey);
    let mut policy = Policy::new(vec![path], PolicyType::PrimaryOnly).unwrap();
    let descriptor = policy.compile().unwrap().clone();
    let Descriptor::Tr(tr) = &descriptor else {
        panic!("expected tr()");
    };
    assert_eq!(
        tr.internal_key(),
        &musig_key(&[l.clone(), h.clone()], start).unwrap()
    );
    assert!(tr.tap_tree().is_none());
    descriptor
}

/// `tr(NUMS,pk(musig(l,h)/<0;1>/*))`: one musig() leaf under the NUMS internal key
/// bwk-bup derives from it.
pub fn leaf_2of2(l: &OXpub, h: &OXpub) -> WalletDescriptor {
    let keys = [l.clone(), h.clone()];
    let leaf = TapTree::Leaf(Arc::new(musig_leaf(&keys, 0).unwrap()));
    nums_tr(musig_key(&keys, 2).unwrap(), leaf)
}

/// bwk-bup 2-of-3 MuSig2 over [a, b, c]: 3 `pk(musig(..))` leaves under a NUMS
/// internal key, as sign/tests/musig_core_interop.rs:509-530 (af8cdf5) compiles it.
pub fn policy_2_of_3(a: &OXpub, b: &OXpub, c: &OXpub) -> WalletDescriptor {
    let semantic = Semantic::Multi {
        keys: vec![a.clone(), b.clone(), c.clone()],
        threshold: 2,
    };
    let path = Path::new(semantic, Locktime::None, TapPosition::TapTree(vec![]));
    let mut policy = Policy::new(vec![path], PolicyType::PrimaryOnly).unwrap();
    let descriptor = policy.compile().unwrap().clone();
    let Descriptor::Tr(tr) = &descriptor else {
        panic!("expected tr()");
    };
    let musig_leaves = tr
        .iter_scripts()
        .filter(|(_, ms)| ms.iter_pk().any(|key| key.is_musig()))
        .count();
    assert_eq!(musig_leaves, 3);
    descriptor
}

/// A tr() whose only leaf is `leaf`, under the NUMS internal key bwk-bup derives
/// from it (`placeholder` stands in for the internal key until then).
fn nums_tr(placeholder: MusigKey, leaf: TapTree<MusigKey>) -> WalletDescriptor {
    let Descriptor::Tr(tr) = Descriptor::new_tr(placeholder, Some(leaf.clone())).unwrap() else {
        panic!("expected tr()");
    };
    let nums = unspendable_internal_key(&tr).unwrap();
    Descriptor::new_tr(nums, Some(leaf)).unwrap()
}

/// The registration screens of `policy`: one "Our key", "Their key" or "Dummy key"
/// (the BIP-341 NUMS point) review per key, in policy order.
pub fn register_steps(policy: &str, ledger_key: &OXpub) -> Vec<(String, Button)> {
    let (_, keys) = extract_keys_and_template::<WalletPubKey>(policy).unwrap();
    let mut steps: Vec<(String, Button)> = vec![
        ("Review account".into(), Button::Right),
        ("Account name".into(), Button::Right),
        ("Wallet policy".into(), Button::Right),
        ("Review co-signer".into(), Button::Right),
    ];
    for (i, key) in keys.iter().enumerate() {
        let owner = if key.inner == ledger_key.xkey {
            "Our"
        } else if key.inner.public_key == bip341_nums() {
            "Dummy"
        } else {
            "Their"
        };
        for page in 1..=3 {
            steps.push((format!("{owner} key@{i} ({page}/3)"), Button::Right));
        }
    }
    steps.push(("Register account".into(), Button::Both));
    steps
}

/// The BIP-390 text the Ledger registers.
pub fn ledger_policy(descriptor: &WalletDescriptor) -> String {
    musig_descriptor_to_string(descriptor, false)
}

/// `descriptor` at `index` of `keychain` (0 receive, 1 change). Port of
/// sign/tests/musig_core_interop.rs:279-283 (af8cdf5).
pub fn derived(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
) -> WalletDefiniteDescriptor {
    descriptor.single_paths().unwrap()[keychain]
        .derive_at(index)
        .unwrap()
}

/// The hash of the only leaf of `descriptor` at receive index 0.
pub fn spend_leaf_hash(descriptor: &WalletDescriptor) -> TapLeafHash {
    let Descriptor::Tr(tr) = derived(descriptor, 0, 0) else {
        panic!("expected tr()");
    };
    let (_, ms) = tr.iter_scripts().next().unwrap();
    TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript)
}

/// The leaf of `signers` in the `keychain` descriptor at `index`: its hash and the
/// KeyAgg output of its musig(). Port of sign/tests/musig_core_interop.rs:248-276
/// (af8cdf5).
pub fn spend_leaf(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    signers: [Fingerprint; 2],
) -> (TapLeafHash, PublicKey) {
    let Descriptor::Tr(tr) = derived(descriptor, keychain, index) else {
        panic!("expected tr()");
    };
    let wanted: BTreeSet<Fingerprint> = signers.into_iter().collect();
    tr.iter_scripts()
        .find_map(|(_, ms)| {
            let agg = ms.iter_pk().find_map(|key| key.as_musig().cloned())?;
            let fingerprints: BTreeSet<Fingerprint> = agg
                .cosigners()
                .iter()
                .map(|key| key.master_fingerprint())
                .collect();
            (fingerprints == wanted).then(|| {
                (
                    TapLeafHash::from_script(&ms.encode(), LeafVersion::TapScript),
                    agg.aggregate(),
                )
            })
        })
        .unwrap()
}

/// Only `leaf`: its script and the 0x1a of `aggregate`. Port of
/// sign/tests/musig_core_interop.rs:285-300 (af8cdf5) without the `tap_key_origins`
/// restriction: the Coldcard matches an input against the enrolled wallet by its
/// whole origin list (`MiniScriptWallet.matching_subpaths`, coldcard/firmware
/// 04e949d6 `shared/wallet.py`) and skips an input that lists only the leaf's keys.
fn keep_leaf(input: &mut Input, leaf: TapLeafHash, aggregate: PublicKey) {
    input
        .tap_scripts
        .retain(|_, (script, version)| TapLeafHash::from_script(script, *version) == leaf);
    input.unknown.retain(|key, _| {
        key.type_value != PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS || key.key == aggregate.serialize()
    });
}

/// `psbt` restricted to the leaf of `signers` (keep_leaf on every input).
pub fn restrict_to_leaf(
    psbt: &mut Psbt,
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    signers: [Fingerprint; 2],
) {
    let (leaf, aggregate) = spend_leaf(descriptor, keychain, index, signers);
    for input in &mut psbt.inputs {
        keep_leaf(input, leaf, aggregate);
    }
}

/// 1-in 1-out PSBT spending a fake funding output of `value` at (keychain, index) of
/// `descriptor` to `output`, the input filled by bwk's updater.
fn spend_coin(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    value: Amount,
    output: TxOut,
) -> Psbt {
    let definite = derived(descriptor, keychain, index);
    let coin = TxOut {
        value,
        script_pubkey: definite.script_pubkey(),
    };
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![coin.clone()],
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![output],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(coin);
    update_input(&mut psbt, 0, &definite).unwrap();
    psbt
}

/// Spends the receive coin at index 0 (`COIN_SATS`) to a fixed external P2TR
/// (`SPEND_SATS`).
pub fn spend_psbt(descriptor: &WalletDescriptor) -> Psbt {
    let secp = Secp256k1::new();
    let external = SecretKey::from_slice(&[9; 32])
        .unwrap()
        .x_only_public_key(&secp)
        .0;
    let output = TxOut {
        value: Amount::from_sat(SPEND_SATS),
        script_pubkey: ScriptBuf::new_p2tr(&secp, external, None),
    };
    spend_coin(descriptor, 0, 0, Amount::from_sat(COIN_SATS), output)
}

/// 1-in 1-out PSBT spending a fake funding output of `value` at (keychain, index) of
/// `descriptor` back to its receive index 0, inputs and outputs filled by bwk's
/// updater (as bwk builds them).
pub fn offline_psbt(
    descriptor: &WalletDescriptor,
    keychain: usize,
    index: u32,
    value: Amount,
) -> Psbt {
    let receive_0 = derived(descriptor, 0, 0);
    let output = TxOut {
        value: value - OFFLINE_FEE,
        script_pubkey: receive_0.script_pubkey(),
    };
    let mut psbt = spend_coin(descriptor, keychain, index, value, output);
    update_output(&mut psbt, 0, &receive_0).unwrap();
    psbt
}

/// A copy of `psbt` without any 0x1b / 0x1c: the round 1 input for every signer (one
/// pubnonce makes the Ledger run round 2).
pub fn without_nonces(psbt: &Psbt) -> Psbt {
    let mut copy = psbt.clone();
    for input in &mut copy.inputs {
        remove_musig_input_pub_nonces(input);
        remove_musig_input_partial_sigs(input);
    }
    copy
}

/// Adds the 0x1b and 0x1c entries of `answer` to `master`, input by input.
pub fn merge_round(master: &mut Psbt, answer: &Psbt) {
    for (input, answer) in master.inputs.iter_mut().zip(&answer.inputs) {
        for nonce in musig_input_pub_nonces(answer).unwrap() {
            set_musig_input_pub_nonce(input, &nonce);
        }
        for sig in musig_input_partial_sigs(answer).unwrap() {
            set_musig_input_partial_sig(input, &sig);
        }
    }
}

/// `sign_tx` on a fresh connection with the registered policy, walking `steps`
/// while it runs; its result and the PSBT it filled.
pub fn ledger_sign_tx(
    sim: &Speculos,
    policy: &str,
    hmac: [u8; 32],
    mut psbt: Psbt,
    steps: &[(&str, Button)],
) -> (Result<(), HWIError>, Psbt) {
    let device = LedgerSimulator::try_connect_on(sim.apdu_addr())
        .unwrap()
        .with_wallet(WALLET_NAME, policy, Some(hmac))
        .unwrap();
    let task = std::thread::spawn(move || {
        let result = device.sign_tx(&mut psbt);
        (result, psbt)
    });
    run_steps(sim, steps);
    task.join().unwrap()
}

/// Aggregates the partial sigs, finalizes, then checks the final Schnorr signature
/// against the sighash: the key path against the output key, a leaf against the
/// key of its `pk()` script.
pub fn finalize_and_verify(mut psbt: Psbt, descriptor: &WalletDescriptor) {
    assert_eq!(aggregate_partial_sigs(&mut psbt, descriptor).unwrap(), 1);
    let secp = Secp256k1::verification_only();
    psbt.finalize_mut(&secp).unwrap();
    let prevout = psbt.inputs[0].witness_utxo.clone().unwrap();
    let prevouts = [prevout.clone()];
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let witness = psbt.inputs[0].final_script_witness.clone().unwrap();
    let (signature, sighash, key) = match witness.len() {
        1 => {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();
            let output_key =
                XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..]).unwrap();
            (&witness[0], sighash.to_byte_array(), output_key)
        }
        3 => {
            let script = ScriptBuf::from_bytes(witness[1].to_vec());
            let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
            let sighash = cache
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .unwrap();
            // pk(K): OP_PUSHBYTES_32 K OP_CHECKSIG
            assert_eq!(script.len(), 34);
            let leaf_key = XOnlyPublicKey::from_slice(&script.as_bytes()[1..33]).unwrap();
            (&witness[0], sighash.to_byte_array(), leaf_key)
        }
        n => panic!("unexpected witness of {n} elements"),
    };
    let signature = schnorr::Signature::from_slice(signature).unwrap();
    secp.verify_schnorr(&signature, &Message::from_digest(sighash), &key)
        .unwrap();
}
