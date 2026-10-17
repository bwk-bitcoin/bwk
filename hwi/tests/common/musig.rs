//! MuSig2 helpers for the Ledger Speculos tests: the Ledger's and a hot signer's
//! BIP-87 role keys, the bwk-bup 2-of-2 descriptors, the spend PSBT, the PSBT
//! handling of the two rounds and the check of the final signature.

use std::sync::Arc;

use bitcoin::{
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint, Xpub},
    hashes::Hash,
    key::{Secp256k1, XOnlyPublicKey},
    psbt::Psbt,
    secp256k1::{schnorr, Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
    Amount, Network, NetworkKind, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bwk_bup::{
    key_role::bip87_account_path,
    musig::{musig_key, musig_leaf},
    unspendable_internal_key, Bip87Account, KeyType, Locktime, OXpub, Path, Policy, PolicyType,
    Semantic, TapPosition,
};
use bwk_descriptor::{
    musig::musig_descriptor_to_string,
    updater::update_input,
    wallet::{WalletDefiniteDescriptor, WalletDescriptor, WalletDescriptorExt},
};
use bwk_hwi::{
    ledger::{bitcoin_client::wallet::WalletPubKey, LedgerSimulator},
    utils::extract_keys_and_template,
    Error as HWIError, HWI,
};
use bwk_keys::{musig::MusigKey, nums::bip341_nums};
use bwk_psbt::musig::{
    musig_input_pub_nonces, remove_musig_input_pub_nonces, set_musig_input_pub_nonce,
};
use bwk_sign::{hot_signer::HotSigner, musig::aggregate_partial_sigs};
use miniscript::{descriptor::TapTree, psbt::PsbtExt, Descriptor};
use speculos::{Button, Speculos};

use crate::common::speculos::{connect_to, run_steps};

/// The hot cosigner's seed: fingerprint `73c5da0a`, not the Speculos seed.
const HOT_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The name the policies are registered under.
pub const WALLET_NAME: &str = "musig";
const COIN_SATS: u64 = 100_000;
const SPEND_SATS: u64 = 90_000;

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
    Bip87Account::new(fingerprint, ledger_account_path(), xpub)
        .unwrap()
        .role_key(KeyType::Cosigner, 0)
        .unwrap()
}

/// The other cosigner: a bwk hot signer and its BIP-87 internal role key
/// `[73c5da0a/87'/1'/0'/0]tpub`.
pub struct HotCosigner {
    pub signer: HotSigner,
    pub key: OXpub,
}

impl HotCosigner {
    pub fn new() -> Self {
        let signer = HotSigner::new_from_mnemonics(Network::Testnet, HOT_MNEMONIC).unwrap();
        let path = bip87_account_path(NetworkKind::Test, 0);
        let account = signer.xpub(&path);
        let key = Bip87Account::new(signer.fingerprint(), path, account.xkey)
            .unwrap()
            .role_key(KeyType::Internal, 0)
            .unwrap();
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

/// `descriptor` at `index` of `keychain` (0 receive, 1 change).
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

/// Spends the receive coin at index 0 (`COIN_SATS`) to a fixed external P2TR
/// (`SPEND_SATS`), the input filled by bwk's updater.
pub fn spend_psbt(descriptor: &WalletDescriptor) -> Psbt {
    let secp = Secp256k1::new();
    let external = SecretKey::from_slice(&[9; 32])
        .unwrap()
        .x_only_public_key(&secp)
        .0;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(SPEND_SATS),
            script_pubkey: ScriptBuf::new_p2tr(&secp, external, None),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    let definite = derived(descriptor, 0, 0);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(COIN_SATS),
        script_pubkey: definite.script_pubkey(),
    });
    update_input(&mut psbt, 0, &definite).unwrap();
    psbt
}

/// The PSBT the Ledger gets for round 1: `psbt` without any pubnonce, since one
/// pubnonce makes the app run round 2.
pub fn round1_copy(psbt: &Psbt) -> Psbt {
    let mut copy = psbt.clone();
    for input in &mut copy.inputs {
        remove_musig_input_pub_nonces(input);
    }
    copy
}

/// Copies every pubnonce of `from` into `into`, input by input.
pub fn merge_nonces(into: &mut Psbt, from: &Psbt) {
    for (input, from) in into.inputs.iter_mut().zip(&from.inputs) {
        for nonce in musig_input_pub_nonces(from).unwrap() {
            set_musig_input_pub_nonce(input, &nonce);
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
