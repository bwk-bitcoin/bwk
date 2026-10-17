//! A bwk-bup 2-of-3 MuSig2 wallet over a hot key (A), a Ledger on Speculos (B) and
//! the Coldcard simulator (C), registered on both devices, one coin spent through
//! each of its three 2-key leaves on a Bitcoin Core v31 regtest node. Run with
//! `hwi/tests/devices/run.sh`.

#![cfg(all(
    feature = "ledger",
    feature = "coldcard",
    feature = "service",
    feature = "musig",
    unix
))]

mod common;

use std::{env, net::SocketAddr, path::Path};

use bitcoin::{
    bip32::Fingerprint, consensus::encode::serialize_hex, psbt::Psbt, secp256k1::Secp256k1, Amount,
    Network,
};
use bwk_bup::KeyType;
use bwk_descriptor::{musig::musig_descriptor_to_string, wallet::WalletDescriptor};
use bwk_hwi::{coldcard::Coldcard, ledger::LedgerSimulator, service::COLDCARD_SIMULATOR_ENV, HWI};
use bwk_psbt::musig::{musig_input_partial_sigs, musig_input_pub_nonces};
use bwk_sign::{hot_signer::HotSigner, musig::aggregate_partial_sigs};
use miniscript::psbt::PsbtExt;

use common::{
    coldcard_sim::{enroll, Approver},
    musig::{
        derived, device_key, merge_round, policy_2_of_3, psbt_spending, restrict_to_leaf,
        spend_leaf, without_nonces, HotParticipant,
    },
    regtest::Core,
    speculos_clicker::Clicker,
    SEED_A, SEED_B, SEED_C,
};

const RUN_SCRIPT: &str = "hwi/tests/devices/run.sh";
const SPECULOS_APDU_ENV: &str = "SPECULOS_APDU";
const SPECULOS_API_ENV: &str = "SPECULOS_API";
const DEFAULT_SPECULOS_APDU: &str = "127.0.0.1:9999";
const DEFAULT_SPECULOS_API: &str = "127.0.0.1:5000";
const WALLET_NAME: &str = "bwk-musig-e2e";
const COIN: Amount = Amount::from_sat(100_000);
const FEE: Amount = Amount::from_sat(1_000);

/// A signer of a leaf: `HWI::sign_tx` for the devices, `inner_sign` for the hot key.
enum Signer<'a> {
    Ledger(&'a LedgerSimulator),
    /// The device and the simulator socket its approver connects to.
    Coldcard(&'a Coldcard, &'a Path),
    Hot(&'a HotSigner),
}

impl Signer<'_> {
    fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Ledger(ledger) => ledger.get_master_fingerprint().unwrap(),
            Self::Coldcard(coldcard, _) => coldcard.get_master_fingerprint().unwrap(),
            Self::Hot(signer) => signer.fingerprint(),
        }
    }

    /// One signing call on `psbt`; the stories the Coldcard showed (none for the
    /// others).
    fn sign(&self, psbt: &mut Psbt, descriptor: &WalletDescriptor) -> Vec<(String, String)> {
        match self {
            Self::Ledger(ledger) => {
                ledger.sign_tx(psbt).unwrap();
                vec![]
            }
            Self::Coldcard(coldcard, socket) => {
                // one approver per call: a story poll during the PSBT upload breaks
                // the device link (see `Approver`)
                let approver = Approver::spawn(socket);
                coldcard.sign_tx(psbt).unwrap();
                approver.stories()
            }
            Self::Hot(signer) => {
                signer.inner_sign(psbt, descriptor).unwrap();
                vec![]
            }
        }
    }
}

fn env_addr(name: &str, default: &str) -> SocketAddr {
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .unwrap()
}

#[test]
#[ignore = "run through hwi/tests/devices/run.sh (Speculos, Coldcard simulator, BITCOIND_V31_EXE)"]
fn musig_2_of_3_ledger_coldcard_hot_regtest() {
    let apdu = env_addr(SPECULOS_APDU_ENV, DEFAULT_SPECULOS_APDU);
    let api = env_addr(SPECULOS_API_ENV, DEFAULT_SPECULOS_API);
    let socket = env::var_os(COLDCARD_SIMULATOR_ENV)
        .unwrap_or_else(|| panic!("set {COLDCARD_SIMULATOR_ENV}: run {RUN_SCRIPT}"));
    let socket = Path::new(&socket);

    let clicker = Clicker::spawn(api);
    println!("[1] Speculos clicker on {api}, Coldcard simulator on {socket:?}");

    let a = HotParticipant::new(SEED_A, KeyType::Internal);
    let expected_b = HotParticipant::new(SEED_B, KeyType::Cosigner);
    let expected_c = HotParticipant::new(SEED_C, KeyType::External);
    let ledger = LedgerSimulator::try_connect_on(apdu).unwrap();
    let coldcard = Coldcard::connect_simulator(socket).unwrap();
    let ledger_fingerprint = ledger.get_master_fingerprint().unwrap();
    let coldcard_fingerprint = coldcard.get_master_fingerprint().unwrap();
    assert_eq!(ledger_fingerprint, expected_b.signer.fingerprint());
    assert_eq!(coldcard_fingerprint, expected_c.signer.fingerprint());
    println!(
        "[2] Ledger app {:?} fingerprint {ledger_fingerprint}, Coldcard fingerprint {coldcard_fingerprint}",
        ledger.get_version().unwrap()
    );

    let b = device_key(&ledger, KeyType::Cosigner);
    let c = device_key(&coldcard, KeyType::External);
    assert_eq!(b, expected_b.key);
    assert_eq!(c, expected_c.key);
    println!("[3] role keys: A {:?}, B {b:?}, C {c:?}", a.key);

    // asserts the 3 musig() leaves
    let descriptor = policy_2_of_3(&a.key, &b, &c);
    let text = musig_descriptor_to_string(&descriptor, false);
    println!("[4] bwk-bup 2-of-3: {text}");

    let hmac = ledger.register_wallet(WALLET_NAME, &text).unwrap().unwrap();
    let ledger = ledger.with_wallet(WALLET_NAME, &text, Some(hmac)).unwrap();
    let coldcard = enroll(socket, coldcard, WALLET_NAME, &text);
    println!("[5] {WALLET_NAME} registered on the Ledger (HMAC kept) and enrolled on the Coldcard");

    let core = Core::start();
    let public = musig_descriptor_to_string(&descriptor, true);
    for index in 0..3 {
        let address = derived(&descriptor, 0, index)
            .address(Network::Regtest)
            .unwrap();
        assert_eq!(core.derive_address(&public, index), address.to_string());
    }
    println!(
        "[6] {} agrees with bwk on receive addresses 0 to 2",
        core.miner("getnetworkinfo", &[])["subversion"]
    );

    let a_signer = Signer::Hot(&a.signer);
    let b_signer = Signer::Ledger(&ledger);
    let c_signer = Signer::Coldcard(&coldcard, socket);
    let leaves = [
        (0, "Ledger + Coldcard", [&b_signer, &c_signer]),
        (1, "Ledger + hot", [&b_signer, &a_signer]),
        (2, "Coldcard + hot", [&c_signer, &a_signer]),
    ];
    let mut stories = Vec::new();
    for (index, name, signers) in leaves {
        let address = derived(&descriptor, 0, index)
            .address(Network::Regtest)
            .unwrap();
        let (funding, vout) = core.fund(&address, COIN);
        let mut master = psbt_spending(
            &descriptor,
            0,
            index,
            &funding,
            vout,
            core.new_address().script_pubkey(),
            FEE,
        );
        let unrestricted = master.clone();
        let fingerprints = [signers[0].fingerprint(), signers[1].fingerprint()];
        restrict_to_leaf(&mut master, &descriptor, 0, index, fingerprints);
        let (leaf, _) = spend_leaf(&descriptor, 0, index, fingerprints);
        assert_eq!(master.inputs[0].tap_scripts.len(), 1);
        assert_eq!(
            master.inputs[0].tap_key_origins.len(),
            unrestricted.inputs[0].tap_key_origins.len()
        );

        // round 1: every signer gets the PSBT without nonces
        for signer in signers {
            let mut answer = without_nonces(&master);
            stories.extend(signer.sign(&mut answer, &descriptor));
            merge_round(&mut master, &answer);
        }
        let input = &master.inputs[0];
        let nonces = musig_input_pub_nonces(input).unwrap();
        assert_eq!(nonces.len(), 2, "{nonces:#?}");
        assert!(nonces.iter().all(|nonce| nonce.leaf_hash == Some(leaf)));
        assert!(musig_input_partial_sigs(input).unwrap().is_empty());

        // round 2: both get the PSBT as it stood after round 1
        let after_round_1 = master.clone();
        for signer in signers {
            let mut answer = after_round_1.clone();
            stories.extend(signer.sign(&mut answer, &descriptor));
            // no signer aggregates: it never sees the other partial signature
            assert!(answer.inputs[0].tap_script_sigs.is_empty());
            assert!(answer.inputs[0].tap_key_sig.is_none());
            merge_round(&mut master, &answer);
        }
        assert_eq!(
            musig_input_partial_sigs(&master.inputs[0]).unwrap().len(),
            2
        );

        assert_eq!(aggregate_partial_sigs(&mut master, &descriptor).unwrap(), 1);
        master
            .finalize_mut(&Secp256k1::verification_only())
            .unwrap();
        let txid = core.broadcast(&serialize_hex(&master.extract_tx_unchecked_fee_rate()));
        println!("[7] leaf {name}: {txid} confirmed");
    }

    let screens = clicker.screens();
    println!(
        "[8] {} Ledger screens: {screens:#?}\n{} Coldcard stories: {stories:#?}",
        screens.len(),
        stories.len()
    );
}
