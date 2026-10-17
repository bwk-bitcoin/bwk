//! Tests against a Coldcard simulator this process starts (see `common::coldcard_sim`).

#![cfg(all(feature = "coldcard", unix))]

mod common;

use std::{
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "service")]
use bitcoin::Network;
use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    hashes::Hash,
    secp256k1::{Message, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    Amount,
};
#[cfg(feature = "service")]
use bwk_hwi::service::{HwiService, SigningDeviceMsg, COLDCARD_SIMULATOR_ENV};
use bwk_hwi::{coldcard::Coldcard, DeviceKind, HWI};

use common::{
    build_tr_keypath_test_psbt,
    coldcard_sim::{Approver, SimProcess, SEED_A_BIP87_TPUB, SEED_A_FINGERPRINT},
    cosigner_origin, KeyOrigin, SEED_A,
};

const WALLET_NAME: &str = "bwk-plain-tr";
const COSIGNER_FINGERPRINT: &str = "a5a5a5a5";
const ACCOUNT_PATH: &str = "m/87'/1'/0'";
const REGISTERED_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(feature = "service")]
const SERVICE_LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// Three poll cycles of the service.
#[cfg(feature = "service")]
const SERVICE_STAY_LISTED: Duration = Duration::from_secs(6);

/// `tr(<SEED_A account>/<0;1>/*,pk(<cosigner>/<0;1>/*))`
fn plain_tr_policy() -> String {
    let cosigner = cosigner_origin(COSIGNER_FINGERPRINT, ACCOUNT_PATH);
    format!(
        "tr([{SEED_A_FINGERPRINT}/87'/1'/0']{SEED_A_BIP87_TPUB}/<0;1>/*,pk({cosigner}/<0;1>/*))"
    )
}

/// Enrolls `plain_tr_policy` with an approver running and waits until it is listed.
fn enroll_plain_tr(sim: &SimProcess, cc: &Coldcard) -> String {
    let policy = plain_tr_policy();
    let approver = Approver::spawn(sim.socket());
    assert_eq!(cc.register_wallet(WALLET_NAME, &policy).unwrap(), None);

    let deadline = Instant::now() + REGISTERED_TIMEOUT;
    while !matches!(cc.is_wallet_registered(WALLET_NAME, &policy), Ok(true)) {
        assert!(
            Instant::now() < deadline,
            "{WALLET_NAME} not registered after {REGISTERED_TIMEOUT:?}"
        );
        thread::sleep(Duration::from_millis(500));
    }

    let stories = approver.stories();
    println!("stories seen while enrolling: {stories:#?}");
    assert!(stories
        .iter()
        .any(|(title, body)| title.contains("miniscript") || body.contains("miniscript")));
    policy
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_connects() {
    let sim = SimProcess::start(SEED_A);
    let cc = Coldcard::connect_simulator(sim.socket()).unwrap();
    assert_eq!(cc.device_kind(), DeviceKind::ColdcardSimulator);
    let fingerprint = cc.get_master_fingerprint().unwrap();
    println!("master fingerprint: {fingerprint}");
    assert_eq!(
        fingerprint,
        Fingerprint::from_hex(SEED_A_FINGERPRINT).unwrap()
    );
    println!("version: {:?}", cc.get_version());
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_xpub() {
    let sim = SimProcess::start(SEED_A);
    let cc = Coldcard::connect_simulator(sim.socket()).unwrap();

    let account = cc
        .get_extended_pubkey(&DerivationPath::from_str(ACCOUNT_PATH).unwrap())
        .unwrap();
    assert_eq!(account, Xpub::from_str(SEED_A_BIP87_TPUB).unwrap());

    let child = cc
        .get_extended_pubkey(&DerivationPath::from_str("m/87'/1'/0'/2").unwrap())
        .unwrap();
    println!("m/87'/1'/0'/2: {child}");
    assert_eq!(child.parent_fingerprint, account.fingerprint());
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_enrolls_plain_tr() {
    let sim = SimProcess::start(SEED_A);
    let cc = Coldcard::connect_simulator(sim.socket()).unwrap();
    let policy = enroll_plain_tr(&sim, &cc);
    assert!(cc.is_wallet_registered(WALLET_NAME, &policy).unwrap());
}

#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_signs_plain_psbt() {
    let sim = SimProcess::start(SEED_A);
    let cc = Coldcard::connect_simulator(sim.socket()).unwrap();
    let policy = enroll_plain_tr(&sim, &cc);

    let mut psbt = build_tr_keypath_test_psbt(
        &policy,
        // declaration order: the internal key, then the leaf keys
        &[
            KeyOrigin::new(SEED_A_FINGERPRINT, ACCOUNT_PATH),
            KeyOrigin::new(COSIGNER_FINGERPRINT, ACCOUNT_PATH),
        ],
    );
    // the fixture pays an 11% fee, the Coldcard refuses more than 10%
    psbt.unsigned_tx.output[0].value = Amount::from_sat(9_500);
    let cc = cc.with_wallet_name(WALLET_NAME.to_owned());
    let approver = Approver::spawn(sim.socket());
    cc.sign_tx(&mut psbt).unwrap();
    println!("stories seen while signing: {:#?}", approver.stories());
    drop(approver);

    let input = &psbt.inputs[0];
    let sig = input.tap_key_sig.unwrap();
    let utxo = input.witness_utxo.clone().unwrap();
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[utxo.clone()]), sig.sighash_type)
        .unwrap();
    let output_key = XOnlyPublicKey::from_slice(&utxo.script_pubkey.as_bytes()[2..34]).unwrap();
    Secp256k1::verification_only()
        .verify_schnorr(
            &sig.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key,
        )
        .unwrap();
    println!("key path signature verified against {output_key}");
}

#[cfg(feature = "service")]
/// The test only reads the device map, so the messages are dropped.
#[derive(Debug, Clone)]
struct ServiceMessage;

#[cfg(feature = "service")]
impl From<SigningDeviceMsg> for ServiceMessage {
    fn from(_: SigningDeviceMsg) -> Self {
        ServiceMessage
    }
}

#[cfg(feature = "service")]
#[test]
#[ignore = "needs COLDCARD_SIM_UNIX_DIR and COLDCARD_SIM_PYTHON"]
fn coldcard_sim_service_lists_simulator() {
    let sim = SimProcess::start(SEED_A);
    // tests run single threaded, nothing else reads the environment meanwhile
    std::env::set_var(COLDCARD_SIMULATOR_ENV, sim.socket());

    let service: HwiService<ServiceMessage> = HwiService::new(Network::Testnet);
    let (sender, _receiver) = crossbeam::channel::unbounded();
    service.start(sender);

    let expected = Fingerprint::from_hex(SEED_A_FINGERPRINT).unwrap();
    let deadline = Instant::now() + SERVICE_LIST_TIMEOUT;
    let device = loop {
        if let Some(device) = service.list().remove("coldcard-simulator") {
            break device;
        }
        assert!(
            Instant::now() < deadline,
            "coldcard-simulator not listed after {SERVICE_LIST_TIMEOUT:?}"
        );
        thread::sleep(Duration::from_millis(500));
    };
    // the HID cleanup of the next poll cycles must keep it
    thread::sleep(SERVICE_STAY_LISTED);
    assert!(service.list().contains_key("coldcard-simulator"));
    service.stop();
    std::env::remove_var(COLDCARD_SIMULATOR_ENV);

    println!(
        "listed: {} {:?} {:?}",
        device.id(),
        device.kind(),
        device.fingerprint()
    );
    assert!(device.is_supported());
    assert_eq!(device.fingerprint(), Some(expected));
    assert_eq!(device.kind(), &DeviceKind::ColdcardSimulator);
}
