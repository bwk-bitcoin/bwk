//! Speculos helpers shared by the Ledger test binaries.

use std::{str::FromStr, time::Duration};

use bitcoin::bip32::DerivationPath;
use bwk_hwi::{ledger::LedgerSimulator, HWI};
use regex::Regex;
use speculos::{Button, Speculos};

/// /reset does not fully clear the embedded app's wallet-policy text
/// buffer or prior register-wallet state, so we boot per-test.
pub fn fresh_speculos() -> Speculos {
    let model = std::env::var("SPECULOS_MODEL")
        .expect("SPECULOS_MODEL")
        .parse::<speculos::Model>()
        .expect("parse model");
    Speculos::launch_model(model).expect("Speculos::launch_model")
}

pub fn connect_to(sim: &Speculos) -> LedgerSimulator {
    LedgerSimulator::try_connect_on(sim.apdu_addr()).expect("connect to Speculos APDU port")
}

pub fn get_xpub_for_path(device: &LedgerSimulator, path: &str) -> String {
    let derivation = DerivationPath::from_str(path).expect("valid derivation path");
    let fp = device
        .get_master_fingerprint()
        .expect("get_master_fingerprint");
    let xpub = device
        .get_extended_pubkey(&derivation)
        .expect("get_extended_pubkey");
    let path_in_origin = derivation.to_string();
    let path_in_origin = path_in_origin.trim_start_matches("m/");
    format!("[{fp:x}/{path_in_origin}]{xpub}")
}

pub fn run_steps(sim: &Speculos, steps: &[(&str, Button)]) {
    for &(text, button) in steps {
        screen_contains(sim, text);
        sim.press(button).unwrap();
    }
}

pub fn screen_contains(sim: &Speculos, expected: &str) {
    let re = Regex::new(&format!("^{}$", regex::escape(expected))).unwrap();
    if sim.wait_for(&re, Duration::from_secs(10)).is_err() {
        let last_screens: Vec<_> = sim
            .events()
            .unwrap()
            .into_iter()
            .rev()
            .take(12)
            .map(|e| e.text)
            .collect();
        let msg = format!(
            "expected screen {expected:?}; recent screens (newest first): {last_screens:?}"
        );
        panic!("{}", msg);
    }
}

/// Register `policy` to ack and return the hmac. Panics on any
/// non-success outcome. Used by display/sign helpers that need a
/// registered wallet before they can exercise their own flow.
pub fn register_for_hmac(
    sim: &Speculos,
    device: LedgerSimulator,
    name: &str,
    policy: &str,
    register_steps: &[(&str, Button)],
) -> [u8; 32] {
    let name = name.to_string();
    let policy = policy.to_string();
    let task = std::thread::spawn(move || device.register_wallet(&name, &policy));
    run_steps(sim, register_steps);
    match task.join().unwrap() {
        Ok(Some(hmac)) => {
            assert_eq!(hmac.len(), 32, "expected 32-byte hmac from register_wallet");
            hmac
        }
        other => {
            let msg = format!("register_for_hmac unexpected outcome: {other:?}");
            panic!("{}", msg);
        }
    }
}

/// Click sequence for a transaction-review flow on Nano X / Nano S Plus.
/// `from_screen=true` adds the multisig "From <wallet-name>" page that
/// the device shows for non-default wallet policies. `to_pages` is the
/// pagination count of the "To" address screen (1 for short bech32
/// wpkh addresses, 2 for longer wsh / taproot addresses).
pub fn sign_steps(ack: bool, from_screen: bool, to_pages: u32) -> Vec<(String, Button)> {
    let mut steps: Vec<(String, Button)> = vec![("Review transaction".into(), Button::Right)];
    if from_screen {
        steps.push(("From".into(), Button::Right));
    }
    steps.push(("Amount".into(), Button::Right));
    if to_pages == 1 {
        steps.push(("To".into(), Button::Right));
    } else {
        for i in 1..=to_pages {
            steps.push((format!("To ({i}/{to_pages})"), Button::Right));
        }
    }
    steps.push(("Fees".into(), Button::Right));
    if ack {
        steps.push(("Sign transaction".into(), Button::Both));
    } else {
        steps.push(("Sign transaction".into(), Button::Right));
        steps.push(("Reject transaction".into(), Button::Both));
    }
    steps
}

pub fn sign_step_refs(steps: &[(String, Button)]) -> Vec<(&str, Button)> {
    steps.iter().map(|(s, b)| (s.as_str(), *b)).collect()
}
