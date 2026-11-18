//! The Ledger through `HwiService`: the service finds Speculos on `127.0.0.1:9999`
//! and every request carries its wallet (`DeviceWallet`). Run with
//! `tests/speculos/run.sh [nanox|nanosp]` (`--test-threads=1`, one Speculos per test,
//! never next to another Speculos on port 9999).

#![cfg(all(feature = "service", feature = "ledger"))]

mod common;

use std::str::FromStr;

use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::Psbt,
};
use bwk_hwi::{service::SigningDeviceMsg, AddressScript, DeviceWallet, Error as HWIError};
use common::{
    build_tr_keypath_test_psbt, cosigner_origin,
    speculos::{
        key_origin, service::SpeculosService, sign_step_refs, sign_steps, tr_1leaf_policy,
        DISPLAY_STEPS_TR_1LEAF, REGISTER_STEPS_TR_1LEAF_ACK,
    },
    KeyOrigin, SPECULOS_DEFAULT_FINGERPRINT,
};
use speculos::Button;

#[cfg(feature = "musig")]
use bwk_bup::KeyType;
#[cfg(feature = "musig")]
use bwk_psbt::musig::musig_input_pub_nonces;
#[cfg(feature = "musig")]
use common::{
    musig::{
        cosigner_role_key, finalize_and_verify, key_path_2of2, ledger_account_path, ledger_policy,
        merge_round, register_steps, spend_psbt, without_nonces, HotParticipant,
        APPROVE_XPUB_STEPS, WALLET_NAME,
    },
    speculos::screen_seen,
    SEED_A,
};

const TR_1LEAF_NAME: &str = "tr-1leaf";
const TR_1LEAF_DEVICE_PATH: &str = "m/48h/1h/9h/2h";
const TR_1LEAF_COSIGNER_PATH: &str = "m/48h/1h/8h/2h";
const TR_1LEAF_COSIGNER_FINGERPRINT: &str = "d4ab66f1";

fn speculos_fingerprint() -> Fingerprint {
    Fingerprint::from_hex(SPECULOS_DEFAULT_FINGERPRINT).unwrap()
}

/// The device key at `path`, exported without a screen.
fn device_key(svc: &SpeculosService, id: u64, path: &DerivationPath) -> String {
    match svc.request(id, &[], |device, id| {
        device.get_extended_pubkey(id, path, false)
    }) {
        SigningDeviceMsg::XPub(_, fingerprint, answered, xpub) => {
            assert_eq!(fingerprint, speculos_fingerprint());
            assert_eq!(&answered, path);
            key_origin(fingerprint, path, &xpub)
        }
        other => panic!("get_extended_pubkey: {other:?}"),
    }
}

/// Registers `policy` under `name` through the service, walking `steps`; the HMAC from
/// `WalletRegistered`.
fn register(
    svc: &SpeculosService,
    id: u64,
    name: &str,
    policy: &str,
    steps: &[(&str, Button)],
) -> [u8; 32] {
    match svc.request(id, steps, |device, id| {
        device.register_wallet(id, name, policy)
    }) {
        SigningDeviceMsg::WalletRegistered(_, fingerprint, registered, Some(hmac)) => {
            assert_eq!(fingerprint, speculos_fingerprint());
            assert_eq!(registered, name);
            hmac
        }
        other => panic!("register_wallet: {other:?}"),
    }
}

/// `sign_tx_with_wallet` through the service, walking `steps`; the signed PSBT.
fn sign_with_wallet(
    svc: &SpeculosService,
    id: u64,
    psbt: Psbt,
    wallet: &DeviceWallet,
    steps: &[(&str, Button)],
) -> Psbt {
    match svc.request(id, steps, |device, id| {
        device.sign_tx_with_wallet(id, psbt, wallet.clone())
    }) {
        SigningDeviceMsg::TransactionSigned(_, fingerprint, signed) => {
            assert_eq!(fingerprint, speculos_fingerprint());
            signed
        }
        other => panic!("sign_tx_with_wallet: {other:?}"),
    }
}

/// The `tr(device, and_v(v:pk(cosigner), older(50)))` policy, registered
/// through the service, and its key-path spend PSBT.
fn register_tr_1leaf(svc: &SpeculosService) -> (DeviceWallet, Psbt) {
    let device_path = DerivationPath::from_str(TR_1LEAF_DEVICE_PATH).unwrap();
    let internal = device_key(svc, 1, &device_path);
    let leaf = cosigner_origin(TR_1LEAF_COSIGNER_FINGERPRINT, TR_1LEAF_COSIGNER_PATH);
    let policy = tr_1leaf_policy(&internal, &leaf);
    let hmac = register(svc, 2, TR_1LEAF_NAME, &policy, REGISTER_STEPS_TR_1LEAF_ACK);
    let key_origins = [
        KeyOrigin {
            fingerprint: speculos_fingerprint(),
            account_path: device_path,
        },
        KeyOrigin::new(TR_1LEAF_COSIGNER_FINGERPRINT, TR_1LEAF_COSIGNER_PATH),
    ];
    let psbt = build_tr_keypath_test_psbt(&policy, &key_origins);
    let wallet = DeviceWallet {
        name: TR_1LEAF_NAME.into(),
        policy,
        hmac: Some(hmac),
    };
    (wallet, psbt)
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_service_plain_policy_registers_and_signs() {
    let svc = SpeculosService::launch();
    let (wallet, psbt) = register_tr_1leaf(&svc);

    // Without a wallet the Ledger still cannot sign.
    match svc.request(3, &[], |device, id| device.sign_tx(id, psbt.clone())) {
        SigningDeviceMsg::Error(Some(3), error) => {
            assert_eq!(error, HWIError::UnimplementedMethod.to_string())
        }
        other => panic!("sign_tx: {other:?}"),
    }

    let steps = sign_steps(true, true, 2);
    let signed = sign_with_wallet(&svc, 4, psbt, &wallet, &sign_step_refs(&steps));
    assert!(signed.inputs[0].tap_key_sig.is_some());

    let script = AddressScript::Miniscript {
        index: 0,
        change: false,
    };
    match svc.request(5, DISPLAY_STEPS_TR_1LEAF, |device, id| {
        device.display_address_with_wallet(id, &script, wallet.clone())
    }) {
        SigningDeviceMsg::AddressDisplayed(5, fingerprint, displayed) => {
            assert_eq!(fingerprint, speculos_fingerprint());
            assert_eq!(displayed, script);
        }
        other => panic!("display_address_with_wallet: {other:?}"),
    }
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_service_wrong_hmac_is_refused() {
    let svc = SpeculosService::launch();
    let (wallet, psbt) = register_tr_1leaf(&svc);
    let wallet = DeviceWallet {
        hmac: Some([0; 32]),
        ..wallet
    };
    match svc.request(3, &[], |device, id| {
        device.sign_tx_with_wallet(id, psbt, wallet)
    }) {
        SigningDeviceMsg::Error(Some(3), error) => {
            assert!(error.contains("status: IncorrectData"), "{error}")
        }
        other => panic!("sign_tx_with_wallet with a zeroed HMAC: {other:?}"),
    }
}

#[cfg(feature = "musig")]
#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_service_musig_two_rounds() {
    let svc = SpeculosService::launch();
    // App 2.4.6 refuses the silent export of m/87'/1'/0': the retry shows the path.
    let path = ledger_account_path();
    let ledger_key = match svc.request(1, APPROVE_XPUB_STEPS, |device, id| {
        device.get_extended_pubkey(id, &path, false)
    }) {
        SigningDeviceMsg::XPub(_, fingerprint, _, xpub) => cosigner_role_key(fingerprint, xpub),
        other => panic!("get_extended_pubkey: {other:?}"),
    };
    let hot = HotParticipant::new(SEED_A, KeyType::Internal);
    let descriptor = key_path_2of2(&ledger_key, &hot.key);
    let policy = ledger_policy(&descriptor);
    let steps = register_steps(&policy, &ledger_key);
    let hmac = register(&svc, 2, WALLET_NAME, &policy, &sign_step_refs(&steps));
    let wallet = DeviceWallet {
        name: WALLET_NAME.into(),
        policy,
        hmac: Some(hmac),
    };

    // Round 1 on the copy without nonces: no screen, one Ledger 0x1b.
    let mut psbt = spend_psbt(&descriptor);
    let nonces = sign_with_wallet(&svc, 3, without_nonces(&psbt), &wallet, &[]);
    assert!(!screen_seen(&svc.sim, "Review transaction"));
    merge_round(&mut psbt, &nonces);
    let ledger_nonces = musig_input_pub_nonces(&psbt.inputs[0])
        .unwrap()
        .into_iter()
        .filter(|n| n.participant == ledger_key.xkey.public_key)
        .count();
    assert_eq!(ledger_nonces, 1);
    hot.signer.inner_sign(&mut psbt, &descriptor).unwrap();
    assert_eq!(musig_input_pub_nonces(&psbt.inputs[0]).unwrap().len(), 2);

    // Round 2 with every nonce, approved on screen.
    let steps = sign_steps(true, true, 2);
    let mut psbt = sign_with_wallet(&svc, 4, psbt, &wallet, &sign_step_refs(&steps));
    hot.signer.inner_sign(&mut psbt, &descriptor).unwrap();
    finalize_and_verify(psbt, &descriptor);
}
