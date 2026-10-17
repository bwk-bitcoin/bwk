//! Ledger as a MuSig2 cosigner next to a bwk `HotSigner`, on 2-of-2 bwk-bup
//! descriptors: `tr(musig(L,H))` spent by the key path and `pk(musig(L,H))` in a
//! leaf under the NUMS internal key. Run with `tests/speculos/run.sh
//! [nanox|nanosp]` (`--test-threads=1`, one Speculos per test).

#![cfg(all(feature = "ledger", feature = "musig"))]

mod common;

use bitcoin::{psbt::Psbt, taproot::TapLeafHash, Network};
use bwk_bup::OXpub;
use bwk_descriptor::wallet::WalletDescriptor;
use bwk_hwi::{
    ledger::{
        bitcoin_client::{
            client::BitcoinClient,
            wallet::{Version as WalletVersion, WalletPolicy, WalletPubKey},
        },
        TransportTcp,
    },
    utils::extract_keys_and_template,
};
use bwk_keys::nums::bip341_nums;
use bwk_psbt::musig::{musig_input_partial_sigs, musig_input_pub_nonces};
use bwk_sign::musig::{musig_status, MusigRound};
use common::{
    musig::{
        derived, finalize_and_verify, key_path_2of2, leaf_2of2, ledger_policy, ledger_role_key,
        ledger_sign_tx, merge_nonces, round1_copy, spend_leaf_hash, spend_psbt, HotCosigner,
        WALLET_NAME,
    },
    speculos::{connect_to, fresh_speculos, register_for_hmac, sign_step_refs, sign_steps},
};
use speculos::{Button, Speculos};

/// The Ledger's role key, the hot cosigner, and the descriptor `shape` builds
/// from both, registered on the device.
struct Setup {
    sim: Speculos,
    ledger_key: OXpub,
    hot: HotCosigner,
    descriptor: WalletDescriptor,
    policy: String,
    hmac: [u8; 32],
}

impl Setup {
    fn new(shape: fn(&OXpub, &OXpub) -> WalletDescriptor) -> Self {
        let sim = fresh_speculos();
        let ledger_key = ledger_role_key(&sim);
        let hot = HotCosigner::new();
        let descriptor = shape(&ledger_key, &hot.key);
        let policy = ledger_policy(&descriptor);
        let steps = register_steps(&policy, &ledger_key);
        let steps: Vec<(&str, Button)> = steps.iter().map(|(s, b)| (s.as_str(), *b)).collect();
        let hmac = register_for_hmac(&sim, connect_to(&sim), WALLET_NAME, &policy, &steps);
        Self {
            sim,
            ledger_key,
            hot,
            descriptor,
            policy,
            hmac,
        }
    }

    /// Ledger round 1 on `round1_copy(psbt)`, its nonces merged into `psbt`. No
    /// screen: the app asks nothing when it only produces pubnonces.
    fn ledger_round1(&self, psbt: &mut Psbt) {
        let (result, signed) =
            ledger_sign_tx(&self.sim, &self.policy, self.hmac, round1_copy(psbt), &[]);
        result.unwrap();
        assert!(!self.screen_seen("Review transaction"));
        merge_nonces(psbt, &signed);
    }

    /// Ledger round 2 on `psbt` as it is, approved on screen.
    fn ledger_round2(&self, psbt: Psbt) -> Psbt {
        let steps = sign_steps(true, true, 2);
        let (result, signed) = ledger_sign_tx(
            &self.sim,
            &self.policy,
            self.hmac,
            psbt,
            &sign_step_refs(&steps),
        );
        result.unwrap();
        signed
    }

    fn hot_sign(&self, psbt: &mut Psbt) {
        self.hot.signer.inner_sign(psbt, &self.descriptor).unwrap();
    }

    fn round(&self, psbt: &Psbt) -> MusigRound {
        musig_status(psbt, &self.descriptor).unwrap().round
    }

    fn screen_seen(&self, text: &str) -> bool {
        self.sim.events().unwrap().iter().any(|e| e.text == text)
    }

    /// The leaf of every Ledger 0x1b of input 0.
    fn ledger_nonce_slots(&self, psbt: &Psbt) -> Vec<Option<TapLeafHash>> {
        musig_input_pub_nonces(&psbt.inputs[0])
            .unwrap()
            .into_iter()
            .filter(|n| n.participant == self.ledger_key.xkey.public_key)
            .map(|n| n.leaf_hash)
            .collect()
    }

    /// The leaf of every Ledger 0x1c of input 0.
    fn ledger_partial_sig_slots(&self, psbt: &Psbt) -> Vec<Option<TapLeafHash>> {
        musig_input_partial_sigs(&psbt.inputs[0])
            .unwrap()
            .into_iter()
            .filter(|s| s.participant == self.ledger_key.xkey.public_key)
            .map(|s| s.leaf_hash)
            .collect()
    }
}

/// The registration screens of `policy`: one "Our key", "Their key" or "Dummy key"
/// (the BIP-341 NUMS point) review per key, in policy order.
fn register_steps(policy: &str, ledger_key: &OXpub) -> Vec<(String, Button)> {
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

/// Registers, then the device's receive address 0 equals bwk's.
fn register_and_check_address(shape: fn(&OXpub, &OXpub) -> WalletDescriptor) {
    let setup = Setup::new(shape);
    let (template, keys) = extract_keys_and_template::<WalletPubKey>(&setup.policy).unwrap();
    let wallet = WalletPolicy::new(WALLET_NAME.into(), WalletVersion::V2, template, keys);
    let client = BitcoinClient::new(TransportTcp::new_on(setup.sim.apdu_addr()).unwrap());
    let address = client
        .get_wallet_address(&wallet, Some(&setup.hmac), false, 0, false)
        .unwrap();
    let expected = derived(&setup.descriptor, 0, 0)
        .address(Network::Testnet)
        .unwrap();
    assert_eq!(address.assume_checked(), expected);
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_musig_register_key_path_2of2() {
    register_and_check_address(key_path_2of2);
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_musig_register_leaf_2of2() {
    register_and_check_address(leaf_2of2);
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_musig_sign_key_path_2of2() {
    let setup = Setup::new(key_path_2of2);
    let mut psbt = spend_psbt(&setup.descriptor);

    setup.ledger_round1(&mut psbt);
    assert_eq!(setup.ledger_nonce_slots(&psbt), vec![None]);
    assert_eq!(setup.round(&psbt), MusigRound::Nonces);
    setup.hot_sign(&mut psbt);
    assert_eq!(musig_input_pub_nonces(&psbt.inputs[0]).unwrap().len(), 2);
    assert_eq!(setup.round(&psbt), MusigRound::PartialSigs);

    let mut psbt = setup.ledger_round2(psbt);
    assert_eq!(setup.ledger_partial_sig_slots(&psbt), vec![None]);
    setup.hot_sign(&mut psbt);
    assert_eq!(setup.round(&psbt), MusigRound::Ready);
    finalize_and_verify(psbt, &setup.descriptor);
}

#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_musig_sign_leaf_2of2() {
    let setup = Setup::new(leaf_2of2);
    let leaf = Some(spend_leaf_hash(&setup.descriptor));
    let mut psbt = spend_psbt(&setup.descriptor);

    setup.hot_sign(&mut psbt);
    assert_eq!(musig_input_pub_nonces(&psbt.inputs[0]).unwrap().len(), 1);
    setup.ledger_round1(&mut psbt);
    assert_eq!(setup.ledger_nonce_slots(&psbt), vec![leaf]);
    assert_eq!(setup.round(&psbt), MusigRound::PartialSigs);

    let mut psbt = setup.ledger_round2(psbt);
    assert_eq!(setup.ledger_partial_sig_slots(&psbt), vec![leaf]);
    setup.hot_sign(&mut psbt);
    assert_eq!(setup.round(&psbt), MusigRound::Ready);
    finalize_and_verify(psbt, &setup.descriptor);
}

/// A PSBT carrying a cosigner's pubnonce makes the app run round 2: after the
/// approval it asks for its own pubnonce, which the PSBT lacks, and the client
/// cannot answer (`Interpreter(UnknownHash)`). Round 1 must go without nonces.
#[test]
#[ignore = "requires SPECULOS_ELF"]
fn speculos_musig_round1_with_a_cosigner_nonce_is_round2() {
    let setup = Setup::new(key_path_2of2);
    let mut psbt = spend_psbt(&setup.descriptor);
    setup.hot_sign(&mut psbt);

    let steps = sign_steps(true, true, 2);
    let (result, signed) = ledger_sign_tx(
        &setup.sim,
        &setup.policy,
        setup.hmac,
        psbt.clone(),
        &sign_step_refs(&steps),
    );
    let error = result.unwrap_err();
    assert!(
        matches!(&error, bwk_hwi::Error::Device(e) if e.contains("UnknownHash")),
        "{error:?}"
    );
    assert!(setup.ledger_nonce_slots(&signed).is_empty());
    assert_eq!(signed, psbt);
}
