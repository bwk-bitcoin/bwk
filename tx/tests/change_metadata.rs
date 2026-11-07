//! A MuSig change output carries what a signer needs to verify it pays back to
//! the wallet: the aggregate internal key, every cosigner's origin and the
//! BIP373 participants, plus the tap tree when there are leaves.
#![cfg(feature = "musig")]

use std::str::FromStr;

use bitcoin::{
    bip32::{DerivationPath, Xpriv, Xpub},
    psbt::Output,
    secp256k1::Secp256k1,
    Network, OutPoint, Sequence, TxOut,
};
use bwk_coin::{
    derive_descriptor, max_input_satisfaction_size, Coin, CoinSpendInfo, CoinStatus, KeyChain,
};
use bwk_descriptor::{
    musig::parse_musig_descriptor,
    updater::{to_plain_definite, update_output},
    wallet::WalletDescriptor,
};
use bwk_psbt::musig::musig_output_participants;
use bwk_tx::{recipient::ChangeRecipientProvider, tx_builder::TxBuilder};

fn key(seed: u8) -> String {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, &[seed; 32]).unwrap();
    let path = DerivationPath::from_str("m/87'/1'/0'").unwrap();
    let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap());
    format!("[{}/87'/1'/0']{}", master.fingerprint(&secp), xpub)
}

/// The change output of a one-input spend built from `descriptor` with the
/// change tip at 4, and the fields the updater writes for change index 5.
fn change_output(descriptor: &str) -> (Output, Output) {
    let descriptor: WalletDescriptor = parse_musig_descriptor(descriptor).unwrap();
    let funding = derive_descriptor(&descriptor, KeyChain::Receive, 3).unwrap();
    let coin = Coin {
        txout: TxOut {
            value: bitcoin::Amount::from_sat(1_000_000),
            script_pubkey: to_plain_definite(&funding).unwrap().script_pubkey(),
        },
        outpoint: OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001:0",
        )
        .unwrap(),
        height: Some(1),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        status: CoinStatus::Confirmed,
        label: None,
        satisfaction_size: max_input_satisfaction_size(&descriptor) as u64,
        spend_info: CoinSpendInfo::Bip32 {
            coin_path: (KeyChain::Receive, 3),
            descriptor: descriptor.clone(),
        },
    };
    let change = ChangeRecipientProvider::new(descriptor.clone(), Network::Regtest).tip(4);
    let mut builder = TxBuilder::new(Box::new(change)).feerate(2_000);
    let external = bitcoin::Address::from_str("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")
        .unwrap()
        .assume_checked();
    builder.send_to(external, 300_000);
    builder.add_input(coin);
    let mut psbt = builder.generate().unwrap();

    let definite = derive_descriptor(&descriptor, KeyChain::Change, 5).unwrap();
    let spk = to_plain_definite(&definite).unwrap().script_pubkey();
    let index = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("the change pays the next change index");
    let built = psbt.outputs[index].clone();
    psbt.outputs[index] = Output::default();
    update_output(&mut psbt, index, &definite).unwrap();
    (built, psbt.outputs[index].clone())
}

#[test]
fn musig_key_path_change_carries_its_derivation() {
    let (a, b) = (key(1), key(2));
    let (built, expected) = change_output(&format!("tr(musig({a},{b})/<0;1>/*)"));
    assert_eq!(
        built, expected,
        "the change output has the updater's fields"
    );
    assert!(
        built.tap_internal_key.is_some(),
        "the aggregate internal key"
    );
    assert_eq!(
        built.tap_key_origins.len(),
        3,
        "the aggregate and both cosigners"
    );
    assert_eq!(
        musig_output_participants(&built).unwrap().len(),
        1,
        "the BIP373 participants"
    );
}

#[test]
fn musig_change_with_leaves_carries_its_tap_tree() {
    let (a, b, c) = (key(1), key(2), key(3));
    let (built, expected) = change_output(&format!("tr(musig({a},{b})/<0;1>/*,pk({c}/<0;1>/*))"));
    assert_eq!(
        built, expected,
        "the change output has the updater's fields"
    );
    assert!(built.tap_tree.is_some(), "the tap tree");
    assert_eq!(
        built.tap_key_origins.len(),
        4,
        "the aggregate, cosigners and leaf key"
    );
}
