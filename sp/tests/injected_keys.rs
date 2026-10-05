//! A watch-only account (built from the scan key and the public spend key)
//! scans like a hot one and spends only with keys lent for one call.

mod common;

use std::str::FromStr;

use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::{Secp256k1, SecretKey},
    Network,
};
use bwk_sign::hot_signer::HotSigner;
use bwk_sp::account::{
    config::Config,
    spend_keys::{KeyRing, OriginXpriv, SpendKeys},
    Account, AccountError,
};

use common::{bip32_mnemonic, test_mnemonic, test_mnemonic_2, TestEnv};

fn master(mnemonic: &str) -> Xpriv {
    let seed = bip39::Mnemonic::from_str(mnemonic).unwrap().to_seed("");
    Xpriv::new_master(Network::Regtest, &seed).unwrap()
}

fn derive(mnemonic: &str, path: &str) -> SecretKey {
    let secp = Secp256k1::new();
    master(mnemonic)
        .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
        .unwrap()
        .private_key
}

/// The BIP352 scan and spend secrets of `test_mnemonic` on regtest.
fn sp_secrets() -> (SecretKey, SecretKey) {
    (
        derive(test_mnemonic(), "m/352'/1'/0'/1'/0"),
        derive(test_mnemonic(), "m/352'/1'/0'/0'/0"),
    )
}

fn watch_only_config(env: &TestEnv, name: &str) -> Config {
    let secp = Secp256k1::new();
    let (scan_sk, b_spend) = sp_secrets();
    Config::from_keys(
        name.to_string(),
        Network::Regtest,
        hex::encode(scan_sk.secret_bytes()),
        b_spend.public_key(&secp).to_string(),
        env.url(),
        std::path::PathBuf::from("/unused"),
    )
    .unwrap()
    .with_persistence(None)
}

fn watch_only_account(env: &TestEnv, name: &str) -> Account {
    Account::new(watch_only_config(env, name)).unwrap()
}

/// A watch-only account with a taproot sub-account built from its descriptor
/// alone: no mnemonic, so it holds no signer.
fn watch_only_account_with_taproot_sub_account(env: &TestEnv, name: &str) -> Account {
    let signer = HotSigner::new_taproot_from_mnemonics(Network::Regtest, bip32_mnemonic()).unwrap();
    let mut config = watch_only_config(env, name);
    config.add_watch_only_sub_account(signer.descriptors().into_iter().next().unwrap());
    Account::new(config).unwrap()
}

/// The spend authority for `test_mnemonic`'s SP key and the BIP86 account
/// `m/86'/1'/0'` of `bip32_mnemonic` — an account key, not its master.
fn lent_keys() -> SpendKeys {
    let secp = Secp256k1::new();
    let bip32_master = master(bip32_mnemonic());
    let account_path = DerivationPath::from_str("m/86'/1'/0'").unwrap();
    let mut ring = KeyRing::new();
    ring.push(OriginXpriv {
        master_fingerprint: bip32_master.fingerprint(&secp),
        origin_path: account_path.clone(),
        xpriv: bip32_master.derive_priv(&secp, &account_path).unwrap(),
    });
    SpendKeys::new(sp_secrets().1, ring)
}

fn external_address() -> bitcoin::Address {
    let signer =
        HotSigner::new_taproot_from_mnemonics(Network::Regtest, test_mnemonic_2()).unwrap();
    signer.taproot_receive_address_and_key(0).0
}

#[test]
fn a_watch_only_account_has_the_hot_accounts_address() {
    let env = TestEnv::new();
    let hot = env.sp_account("hot");
    let watch = watch_only_account(&env, "watch");

    assert_eq!(watch.sp_address(), hot.sp_address());
    assert!(hot.can_sign());
    assert!(!watch.can_sign());
}

#[test]
fn a_watch_only_account_spends_with_lent_keys_only() {
    let mut env = TestEnv::new();
    let mut watch = watch_only_account_with_taproot_sub_account(&env, "watch-spend");

    env.fund_sp(&mut watch, 0.1);
    assert!(watch.balance() > 0, "the scan key alone finds the payment");

    let coin = env.create_taproot_coin(0.05);
    let funding_tx = bwk_utils::test::get_tx(&mut env.bitcoind.client, coin.outpoint.txid).unwrap();
    watch
        .scanners()
        .next()
        .unwrap()
        .record_unconfirmed_spend(&funding_tx);
    let sp_coins: Vec<_> = watch
        .coins()
        .iter()
        .map(|(outpoint, entry)| bwk_sp::account::sp_coin_entry_to_coin(*outpoint, entry))
        .collect();
    let external = external_address();

    // Without keys the account cannot even build a send: SP change needs the
    // spend authority to derive its output script.
    let mut unkeyed = watch.tx_builder().feerate(1000);
    unkeyed.send_to(external.clone(), 100_000);
    unkeyed.add_input(coin.clone());
    for sp_coin in &sp_coins {
        unkeyed.add_input(sp_coin.clone());
    }
    assert!(unkeyed.generate().is_err());

    let keys = lent_keys();
    let mut builder = watch.tx_builder_with_keys(&keys).unwrap().feerate(1000);
    builder.send_to(external.clone(), 100_000);
    builder.add_input(coin);
    for sp_coin in &sp_coins {
        builder.add_input(sp_coin.clone());
    }
    let mut psbt = builder.generate().unwrap();

    // Signing without the lent keys leaves the inputs unsigned.
    let mut unsigned = psbt.clone();
    assert!(watch.sign_and_finalize(&mut unsigned).is_err());

    let tx = watch.sign_and_finalize_with_keys(&mut psbt, &keys).unwrap();
    assert_eq!(tx.input.len(), 1 + sp_coins.len());
    assert!(tx
        .output
        .iter()
        .any(|o| o.script_pubkey == external.script_pubkey()));

    // bitcoind validates every signature, the SP and the BIP86 ones alike.
    env.broadcast_and_mine(&tx);

    // The watch-only account finds its own SP change.
    let txid = tx.compute_txid();
    watch.scan_blocks(Some(1), Some(env.height)).unwrap();
    assert!(watch
        .coins()
        .iter()
        .any(|(outpoint, entry)| outpoint.txid == txid && entry.label().is_some()));
}

#[test]
fn keys_of_another_account_are_refused() {
    let env = TestEnv::new();
    let watch = watch_only_account(&env, "watch-mismatch");
    let foreign = SpendKeys::new(
        derive(test_mnemonic_2(), "m/352'/1'/0'/0'/0"),
        KeyRing::new(),
    );

    assert!(matches!(
        watch.tx_builder_with_keys(&foreign),
        Err(AccountError::SpendKeyMismatch)
    ));
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
    .unwrap();
    assert!(matches!(
        watch.sign_psbt_with_keys(&mut psbt, &foreign),
        Err(AccountError::SpendKeyMismatch)
    ));
}
