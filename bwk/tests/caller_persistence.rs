#![cfg(feature = "test")]

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bwk::{account::Account, config::Config};
use bwk_electrum::{
    header_store::HeaderStore,
    persistence::{test_support::CallerFactory, BackendIdentity, BackendKind},
};
use bwk_persist::{
    backend::PersistenceBackend,
    config_store::{CallbackConfigStore, NoopConfigStore},
    PersistError, ACCOUNT_STORE_KEY, LABELS_STORE_KEY, TRANSACTIONS_STORE_KEY,
};
use bwk_utils::test::{
    electrsd::bitcoind::bitcoincore_rpc::{jsonrpc::serde_json::Value, RpcApi},
    regtest::{bootstrap_electrs, generate, wait_until},
};
use miniscript::bitcoin::{
    absolute,
    bip32::{Xpriv, Xpub},
    secp256k1::Secp256k1,
    transaction, Amount, Network, OutPoint, Transaction, TxOut,
};

fn xpub(seed: u8) -> Xpub {
    Xpub::from_priv(
        &Secp256k1::new(),
        &Xpriv::new_master(Network::Regtest, &[seed; 32]).unwrap(),
    )
}

fn identity(name: &str, kind: BackendKind) -> BackendIdentity {
    BackendIdentity {
        account: name.into(),
        network: Network::Regtest,
        kind,
    }
}

fn config(name: &str, descriptor: &str) -> Config {
    let mut config = Config::new_from_descriptor(
        None,
        name.into(),
        Network::Regtest,
        descriptor,
        std::env::temp_dir().join(format!("bwk-caller-{}-{name}", std::process::id())),
        "not-a-native-wallet".into(),
        None,
    )
    .unwrap();
    config.scanner.set_stay_offline(true);
    config
}

fn lifecycle(name: &str, descriptor: &str, whole_file: bool) {
    let mut config = config(name, descriptor);
    if whole_file {
        config.scanner.persistence = Some(bwk_persist::PersistenceKind::Json);
    }
    let path = config.scanner.account_dir();
    assert!(!path.exists());
    let factory = Arc::new(CallerFactory::new(whole_file));
    let shared = HeaderStore::new_in_memory(Network::Regtest);
    let mut account: Account = Account::try_with_backend_factory(
        config,
        factory.clone(),
        Arc::new(NoopConfigStore::new()),
        Some(shared.clone()),
    )
    .unwrap();
    assert!(!factory
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|id| id.kind == BackendKind::Headers));
    let address = account.scanner_mut().new_recv_addr();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(73000),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let outpoint = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    account.scanner().record_unconfirmed_spend(&tx);
    account
        .scanner()
        .try_update_coin_label(outpoint, "caller funded".into())
        .unwrap();
    let last_address = account.scanner_mut().new_addr();
    account.try_persist().unwrap();
    assert_eq!(account.scanner().coins().len(), 1);
    let config = account.get_config();
    assert!(config.scanner.backend_factory.is_some());
    let metadata = serde_json::to_vec(&config).unwrap();
    let mut decoded: Config = serde_json::from_slice(&metadata).unwrap();
    assert!(decoded.scanner.backend_factory.is_none());
    drop(account);
    let mut reopened: Account = Account::try_new(config).unwrap();
    assert_eq!(
        reopened.scanner().coins()[&outpoint]
            .coin
            .txout
            .value
            .to_sat(),
        73000
    );
    assert_eq!(reopened.scanner().tx_history()[0].tx(), &tx);
    assert_eq!(
        reopened.scanner_mut().new_addr().index,
        last_address.index + 1
    );
    reopened.try_persist().unwrap();
    let backend = factory.backend(identity(name, BackendKind::Wallet));
    for store in [ACCOUNT_STORE_KEY, LABELS_STORE_KEY, TRANSACTIONS_STORE_KEY] {
        assert!(!backend.get_rows(store).unwrap().is_empty());
    }
    drop(reopened);
    // Deserialized metadata needs the runtime provider reattached explicitly.
    decoded.scanner.set_stay_offline(true);
    let reopened: Account =
        Account::try_with_backend_factory(decoded, factory, Arc::new(NoopConfigStore::new()), None)
            .unwrap();
    assert_eq!(
        reopened.scanner().coins()[&outpoint]
            .coin
            .txout
            .value
            .to_sat(),
        73000
    );
    assert!(!path.exists());
}

#[test]
fn descriptor_wallet_memory_lifecycle() {
    lifecycle(
        "descriptor-memory",
        &format!("wpkh({}/<0;1>/*)", xpub(1)),
        false,
    );
}

#[test]
fn descriptor_wallet_whole_file_lifecycle() {
    lifecycle(
        "descriptor-whole-file",
        &format!("wpkh({}/<0;1>/*)", xpub(1)),
        true,
    );
}

#[cfg(feature = "musig")]
#[test]
fn musig_whole_file_lifecycle() {
    lifecycle(
        "musig-whole-file",
        &format!("tr(musig({},{})/<0;1>/*)", xpub(1), xpub(2)),
        true,
    );
}

#[test]
fn factory_and_initial_tip_flush_failures_propagate() {
    for kind in [BackendKind::Wallet, BackendKind::Headers] {
        let factory = Arc::new(CallerFactory::new(true));
        *factory.fail_open.lock().unwrap() = Some(kind);
        let result: Result<Account, _> = Account::try_with_backend_factory(
            config("open-failure", &format!("wpkh({}/<0;1>/*)", xpub(1))),
            factory,
            Arc::new(NoopConfigStore::new()),
            None,
        );
        assert!(result.unwrap_err().to_string().contains("open denied"));
    }
    let factory = Arc::new(CallerFactory::new(true));
    *factory
        .backend(identity("tip-failure", BackendKind::Wallet))
        .fail_write
        .lock()
        .unwrap() = Some(ACCOUNT_STORE_KEY.into());
    let result: Result<Account, _> = Account::try_with_backend_factory(
        config("tip-failure", &format!("wpkh({}/<0;1>/*)", xpub(1))),
        factory,
        Arc::new(NoopConfigStore::new()),
        None,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("write denied: account"));
}

#[test]
fn config_and_wallet_flush_failures_are_retryable() {
    let factory = Arc::new(CallerFactory::new(true));
    let refused = Arc::new(Mutex::new(true));
    let flag = refused.clone();
    let store = Arc::new(CallbackConfigStore::new(
        move |_: &Config| {
            if *flag.lock().unwrap() {
                Err(PersistError::Io("config denied".into()))
            } else {
                Ok(())
            }
        },
        || Ok(None),
    ));
    let mut account: Account = Account::try_with_backend_factory(
        config("flush-failure", &format!("wpkh({}/<0;1>/*)", xpub(1))),
        factory.clone(),
        store,
        None,
    )
    .unwrap();
    assert_eq!(
        account.try_persist(),
        Err(PersistError::Io("config denied".into()))
    );
    *refused.lock().unwrap() = false;
    account.try_persist().unwrap();
    let backend = factory.backend(identity("flush-failure", BackendKind::Wallet));
    *backend.fail_write.lock().unwrap() = Some(ACCOUNT_STORE_KEY.into());
    account.scanner_mut().new_recv_addr();
    assert_eq!(
        account.try_persist(),
        Err(PersistError::Io("write denied: account".into()))
    );
    *backend.fail_write.lock().unwrap() = None;
    account.try_persist().unwrap();
}

fn funded_reopen(name: &str, descriptor: &str) {
    let (url, port, _electrs, bitcoind) = bootstrap_electrs();
    let factory = Arc::new(CallerFactory::new(true));
    let mut config = config(name, descriptor);
    config.scanner.set_stay_offline(false);
    config.scanner.set_electrum(Some(url), Some(port));
    let path = config.scanner.account_dir();
    let mut account: Account = Account::try_with_backend_factory(
        config,
        factory.clone(),
        Arc::new(NoopConfigStore::new()),
        None,
    )
    .unwrap();
    let address = account.scanner_mut().new_recv_addr();
    let txid: String = bitcoind
        .client
        .call(
            "sendtoaddress",
            &[
                Value::String(address.to_string()),
                Value::from(Amount::from_sat(73000).to_btc()),
            ],
        )
        .unwrap();
    let txid = miniscript::bitcoin::Txid::from_str(&txid).unwrap();
    generate(&bitcoind, 1);
    assert!(wait_until(Duration::from_secs(30), || account
        .scanner()
        .coins()
        .values()
        .any(
            |entry| entry.coin.outpoint.txid == txid && entry.coin.height.is_some()
        )));
    let coin = account
        .scanner()
        .coins()
        .into_values()
        .find(|entry| entry.coin.outpoint.txid == txid)
        .unwrap()
        .coin;
    assert_eq!(coin.txout.value.to_sat(), 73000);
    account
        .scanner()
        .try_update_coin_label(coin.outpoint, "mined funding".into())
        .unwrap();
    account.stop_electrum();
    account.try_persist().unwrap();
    let mut config = account.get_config();
    config.scanner.set_stay_offline(true);
    drop(account);
    let mut reopened: Account = Account::try_new(config).unwrap();
    assert_eq!(
        reopened.scanner().coins()[&coin.outpoint]
            .coin
            .txout
            .value
            .to_sat(),
        73000
    );
    assert_eq!(
        reopened.scanner().coins()[&coin.outpoint].coin.height,
        coin.height
    );
    reopened.try_persist().unwrap();
    assert!(!factory
        .backend(identity(name, BackendKind::Headers))
        .get_rows(bwk_persist::HEADERS_STORE_KEY)
        .unwrap()
        .is_empty());
    assert!(!factory
        .backend(identity(name, BackendKind::Wallet))
        .get_rows(bwk_persist::STATUSES_STORE_KEY)
        .unwrap()
        .is_empty());
    assert!(!path.exists());
}

#[test]
fn funded_descriptor_wallet_reopens_caller_storage() {
    funded_reopen("funded-descriptor", &format!("wpkh({}/<0;1>/*)", xpub(1)));
}

#[cfg(feature = "musig")]
#[test]
fn funded_musig_wallet_reopens_caller_storage() {
    funded_reopen(
        "funded-musig",
        &format!("tr(musig({},{})/<0;1>/*)", xpub(1), xpub(2)),
    );
}
