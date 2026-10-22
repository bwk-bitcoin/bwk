#![cfg(feature = "mnemonic")]

use std::sync::{Arc, Mutex};

use bitcoin::{
    absolute,
    hashes::Hash,
    key::TweakedPublicKey,
    secp256k1::{Scalar, Secp256k1},
    transaction, Amount, Network, OutPoint, Transaction, TxOut, Txid,
};
use bwk::{
    bwk_electrum::{
        header_store::HeaderStore,
        label_store::LabelKey,
        persistence::{test_support::CallerFactory, BackendIdentity, BackendKind},
    },
    persist::{
        backend::PersistenceBackend,
        config_store::{CallbackConfigStore, ConfigStore, NoopConfigStore},
        PersistError, ACCOUNT_STORE_KEY, BLOCK_HASHES_STORE_KEY, COINS_STORE_KEY,
        HEADERS_STORE_KEY, LABELS_STORE_KEY, STATUSES_STORE_KEY, TRANSACTIONS_STORE_KEY,
        TXS_STORE_KEY,
    },
};
use bwk_sp::{
    account::{
        coin_store::SpCoinStore,
        config::Config,
        tx_store::{SpTxEntry, SpTxStore},
        Account, AccountError,
    },
    receiver::{OutputSpendStatus, OwnedOutput},
    scan::{state::ScanState, ScanRuntimeConfig},
};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn config(name: &str) -> Config {
    let mut config = Config::new(
        name.into(),
        Network::Regtest,
        MNEMONIC.into(),
        "http://127.0.0.1:1".into(),
        std::env::temp_dir().join(format!("bwk-caller-{}-{name}", std::process::id())),
    )
    .unwrap();
    config.persistence = None;
    config.add_default_segwit_sub_account().unwrap();
    config.add_default_taproot_sub_account().unwrap();
    config
}

fn identity(account: &str, kind: BackendKind) -> BackendIdentity {
    BackendIdentity {
        account: account.into(),
        network: Network::Regtest,
        kind,
    }
}

fn open(config: Config, factory: Arc<CallerFactory>) -> Result<Account, AccountError> {
    Account::with_backend_factory(
        config,
        factory,
        Arc::new(NoopConfigStore::new()),
        None,
        ScanRuntimeConfig::default(),
    )
}

fn funding(script_pubkey: bitcoin::ScriptBuf, sats: u64) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey,
        }],
    }
}

fn lifecycle(whole_file: bool, name: &str) {
    let factory = Arc::new(CallerFactory::new(whole_file));
    let mut config = config(name);
    if whole_file {
        config.persistence = Some(bwk::persist::PersistenceKind::Json);
    }
    let native_path = config.data_dir.clone();
    assert!(!native_path.exists());
    let root = factory.backend(identity(name, BackendKind::SilentPayment));
    let secp = Secp256k1::new();
    let spend_key = config.descriptor.spend_public_key(&secp).unwrap();
    let output_key = spend_key
        .add_exp_tweak(&secp, &Scalar::from_be_bytes([1; 32]).unwrap())
        .unwrap()
        .x_only_public_key()
        .0;
    let script = bitcoin::ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
        output_key,
    ));
    let tx = funding(script.clone(), 42000);
    let outpoint = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    // Populate public domain stores through the same injected backend as the account.
    let mut coins: SpCoinStore =
        SpCoinStore::load_from_backend(root.clone(), COINS_STORE_KEY).unwrap();
    coins.insert(
        outpoint,
        OwnedOutput {
            blockheight: None,
            tweak: [1; 32],
            amount: Amount::from_sat(42000),
            script,
            label: None,
            spend_status: OutputSpendStatus::Unspent,
        },
    );
    coins.try_persist().unwrap();
    let mut txs: SpTxStore = SpTxStore::load_from_backend(root.clone(), TXS_STORE_KEY).unwrap();
    txs.insert(SpTxEntry::with_tx(outpoint.txid, tx));
    txs.try_persist().unwrap();
    let mut state = ScanState::load_from_backend(0, root.clone()).unwrap();
    state.advance_frontier(19, [19; 32]);
    state.advance_spend_frontier(17);
    state.try_persist().unwrap();

    let saved = Arc::new(Mutex::new(None));
    let sink = saved.clone();
    let source = saved.clone();
    let store: Arc<dyn ConfigStore<Config>> = Arc::new(CallbackConfigStore::new(
        move |config: &Config| {
            *sink.lock().unwrap() = Some(config.clone());
            Ok(())
        },
        move || Ok(source.lock().unwrap().clone()),
    ));
    let shared = HeaderStore::new_in_memory(Network::Regtest);
    let mut account = Account::with_backend_factory(
        config,
        factory.clone(),
        store.clone(),
        Some(shared.clone()),
        ScanRuntimeConfig::default(),
    )
    .unwrap();
    assert_eq!(account.coins()[&outpoint].amount_sat(), 42000);
    assert_eq!(account.tx_history()[0].txid, outpoint.txid);
    account
        .try_update_coin_label(outpoint, "SP funded".into())
        .unwrap();
    let mut sub_funding = Vec::new();
    for (index, scanner) in account.scanners_mut().enumerate() {
        let script = scanner.new_recv_addr().script_pubkey();
        let tx = funding(script, 50000 + index as u64);
        let txid = tx.compute_txid();
        scanner.record_unconfirmed_spend(&tx);
        scanner
            .try_update_coin_label(OutPoint { txid, vout: 0 }, format!("sub {index}"))
            .unwrap();
        sub_funding.push(txid);
    }
    let mut extra = account.get_config();
    extra.add_default_taproot_sub_account().unwrap();
    account
        .create_sub_account(extra.descriptors.pop().unwrap())
        .unwrap();
    assert_eq!(account.scanners().count(), 3);
    account.new_taproot_address().unwrap();
    account.try_persist().unwrap();
    let runtime = account.get_config();
    assert!(runtime.backend_factory.is_some());
    let metadata = serde_json::to_vec(&runtime).unwrap();
    let decoded: Config = serde_json::from_slice(&metadata).unwrap();
    assert!(decoded.backend_factory.is_none());
    assert!(!String::from_utf8(metadata)
        .unwrap()
        .contains("backend_factory"));
    drop(account);

    let mut reopened =
        Account::with_config_store(store.load().unwrap().unwrap(), store.clone()).unwrap();
    assert_eq!(reopened.scanners().count(), 3);
    assert_eq!(reopened.coins()[&outpoint].amount_sat(), 42000);
    assert_eq!(reopened.tx_history()[0].txid, outpoint.txid);
    for (index, scanner) in reopened.scanners().take(2).enumerate() {
        assert_eq!(scanner.tx_history()[0].txid(), sub_funding[index]);
        assert_eq!(scanner.coins().len(), 1);
        let key = LabelKey::OutPoint(OutPoint {
            txid: sub_funding[index],
            vout: 0,
        });
        assert_eq!(
            scanner.label_store().lock().unwrap().get(&key),
            Some(format!("sub {index}"))
        );
    }
    reopened.try_persist().unwrap();
    assert_eq!(
        ScanState::load_from_backend(0, root.clone())
            .unwrap()
            .last_spend_height(),
        Some(17)
    );
    assert_eq!(
        ScanState::load_from_backend(0, root.clone())
            .unwrap()
            .block_hashes()
            .get(&19),
        Some(&[19; 32])
    );
    assert!(!root.get_rows(LABELS_STORE_KEY).unwrap().is_empty());
    let requests = factory.requests.lock().unwrap();
    assert!(requests
        .iter()
        .any(|id| *id == identity(&format!("{name}-sub-2"), BackendKind::SubAccount(2))));
    // The reopen owns its own caller-backed header cache, unlike the shared first open.
    assert!(requests
        .iter()
        .any(|id| *id == identity(name, BackendKind::Headers)));
    assert!(!native_path.exists());
}

#[test]
fn memory_lifecycle() {
    lifecycle(false, "memory-lifecycle");
}

#[test]
fn whole_file_lifecycle() {
    lifecycle(true, "whole-file-lifecycle");
}

#[test]
fn every_backend_open_failure_propagates() {
    for kind in [
        BackendKind::SilentPayment,
        BackendKind::SubAccount(0),
        BackendKind::SubAccount(1),
        BackendKind::Headers,
    ] {
        let factory = Arc::new(CallerFactory::new(true));
        *factory.fail_open.lock().unwrap() = Some(kind);
        let result = open(config("open-failure"), factory);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("open denied"));
    }
}

#[test]
fn every_store_read_failure_propagates() {
    for (kind, account, stores) in [
        (
            BackendKind::SilentPayment,
            "read-failure",
            &[
                COINS_STORE_KEY,
                LABELS_STORE_KEY,
                TXS_STORE_KEY,
                ACCOUNT_STORE_KEY,
                BLOCK_HASHES_STORE_KEY,
            ][..],
        ),
        (
            BackendKind::SubAccount(0),
            "read-failure-sub-0",
            &[
                TRANSACTIONS_STORE_KEY,
                LABELS_STORE_KEY,
                STATUSES_STORE_KEY,
                ACCOUNT_STORE_KEY,
            ][..],
        ),
        (
            BackendKind::Headers,
            "read-failure",
            &[HEADERS_STORE_KEY][..],
        ),
    ] {
        for store in stores {
            let factory = Arc::new(CallerFactory::new(true));
            *factory
                .backend(identity(account, kind))
                .fail_read
                .lock()
                .unwrap() = Some((*store).into());
            let result = open(config("read-failure"), factory);
            assert!(result
                .err()
                .unwrap()
                .to_string()
                .contains(&format!("read denied: {store}")));
        }
    }
}

#[test]
fn corrupt_custom_blob_is_an_error() {
    for (kind, account, store) in [
        (BackendKind::SilentPayment, "corrupt", COINS_STORE_KEY),
        (
            BackendKind::SubAccount(0),
            "corrupt-sub-0",
            TRANSACTIONS_STORE_KEY,
        ),
        (BackendKind::Headers, "corrupt", HEADERS_STORE_KEY),
    ] {
        let factory = Arc::new(CallerFactory::new(true));
        factory.backend(identity(account, kind)).corrupt(store);
        assert!(open(config("corrupt"), factory).is_err());
    }
}

#[test]
fn new_sub_account_failure_and_flush_retry() {
    let factory = Arc::new(CallerFactory::new(true));
    let mut account = open(config("retry"), factory.clone()).unwrap();
    let sub = account.get_config().descriptors[0].clone();
    *factory.fail_open.lock().unwrap() = Some(BackendKind::SubAccount(2));
    assert!(account.create_sub_account(sub.clone()).is_err());
    assert_eq!(account.scanners().count(), 2);
    assert_eq!(account.get_config().descriptors.len(), 2);
    *factory.fail_open.lock().unwrap() = None;
    account.create_sub_account(sub).unwrap();
    let root = factory.backend(identity("retry", BackendKind::SilentPayment));
    *root.fail_write.lock().unwrap() = Some(LABELS_STORE_KEY.into());
    let outpoint = OutPoint {
        txid: Txid::all_zeros(),
        vout: 3,
    };
    assert!(account
        .try_update_coin_label(outpoint, "retry me".into())
        .is_err());
    assert!(account.try_persist().is_err());
    *root.fail_write.lock().unwrap() = None;
    account.try_persist().unwrap();
    let config = account.get_config();
    drop(account);
    let mut reopened = Account::new(config).unwrap();
    assert_eq!(reopened.scanners().count(), 3);
    assert_eq!(root.get_rows(LABELS_STORE_KEY).unwrap().len(), 1);
    reopened.try_persist().unwrap();
}

#[test]
fn config_callback_failure_is_returned_and_retryable() {
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
    let mut account = Account::with_backend_factory(
        config("config-failure"),
        factory,
        store,
        None,
        ScanRuntimeConfig::default(),
    )
    .unwrap();
    assert!(
        matches!(account.try_persist(), Err(AccountError::Persist(PersistError::Io(message))) if message == "config denied")
    );
    let sub = account.get_config().descriptors[0].clone();
    assert!(
        matches!(account.create_sub_account(sub), Err(AccountError::Persist(PersistError::Io(message))) if message == "config denied")
    );
    assert_eq!(account.scanners().count(), 3);
    assert_eq!(account.get_config().descriptors.len(), 3);
    *refused.lock().unwrap() = false;
    account.try_persist().unwrap();
}

#[test]
fn managed_creation_refuses_untracked_external_scanners() {
    let factory = Arc::new(CallerFactory::new(true));
    let mut account = open(config("untracked"), factory).unwrap();
    let mut config = account.scanners().next().unwrap().config().clone();
    config.account = "external-scanner".into();
    let scanner = bwk::bwk_electrum::scanner::ElectrumScanner::try_new(config).unwrap();
    account.add_sub_account(scanner, None).unwrap();
    let sub = account.get_config().descriptors[0].clone();
    assert!(matches!(
        account.create_sub_account(sub),
        Err(AccountError::UntrackedSubAccounts)
    ));
    assert_eq!(account.scanners().count(), 3);
    assert_eq!(account.get_config().descriptors.len(), 2);
}
