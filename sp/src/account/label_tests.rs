use std::{fs, path::Path};

use bitcoin::{Network, OutPoint};
use bwk::{
    bwk_electrum::label_store::LabelKey,
    persist::{PersistError, PersistenceKind},
};
use bwk_utils::test::temp_dir::TempDir;

use crate::account::{config::Config, Account, AccountError};

fn update(account: &Account, key: &LabelKey, label: &str) -> Result<(), AccountError> {
    match key {
        LabelKey::OutPoint(outpoint) => account.try_update_coin_label(*outpoint, label.into()),
        LabelKey::Transaction(txid) => account.try_update_tx_label(*txid, label.into()),
        LabelKey::Address(_) => unreachable!(),
    }
}

fn with_read_only_dir<T>(dir: &Path, action: impl FnOnce() -> T) -> T {
    let permissions = fs::metadata(dir).unwrap().permissions();
    let mut readonly = permissions.clone();
    readonly.set_readonly(true);
    fs::set_permissions(dir, readonly).unwrap();
    let result = action();
    fs::set_permissions(dir, permissions).unwrap();
    result
}

fn check_label_write_retry(key: LabelKey, value: &str) {
    let dir = TempDir::new().unwrap();
    let mut config = Config::new(
        "labels".into(),
        Network::Regtest,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .into(),
        "http://127.0.0.1:1".into(),
        dir.path().to_path_buf(),
    )
    .unwrap()
    .with_persistence(Some(PersistenceKind::Json));
    config.header_scanner = false;
    let open = || Account::new(config.clone()).unwrap();
    let account = open();
    update(&account, &key, "old").unwrap();
    let expected = (!value.is_empty()).then_some(value);
    with_read_only_dir(&config.account_dir(), || {
        assert!(matches!(
            update(&account, &key, value),
            Err(AccountError::Persist(PersistError::Io(_)))
        ));
        assert_eq!(
            account.label_store.lock().unwrap().get(&key).as_deref(),
            expected
        );
        // Drop also flushes: keep the directory read-only until it releases the lock.
        drop(account);
    });

    let account = open();
    assert_eq!(
        account.label_store.lock().unwrap().get(&key).as_deref(),
        Some("old")
    );
    assert!(matches!(
        with_read_only_dir(&config.account_dir(), || update(&account, &key, value)),
        Err(AccountError::Persist(PersistError::Io(_)))
    ));
    update(&account, &key, value).unwrap();
    drop(account);

    let account = open();
    assert_eq!(
        account.label_store.lock().unwrap().get(&key).as_deref(),
        expected
    );
}

#[test]
fn label_write_errors_survive_retry_and_reopen() {
    let outpoint = OutPoint::null();
    for key in [
        LabelKey::OutPoint(outpoint),
        LabelKey::Transaction(outpoint.txid),
    ] {
        for value in ["new", ""] {
            check_label_write_retry(key.clone(), value);
        }
    }
}
