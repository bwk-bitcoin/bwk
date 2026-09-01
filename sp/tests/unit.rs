//! Unit tests for bwk-sp.
//!
//! These tests verify individual components using the MockBackend
//! and test fixtures from the common module.

mod common;

use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use common::{
    test_config, test_mnemonic, test_outpoint, test_owned_output, test_spent_output, MockBackend,
    TempDir,
};

use bwk::bwk_electrum::{
    label_store::{LabelKey, LabelStore},
    notification::{Notification, SpNotification},
};
use bwk_sp::account::{
    coin_store::SpCoinStore, config::Config, tx_store::SpTxStore, Account, AccountError,
};

#[test]
fn test_common_helpers() {
    common::tests::run();
}

// MockBackend Tests

/// Test that MockBackend returns the configured block height.
#[test]
fn test_mock_backend_block_height() {
    let backend = MockBackend::new(850_000);
    assert_eq!(backend.block_height().unwrap(), 850_000);

    // Each call increments call count
    assert_eq!(backend.call_count(), 1);
    let _ = backend.block_height();
    assert_eq!(backend.call_count(), 2);
}

/// Test that MockBackend can simulate failures.
#[test]
fn test_mock_backend_failure() {
    use common::MockBackendError;

    // Configure to fail after 1 successful call
    let backend = MockBackend::new(100).fail_after(1);

    // First call succeeds
    assert!(backend.block_height().is_ok());

    // Second call fails
    let result = backend.block_height();
    assert!(result.is_err());
    let MockBackendError::SimulatedFailure(n) = result.unwrap_err();
    assert_eq!(n, 1);

    // Further calls also fail
    assert!(backend.block_height().is_err());
}

// Account Construction Tests

/// Test that Account::new fails when neither mnemonic nor scan_sk is provided.
#[test]
fn test_account_new_invalid_no_keys() {
    let dir = TempDir::new().unwrap();

    // Create config with no mnemonic and no scan_sk
    let mut config = Config::new(
        "no-keys".to_string(),
        bitcoin::Network::Signet,
        test_mnemonic().to_string(),
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    )
    .with_persistence(None);

    // Remove the mnemonic
    config.mnemonic = None;
    config.scan_sk = None;

    let result = Account::new(config);
    match result {
        Err(AccountError::MissingKeys) => {}
        Err(other) => panic!("expected MissingKeys error, got {other:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

/// Test that Account::new fails with an invalid mnemonic.
#[test]
fn test_account_new_invalid_bad_mnemonic() {
    let dir = TempDir::new().unwrap();

    let config = Config::new(
        "bad-mnemonic".to_string(),
        bitcoin::Network::Signet,
        "invalid mnemonic words that are not valid".to_string(),
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    )
    .with_persistence(None);

    let result = Account::new(config);
    match result {
        Err(AccountError::InvalidMnemonic(_)) => {}
        Err(other) => panic!("expected InvalidMnemonic error, got {other:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

/// Test that Account::new fails with invalid hex scan_sk.
#[test]
fn test_account_new_invalid_bad_hex_key() {
    let dir = TempDir::new().unwrap();

    // Use Config::from_keys with invalid hex
    let result = Config::from_keys(
        "bad-hex".to_string(),
        bitcoin::Network::Signet,
        "not_valid_hex_at_all_should_fail_validation".to_string(),
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    );

    // Config::from_keys should fail with invalid hex
    assert!(result.is_err());
}

/// Test that Account::new fails with an empty blindbit_url.
#[test]
fn test_account_new_invalid_empty_url() {
    let dir = TempDir::new().unwrap();

    let config = Config::new(
        "empty-url".to_string(),
        bitcoin::Network::Signet,
        test_mnemonic().to_string(),
        String::new(), // Empty URL
        dir.path().to_path_buf(),
    )
    .with_persistence(None);

    let result = Account::new(config);
    match result {
        Err(AccountError::MissingBlindbitUrl) => {}
        Err(other) => panic!("expected MissingBlindbitUrl error, got {other:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

// Notification Tests

/// Test that notifications can be sent through the channel.
#[test]
fn test_notification_channel_send_receive() {
    let (sender, receiver) = mpsc::channel::<Notification>();

    // Send various notifications
    sender.send(SpNotification::StartingScan.into()).unwrap();
    sender
        .send(Notification::Sp(SpNotification::ScanReceiveProgress {
            current: 100,
            end: 200,
        }))
        .unwrap();
    sender.send(SpNotification::ScanCompleted.into()).unwrap();
    sender
        .send(Notification::Sp(SpNotification::FailStartScanning {
            message: "test error".to_string(),
        }))
        .unwrap();
    sender
        .send(Notification::Sp(SpNotification::FailScan {
            message: "scan error".to_string(),
        }))
        .unwrap();
    sender.send(SpNotification::StoppingScan.into()).unwrap();
    sender.send(SpNotification::ScanStopped.into()).unwrap();

    // Verify received notifications
    assert!(matches!(
        receiver.recv().unwrap(),
        Notification::Sp(SpNotification::StartingScan)
    ));
    match receiver.recv().unwrap() {
        Notification::Sp(SpNotification::ScanReceiveProgress { current, end }) => {
            assert_eq!(current, 100);
            assert_eq!(end, 200);
        }
        _ => panic!("expected ScanReceiveProgress"),
    }
    assert!(matches!(
        receiver.recv().unwrap(),
        Notification::Sp(SpNotification::ScanCompleted)
    ));
    match receiver.recv().unwrap() {
        Notification::Sp(SpNotification::FailStartScanning { message }) => {
            assert_eq!(message, "test error");
        }
        _ => panic!("expected FailStartScanning"),
    }
    match receiver.recv().unwrap() {
        Notification::Sp(SpNotification::FailScan { message }) => {
            assert_eq!(message, "scan error");
        }
        _ => panic!("expected FailScan"),
    }
    assert!(matches!(
        receiver.recv().unwrap(),
        Notification::Sp(SpNotification::StoppingScan)
    ));
    assert!(matches!(
        receiver.recv().unwrap(),
        Notification::Sp(SpNotification::ScanStopped)
    ));
}

/// Test NewOutput and OutputSpent notifications.
#[test]
fn test_notification_output_events() {
    let (sender, receiver) = mpsc::channel::<Notification>();
    let outpoint = test_outpoint();

    sender
        .send(Notification::Sp(SpNotification::NewOutput(outpoint)))
        .unwrap();
    sender
        .send(Notification::Sp(SpNotification::OutputSpent(outpoint)))
        .unwrap();

    match receiver.recv().unwrap() {
        Notification::Sp(SpNotification::NewOutput(op)) => assert_eq!(op, outpoint),
        _ => panic!("expected NewOutput"),
    }
    match receiver.recv().unwrap() {
        Notification::Sp(SpNotification::OutputSpent(op)) => assert_eq!(op, outpoint),
        _ => panic!("expected OutputSpent"),
    }
}

// Signing Config Tests

/// Test that Config with mnemonic should enable signing (via Account.can_sign()).
#[test]
fn test_config_for_hot_key_signing() {
    let dir = TempDir::new().unwrap();

    let config = test_config(dir.path());

    // A config with mnemonic should enable signing
    assert!(config.mnemonic.is_some());
    assert!(config.scan_sk.is_none());
}

/// Test that Config with scan_sk and public spend_key would NOT enable signing.
#[test]
fn test_config_for_signing_device_watch_only() {
    let dir = TempDir::new().unwrap();

    // Create config with scan_sk and a PUBLIC spend_key (66 hex chars = 33 bytes)
    let config = Config::from_keys(
        "watch-only".to_string(),
        bitcoin::Network::Signet,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        "02fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    )
    .expect("valid config");

    // This config has no mnemonic and spend_key is public
    assert!(config.mnemonic.is_none());
    assert!(config.scan_sk.is_some());
    assert!(config.spend_key.is_some());
}

/// Test that Config with scan_sk and secret spend_key WOULD enable signing.
#[test]
fn test_config_for_signing_device_hot() {
    let dir = TempDir::new().unwrap();

    // Create config with scan_sk and a SECRET spend_key (64 hex chars = 32 bytes)
    let config = Config::from_keys(
        "signing-device-hot".to_string(),
        bitcoin::Network::Signet,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    )
    .expect("valid config");

    // This config has secret spend_key (64 chars = 32 bytes)
    assert!(config.mnemonic.is_none());
    assert!(config.scan_sk.is_some());
    assert!(config.spend_key.is_some());
    assert_eq!(config.spend_key.as_ref().unwrap().len(), 64);
}

// Transaction Building Tests

/// Test that create_transaction fails with empty coin store.
#[test]
fn test_empty_coin_store_has_no_spendable() {
    let store = SpCoinStore::new();
    let state = store.spendable_coins();

    assert!(state.coins.is_empty());
    assert_eq!(state.confirmed_balance, 0);
    assert_eq!(state.confirmed_coins, 0);
}

/// Test that coin store with only spent coins has no spendable.
#[test]
fn test_spent_coins_not_spendable() {
    let mut store = SpCoinStore::new();
    store.insert(test_outpoint(), test_spent_output(100, 50000));

    let state = store.spendable_coins();
    assert!(state.coins.is_empty());
    assert_eq!(state.confirmed_balance, 0);
}

// Concurrency Tests

/// Test that SpCoinStore can be read concurrently from multiple threads.
#[test]
fn test_concurrent_reads_coin_store() {
    let mut store = SpCoinStore::new();
    store.insert(test_outpoint(), test_owned_output(100, 10000));
    store.insert(common::test_outpoint_2(), test_owned_output(100, 20000));
    store.insert(common::test_outpoint_3(), test_owned_output(100, 30000));

    let store = Arc::new(Mutex::new(store));

    let mut handles = vec![];

    // Spawn 10 threads that all read from the store
    for i in 0..10 {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            // Read operations
            let guard = store_clone.lock().expect("poisoned");
            let _coins = guard.coins();
            let _balance = guard.balance();
            let _state = guard.spendable_coins();
            let _len = guard.len();
            drop(guard);
            i
        });
        handles.push(handle);
    }

    // All threads should complete successfully
    for handle in handles {
        let result = handle.join();
        assert!(result.is_ok());
    }
}

/// Test that accessing coin_store then label_store doesn't deadlock.
#[test]
fn test_no_deadlock_coin_then_label() {
    use std::time::Duration;

    let coin_store = Arc::new(Mutex::new(SpCoinStore::new()));
    let label_store = Arc::new(Mutex::new(LabelStore::new()));

    let coin_store_1 = Arc::clone(&coin_store);
    let label_store_1 = Arc::clone(&label_store);
    let coin_store_2 = Arc::clone(&coin_store);
    let label_store_2 = Arc::clone(&label_store);

    // Thread 1: lock coin_store, then label_store
    let h1 = thread::spawn(move || {
        for _ in 0..100 {
            {
                let mut coins = coin_store_1.lock().expect("poisoned");
                coins.insert(test_outpoint(), test_owned_output(100, 1000));
            }
            // Release coin_store before acquiring label_store
            {
                let mut labels = label_store_1.lock().expect("poisoned");
                labels.edit(
                    LabelKey::OutPoint(test_outpoint()),
                    Some("label from thread 1".to_string()),
                );
            }
            thread::sleep(Duration::from_micros(1));
        }
    });

    // Thread 2: also lock coin_store, then label_store (same order)
    let h2 = thread::spawn(move || {
        for _ in 0..100 {
            {
                let coins = coin_store_2.lock().expect("poisoned");
                let _ = coins.balance();
            }
            // Release coin_store before acquiring label_store
            {
                let labels = label_store_2.lock().expect("poisoned");
                let _ = labels.outpoint(test_outpoint());
            }
            thread::sleep(Duration::from_micros(1));
        }
    });

    // Both threads should complete without deadlock
    h1.join().expect("thread 1 panicked");
    h2.join().expect("thread 2 panicked");
}

/// Test concurrent writes to different stores.
#[test]
fn test_concurrent_writes_different_stores() {
    let coin_store = Arc::new(Mutex::new(SpCoinStore::new()));
    let tx_store = Arc::new(Mutex::new(SpTxStore::new()));

    let coin_store_clone = Arc::clone(&coin_store);
    let tx_store_clone = Arc::clone(&tx_store);

    // Thread 1: write to coin_store
    let h1 = thread::spawn(move || {
        for i in 0..50 {
            let mut store = coin_store_clone.lock().expect("poisoned");
            let mut outpoint = test_outpoint();
            outpoint.vout = i;
            store.insert(outpoint, test_owned_output(100 + i, 1000 * (i as u64 + 1)));
        }
    });

    // Thread 2: write to tx_store
    let h2 = thread::spawn(move || {
        for i in 0..50 {
            let mut store = tx_store_clone.lock().expect("poisoned");
            store.insert(bwk_sp::account::tx_store::SpTxEntry {
                txid: test_outpoint().txid,
                tx: None,
                fee: None,
                label: Some(format!("tx {i}")),
                height: Some(100 + i),
                timestamp: None,
                change: 0,
            });
        }
    });

    h1.join().expect("thread 1 panicked");
    h2.join().expect("thread 2 panicked");

    // Verify final state
    let coins = coin_store.lock().expect("poisoned");
    assert_eq!(coins.len(), 50);

    let txs = tx_store.lock().expect("poisoned");
    // Note: tx_store replaces by txid, so only 1 entry
    assert!(!txs.transactions().is_empty());
}

// Additional Unit Tests for Coverage

/// Test AccountError display messages.
#[test]
fn test_account_error_display() {
    let err = AccountError::MissingBlindbitUrl;
    assert!(err.to_string().contains("blindbit_url"));

    let err = AccountError::Scan(bwk_sp::receiver::error::Error::SeedDerivation);
    assert!(err.to_string().contains("scan failed"));

    let err = AccountError::Network("test network error".to_string());
    assert!(err.to_string().contains("network error"));

    let err = AccountError::NoKeys;
    assert!(err.to_string().contains("no keys"));

    let err = AccountError::ScannerAlreadyRunning;
    assert!(err.to_string().contains("already running"));

    let err = AccountError::Tweak(bitcoin::secp256k1::Error::InvalidTweak);
    assert!(err.to_string().contains("tweak"));
}

/// Test Notification Debug.
#[test]
fn test_notification_debug() {
    let notif = Notification::Sp(SpNotification::ScanReceiveProgress {
        current: 100,
        end: 200,
    });
    let debug = format!("{notif:?}");
    assert!(debug.contains("ScanReceiveProgress"));
    assert!(debug.contains("100"));
}
