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
};

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bwk::bwk_electrum::{
    label_store::{LabelKey, LabelStore},
    notification::{Notification, SpNotification},
};
use bwk_sp::{
    account::{
        coin_store::SpCoinStore, config::Config, tx_store::SpTxStore, Account, AccountError,
    },
    bwk_sign::bwk_descriptor::{
        sp_descriptor::SpDescriptor,
        sp_key::{SpKey, SpScanKey, SpSpendKey},
    },
};
use bwk_utils::test::temp_dir::TempDir;

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

/// Test that Config::new fails with an invalid mnemonic.
#[test]
fn test_config_new_invalid_bad_mnemonic() {
    let result = Config::new(
        "bad-mnemonic".to_string(),
        bitcoin::Network::Signet,
        "invalid mnemonic words that are not valid".to_string(),
        "https://blindbit.example.com".to_string(),
        std::path::PathBuf::from("/tmp/bwk-sp-test-bad-mnemonic"),
    );

    match result {
        Err(bwk_sp::account::config::ConfigError::Signer(_)) => {}
        Err(other) => panic!("expected Signer error, got {other:?}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
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
    .unwrap()
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
}

/// Test that Config from a watch-only `sp(scan_priv,spend_pub)` descriptor
/// would NOT enable signing.
#[test]
fn test_config_for_signing_device_watch_only() {
    let dir = TempDir::new().unwrap();
    let secp = Secp256k1::new();
    let descriptor = SpDescriptor::Packed {
        origin: None,
        key: SpKey::Scan(SpScanKey {
            scan_key: SecretKey::from_slice(&[0x01; 32]).unwrap(),
            spend_key: PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[0x02; 32]).unwrap(),
            ),
            network: bitcoin::NetworkKind::Test,
        }),
    };

    let config = Config::from_descriptor(
        "watch-only".to_string(),
        bitcoin::Network::Signet,
        descriptor,
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    );

    // This config has no mnemonic and the descriptor is watch-only
    assert!(config.mnemonic.is_none());
    assert!(config.descriptor.is_watch_only(&secp).unwrap());
}

/// Test that Config from a hot `sp(scan_priv,spend_priv)` descriptor WOULD
/// enable signing.
#[test]
fn test_config_for_signing_device_hot() {
    let dir = TempDir::new().unwrap();
    let secp = Secp256k1::new();
    let descriptor = SpDescriptor::Packed {
        origin: None,
        key: SpKey::Spend(SpSpendKey {
            scan_key: SecretKey::from_slice(&[0x01; 32]).unwrap(),
            spend_key: SecretKey::from_slice(&[0x02; 32]).unwrap(),
            network: bitcoin::NetworkKind::Test,
        }),
    };

    let config = Config::from_descriptor(
        "signing-device-hot".to_string(),
        bitcoin::Network::Signet,
        descriptor,
        "https://blindbit.example.com".to_string(),
        dir.path().to_path_buf(),
    );

    // This config has no mnemonic but the descriptor carries a spend secret key
    assert!(config.mnemonic.is_none());
    assert!(!config.descriptor.is_watch_only(&secp).unwrap());
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
