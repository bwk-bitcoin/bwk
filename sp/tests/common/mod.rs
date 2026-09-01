//! Test utilities for bwk-sp integration tests.
//!
//! This module provides:
//! - Test fixtures (mnemonic, config, outpoints, owned outputs)
//! - Temporary directory helpers for persistence tests
//! - Blindbitd helpers for integration tests (Phase 10.4)

// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use bitcoin::{
    absolute::Height, hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
};

use blindbitd::BlindbitD;
use bwk_utils::test::corepc_node;

use bwk_sp::{
    account::config::Config,
    receiver::{OutputSpendStatus, OwnedOutput},
};

pub fn blindbitd() -> BlindbitD {
    BlindbitD::new().unwrap()
}

/// Aborts the process with a full thread dump if not disarmed within `timeout`.
///
/// Turns a silent CI hang (a scan that never returns) into a fast, diagnosable
/// failure: on timeout it dumps every thread's backtrace via gdb, then aborts so
/// the job fails in minutes with the stuck frame in the log instead of stalling
/// for hours. Drop the returned guard (returning from the test does) to disarm.
#[must_use]
#[allow(dead_code)]
pub fn abort_after(label: &'static str, timeout: Duration) -> WatchdogGuard {
    let armed = Arc::new(AtomicBool::new(true));
    let watch = armed.clone();
    let handle = thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            let start = Instant::now();
            while watch.load(Ordering::Relaxed) {
                if start.elapsed() >= timeout {
                    eprintln!(
                        "\nWATCHDOG: {label} exceeded {timeout:?}; dumping threads and aborting"
                    );
                    dump_threads();
                    std::process::abort();
                }
                thread::sleep(Duration::from_millis(200));
            }
        })
        .expect("spawn watchdog");
    WatchdogGuard {
        armed,
        _handle: handle,
    }
}

pub struct WatchdogGuard {
    armed: Arc<AtomicBool>,
    _handle: JoinHandle<()>,
}

impl Drop for WatchdogGuard {
    fn drop(&mut self) {
        self.armed.store(false, Ordering::Relaxed);
    }
}

/// Dump every thread's backtrace by attaching gdb to our own pid. Best-effort:
/// prints a note and continues if gdb is unavailable or cannot attach.
#[allow(dead_code)]
fn dump_threads() {
    #[cfg(target_os = "linux")]
    unsafe {
        // Let the gdb child ptrace us regardless of the yama ptrace_scope setting.
        const PR_SET_PTRACER_ANY: libc::c_ulong = libc::c_ulong::MAX;
        libc::prctl(libc::PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    }
    let pid = std::process::id().to_string();
    match Command::new("gdb")
        .args([
            "-p",
            &pid,
            "-batch",
            "-ex",
            "set pagination off",
            "-ex",
            "thread apply all bt",
        ])
        .output()
    {
        Ok(out) => {
            eprintln!("{}", String::from_utf8_lossy(&out.stdout));
            if !out.stderr.is_empty() {
                eprintln!("gdb stderr: {}", String::from_utf8_lossy(&out.stderr));
            }
        }
        Err(e) => eprintln!("WATCHDOG: gdb thread dump unavailable: {e}"),
    }
}

// MockBackendError

/// Errors that can occur in MockBackend operations.
#[derive(Debug, thiserror::Error)]
pub enum MockBackendError {
    #[error("simulated network failure after {0} calls")]
    SimulatedFailure(u32),
}

// MockBlock

/// A mock block for testing.
#[derive(Debug, Clone)]
pub struct MockBlock {
    /// Block height
    pub height: u32,
    /// Outputs found in this block (outpoint -> owned output)
    pub outputs: Vec<(OutPoint, OwnedOutput)>,
    /// Inputs spent in this block (outpoints that were consumed)
    pub spent_inputs: Vec<OutPoint>,
}

impl MockBlock {
    /// Create a new mock block with no transactions.
    pub fn new(height: u32) -> Self {
        Self {
            height,
            outputs: Vec::new(),
            spent_inputs: Vec::new(),
        }
    }

    /// Add an output to this block.
    pub fn with_output(mut self, outpoint: OutPoint, output: OwnedOutput) -> Self {
        self.outputs.push((outpoint, output));
        self
    }

    /// Add a spent input to this block.
    pub fn with_spent_input(mut self, outpoint: OutPoint) -> Self {
        self.spent_inputs.push(outpoint);
        self
    }
}

// MockBackend

/// A mock backend for testing scanner logic without real network.
///
/// This can be used to:
/// - Simulate different chain states
/// - Test error handling with `fail_after`
/// - Track call counts for retry testing
pub struct MockBackend {
    /// Predefined blocks
    blocks: Vec<MockBlock>,
    /// Simulate network failure after N calls (None = no failures)
    fail_after: Option<u32>,
    /// Track number of calls for retry testing
    call_count: AtomicU32,
    /// Current chain tip height
    tip_height: u32,
}

impl MockBackend {
    // Constructors

    /// Create a new MockBackend with specified tip height.
    pub fn new(tip_height: u32) -> Self {
        Self {
            blocks: Vec::new(),
            fail_after: None,
            call_count: AtomicU32::new(0),
            tip_height,
        }
    }

    /// Create a MockBackend with predefined blocks.
    pub fn with_blocks(blocks: Vec<MockBlock>) -> Self {
        let tip_height = blocks.iter().map(|b| b.height).max().unwrap_or(0);
        Self {
            blocks,
            fail_after: None,
            call_count: AtomicU32::new(0),
            tip_height,
        }
    }

    // Configuration (builder pattern)

    /// Configure the backend to fail after N calls.
    pub fn fail_after(mut self, n: u32) -> Self {
        self.fail_after = Some(n);
        self
    }

    // Getters

    /// Returns the current call count.
    pub fn call_count(&self) -> u32 {
        self.call_count.load(Ordering::Relaxed)
    }

    /// Reset the call count to zero.
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::Relaxed);
    }

    // Mock API methods

    /// Get the current block height (simulates backend.block_height()).
    ///
    /// Increments call count and may return an error if `fail_after` is set.
    pub fn block_height(&self) -> Result<u32, MockBackendError> {
        let count = self.call_count.fetch_add(1, Ordering::Relaxed);

        if let Some(fail_after) = self.fail_after {
            if count >= fail_after {
                return Err(MockBackendError::SimulatedFailure(fail_after));
            }
        }

        Ok(self.tip_height)
    }

    /// Get block data at a specific height.
    ///
    /// Increments call count and may return an error if `fail_after` is set.
    pub fn get_block(&self, height: u32) -> Result<Option<&MockBlock>, MockBackendError> {
        let count = self.call_count.fetch_add(1, Ordering::Relaxed);

        if let Some(fail_after) = self.fail_after {
            if count >= fail_after {
                return Err(MockBackendError::SimulatedFailure(fail_after));
            }
        }

        Ok(self.blocks.iter().find(|b| b.height == height))
    }

    /// Get all blocks in a range.
    pub fn get_blocks_in_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<Vec<&MockBlock>, MockBackendError> {
        let count = self.call_count.fetch_add(1, Ordering::Relaxed);

        if let Some(fail_after) = self.fail_after {
            if count >= fail_after {
                return Err(MockBackendError::SimulatedFailure(fail_after));
            }
        }

        Ok(self
            .blocks
            .iter()
            .filter(|b| b.height >= start && b.height <= end)
            .collect())
    }
}

// Test Fixtures

/// Returns a fixed 12-word test mnemonic.
///
/// This is the standard BIP39 test vector mnemonic.
/// WARNING: Never use this mnemonic for real funds!
pub fn test_mnemonic() -> &'static str {
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}

/// Returns a second test mnemonic (different from test_mnemonic).
/// WARNING: Never use this mnemonic for real funds!
#[allow(dead_code)]
pub fn test_mnemonic_2() -> &'static str {
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
}

/// Returns a valid test Config pointing to a temporary directory.
///
/// The config has:
/// - account_name: "test-account"
/// - network: Signet
/// - mnemonic: standard test mnemonic
/// - blindbit_url: placeholder URL
/// - persistence: none (to avoid file I/O in tests)
pub fn test_config(temp_dir: &std::path::Path) -> Config {
    Config::new(
        "test-account".to_string(),
        bitcoin::Network::Signet,
        test_mnemonic().to_string(),
        "https://blindbit.test.example.com".to_string(),
        temp_dir.to_path_buf(),
    )
    .with_persistence(None)
}

/// Creates a test Account with BlindbitD backend (no persistence).
#[allow(dead_code)]
pub fn test_account(url: &str) -> bwk_sp::account::Account {
    let config = Config::new(
        "test".to_string(),
        bitcoin::Network::Regtest,
        test_mnemonic().to_string(),
        url.to_string(),
        std::path::PathBuf::from("/unused"),
    )
    .with_persistence(None);
    bwk_sp::account::Account::new(config).expect("create test account")
}

/// Creates a test Account with custom name (no persistence).
#[allow(dead_code)]
pub fn test_account_named(name: &str, url: &str) -> bwk_sp::account::Account {
    test_account_with_mnemonic(name, test_mnemonic(), url)
}

/// Creates a test Account with custom name and mnemonic (no persistence).
#[allow(dead_code)]
pub fn test_account_with_mnemonic(
    name: &str,
    mnemonic: &str,
    url: &str,
) -> bwk_sp::account::Account {
    let config = Config::new(
        name.to_string(),
        bitcoin::Network::Regtest,
        mnemonic.to_string(),
        url.to_string(),
        std::path::PathBuf::from("/unused"),
    )
    .with_persistence(None);
    bwk_sp::account::Account::new(config).expect("create test account")
}

/// Creates a test Account with persistence enabled.
/// Returns (Account, Config, TempDir) - keep TempDir alive for persistence to work.
#[allow(dead_code)]
pub fn test_account_persistent(url: &str) -> (bwk_sp::account::Account, Config, TempDir) {
    test_account_persistent_named("test", url)
}

/// Creates a test Account with persistence enabled and custom name.
#[allow(dead_code)]
pub fn test_account_persistent_named(
    name: &str,
    url: &str,
) -> (bwk_sp::account::Account, Config, TempDir) {
    let dir = TempDir::new().unwrap();
    let config = Config::new(
        name.to_string(),
        bitcoin::Network::Regtest,
        test_mnemonic().to_string(),
        url.to_string(),
        dir.path().to_path_buf(),
    )
    .with_persistence(Some(bwk::persist::PersistenceKind::Json));
    let account = bwk_sp::account::Account::new(config.clone()).expect("create test account");
    (account, config, dir)
}

/// Returns a test OutPoint with a deterministic txid.
///
/// The txid is created from byte array [1u8; 32] with vout=0.
pub fn test_outpoint() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([1u8; 32]),
        vout: 0,
    }
}

/// Returns a second test OutPoint with a different txid.
///
/// The txid is created from byte array [2u8; 32] with vout=1.
pub fn test_outpoint_2() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([2u8; 32]),
        vout: 1,
    }
}

/// Returns a third test OutPoint with a different txid.
///
/// The txid is created from byte array [3u8; 32] with vout=2.
pub fn test_outpoint_3() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([3u8; 32]),
        vout: 2,
    }
}

/// Returns a test OwnedOutput with specified height and amount.
///
/// The output is unspent and has default values for tweak and script.
pub fn test_owned_output(height: u32, amount: u64) -> OwnedOutput {
    OwnedOutput {
        blockheight: Height::from_consensus(height).unwrap_or(Height::ZERO),
        tweak: [0u8; 32],
        amount: Amount::from_sat(amount),
        script: ScriptBuf::new(),
        label: None,
        spend_status: OutputSpendStatus::Unspent,
    }
}

/// Returns a test OwnedOutput that has been spent.
///
/// The output is marked as Spent with a zeroed spending txid.
pub fn test_spent_output(height: u32, amount: u64) -> OwnedOutput {
    OwnedOutput {
        blockheight: Height::from_consensus(height).unwrap_or(Height::ZERO),
        tweak: [0u8; 32],
        amount: Amount::from_sat(amount),
        script: ScriptBuf::new(),
        label: None,
        spend_status: OutputSpendStatus::Spent {
            txid: [0u8; 32],
            block_hash: None,
        },
    }
}

pub use bwk_utils::test::TempDir;

// Blindbitd Helpers (Phase 10.4)

/// Dust threshold for Silent Payment outputs.
#[allow(dead_code)]
pub const DUST: u64 = 330;

pub trait SyncTarget {
    fn url(&self) -> String;
    fn dump_logs(&mut self) {}
}

impl SyncTarget for &mut BlindbitD {
    fn url(&self) -> String {
        BlindbitD::url(self)
    }

    fn dump_logs(&mut self) {
        eprintln!("blindbitd logs:");
        while let Ok(log) = self.logs.try_recv() {
            eprint!("{log}");
        }
    }
}

/// Wait until the backend has synced to at least the given height.
///
/// Polls the backend every 500ms until `block_height()` returns at least `height`.
/// 60 s flaked under CI load when the runner was indexing many regtest blocks
/// in parallel; 120 s with finer polling is more robust.
pub fn wait_until_sync_at_height(mut target: impl SyncTarget, height: u32) {
    let agent = bwk_sp::blindbit::agent().expect("blindbit agent");
    let blindbit_url = target.url();
    let start = std::time::Instant::now();
    // Generous: blindbitd indexes 100 blocks in seconds locally, but deep into a
    // long single-threaded CI run (dozens of daemon spin-ups) it gets starved and
    // can crawl ~50x slower, so wait long enough for the slow tail rather than
    // flaking the test.
    let timeout = Duration::from_secs(600);
    let mut last_error = None;
    loop {
        if start.elapsed() > timeout {
            if let Some(error) = last_error {
                eprintln!("last block_height error: {error}");
            }
            target.dump_logs();
            panic!("wait_until_sync_at_height: timed out waiting for height {height}");
        }
        match bwk_sp::blindbit::block_height(&agent, &blindbit_url) {
            Ok(h) => {
                if h.to_consensus_u32() >= height {
                    return;
                }
            }
            Err(e) => last_error = Some(e),
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Wait for sync and add extra delay for indexing.
///
/// Waits until sync reaches `height`, then sleeps an additional 2 seconds
/// to allow BlindbitD time to index the new blocks.
pub fn wait_for_sync_and_index(target: impl SyncTarget, height: u32) {
    wait_until_sync_at_height(target, height);
    // Give blindbitd extra time to index new blocks
    thread::sleep(Duration::from_secs(2));
}

/// Block until a background one-shot scan finishes (or `timeout` elapses).
#[allow(dead_code)]
pub fn wait_for_oneshot_done(account: &bwk_sp::account::Account, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while account.is_scanning() {
        assert!(
            Instant::now() < deadline,
            "one-shot scan did not finish in time"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// Extract the XOnlyPublicKey from a P2TR output script.
///
/// # Panics
///
/// Panics if the script is not a valid P2TR output (OP_1 <32-byte key>).
pub fn get_taproot_pubkey(txout: &TxOut) -> XOnlyPublicKey {
    let script_bytes = txout.script_pubkey.as_bytes();
    assert_eq!(script_bytes[0], 0x51); // OP_1
    assert_eq!(script_bytes[1], 0x20); // 32 bytes
    bitcoin::key::XOnlyPublicKey::from_slice(&script_bytes[2..34]).expect("valid output key")
}

/// Generate a recipient public key for a Silent Payment transaction.
///
/// This function:
/// 1. Tweaks the input secret key for taproot
/// 2. Verifies it matches the prevout script
/// 3. Calculates the partial secret from input keys and outpoints
/// 4. Generates the recipient pubkey using the SP address
///
/// # Arguments
///
/// * `sk` - Internal (untweaked) secret key for the input being spent
/// * `outpoint` - The outpoint being spent
/// * `txout` - The prevout (previous output being spent)
/// * `sp_addr` - The Silent Payment address to send to
/// * `secp` - Secp256k1 context
///
/// # Returns
///
/// The recipient's XOnlyPublicKey for the SP output, or None if generation fails.
#[allow(non_snake_case)]
pub fn generate_recipient_pubkey(
    sk: bitcoin::secp256k1::SecretKey,
    outpoint: OutPoint,
    txout: &TxOut,
    sp_addr: bwk_sp::core::utils::common::SilentPaymentAddress,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
) -> Option<XOnlyPublicKey> {
    use bitcoin::key::TapTweak;

    // tweak the key
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &sk);
    #[allow(deprecated)]
    let keypair = keypair.tap_tweak(secp, None).to_inner();
    let taproot_pubkey = get_taproot_pubkey(txout);

    // check the secret key we pass to calculate_partial_secret() is the one related to
    // the txout script_pubkey
    let (sp_pk, _parity) = keypair.x_only_public_key();
    assert_eq!(taproot_pubkey, sp_pk);

    // process partial secret
    let sp_sk = keypair.secret_key();

    let input_keys = vec![(sp_sk, true /* is taproot */)];
    let outpoints = vec![(outpoint.txid.to_string(), outpoint.vout)];
    let partial_secret =
        bwk_sp::core::sending::calculate_partial_secret(&input_keys, &outpoints).ok()?;

    // generate recipient pubkey
    bwk_sp::core::sending::generate_recipient_pubkeys(vec![sp_addr], partial_secret)
        .ok()?
        .into_iter()
        .next()
        .and_then(|(_addr, k)| k.into_iter().next())
}

/// Build and sign a transaction that sends to a Silent Payment output.
///
/// Creates a simple 1-input, 1-output transaction spending from a P2TR input
/// to a P2TR output with the given recipient pubkey.
///
/// # Arguments
///
/// * `sk` - Internal (untweaked) secret key for the input
/// * `outpoint` - The outpoint being spent
/// * `txout` - The prevout (previous output being spent)
/// * `recipient_pubkey` - The SP recipient's XOnlyPublicKey
/// * `fees` - Transaction fee amount
/// * `secp` - Secp256k1 context
///
/// # Returns
///
/// A signed transaction, or None if the input value is insufficient.
#[allow(dead_code)]
pub fn swap_to_sp(
    sk: bitcoin::secp256k1::SecretKey,
    outpoint: OutPoint,
    txout: TxOut,
    recipient_pubkey: XOnlyPublicKey,
    fees: bitcoin::Amount,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
) -> Option<bitcoin::Transaction> {
    use bitcoin::{
        absolute, key::TapTweak, sighash, transaction::Version, Sequence, TxIn, Witness,
    };

    // craft tx
    let script = ScriptBuf::new_p2tr_tweaked(recipient_pubkey.dangerous_assume_tweaked());
    if txout.value < (fees + Amount::from_sat(DUST)) {
        return None;
    }
    let value = txout.value - fees;
    let output = vec![TxOut {
        value,
        script_pubkey: script,
    }];
    let input = vec![TxIn {
        previous_output: outpoint,
        script_sig: Default::default(),
        sequence: Sequence::ZERO,
        witness: Default::default(),
    }];
    let mut tx = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output,
    };

    // tweak the key
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &sk);
    #[allow(deprecated)]
    let keypair = keypair.tap_tweak(secp, None).to_inner();

    // process sighash
    let mut cache = sighash::SighashCache::new(tx.clone());
    let sighash_type = sighash::TapSighashType::Default;
    let txouts = vec![txout.clone()];
    let prevouts = sighash::Prevouts::All(&txouts);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .ok()?;
    let sighash = bitcoin::secp256k1::Message::from_digest_slice(
        &bitcoin::hashes::Hash::to_byte_array(sighash),
    )
    .expect("Sighash is always 32 bytes.");

    // sign
    let signature = secp.sign_schnorr_no_aux_rand(&sighash, &keypair);
    let sig = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    // craft & add witness
    let witness = Witness::p2tr_key_spend(&sig);
    tx.input[0].witness = witness;

    Some(tx)
}

// TestEnv: integration test harness

use bwk::bwk_electrum::{config::ScannerConfig, scanner::ElectrumScanner};
use bwk_coin::{Coin, CoinSpendInfo, CoinStatus, KeyChain};
use bwk_sign::HotSigner;

/// Mnemonic for BIP32 coins (different from SP mnemonics).
#[allow(dead_code)]
pub fn bip32_mnemonic() -> &'static str {
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
}

/// Attach an offline sub-account watching `signer`'s only descriptor, signed
/// by the BIP32 mnemonic every sub-account here shares.
#[allow(dead_code)]
fn add_offline_sub_account(account: &mut bwk_sp::account::Account, name: &str, signer: &HotSigner) {
    let descriptor = signer.descriptors().into_iter().next().unwrap();
    let mut config = ScannerConfig::new(
        descriptor,
        std::path::PathBuf::new(),
        String::new(),
        name.to_string(),
        bitcoin::Network::Regtest,
        None,
    );
    config.stay_offline = true;
    let scanner = ElectrumScanner::try_new(config).unwrap();
    account
        .add_sub_account(scanner, Some(bip32_mnemonic().to_string()))
        .expect("add_sub_account");
}

/// Satisfaction weight for a taproot key-spend input (same as SP coins).
#[allow(dead_code)]
const TR_KEYSPEND_SATISFACTION_WEIGHT: u64 = 66;

/// Integration test environment wrapping BlindbitD + bitcoind.
#[allow(dead_code)]
pub struct TestEnv {
    pub bbd: BlindbitD,
    pub bitcoind: corepc_node::Node,
    pub height: u32,
    fund_index: u32,
    /// Keeps blindbitd's embedded electrsd alive once taken (type-erased to avoid
    /// an electrsd dev-dep). Populated by `electrum_endpoint`.
    _electrs: Option<Box<dyn std::any::Any>>,
    electrum_endpoint: Option<(String, u16)>,
}

#[allow(dead_code)]
impl TestEnv {
    /// Create BlindbitD, take bitcoind, mine 101 blocks, wait for sync.
    pub fn new() -> Self {
        let mut bbd = blindbitd();
        let mut bitcoind = bbd.bitcoin().unwrap();
        bwk_utils::test::generate_blocks(&mut bitcoind.client, 101);
        wait_for_sync_and_index(&mut bbd, 101);
        TestEnv {
            bbd,
            bitcoind,
            height: 101,
            fund_index: 0,
            _electrs: None,
            electrum_endpoint: None,
        }
    }

    pub fn url(&self) -> String {
        self.bbd.url()
    }

    /// Take blindbitd's embedded electrsd, keep it alive, and return its
    /// `(host, port)` so an account can fetch block times during a scan.
    pub fn electrum_endpoint(&mut self) -> (String, u16) {
        if let Some(endpoint) = &self.electrum_endpoint {
            return endpoint.clone();
        }
        let electrs = self
            .bbd
            .electrum()
            .expect("blindbitd built with the electrum feature");
        let url = electrs.electrum_url.clone();
        let (host, port) = url.rsplit_once(':').expect("electrum url host:port");
        let endpoint = (host.to_string(), port.parse().expect("electrum port"));
        self._electrs = Some(Box::new(electrs));
        self.electrum_endpoint = Some(endpoint.clone());
        endpoint
    }

    /// Create SP account with default mnemonic (no persistence).
    pub fn sp_account(&self, name: &str) -> bwk_sp::account::Account {
        test_account_named(name, &self.bbd.url())
    }

    /// Create SP account with custom mnemonic (no persistence).
    pub fn sp_account_with_mnemonic(&self, name: &str, mnemonic: &str) -> bwk_sp::account::Account {
        test_account_with_mnemonic(name, mnemonic, &self.bbd.url())
    }

    /// Mine blocks and wait for BlindbitD to sync.
    pub fn mine(&mut self, blocks: usize) {
        bwk_utils::test::generate_blocks(&mut self.bitcoind.client, blocks);
        self.height = bwk_utils::test::get_height(&mut self.bitcoind.client) as u32;
        wait_for_sync_and_index(&mut self.bbd, self.height);
    }

    pub fn next_scan_height(&self) -> u32 {
        self.height + 1
    }

    pub fn invalidate_block(&mut self, height: u32) -> String {
        let hash: String = self
            .bitcoind
            .client
            .call("getblockhash", &[height.into()])
            .unwrap();
        let _: serde_json::Value = self
            .bitcoind
            .client
            .call("invalidateblock", &[hash.clone().into()])
            .unwrap();
        self.height = self.bitcoind.client.call("getblockcount", &[]).unwrap();
        hash
    }

    /// Broadcast a transaction and mine 1 block.
    pub fn broadcast_and_mine(&mut self, tx: &bitcoin::Transaction) {
        self.bitcoind.client.send_raw_transaction(tx).unwrap();
        self.mine(1);
    }

    /// Fund an SP account by creating a swap_to_sp transaction.
    ///
    /// Creates a taproot signer from the SP mnemonic, sends BTC to it via
    /// bitcoind, then creates a swap_to_sp transaction to the SP address.
    pub fn fund_sp(&mut self, account: &mut bwk_sp::account::Account, btc: f64) -> (Txid, u32) {
        let mnemonic = test_mnemonic();
        let network = bitcoin::Network::Regtest;
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let tr_signer = HotSigner::new_taproot_from_mnemonics(network, mnemonic).unwrap();
        let idx = self.fund_index;
        self.fund_index += 1;
        let (taproot_addr, sk) = tr_signer.taproot_receive_address_and_key(idx);

        let fund_txid =
            bwk_utils::test::send(&mut self.bitcoind.client, taproot_addr.clone(), btc).unwrap();
        self.mine(2);

        let tx = bwk_utils::test::get_tx(&mut self.bitcoind.client, fund_txid).unwrap();
        let (index, txout) = bwk_utils::test::txouts_for(&taproot_addr, &tx)
            .into_iter()
            .next()
            .unwrap();
        let outpoint = OutPoint {
            txid: fund_txid,
            vout: index as u32,
        };

        let sp_address = account.sp_address();
        let recipient_pubkey =
            generate_recipient_pubkey(sk, outpoint, &txout, sp_address, &secp).unwrap();

        let sp_tx = swap_to_sp(
            sk,
            outpoint,
            txout,
            recipient_pubkey,
            Amount::from_sat(1000),
            &secp,
        )
        .unwrap();

        let sp_txid = sp_tx.compute_txid();
        self.broadcast_and_mine(&sp_tx);
        let sp_height = self.height;
        account
            .scan_blocks(Some(self.height), Some(self.height))
            .unwrap();
        (sp_txid, sp_height)
    }

    /// Derive a taproot receive address from the BIP32 mnemonic.
    pub fn taproot_addr(&self, index: u32) -> bitcoin::Address {
        let signer =
            HotSigner::new_taproot_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        let (addr, _) = signer.taproot_receive_address_and_key(index);
        addr
    }

    /// Derive a segwit (P2WPKH) receive address from the BIP32 mnemonic.
    pub fn segwit_addr(&self, index: u32) -> bitcoin::Address {
        let signer =
            HotSigner::new_wpkh_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        let (addr, _) = signer.wpkh_receive_address_and_key(index);
        addr
    }

    /// Add a taproot sub-account to an SP account so it can sign BIP32
    /// taproot inputs via `sign_and_finalize()`.
    pub fn add_taproot_sub_account(&self, account: &mut bwk_sp::account::Account) {
        let signer =
            HotSigner::new_taproot_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        add_offline_sub_account(account, "sub-tr", &signer);
    }

    /// Add a segwit (P2WPKH) sub-account to an SP account so it can sign
    /// BIP32 segwit inputs via `sign_and_finalize()`.
    pub fn add_segwit_sub_account(&self, account: &mut bwk_sp::account::Account) {
        let signer =
            HotSigner::new_wpkh_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        add_offline_sub_account(account, "sub-sw", &signer);
    }

    /// Create a funded taproot coin via bitcoind.
    ///
    /// The coin is built manually with `CoinSpendInfo::Bip32` so it can be
    /// added to a TxBuilder as a BIP32 input. Register a taproot sub-account
    /// via `add_taproot_sub_account()` so `sign_and_finalize()` can sign it.
    pub fn create_taproot_coin(&mut self, btc: f64) -> Coin {
        let signer =
            HotSigner::new_taproot_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        let (addr, _) = signer.taproot_receive_address_and_key(0);

        let txid = bwk_utils::test::send(&mut self.bitcoind.client, addr.clone(), btc).unwrap();
        self.mine(1);

        let tx = bwk_utils::test::get_tx(&mut self.bitcoind.client, txid).unwrap();
        let (vout, txout) = bwk_utils::test::txouts_for(&addr, &tx)
            .into_iter()
            .next()
            .unwrap();
        let height = bwk_utils::test::get_tx_height(&mut self.bitcoind.client, txid);

        let descriptor = signer.descriptors().into_iter().next().unwrap();
        Coin {
            txout,
            outpoint: OutPoint {
                txid,
                vout: vout as u32,
            },
            height,
            sequence: bitcoin::Sequence::ZERO,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: TR_KEYSPEND_SATISFACTION_WEIGHT,
            spend_info: CoinSpendInfo::Bip32 {
                coin_path: (KeyChain::Receive, 0),
                descriptor,
                secret_key: None,
            },
        }
    }

    /// Create a funded segwit (P2WPKH) coin via bitcoind.
    ///
    /// Register a segwit sub-account via `add_segwit_sub_account()` so
    /// `sign_and_finalize()` can sign it.
    pub fn create_segwit_coin(&mut self, btc: f64) -> Coin {
        let signer =
            HotSigner::new_wpkh_from_mnemonics(bitcoin::Network::Regtest, bip32_mnemonic())
                .unwrap();
        let (addr, _) = signer.wpkh_receive_address_and_key(0);

        let txid = bwk_utils::test::send(&mut self.bitcoind.client, addr.clone(), btc).unwrap();
        self.mine(1);

        let tx = bwk_utils::test::get_tx(&mut self.bitcoind.client, txid).unwrap();
        let (vout, txout) = bwk_utils::test::txouts_for(&addr, &tx)
            .into_iter()
            .next()
            .unwrap();
        let height = bwk_utils::test::get_tx_height(&mut self.bitcoind.client, txid);

        let descriptor = signer.descriptors().into_iter().next().unwrap();
        let satisfaction = descriptor
            .clone()
            .into_single_descriptors()
            .unwrap()
            .first()
            .unwrap()
            .clone()
            .max_weight_to_satisfy()
            .unwrap()
            .to_wu();

        Coin {
            txout,
            outpoint: OutPoint {
                txid,
                vout: vout as u32,
            },
            height,
            sequence: bitcoin::Sequence::ZERO,
            status: CoinStatus::Confirmed,
            label: None,
            satisfaction_size: satisfaction,
            spend_info: CoinSpendInfo::Bip32 {
                coin_path: (KeyChain::Receive, 0),
                descriptor,
                secret_key: None,
            },
        }
    }
}

// Tests for test utilities

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn run() {
        test_mock_backend_new();
        test_mock_backend_with_blocks();
        test_mock_backend_fail_after();
        test_mock_backend_call_count();
        test_mock_block_builder();
        test_mock_backend_get_blocks_in_range();
        test_test_mnemonic();
        test_test_config();
        test_test_outpoints();
        test_test_owned_output();
        test_test_spent_output();
        test_temp_dir_creation();
    }

    fn test_mock_backend_new() {
        let backend = MockBackend::new(100);
        assert_eq!(backend.block_height().unwrap(), 100);
        assert_eq!(backend.call_count(), 1);
    }

    fn test_mock_backend_with_blocks() {
        let blocks = vec![
            MockBlock::new(100),
            MockBlock::new(101),
            MockBlock::new(102),
        ];
        let backend = MockBackend::with_blocks(blocks);

        assert_eq!(backend.block_height().unwrap(), 102);
        assert!(backend.get_block(100).unwrap().is_some());
        assert!(backend.get_block(101).unwrap().is_some());
        assert!(backend.get_block(102).unwrap().is_some());
        assert!(backend.get_block(103).unwrap().is_none());
    }

    fn test_mock_backend_fail_after() {
        let backend = MockBackend::new(100).fail_after(2);

        // First two calls succeed
        assert!(backend.block_height().is_ok());
        assert!(backend.block_height().is_ok());

        // Third call fails
        let result = backend.block_height();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MockBackendError::SimulatedFailure(2)
        ));
    }

    fn test_mock_backend_call_count() {
        let backend = MockBackend::new(100);

        assert_eq!(backend.call_count(), 0);
        let _ = backend.block_height();
        assert_eq!(backend.call_count(), 1);
        let _ = backend.block_height();
        assert_eq!(backend.call_count(), 2);

        backend.reset_call_count();
        assert_eq!(backend.call_count(), 0);
    }

    fn test_mock_block_builder() {
        let outpoint = test_outpoint();
        let output = test_owned_output(100, 50000);

        let block = MockBlock::new(100)
            .with_output(outpoint, output)
            .with_spent_input(test_outpoint_2());

        assert_eq!(block.height, 100);
        assert_eq!(block.outputs.len(), 1);
        assert_eq!(block.spent_inputs.len(), 1);
    }

    fn test_mock_backend_get_blocks_in_range() {
        let blocks = vec![
            MockBlock::new(100),
            MockBlock::new(101),
            MockBlock::new(102),
            MockBlock::new(103),
        ];
        let backend = MockBackend::with_blocks(blocks);

        let range = backend.get_blocks_in_range(101, 102).unwrap();
        assert_eq!(range.len(), 2);
        assert!(range.iter().any(|b| b.height == 101));
        assert!(range.iter().any(|b| b.height == 102));
    }

    fn test_test_mnemonic() {
        let mnemonic = test_mnemonic();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert!(mnemonic.starts_with("abandon"));
    }

    fn test_test_config() {
        let dir = TempDir::new().unwrap();
        let config = test_config(dir.path());

        assert_eq!(config.account_name, "test-account");
        assert_eq!(config.network, bitcoin::Network::Signet);
        assert!(config.persistence.is_none());
        assert!(config.mnemonic.is_some());
    }

    fn test_test_outpoints() {
        let op1 = test_outpoint();
        let op2 = test_outpoint_2();
        let op3 = test_outpoint_3();

        // All should be different
        assert_ne!(op1.txid, op2.txid);
        assert_ne!(op2.txid, op3.txid);
        assert_ne!(op1.txid, op3.txid);

        // Vouts should be as expected
        assert_eq!(op1.vout, 0);
        assert_eq!(op2.vout, 1);
        assert_eq!(op3.vout, 2);
    }

    fn test_test_owned_output() {
        let output = test_owned_output(100, 50000);

        assert_eq!(output.blockheight.to_consensus_u32(), 100);
        assert_eq!(output.amount.to_sat(), 50000);
        assert!(matches!(output.spend_status, OutputSpendStatus::Unspent));
    }

    fn test_test_spent_output() {
        let output = test_spent_output(100, 50000);

        assert_eq!(output.blockheight.to_consensus_u32(), 100);
        assert_eq!(output.amount.to_sat(), 50000);
        assert!(matches!(
            output.spend_status,
            OutputSpendStatus::Spent { .. }
        ));
    }

    fn test_temp_dir_creation() {
        let dir = TempDir::new().unwrap();
        assert!(dir.path().exists());
        assert!(dir.path().is_dir());
        // TempDir auto-cleans on Drop
    }
}
