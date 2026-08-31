# bwk-electrum

**Experimental. Do not use in production or with real coins. API will break.**

Electrum protocol client with TCP/SSL support, plus the scanner built on it.

Implements the Electrum JSON-RPC protocol for querying blockchain data. Provides
both a threaded async listener (for wallet sync) and sync methods (for one-off
queries). Handles request batching and connection management.

`ElectrumScanner` sits on top: it watches a descriptor against a server and
holds what the server reported (coins, transactions, addresses, labels). It is
usable on its own, with no wallet and no header validation, and it never reads
a header, verifies an inclusion proof or promotes a claim. `HeaderStore` is the
independent half: it opens two connections of its own, one for the worker that
maintains the validated chain and one for the client that fetches merkle
proofs. Two, because `Client::listen_headers` and `Client::listen_txs` each
consume the `Client`, so a connection hosts exactly one typed listener.

`Reconciler` is the pass between the two halves, one per scanner and on its own
thread: it promotes what the scanner recorded against the validated chain and
fetches the proofs it needs through the store. `HeaderFollower` is the other
side of that pairing, keeping a wallet's header store pointed at the endpoint
its scanners watch. Wiring them together is the consumer's job (see
`bwk::Account`).

**Scope:** Electrum protocol, script subscription, transaction history/fetch,
broadcasting, the scan stores, the validated header chain and the reconcile
pass. Does NOT parse transactions (use rust-bitcoin) or sign anything (use
bwk-sign).

## Usage

### Scanner

```rust
use bwk_electrum::{config::ScannerConfig, scanner::ElectrumScanner};

let mut config = ScannerConfig::new(
    descriptor,
    data_dir,
    ".bwk".to_string(),
    "my_account".to_string(),
    Network::Bitcoin,
    Some(PersistenceKind::Json),
);
config.electrum_url = Some("ssl://electrum.example.com".to_string());
config.electrum_port = Some(50002);

let mut scanner: ElectrumScanner = ElectrumScanner::try_new(config)?;
let notifications = scanner.receiver().unwrap();
// The constructor starts nothing; the caller decides when to connect.
scanner.start();

for (outpoint, entry) in scanner.coins() {
    println!("{outpoint}: {}", entry.coin.txout.value);
}
```

### Async Listener (Recommended)

```rust
use bwk_electrum::client::{Client, CoinRequest, CoinResponse};

// Connect to server
let client = Client::new("ssl://electrum.example.com", 50002)?;

// Start listener thread, get channel pair
let (sender, receiver) = client.listen_txs::<CoinRequest, CoinResponse>();

// Subscribe to scripts
let scripts = vec![my_script_pubkey];
sender.send(CoinRequest::Subscribe(scripts))?;

// Handle responses
loop {
    match receiver.recv()? {
        CoinResponse::Status(statuses) => {
            for (spk, status) in statuses {
                println!("Script status changed: {:?}", status);
            }
        }
        CoinResponse::History(histories) => {
            for (spk, txs) in histories {
                println!("Found {} transactions", txs.len());
            }
        }
        CoinResponse::Txs(transactions) => {
            for tx in transactions {
                println!("Got tx: {}", tx.compute_txid());
            }
        }
        CoinResponse::TxMerkle { txid, height, .. } => {
            println!("Got the merkle branch of {} at {}", txid, height);
        }
        CoinResponse::Stopped => break,
        CoinResponse::Error(e) => eprintln!("Error: {}", e),
    }
}
```

### Sync Methods

```rust
let mut client = Client::new("127.0.0.1", 50001)?;

// Fetch transaction
let tx = client.get_tx(txid)?;

// Get UTXOs at script
let (coins, txs) = client.get_coins_at(&script)?;

// Broadcast transaction
client.broadcast(&signed_tx)?;
```

## Architecture

```
Consumer
    │
    ├──► mpsc::Sender<CoinRequest>
    │         │
    │         ▼
    │    listen_txs() thread
    │         │
    │         ▼
    │    RawClient (TCP or SSL)
    │         │
    │         ▼
    │    Electrum server
    │
    └──◄ mpsc::Receiver<CoinResponse>
```

## Request/Response Types

**Requests:**
- `CoinRequest::Subscribe(Vec<ScriptBuf>)`: Subscribe to script status changes
- `CoinRequest::History(Vec<ScriptBuf>)`: Get transaction history for scripts
- `CoinRequest::Txs(Vec<Txid>)`: Fetch raw transactions
- `CoinRequest::GetTxMerkle { txid, height }`: Fetch the merkle branch proving
  `txid` is in the block at `height`
- `CoinRequest::Stop`: Stop the listener thread

**Responses:**
- `CoinResponse::Status(BTreeMap<ScriptBuf, Option<String>>)`: Script statuses
- `CoinResponse::History(BTreeMap<ScriptBuf, Vec<(Txid, Option<u64>)>>)`: Tx history
- `CoinResponse::Txs(Vec<Transaction>)`: Raw transactions
- `CoinResponse::TxMerkle { txid, height, branch, pos }`: The merkle branch and
  the position of `txid` in the block at `height`
- `CoinResponse::Stopped`: Listener stopped
- `CoinResponse::Error(CoinError)`: What went wrong, typed per failing step

## Local Development

For self-signed certificates (regtest):
```rust
let client = Client::new_local("127.0.0.1", 50001)?;
```
