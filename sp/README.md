# bwk-sp

**Experimental. Do not use in production or with real coins. API will break.**

Silent Payments (BIP352) account using Blindbit backend for chain data.

High-level account orchestrator for Silent Payment wallets. Handles UTXO
scanning, coin management, and transaction history. Uses Blindbit oracle for
efficient SP-specific blockchain queries.

**Scope:** SP account lifecycle, stores (coins/txs/labels/scan state), background
scanner thread, SP address generation. Does NOT handle standard descriptor
wallets (use bwk) or direct Electrum queries (use bwk-electrum).

## Usage

```rust
use bwk_sp::{Account, Config, Notification, ScanMode};
use bitcoin::Network;

// Create account from SP keys
let config = Config::new(sp_receiver, Network::Signet)
    .blindbit_url("https://blindbit.example.com")
    .data_dir(data_path);
let mut account = Account::new(config)?;

// Take notification receiver
let receiver = account.receiver().unwrap();

// Start background scanning
account.start_scan(ScanMode::Continuous, None);

// Handle notifications
loop {
    match receiver.recv() {
        Ok(Notification::NewCoin(coin)) => {
            println!("Found coin: {} sats", coin.value);
        }
        Ok(Notification::ScanProgress { height, tip }) => {
            println!("Scanned {}/{}", height, tip);
        }
        _ => {}
    }
}
```

## Architecture

```
Blindbit oracle
     │
     ▼
Scanner thread ──► SpCoinStore (UTXOs from SP scanning)
     │
     ▼
SpTxStore (transaction history)
     │
     ▼
Notification ──► Account consumer
```

## Stores

- `SpCoinStore`: Detected SP outputs with spend status
- `SpTxStore`: Transaction history (direction and amount derived by the aggregator)
- `bwk_electrum::label_store::LabelStore`: User labels for coins and transactions (shared with bwk)
- `ScanState`: Scan progress and checkpoint management

## Packaging

`bwk-sp` depends on `secp256k1_spscan-sys`, whose C sources live in the
`secp256k1_spscan-sys/depend/secp256k1` git submodule. The build script
initializes the submodule automatically for git checkouts when those files are
missing.

Before publishing `bwk-sp`, run:

```bash
cargo package -p bwk-sp
```

Cargo builds the package from the generated tarball, so this verifies that the
submodule contents needed by `secp256k1_spscan-sys` are included in the package.
It also catches crates.io packaging blockers. For example, git-only benchmark
dependencies such as `bench-spdk` must be removed, moved out of the published
crate, or replaced with versioned crates before publishing.

## Benchmarking

The `sp_sync_bench` binary measures SP sync throughput by driving the scanner
directly against a Blindbit oracle (in-RAM, no persistence). It lives behind the
`bench` feature (which pulls in `plotters` for the `plot` subcommand), so pass
`--features bench` when building or running it. Only `--url` is required:

```bash
cargo run --release -p bwk-sp --features bench --bin sp_sync_bench -- --url http://localhost:8000
```

The URL can also come from `BWK_SP_BLINDBIT_URL`. Other options default to
mainnet, the network birthday, the chain tip, and a 600 sat dust limit
(`--dust-limit 0` disables it). `--dust-limit` also accepts a comma-separated
list of values, running one full bench (and saving one file) per value, e.g.
`--dust-limit 0,300,600`. The requested network must match the one the oracle
serves, or the bench errors out. Run with `--help` for the full flag list.

Every run auto-saves its per-block data (height, tweaks, filter bytes) as JSON
into the `bench_data/` directory (gitignored), under a unique filename per run
derived from the run config plus a timestamp. Existing files are never
overwritten. Each file also records the run timing (elapsed / fetch / process
seconds) and best-effort host info (CPU model, cores, RAM).

The `plot` subcommand overlaps every run stored in `bench_data/` into a single
PNG, plotting tweaks per block against block height. The curves are smoothed
into a trend (moving average over `--smooth <PERCENT>` of the x range, default
10, 0 disables). It writes to `bench_data/graph.png` by default, override with
`--out`:

```bash
cargo run --release -p bwk-sp --features bench --bin sp_sync_bench -- plot
cargo run --release -p bwk-sp --features bench --bin sp_sync_bench -- plot --out graph.png --smooth 10
```

The `clean` subcommand removes the `bench_data/` directory (every saved run and
any rendered graph):

```bash
cargo run --release -p bwk-sp --features bench --bin sp_sync_bench -- clean
```
