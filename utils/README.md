# bwk-utils

**Experimental. Do not use in production or with real coins. API will break.**

Shared utilities and test helpers.

Provides common utilities used across bwk crates. Test helpers are behind the
`test` feature flag to avoid leaking test dependencies to consumers.

**Scope:** String formatting, test fixtures. Does NOT contain wallet logic.

## Usage

```rust
use bwk_utils::short_string;

// Truncate long strings with ellipsis
let s = short_string("abcdefghijklmnop".to_string(), 10);
assert_eq!(s, "abcd..mnop");
```

## Test Helpers (feature = "test")

`corepc_node`, `miniscript` and `temp_dir::TempDir` are re-exported, so a
consumer does not have to depend on them itself. `Client` and `Node` are
`corepc_node` types; every node helper takes `&mut Client`.

```rust
use bwk_utils::test::{bitcoind_with_txindex, generate_blocks, get_tx, send};

// Regtest node started with -txindex and pre-mined to 110 blocks
let mut node = bitcoind_with_txindex();
let client = &mut node.client;

// Generate blocks
generate_blocks(client, 10);

// Send to a fresh address, then fetch the transaction back
let addr = client.new_address().unwrap();
let txid = send(client, addr, 0.5).unwrap();
let tx = get_tx(client, txid);
```

`bitcoind` is downloaded by `corepc_node`; the other helpers just need a
`Client` connected to a regtest node.

### `regtest`: bitcoind + electrs

`bwk_utils::test::regtest` spins up a bitcoind and an electrs against it. The
binaries are looked up as `tests/bin/bitcoind_25_2` and
`tests/bin/electrs_0_9_11` under the crate running the test, so each consumer
ships its own pair.

```rust
use std::time::Duration;

use bwk_utils::test::regtest::{
    bootstrap_electrs, generate, get_block_height, init_logger, restart_electrs, wait_until,
};

init_logger();

// bitcoind + electrs, 101 blocks pre-mined
let (url, port, electrsd, bitcoind) = bootstrap_electrs();

generate(&bitcoind, 5);
assert!(wait_until(Duration::from_secs(10), || get_block_height(&bitcoind) >= 106));

// Server restart: the new electrs listens on its own port
let (url, port, electrsd) = restart_electrs(electrsd, &bitcoind);
```

`get_block_hash_str(&bitcoind, height)` and `invalidate_block(&bitcoind, hash)`
drive a reorg. `wait_until` polls its closure every 100ms and returns whether it
ever held. `init_logger` keeps the `RUST_LOG` default so bitcoind and electrs do
not flood the output, unlike `test::setup_logger` which forces debug level.
