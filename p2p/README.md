# bwk-p2p

**Experimental. Do not use in production or with real coins. API will break.**

Bitcoin P2P network client and DNS seed resolution.

Connects to Bitcoin nodes using the P2P protocol. Includes DNS seed lookup
for peer discovery on mainnet/testnet.

**Scope:** P2P connection, handshake, message parsing, DNS seeds. Does NOT
handle full node validation, block storage, or mempool management.

## Usage

```rust
use bwk_p2p::{
    client::Client,
    dns::{fetch_peers, DNS_SEED_SERVERS},
};
use bitcoin::Network;

// Discover peers via DNS
let peers = fetch_peers(Network::Bitcoin)?;

// Connect to a peer
let client = Client::new("127.0.0.1:8333", Network::Bitcoin)?;
```

## Components

- `Client`: P2P connection with version handshake
- `fetch_peers()`: DNS seed resolution for peer discovery
- `DNS_SEED_SERVERS`: Known DNS seeds per network
- `network_to_magic()`: Network magic bytes
