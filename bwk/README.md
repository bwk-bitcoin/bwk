# bwk

**Experimental. Do not use in production or with real coins. API will break.**

Descriptor-based Bitcoin wallet account using Electrum for chain data.

High-level account orchestrator that ties together UTXO tracking, address
generation, transaction history, and labels. Handles background sync with
Electrum server and emits notifications on state changes.

**Scope:** Account lifecycle, pairing an `ElectrumScanner` with a `HeaderStore`
and reconciling them, signer management, change address management. The stores
and the sync thread live in bwk-electrum. Does NOT handle signing itself (use
bwk-sign) or transaction construction (use bwk-tx).

## Usage

```rust
use bwk::{
    bwk_descriptor::descriptor::ScriptType,
    bwk_electrum::notification::{Notification, TxListenerNotif},
    miniscript::bitcoin::{bip32::ChildNumber, Network},
    persist::PersistenceKind,
    Account, Config,
};

// An account derived from `mnemonic`, persisted as JSON under
// `data_dir/.bwk/my_account`. `ScriptType::Descriptor` takes a descriptor
// instead, and then no mnemonic is needed.
let mut config = Config::new(
    Some(mnemonic),
    "my_account".to_string(),
    Network::Regtest,
    ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
    data_dir,
    ".bwk".to_string(),
    Some(PersistenceKind::Json),
)
.expect("a Segwit account needs a mnemonic");
config.set_electrum_url("127.0.0.1".to_string());
config.set_electrum_port("50001".to_string());

// Opening with an endpoint configured connects and starts syncing;
// `stop_electrum` / `start_electrum` idle and resume it afterwards.
let mut account: Account = Account::try_new(config).expect("failed to open account");

// Take the notification receiver (only the first call returns it).
let receiver = account.receiver().expect("receiver");

for notification in receiver {
    match notification {
        Notification::CoinUpdate => {
            let state = account.spendable_coins();
            println!("confirmed balance: {}", state.confirmed_balance);
        }
        Notification::Electrum(TxListenerNotif::Stopped) => break,
        _ => {}
    }
}
```

An `ssl://` endpoint is verified against the system trust store by default.
Passing `bwk_electrum::raw_client::CertificateCheck::DangerAcceptInvalid` to
`config.scanner.set_certificate_check()` drops that check entirely: the chain
of trust, the expiry and the hostname are all skipped, so any party on the
network path can impersonate the server. It is what a self-signed or onion
server needs, and it is unsafe against anything else. The account hands the
same policy to its scanner connection and to both of the header store's
connections. Pointing the config at another endpoint puts the check back, so
the choice is made once per server.

## Architecture

`Account` owns two independent halves and reconciles them. The scanner records
what the server reports; the header store validates the chain and fetches
inclusion proofs. Neither knows about the other, and only the reconcile pass
touches both. Three Electrum connections in total: one for the scanner, two for
the header store, because `Client::listen_headers` and `Client::listen_txs`
each consume the `Client`, so a connection hosts exactly one typed listener.

```
Electrum server              Electrum server          Electrum server
     │  (scanner conn)            │  (header conn)         │  (merkle conn)
     ▼                            ▼                        ▼
listen_txs() thread          HeaderStore worker       merkle client
     │  ◄──► AddressStore         │                        │
     ▼                            ▼                        ▼
CoinStore.handle_history_    validated header chain   MerkleProof
  response()                      │                        │
CoinStore.handle_txs_             └────────────────────────┘
  response()                                  │
CoinStore.record_reported_                    │
  heights()                                   │
     │                                        │
     ▼                                        ▼
TxStore (raw txs + metadata)  ◄──── Account reconcile thread
     │                                (promote, verify, stamp times)
     ▼
CoinStore.generate() ──► coins cache + address statuses
     │
     ▼
Notification::CoinUpdate ──► Account consumer
```

## Store Relationships

- `TxStore`: Source of truth for transactions. Persisted to JSON.
- `CoinStore`: Generated cache from TxStore. Tracks UTXOs and their status
  (Unconfirmed/ConfirmedUnverified/Confirmed/Spent). A confirmed coin follows
  the inclusion lifecycle Unconfirmed -> ConfirmedUnverified (server reports a
  height, its header is known) -> Verified (a merkle proof checks against that
  header). A CTA pass that mutates tx state emits `Notification::HeaderStoreUpdated`;
  a failed merkle proof or a header store that fails its own validation emits
  `Notification::ValidationFailed`.
- `AddressStore`: Tracks generated addresses (recv/change tips + look_ahead).
  Notifies Electrum thread when new addresses need watching.
- `LabelStore`: User labels keyed by OutPoint or Txid.
- `HeaderStore`: Shared validated chain-header store used to verify merkle
  proofs and track reorgs across accounts.

Stores wrap the typed `bwk-persist::Store` abstraction. Serialization lives in
store-local encode/decode helpers; file or database layout details live in
`PersistenceBackend` implementations.

## Address Generation

`recv_generated_tip` / `change_generated_tip` track last user-requested index.
`recv_watch_tip` / `change_watch_tip` = generated_tip + look_ahead + 1.

Electrum subscribes to all SPKs up to watch_tip. When a coin is received at
index N, if N >= generated_tip, the tip advances and new addresses get watched.

## Change Output Derivation

`ChangeRecipientProvider` implements `RecipientProvider` for TxBuilder.
Uses `ChangeTipUpdater` to increment change_generated_tip on each
`create_script()` call. The index is stored in a `Cell` so `psbt_output_info()`
can return correct BIP32 derivation path.

## Features

All off by default. `logger` installs `env_logger` as the global logger; leave
it off if the consumer installs its own. `sp` adds the silent-payments
notification variants `bwk-sp` needs, `hwi` adds hardware wallet signers,
`sqlite` selects the SQLite persistence backend, and `test` exposes the
test-only constructors the integration tests reach for.
