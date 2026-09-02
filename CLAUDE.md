# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

Bitcoin Wallet Kit (bwk) - a modular Rust workspace providing components for
building Bitcoin wallets. Experimental, API unstable.

See [CODE_GUIDELINES.md](CODE_GUIDELINES.md) for code style rules.

## Build Commands

```bash
# Build release
cargo build --release

# Run all tests
scripts/ci-checks.sh tests

# Run tests with output
scripts/ci-checks.sh tests

# Single test
cargo test --features test,sqlite <test_name>

# Lint
scripts/ci-checks.sh clippy
cargo fmt -- --check
```

MSRV: 1.88

**Before committing:** Ensure CI will pass by running clippy, fmt check, and
tests locally. Commit messages must be single-line and follow existing style
(e.g., `crate: short description`).

## Workspace Crates

```
+-----------------+-------------------------------------------------------------+
| Crate           | Purpose                                                     |
+-----------------+-------------------------------------------------------------+
| bwk             | Main library - Account orchestrator for descriptor-based    |
|                 | wallets (Electrum backend)                                  |
| bwk-sp          | Silent Payments account orchestrator (BIP352, Blindbit)     |
| bwk-tx          | Transaction building, coin selection, fee estimation, PSBT  |
| bwk-electrum    | Electrum protocol client (TCP/SSL), ElectrumScanner, and    |
|                 | the scan stores, the header chain and the reconcile pass    |
| bwk-sign        | Hot signer, SigningManager for BIP32 key management         |
| bwk-descriptor  | Miniscript descriptor handling, SpkDerivator                |
| bwk-keys        | Key derivation utilities (OXpriv, OXpub, KeyDerivator)      |
| bwk-p2p         | Bitcoin P2P network client, DNS seed resolution             |
| bwk-coin        | Coin domain types shared by bwk-tx and bwk-electrum         |
| bwk-persist     | KV persistence: Store, RamStore, JSON/SQLite backends       |
| bwk-hwi         | Hardware wallet transport and device drivers                |
| bwk-error       | In-house derive for error impls, reached as `thiserror`     |
| bwk-qr          | QR generation, scanning, BBQR framing                       |
| bwk-qr-protocol | Signing-flow message codec (no_std, no deps, C binding)     |
| bwk-backoff     | Exponential backoff utility                                 |
| bwk-utils       | Test helpers (behind `test` feature)                        |
+-----------------+-------------------------------------------------------------+
```

See crate READMEs for usage examples:
- [bwk/README.md](bwk/README.md): Account, stores, address generation
- [sign/README.md](sign/README.md): SigningManager, Signer trait
- [descriptor/README.md](descriptor/README.md): SpkDerivator, descriptor helpers
- [electrum/README.md](electrum/README.md): Electrum client modes
- [coin/README.md](coin/README.md): coin domain types
- [error/README.md](error/README.md): the in-house error derive

## Architecture

### Standard Wallet (`bwk`)
```
Account (bwk/src/account.rs)
├── ElectrumScanner (bwk-electrum, records what the server reports)
│   ├── CoinStore (UTXOs, derives addresses via SpkDerivator, and owns
│   │   the TxStore holding the raw txs and their inclusion state)
│   ├── LabelStore (user labels)
│   └── listener thread (its own Electrum connection)
├── HeaderFollower (holds the HeaderStore: validated header chain, two
│   Electrum connections of its own, one for the header worker and one
│   for the merkle-proof client, and keeps it on the scanner's endpoint)
├── SigningManager (hot signers)
└── Reconciler (bwk-electrum, its own thread: promotes what the scanner
    recorded against the header chain, verifies proofs)
```

The scanner and the header validator are independent and never talk to each
other: the scanner has no header store and never sees a merkle request or
response, and the validator never touches the coin stores. The `Reconciler`
pairs them, promoting `ConfirmedUnverified` to `Verified` and stamping
confirmation times through `ElectrumScanner::coin_store`.

### Silent Payments Wallet (`bwk-sp`)
```
Account (sp/src/account/mod.rs)
├── SpReceiver - SP key management and scan matching
├── Blindbit transport - blockchain data via Blindbit oracle
├── SpCoinStore, SpTxStore, ScanState (bwk-sp's own)
├── LabelStore (from bwk-electrum)
├── SP scanner thread (background block scanning)
├── ElectrumScanner per sub-account descriptor (bwk-electrum)
├── HeaderStore (validated header chain, shared by every scanner)
├── Reconciler per scanner (promotes its scan against the header chain)
└── SigningManager (hot signers for the sub-account descriptors)
```

### Transaction Building (`bwk-tx`)
```
TxBuilder
├── RecipientProvider trait - outputs (Recipient, SpRecipient, change providers)
├── CoinSource trait - input selection
├── coin_selection module - weighted random selection algorithm
└── TxTemplate -> Psbt via generate()
```

Key traits:
- `RecipientProvider`: Defines transaction outputs (address, amount, PSBT
  metadata)
- `CoinSource`: Provides spendable coins for selection
- `ChangeTip`: Manages change address index progression
- `Signer`: Signs PSBTs (implemented by HotSigner)

### Notification Pattern

Both Account types use `mpsc::channel<Notification>` for async events
(connection status, new coins, scan progress). Call `account.receiver()` to
take the receiver.

## Features

`bwk` gates optional behaviour behind cargo features, all off by default:
- `logger`: installs `env_logger` as the global logger. Off by default so a
  consumer with its own logger does not pull env_logger and its
  timestamp/colour stack.
- `sp`: silent-payments notification variants, used by `bwk-sp`.
- `hwi`: hardware wallet signers.
- `sqlite`: the SQLite persistence backend.
- `test`: see below.

## Testing

Integration tests require the `test` feature flag which enables:
- `bwk-electrum/test`: Test-only store constructors and accessors (synthetic
  header chains, tx-entry and validation-state setters)
- `bwk-utils/test`: Test helpers (funding_tx, corepc_node utilities, and the
  shared regtest harness in `utils/src/test/regtest.rs`)
- `bwk-sign/test`: Test signer constructors
- `bwk-tx/test`: TxBuilder test methods (fund_with_bitcoind, mark_tx_mined)
- `bwk-persist/test`: Test-only accessors on the backends (on-disk paths)
- `logger`: env_logger as the global logger, so tests get log output

Tests in `bwk/src/account.rs` and `electrum/tests/` use `electrsd` for regtest
Electrum integration, all through `bwk_utils::test::regtest`. Tests in
`sp/tests/` use `blindbitd` for regtest Blindbit integration.

## External Dependencies

- `spdk-core`, `spdk-wallet`, `backend-blindbit-v1`: optional comparison
  benchmark dependencies only (`bwk-sp/bench-spdk`)
- `miniscript`: Descriptor parsing and script generation
- `bitcoin`: Bitcoin primitives (v0.32)
