# Bitcoin Wallet Kit

**Experimental. Do not use in production or with real coins. API will break.**

Modular Rust workspace for building Bitcoin wallets. Provides account management,
UTXO tracking, transaction building, and signing, with backends for both
standard descriptor wallets (via Electrum) and Silent Payments (BIP352 via
Blindbit).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Application                                    │
└─────────────────────────────────────────────────────────────────────────────┘
        │                                    │
        ▼                                    ▼
┌───────────────────┐              ┌───────────────────┐
│       bwk         │              │      bwk-sp       │
│ (descriptor-based │              │ (silent payments) │
│     account)      │              │     account)      │
└───────────────────┘              └───────────────────┘
        │                                    │
        ├────────────┬───────────────────────┤
        ▼            ▼                       ▼
┌─────────────┐ ┌─────────────┐      ┌─────────────┐
│ bwk-electrum│ │  bwk-sign   │      │  blindbit   │
│  (chain)    │ │  (signing)  │      │  (SP data)  │
└─────────────┘ └─────────────┘      └─────────────┘
        │            │                       │
        └────────────┴───────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
┌──────────────┐ ┌─────────────┐ ┌─────────────┐
│bwk-descriptor│ │  bwk-keys   │ │   bwk-tx    │
│ (derivation) │ │ (key mgmt)  │ │  (building) │
└──────────────┘ └─────────────┘ └─────────────┘
```

## Crates

```
+-----------------+-------------------------------------------------------+
| Crate           | Purpose                                               |
+-----------------+-------------------------------------------------------+
| bwk             | Account for descriptor wallets (Electrum backend)     |
| bwk-sp          | Silent Payments account (BIP352, Blindbit backend)    |
| bwk-tx          | Transaction building, coin selection, PSBT            |
| bwk-psbt        | PSBTv2 (BIP370), silent-payment fields (BIP375/376)   |
| bwk-electrum    | Electrum client, scanner, scan stores, header chain   |
| bwk-sign        | Hot signer, SigningManager                            |
| bwk-descriptor  | Miniscript and sp() descriptors, SpkDerivator         |
| bwk-keys        | Key derivation (OXpriv, OXpub)                        |
| bwk-p2p         | Bitcoin P2P client                                    |
| bwk-coin        | Coin domain types shared by bwk-tx and bwk-electrum   |
| bwk-persist     | KV persistence: Store, RamStore, JSON/SQLite backends |
| bwk-hwi         | Hardware wallet transport and device drivers          |
| bwk-error       | In-house error derive, reached as `thiserror`         |
| bwk-qr          | QR generation, scanning, BBQR framing                 |
| bwk-qr-protocol | Signing-flow message codec (no_std, C binding)        |
| bwk-backoff     | Exponential backoff                                   |
| bwk-utils       | Test helpers                                          |
+-----------------+-------------------------------------------------------+
```

See crate READMEs:
[bwk](bwk/README.md),
[bwk-sp](sp/README.md),
[bwk-tx](tx/README.md),
[bwk-psbt](psbt/README.md),
[bwk-electrum](electrum/README.md),
[bwk-sign](sign/README.md),
[bwk-descriptor](descriptor/README.md),
[bwk-keys](keys/README.md),
[bwk-p2p](p2p/README.md),
[bwk-coin](coin/README.md),
[bwk-hwi](hwi/README.md),
[bwk-error](error/README.md),
[bwk-qr](qr/README.md),
[bwk-qr-protocol](qr-protocol/README.md),
[bwk-backoff](backoff/README.md),
[bwk-utils](utils/README.md)

## Build

```bash
cargo build --release
scripts/ci-checks.sh tests
scripts/ci-checks.sh clippy
```

MSRV: 1.88
