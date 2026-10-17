# bwk-hwi

Fork of [async-hwi](https://github.com/wizardsardine/async-hwi) with async and tokio dependency removed.

Current **Minimum Supported Rust Version**: v1.81 (1.85 if coldcard feature enabled)

```rust
/// HWI is the common Hardware Wallet Interface.
pub trait HWI: Debug {
    /// 0. Return the device kind
    fn device_kind(&self) -> DeviceKind;
    /// 1. Application version or OS version.
    fn get_version(&self) -> Result<Version, Error>;
    /// 2. Get master fingerprint.
    fn get_master_fingerprint(&self) -> Result<Fingerprint, Error>;
    /// 3. Get the xpub with the given derivation path.
    fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, Error>;
    /// Display xpubs on the device screen when the device supports it.
    fn display(&self, _display: bool) {}
    /// 4. Register a new wallet policy
    fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, Error>;
    /// 5. Returns true if the wallet is registered
    fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, Error>;
    /// 6. Display an address on the device screen
    fn display_address(&self, script: &AddressScript) -> Result<(), Error>;
    /// 7. Sign a partially signed bitcoin transaction (PSBT).
    fn sign_tx(&self, tx: &mut Psbt) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressScript {
    /// Must be a bip86 path.
    P2TR(DerivationPath),
    /// Miniscript requires the policy be loaded into the device.
    Miniscript { index: u32, change: bool },
}
```

## Supported devices

A Empty case means the method is unimplemented on the client or device side.

| device               | 1          | 2          | 3          | 4          | 5                    | 6          | 7          |
| -------------------- | ---------- | ---------- | ---------- | ---------- | -------------------- | ---------- | ---------- |
| BitBox02[^1]         | >= v9.15.0 | >= v9.15.0 | >= v9.15.0 | >= v9.15.0 | >= v9.15.0           | >= v9.15.0 | >= v9.15.0 |
| Coldcard[^2]         | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X | >= v6.2.1X           | >= v6.2.1X | >= v6.2.1X |
| Jade[^3]             | >= v1.0.30 | >= v1.0.30 | >= v1.0.30 | >= v1.0.30 | >= v1.0.30           | >= v1.0.30 | >= v1.0.30 |
| Ledger Nano S/S+[^4] | >= v2.1.2  | >= v2.1.2  | >= v2.1.2  | >= v2.1.2  | *check hmac presence | >= v2.1.2  | >= v2.1.2  |
| Specter[^5]          |            | >= v1.8.0  | >= v1.8.0  | >= v1.8.0  |                      |            | >= v1.8.0  |

[^1]: https://github.com/digitalbitbox/bitbox02-firmware
[^2]: https://github.com/alfred-hodler/rust-coldcard, vendored as a fork in `hwi/coldcard`:
    USB HID and the simulator's Unix socket (see [coldcard/README.md](coldcard/README.md)).
[^3]: https://github.com/Blockstream/Jade
[^4]: https://github.com/LedgerHQ/app-bitcoin-new
[^5]: https://github.com/cryptoadvance/specter-diy

## Service Module

The `service` module provides automatic device discovery and management with support
for multiple concurrent consumers. See [SERVICE.md](SERVICE.md) for detailed
documentation and usage examples.

## Speculos tests

`tests/ledger_speculos.rs` drives `LedgerSimulator` against the Ledger Bitcoin Test
app running under [Speculos](https://github.com/LedgerHQ/speculos). The tests are
`#[ignore]`d; run them with `tests/speculos/run.sh [nanox|nanosp]`, or `just test-ledger`
in `hwi/` for both devices. Docker is the only prerequisite.

`run.sh` builds the app ELF with the pinned builder image (cached in
`target/speculos-cache/`), then runs `cargo test` with `SPECULOS_BIN` pointing at
`tests/speculos/speculos-docker.sh`, which runs the pinned Speculos image for the
`speculos` crate and removes its container when the crate kills it.

`tests/speculos/versions.env` pins every input, for `run.sh` and CI alike: the app
version (`LEDGER_APP_VERSION=2.4.6`), the builder image and the Speculos image, both
by digest. 2.4.6 is the newest 2.4.x, runs the same MuSig2 round model as 2.4.2, and
its screens are the ones the tests expect (2.4.2 fails 33 of the 44 tests).

- `SPECULOS_ELF`: a prebuilt ELF of `LEDGER_APP_VERSION` for the device, used as is
  instead of building one.
- `SPECULOS_BIN`: overrides the wrapper (e.g. a local `speculos`).

## License

- bwk code: MIT, see [LICENSE-MIT](LICENSE-MIT)
- code forked from async-hwi: BSD-3-Clause, see [LICENSE-BSD](LICENSE-BSD)
- `bitbox::api`, `ledger::bitcoin_client` and `ledger::transport_hidapi`: Apache-2.0, see
  [LICENSE-APACHE](LICENSE-APACHE)
