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

## Ledger MuSig2

The `musig` feature (off by default, forwarded by `bwk-sign/musig`) makes the Ledger a
MuSig2 cosigner: `Ledger::sign_tx` writes what the app yields as BIP-373 fields through
`bwk_psbt::musig`, keyed by the participant, the aggregate and the leaf hash exactly as
the device yields them. Without it MuSig2 yields are ignored.

```text
+---------------------------------+---------------------------------------------+
| yield                           | written to psbt.inputs[i]                   |
+---------------------------------+---------------------------------------------+
| Partial(Sig(key, sig))          | partial_sigs                                |
| Partial(TapScriptSig(k,Some,s)) | tap_script_sigs                             |
| Partial(TapScriptSig(_,None,s)) | tap_key_sig                                 |
| MusigPubNonce (musig)           | 0x1b via set_musig_input_pub_nonce          |
| MusigPartialSignature (musig)   | 0x1c via set_musig_input_partial_sig        |
| MusigPubNonce / PartialSig      | ignored without the musig feature           |
| Unknown, any other variant      | ignored                                     |
+---------------------------------+---------------------------------------------+
```

Round rule: the app runs MuSig2 round 2 whenever the PSBT carries any
`PSBT_IN_MUSIG2_PUB_NONCE`, and round 1 (pubnonces only, no user approval when it signs
musig keys only) otherwise. The caller sends round 1 with every pubnonce removed
(`bwk_psbt::musig::remove_musig_input_pub_nonces` on a copy) and merges the device's
nonces into the shared PSBT, then sends round 2 once every participant's nonce is
there, with the same unsigned transaction. `sign_tx` does not strip nonces itself. A
round 1 sent with a cosigner's nonce runs round 2: after the approval the app asks for
its own missing pubnonce, the client cannot answer, and `sign_tx` fails with
`Error::Device("Interpreter(\n    UnknownHash,\n)")`.

The PSBT goes to the device as bwk's updater writes it: next to the aggregate's
`[agg_fp]/<a or a+1>/i` `tap_key_origins` entry, each cosigner's own
`[fp/87'/1'/0'/R]` entry. App 2.4.6 accepts it (it only matches musig() keys against
2-step entries under the aggregate's fingerprint), so nothing is stripped.

Registration and address checks of `musig()` policies work as is: the client's paranoid
check replaces each `musig()` by its aggregate xpub before miniscript parses the
descriptor.

## Speculos tests

`tests/ledger_speculos.rs` drives `LedgerSimulator` against the Ledger Bitcoin Test
app running under [Speculos](https://github.com/LedgerHQ/speculos), and
`tests/ledger_musig_speculos.rs` (features `ledger,musig`) registers bwk-bup 2-of-2
`tr(musig(L,H))` and `tr(NUMS,pk(musig(L,H)))` policies and spends both through the two
MuSig2 rounds with a bwk `HotSigner` as the other cosigner. The tests are
`#[ignore]`d; run them with `tests/speculos/run.sh [nanox|nanosp]`, or `just test-ledger`
in `hwi/` for both devices. Docker is the only prerequisite.

`run.sh` builds the app ELF with the pinned builder image (cached in
`target/speculos-cache/`), then runs both test binaries with `SPECULOS_BIN` pointing at
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
