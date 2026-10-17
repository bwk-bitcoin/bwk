# Service Module

The `service` module provides a hardware wallet device discovery and management
service. It polls for connected hardware wallets every 2 seconds and maintains a
shared device map with support for multiple concurrent consumers via
reference-counted start/stop.

## Features

- Automatic device discovery and connection
- Support for multiple concurrent consumers
- Reference-counted service lifecycle management
- Device operations via message passing
- BitBox02 pairing configuration support

## Core Types

### `HwiService<Message, Id>`

The main service struct that manages device discovery and maintains the device map.

```rust
use bwk_hwi::service::{HwiService, SigningDeviceMsg};
use bitcoin::Network;
use crossbeam::channel;

// Define your application message type
#[derive(Clone)]
enum AppMessage {
    Device(SigningDeviceMsg),
    // ... other app messages
}

impl From<SigningDeviceMsg> for AppMessage {
    fn from(msg: SigningDeviceMsg) -> Self {
        AppMessage::Device(msg)
    }
}

// Create the service
let service: HwiService<AppMessage> = HwiService::new(
    Network::Bitcoin,
    None, // Optional noise config for BitBox02
);
```

### `SigningDevice<Message, Id>`

Represents a detected hardware wallet in one of three states:

- **`Supported`**: Device is ready for use
- **`Locked`**: Device requires unlocking (e.g., PIN entry, pairing confirmation)
- **`Unsupported`**: Device detected but cannot be used (wrong version, wrong
network, etc.)

### `SigningDeviceMsg<Id>`

Messages emitted by the service when device state changes:

```rust
pub enum SigningDeviceMsg<Id = ()> {
    /// Error (None for polling errors, Some(id) for operation errors)
    Error(Option<Id>, String),
    /// Device map changed
    Update,
    /// Extended public key retrieved
    XPub(Id, Fingerprint, DerivationPath, Xpub),
    /// Device version retrieved
    Version(Id, Fingerprint, Version),
    /// Wallet registered with optional HMAC (Ledger), to send back in
    /// `DeviceWallet::hmac`
    WalletRegistered(Id, Fingerprint, String, Option<[u8; 32]>),
    /// Wallet registration check result
    WalletIsRegistered(Id, Fingerprint, String, bool),
    /// Address displayed on device
    AddressDisplayed(Id, Fingerprint, AddressScript),
    /// Transaction signed
    TransactionSigned(Id, Fingerprint, Psbt),
}
```

## Usage

### Basic Setup

```rust
use bwk_hwi::service::{HwiService, SigningDevice, SigningDeviceMsg};
use bitcoin::Network;
use crossbeam::channel;
use std::sync::Arc;

#[derive(Clone)]
enum AppMessage {
    Device(SigningDeviceMsg),
}

impl From<SigningDeviceMsg> for AppMessage {
    fn from(msg: SigningDeviceMsg) -> Self {
        AppMessage::Device(msg)
    }
}

fn main() {
    // Create a channel for receiving device messages
    let (sender, receiver) = channel::unbounded();

    // Create the service
    let service: Arc<HwiService<AppMessage>> = Arc::new(
        HwiService::new(Network::Bitcoin, None)
    );

    // Start the service (reference counted)
    service.start(sender);

    // Process messages in your application loop
    loop {
        match receiver.recv() {
            Ok(AppMessage::Device(SigningDeviceMsg::Update)) => {
                // Device list changed, refresh UI
                let devices = service.list();
                for (id, device) in devices {
                    match device {
                        SigningDevice::Supported(supported) => {
                            println!("Ready: {} ({:?}) - {}",
                                id,
                                supported.kind(),
                                supported.fingerprint()
                            );
                        }
                        SigningDevice::Locked { id, kind, pairing_code, .. } => {
                            println!("Locked: {} ({:?})", id, kind);
                            if let Some(code) = pairing_code {
                                println!("  Pairing code: {}", code);
                            }
                        }
                        SigningDevice::Unsupported { id, kind, reason, .. } => {
                            println!("Unsupported: {} ({:?}) - {:?}", id, kind,reason);
                        }
                    }
                }
            }
            Ok(AppMessage::Device(SigningDeviceMsg::Error(id, err))) => {
                eprintln!("Error (id={:?}): {}", id, err);
            }
            Ok(AppMessage::Device(msg)) => {
                // Handle other device messages
                println!("Device message: {:?}", msg);
            }
            Err(_) => break,
        }
    }

    // Stop the service when done
    service.stop();
}
```

### Using Device Operations

Operations on `SupportedDevice` return results via the message
channel:

```rust
use bwk_hwi::service::{SigningDevice, SigningDeviceMsg, SupportedDevice};
use bitcoin::bip32::DerivationPath;
use std::str::FromStr;

// Get a supported device from the service
let devices = service.list();
for (id, device) in devices {
    if let SigningDevice::Supported(supported) = device {
        // Request an extended public key, pass true to also show it on the device
        // Results arrive via SigningDeviceMsg::XPub
        let path = DerivationPath::from_str("m/84'/0'/0'").unwrap();
        supported.get_extended_pubkey((), &path, false);

        // Register a wallet policy
        // Results arrive via SigningDeviceMsg::WalletRegistered
        supported.register_wallet(
            (),
            "My Wallet",
            "wsh(sortedmulti(2,@0/**,@1/**))"
        );

        // Check if wallet is registered
        // Results arrive via SigningDeviceMsg::WalletIsRegistered
        supported.is_wallet_registered(
            (),
            "My Wallet",
            "wsh(sortedmulti(2,@0/**,@1/**))"
        );

        // Display an address on the device
        // Results arrive via SigningDeviceMsg::AddressDisplayed
        use bwk_hwi::AddressScript;
        let path = DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
        supported.display_address((), &AddressScript::P2TR(path));

        // Sign a PSBT
        // Results arrive via SigningDeviceMsg::TransactionSigned
        // supported.sign_tx((), psbt);

        // Sign a PSBT or display a miniscript address of a registered wallet: the
        // name and policy given to register_wallet, and the HMAC it answered
        use bwk_hwi::DeviceWallet;
        // From SigningDeviceMsg::WalletRegistered(_, _, _, Some(hmac))
        let hmac: [u8; 32] = registered_hmac;
        let wallet = DeviceWallet {
            name: "My Wallet".into(),
            policy: "wsh(sortedmulti(2,[aabbccdd/48'/1'/0'/2']tpub.../**,...))".into(),
            hmac: Some(hmac),
        };
        // Results arrive via SigningDeviceMsg::TransactionSigned
        // supported.sign_tx_with_wallet((), psbt, wallet.clone());
        // Results arrive via SigningDeviceMsg::AddressDisplayed
        supported.display_address_with_wallet(
            (),
            &AddressScript::Miniscript { index: 0, change: false },
            wallet,
        );
    }
}
```

### Ledger

The Ledger holds no wallet: every signing request and every miniscript address
display needs the wallet policy and the HMAC `register_wallet` answered
(`SigningDeviceMsg::WalletRegistered`). Send them with `sign_tx_with_wallet` and
`display_address_with_wallet`; the HMAC covers the wallet name, so the name must be
the one given at registration. Plain `sign_tx` answers `Error(Some(id), "Unimplemented
method")` and a miniscript `display_address` `Error(Some(id), "Missing policy")`. A
wrong HMAC is refused by the device (`Error(Some(id), ..)` with status
`IncorrectData`). Other devices hold their registered policies and ignore the wallet
sent with these two requests. The HMAC is never logged.

`get_extended_pubkey` of a path the app refuses to export silently asks again with
the xpub shown on the device: app 2.4.x exports BIP-87 account xpubs (`m/87'/..`)
only after the user approves them, 2.5.0 and later without a screen.

### Using Request IDs

The `Id` type parameter allows tracking which request a response corresponds to:

```rust
use bwk_hwi::service::{HwiService, SigningDeviceMsg};

#[derive(Clone, Debug)]
struct RequestId(u64);

#[derive(Clone)]
enum AppMessage {
    Device(SigningDeviceMsg<RequestId>),
}

impl From<SigningDeviceMsg<RequestId>> for AppMessage {
    fn from(msg: SigningDeviceMsg<RequestId>) -> Self {
        AppMessage::Device(msg)
    }
}

// Create service with custom ID type
let service: HwiService<AppMessage, RequestId> = HwiService::new(Network::Bitcoin,
None);

// Later, when making requests:
// supported.get_extended_pubkey(RequestId(42), &path, false);

// When handling responses:
// SigningDeviceMsg::XPub(RequestId(42), fingerprint, path, xpub)
```

### BitBox02 Pairing Configuration

For BitBox02 devices, you can provide a noise configuration to persist pairing:

```rust
use bwk_hwi::bitbox::api::noise::{NoiseConfig, NoiseConfigData, ConfigError};
use std::sync::Arc;

struct MyNoiseConfig {
    // Your storage implementation
}

impl bwk_hwi::bitbox::api::util::Threading for MyNoiseConfig {}

impl NoiseConfig for MyNoiseConfig {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        // Read from your storage
        todo!()
    }

    fn store_config(&self, data: &NoiseConfigData) -> Result<(), ConfigError> {
        // Write to your storage
        todo!()
    }
}

// Set the configuration before starting the service
let noise_config: Arc<dyn NoiseConfig> = Arc::new(MyNoiseConfig { /* ... */ });
service.set_bitbox_noise_config(noise_config);

// Start the service
service.start(sender);

// Later, if needed:
// service.clear_bitbox_noise_config();
```

### Multiple Consumers

The service supports multiple concurrent consumers with reference counting:

```rust
// First consumer starts the service
service.start(sender1.clone());

// Second consumer increments ref count (service already running)
service.start(sender2.clone());

// First consumer done - decrements ref count (service keeps running)
service.stop();

// Second consumer done - decrements ref count to 0, service stops
service.stop();
```

## Device States

### Supported Devices

A `SupportedDevice` provides access to:
- `device()` - The underlying `HWI` trait object
- `version()` - Device firmware version
- `fingerprint()` - Master key fingerprint
- `kind()` - Device type (Ledger, BitBox02, etc.)

### Locked Devices

Devices in the `Locked` state require user interaction:
- **BitBox02**: Requires pairing confirmation on device (displays pairing code)
- **Jade**: Requires PIN entry and blind oracle authentication

The service automatically attempts to unlock devices. Monitor
`SigningDeviceMsg::Update` for state transitions.

### Unsupported Devices

Devices may be unsupported for various reasons:

```rust
pub enum UnsupportedReason {
    /// Firmware version too old
    Version { minimal_supported_version: &'static str },
    /// Method not supported by device
    Method(&'static str),
    /// Device not part of wallet (fingerprint mismatch)
    NotPartOfWallet(Fingerprint),
    /// Device configured for different network
    WrongNetwork,
    /// Ledger: Bitcoin app not open
    AppIsNotOpen,
}
```

## Simulators

The Ledger simulator (Speculos) is probed on `127.0.0.1:9999` every poll cycle and
listed as `ledger-simulator`.

The Coldcard simulator is probed only when `BWK_COLDCARD_SIMULATOR`
(`service::COLDCARD_SIMULATOR_ENV`, Unix only) holds the path of its socket, for
example `/tmp/ckcc-simulator.sock` or `/tmp/ckcc-simulator-<pid>.sock` with
`--segregate`. The variable is read when the listener starts; when it is unset the
service never touches a socket. The device is listed as `coldcard-simulator` with
kind `ColdcardSimulator` and no firmware version gate, since the simulator only
reports its bootloader version.

It is dropped when its socket goes away or the path names another file (a
restarted simulator), and found again once a simulator answers on the path.

## Taproot Miniscript Compatibility

Check if a device supports Taproot Miniscript:

```rust
use bwk_hwi::service::is_compatible_with_tapminiscript;
use bwk_hwi::DeviceKind;

let compatible = is_compatible_with_tapminiscript(
    &DeviceKind::Ledger,
    Some(&version)
);
```

Minimum versions for Taproot Miniscript support:
- Ledger: v2.2.0
- Coldcard: v6.3.3
- Coldcard simulator: All versions
- BitBox02: v9.21.0
- Specter: All versions

## MuSig2 Session Errors

`SigningDeviceMsg::Error` carries the error as text. A device that no longer holds
the MuSig2 session of a PSBT answers `Error::MusigSession`, whose text is
`bwk_hwi::MUSIG_SESSION_ERROR`; compare with it to tell this case apart, then start
again from round 1 with every signer.

```
+----------+--------------------------------------------------------------------+
| Device   | When                                                               |
+----------+--------------------------------------------------------------------+
| Ledger   | SW_BAD_STATE (0xB007) on a PSBT carrying a pubnonce (0x1b): round  |
|          | 2 without the session round 1 stored (restart, round 2 sent twice) |
| Coldcard | "musig needs restart" or "resign" in the error, or "Signing failed |
|          | late" on a PSBT where the device is a MuSig2 participant (round 1  |
|          | holding its own pubnonce after a restart, round 1 sent twice)      |
+----------+--------------------------------------------------------------------+
```

The same SW_BAD_STATE without a pubnonce, and "Signing failed late" on a PSBT the
Coldcard is no MuSig2 participant of, stay `Error::Device`.

A Coldcard answer keeps its BIP-373 entries: participants (0x1a), pubnonces (0x1b)
and partial signatures (0x1c) are copied into the PSBT next to the signatures. The
Coldcard only signs an input whose `tap_key_origins` list every key of the enrolled
wallet: a PSBT restricted to one leaf must keep them all.
