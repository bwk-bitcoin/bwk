//! Speculos helpers shared by the Ledger test binaries.

use std::{str::FromStr, time::Duration};

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bwk_hwi::{ledger::LedgerSimulator, HWI};
use regex::Regex;
use speculos::{Button, Speculos};

/// /reset does not fully clear the embedded app's wallet-policy text
/// buffer or prior register-wallet state, so we boot per-test.
pub fn fresh_speculos() -> Speculos {
    Speculos::launch_model(speculos_model()).expect("Speculos::launch_model")
}

/// The device `SPECULOS_MODEL` names.
pub fn speculos_model() -> speculos::Model {
    std::env::var("SPECULOS_MODEL")
        .expect("SPECULOS_MODEL")
        .parse::<speculos::Model>()
        .expect("parse model")
}

pub fn connect_to(sim: &Speculos) -> LedgerSimulator {
    LedgerSimulator::try_connect_on(sim.apdu_addr()).expect("connect to Speculos APDU port")
}

pub fn get_xpub_for_path(device: &LedgerSimulator, path: &str) -> String {
    let derivation = DerivationPath::from_str(path).expect("valid derivation path");
    let fp = device
        .get_master_fingerprint()
        .expect("get_master_fingerprint");
    let xpub = device
        .get_extended_pubkey(&derivation)
        .expect("get_extended_pubkey");
    key_origin(fp, &derivation, &xpub)
}

/// `[fp/path]xpub`, the key text of a wallet policy.
pub fn key_origin(fingerprint: Fingerprint, path: &DerivationPath, xpub: &Xpub) -> String {
    let path = path.to_string();
    let path = path.trim_start_matches("m/");
    format!("[{fingerprint:x}/{path}]{xpub}")
}

/// `tr(internal, and_v(v:pk(leaf), older(50)))` single-leaf miniscript.
pub fn tr_1leaf_policy(internal: &str, leaf: &str) -> String {
    format!("tr({internal}/**,and_v(v:pk({leaf}/**),older(50)))")
}

/// Registration of `tr_1leaf_policy` with the device key as the internal key.
pub const REGISTER_STEPS_TR_1LEAF_ACK: &[(&str, Button)] = &[
    ("Review account", Button::Right),
    ("Account name", Button::Right),
    ("Wallet policy", Button::Right),
    ("Review co-signer", Button::Right),
    ("Our key@0 (1/3)", Button::Right),
    ("Our key@0 (2/3)", Button::Right),
    ("Our key@0 (3/3)", Button::Right),
    ("Their key@1 (1/3)", Button::Right),
    ("Their key@1 (2/3)", Button::Right),
    ("Their key@1 (3/3)", Button::Right),
    ("Register account", Button::Both),
];

/// Display of a `tr_1leaf_policy` address.
pub const DISPLAY_STEPS_TR_1LEAF: &[(&str, Button)] = &[
    ("Verify bitcoin", Button::Right),
    ("Address (1/2)", Button::Right),
    ("Address (2/2)", Button::Right),
    ("Account name", Button::Right),
    ("Confirm", Button::Both),
];

/// Whether `text` was shown since `sim` started.
pub fn screen_seen(sim: &Speculos, text: &str) -> bool {
    sim.events().unwrap().iter().any(|e| e.text == text)
}

pub fn run_steps(sim: &Speculos, steps: &[(&str, Button)]) {
    for &(text, button) in steps {
        screen_contains(sim, text);
        sim.press(button).unwrap();
    }
}

pub fn screen_contains(sim: &Speculos, expected: &str) {
    let re = Regex::new(&format!("^{}$", regex::escape(expected))).unwrap();
    if sim.wait_for(&re, Duration::from_secs(10)).is_err() {
        let last_screens: Vec<_> = sim
            .events()
            .unwrap()
            .into_iter()
            .rev()
            .take(12)
            .map(|e| e.text)
            .collect();
        let msg = format!(
            "expected screen {expected:?}; recent screens (newest first): {last_screens:?}"
        );
        panic!("{}", msg);
    }
}

/// Register `policy` to ack and return the hmac. Panics on any
/// non-success outcome. Used by display/sign helpers that need a
/// registered wallet before they can exercise their own flow.
pub fn register_for_hmac(
    sim: &Speculos,
    device: LedgerSimulator,
    name: &str,
    policy: &str,
    register_steps: &[(&str, Button)],
) -> [u8; 32] {
    let name = name.to_string();
    let policy = policy.to_string();
    let task = std::thread::spawn(move || device.register_wallet(&name, &policy));
    run_steps(sim, register_steps);
    match task.join().unwrap() {
        Ok(Some(hmac)) => {
            assert_eq!(hmac.len(), 32, "expected 32-byte hmac from register_wallet");
            hmac
        }
        other => {
            let msg = format!("register_for_hmac unexpected outcome: {other:?}");
            panic!("{}", msg);
        }
    }
}

/// Click sequence for a transaction-review flow on Nano X / Nano S Plus.
/// `from_screen=true` adds the multisig "From <wallet-name>" page that
/// the device shows for non-default wallet policies. `to_pages` is the
/// pagination count of the "To" address screen (1 for short bech32
/// wpkh addresses, 2 for longer wsh / taproot addresses).
pub fn sign_steps(ack: bool, from_screen: bool, to_pages: u32) -> Vec<(String, Button)> {
    let mut steps: Vec<(String, Button)> = vec![("Review transaction".into(), Button::Right)];
    if from_screen {
        steps.push(("From".into(), Button::Right));
    }
    steps.push(("Amount".into(), Button::Right));
    if to_pages == 1 {
        steps.push(("To".into(), Button::Right));
    } else {
        for i in 1..=to_pages {
            steps.push((format!("To ({i}/{to_pages})"), Button::Right));
        }
    }
    steps.push(("Fees".into(), Button::Right));
    if ack {
        steps.push(("Sign transaction".into(), Button::Both));
    } else {
        steps.push(("Sign transaction".into(), Button::Right));
        steps.push(("Reject transaction".into(), Button::Both));
    }
    steps
}

pub fn sign_step_refs(steps: &[(String, Button)]) -> Vec<(&str, Button)> {
    steps.iter().map(|(s, b)| (s.as_str(), *b)).collect()
}

/// `HwiService` over Speculos: the service finds the simulator on the port it polls.
#[cfg(feature = "service")]
pub mod service {
    use std::{
        net::{Ipv4Addr, SocketAddr, TcpListener},
        path::Path,
        time::{Duration, Instant},
    };

    use bitcoin::Network;
    use bwk_hwi::service::{HwiService, SigningDevice, SigningDeviceMsg, SupportedDevice};
    use crossbeam::channel::{self, Receiver};
    use speculos::{Button, SpawnOptions, Speculos};

    use crate::common::{
        speculos::{run_steps, speculos_model},
        SPECULOS_DEFAULT_FINGERPRINT,
    };

    /// The APDU port `HwiService` polls for the Ledger simulator.
    const SERVICE_APDU_PORT: u16 = 9999;
    /// How long the service gets to list the device or to answer a request.
    const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
    /// The Ledger simulator in the service's device map.
    pub const SERVICE_DEVICE_ID: &str = "ledger-simulator";

    /// The message type of the test service.
    #[derive(Debug, Clone)]
    pub struct Msg(pub SigningDeviceMsg<u64>);

    impl From<SigningDeviceMsg<u64>> for Msg {
        fn from(msg: SigningDeviceMsg<u64>) -> Self {
            Self(msg)
        }
    }

    /// Speculos on the port the service polls, and a started `HwiService` listing it.
    /// Dropping it stops the service before Speculos goes.
    pub struct SpeculosService {
        pub service: HwiService<Msg, u64>,
        pub rx: Receiver<Msg>,
        pub sim: Speculos,
    }

    impl SpeculosService {
        /// Waits for the port of the previous test's Speculos, launches Speculos on it,
        /// starts the service and waits until it lists the device as supported.
        pub fn launch() -> Self {
            let apdu = SocketAddr::from((Ipv4Addr::LOCALHOST, SERVICE_APDU_PORT));
            wait_for_free_port(apdu);
            let elf = std::env::var("SPECULOS_ELF").expect("SPECULOS_ELF");
            let options = SpawnOptions {
                apdu: Some(apdu),
                api: None,
                seed: None,
            };
            let sim = Speculos::launch_with(Path::new(&elf), speculos_model(), options).unwrap();
            let service = HwiService::new(Network::Testnet);
            let (sender, rx) = channel::unbounded();
            service.start(sender);
            let this = Self { service, rx, sim };
            this.wait_for_device();
            this
        }

        fn wait_for_device(&self) {
            let deadline = Instant::now() + SERVICE_TIMEOUT;
            while Instant::now() < deadline {
                if let Some(SigningDevice::Supported(device)) =
                    self.service.list().get(SERVICE_DEVICE_ID)
                {
                    assert_eq!(
                        format!("{:x}", device.fingerprint()),
                        SPECULOS_DEFAULT_FINGERPRINT
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            panic!("the service did not list {SERVICE_DEVICE_ID} as supported");
        }

        /// The Ledger simulator as the service lists it.
        pub fn device(&self) -> SupportedDevice<Msg, u64> {
            match self.service.list().get(SERVICE_DEVICE_ID) {
                Some(SigningDevice::Supported(device)) => device.clone(),
                other => panic!("{SERVICE_DEVICE_ID} is not supported: {other:?}"),
            }
        }

        /// Sends request `id` through `call`, walks `steps` while it runs, then returns its
        /// answer.
        pub fn request(
            &self,
            id: u64,
            steps: &[(&str, Button)],
            call: impl FnOnce(&SupportedDevice<Msg, u64>, u64),
        ) -> SigningDeviceMsg<u64> {
            call(&self.device(), id);
            run_steps(&self.sim, steps);
            self.expect_msg(id, SERVICE_TIMEOUT)
        }

        /// The next message answering request `id`, skipping `Update`, polling errors and
        /// answers to other requests.
        pub fn expect_msg(&self, id: u64, timeout: Duration) -> SigningDeviceMsg<u64> {
            let deadline = Instant::now() + timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let Msg(msg) = self
                    .rx
                    .recv_timeout(left)
                    .unwrap_or_else(|e| panic!("no answer to request {id}: {e}"));
                if request_id(&msg) == Some(id) {
                    return msg;
                }
            }
        }
    }

    impl Drop for SpeculosService {
        fn drop(&mut self) {
            self.service.stop();
        }
    }

    fn request_id(msg: &SigningDeviceMsg<u64>) -> Option<u64> {
        match msg {
            SigningDeviceMsg::Error(id, _) => *id,
            SigningDeviceMsg::Update => None,
            SigningDeviceMsg::XPub(id, ..)
            | SigningDeviceMsg::Version(id, ..)
            | SigningDeviceMsg::WalletRegistered(id, ..)
            | SigningDeviceMsg::WalletIsRegistered(id, ..)
            | SigningDeviceMsg::AddressDisplayed(id, ..)
            | SigningDeviceMsg::TransactionSigned(id, ..) => Some(*id),
        }
    }

    /// The Speculos container of the previous test leaves within seconds of its kill.
    fn wait_for_free_port(addr: SocketAddr) {
        let deadline = Instant::now() + SERVICE_TIMEOUT;
        while TcpListener::bind(addr).is_err() {
            if Instant::now() > deadline {
                panic!("{addr} is taken: the service polls only this port for Speculos, free it");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}
