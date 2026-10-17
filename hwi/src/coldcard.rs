#[cfg(unix)]
use std::{io::ErrorKind, path::Path};
use std::{
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use bitcoin::{
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    secp256k1::PublicKey,
};
use hidapi::DeviceInfo;

use coldcard::protocol::DescriptorName;

use crate::{
    parse_version,
    utils::{self, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS},
    AddressScript, DeviceKind, Error as HWIError, Version, HWI,
};
pub use coldcard as api;

/// Pause between two `get_signed_tx` polls while the user reviews the transaction.
const SIGNED_TX_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// What the firmware raises on a lost MuSig2 session (`shared/psbt.py`,
/// `musig_process_input`, at coldcard/firmware 04e949d6): its own pubnonce in a
/// round 1 PSBT, or missing from a round 2 one.
const MUSIG_SESSION_TEXTS: [&str; 2] = ["musig needs restart", "resign"];
/// The answer to the signed transaction poll when signing raised after the user
/// approved (`shared/auth.py`, `ApproveTransaction.interact`, same commit); the reason
/// only goes to the screen.
const SIGNING_FAILED_LATE: &str = "Signing failed late";
const PUBLIC_KEY_LEN: usize = 33;

#[derive(Debug)]
pub struct Coldcard {
    device: Arc<Mutex<coldcard::Coldcard>>,
    wallet_name: Option<String>,
    kind: DeviceKind,
}

/// The Coldcard simulator, reached over its Unix datagram socket.
pub type ColdcardSimulator = Coldcard;

impl Coldcard {
    /// Connects to the simulator at `socket` as ckcc-protocol's
    /// `ColdcardDevice(sn=<socket>)` does; kind `ColdcardSimulator`.
    #[cfg(unix)]
    pub fn connect_simulator(socket: &Path) -> Result<Self, HWIError> {
        let (cc, _) = api::Coldcard::open_simulator(socket, None).map_err(|e| match e {
            api::Error::Io(e)
                if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) =>
            {
                HWIError::DeviceNotFound
            }
            e => e.into(),
        })?;
        Ok(Coldcard {
            device: Arc::new(Mutex::new(cc)),
            wallet_name: None,
            kind: DeviceKind::ColdcardSimulator,
        })
    }

    pub fn with_wallet_name(mut self, wallet_name: String) -> Self {
        self.wallet_name = Some(wallet_name);
        self
    }

    fn device(&self) -> Result<MutexGuard<'_, coldcard::Coldcard>, HWIError> {
        self.device
            .lock()
            .map_err(|_| HWIError::Unexpected("Failed to unlock"))
    }
}

impl From<coldcard::Coldcard> for Coldcard {
    fn from(cc: coldcard::Coldcard) -> Self {
        Coldcard {
            device: Arc::new(Mutex::new(cc)),
            wallet_name: None,
            kind: DeviceKind::Coldcard,
        }
    }
}

impl HWI for Coldcard {
    fn device_kind(&self) -> DeviceKind {
        self.kind
    }

    /// The first semver version returned by coldcard is the firmware version.
    fn get_version(&self) -> Result<Version, HWIError> {
        let s = self.device()?.version()?;
        for line in s.split('\n') {
            if let Ok(version) = parse_version(line) {
                return Ok(version);
            }
        }
        Err(HWIError::UnsupportedVersion)
    }

    fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        master_fingerprint(&mut *self.device()?)
    }

    fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let path = path.to_string();
        let path = if path.starts_with("m/") {
            path
        } else {
            format!("m/{path}")
        };
        let path = coldcard::protocol::DerivationPath::new(&path)
            .map_err(|e| HWIError::InvalidParameter("path", format!("{e:?}")))?;
        let s = self.device()?.xpub(Some(path))?;
        Xpub::from_str(&s).map_err(|e| HWIError::Device(e.to_string()))
    }

    fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        if let Some(name) = &self.wallet_name {
            let descriptor_name = coldcard::protocol::DescriptorName::new(name)
                .map_err(|_| HWIError::UnsupportedInput)?;
            if let AddressScript::Miniscript { index, change } = script {
                self.device()?
                    .miniscript_address(descriptor_name, *change, *index)?;
                Ok(())
            } else {
                Err(HWIError::UnimplementedMethod)
            }
        } else {
            Err(HWIError::UnimplementedMethod)
        }
    }

    fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, HWIError> {
        let payload = format!("{{\"name\":\"{name}\",\"desc\":\"{policy}\"}}");
        self.device()?.miniscript_enroll(payload.as_bytes())?;
        Ok(None)
    }

    fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError> {
        let descriptor_name = coldcard::protocol::DescriptorName::new(name)
            .map_err(|_| HWIError::UnsupportedInput)?;
        let desc = self.device()?.miniscript_get(descriptor_name)?;
        if let Some(desc) = desc {
            // the device answers with `h` hardened markers
            let policy = policy.replace('\'', "h");
            let policy = policy.split_once('#').map_or(policy.as_str(), |(p, _)| p);
            Ok(desc.contains(policy))
        } else {
            Ok(false)
        }
    }

    fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        let mut cc = self.device()?;

        let wallet_name = if let Some(name) = self.wallet_name.clone() {
            Some(
                DescriptorName::new(name)
                    .map_err(|_| HWIError::Unexpected("Coldcard: Invalid wallet name"))?,
            )
        } else {
            None
        };

        let tx =
            sign_and_wait(&mut cc, psbt, wallet_name).map_err(|e| sign_error(&mut cc, e, psbt))?;

        let new_psbt = Psbt::deserialize(&tx).map_err(|e| HWIError::Device(e.to_string()))?;
        if new_psbt.inputs.len() != psbt.inputs.len() {
            return Err(HWIError::Device(format!(
                "Coldcard returned a PSBT with {} inputs, expected {}",
                new_psbt.inputs.len(),
                psbt.inputs.len()
            )));
        }

        utils::merge_signatures(psbt, &new_psbt);
        utils::merge_musig_fields(psbt, &new_psbt);

        Ok(())
    }
}

fn master_fingerprint(cc: &mut coldcard::Coldcard) -> Result<Fingerprint, HWIError> {
    let s = cc.xpub(None)?;
    let xpub = Xpub::from_str(&s).map_err(|e| HWIError::Device(e.to_string()))?;
    Ok(xpub.fingerprint())
}

/// Sends `psbt` for signing and polls until the device answers with the signed PSBT.
fn sign_and_wait(
    cc: &mut coldcard::Coldcard,
    psbt: &Psbt,
    wallet_name: Option<DescriptorName>,
) -> Result<Vec<u8>, api::Error> {
    cc.sign_psbt_miniscript(&psbt.serialize(), api::SignMode::Signed, wallet_name)?;
    loop {
        if let Some(tx) = cc.get_signed_tx()? {
            return Ok(tx);
        }
        thread::sleep(SIGNED_TX_POLL_INTERVAL);
    }
}

/// `MusigSession` when the device error means it lost the MuSig2 session of `psbt`
/// (see [`musig_session_error`]), else the plain mapping. The fingerprint is only
/// read for a protocol error.
fn sign_error(cc: &mut coldcard::Coldcard, e: api::Error, psbt: &Psbt) -> HWIError {
    match e {
        api::Error::Decoding(api::protocol::DecodeError::Protocol(ref text))
            if master_fingerprint(cc)
                .is_ok_and(|fingerprint| musig_session_error(text, psbt, fingerprint)) =>
        {
            HWIError::MusigSession
        }
        e => e.into(),
    }
}

/// True when the device error `text` reports a lost MuSig2 session: the firmware's
/// own reason when it forwards it, or "Signing failed late" on a PSBT where the
/// device (`fingerprint`) is a MuSig2 participant.
fn musig_session_error(text: &str, psbt: &Psbt, fingerprint: Fingerprint) -> bool {
    MUSIG_SESSION_TEXTS
        .iter()
        .any(|reason| text.contains(reason))
        || (text == SIGNING_FAILED_LATE && is_musig_participant(psbt, fingerprint))
}

/// True when a participant key of an input's 0x1a entries has a `tap_key_origins`
/// entry with `fingerprint`.
fn is_musig_participant(psbt: &Psbt, fingerprint: Fingerprint) -> bool {
    psbt.inputs.iter().any(|input| {
        input
            .unknown
            .iter()
            .filter(|(key, _)| key.type_value == PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)
            .flat_map(|(_, participants)| participants.chunks(PUBLIC_KEY_LEN))
            .filter_map(|participant| PublicKey::from_slice(participant).ok())
            .any(|participant| {
                input
                    .tap_key_origins
                    .get(&participant.x_only_public_key().0)
                    .is_some_and(|(_, (origin, _))| *origin == fingerprint)
            })
    })
}

impl From<api::Error> for HWIError {
    fn from(e: api::Error) -> Self {
        if let api::Error::UnexpectedResponse(api::protocol::Response::Refused) = e {
            HWIError::UserRefused
        } else {
            HWIError::Device(e.to_string())
        }
    }
}

impl From<Coldcard> for Box<dyn HWI + Send> {
    fn from(s: Coldcard) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl From<Coldcard> for Arc<dyn HWI + Sync + Send> {
    fn from(s: Coldcard) -> Arc<dyn HWI + Sync + Send> {
        Arc::new(s)
    }
}

pub fn is_coldcard(device_info: &DeviceInfo) -> bool {
    device_info.vendor_id() == api::COINKITE_VID && device_info.product_id() == api::CKCC_PID
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        absolute::LockTime,
        bip32::{DerivationPath, Fingerprint},
        psbt::{raw::Key, Psbt},
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        transaction::Version,
        Transaction, TxIn,
    };

    use crate::{
        coldcard::{musig_session_error, SIGNING_FAILED_LATE},
        utils::PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    };

    /// The fingerprint of the device under test.
    fn device() -> Fingerprint {
        Fingerprint::from([0xcc; 4])
    }

    fn other() -> Fingerprint {
        Fingerprint::from([0xdd; 4])
    }

    fn pubkey(byte: u8) -> PublicKey {
        SecretKey::from_slice(&[byte; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
    }

    fn one_input_psbt() -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        })
        .unwrap()
    }

    /// An input with a 0x1a entry of the keys 1 and 2, key 2 having an origin with
    /// the `device()` fingerprint.
    fn musig_psbt() -> Psbt {
        let mut psbt = one_input_psbt();
        let input = &mut psbt.inputs[0];
        input.unknown.insert(
            Key {
                type_value: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
                key: pubkey(3).serialize().to_vec(),
            },
            [pubkey(1).serialize(), pubkey(2).serialize()].concat(),
        );
        input.tap_key_origins.insert(
            pubkey(2).x_only_public_key().0,
            (
                vec![],
                (device(), DerivationPath::from_str("m/87'/1'/0'/2").unwrap()),
            ),
        );
        psbt
    }

    #[test]
    fn firmware_reason_is_a_musig_session_error() {
        for text in ["musig needs restart", "resign"] {
            assert!(musig_session_error(text, &one_input_psbt(), other()));
            assert!(musig_session_error(text, &musig_psbt(), device()));
        }
    }

    #[test]
    fn signing_failed_late_needs_a_participant() {
        assert!(musig_session_error(
            SIGNING_FAILED_LATE,
            &musig_psbt(),
            device()
        ));
        assert!(!musig_session_error(
            SIGNING_FAILED_LATE,
            &musig_psbt(),
            other()
        ));
        assert!(!musig_session_error(
            SIGNING_FAILED_LATE,
            &one_input_psbt(),
            device()
        ));
    }

    #[test]
    fn other_errors_are_not_musig_session_errors() {
        assert!(!musig_session_error(
            "Invalid PSBT",
            &musig_psbt(),
            device()
        ));
    }
}
