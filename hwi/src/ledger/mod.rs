use std::convert::TryFrom;
use std::default::Default;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
};

use ledger_apdu::APDUAnswer;

use crate::{
    ledger::bitcoin_client::{
        apdu::{APDUCommand, StatusWord},
        client::{BitcoinClient, Transport},
        error::BitcoinClientError,
        protocol::SignPsbtYieldedObject,
        psbt::PartialSignature,
        wallet::{Version as WalletVersion, WalletPolicy, WalletPubKey},
    },
    ledger::transport_hidapi::TransportNativeHID,
    parse_version, utils, AddressScript, DeviceKind, Error as HWIError, HWI,
};

#[cfg(feature = "musig")]
use bwk_psbt::musig::{
    set_musig_input_partial_sig, set_musig_input_pub_nonce, MusigPartialSig, MusigPubNonce,
};

pub mod bitcoin_client;
mod transport_hidapi;

pub use hidapi;
use hidapi::{DeviceInfo, HidApi};

const RECV_INDEX: ChildNumber = ChildNumber::Normal { index: 0 };
const CHANGE_INDEX: ChildNumber = ChildNumber::Normal { index: 1 };

#[derive(Default)]
struct CommandOptions {
    wallet: Option<(WalletPolicy, Option<[u8; 32]>)>,
    display_xpub: Mutex<bool>,
}

pub struct Ledger<T: Transport> {
    client: BitcoinClient<T>,
    options: CommandOptions,
    kind: DeviceKind,
}

impl<T: Transport> Ledger<T> {
    pub fn display_xpub(self, display: bool) -> Result<Self, HWIError> {
        *self.options.display_xpub.lock().expect("poisoned") = display;
        Ok(self)
    }

    pub fn with_wallet(
        mut self,
        name: impl Into<String>,
        policy: &str,
        hmac: Option<[u8; 32]>,
    ) -> Result<Self, HWIError> {
        let (descriptor_template, keys) = utils::extract_keys_and_template::<WalletPubKey>(policy)?;
        let wallet = WalletPolicy::new(name.into(), WalletVersion::V2, descriptor_template, keys);
        self.options.wallet = Some((wallet, hmac));
        Ok(self)
    }
}

/// TODO: remove
impl<T: Transport> std::fmt::Debug for Ledger<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger").finish()
    }
}

impl<T: 'static + Transport + Sync + Send> From<Ledger<T>> for Box<dyn HWI + Send> {
    fn from(s: Ledger<T>) -> Box<dyn HWI + Send> {
        Box::new(s)
    }
}

impl<T: Transport> HWI for Ledger<T> {
    fn device_kind(&self) -> DeviceKind {
        self.kind
    }

    fn get_version(&self) -> Result<super::Version, HWIError> {
        let (_, version, _) = self.client.get_version()?;
        parse_version(&version)
    }

    fn get_master_fingerprint(&self) -> Result<Fingerprint, HWIError> {
        Ok(self.client.get_master_fingerprint()?)
    }

    fn get_extended_pubkey(&self, path: &DerivationPath) -> Result<Xpub, HWIError> {
        let display = *self.options.display_xpub.lock().expect("poisoned");
        Ok(self.client.get_extended_pubkey(path, display)?)
    }

    fn display(&self, display: bool) {
        *self.options.display_xpub.lock().expect("poisoned") = display;
    }

    fn display_address(&self, script: &AddressScript) -> Result<(), HWIError> {
        match script {
            AddressScript::P2TR(path) => {
                let children = utils::bip86_path_child_numbers(path.clone())?;
                let (hardened_children, normal_children) = children.split_at(3);
                let path = DerivationPath::from(hardened_children);
                let fg = self.get_master_fingerprint()?;
                let xpub = self.get_extended_pubkey(&path)?;
                let policy = format!("tr({}/**)", key_string_from_parts(fg, path, xpub));
                let (descriptor_template, keys) =
                    utils::extract_keys_and_template::<WalletPubKey>(&policy)?;
                let wallet =
                    WalletPolicy::new("".into(), WalletVersion::V2, descriptor_template, keys);

                if ![RECV_INDEX, CHANGE_INDEX].contains(&normal_children[0]) {
                    return Err(HWIError::Bip86ChangeIndex);
                }
                self.client
                    .get_wallet_address(
                        &wallet,
                        None,
                        normal_children[0] == CHANGE_INDEX,
                        normal_children[1].into(),
                        true,
                    )
                    .map_err(HWIError::from)?;
            }
            AddressScript::Miniscript { index, change } => {
                let (policy, hmac) = &self
                    .options
                    .wallet
                    .as_ref()
                    .ok_or(HWIError::MissingPolicy)?;
                self.client
                    .get_wallet_address(policy, hmac.as_ref(), *change, *index, true)
                    .map_err(HWIError::from)?;
            }
        }
        Ok(())
    }

    fn register_wallet(&self, name: &str, policy: &str) -> Result<Option<[u8; 32]>, HWIError> {
        let (descriptor_template, keys) = utils::extract_keys_and_template::<WalletPubKey>(policy)?;
        let wallet = WalletPolicy::new(
            name.to_string(),
            WalletVersion::V2,
            descriptor_template,
            keys,
        );
        let (_id, hmac) = self.client.register_wallet(&wallet)?;
        Ok(Some(hmac))
    }

    fn is_wallet_registered(&self, name: &str, policy: &str) -> Result<bool, HWIError> {
        if let Some((wallet, hmac)) = &self.options.wallet {
            let (descriptor_template, keys) =
                utils::extract_keys_and_template::<WalletPubKey>(policy)?;
            Ok(hmac.is_some()
                && name == wallet.name
                && descriptor_template == wallet.descriptor_template
                && keys == wallet.keys)
        } else {
            Ok(false)
        }
    }

    /// Signs with the registered policy and merges what the device yields into `psbt`
    /// (see [`merge_yields`]).
    ///
    /// MuSig2 round rule: the app runs MuSig2 round 2 whenever the PSBT carries any
    /// PSBT_IN_MUSIG2_PUB_NONCE, and round 1 (pubnonces only, no user approval when it
    /// signs musig keys only) otherwise. Send round 1 with every pubnonce removed
    /// (`bwk_psbt::musig::remove_musig_input_pub_nonces` on a copy) and merge the
    /// device's nonces into the shared PSBT; send round 2 once every participant's
    /// nonce is present, with the same unsigned transaction. This method does not strip
    /// nonces: the round decision belongs to the caller.
    fn sign_tx(&self, psbt: &mut Psbt) -> Result<(), HWIError> {
        if let Some((policy, hmac)) = &self.options.wallet {
            let yielded_objects = self.client.sign_psbt(psbt, policy, hmac.as_ref())?;
            merge_yields(psbt, yielded_objects)
        } else {
            // Ledger cannot sign without policy.
            Err(HWIError::UnimplementedMethod)
        }
    }
}

/// Writes the objects yielded by `sign_psbt` into `psbt`.
///
/// Plain signatures go to `partial_sigs`, `tap_script_sigs` or `tap_key_sig`. With the
/// `musig` feature, MuSig2 pubnonces become PSBT_IN_MUSIG2_PUB_NONCE (0x1b) and MuSig2
/// partial signatures PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c) entries, keyed by the
/// participant, the aggregate and the leaf hash as the device yields them (the BIP-373
/// slot rule, see `bwk_psbt::musig`); without it they are ignored, as are payloads this
/// client does not know. The app yields round 1 objects (pubnonces) when the PSBT
/// carries no pubnonce and round 2 objects (partial signatures) otherwise, see
/// [`HWI::sign_tx`] on [`Ledger`].
fn merge_yields(
    psbt: &mut Psbt,
    yields: Vec<(usize, SignPsbtYieldedObject)>,
) -> Result<(), HWIError> {
    for (i, obj) in yields {
        let input = psbt.inputs.get_mut(i).ok_or(HWIError::DeviceDidNotSign)?;
        match obj {
            SignPsbtYieldedObject::Partial(PartialSignature::Sig(key, sig)) => {
                input.partial_sigs.insert(key, sig);
            }
            SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                key,
                Some(tapleaf_hash),
                sig,
            )) => {
                input.tap_script_sigs.insert((key, tapleaf_hash), sig);
            }
            SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(_, None, sig)) => {
                input.tap_key_sig = Some(sig);
            }
            #[cfg(feature = "musig")]
            SignPsbtYieldedObject::MusigPubNonce(n) => set_musig_input_pub_nonce(
                input,
                &MusigPubNonce {
                    participant: n.participant_pubkey.inner,
                    aggregate: n.aggregate_pubkey.inner,
                    leaf_hash: n.tapleaf_hash,
                    nonce: n.pubnonce,
                },
            ),
            #[cfg(feature = "musig")]
            SignPsbtYieldedObject::MusigPartialSignature(s) => set_musig_input_partial_sig(
                input,
                &MusigPartialSig {
                    participant: s.participant_pubkey.inner,
                    aggregate: s.aggregate_pubkey.inner,
                    leaf_hash: s.tapleaf_hash,
                    signature: s.partial_signature,
                },
            ),
            // MuSig2 yields without the musig feature, unknown payloads, future variants.
            _ => {}
        }
    }
    Ok(())
}

fn key_string_from_parts(fg: Fingerprint, path: DerivationPath, xpub: Xpub) -> String {
    format!(
        "[{}/{}]{}",
        fg,
        path.to_string().trim_start_matches("m/"),
        xpub
    )
}

impl Ledger<TransportHID> {
    pub fn enumerate(api: &HidApi) -> impl Iterator<Item = &DeviceInfo> {
        TransportNativeHID::list_ledgers(api)
    }

    pub fn connect(api: &HidApi, device: &DeviceInfo) -> Result<Self, HWIError> {
        let hid =
            TransportNativeHID::open_device(api, device).map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(TransportHID(hid)),
            options: CommandOptions::default(),
            kind: DeviceKind::Ledger,
        })
    }

    pub fn try_connect_hid() -> Result<Self, HWIError> {
        let hid = TransportNativeHID::new(&HidApi::new().map_err(|_| HWIError::DeviceNotFound)?)
            .map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(TransportHID(hid)),
            options: CommandOptions::default(),
            kind: DeviceKind::Ledger,
        })
    }
}

/// Transport with the Ledger device.
pub struct TransportHID(TransportNativeHID);

impl Transport for TransportHID {
    type Error = Box<dyn Error>;
    fn exchange(&self, cmd: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0
            .exchange(&ledger_apdu::APDUCommand {
                ins: cmd.ins,
                cla: cmd.cla,
                p1: cmd.p1,
                p2: cmd.p2,
                data: cmd.data.clone(),
            })
            .map(|answer| {
                (
                    StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
                    answer.data().to_vec(),
                )
            })
            .map_err(|e| e.into())
    }
}

pub type LedgerSimulator = Ledger<TransportTcp>;

impl LedgerSimulator {
    /// Connect to a Speculos simulator on the default address (`127.0.0.1:9999`).
    pub fn try_connect() -> Result<Self, HWIError> {
        Self::try_connect_on(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9999,
        ))
    }

    /// Connect to a Speculos simulator at `addr`.
    pub fn try_connect_on(addr: SocketAddr) -> Result<Self, HWIError> {
        let transport = TransportTcp::new_on(addr).map_err(|_| HWIError::DeviceNotFound)?;
        Ok(Ledger {
            client: BitcoinClient::new(transport),
            options: CommandOptions::default(),
            kind: DeviceKind::LedgerSimulator,
        })
    }
}

/// Transport to communicate with the Ledger Speculos simulator.
pub struct TransportTcp {
    connection: Mutex<std::net::TcpStream>,
}

impl TransportTcp {
    /// Connect to Speculos on the default address (`127.0.0.1:9999`).
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Self::new_on(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9999,
        ))
    }

    /// Connect to Speculos at the given address.
    pub fn new_on(addr: SocketAddr) -> Result<Self, Box<dyn Error>> {
        let stream = std::net::TcpStream::connect(addr)?;
        Ok(Self {
            connection: Mutex::new(stream),
        })
    }
}

impl Transport for TransportTcp {
    type Error = Box<dyn Error>;
    fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        let mut stream = self.connection.lock().unwrap();
        let command_bytes = command.encode();

        let mut req = vec![0u8; command_bytes.len() + 4];
        req[..4].copy_from_slice(&(command_bytes.len() as u32).to_be_bytes());
        req[4..].copy_from_slice(&command_bytes);
        stream.write_all(&req)?;

        let mut buff = [0u8; 4];
        stream.read_exact(&mut buff)?;
        let len = u32::from_be_bytes(buff);

        let mut resp = vec![0u8; len as usize + 2];
        stream.read_exact(&mut resp)?;
        let answer = APDUAnswer::from_answer(resp).map_err(|_| "Invalid Answer")?;
        Ok((
            StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
            answer.data().to_vec(),
        ))
    }
}

impl<T: core::fmt::Debug> From<BitcoinClientError<T>> for HWIError {
    fn from(e: BitcoinClientError<T>) -> HWIError {
        if let BitcoinClientError::Device { status, .. } = e {
            if status == StatusWord::Deny {
                return HWIError::UserRefused;
            }
        };
        HWIError::Device(format!("{e:#?}"))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    use crate::ledger::bitcoin_client::protocol;
    use bitcoin::{
        absolute::LockTime,
        ecdsa,
        hashes::Hash,
        secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey},
        taproot::{self, TapLeafHash},
        transaction::Version as TxVersion,
        TapSighashType, Transaction, TxIn,
    };

    #[cfg(feature = "musig")]
    use bwk_psbt::musig::{musig_input_partial_sigs, musig_input_pub_nonces};

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn pubkey(byte: u8) -> PublicKey {
        key(byte).public_key(&Secp256k1::new())
    }

    fn one_input_psbt() -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        })
        .unwrap()
    }

    fn leaf() -> TapLeafHash {
        TapLeafHash::from_byte_array([7; 32])
    }

    fn pub_nonce_yield(leaf_hash: Option<TapLeafHash>) -> SignPsbtYieldedObject {
        SignPsbtYieldedObject::MusigPubNonce(protocol::MusigPubNonce {
            participant_pubkey: bitcoin::PublicKey::new(pubkey(1)),
            aggregate_pubkey: bitcoin::PublicKey::new(pubkey(2)),
            tapleaf_hash: leaf_hash,
            pubnonce: [0xaa; 66],
        })
    }

    fn partial_sig_yield(leaf_hash: Option<TapLeafHash>) -> SignPsbtYieldedObject {
        SignPsbtYieldedObject::MusigPartialSignature(protocol::MusigPartialSignature {
            participant_pubkey: bitcoin::PublicKey::new(pubkey(1)),
            aggregate_pubkey: bitcoin::PublicKey::new(pubkey(2)),
            tapleaf_hash: leaf_hash,
            partial_signature: [0xbb; 32],
        })
    }

    #[cfg(feature = "musig")]
    #[test]
    fn merge_yields_writes_musig_pubnonce() {
        for leaf_hash in [None, Some(leaf())] {
            let mut psbt = one_input_psbt();
            merge_yields(&mut psbt, vec![(0, pub_nonce_yield(leaf_hash))]).unwrap();
            assert_eq!(
                musig_input_pub_nonces(&psbt.inputs[0]).unwrap(),
                vec![MusigPubNonce {
                    participant: pubkey(1),
                    aggregate: pubkey(2),
                    leaf_hash,
                    nonce: [0xaa; 66],
                }]
            );
        }
    }

    #[cfg(feature = "musig")]
    #[test]
    fn merge_yields_writes_musig_partial_sig() {
        for leaf_hash in [None, Some(leaf())] {
            let mut psbt = one_input_psbt();
            merge_yields(&mut psbt, vec![(0, partial_sig_yield(leaf_hash))]).unwrap();
            assert_eq!(
                musig_input_partial_sigs(&psbt.inputs[0]).unwrap(),
                vec![MusigPartialSig {
                    participant: pubkey(1),
                    aggregate: pubkey(2),
                    leaf_hash,
                    signature: [0xbb; 32],
                }]
            );
        }
    }

    #[test]
    fn merge_yields_keeps_plain_signatures() {
        let secp = Secp256k1::new();
        let message = Message::from_digest([1; 32]);
        let ecdsa_sig = ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &key(3)));
        let keypair = Keypair::from_secret_key(&secp, &key(4));
        let xonly = keypair.x_only_public_key().0;
        let schnorr_sig = taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&message, &keypair),
            sighash_type: TapSighashType::Default,
        };
        let ecdsa_key = bitcoin::PublicKey::new(pubkey(3));
        let mut psbt = one_input_psbt();
        merge_yields(
            &mut psbt,
            vec![
                (
                    0,
                    SignPsbtYieldedObject::Partial(PartialSignature::Sig(ecdsa_key, ecdsa_sig)),
                ),
                (
                    0,
                    SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                        xonly,
                        Some(leaf()),
                        schnorr_sig,
                    )),
                ),
                (
                    0,
                    SignPsbtYieldedObject::Partial(PartialSignature::TapScriptSig(
                        xonly,
                        None,
                        schnorr_sig,
                    )),
                ),
            ],
        )
        .unwrap();
        let input = &psbt.inputs[0];
        assert_eq!(input.partial_sigs.get(&ecdsa_key), Some(&ecdsa_sig));
        assert_eq!(
            input.tap_script_sigs.get(&(xonly, leaf())),
            Some(&schnorr_sig)
        );
        assert_eq!(input.tap_key_sig, Some(schnorr_sig));
        assert!(input.unknown.is_empty());
    }

    #[test]
    fn merge_yields_ignores_unknown() {
        let mut psbt = one_input_psbt();
        merge_yields(
            &mut psbt,
            vec![(0, SignPsbtYieldedObject::Unknown(vec![1, 2, 3]))],
        )
        .unwrap();
        assert_eq!(psbt, one_input_psbt());
    }

    #[cfg(not(feature = "musig"))]
    #[test]
    fn merge_yields_ignores_musig_without_feature() {
        let mut psbt = one_input_psbt();
        merge_yields(
            &mut psbt,
            vec![(0, pub_nonce_yield(None)), (0, partial_sig_yield(None))],
        )
        .unwrap();
        assert_eq!(psbt, one_input_psbt());
    }

    #[test]
    fn merge_yields_rejects_out_of_range_input() {
        let mut psbt = one_input_psbt();
        assert!(matches!(
            merge_yields(&mut psbt, vec![(1, pub_nonce_yield(None))]),
            Err(HWIError::DeviceDidNotSign)
        ));
    }

    // This is a foolproof test in case next rust-bitcoin version introduces again the m/
    #[test]
    fn test_key_string_from_parts() {
        let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
        let fg = Fingerprint::from_hex("aabbccdd").unwrap();
        let xpub = Xpub::from_str("tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N").unwrap();
        assert_eq!(key_string_from_parts(fg, path, xpub), "[aabbccdd/48'/1'/0'/2']tpubDExA3EC3iAsPxPhFn4j6gMiVup6V2eH3qKyk69RcTc9TTNRfFYVPad8bJD5FCHVQxyBT4izKsvr7Btd2R4xmQ1hZkvsqGBaeE82J71uTK4N");
    }
}
