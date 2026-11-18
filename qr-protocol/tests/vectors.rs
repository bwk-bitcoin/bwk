#![cfg(feature = "bitcoin")]

mod common;

use bitcoin::{
    absolute,
    hex::{DisplayHex, FromHex},
    transaction, Psbt, Transaction,
};
use bwk_qr_protocol::{self as protocol, request, response, types::Fingerprint, Message};
use serde_json::Value;

use common::{
    bip380, bip388, key_request, musig_partial_sigs, musig_pub_nonces, path, sp_foreign_scan_keys,
    sp_global_send, sp_keys, sp_per_input_send, xpriv, xpub, xpub_key,
};

fn id() -> protocol::RequestId {
    protocol::RequestId([0, 1])
}

fn request(body: request::Body) -> Message {
    Message::Request(protocol::Request { id: id(), body })
}

fn response(body: response::Body) -> Message {
    Message::Response(protocol::Response { id: id(), body })
}

fn psbt() -> Vec<u8> {
    Psbt::from_unsigned_tx(Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })
    .unwrap()
    .serialize()
}

fn register_descriptor_request(descriptor: Option<request::DescriptorBody>) -> Message {
    request(request::Body::RegisterDescriptor(
        request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor,
        },
    ))
}

fn get_keys_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "get_keys_request_one_path",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![key_request("m/48'/0'/0'/2'", request::KeyKind::Public)],
            })),
        ),
        (
            "get_keys_request_silent_payment_and_xpubs",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![
                    key_request("m/352'/1'/0'/0'", request::KeyKind::Public),
                    key_request("m/352'/1'/0'/1'", request::KeyKind::Private),
                    key_request("m/86'/1'/0'", request::KeyKind::Public),
                    key_request("m/84'/1'/0'", request::KeyKind::Public),
                ],
            })),
        ),
        (
            "get_keys_response_ok",
            response(response::Body::Keys(response::Keys {
                keys: vec![xpub(), xpriv()],
                fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
                vendor: "bwk".to_string(),
                model: "bwk-signer".to_string(),
                version: response::FirmwareVersion {
                    major: 1,
                    minor: 2,
                    patch: 3,
                    flag: response::ReleaseFlag::Beta,
                },
                capabilities: response::Capabilities(0x0000_000f),
            })),
        ),
    ]
}

fn register_descriptor_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "register_descriptor_request_bip380",
            register_descriptor_request(Some(bip380())),
        ),
        (
            "register_descriptor_request_bip388",
            register_descriptor_request(Some(bip388())),
        ),
        (
            "register_descriptor_request_sp_keys",
            register_descriptor_request(Some(sp_keys())),
        ),
        (
            "register_descriptor_request_status_query",
            register_descriptor_request(None),
        ),
        (
            "register_descriptor_response_registered",
            response(response::Body::Registration(response::Registration {
                descriptor_alias: "main".to_string(),
                registered: Some(true),
                stored: Some(true),
                proof: Some(vec![0xaa; 8]),
            })),
        ),
        (
            "register_descriptor_response_not_registered",
            response(response::Body::Registration(response::Registration {
                descriptor_alias: "main".to_string(),
                registered: Some(false),
                stored: None,
                proof: None,
            })),
        ),
    ]
}

fn address_verification_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "address_verification_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m/84'/1'/0'/0/7"),
                address: Some("bc1qxyz".to_string()),
                descriptor: Some(bip380()),
                proof: Some(vec![0x5a; 4]),
            })),
        ),
        (
            "address_verification_sp_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_keys()),
                proof: None,
            })),
        ),
        (
            "address_verification_sp_request_with_por",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_keys()),
                proof: Some(vec![0x5a; 4]),
            })),
        ),
        (
            "address_verification_sp_foreign_scan_request",
            request(request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: path("m/2"),
                address: Some("sp1qxyz".to_string()),
                descriptor: Some(sp_foreign_scan_keys()),
                proof: None,
            })),
        ),
        (
            "address_verification_response_uri",
            response(response::Body::AddressUri(response::AddressUri {
                uri: Some("bitcoin:bc1qxyz".to_string()),
            })),
        ),
        (
            "address_verification_response_no_uri",
            response(response::Body::AddressUri(response::AddressUri {
                uri: None,
            })),
        ),
    ]
}

fn signing_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "signing_request",
            request(request::Body::Sign(request::Sign {
                descriptors: vec![request::Descriptor {
                    alias: "main".to_string(),
                    descriptor: Some(bip380()),
                    proof: Some(vec![0x5a; 4]),
                }],
                psbt: psbt(),
                want_kind: Some(protocol::SignResponseKind::Signatures),
            })),
        ),
        (
            "signing_response_psbt",
            response(response::Body::Signed(response::Signed::Psbt(psbt()))),
        ),
        (
            "signing_response_signatures",
            response(response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Ecdsa {
                    input_index: 0,
                    public_key: xpub_key(),
                    signature: vec![0x30; 71],
                },
                response::SignatureEntry::TapKey {
                    input_index: 1,
                    signature: vec![0x01; 64],
                },
                response::SignatureEntry::TapScript {
                    input_index: 2,
                    xonly_public_key: [0x02; 32],
                    tap_leaf_hash: [0x03; 32],
                    signature: vec![0x04; 65],
                },
            ]))),
        ),
        (
            "signing_response_musig_pub_nonces",
            response(response::Body::Signed(response::Signed::Signatures(
                musig_pub_nonces(),
            ))),
        ),
        (
            "signing_response_musig_partial_sigs",
            response(response::Body::Signed(response::Signed::Signatures(
                musig_partial_sigs(),
            ))),
        ),
        (
            "signing_response_silent_payment_global",
            response(response::Body::Signed(response::Signed::Signatures(
                sp_global_send(),
            ))),
        ),
        (
            "signing_response_silent_payment_per_input",
            response(response::Body::Signed(response::Signed::Signatures(
                sp_per_input_send(),
            ))),
        ),
        (
            "signing_response_unknown_sig_kind",
            response(response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Unknown {
                    input_index: 0,
                    kind: 0x08,
                    fields: vec![0xde, 0xad, 0xbe, 0xef],
                },
                response::SignatureEntry::TapKey {
                    input_index: 0,
                    signature: vec![0x01; 64],
                },
            ]))),
        ),
    ]
}

fn nonce_cache_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "nonce_preparation_request",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: [0x51; 4],
                session_ref: None,
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 0,
                end: 1,
            })),
        ),
        (
            "nonce_preparation_request_with_session_ref",
            request(request::Body::PrepareNonces(request::PrepareNonces {
                session_id: [0x51; 4],
                session_ref: Some([0x52; 4]),
                max_inputs: 2,
                derivation_path: path("m/86'/1'/0'/0/3"),
                start: 2,
                end: 3,
            })),
        ),
        (
            "nonce_preparation_response",
            response(response::Body::NoncesPrepared(response::NoncesPrepared {
                session_id: [0x51; 4],
                session_ref: [0x52; 4],
                max_inputs: 2,
                start: 2,
                end: 3,
                nonces: vec![[0x22; 66], [0x55; 66], [0x66; 66], [0x77; 66]],
            })),
        ),
    ]
}

fn info(state: response::State) -> response::Info {
    response::Info {
        vendor: "bwk".to_string(),
        model: "bwk-signer".to_string(),
        version: response::FirmwareVersion {
            major: 1,
            minor: 2,
            patch: 3,
            flag: response::ReleaseFlag::Beta,
        },
        capabilities: response::Capabilities(0x0000_000f),
        state,
        networks: response::Networks(0x00),
        max_message: 0,
        max_alias: 0,
        max_keys: 0,
        slots: 0,
        fingerprint: None,
    }
}

fn get_info_messages() -> Vec<(&'static str, Message)> {
    vec![
        ("get_info_request", request(request::Body::GetInfo)),
        (
            "get_info_response_ready",
            response(response::Body::Info(response::Info {
                networks: response::Networks(
                    response::Networks::MAINNET
                        | response::Networks::TESTNET
                        | response::Networks::SIGNET
                        | response::Networks::REGTEST,
                ),
                max_message: 512 * 1024,
                max_alias: 32,
                max_keys: 16,
                slots: 8,
                fingerprint: Some(Fingerprint([0xde, 0xad, 0xbe, 0xef])),
                ..info(response::State::Ready)
            })),
        ),
        (
            "get_info_response_locked",
            response(response::Body::Info(response::Info {
                networks: response::Networks(response::Networks::MAINNET),
                max_message: 4096,
                max_alias: 16,
                max_keys: 5,
                slots: 0,
                ..info(response::State::Locked)
            })),
        ),
    ]
}

fn error_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "error_response_user_declined",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::UserDeclined,
                message: "signing was declined".to_string(),
            })),
        ),
        (
            "error_response_vendor",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::Vendor,
                message: "device is locked".to_string(),
            })),
        ),
        (
            "error_response_private_key_export_refused",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::GetKeys,
                error: response::Error::PrivateKeyExportRefused,
                message: "private key export refused".to_string(),
            })),
        ),
        (
            "error_response_musig_session",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::Signing,
                error: response::Error::MusigSession,
                message: "musig2 session missing".to_string(),
            })),
        ),
        (
            "error_response_already_registered",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::RegisterDescriptor,
                error: response::Error::AlreadyRegistered,
                message: "alias already registered".to_string(),
            })),
        ),
        (
            "error_response_reserved_code",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::GetKeys,
                error: response::Error::Unknown(0x0f),
                message: "code added after version 1".to_string(),
            })),
        ),
    ]
}

fn versioning_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "versioning_get_keys_request_version_two",
            request(request::Body::GetKeys(request::GetKeys {
                keys: vec![key_request("m/48'/0'/0'/2'", request::KeyKind::Public)],
            })),
        ),
        (
            "versioning_address_uri_response_version_two",
            response(response::Body::AddressUri(response::AddressUri {
                uri: Some("bitcoin:bc1qxyz".to_string()),
            })),
        ),
    ]
}

fn check(json: &str, expected: &[(&str, Message)]) {
    let parsed: Value = serde_json::from_str(json).unwrap();
    let mut unpaired: Vec<&Value> = parsed["vectors"].as_array().unwrap().iter().collect();
    for (name, message) in expected {
        let index = unpaired
            .iter()
            .position(|vector| vector["name"] == *name)
            .unwrap_or_else(|| panic!("no json vector named {name}"));
        check_vector(unpaired.remove(index), message);
    }
    let extra: Vec<&str> = unpaired
        .iter()
        .map(|vector| vector["name"].as_str().unwrap())
        .collect();
    assert!(
        extra.is_empty(),
        "json vectors paired with no rust message: {extra:?}"
    );
}

fn check_vector(vector: &Value, message: &Message) {
    let name = vector["name"].as_str().unwrap();
    let hex = vector["hex"].as_str().unwrap();
    let (direction, encoded) = match message {
        Message::Request(request) => ("request", protocol::encode_request(request).unwrap()),
        Message::Response(response) => ("response", protocol::encode_response(response).unwrap()),
    };
    assert_eq!(vector["direction"], direction, "{name}: wrong direction");
    let bytes = Vec::<u8>::from_hex(hex).unwrap();
    assert_eq!(
        &protocol::decode(&bytes).unwrap(),
        message,
        "{name}: decodes to another message"
    );
    // a decode-only vector is not version 1, so the encoder cannot produce its bytes
    if vector["decode_only"].as_bool().unwrap() {
        return;
    }
    assert_eq!(
        encoded.to_lower_hex_string(),
        hex,
        "{name}: encodes to other bytes"
    );
}

#[test]
fn get_keys_vectors() {
    check(include_str!("get_keys.json"), &get_keys_messages());
}

#[test]
fn register_descriptor_vectors() {
    check(
        include_str!("register_descriptor.json"),
        &register_descriptor_messages(),
    );
}

#[test]
fn address_verification_vectors() {
    check(
        include_str!("address_verification.json"),
        &address_verification_messages(),
    );
}

#[test]
fn signing_vectors() {
    check(include_str!("signing.json"), &signing_messages());
}

#[test]
fn nonce_cache_vectors() {
    check(include_str!("nonce_cache.json"), &nonce_cache_messages());
}

#[test]
fn get_info_vectors() {
    check(include_str!("get_info.json"), &get_info_messages());
}

#[test]
fn error_vectors() {
    check(include_str!("errors.json"), &error_messages());
}

#[test]
fn versioning_vectors() {
    check(include_str!("versioning.json"), &versioning_messages());
}
