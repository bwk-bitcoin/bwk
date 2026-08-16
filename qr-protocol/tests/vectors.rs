#![cfg(feature = "bitcoin")]

mod common;

use bitcoin::{
    absolute,
    hex::{DisplayHex, FromHex},
    transaction, Psbt, PublicKey, Transaction,
};
use bwk_qr_protocol::{self as protocol, request, response, types::Fingerprint, Message};
use serde_json::Value;

use common::{bip380, bip388, bitcoin_xpub, path, xpub};

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

fn get_xpubs_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "get_xpubs_request_one_path",
            request(request::Body::GetXpubs(request::GetXpubs {
                derivation_paths: vec![path("m/48'/0'/0'/2'")],
            })),
        ),
        (
            "get_xpubs_request_two_paths",
            request(request::Body::GetXpubs(request::GetXpubs {
                derivation_paths: vec![path("m/48'/0'/0'/2'"), path("m/84'/1'/0'")],
            })),
        ),
        (
            "get_xpubs_response_ok",
            response(response::Body::Xpubs(response::Xpubs {
                xpubs: vec![xpub()],
                fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
                model: "bwk-signer".to_string(),
                version: response::FirmwareVersion {
                    major: 1,
                    minor: 2,
                    patch: 3,
                    flag: response::ReleaseFlag::Beta,
                },
                capabilities: response::Capabilities(0x0000_000b),
            })),
        ),
    ]
}

fn get_sp_descriptor_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "get_sp_descriptor_request",
            request(request::Body::GetSpDescriptor(request::GetSpDescriptor {})),
        ),
        (
            "get_sp_descriptor_response",
            response(response::Body::SpDescriptor(response::SpDescriptor {
                descriptor: "sp(scan,spend)".to_string(),
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
                    public_key: (&PublicKey::new(bitcoin_xpub().public_key))
                        .try_into()
                        .unwrap(),
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
            "error_response_reserved_code",
            response(response::Body::Error(response::ErrorBody {
                message_type: protocol::MessageType::GetXpubs,
                error: response::Error::Unknown(0x0c),
                message: "code added after version 1".to_string(),
            })),
        ),
    ]
}

fn versioning_messages() -> Vec<(&'static str, Message)> {
    vec![
        (
            "versioning_get_xpubs_request_version_two",
            request(request::Body::GetXpubs(request::GetXpubs {
                derivation_paths: vec![path("m/48'/0'/0'/2'")],
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
fn get_xpubs_vectors() {
    check(include_str!("get_xpubs.json"), &get_xpubs_messages());
}

#[test]
fn get_sp_descriptor_vectors() {
    check(
        include_str!("get_sp_descriptor.json"),
        &get_sp_descriptor_messages(),
    );
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
fn error_vectors() {
    check(include_str!("errors.json"), &error_messages());
}

#[test]
fn versioning_vectors() {
    check(include_str!("versioning.json"), &versioning_messages());
}
