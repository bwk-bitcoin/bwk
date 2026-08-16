#![cfg(feature = "bitcoin")]

mod common;

use bwk_qr_protocol::{
    decode, encode, encode_request, encode_response, reader, request, response, types::Fingerprint,
    Message, MessageType, Request, RequestId, Response, MAX_DESCRIPTOR_ALIAS, REQUEST_ID_LEN,
};

use common::{path, xpub};

// MAGIC is 6 bytes, so VERSION sits at index 6 and MSG_TYPE right after it
const VERSION_OFFSET: usize = 6;
const MSG_TYPE_OFFSET: usize = 7;
const HEADER_LEN: usize = MSG_TYPE_OFFSET + 1 + REQUEST_ID_LEN;
// STORED's value follows the header, the alias "main" as a STRING (1 + 4),
// REGISTERED (1 + 1), and STORED's own presence byte
const STORED_VALUE_OFFSET: usize = HEADER_LEN + 5 + 2 + 1;

fn id() -> RequestId {
    RequestId([42; REQUEST_ID_LEN])
}

fn get_xpubs_request() -> Request {
    Request {
        id: id(),
        body: request::Body::GetXpubs(request::GetXpubs {
            derivation_paths: vec![path("m/48'/0'/0'/2'"), path("m/84'/1'/0'")],
        }),
    }
}

fn xpubs_response(capabilities: u32) -> Response {
    Response {
        id: id(),
        body: response::Body::Xpubs(response::Xpubs {
            xpubs: vec![xpub()],
            fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
            model: "bwk-signer".to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 7,
                patch: 0x00ab_cdef,
                flag: response::ReleaseFlag::ReleaseCandidate,
            },
            capabilities: response::Capabilities(capabilities),
        }),
    }
}

fn get_sp_descriptor_request() -> Request {
    Request {
        id: id(),
        body: request::Body::GetSpDescriptor(request::GetSpDescriptor {}),
    }
}

fn sp_descriptor_response() -> Response {
    Response {
        id: id(),
        body: response::Body::SpDescriptor(response::SpDescriptor {
            descriptor: "sp(scan,spend)".to_string(),
        }),
    }
}

fn registration_response(stored: Option<bool>) -> Response {
    Response {
        id: id(),
        body: response::Body::Registration(response::Registration {
            descriptor_alias: "main".to_string(),
            registered: Some(true),
            stored,
            proof: Some(vec![0xaa; 32]),
        }),
    }
}

fn error_response(error: response::Error) -> Response {
    Response {
        id: id(),
        body: response::Body::Error(response::ErrorBody {
            message_type: MessageType::Signing,
            error,
            message: "signing was declined".to_string(),
        }),
    }
}

fn register_descriptor_request(alias: String) -> Request {
    Request {
        id: id(),
        body: request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: alias,
            descriptor: None,
        }),
    }
}

#[test]
fn decode_accepts_a_version_one_blob() {
    let request = get_xpubs_request();
    let bytes = encode_request(&request).unwrap();
    assert_eq!(bytes[VERSION_OFFSET], 1);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_of_a_newer_version() {
    let request = get_xpubs_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes[VERSION_OFFSET] = 2;
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_at_version_one() {
    let request = get_xpubs_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_rejects_version_zero() {
    let mut bytes = encode_request(&get_xpubs_request()).unwrap();
    bytes[VERSION_OFFSET] = 0;
    assert_eq!(decode(&bytes), Err(decode::Error::ReservedVersion));
}

#[test]
fn decode_rejects_wrong_magic() {
    let mut bytes = encode_request(&get_xpubs_request()).unwrap();
    bytes[0] = b'X';
    assert_eq!(decode(&bytes), Err(decode::Error::InvalidMagic));
}

#[test]
fn decode_rejects_a_truncated_field() {
    let bytes = encode_request(&get_xpubs_request()).unwrap();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn decode_rejects_an_unknown_message_type() {
    let mut bytes = encode_request(&get_xpubs_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x09;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x09)));
}

#[test]
fn get_sp_descriptor_round_trips() {
    let request = get_sp_descriptor_request();
    assert_eq!(
        decode(&encode_request(&request).unwrap()),
        Ok(Message::Request(request))
    );

    let response = sp_descriptor_response();
    assert_eq!(
        decode(&encode_response(&response).unwrap()),
        Ok(Message::Response(response))
    );
}

#[test]
fn decode_rejects_error_status_on_a_request() {
    let mut bytes = encode_request(&get_xpubs_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] |= 0x40;
    assert_eq!(decode(&bytes), Err(decode::Error::ErrorStatusOnRequest));
}

#[test]
fn decode_rejects_an_invalid_stored_byte() {
    let mut bytes = encode_response(&registration_response(Some(true))).unwrap();
    bytes[STORED_VALUE_OFFSET] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidBool(0x02)))
    );
}

#[test]
fn decode_rejects_a_string_holding_a_nul() {
    let response = registration_response(None);
    let bytes = encode_response(&response).unwrap();
    // the alias "main" starts right after the header and its length byte
    let mut bytes = bytes.clone();
    bytes[HEADER_LEN + 1] = 0;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::StringNul))
    );
}

#[test]
fn decode_rejects_an_oversized_vector_without_allocating_it() {
    let mut bytes = encode_request(&get_xpubs_request()).unwrap();
    // the derivation path count is the first body byte, after the header
    bytes[HEADER_LEN] = 0xfd;
    bytes.splice(HEADER_LEN + 1..HEADER_LEN + 1, [0xff, 0x0f]);
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn encode_rejects_reserved_capability_bits() {
    assert_eq!(
        encode_response(&xpubs_response(0x0000_0010)),
        Err(encode::Error::ReservedCapabilityBits(0x0000_0010))
    );
}

#[test]
fn encode_rejects_colliding_unknown_error_codes() {
    for value in [0x00, 0x03, 0xff] {
        assert_eq!(
            encode_response(&error_response(response::Error::Unknown(value))),
            Err(encode::Error::ErrorCodeOutOfRange(value))
        );
    }
}

#[test]
fn encode_rejects_a_string_holding_a_nul() {
    let request = register_descriptor_request("ma\0in".to_string());
    assert_eq!(encode_request(&request), Err(encode::Error::StringNul));
}

#[test]
fn encode_rejects_an_oversized_descriptor_alias() {
    let request = register_descriptor_request("a".repeat(MAX_DESCRIPTOR_ALIAS + 1));
    assert_eq!(
        encode_request(&request),
        Err(encode::Error::StringTooLong {
            len: MAX_DESCRIPTOR_ALIAS + 1,
            max: MAX_DESCRIPTOR_ALIAS,
        })
    );
}

#[test]
fn decode_rejects_an_oversized_descriptor_alias() {
    let request = register_descriptor_request("a".repeat(MAX_DESCRIPTOR_ALIAS));
    let mut bytes = encode_request(&request).unwrap();
    bytes[HEADER_LEN] = (MAX_DESCRIPTOR_ALIAS + 1) as u8;
    bytes.insert(HEADER_LEN + 1, b'a');
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::StringTooLarge(
            MAX_DESCRIPTOR_ALIAS + 1
        )))
    );
}

#[test]
fn encode_rejects_a_fixed_string_holding_a_nul() {
    let mut response = xpubs_response(0);
    let response::Body::Xpubs(body) = &mut response.body else {
        unreachable!()
    };
    body.model = "bwk\0signer".to_string();
    assert_eq!(encode_response(&response), Err(encode::Error::StringNul));
}

#[test]
fn every_error_message_is_terminated_and_uniquely_coded() {
    let reader_errors = [
        reader::Error::Truncated,
        reader::Error::LengthOverflow,
        reader::Error::NonCanonicalCompactSize,
        reader::Error::CompactSizeTooLarge(0),
        reader::Error::InvalidBool(0),
        reader::Error::InvalidPresence(0),
        reader::Error::StringTooLarge(0),
        reader::Error::BytesTooLarge(0),
        reader::Error::VecTooLarge(0),
        reader::Error::InvalidFixedStringPadding,
        reader::Error::InvalidUtf8(String::from_utf8(vec![0xff]).unwrap_err()),
        reader::Error::StringNul,
    ];
    let decode_errors = [
        decode::Error::InvalidMagic,
        decode::Error::ReservedVersion,
        decode::Error::UnknownMessageType(0),
        decode::Error::ErrorStatusOnRequest,
        decode::Error::UnknownDescriptorForm(0),
        decode::Error::UnknownSignatureKind(0),
        decode::Error::UnknownSignResponseKind(0),
    ];
    let encode_errors = [
        encode::Error::PathTooLong(0),
        encode::Error::PatchTooLarge(0),
        encode::Error::ReservedCapabilityBits(0),
        encode::Error::ErrorCodeOutOfRange(0),
        encode::Error::VecTooLarge(0),
        encode::Error::BytesTooLarge(0),
        encode::Error::StringTooLong { len: 0, max: 0 },
        encode::Error::StringNul,
        encode::Error::FixedStringTooLong { len: 0, max: 0 },
        encode::Error::Unreachable,
    ];

    let mut infos = Vec::new();
    infos.extend(reader_errors.iter().map(reader::Error::info));
    infos.extend(decode_errors.iter().map(decode::Error::info));
    infos.extend(encode_errors.iter().map(encode::Error::info));

    let mut codes = Vec::new();
    for info in &infos {
        let code = info.code;
        let message = info.message;
        assert!(message.ends_with('\0'), "{message} is not nul-terminated");
        assert!(message.is_ascii(), "{message} is not ascii");
        assert!(message.len() > 1, "empty message for code {code}");
        codes.push(code);
    }
    codes.sort_unstable();
    let mut unique = codes.clone();
    unique.dedup();
    assert_eq!(codes, unique, "error codes are not unique");

    assert_eq!(
        decode::Error::Read(reader::Error::Truncated).info(),
        reader::Error::Truncated.info()
    );
    assert_eq!(reader::Error::Truncated.to_string(), "truncated field");
}
