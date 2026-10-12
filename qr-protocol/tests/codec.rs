#![cfg(feature = "bitcoin")]

mod common;

use bwk_qr_protocol::{
    decode, encode, encode_request, encode_response, reader, request, response, types::Fingerprint,
    Message, MessageType, Request, RequestId, Response, MAX_DESCRIPTOR_ALIAS, REQUEST_ID_LEN,
};

use common::{key_request, xpub};

// MAGIC is 6 bytes, so VERSION sits at index 6 and MSG_TYPE right after it
const VERSION_OFFSET: usize = 6;
const MSG_TYPE_OFFSET: usize = 7;
const HEADER_LEN: usize = MSG_TYPE_OFFSET + 1 + REQUEST_ID_LEN;
// STORED's value follows the header, the alias "main" as a STRING (1 + 4),
// REGISTERED (1 + 1), and STORED's own presence byte
const STORED_VALUE_OFFSET: usize = HEADER_LEN + 5 + 2 + 1;
// the first KIND of get_keys_request() follows the KEYS count and its path m/48'/0'/0'/2'
// (CHILD_COUNT + 4 steps of 4 bytes)
const FIRST_KEY_KIND_OFFSET: usize = HEADER_LEN + 1 + 1 + 4 * 4;

fn id() -> RequestId {
    RequestId([42; REQUEST_ID_LEN])
}

fn get_keys_request() -> Request {
    Request {
        id: id(),
        body: request::Body::GetKeys(request::GetKeys {
            keys: vec![
                key_request("m/48'/0'/0'/2'", request::KeyKind::Public),
                key_request("m/84'/1'/0'", request::KeyKind::Public),
            ],
        }),
    }
}

fn keys_response(capabilities: u32) -> Response {
    Response {
        id: id(),
        body: response::Body::Keys(response::Keys {
            keys: vec![xpub()],
            fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
            vendor: "bwk".to_string(),
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
    let request = get_keys_request();
    let bytes = encode_request(&request).unwrap();
    assert_eq!(bytes[VERSION_OFFSET], 1);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_of_a_newer_version() {
    let request = get_keys_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes[VERSION_OFFSET] = 2;
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_ignores_trailing_bytes_at_version_one() {
    let request = get_keys_request();
    let mut bytes = encode_request(&request).unwrap();
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode(&bytes), Ok(Message::Request(request)));
}

#[test]
fn decode_rejects_version_zero() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[VERSION_OFFSET] = 0;
    assert_eq!(decode(&bytes), Err(decode::Error::ReservedVersion));
}

#[test]
fn decode_rejects_wrong_magic() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[0] = b'X';
    assert_eq!(decode(&bytes), Err(decode::Error::InvalidMagic));
}

#[test]
fn decode_rejects_a_truncated_field() {
    let bytes = encode_request(&get_keys_request()).unwrap();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn decode_rejects_an_unknown_message_type() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x09;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x09)));
}

#[test]
fn decode_rejects_the_reserved_message_type_five() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x05;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x05)));
}

#[test]
fn decode_rejects_an_unknown_key_kind() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[FIRST_KEY_KIND_OFFSET] = 0x02;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownKeyKind(0x02)));
}

#[test]
fn decode_rejects_error_status_on_a_request() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
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
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    // the KEYS count is the first body byte, after the header
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
        encode_response(&keys_response(0x0000_0010)),
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
    let mut response = keys_response(0);
    let response::Body::Keys(body) = &mut response.body else {
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
        decode::Error::UnknownKeyKind(0),
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

#[cfg(feature = "bitcoin")]
mod sp_keys {
    use bwk_qr_protocol::{request::DescriptorBody, types::SpKeys};

    const TEXT: &str = "73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0";

    #[test]
    fn round_trips_through_its_text() {
        let keys: SpKeys = TEXT.parse().unwrap();
        assert_eq!(keys.fingerprint.to_string(), "73c5da0a");
        assert_eq!(keys.spend_path, "m/352'/1'/0'/0'/0".parse().unwrap());
        assert_eq!(keys.scan_path, "m/352'/1'/0'/1'/0".parse().unwrap());
        assert_eq!(keys.to_string(), TEXT);
        assert_eq!(
            DescriptorBody::from(&keys),
            DescriptorBody::SpKeys(TEXT.to_string())
        );
    }

    #[test]
    fn reads_h_as_hardened() {
        let keys: SpKeys = "73c5da0a|m/352h/1h/0h/0h/0|m/352h/1h/0h/1h/0"
            .parse()
            .unwrap();
        assert_eq!(keys.to_string(), TEXT);
    }

    #[test]
    fn refuses_malformed_text() {
        for text in [
            "",
            "73c5da0a|m/352'/1'/0'/0'/0",
            "73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0|extra",
            "73c5da0|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0",
            "73c5da0a|352'/1'/0'/0'/0|m/352'/1'/0'/1'/0",
            "73c5da0a|m/352'/1'/0'/0'/0|m/x",
        ] {
            assert!(text.parse::<SpKeys>().is_err(), "{text:?} parsed");
        }
    }
}

#[cfg(feature = "bitcoin")]
mod extended_key {
    use bitcoin::{bip32, hex::DisplayHex, secp256k1::Secp256k1};
    use bwk_qr_protocol::types::{Error, ExtendedKey};

    use crate::common::{bitcoin_xpriv, bitcoin_xpub};

    const XPRIV_HEX: &str = "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const XPUB_HEX: &str = "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

    #[test]
    fn the_xpriv_fixture_is_the_xpub_fixtures_private_key() {
        assert_eq!(
            bip32::Xpub::from_priv(&Secp256k1::new(), &bitcoin_xpriv()),
            bitcoin_xpub()
        );
    }

    #[test]
    fn xpriv_round_trips() {
        let key = ExtendedKey::from(&bitcoin_xpriv());
        assert_eq!(key.0.to_lower_hex_string(), XPRIV_HEX);
        assert_eq!(bip32::Xpriv::try_from(&key), Ok(bitcoin_xpriv()));
    }

    #[test]
    fn xpub_round_trips() {
        let key = ExtendedKey::from(&bitcoin_xpub());
        assert_eq!(key.0.to_lower_hex_string(), XPUB_HEX);
        assert_eq!(bip32::Xpub::try_from(&key), Ok(bitcoin_xpub()));
    }

    #[test]
    fn an_xpriv_is_not_read_as_an_xpub() {
        let key = ExtendedKey::from(&bitcoin_xpriv());
        assert_eq!(
            bip32::Xpub::try_from(&key),
            Err(Error::ExtendedKey(bip32::Error::UnknownVersion([
                0x04, 0x88, 0xad, 0xe4
            ])))
        );
    }

    #[test]
    fn an_xpub_is_not_read_as_an_xpriv() {
        let key = ExtendedKey::from(&bitcoin_xpub());
        assert_eq!(
            bip32::Xpriv::try_from(&key),
            Err(Error::ExtendedKey(bip32::Error::UnknownVersion([
                0x04, 0x88, 0xb2, 0x1e
            ])))
        );
    }
}
