#![cfg(feature = "bitcoin")]

mod common;

use bwk_qr_protocol::{
    decode, encode, encode_request, encode_response, get_info, reader, request,
    response::{self, SpScope},
    sp,
    types::Fingerprint,
    Message, MessageType, Request, RequestId, Response, MAX_DESCRIPTOR_ALIAS, REQUEST_ID_LEN,
};

use common::{
    aggregate, key_request, musig_partial_sigs, musig_pub_nonces, sp_global_send,
    sp_per_input_send, sp_proof, sp_share, xpub,
};

// MAGIC is 6 bytes, so VERSION sits at index 6 and MSG_TYPE right after it
const VERSION_OFFSET: usize = 6;
const MSG_TYPE_OFFSET: usize = 7;
const HEADER_LEN: usize = MSG_TYPE_OFFSET + 1 + REQUEST_ID_LEN;
// STORED's value follows the header, the alias "main" as a STRING (1 + 4),
// REGISTERED (1 + 1), and STORED's own presence byte
const STORED_VALUE_OFFSET: usize = HEADER_LEN + 5 + 2 + 1;
// the first SIG_ENTRY follows KIND and the SIG_ENTRY count
const FIRST_ENTRY_OFFSET: usize = HEADER_LEN + 1 + 1;
// INPUT_INDEX, SIG_KIND and a one-byte LENGTH come before an entry's KIND_FIELDS
const ENTRY_HEADER_LEN: usize = 4 + 1 + 1;
// the first LEAF_HASH presence byte of musig_pub_nonces() follows the entry header,
// PARTICIPANT and AGGREGATE
const FIRST_LEAF_HASH_PRESENCE_OFFSET: usize = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN + 33 + 33;
// a tapkey entry holds a 64-byte SIGNATURE behind its own one-byte LENGTH
const TAP_KEY_ENTRY_LEN: usize = ENTRY_HEADER_LEN + 1 + 64;
// GLOBAL, SCAN_KEY and SHARE
const SP_SHARE_ENTRY_LEN: usize = ENTRY_HEADER_LEN + 1 + 33 + 33;
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

fn signatures_response(entries: Vec<response::SignatureEntry>) -> Response {
    Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Signatures(entries)),
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
fn decode_rejects_the_reserved_message_type_eight() {
    let mut bytes = encode_request(&get_keys_request()).unwrap();
    bytes[MSG_TYPE_OFFSET] = 0x08;
    assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x08)));
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
        encode_response(&keys_response(0x0000_0020)),
        Err(encode::Error::ReservedCapabilityBits(0x0000_0020))
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
        decode::Error::UnknownSignResponseKind(0),
        decode::Error::UnknownKeyKind(0),
        decode::Error::SignatureLength(0),
        decode::Error::GlobalInputIndex(0),
    ];
    let get_info_errors = [
        get_info::Error::MaxAliasTooLarge(0),
        get_info::Error::FingerprintWhenNotReady,
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
        encode::Error::DefinedSignatureKind(0),
        encode::Error::ReservedNetworkBits(0),
        encode::Error::DefinedState(0),
    ];
    let sp_errors = [
        sp::Error::DuplicateShare,
        sp::Error::DuplicateProof,
        sp::Error::MissingProof,
        sp::Error::MissingShare,
    ];

    let mut infos = Vec::new();
    infos.extend(reader_errors.iter().map(reader::Error::info));
    infos.extend(decode_errors.iter().map(decode::Error::info));
    infos.extend(encode_errors.iter().map(encode::Error::info));
    infos.extend(sp_errors.iter().map(sp::Error::info));
    infos.extend(get_info_errors.iter().map(get_info::Error::info));

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

mod sp_keys {
    use bwk_qr_protocol::{
        decode, encode, encode_request, reader, request, types::DerivationPath, Request,
    };

    use crate::{common::sp_keys, id};

    fn verify_address_request(descriptor: request::DescriptorBody) -> Request {
        Request {
            id: id(),
            body: request::Body::VerifyAddress(request::VerifyAddress {
                descriptor_alias: "main".to_string(),
                derivation_path: DerivationPath(vec![]),
                address: None,
                descriptor: Some(descriptor),
                proof: None,
            }),
        }
    }

    #[test]
    fn encode_rejects_a_path_over_255_steps() {
        let request::DescriptorBody::SpKeys(mut keys) = sp_keys() else {
            unreachable!()
        };
        keys.scan_path = DerivationPath(vec![0; 256]);
        let request = verify_address_request(request::DescriptorBody::SpKeys(keys));
        assert_eq!(
            encode_request(&request),
            Err(encode::Error::PathTooLong(256))
        );
    }

    #[test]
    fn decode_rejects_a_truncated_scan_path() {
        let bytes = encode_request(&verify_address_request(sp_keys())).unwrap();
        // drop the absent POR byte and the last byte of the scan path's last CHILD
        assert_eq!(
            decode(&bytes[..bytes.len() - 2]),
            Err(decode::Error::Read(reader::Error::Truncated))
        );
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

#[test]
fn musig_signatures_round_trip() {
    let mut entries = musig_pub_nonces();
    entries.extend(musig_partial_sigs());
    let response = signatures_response(entries);
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

#[test]
fn musig_leaf_hash_presence_must_be_zero_or_one() {
    let mut bytes = encode_response(&signatures_response(musig_pub_nonces())).unwrap();
    assert_eq!(bytes[FIRST_LEAF_HASH_PRESENCE_OFFSET], 0);
    bytes[FIRST_LEAF_HASH_PRESENCE_OFFSET] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
    );
}

#[test]
fn truncated_musig_nonce_is_refused() {
    let bytes = encode_response(&signatures_response(musig_pub_nonces())).unwrap();
    assert_eq!(
        decode(&bytes[..bytes.len() - 1]),
        Err(decode::Error::Read(reader::Error::Truncated))
    );
}

#[test]
fn musig_session_error_code_round_trips() {
    assert_eq!(u8::from(response::Error::MusigSession), 0x0d);
    assert_eq!(response::Error::from(0x0d), response::Error::MusigSession);
    assert_eq!(
        encode_response(&error_response(response::Error::Unknown(0x0d))),
        Err(encode::Error::ErrorCodeOutOfRange(0x0d))
    );
    let response = error_response(response::Error::Unknown(0x0e));
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode(&bytes), Ok(Message::Response(response)));
}

fn tap_key_response() -> Response {
    signatures_response(vec![response::SignatureEntry::TapKey {
        input_index: 0,
        signature: vec![0x01; 64],
    }])
}

#[test]
fn decode_rejects_known_fields_overflowing_their_length() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    let length = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN - 1;
    assert_eq!(bytes[length], 0x41);
    // one byte short: the SIGNATURE no longer fits
    bytes[length] = 0x40;
    bytes.pop();
    assert_eq!(decode(&bytes), Err(decode::Error::SignatureLength(0x02)));
}

#[test]
fn decode_rejects_known_fields_short_of_their_length() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    let length = FIRST_ENTRY_OFFSET + ENTRY_HEADER_LEN - 1;
    // one byte past the SIGNATURE that a tapkey entry does not hold
    bytes[length] = 0x42;
    bytes.push(0x00);
    assert_eq!(decode(&bytes), Err(decode::Error::SignatureLength(0x02)));
}

#[test]
fn decode_keeps_an_unknown_kind_whatever_its_fields() {
    let mut bytes = encode_response(&tap_key_response()).unwrap();
    // the same entry under the reserved kind 0x00: 65 bytes no known kind would parse
    bytes[FIRST_ENTRY_OFFSET + 4] = 0x00;
    let mut fields = vec![0x40];
    fields.extend([0x01; 64]);
    assert_eq!(
        decode(&bytes),
        Ok(Message::Response(signatures_response(vec![
            response::SignatureEntry::Unknown {
                input_index: 0,
                kind: 0x00,
                fields,
            }
        ])))
    );
}

#[test]
fn encode_rejects_an_unknown_entry_of_a_defined_or_reserved_kind() {
    for kind in [0x00, 0x02, 0x07] {
        let response = signatures_response(vec![response::SignatureEntry::Unknown {
            input_index: 0,
            kind,
            fields: vec![],
        }]);
        assert_eq!(
            encode_response(&response),
            Err(encode::Error::DefinedSignatureKind(kind))
        );
    }
}

#[test]
fn silent_payment_entries_round_trip() {
    for entries in [sp_global_send(), sp_per_input_send()] {
        let response = signatures_response(entries);
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode(&bytes), Ok(Message::Response(response)));
    }
}

#[test]
fn a_global_entry_carries_input_index_zero() {
    let mut bytes = encode_response(&signatures_response(sp_global_send())).unwrap();
    let share = FIRST_ENTRY_OFFSET + 2 * TAP_KEY_ENTRY_LEN;
    assert_eq!(bytes[share..share + 5], [0, 0, 0, 0, 0x06]);
    bytes[share + 3] = 0x01;
    assert_eq!(decode(&bytes), Err(decode::Error::GlobalInputIndex(1)));
}

#[test]
fn decode_rejects_a_global_byte_outside_bool() {
    let mut bytes = encode_response(&signatures_response(sp_global_send())).unwrap();
    let global = FIRST_ENTRY_OFFSET + 2 * TAP_KEY_ENTRY_LEN + ENTRY_HEADER_LEN;
    assert_eq!(bytes[global], 0x01);
    bytes[global] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidBool(0x02)))
    );
}

#[test]
fn a_share_without_its_proof_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![sp_share(SpScope::Input(0), scan, 0xa0)]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Sp(sp::Error::MissingProof))
    );

    // a proof for another input does not cover the share of input 0
    let paired = signatures_response(vec![
        sp_share(SpScope::Input(0), scan, 0xa0),
        sp_proof(SpScope::Input(0), scan, 0xb0),
    ]);
    let mut bytes = encode_response(&paired).unwrap();
    let proof = FIRST_ENTRY_OFFSET + SP_SHARE_ENTRY_LEN;
    assert_eq!(bytes[proof..proof + 5], [0, 0, 0, 0, 0x07]);
    bytes[proof + 3] = 0x01;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Sp(sp::Error::MissingProof))
    );
}

#[test]
fn a_global_proof_does_not_cover_a_per_input_share() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![
        sp_share(SpScope::Input(0), scan, 0xa0),
        sp_proof(SpScope::Global, scan, 0xb0),
    ]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Sp(sp::Error::MissingProof))
    );
}

#[test]
fn a_proof_without_its_share_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let response = signatures_response(vec![sp_proof(SpScope::Global, scan, 0xb0)]);
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::Sp(sp::Error::MissingShare))
    );
}

#[test]
fn a_second_share_or_proof_for_a_scan_key_is_refused() {
    let scan = aggregate(0x02, 0x5a);
    let mut entries = sp_per_input_send();
    entries.push(sp_share(SpScope::Input(2), scan, 0xa3));
    assert_eq!(
        encode_response(&signatures_response(entries)),
        Err(encode::Error::Sp(sp::Error::DuplicateShare))
    );

    let mut entries = sp_per_input_send();
    entries.push(sp_proof(SpScope::Input(0), scan, 0xb3));
    assert_eq!(
        encode_response(&signatures_response(entries)),
        Err(encode::Error::Sp(sp::Error::DuplicateProof))
    );
}

mod get_info_response {
    use bwk_qr_protocol::{
        decode, encode, encode_request, encode_response, get_info, reader, request, response,
        types::Fingerprint, Message, Request, Response, MAX_DESCRIPTOR_ALIAS,
    };

    use crate::{id, HEADER_LEN};

    // VENDOR, MODEL, VERSION and CAPABILITIES come before STATE
    const STATE_OFFSET: usize = HEADER_LEN + 16 + 16 + 8 + 4;
    const NETWORKS_OFFSET: usize = STATE_OFFSET + 1;
    // NETWORKS and MAX_MESSAGE come before MAX_ALIAS
    const MAX_ALIAS_OFFSET: usize = NETWORKS_OFFSET + 1 + 4;

    fn info(state: response::State, fingerprint: Option<Fingerprint>) -> response::Info {
        response::Info {
            vendor: "bwk".to_string(),
            model: "bwk-signer".to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 7,
                patch: 0x00ab_cdef,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(0x0000_001f),
            state,
            networks: response::Networks(response::Networks::SIGNET),
            max_message: 0x0001_0000,
            max_alias: MAX_DESCRIPTOR_ALIAS as u8,
            max_keys: 20,
            slots: 0xffff,
            fingerprint,
        }
    }

    fn info_response(info: response::Info) -> Response {
        Response {
            id: id(),
            body: response::Body::Info(info),
        }
    }

    fn ready() -> response::Info {
        info(
            response::State::Ready,
            Some(Fingerprint([0xde, 0xad, 0xbe, 0xef])),
        )
    }

    #[test]
    fn the_request_has_an_empty_body() {
        let request = Request {
            id: id(),
            body: request::Body::GetInfo,
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(decode(&bytes), Ok(Message::Request(request)));
    }

    #[test]
    fn every_state_round_trips() {
        for info in [
            ready(),
            info(response::State::Ready, None),
            info(response::State::Locked, None),
            info(response::State::Uninitialized, None),
            info(response::State::Unknown(0x03), None),
            info(response::State::Unknown(0xff), None),
        ] {
            let response = info_response(info);
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode(&bytes), Ok(Message::Response(response)));
        }
    }

    #[test]
    fn encode_rejects_a_fingerprint_when_not_ready() {
        for state in [
            response::State::Locked,
            response::State::Uninitialized,
            response::State::Unknown(0x03),
        ] {
            let response = info_response(info(state, Some(Fingerprint([1, 2, 3, 4]))));
            assert_eq!(
                encode_response(&response),
                Err(encode::Error::GetInfo(
                    get_info::Error::FingerprintWhenNotReady
                ))
            );
        }
    }

    #[test]
    fn decode_rejects_a_fingerprint_when_not_ready() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        for state in [0x01, 0x02, 0x03] {
            bytes[STATE_OFFSET] = state;
            assert_eq!(
                decode(&bytes),
                Err(decode::Error::GetInfo(
                    get_info::Error::FingerprintWhenNotReady
                ))
            );
        }
    }

    #[test]
    fn encode_rejects_a_max_alias_above_the_alias_bound() {
        let mut info = ready();
        info.max_alias = MAX_DESCRIPTOR_ALIAS as u8 + 1;
        assert_eq!(
            encode_response(&info_response(info)),
            Err(encode::Error::GetInfo(get_info::Error::MaxAliasTooLarge(
                33
            )))
        );
    }

    #[test]
    fn decode_rejects_a_max_alias_above_the_alias_bound() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        assert_eq!(bytes[MAX_ALIAS_OFFSET], 32);
        bytes[MAX_ALIAS_OFFSET] = 33;
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::GetInfo(get_info::Error::MaxAliasTooLarge(
                33
            )))
        );
    }

    #[test]
    fn encode_rejects_reserved_network_bits() {
        let mut info = ready();
        info.networks = response::Networks(0x10 | response::Networks::MAINNET);
        assert_eq!(
            encode_response(&info_response(info)),
            Err(encode::Error::ReservedNetworkBits(0x11))
        );
    }

    #[test]
    fn decode_ignores_reserved_network_bits() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        assert_eq!(bytes[NETWORKS_OFFSET], response::Networks::SIGNET);
        bytes[NETWORKS_OFFSET] = 0xf4;
        let mut expected = ready();
        expected.networks = response::Networks(0xf4);
        assert_eq!(
            decode(&bytes),
            Ok(Message::Response(info_response(expected)))
        );
    }

    #[test]
    fn encode_rejects_an_unknown_state_of_a_defined_value() {
        for value in [0x00, 0x01, 0x02] {
            let response = info_response(info(response::State::Unknown(value), None));
            assert_eq!(
                encode_response(&response),
                Err(encode::Error::DefinedState(value))
            );
        }
    }

    #[test]
    fn decode_rejects_an_invalid_fingerprint_presence() {
        let mut bytes = encode_response(&info_response(ready())).unwrap();
        let presence = bytes.len() - 5;
        assert_eq!(bytes[presence], 0x01);
        bytes[presence] = 0x02;
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
        );
    }
}
