#![cfg(feature = "ffi")]

mod common;

use std::{
    ffi::{c_char, CStr, CString},
    ptr, slice,
};

use bwk_qr_protocol::{
    encode, encode_request,
    ffi::{
        bwk_qr_buf_free, bwk_qr_request_decode, bwk_qr_request_free, bwk_qr_response_encode, types,
        Error, OK,
    },
    get_info, nonce_cache, request,
    response::{self, SpScope},
    signature, sp,
    types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey},
    ErrorInfo, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    MAX_NONCE_EXPRESSIONS, REQUEST_ID_LEN,
};

use common::{bip380, bip388, sp_foreign_scan_keys, sp_keys, FOREIGN_SCAN_KEY};

const ID: [u8; REQUEST_ID_LEN] = [42; REQUEST_ID_LEN];

fn id() -> RequestId {
    RequestId(ID)
}

#[test]
fn nonce_preparation_request_exposes_session_ref_coverage_path_and_range() {
    for (session_ref, has_session_ref, ffi_session_ref) in
        [(None, 0, [0; 4]), (Some([0x52; 4]), 1, [0x52; 4])]
    {
        let request = request(request::Body::PrepareNonces(request::PrepareNonces {
            session_id: [0x51; 4],
            session_ref,
            max_inputs: 3,
            derivation_path: path(),
            start: 2,
            end: 9,
        }));
        unsafe {
            let handle = view(&request);
            assert_eq!((*handle).id, ID);
            assert_eq!((*handle).message_type, 0x06);
            let body = (*handle).body.prepare_nonces;
            assert_eq!(body.session_id, [0x51; 4]);
            assert_eq!(body.has_session_ref, has_session_ref);
            assert_eq!(body.session_ref, ffi_session_ref);
            assert_eq!(body.max_inputs, 3);
            assert_eq!(
                body.derivation_path.as_slice(),
                [0x8000_0030, 0x8000_0000, 7]
            );
            assert_eq!(body.start, 2);
            assert_eq!(body.end, 9);
            bwk_qr_request_free(handle);
        }
    }
}

fn nonces_response_view(
    max_inputs: u8,
    start: u32,
    end: u32,
    nonces: types::List<[u8; 66]>,
) -> types::Response {
    response_view(
        0x06,
        false,
        types::ResponseBody {
            nonces_prepared: types::NoncesPrepared {
                session_id: [0x51; 4],
                session_ref: [0x52; 4],
                max_inputs,
                start,
                end,
                nonces,
            },
        },
    )
}

#[test]
fn nonces_prepared_response_converts_every_nonce_field() {
    let nonces = [[0x22; 66], [0x55; 66], [0x66; 66], [0x77; 66]];
    unsafe {
        assert_eq!(
            encoded(&nonces_response_view(2, 4, 5, list_view(&nonces))),
            Response {
                id: id(),
                body: response::Body::NoncesPrepared(response::NoncesPrepared {
                    session_id: [0x51; 4],
                    session_ref: [0x52; 4],
                    max_inputs: 2,
                    start: 4,
                    end: 5,
                    nonces: nonces.to_vec(),
                }),
            }
        );
    }
}

#[test]
fn nonces_prepared_ffi_rejects_invalid_coverage_range_count_and_absent_nonces() {
    unsafe {
        let nonces = [[0x66; 66]];
        assert_eq!(
            encode_failure(&nonces_response_view(0, 0, 0, list_view(&nonces))),
            Error::NonceCache(nonce_cache::Error::InputCoverage).info_owned()
        );
        let range = Error::NonceCache(nonce_cache::Error::ExpressionRange).info_owned();
        assert_eq!(
            encode_failure(&nonces_response_view(1, 1, 0, list_view(&nonces))),
            range
        );
        let nonces = vec![[0x66; 66]; MAX_NONCE_EXPRESSIONS + 1];
        assert_eq!(
            encode_failure(&nonces_response_view(
                1,
                0,
                MAX_NONCE_EXPRESSIONS as u32,
                list_view(&nonces)
            )),
            range
        );
        let nonce_count = Error::NonceCache(nonce_cache::Error::NonceCount).info_owned();
        for count in [0, 1, 3, usize::MAX] {
            let wrong = types::List {
                ptr: nonces.as_ptr(),
                len: count,
            };
            assert_eq!(
                encode_failure(&nonces_response_view(2, 0, 0, wrong)),
                nonce_count
            );
        }
        let absent = types::List {
            ptr: ptr::null(),
            len: 2,
        };
        assert_eq!(
            encode_failure(&nonces_response_view(2, 0, 0, absent)),
            Error::NullPointer.info_owned()
        );
    }
}

fn path() -> DerivationPath {
    DerivationPath(vec![0x8000_0030, 0x8000_0000, 7])
}

fn request(body: request::Body) -> Request {
    Request { id: id(), body }
}

fn register_descriptor_request(descriptor: Option<request::DescriptorBody>) -> Request {
    request(request::Body::RegisterDescriptor(
        request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor,
        },
    ))
}

fn response_view(message_type: u8, is_error: bool, body: types::ResponseBody) -> types::Response {
    types::Response {
        id: ID,
        message_type,
        is_error,
        body,
    }
}

fn signatures_view(entries: &[types::Signature]) -> types::Response {
    response_view(
        MessageType::Signing.value(),
        false,
        types::ResponseBody {
            signed: types::Signed {
                kind: SignResponseKind::Signatures.value(),
                value: types::SignedValue {
                    signatures: list_view(entries),
                },
            },
        },
    )
}

fn list_view<T>(items: &[T]) -> types::List<T> {
    types::List {
        ptr: items.as_ptr(),
        len: items.len(),
    }
}

fn empty_buf() -> types::Buf {
    types::Buf {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

/// Encodes a request and hands back the C view the signer would read.
unsafe fn view(request: &Request) -> *const types::Request {
    let bytes = encode_request(request).unwrap();
    let mut out = ptr::null();
    let mut err = ptr::null();
    let code = bwk_qr_request_decode(bytes.as_ptr(), bytes.len(), &mut out, &mut err);
    assert_eq!(code, OK, "{}", message(err));
    assert!(err.is_null(), "err was written on success");
    out
}

unsafe fn decode_failure(bytes: &[u8]) -> (i32, String) {
    let mut out = ptr::null();
    let mut err = ptr::null();
    let code = bwk_qr_request_decode(bytes.as_ptr(), bytes.len(), &mut out, &mut err);
    assert_ne!(code, OK);
    assert!(out.is_null(), "out was written on failure");
    (code, message(err))
}

/// Encodes a C response and decodes it back into the Rust types.
unsafe fn encoded(view: &types::Response) -> Response {
    let mut buf = empty_buf();
    let mut err = ptr::null();
    let code = bwk_qr_response_encode(view, &mut buf, &mut err);
    assert_eq!(code, OK, "{}", message(err));
    let bytes = slice::from_raw_parts(buf.ptr, buf.len).to_vec();
    bwk_qr_buf_free(buf);
    match bwk_qr_protocol::decode(&bytes).unwrap() {
        Message::Response(response) => response,
        Message::Request(_) => panic!("a response encoded as a request"),
    }
}

unsafe fn encode_failure(view: &types::Response) -> (i32, String) {
    let mut buf = empty_buf();
    let mut err = ptr::null();
    let code = bwk_qr_response_encode(view, &mut buf, &mut err);
    assert_ne!(code, OK);
    assert!(buf.ptr.is_null(), "buf was written on failure");
    (code, message(err))
}

unsafe fn message(err: *const c_char) -> String {
    if err.is_null() {
        return String::new();
    }
    CStr::from_ptr(err).to_str().unwrap().to_string()
}

unsafe fn text(ptr: *const c_char) -> String {
    assert!(!ptr.is_null(), "unexpected null string");
    CStr::from_ptr(ptr).to_str().unwrap().to_string()
}

#[test]
fn get_keys_request_view() {
    unsafe {
        let request = request(request::Body::GetKeys(request::GetKeys {
            keys: vec![
                request::KeyRequest {
                    derivation_path: path(),
                    kind: request::KeyKind::Public,
                },
                request::KeyRequest {
                    derivation_path: DerivationPath(vec![]),
                    kind: request::KeyKind::Private,
                },
            ],
        }));
        let view = view(&request);
        assert_eq!((*view).id, ID);
        assert_eq!((*view).message_type, MessageType::GetKeys.value());

        let keys = (*view).body.get_keys.keys.as_slice();
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0].derivation_path.as_slice(),
            &[0x8000_0030, 0x8000_0000, 7]
        );
        assert_eq!(keys[0].kind, request::KeyKind::Public.value());
        assert_eq!(keys[1].derivation_path.len, 0);
        assert_eq!(keys[1].kind, request::KeyKind::Private.value());
        bwk_qr_request_free(view);
    }
}

#[test]
fn register_descriptor_bip380_view() {
    unsafe {
        let request = register_descriptor_request(Some(bip380()));
        let view = view(&request);
        let body = (*view).body.register_descriptor;
        assert_eq!(text(body.descriptor_alias), "main");
        assert_eq!((*body.descriptor).tag, request::DESCRIPTOR_BIP380);
        assert_eq!(
            text((*body.descriptor).value.bip380),
            "wpkh([00000000/84h/1h/0h]xpub/0/*)"
        );
        bwk_qr_request_free(view);
    }
}

#[test]
fn register_descriptor_bip388_view() {
    unsafe {
        let request = register_descriptor_request(Some(bip388()));
        let view = view(&request);
        let descriptor = (*view).body.register_descriptor.descriptor;
        assert_eq!((*descriptor).tag, request::DESCRIPTOR_BIP388);
        let bip388 = (*descriptor).value.bip388;
        let keys = bip388.keys.as_slice();
        assert_eq!(keys.len(), 2);
        assert_eq!(text(keys[0]), "[00000000/48h/1h/0h/2h]xpub");
        assert_eq!(text(keys[1]), "[11111111/48h/1h/0h/2h]xpub");
        assert_eq!(text(bip388.policy), "wsh(sortedmulti(2,@0/**,@1/**))");
        bwk_qr_request_free(view);
    }
}

#[test]
fn register_descriptor_sp_keys_view() {
    unsafe {
        let request = register_descriptor_request(Some(sp_keys()));
        let view = view(&request);
        let body = (*view).body.register_descriptor;
        assert_eq!(text(body.descriptor_alias), "main");
        assert_eq!((*body.descriptor).tag, request::DESCRIPTOR_SP_KEYS);
        let keys = (*body.descriptor).value.sp_keys;
        assert_eq!(keys.fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
        assert_eq!(
            keys.spend_path.as_slice(),
            &[0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0000, 0]
        );
        assert_eq!(keys.scan_kind, types::SCAN_PATH);
        assert_eq!(
            keys.scan.path.as_slice(),
            &[0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0001, 0]
        );
        bwk_qr_request_free(view);
    }
}

#[test]
fn absent_descriptor_is_a_null_pointer() {
    unsafe {
        let request = register_descriptor_request(None);
        let view = view(&request);
        assert!((*view).body.register_descriptor.descriptor.is_null());
        bwk_qr_request_free(view);
    }
}

#[test]
fn verify_address_view_with_every_option_present() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: path(),
            address: Some("bc1qxyz".to_string()),
            descriptor: Some(bip380()),
            proof: Some(vec![0x5a; 4]),
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert_eq!(text(body.descriptor_alias), "main");
        assert_eq!(
            body.derivation_path.as_slice(),
            &[0x8000_0030, 0x8000_0000, 7]
        );
        assert_eq!(text(body.address), "bc1qxyz");
        assert!(!body.descriptor.is_null());
        assert_eq!(body.proof.as_slice(), &[0x5a; 4]);
        bwk_qr_request_free(view);
    }
}

#[test]
fn verify_address_view_with_silent_payment_keys() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: DerivationPath(vec![]),
            address: Some("sp1qxyz".to_string()),
            descriptor: Some(sp_keys()),
            proof: None,
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert!(body.derivation_path.as_slice().is_empty());
        let descriptor = body.descriptor;
        assert_eq!((*descriptor).tag, request::DESCRIPTOR_SP_KEYS);
        let keys = (*descriptor).value.sp_keys;
        assert_eq!(keys.fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
        assert_eq!(
            keys.spend_path.as_slice(),
            &[0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0000, 0]
        );
        assert_eq!(keys.scan_kind, types::SCAN_PATH);
        assert_eq!(
            keys.scan.path.as_slice(),
            &[0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0001, 0]
        );
        bwk_qr_request_free(view);
    }
}

#[test]
fn verify_address_view_with_silent_payment_keys_and_a_proof() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: DerivationPath(vec![]),
            address: Some("sp1qxyz".to_string()),
            descriptor: Some(sp_keys()),
            proof: Some(vec![0x5a; 4]),
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert_eq!(text(body.descriptor_alias), "main");
        assert_eq!((*body.descriptor).tag, request::DESCRIPTOR_SP_KEYS);
        assert_eq!(body.proof.as_slice(), &[0x5a; 4]);
        bwk_qr_request_free(view);
    }
}

#[test]
fn verify_address_view_with_a_foreign_scan_key() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: DerivationPath(vec![2]),
            address: Some("sp1qxyz".to_string()),
            descriptor: Some(sp_foreign_scan_keys()),
            proof: None,
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert_eq!(body.derivation_path.as_slice(), &[2]);
        let descriptor = body.descriptor;
        assert_eq!((*descriptor).tag, request::DESCRIPTOR_SP_KEYS);
        let keys = (*descriptor).value.sp_keys;
        assert_eq!(keys.fingerprint, [0x73, 0xc5, 0xda, 0x0a]);
        assert_eq!(
            keys.spend_path.as_slice(),
            &[0x8000_0160, 0x8000_0001, 0x8000_0000, 0x8000_0000, 0]
        );
        assert_eq!(keys.scan_kind, types::SCAN_KEY);
        assert_eq!(keys.scan.key, FOREIGN_SCAN_KEY);
        bwk_qr_request_free(view);
    }
}

#[test]
fn verify_address_view_with_every_option_absent() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: DerivationPath(vec![]),
            address: None,
            descriptor: None,
            proof: None,
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert!(body.address.is_null());
        assert!(body.descriptor.is_null());
        assert!(body.proof.is_absent());
        bwk_qr_request_free(view);
    }
}

#[test]
fn an_empty_proof_is_present_not_absent() {
    unsafe {
        let request = request(request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: DerivationPath(vec![]),
            address: Some(String::new()),
            descriptor: None,
            proof: Some(Vec::new()),
        }));
        let view = view(&request);
        let body = (*view).body.verify_address;
        assert!(
            !body.proof.is_absent(),
            "an empty proof must not read as absent"
        );
        assert_eq!(body.proof.len, 0);
        assert_eq!(text(body.address), "");
        bwk_qr_request_free(view);
    }
}

#[test]
fn sign_request_view() {
    unsafe {
        let request = request(request::Body::Sign(request::Sign {
            descriptors: vec![
                request::Descriptor {
                    alias: "main".to_string(),
                    descriptor: Some(bip380()),
                    proof: Some(vec![1, 2, 3]),
                },
                request::Descriptor {
                    alias: "backup".to_string(),
                    descriptor: Some(bip388()),
                    proof: None,
                },
            ],
            psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
            want_kind: Some(SignResponseKind::Signatures),
        }));
        let view = view(&request);
        let body = (*view).body.sign;
        let descriptors = body.descriptors.as_slice();
        assert_eq!(descriptors.len(), 2);
        assert_eq!(text(descriptors[0].alias), "main");
        assert_eq!((*descriptors[0].body).tag, request::DESCRIPTOR_BIP380);
        assert_eq!(descriptors[0].proof.as_slice(), &[1, 2, 3]);
        assert_eq!(text(descriptors[1].alias), "backup");
        assert_eq!((*descriptors[1].body).tag, request::DESCRIPTOR_BIP388);
        assert!(descriptors[1].proof.is_absent());
        assert_eq!(body.psbt.as_slice(), &[0x70, 0x73, 0x62, 0x74, 0xff]);
        assert_eq!(body.want_kind, SignResponseKind::Signatures.value() as i16);
        bwk_qr_request_free(view);
    }
}

#[test]
fn an_absent_want_kind_is_negative() {
    unsafe {
        let request = request(request::Body::Sign(request::Sign {
            descriptors: vec![],
            psbt: vec![0x70],
            want_kind: None,
        }));
        let view = view(&request);
        assert_eq!((*view).body.sign.want_kind, types::ABSENT_KIND);
        assert_eq!((*view).body.sign.descriptors.len, 0);
        bwk_qr_request_free(view);
    }
}

#[test]
fn keys_response_encodes() {
    unsafe {
        let keys = [[0xab; 78], [0xcd; 78]];
        let view = response_view(
            MessageType::GetKeys.value(),
            false,
            types::ResponseBody {
                keys: types::Keys {
                    keys: list_view(&keys),
                    fingerprint: [0xde, 0xad, 0xbe, 0xef],
                    vendor: c"bwk".as_ptr(),
                    model: c"bwk-signer".as_ptr(),
                    version: types::FirmwareVersion {
                        major: 1,
                        minor: 7,
                        patch: 0x00ab_cdef,
                        flag: response::ReleaseFlag::Beta.value(),
                    },
                    capabilities: 0x0000_000b,
                },
            },
        );
        assert_eq!(
            encoded(&view),
            Response {
                id: id(),
                body: response::Body::Keys(response::Keys {
                    keys: vec![ExtendedKey([0xab; 78]), ExtendedKey([0xcd; 78])],
                    fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
                    vendor: "bwk".to_string(),
                    model: "bwk-signer".to_string(),
                    version: response::FirmwareVersion {
                        major: 1,
                        minor: 7,
                        patch: 0x00ab_cdef,
                        flag: response::ReleaseFlag::Beta,
                    },
                    capabilities: response::Capabilities(0x0000_000b),
                }),
            }
        );
    }
}

#[test]
fn get_info_request_view() {
    unsafe {
        let view = view(&request(request::Body::GetInfo));
        assert_eq!((*view).id, ID);
        assert_eq!((*view).message_type, MessageType::GetInfo.value());
        bwk_qr_request_free(view);
    }
}

fn info_view(state: u8, has_fingerprint: u8, max_alias: u8) -> types::Response {
    response_view(
        MessageType::GetInfo.value(),
        false,
        types::ResponseBody {
            info: types::Info {
                vendor: c"bwk".as_ptr(),
                model: c"bwk-signer".as_ptr(),
                version: types::FirmwareVersion {
                    major: 1,
                    minor: 7,
                    patch: 0x00ab_cdef,
                    flag: response::ReleaseFlag::Alpha.value(),
                },
                capabilities: 0x0000_0013,
                state,
                networks: response::Networks::MAINNET | response::Networks::REGTEST,
                max_message: 0x0002_0000,
                max_alias,
                max_keys: 15,
                slots: 300,
                has_fingerprint,
                fingerprint: [0xde, 0xad, 0xbe, 0xef],
            },
        },
    )
}

#[test]
fn info_response_encodes() {
    unsafe {
        let expected = |state, fingerprint| Response {
            id: id(),
            body: response::Body::Info(response::Info {
                vendor: "bwk".to_string(),
                model: "bwk-signer".to_string(),
                version: response::FirmwareVersion {
                    major: 1,
                    minor: 7,
                    patch: 0x00ab_cdef,
                    flag: response::ReleaseFlag::Alpha,
                },
                capabilities: response::Capabilities(0x0000_0013),
                state,
                networks: response::Networks(0x12),
                max_message: 0x0002_0000,
                max_alias: 32,
                max_keys: 15,
                slots: 300,
                fingerprint,
            }),
        };
        assert_eq!(
            encoded(&info_view(response::STATE_READY, 1, 32)),
            expected(
                response::State::Ready,
                Some(Fingerprint([0xde, 0xad, 0xbe, 0xef]))
            )
        );
        // the fingerprint bytes are ignored when has_fingerprint is 0
        assert_eq!(
            encoded(&info_view(response::STATE_LOCKED, 0, 32)),
            expected(response::State::Locked, None)
        );
    }
}

#[test]
fn info_encode_rejects_an_invalid_fingerprint_presence() {
    unsafe {
        let view = info_view(response::STATE_READY, 2, 32);
        assert_eq!(encode_failure(&view), Error::InvalidBool.info_owned());
    }
}

#[test]
fn info_encode_rejects_a_fingerprint_when_not_ready() {
    unsafe {
        for state in [response::STATE_LOCKED, response::STATE_UNINITIALIZED, 0x03] {
            let view = info_view(state, 1, 32);
            assert_eq!(
                encode_failure(&view),
                get_info::Error::FingerprintWhenNotReady.info_owned()
            );
        }
    }
}

#[test]
fn info_encode_rejects_a_max_alias_above_the_alias_bound() {
    unsafe {
        let view = info_view(response::STATE_READY, 1, 33);
        assert_eq!(
            encode_failure(&view),
            get_info::Error::MaxAliasTooLarge(33).info_owned()
        );
    }
}

#[test]
fn info_encode_rejects_reserved_network_bits() {
    unsafe {
        let mut view = info_view(response::STATE_READY, 1, 32);
        for networks in [0x01, 0x80] {
            view.body.info.networks = networks;
            assert_eq!(
                encode_failure(&view),
                encode::Error::ReservedNetworkBits(networks).info_owned()
            );
        }
    }
}

#[test]
fn registration_response_encodes_every_tri_state() {
    for (registered, stored, expected_registered, expected_stored) in [
        (1i8, 1i8, Some(true), Some(true)),
        (0, 1, Some(false), Some(true)),
        (types::ABSENT_BOOL, 0, None, Some(false)),
        (types::ABSENT_BOOL, types::ABSENT_BOOL, None, None),
    ] {
        unsafe {
            let alias = CString::new("main").unwrap();
            let proof = [0xaa; 32];
            let view = response_view(
                MessageType::RegisterDescriptor.value(),
                false,
                types::ResponseBody {
                    registration: types::Registration {
                        descriptor_alias: alias.as_ptr(),
                        registered,
                        stored,
                        proof: list_view(&proof),
                    },
                },
            );
            assert_eq!(
                encoded(&view).body,
                response::Body::Registration(response::Registration {
                    descriptor_alias: "main".to_string(),
                    registered: expected_registered,
                    stored: expected_stored,
                    proof: Some(proof.to_vec()),
                })
            );
        }
    }
}

#[test]
fn an_absent_proof_encodes_as_absent() {
    unsafe {
        let alias = CString::new("main").unwrap();
        let view = response_view(
            MessageType::RegisterDescriptor.value(),
            false,
            types::ResponseBody {
                registration: types::Registration {
                    descriptor_alias: alias.as_ptr(),
                    registered: types::ABSENT_BOOL,
                    stored: types::ABSENT_BOOL,
                    proof: types::Bytes::absent(),
                },
            },
        );
        let response::Body::Registration(body) = encoded(&view).body else {
            panic!("not a registration response")
        };
        assert_eq!(body.proof, None);
    }
}

#[test]
fn address_uri_response_encodes_present_and_absent() {
    for (uri, expected) in [
        (Some("bitcoin:bc1qxyz"), Some("bitcoin:bc1qxyz".to_string())),
        (None, None),
    ] {
        unsafe {
            let owned = uri.map(|uri| CString::new(uri).unwrap());
            let view = response_view(
                MessageType::AddressVerification.value(),
                false,
                types::ResponseBody {
                    address_uri: types::AddressUri {
                        uri: owned.as_ref().map_or(ptr::null(), |uri| uri.as_ptr()),
                    },
                },
            );
            assert_eq!(
                encoded(&view).body,
                response::Body::AddressUri(response::AddressUri { uri: expected })
            );
        }
    }
}

#[test]
fn signed_psbt_response_encodes() {
    unsafe {
        let psbt = [0x70, 0x73, 0x62, 0x74, 0xff];
        let view = response_view(
            MessageType::Signing.value(),
            false,
            types::ResponseBody {
                signed: types::Signed {
                    kind: SignResponseKind::Psbt.value(),
                    value: types::SignedValue {
                        psbt: list_view(&psbt),
                    },
                },
            },
        );
        assert_eq!(
            encoded(&view).body,
            response::Body::Signed(response::Signed::Psbt(psbt.to_vec()))
        );
    }
}

#[test]
fn signed_signatures_response_encodes_every_kind() {
    unsafe {
        let ecdsa_sig = [0x30; 71];
        let tap_key_sig = [0x01; 64];
        let tap_script_sig = [0x04; 65];
        let entries = [
            types::Signature {
                input_index: 0,
                kind: response::SIGNATURE_ECDSA,
                value: types::SignatureValue {
                    ecdsa: types::Ecdsa {
                        public_key: [0x02; 33],
                        signature: list_view(&ecdsa_sig),
                    },
                },
            },
            types::Signature {
                input_index: 1,
                kind: response::SIGNATURE_TAP_KEY,
                value: types::SignatureValue {
                    tap_key: types::TapKey {
                        signature: list_view(&tap_key_sig),
                    },
                },
            },
            types::Signature {
                input_index: 2,
                kind: response::SIGNATURE_TAP_SCRIPT,
                value: types::SignatureValue {
                    tap_script: types::TapScript {
                        xonly_public_key: [0x05; 32],
                        tap_leaf_hash: [0x06; 32],
                        signature: list_view(&tap_script_sig),
                    },
                },
            },
            types::Signature {
                input_index: 3,
                kind: response::SIGNATURE_MUSIG_PUB_NONCE,
                value: types::SignatureValue {
                    musig_pub_nonce: types::MusigPubNonce {
                        participant: [0x07; 33],
                        aggregate: [0x08; 33],
                        has_leaf_hash: 0,
                        leaf_hash: [0; 32],
                        nonce: [0x09; 66],
                    },
                },
            },
            types::Signature {
                input_index: 4,
                kind: response::SIGNATURE_MUSIG_PARTIAL_SIG,
                value: types::SignatureValue {
                    musig_partial_sig: types::MusigPartialSig {
                        participant: [0x0a; 33],
                        aggregate: [0x0b; 33],
                        has_leaf_hash: 1,
                        leaf_hash: [0x0c; 32],
                        signature: [0x0d; 32],
                    },
                },
            },
            types::Signature {
                input_index: 0,
                kind: response::SIGNATURE_SP_ECDH_SHARE,
                value: types::SignatureValue {
                    sp_ecdh_share: types::SpEcdhShare {
                        global: 1,
                        scan_key: [0x0e; 33],
                        share: [0x0f; 33],
                    },
                },
            },
            types::Signature {
                input_index: 0,
                kind: response::SIGNATURE_SP_DLEQ_PROOF,
                value: types::SignatureValue {
                    sp_dleq_proof: types::SpDleqProof {
                        global: 1,
                        scan_key: [0x0e; 33],
                        proof: [0x10; 64],
                    },
                },
            },
            types::Signature {
                input_index: 5,
                kind: response::SIGNATURE_SP_ECDH_SHARE,
                value: types::SignatureValue {
                    sp_ecdh_share: types::SpEcdhShare {
                        global: 0,
                        scan_key: [0x11; 33],
                        share: [0x12; 33],
                    },
                },
            },
            types::Signature {
                input_index: 5,
                kind: response::SIGNATURE_SP_DLEQ_PROOF,
                value: types::SignatureValue {
                    sp_dleq_proof: types::SpDleqProof {
                        global: 0,
                        scan_key: [0x11; 33],
                        proof: [0x13; 64],
                    },
                },
            },
        ];
        let view = signatures_view(&entries);
        assert_eq!(
            encoded(&view).body,
            response::Body::Signed(response::Signed::Signatures(vec![
                response::SignatureEntry::Ecdsa {
                    input_index: 0,
                    public_key: PublicKey([0x02; 33]),
                    signature: ecdsa_sig.to_vec(),
                },
                response::SignatureEntry::TapKey {
                    input_index: 1,
                    signature: tap_key_sig.to_vec(),
                },
                response::SignatureEntry::TapScript {
                    input_index: 2,
                    xonly_public_key: [0x05; 32],
                    tap_leaf_hash: [0x06; 32],
                    signature: tap_script_sig.to_vec(),
                },
                response::SignatureEntry::MusigPubNonce {
                    input_index: 3,
                    participant: PublicKey([0x07; 33]),
                    aggregate: PublicKey([0x08; 33]),
                    leaf_hash: None,
                    nonce: [0x09; 66],
                },
                response::SignatureEntry::MusigPartialSig {
                    input_index: 4,
                    participant: PublicKey([0x0a; 33]),
                    aggregate: PublicKey([0x0b; 33]),
                    leaf_hash: Some([0x0c; 32]),
                    signature: [0x0d; 32],
                },
                response::SignatureEntry::SpEcdhShare {
                    scope: SpScope::Global,
                    scan_key: PublicKey([0x0e; 33]),
                    share: PublicKey([0x0f; 33]),
                },
                response::SignatureEntry::SpDleqProof {
                    scope: SpScope::Global,
                    scan_key: PublicKey([0x0e; 33]),
                    proof: [0x10; 64],
                },
                response::SignatureEntry::SpEcdhShare {
                    scope: SpScope::Input(5),
                    scan_key: PublicKey([0x11; 33]),
                    share: PublicKey([0x12; 33]),
                },
                response::SignatureEntry::SpDleqProof {
                    scope: SpScope::Input(5),
                    scan_key: PublicKey([0x11; 33]),
                    proof: [0x13; 64],
                },
            ]))
        );
    }
}

#[test]
fn error_response_encodes() {
    unsafe {
        let view = response_view(
            MessageType::Signing.value(),
            true,
            types::ResponseBody {
                error: types::ErrorBody {
                    error: response::Error::UserDeclined.value(),
                    message: c"signing was declined".as_ptr(),
                },
            },
        );
        assert_eq!(
            encoded(&view).body,
            response::Body::Error(response::ErrorBody {
                message_type: MessageType::Signing,
                error: response::Error::UserDeclined,
                message: "signing was declined".to_string(),
            })
        );
    }
}

#[test]
fn decode_rejects_null_pointers() {
    unsafe {
        let mut out = ptr::null();
        let mut err = ptr::null();
        let code = bwk_qr_request_decode(ptr::null(), 0, &mut out, &mut err);
        assert_eq!((code, message(err)), Error::NullPointer.info_owned());

        let bytes = encode_request(&request(request::Body::Sign(request::Sign {
            descriptors: vec![],
            psbt: vec![0x70],
            want_kind: None,
        })))
        .unwrap();
        let code = bwk_qr_request_decode(bytes.as_ptr(), bytes.len(), ptr::null_mut(), &mut err);
        assert_eq!((code, message(err)), Error::NullPointer.info_owned());
    }
}

#[test]
fn decode_rejects_a_response_blob() {
    unsafe {
        let response = Response {
            id: id(),
            body: response::Body::AddressUri(response::AddressUri { uri: None }),
        };
        let bytes = bwk_qr_protocol::encode_response(&response).unwrap();
        assert_eq!(
            decode_failure(&bytes),
            Error::UnexpectedResponse.info_owned()
        );
    }
}

#[test]
fn decode_reports_the_codec_error() {
    unsafe {
        let bytes = encode_request(&request(request::Body::GetKeys(request::GetKeys {
            keys: vec![request::KeyRequest {
                derivation_path: path(),
                kind: request::KeyKind::Public,
            }],
        })))
        .unwrap();
        assert_eq!(
            decode_failure(&bytes[..bytes.len() - 1]),
            bwk_qr_protocol::reader::Error::Truncated.info_owned()
        );
    }
}

#[test]
fn encode_rejects_null_pointers() {
    unsafe {
        let mut buf = empty_buf();
        let mut err = ptr::null();
        let code = bwk_qr_response_encode(ptr::null(), &mut buf, &mut err);
        assert_eq!((code, message(err)), Error::NullPointer.info_owned());
    }
}

#[test]
fn encode_rejects_an_unknown_message_type() {
    unsafe {
        let view = response_view(
            0x09,
            false,
            types::ResponseBody {
                address_uri: types::AddressUri { uri: ptr::null() },
            },
        );
        assert_eq!(encode_failure(&view), Error::UnknownTag.info_owned());
    }
}

#[test]
fn encode_rejects_an_unknown_signature_kind() {
    unsafe {
        let entries = [types::Signature {
            input_index: 0,
            kind: 0x09,
            value: types::SignatureValue {
                tap_key: types::TapKey {
                    signature: types::Bytes::absent(),
                },
            },
        }];
        let view = signatures_view(&entries);
        assert_eq!(encode_failure(&view), Error::UnknownTag.info_owned());
    }
}

#[test]
fn encode_rejects_a_taproot_signature_of_another_length() {
    unsafe {
        let short = [0x01; 63];
        let long = [0x01; 66];
        for signature in [&short[..], &long[..]] {
            let entries = [
                types::Signature {
                    input_index: 0,
                    kind: response::SIGNATURE_TAP_KEY,
                    value: types::SignatureValue {
                        tap_key: types::TapKey {
                            signature: list_view(signature),
                        },
                    },
                },
                types::Signature {
                    input_index: 1,
                    kind: response::SIGNATURE_TAP_SCRIPT,
                    value: types::SignatureValue {
                        tap_script: types::TapScript {
                            xonly_public_key: [0x05; 32],
                            tap_leaf_hash: [0x06; 32],
                            signature: list_view(signature),
                        },
                    },
                },
            ];
            for entry in entries {
                let view = signatures_view(&[entry]);
                assert_eq!(
                    encode_failure(&view),
                    signature::Error::TaprootLength(signature.len()).info_owned()
                );
            }
        }
    }
}

fn sp_share_view(input_index: u32, global: u8) -> types::Signature {
    types::Signature {
        input_index,
        kind: response::SIGNATURE_SP_ECDH_SHARE,
        value: types::SignatureValue {
            sp_ecdh_share: types::SpEcdhShare {
                global,
                scan_key: [0x02; 33],
                share: [0x03; 33],
            },
        },
    }
}

#[test]
fn encode_rejects_a_global_entry_with_an_input_index() {
    unsafe {
        let entries = [sp_share_view(1, 1)];
        let view = signatures_view(&entries);
        assert_eq!(encode_failure(&view), Error::GlobalInputIndex.info_owned());
    }
}

#[test]
fn encode_rejects_a_global_byte_outside_bool() {
    unsafe {
        let entries = [sp_share_view(0, 2)];
        let view = signatures_view(&entries);
        assert_eq!(encode_failure(&view), Error::InvalidBool.info_owned());
    }
}

#[test]
fn encode_rejects_a_share_without_its_proof() {
    unsafe {
        let entries = [sp_share_view(0, 0)];
        let view = signatures_view(&entries);
        assert_eq!(encode_failure(&view), sp::Error::MissingProof.info_owned());
    }
}

#[test]
fn encode_rejects_an_invalid_leaf_hash_presence() {
    unsafe {
        let entries = [types::Signature {
            input_index: 0,
            kind: response::SIGNATURE_MUSIG_PUB_NONCE,
            value: types::SignatureValue {
                musig_pub_nonce: types::MusigPubNonce {
                    participant: [0x02; 33],
                    aggregate: [0x03; 33],
                    has_leaf_hash: 2,
                    leaf_hash: [0x04; 32],
                    nonce: [0x05; 66],
                },
            },
        }];
        let view = signatures_view(&entries);
        assert_eq!(encode_failure(&view), Error::InvalidBool.info_owned());
    }
}

#[test]
fn encode_rejects_an_invalid_tri_state() {
    unsafe {
        let alias = CString::new("main").unwrap();
        let view = response_view(
            MessageType::RegisterDescriptor.value(),
            false,
            types::ResponseBody {
                registration: types::Registration {
                    descriptor_alias: alias.as_ptr(),
                    registered: 2,
                    stored: types::ABSENT_BOOL,
                    proof: types::Bytes::absent(),
                },
            },
        );
        assert_eq!(encode_failure(&view), Error::InvalidBool.info_owned());
    }
}

#[test]
fn encode_rejects_a_null_required_string() {
    unsafe {
        let view = response_view(
            MessageType::RegisterDescriptor.value(),
            false,
            types::ResponseBody {
                registration: types::Registration {
                    descriptor_alias: ptr::null(),
                    registered: types::ABSENT_BOOL,
                    stored: types::ABSENT_BOOL,
                    proof: types::Bytes::absent(),
                },
            },
        );
        assert_eq!(encode_failure(&view), Error::NullPointer.info_owned());
    }
}

#[test]
fn freeing_a_null_handle_is_a_no_op() {
    unsafe {
        bwk_qr_request_free(ptr::null());
        bwk_qr_buf_free(empty_buf());
    }
}

/// The tests compare against `(code, message)` with the message already owned.
trait InfoOwned {
    fn info_owned(&self) -> (i32, String);
}

impl InfoOwned for Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

impl InfoOwned for get_info::Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

impl InfoOwned for encode::Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

impl InfoOwned for signature::Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

impl InfoOwned for sp::Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

impl InfoOwned for bwk_qr_protocol::reader::Error {
    fn info_owned(&self) -> (i32, String) {
        owned(self.info())
    }
}

fn owned(info: ErrorInfo) -> (i32, String) {
    (
        info.code,
        info.message[..info.message.len() - 1].to_string(),
    )
}
