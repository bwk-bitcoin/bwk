#![cfg(feature = "ffi")]

mod common;

use std::{
    ffi::{c_char, CStr, CString},
    ptr, slice,
};

use bwk_qr_protocol::{
    encode_request,
    ffi::{
        bwk_qr_buf_free, bwk_qr_request_decode, bwk_qr_request_free, bwk_qr_response_encode, types,
        Error, OK,
    },
    musig, request, response,
    types::{DerivationPath, ExtendedKey, Fingerprint, PublicKey},
    ErrorInfo, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    ERROR_MESSAGE_LEN, MODEL_LEN, REQUEST_ID_LEN,
};

use common::{bip380, bip388, sp_keys};

const ID: [u8; REQUEST_ID_LEN] = [42; REQUEST_ID_LEN];

fn id() -> RequestId {
    RequestId(ID)
}

#[test]
fn cached_preparation_request_exposes_owned_descriptor_and_derivations() {
    for descriptor in [bip380(), bip388()] {
        let request = request(request::Body::PrepareMusig(request::PrepareMusig {
            descriptor: request::Descriptor {
                alias: "cached".into(),
                descriptor: Some(descriptor.clone()),
                proof: Some(vec![0x81, 0x82]),
            },
            session_id: [0x51; 32],
            max_inputs: 8,
            derivations: vec![
                request::MusigDerivation {
                    keychain: 0,
                    index: 7,
                },
                request::MusigDerivation {
                    keychain: 1,
                    index: 0x7fff_ffff,
                },
            ],
        }));
        unsafe {
            let handle = view(&request);
            assert_eq!((*handle).id, ID);
            assert_eq!((*handle).message_type, 0x05);
            let body = (*handle).body.prepare_musig;
            assert_eq!(body.session_id, [0x51; 32]);
            assert_eq!(body.max_inputs, 8);
            assert_eq!(
                CStr::from_ptr(body.descriptor.alias).to_str().unwrap(),
                "cached"
            );
            assert_eq!(body.descriptor.proof.as_slice(), [0x81, 0x82]);
            let descriptor_view = &*body.descriptor.body;
            assert_eq!(descriptor_view.tag, descriptor.value());
            match &descriptor {
                request::DescriptorBody::Bip380(text) => {
                    assert_eq!(
                        CStr::from_ptr(descriptor_view.value.bip380)
                            .to_str()
                            .unwrap(),
                        text
                    );
                }
                request::DescriptorBody::Bip388 { keys, policy } => {
                    let value = descriptor_view.value.bip388;
                    let actual: Vec<_> = value
                        .keys
                        .as_slice()
                        .iter()
                        .map(|key| CStr::from_ptr(*key).to_str().unwrap())
                        .collect();
                    assert_eq!(actual, keys.iter().map(String::as_str).collect::<Vec<_>>());
                    assert_eq!(CStr::from_ptr(value.policy).to_str().unwrap(), policy);
                }
                request::DescriptorBody::SpKeys(_) => panic!("unexpected fixture"),
            }
            let derivations = body.derivations.as_slice();
            assert_eq!(derivations.len(), 2);
            assert_eq!((derivations[0].keychain, derivations[0].index), (0, 7));
            assert_eq!(
                (derivations[1].keychain, derivations[1].index),
                (1, 0x7fff_ffff)
            );
            bwk_qr_request_free(handle);
        }
    }
}

#[test]
fn cached_signing_request_exposes_both_ids_and_psbt() {
    let request = request(request::Body::SignMusig(request::SignMusig {
        session_id: [0x51; 32],
        attempt_id: [0xa7; 32],
        psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
    }));
    unsafe {
        let handle = view(&request);
        assert_eq!((*handle).id, ID);
        assert_eq!((*handle).message_type, 0x06);
        let body = (*handle).body.sign_musig;
        assert_eq!(body.session_id, [0x51; 32]);
        assert_eq!(body.attempt_id, [0xa7; 32]);
        assert_eq!(body.psbt.as_slice(), b"psbt\xff");
        bwk_qr_request_free(handle);
    }
}

fn cached_nonce(has_leaf_hash: u8) -> types::MusigNonce {
    types::MusigNonce {
        derivation: types::MusigDerivation {
            keychain: 1,
            index: 17,
        },
        input_index: 0,
        expression_index: 3,
        participant: [0x02; 33],
        aggregate: [0x03; 33],
        has_leaf_hash,
        leaf_hash: [0x44; 32],
        nonce: [0x66; 66],
    }
}

fn cached_response_view(nonces: &[types::MusigNonce]) -> types::Response {
    response_view(
        0x05,
        false,
        types::ResponseBody {
            musig_prepared: types::MusigPrepared {
                session_id: [0x51; 32],
                max_inputs: 1,
                nonces: list_view(nonces),
            },
        },
    )
}

#[test]
fn cached_prepared_response_converts_every_nonce_field() {
    for has_leaf_hash in [0, 1] {
        let nonces = [cached_nonce(has_leaf_hash)];
        let view = cached_response_view(&nonces);
        unsafe {
            assert_eq!(
                encoded(&view),
                Response {
                    id: id(),
                    body: response::Body::MusigPrepared(response::MusigPrepared {
                        session_id: [0x51; 32],
                        max_inputs: 1,
                        nonces: vec![response::MusigNonce {
                            derivation: request::MusigDerivation {
                                keychain: 1,
                                index: 17,
                            },
                            input_index: 0,
                            expression_index: 3,
                            participant: PublicKey([0x02; 33]),
                            aggregate: PublicKey([0x03; 33]),
                            leaf_hash: (has_leaf_hash == 1).then_some([0x44; 32]),
                            nonce: [0x66; 66],
                        }],
                    }),
                }
            );
        }
    }
}

#[test]
fn cached_signed_response_converts_both_ids_and_psbt() {
    let psbt = b"psbt\xff";
    let view = response_view(
        0x06,
        false,
        types::ResponseBody {
            musig_signed: types::MusigSigned {
                session_id: [0x51; 32],
                attempt_id: [0xa7; 32],
                psbt: list_view(psbt),
            },
        },
    );
    unsafe {
        assert_eq!(
            encoded(&view),
            Response {
                id: id(),
                body: response::Body::MusigSigned(response::MusigSigned {
                    session_id: [0x51; 32],
                    attempt_id: [0xa7; 32],
                    psbt: psbt.to_vec(),
                }),
            }
        );
    }
}

#[test]
fn cached_prepared_ffi_rejects_invalid_presence_and_attribution() {
    unsafe {
        let nonces = [cached_nonce(2)];
        assert_eq!(
            encode_failure(&cached_response_view(&nonces)),
            Error::InvalidBool.info_owned()
        );
        let mut nonces = [cached_nonce(0), cached_nonce(0)];
        nonces[1].nonce = [0x77; 66];
        let (code, _) = encode_failure(&cached_response_view(&nonces));
        assert_eq!(code, musig::Error::DuplicateNonce.info().code);
        let mut nonces = [cached_nonce(0)];
        nonces[0].input_index = 1;
        let (code, _) = encode_failure(&cached_response_view(&nonces));
        assert_eq!(code, musig::Error::NonceInputIndex.info().code);
        let (code, _) = encode_failure(&cached_response_view(&[]));
        assert_eq!(code, musig::Error::NonceCount.info().code);
    }
}

#[test]
fn cached_response_ffi_rejects_oversized_and_absent_required_fields() {
    unsafe {
        let nonces = vec![cached_nonce(0); bwk_qr_protocol::MAX_VEC + 1];
        let (code, _) = encode_failure(&cached_response_view(&nonces));
        assert_eq!(code, musig::Error::NonceCount.info().code);
        let view = response_view(
            0x05,
            false,
            types::ResponseBody {
                musig_prepared: types::MusigPrepared {
                    session_id: [0x51; 32],
                    max_inputs: 1,
                    nonces: types::List {
                        ptr: ptr::null(),
                        len: 1,
                    },
                },
            },
        );
        assert_eq!(encode_failure(&view), Error::NullPointer.info_owned());
        let view = response_view(
            0x06,
            false,
            types::ResponseBody {
                musig_signed: types::MusigSigned {
                    session_id: [0x51; 32],
                    attempt_id: [0xa7; 32],
                    psbt: types::Bytes::absent(),
                },
            },
        );
        assert_eq!(encode_failure(&view), Error::NullPointer.info_owned());
    }
}

fn path() -> DerivationPath {
    DerivationPath(vec![0x8000_0030, 0x8000_0000, 7])
}

fn extended_key() -> ExtendedKey {
    ExtendedKey([0xab; 78])
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

fn fixed<const N: usize>(text: &str) -> [c_char; N] {
    let mut field = [0; N];
    for (slot, byte) in field.iter_mut().zip(text.bytes()) {
        *slot = byte as c_char;
    }
    field
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
        assert_eq!(
            text((*descriptor).value.sp_keys),
            "73c5da0a|m/352'/1'/0'/0'/0|m/352'/1'/0'/1'/0"
        );
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
                    vendor: fixed("bwk"),
                    model: fixed("bwk-signer"),
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
fn a_model_filling_its_field_keeps_its_terminator() {
    unsafe {
        let model = "0123456789abcdef";
        assert_eq!(model.len(), MODEL_LEN);
        let keys = [extended_key().0];
        let view = response_view(
            MessageType::GetKeys.value(),
            false,
            types::ResponseBody {
                keys: types::Keys {
                    keys: list_view(&keys),
                    fingerprint: [0; 4],
                    vendor: fixed("bwk"),
                    model: fixed(model),
                    version: types::FirmwareVersion {
                        major: 0,
                        minor: 0,
                        patch: 0,
                        flag: 0,
                    },
                    capabilities: 0,
                },
            },
        );
        let response::Body::Keys(body) = encoded(&view).body else {
            panic!("not a keys response")
        };
        assert_eq!(body.model, model);
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
        ];
        let view = response_view(
            MessageType::Signing.value(),
            false,
            types::ResponseBody {
                signed: types::Signed {
                    kind: SignResponseKind::Signatures.value(),
                    value: types::SignedValue {
                        signatures: list_view(&entries),
                    },
                },
            },
        );
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
                    message: fixed::<{ ERROR_MESSAGE_LEN + 1 }>("signing was declined"),
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
        let view = response_view(
            MessageType::Signing.value(),
            false,
            types::ResponseBody {
                signed: types::Signed {
                    kind: SignResponseKind::Signatures.value(),
                    value: types::SignedValue {
                        signatures: list_view(&entries),
                    },
                },
            },
        );
        assert_eq!(encode_failure(&view), Error::UnknownTag.info_owned());
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
        let view = response_view(
            MessageType::Signing.value(),
            false,
            types::ResponseBody {
                signed: types::Signed {
                    kind: SignResponseKind::Signatures.value(),
                    value: types::SignedValue {
                        signatures: list_view(&entries),
                    },
                },
            },
        );
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
fn encode_rejects_an_unterminated_fixed_string() {
    unsafe {
        let view = response_view(
            MessageType::Signing.value(),
            true,
            types::ResponseBody {
                error: types::ErrorBody {
                    error: response::Error::InternalError.value(),
                    message: [0x41; ERROR_MESSAGE_LEN + 1],
                },
            },
        );
        assert_eq!(
            encode_failure(&view),
            Error::UnterminatedFixedString.info_owned()
        );
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
