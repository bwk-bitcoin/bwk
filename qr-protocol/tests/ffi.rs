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
    request, response,
    types::{DerivationPath, Fingerprint, PublicKey, Xpub},
    ErrorInfo, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    ERROR_MESSAGE_LEN, MODEL_LEN, REQUEST_ID_LEN,
};

use common::{bip380, bip388};

const ID: [u8; REQUEST_ID_LEN] = [42; REQUEST_ID_LEN];

fn id() -> RequestId {
    RequestId(ID)
}

fn path() -> DerivationPath {
    DerivationPath(vec![0x8000_0030, 0x8000_0000, 7])
}

fn xpub() -> Xpub {
    Xpub([0xab; 78])
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
fn get_xpubs_request_view() {
    unsafe {
        let request = request(request::Body::GetXpubs(request::GetXpubs {
            derivation_paths: vec![path(), DerivationPath(vec![])],
        }));
        let view = view(&request);
        assert_eq!((*view).id, ID);
        assert_eq!((*view).message_type, MessageType::GetXpubs.value());

        let paths = (*view).body.get_xpubs.derivation_paths.as_slice();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].as_slice(), &[0x8000_0030, 0x8000_0000, 7]);
        assert_eq!(paths[1].len, 0);
        bwk_qr_request_free(view);
    }
}

#[test]
fn get_sp_descriptor_request_view() {
    unsafe {
        let request = request(request::Body::GetSpDescriptor(request::GetSpDescriptor {}));
        let view = view(&request);
        assert_eq!((*view).id, ID);
        assert_eq!((*view).message_type, MessageType::GetSpDescriptor.value());
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
fn xpubs_response_encodes() {
    unsafe {
        let xpubs = [[0xab; 78], [0xcd; 78]];
        let view = response_view(
            MessageType::GetXpubs.value(),
            false,
            types::ResponseBody {
                xpubs: types::Xpubs {
                    xpubs: list_view(&xpubs),
                    fingerprint: [0xde, 0xad, 0xbe, 0xef],
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
                body: response::Body::Xpubs(response::Xpubs {
                    xpubs: vec![Xpub([0xab; 78]), Xpub([0xcd; 78])],
                    fingerprint: Fingerprint([0xde, 0xad, 0xbe, 0xef]),
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
fn sp_descriptor_response_encodes() {
    unsafe {
        let descriptor = CString::new("sp(scan,spend)").unwrap();
        let view = response_view(
            MessageType::GetSpDescriptor.value(),
            false,
            types::ResponseBody {
                sp_descriptor: types::SpDescriptor {
                    descriptor: descriptor.as_ptr(),
                },
            },
        );
        assert_eq!(
            encoded(&view),
            Response {
                id: id(),
                body: response::Body::SpDescriptor(response::SpDescriptor {
                    descriptor: "sp(scan,spend)".to_string(),
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
        let xpubs = [xpub().0];
        let view = response_view(
            MessageType::GetXpubs.value(),
            false,
            types::ResponseBody {
                xpubs: types::Xpubs {
                    xpubs: list_view(&xpubs),
                    fingerprint: [0; 4],
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
        let response::Body::Xpubs(body) = encoded(&view).body else {
            panic!("not an xpubs response")
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
        let bytes = encode_request(&request(request::Body::GetXpubs(request::GetXpubs {
            derivation_paths: vec![path()],
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
