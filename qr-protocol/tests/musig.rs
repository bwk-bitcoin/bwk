use bwk_qr_protocol::{
    decode, encode, encode_request, encode_response, musig, reader, request, response,
    types::{Fingerprint, PublicKey},
    Message, MessageType, Request, RequestId, Response, MAX_BYTES, MAX_MUSIG_DERIVATIONS,
    MAX_MUSIG_INPUTS, MAX_VEC,
};

const ID: RequestId = RequestId([0x12, 0x34]);
const SESSION: [u8; 32] = [0x51; 32];
const ATTEMPT: [u8; 32] = [0xa7; 32];

fn preparation() -> request::PrepareMusig {
    request::PrepareMusig {
        descriptor: request::Descriptor {
            alias: "policy".into(),
            descriptor: Some(request::DescriptorBody::Bip388 {
                keys: vec!["key0".into(), "key1".into()],
                policy: "tr(musig(@0/**,@1/**))".into(),
            }),
            proof: Some(vec![0x70, 0x71]),
        },
        session_id: SESSION,
        max_inputs: 2,
        derivations: vec![
            request::MusigDerivation {
                keychain: 0,
                index: 17,
            },
            request::MusigDerivation {
                keychain: 1,
                index: 0x7fff_ffff,
            },
        ],
    }
}

fn prepared() -> response::MusigPrepared {
    let mut nonces = Vec::new();
    for derivation in preparation().derivations {
        for input_index in 0..2 {
            for expression_index in 0..2 {
                nonces.push(response::MusigNonce {
                    derivation,
                    input_index,
                    expression_index,
                    participant: PublicKey([0x02; 33]),
                    aggregate: PublicKey([0x03; 33]),
                    leaf_hash: (expression_index == 1).then_some([0x44; 32]),
                    nonce: [0x60 + input_index as u8 + expression_index as u8; 66],
                });
            }
        }
    }
    response::MusigPrepared {
        session_id: SESSION,
        max_inputs: 2,
        nonces,
    }
}

fn request(body: request::Body) -> Request {
    Request { id: ID, body }
}

fn response(body: response::Body) -> Response {
    Response { id: ID, body }
}

// Build malformed bodies independently of the validating encoder.
fn raw_preparation(body: &request::PrepareMusig) -> Vec<u8> {
    let ordinary = encode_request(&request(request::Body::Sign(request::Sign {
        descriptors: vec![body.descriptor.clone()],
        psbt: vec![],
        want_kind: None,
    })))
    .unwrap();
    let mut bytes = b"BIPXXX\x01\x05\x12\x34".to_vec();
    bytes.extend_from_slice(&ordinary[11..ordinary.len() - 2]);
    bytes.extend_from_slice(&body.session_id);
    bytes.push(body.max_inputs);
    compact(&mut bytes, body.derivations.len());
    for derivation in &body.derivations {
        bytes.extend_from_slice(&derivation.keychain.to_be_bytes());
        bytes.extend_from_slice(&derivation.index.to_be_bytes());
    }
    bytes
}

fn raw_prepared(body: &response::MusigPrepared) -> Vec<u8> {
    let mut bytes = b"BIPXXX\x01\x85\x12\x34".to_vec();
    bytes.extend_from_slice(&body.session_id);
    bytes.push(body.max_inputs);
    compact(&mut bytes, body.nonces.len());
    for nonce in &body.nonces {
        bytes.extend_from_slice(&nonce.derivation.keychain.to_be_bytes());
        bytes.extend_from_slice(&nonce.derivation.index.to_be_bytes());
        bytes.extend_from_slice(&nonce.input_index.to_be_bytes());
        bytes.extend_from_slice(&nonce.expression_index.to_be_bytes());
        bytes.extend_from_slice(&nonce.participant.0);
        bytes.extend_from_slice(&nonce.aggregate.0);
        bytes.push(u8::from(nonce.leaf_hash.is_some()));
        if let Some(hash) = nonce.leaf_hash {
            bytes.extend_from_slice(&hash);
        }
        bytes.extend_from_slice(&nonce.nonce);
    }
    bytes
}

fn compact(bytes: &mut Vec<u8>, count: usize) {
    match count {
        0..=0xfc => bytes.push(count as u8),
        _ => {
            bytes.push(0xfd);
            bytes.extend_from_slice(&(count as u16).to_le_bytes());
        }
    }
}

fn reject_preparation(body: request::PrepareMusig, error: musig::Error) {
    assert_eq!(
        decode(&raw_preparation(&body)),
        Err(decode::Error::Musig(error))
    );
    assert_eq!(
        encode_request(&request(request::Body::PrepareMusig(body))),
        Err(encode::Error::Musig(error))
    );
}

fn reject_prepared(body: response::MusigPrepared, error: musig::Error) {
    assert_eq!(
        decode(&raw_prepared(&body)),
        Err(decode::Error::Musig(error))
    );
    assert_eq!(
        encode_response(&response(response::Body::MusigPrepared(body))),
        Err(encode::Error::Musig(error))
    );
}

#[test]
fn all_cached_messages_round_trip_every_field() {
    let body = preparation();
    let request = request(request::Body::PrepareMusig(body.clone()));
    let bytes = encode_request(&request).unwrap();
    assert_eq!(bytes, raw_preparation(&body));
    assert_eq!(bytes[6..10], [1, 0x05, 0x12, 0x34]);
    assert_eq!(decode(&bytes).unwrap(), Message::Request(request));

    let body = prepared();
    let response = response(response::Body::MusigPrepared(body.clone()));
    let bytes = encode_response(&response).unwrap();
    assert_eq!(bytes, raw_prepared(&body));
    assert_eq!(bytes[6..10], [1, 0x85, 0x12, 0x34]);
    assert_eq!(decode(&bytes).unwrap(), Message::Response(response));
}

#[test]
fn signing_ids_and_opaque_psbt_have_exact_layout() {
    let psbt = vec![0x70, 0x73, 0x62, 0x74, 0xff];
    let request = request(request::Body::SignMusig(request::SignMusig {
        session_id: SESSION,
        attempt_id: ATTEMPT,
        psbt: psbt.clone(),
    }));
    let response = response(response::Body::MusigSigned(response::MusigSigned {
        session_id: SESSION,
        attempt_id: ATTEMPT,
        psbt,
    }));
    let mut expected = b"BIPXXX\x01\x06\x12\x34".to_vec();
    expected.extend_from_slice(&SESSION);
    expected.extend_from_slice(&ATTEMPT);
    expected.extend_from_slice(b"\x05psbt\xff");
    assert_eq!(encode_request(&request).unwrap(), expected);
    assert_eq!(decode(&expected).unwrap(), Message::Request(request));
    expected[7] = 0x86;
    assert_eq!(encode_response(&response).unwrap(), expected);
    assert_eq!(decode(&expected).unwrap(), Message::Response(response));
}

#[test]
fn preparation_rejects_invalid_coverage_and_derivations_in_both_directions() {
    for max_inputs in [0, MAX_MUSIG_INPUTS + 1, u8::MAX] {
        let mut body = preparation();
        body.max_inputs = max_inputs;
        reject_preparation(body, musig::Error::InputCoverage);
    }
    for count in [0, MAX_MUSIG_DERIVATIONS + 1] {
        let mut body = preparation();
        body.derivations = (0..count)
            .map(|index| request::MusigDerivation {
                keychain: 0,
                index: index as u32,
            })
            .collect();
        reject_preparation(body, musig::Error::DerivationCount);
    }
    let mut body = preparation();
    body.derivations[1] = body.derivations[0];
    reject_preparation(body, musig::Error::DuplicateDerivation);
    for index in [0x8000_0000, u32::MAX] {
        let mut body = preparation();
        body.derivations[0].index = index;
        reject_preparation(body, musig::Error::HardenedIndex);
    }
    let mut body = preparation();
    body.descriptor.descriptor = None;
    reject_preparation(body, musig::Error::MissingDescriptor);
}

#[test]
fn preparation_accepts_both_limit_boundaries() {
    for max_inputs in [1, MAX_MUSIG_INPUTS] {
        for count in [1, MAX_MUSIG_DERIVATIONS] {
            let mut body = preparation();
            body.max_inputs = max_inputs;
            body.derivations = (0..count)
                .map(|keychain| request::MusigDerivation {
                    keychain: keychain as u32,
                    index: 0x7fff_ffff,
                })
                .collect();
            let request = request(request::Body::PrepareMusig(body));
            assert_eq!(
                decode(&encode_request(&request).unwrap()).unwrap(),
                Message::Request(request)
            );
        }
    }
}

#[test]
fn preparation_response_rejects_invalid_nonces_in_both_directions() {
    for max_inputs in [0, MAX_MUSIG_INPUTS + 1, u8::MAX] {
        let mut body = prepared();
        body.max_inputs = max_inputs;
        reject_prepared(body, musig::Error::InputCoverage);
    }
    for count in [0, MAX_VEC + 1] {
        let mut body = prepared();
        body.nonces = vec![body.nonces[0].clone(); count];
        reject_prepared(body, musig::Error::NonceCount);
    }
    for input_index in [2, u32::MAX] {
        let mut body = prepared();
        body.nonces[0].input_index = input_index;
        reject_prepared(body, musig::Error::NonceInputIndex);
    }
    let mut body = prepared();
    body.nonces[0].derivation.index = 0x8000_0000;
    reject_prepared(body, musig::Error::HardenedIndex);
    let mut body = prepared();
    let mut duplicate = body.nonces[0].clone();
    duplicate.nonce = [0xee; 66];
    body.nonces.push(duplicate);
    reject_prepared(body, musig::Error::DuplicateNonce);
    let mut body = prepared();
    body.nonces.retain(|nonce| nonce.input_index == 0);
    reject_prepared(body, musig::Error::MissingInput);
}

#[test]
fn nonce_attribution_includes_every_field_but_not_nonce_bytes() {
    let mut body = prepared();
    body.max_inputs = 1;
    body.nonces.truncate(1);
    let base = body.nonces[0].clone();
    let mut variants = vec![base.clone(); 6];
    variants[0].derivation.keychain += 1;
    variants[1].derivation.index += 1;
    variants[2].expression_index += 1;
    variants[3].participant.0[1] += 1;
    variants[4].aggregate.0[1] += 1;
    variants[5].leaf_hash = Some([0x55; 32]);
    body.nonces.extend(variants);
    let response = response(response::Body::MusigPrepared(body));
    assert_eq!(
        decode(&encode_response(&response).unwrap()).unwrap(),
        Message::Response(response)
    );
}

#[test]
fn nonce_count_accepts_max_vec_with_full_input_coverage() {
    let mut body = prepared();
    body.max_inputs = MAX_MUSIG_INPUTS;
    let base = body.nonces[0].clone();
    body.nonces = (0..MAX_VEC)
        .map(|index| response::MusigNonce {
            input_index: index as u32 % u32::from(MAX_MUSIG_INPUTS),
            expression_index: index as u32,
            ..base.clone()
        })
        .collect();
    let response = response(response::Body::MusigPrepared(body));
    assert_eq!(
        decode(&encode_response(&response).unwrap()).unwrap(),
        Message::Response(response)
    );
}

#[test]
fn signing_psbt_limits_apply_to_both_directions() {
    for count in [0, MAX_BYTES] {
        let request = request(request::Body::SignMusig(request::SignMusig {
            session_id: SESSION,
            attempt_id: ATTEMPT,
            psbt: vec![0x42; count],
        }));
        let response = response(response::Body::MusigSigned(response::MusigSigned {
            session_id: SESSION,
            attempt_id: ATTEMPT,
            psbt: vec![0x43; count],
        }));
        assert_eq!(
            decode(&encode_request(&request).unwrap()).unwrap(),
            Message::Request(request)
        );
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
    let request = request(request::Body::SignMusig(request::SignMusig {
        session_id: SESSION,
        attempt_id: ATTEMPT,
        psbt: vec![0; MAX_BYTES + 1],
    }));
    let response = response(response::Body::MusigSigned(response::MusigSigned {
        session_id: SESSION,
        attempt_id: ATTEMPT,
        psbt: vec![0; MAX_BYTES + 1],
    }));
    assert_eq!(
        encode_request(&request),
        Err(encode::Error::BytesTooLarge(MAX_BYTES + 1))
    );
    assert_eq!(
        encode_response(&response),
        Err(encode::Error::BytesTooLarge(MAX_BYTES + 1))
    );
    for code in [0x06, 0x86] {
        let mut bytes = b"BIPXXX\x01\x06\x12\x34".to_vec();
        bytes[7] = code;
        bytes.extend_from_slice(&SESSION);
        bytes.extend_from_slice(&ATTEMPT);
        bytes.push(0xfe);
        bytes.extend_from_slice(&((MAX_BYTES + 1) as u32).to_le_bytes());
        assert_eq!(
            decode(&bytes),
            Err(decode::Error::Read(reader::Error::BytesTooLarge(
                MAX_BYTES + 1
            )))
        );
    }
}

#[test]
fn cache_capability_is_separate_and_encodes() {
    assert_eq!(response::Capabilities::MUSIG_CACHE, 0x10);
    assert!(!response::Capabilities(1 << 3).supports_musig_cache());
    for mask in [0x10, 0x1f] {
        assert!(response::Capabilities(mask).supports_musig_cache());
        let response = response(response::Body::Keys(response::Keys {
            keys: vec![],
            fingerprint: Fingerprint([1, 2, 3, 4]),
            vendor: "bwk".into(),
            model: "signer".into(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 0,
                patch: 0,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(mask),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

// The old dispatch accepts only these four types, before reading any body.
fn old_message_type(bytes: &[u8]) -> Result<u8, decode::Error> {
    match bytes[7] & 0x3f {
        code @ 0x01..=0x04 => Ok(code),
        code => Err(decode::Error::UnknownMessageType(code)),
    }
}

#[test]
fn old_dispatch_rejects_cached_operations_even_with_a_newer_version() {
    let messages = [
        encode_request(&request(request::Body::PrepareMusig(preparation()))).unwrap(),
        encode_request(&request(request::Body::SignMusig(request::SignMusig {
            session_id: SESSION,
            attempt_id: ATTEMPT,
            psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
        })))
        .unwrap(),
        encode_response(&response(response::Body::MusigPrepared(prepared()))).unwrap(),
        encode_response(&response(response::Body::MusigSigned(
            response::MusigSigned {
                session_id: SESSION,
                attempt_id: ATTEMPT,
                psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
            },
        )))
        .unwrap(),
    ];
    for message in messages {
        for version in [1, 2, u8::MAX] {
            let mut bytes = message.clone();
            bytes[6] = version;
            assert_eq!(
                old_message_type(&bytes),
                Err(decode::Error::UnknownMessageType(bytes[7] & 0x3f))
            );
            assert!(decode(&bytes).is_ok());
        }
        for end in 0..message.len() {
            assert!(
                decode(&message[..end]).is_err(),
                "accepted truncation at {end}"
            );
        }
    }
    assert_eq!(MessageType::MusigPreparation.value(), 0x05);
    assert_eq!(MessageType::MusigSigning.value(), 0x06);
    assert_eq!(MessageType::Signing.value(), 0x04);
}

#[test]
fn ordinary_signing_still_ignores_newer_fields_so_cache_requires_new_codes() {
    let ordinary = request(request::Body::Sign(request::Sign {
        descriptors: vec![],
        psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
        want_kind: None,
    }));
    let mut bytes = encode_request(&ordinary).unwrap();
    assert_eq!(old_message_type(&bytes), Ok(0x04));
    bytes[6] = 2;
    bytes.extend_from_slice(&SESSION);
    bytes.extend_from_slice(&ATTEMPT);
    assert_eq!(decode(&bytes).unwrap(), Message::Request(ordinary));
    for code in [0x07, 0x87, 0xc7] {
        bytes[7] = code;
        assert_eq!(decode(&bytes), Err(decode::Error::UnknownMessageType(0x07)));
    }
}

#[test]
fn cached_nonce_rejects_invalid_leaf_presence() {
    let mut body = prepared();
    body.max_inputs = 1;
    body.nonces.truncate(1);
    let mut bytes = raw_prepared(&body);
    // Header, session, coverage, count, derivation, input, expression and two keys.
    bytes[10 + 32 + 1 + 1 + 8 + 4 + 4 + 33 + 33] = 2;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidPresence(2)))
    );
}

#[test]
fn cached_errors_keep_operation_and_request_attribution() {
    for message_type in [MessageType::MusigPreparation, MessageType::MusigSigning] {
        let response = response(response::Body::Error(response::ErrorBody {
            message_type,
            error: response::Error::MusigSession,
            message: "session refused".into(),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

#[test]
fn musig_validation_errors_have_distinct_codes() {
    let errors = [
        musig::Error::InputCoverage,
        musig::Error::DerivationCount,
        musig::Error::DuplicateDerivation,
        musig::Error::HardenedIndex,
        musig::Error::MissingDescriptor,
        musig::Error::NonceCount,
        musig::Error::NonceInputIndex,
        musig::Error::DuplicateNonce,
        musig::Error::MissingInput,
    ];
    for (error, code) in errors.into_iter().zip(500..=508) {
        assert_eq!(error.info().code, code);
        assert_eq!(encode::Error::Musig(error).info(), error.info());
        assert_eq!(decode::Error::Musig(error).info(), error.info());
        assert!(error.info().message.ends_with('\0'));
    }
}
