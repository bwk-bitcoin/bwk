use bwk_qr_protocol::{
    decode, encode, encode_request, encode_response, nonce_cache, reader, request, response,
    types::{DerivationPath, Fingerprint},
    Message, MessageType, Request, RequestId, Response, MAX_NONCE_EXPRESSIONS,
};

const ID: RequestId = RequestId([0x12, 0x34]);
const SESSION: [u8; 4] = [0x51; 4];
const SESSION_REF: [u8; 4] = [0x52; 4];

fn preparation() -> request::PrepareNonces {
    request::PrepareNonces {
        session_id: SESSION,
        session_ref: None,
        max_inputs: 2,
        derivation_path: DerivationPath(vec![0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 3]),
        start: 4,
        end: 5,
    }
}

fn nonces(count: usize) -> Vec<[u8; 66]> {
    (0..count).map(|index| [index as u8; 66]).collect()
}

fn prepared() -> response::NoncesPrepared {
    response::NoncesPrepared {
        session_id: SESSION,
        session_ref: SESSION_REF,
        max_inputs: 2,
        start: 4,
        end: 5,
        nonces: nonces(4),
    }
}

fn request(body: request::Body) -> Request {
    Request { id: ID, body }
}

fn response(body: response::Body) -> Response {
    Response { id: ID, body }
}

// Build malformed bodies independently of the validating encoder.
fn raw_preparation(body: &request::PrepareNonces) -> Vec<u8> {
    let mut bytes = b"BIPXXX\x01\x08\x12\x34".to_vec();
    bytes.extend_from_slice(&body.session_id);
    match body.session_ref {
        Some(session_ref) => {
            bytes.push(1);
            bytes.extend_from_slice(&session_ref);
        }
        None => bytes.push(0),
    }
    bytes.push(body.max_inputs);
    bytes.push(body.derivation_path.0.len() as u8);
    for child in &body.derivation_path.0 {
        bytes.extend_from_slice(&child.to_be_bytes());
    }
    bytes.extend_from_slice(&body.start.to_be_bytes());
    bytes.extend_from_slice(&body.end.to_be_bytes());
    bytes
}

fn raw_prepared_header(max_inputs: u8, start: u32, end: u32, count: usize) -> Vec<u8> {
    let mut bytes = b"BIPXXX\x01\x88\x12\x34".to_vec();
    bytes.extend_from_slice(&SESSION);
    bytes.extend_from_slice(&SESSION_REF);
    bytes.push(max_inputs);
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    compact(&mut bytes, count);
    bytes
}

fn raw_prepared(body: &response::NoncesPrepared) -> Vec<u8> {
    let mut bytes = raw_prepared_header(body.max_inputs, body.start, body.end, body.nonces.len());
    for nonce in &body.nonces {
        bytes.extend_from_slice(nonce);
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

fn reject_preparation(body: request::PrepareNonces, error: nonce_cache::Error) {
    assert_eq!(
        decode(&raw_preparation(&body)),
        Err(decode::Error::NonceCache(error))
    );
    assert_eq!(
        encode_request(&request(request::Body::PrepareNonces(body))),
        Err(encode::Error::NonceCache(error))
    );
}

fn reject_prepared(body: response::NoncesPrepared, error: nonce_cache::Error) {
    assert_eq!(
        decode(&raw_prepared(&body)),
        Err(decode::Error::NonceCache(error))
    );
    assert_eq!(
        encode_response(&response(response::Body::NoncesPrepared(body))),
        Err(encode::Error::NonceCache(error))
    );
}

#[test]
fn preparation_messages_round_trip_every_field() {
    for session_ref in [None, Some(SESSION_REF)] {
        let mut body = preparation();
        body.session_ref = session_ref;
        let request = request(request::Body::PrepareNonces(body.clone()));
        let bytes = encode_request(&request).unwrap();
        assert_eq!(bytes, raw_preparation(&body));
        assert_eq!(bytes[6..10], [1, 0x08, 0x12, 0x34]);
        assert_eq!(decode(&bytes).unwrap(), Message::Request(request));
    }

    let body = prepared();
    let response = response(response::Body::NoncesPrepared(body.clone()));
    let bytes = encode_response(&response).unwrap();
    assert_eq!(bytes, raw_prepared(&body));
    assert_eq!(bytes[6..10], [1, 0x88, 0x12, 0x34]);
    assert_eq!(decode(&bytes).unwrap(), Message::Response(response));
}

#[test]
fn preparation_rejects_an_invalid_session_ref_presence() {
    let mut bytes = raw_preparation(&preparation());
    bytes[10 + SESSION.len()] = 0x02;
    assert_eq!(
        decode(&bytes),
        Err(decode::Error::Read(reader::Error::InvalidPresence(0x02)))
    );
}

#[test]
fn preparation_accepts_the_bounds() {
    let last = MAX_NONCE_EXPRESSIONS as u32 - 1;
    for (max_inputs, start, end) in [
        (1, 0, 0),
        (1, u32::MAX, u32::MAX),
        (u8::MAX, 0, last),
        (u8::MAX, u32::MAX - last, u32::MAX),
    ] {
        let mut body = preparation();
        body.max_inputs = max_inputs;
        body.start = start;
        body.end = end;
        let request = request(request::Body::PrepareNonces(body));
        assert_eq!(
            decode(&encode_request(&request).unwrap()).unwrap(),
            Message::Request(request)
        );

        let count = (end - start + 1) as usize * usize::from(max_inputs);
        let response = response(response::Body::NoncesPrepared(response::NoncesPrepared {
            session_id: SESSION,
            session_ref: SESSION_REF,
            max_inputs,
            start,
            end,
            nonces: nonces(count),
        }));
        assert_eq!(
            decode(&encode_response(&response).unwrap()).unwrap(),
            Message::Response(response)
        );
    }
}

#[test]
fn preparation_rejects_invalid_coverage_and_range_in_both_directions() {
    let mut body = preparation();
    body.max_inputs = 0;
    reject_preparation(body, nonce_cache::Error::InputCoverage);

    let mut body = preparation();
    body.start = 6;
    reject_preparation(body, nonce_cache::Error::ExpressionRange);

    let mut body = preparation();
    body.start = 0;
    body.end = MAX_NONCE_EXPRESSIONS as u32;
    reject_preparation(body, nonce_cache::Error::ExpressionRange);

    let mut body = preparation();
    body.start = 0;
    body.end = u32::MAX;
    reject_preparation(body, nonce_cache::Error::ExpressionRange);
}

#[test]
fn preparation_response_rejects_invalid_nonces_in_both_directions() {
    let mut body = prepared();
    body.max_inputs = 0;
    reject_prepared(body, nonce_cache::Error::InputCoverage);

    let mut body = prepared();
    body.start = 6;
    reject_prepared(body, nonce_cache::Error::ExpressionRange);

    let mut body = prepared();
    body.start = 0;
    body.end = MAX_NONCE_EXPRESSIONS as u32;
    body.nonces = nonces((MAX_NONCE_EXPRESSIONS + 1) * 2);
    reject_prepared(body, nonce_cache::Error::ExpressionRange);

    for count in [0, 3, 5, 8] {
        let mut body = prepared();
        body.nonces = nonces(count);
        reject_prepared(body, nonce_cache::Error::NonceCount);
    }
}

#[test]
fn decode_rejects_a_wrong_nonce_count_before_reading_entries() {
    for count in [3, 5, MAX_NONCE_EXPRESSIONS * 255 + 1] {
        assert_eq!(
            decode(&raw_prepared_header(2, 4, 5, count)),
            Err(decode::Error::NonceCache(nonce_cache::Error::NonceCount))
        );
    }
}

#[test]
fn nonce_cache_capability_is_separate_and_encodes() {
    assert_eq!(response::Capabilities::NONCE_CACHE, 0x20);
    assert!(!response::Capabilities(0x1f).supports_nonce_cache());
    for mask in [0x20, 0x3f] {
        assert!(response::Capabilities(mask).supports_nonce_cache());
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

// The old dispatch accepts only these seven types, before reading any body.
fn old_message_type(bytes: &[u8]) -> Result<u8, decode::Error> {
    match bytes[7] & 0x3f {
        code @ 0x01..=0x07 => Ok(code),
        code => Err(decode::Error::UnknownMessageType(code)),
    }
}

#[test]
fn old_dispatch_rejects_preparation_even_with_a_newer_version() {
    let messages = [
        encode_request(&request(request::Body::PrepareNonces(preparation()))).unwrap(),
        encode_response(&response(response::Body::NoncesPrepared(prepared()))).unwrap(),
    ];
    for message in messages {
        for version in [1, 2, u8::MAX] {
            let mut bytes = message.clone();
            bytes[6] = version;
            assert_eq!(
                old_message_type(&bytes),
                Err(decode::Error::UnknownMessageType(0x08))
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
    assert_eq!(MessageType::NoncePreparation.value(), 0x08);
}

#[test]
fn nonce_cache_session_refusal_is_the_session_error() {
    assert_eq!(u8::from(response::Error::MusigSession), 0x0d);
    for message_type in [MessageType::NoncePreparation, MessageType::Signing] {
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
fn nonce_cache_validation_errors_have_distinct_codes() {
    let errors = [
        (nonce_cache::Error::InputCoverage, 900),
        (nonce_cache::Error::ExpressionRange, 901),
        (nonce_cache::Error::NonceCount, 902),
    ];
    for (error, code) in errors {
        assert_eq!(error.info().code, code);
        assert_eq!(encode::Error::NonceCache(error).info(), error.info());
        assert_eq!(decode::Error::NonceCache(error).info(), error.info());
        assert!(error.info().message.ends_with('\0'));
    }
}
