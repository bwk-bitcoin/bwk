#![cfg(feature = "protocol")]

use bitcoin::{absolute, bip32, transaction, Psbt, Transaction};
use bwk_qr::{
    config::Config,
    decoder::{Decoded, Decoder, Progress},
    encoder::Encoder,
    image::Image,
    protocol::{self, request, response},
};

fn id() -> protocol::RequestId {
    protocol::RequestId([42; protocol::REQUEST_ID_LEN])
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

fn path(path: &str) -> protocol::types::DerivationPath {
    (&path.parse::<bip32::DerivationPath>().unwrap()).into()
}

fn xpub() -> bip32::Xpub {
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        .parse()
        .unwrap()
}

fn bip380() -> request::DescriptorBody {
    request::DescriptorBody::Bip380("wpkh([00000000/84h/1h/0h]xpub/0/*)".to_string())
}

fn bip388() -> request::DescriptorBody {
    request::DescriptorBody::Bip388 {
        keys: vec![
            "[00000000/48h/1h/0h/2h]xpub".to_string(),
            "[11111111/48h/1h/0h/2h]xpub".to_string(),
        ],
        policy: "wsh(sortedmulti(2,@0/**,@1/**))".to_string(),
    }
}

fn encoder() -> Encoder {
    Encoder::new(Config::default()).unwrap()
}

// small parts force a message across several BBQR frames
fn frame_encoder() -> Encoder {
    Encoder::new(Config {
        bbqr_part_bytes: 16,
        ..Config::default()
    })
    .unwrap()
}

fn decoder() -> Decoder {
    Decoder::new(Config::default()).unwrap()
}

fn decode_all(decoder: &mut Decoder, frames: &[Image]) -> Vec<Decoded> {
    let mut decoded = Vec::new();
    for frame in frames {
        decoded.extend(decoder.process(frame).unwrap());
    }
    decoded
}

fn round_trip_request(request: protocol::Request) {
    let frames = encoder().encode_request(&request).unwrap();
    let mut decoder = decoder();
    assert_eq!(
        decode_all(&mut decoder, &frames),
        vec![Decoded::Request(request)]
    );
}

fn round_trip_response(response: protocol::Response) {
    let frames = encoder().encode_response(&response).unwrap();
    let mut decoder = decoder();
    assert_eq!(
        decode_all(&mut decoder, &frames),
        vec![Decoded::Response(response)]
    );
}

fn get_xpubs_request() -> protocol::Request {
    protocol::Request {
        id: id(),
        body: request::Body::GetXpubs(request::GetXpubs {
            derivation_paths: vec![path("m/48'/0'/0'/2'"), path("m/84'/1'/0'")],
        }),
    }
}

fn xpubs_response(capabilities: u32) -> protocol::Response {
    protocol::Response {
        id: id(),
        body: response::Body::Xpubs(response::Xpubs {
            xpubs: vec![(&xpub()).into(), (&xpub()).into()],
            fingerprint: protocol::types::Fingerprint([0xde, 0xad, 0xbe, 0xef]),
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

fn sign_request() -> protocol::Request {
    protocol::Request {
        id: id(),
        body: request::Body::Sign(request::Sign {
            descriptors: vec![request::Descriptor {
                alias: "main".to_string(),
                descriptor: Some(bip380()),
                proof: None,
            }],
            psbt: psbt(),
            want_kind: Some(protocol::SignResponseKind::Psbt),
        }),
    }
}

fn register_descriptor_request(descriptor: Option<request::DescriptorBody>) -> protocol::Request {
    protocol::Request {
        id: id(),
        body: request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: "main".to_string(),
            descriptor,
        }),
    }
}

fn sign_request_frames() -> (protocol::Request, Vec<Image>) {
    let request = sign_request();
    let frames = frame_encoder().encode_request(&request).unwrap();
    assert_eq!(frames.len(), 5);
    (request, frames)
}

fn registration_response(stored: Option<bool>) -> protocol::Response {
    protocol::Response {
        id: id(),
        body: response::Body::Registration(response::Registration {
            descriptor_alias: "main".to_string(),
            registered: Some(true),
            stored,
            proof: Some(vec![0xaa; 32]),
        }),
    }
}

fn error_response(error: response::Error) -> protocol::Response {
    protocol::Response {
        id: id(),
        body: response::Body::Error(response::ErrorBody {
            message_type: protocol::MessageType::Signing,
            error,
            message: "signing was declined".to_string(),
        }),
    }
}

#[test]
fn protocol_request_round_trips_through_bbqr_frames() {
    let (request, frames) = sign_request_frames();
    let mut decoder = decoder();

    let reversed = frames.iter().rev().cloned().collect::<Vec<_>>();
    assert_eq!(
        decode_all(&mut decoder, &reversed),
        vec![Decoded::Request(request)]
    );
    assert_eq!(decoder.progress(), Some(Progress { seen: 5, total: 5 }));
}

#[test]
fn protocol_response_round_trips_through_one_frame() {
    let response = protocol::Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Signatures(vec![
            response::SignatureEntry::TapKey {
                input_index: 3,
                signature: vec![1; 64],
            },
        ])),
    };
    let frames = encoder().encode_response(&response).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        decoder().process(&frames[0]).unwrap(),
        vec![Decoded::Response(response)]
    );
}

#[test]
fn get_xpubs_request_round_trips() {
    round_trip_request(get_xpubs_request());
}

#[test]
fn xpubs_response_round_trips() {
    round_trip_response(xpubs_response(0x0000_000b));
}

#[test]
fn register_descriptor_bip380_request_round_trips() {
    round_trip_request(register_descriptor_request(Some(bip380())));
}

#[test]
fn register_descriptor_bip388_request_round_trips() {
    round_trip_request(register_descriptor_request(Some(bip388())));
}

#[test]
fn register_descriptor_status_query_round_trips() {
    round_trip_request(register_descriptor_request(None));
}

#[test]
fn registration_response_round_trips() {
    round_trip_response(registration_response(Some(true)));
    round_trip_response(registration_response(Some(false)));
    round_trip_response(registration_response(None));
}

#[test]
fn verify_address_request_round_trips() {
    round_trip_request(protocol::Request {
        id: id(),
        body: request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: "main".to_string(),
            derivation_path: path("m/84'/1'/0'/0/7"),
            address: Some("bc1qxyz".to_string()),
            descriptor: Some(bip388()),
            proof: Some(vec![0x5a; 16]),
        }),
    });
}

#[test]
fn address_uri_response_round_trips() {
    round_trip_response(protocol::Response {
        id: id(),
        body: response::Body::AddressUri(response::AddressUri {
            uri: Some("bitcoin:bc1qxyz".to_string()),
        }),
    });
}

#[test]
fn sign_request_round_trips() {
    round_trip_request(sign_request());
}

#[test]
fn signed_psbt_response_round_trips() {
    round_trip_response(protocol::Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Psbt(psbt())),
    });
}

#[test]
fn signed_signatures_response_round_trips() {
    round_trip_response(protocol::Response {
        id: id(),
        body: response::Body::Signed(response::Signed::Signatures(vec![
            response::SignatureEntry::Ecdsa {
                input_index: 0,
                public_key: (&bitcoin::PublicKey::new(xpub().public_key))
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
        ])),
    });
}

#[test]
fn error_response_round_trips() {
    round_trip_response(error_response(response::Error::UserDeclined));
}

#[test]
fn vendor_error_response_round_trips() {
    round_trip_response(error_response(response::Error::Vendor));
}

#[test]
fn frames_in_order_decode() {
    let (request, frames) = sign_request_frames();
    let mut decoder = decoder();
    assert_eq!(
        decode_all(&mut decoder, &frames),
        vec![Decoded::Request(request)]
    );
}

#[test]
fn frames_out_of_order_decode() {
    let (request, frames) = sign_request_frames();
    // even indices first, then odd ones
    let shuffled = (0..frames.len())
        .step_by(2)
        .chain((1..frames.len()).step_by(2))
        .map(|index| frames[index].clone())
        .collect::<Vec<_>>();
    let mut decoder = decoder();
    assert_eq!(
        decode_all(&mut decoder, &shuffled),
        vec![Decoded::Request(request)]
    );
}

#[test]
fn duplicate_frame_is_ignored() {
    let (request, frames) = sign_request_frames();
    let mut decoder = decoder();
    assert_eq!(decoder.process(&frames[0]).unwrap(), vec![]);
    assert_eq!(decoder.process(&frames[0]).unwrap(), vec![]);
    assert_eq!(decoder.progress(), Some(Progress { seen: 1, total: 5 }));
    assert_eq!(
        decode_all(&mut decoder, &frames[1..]),
        vec![Decoded::Request(request)]
    );
}

#[test]
fn progress_reports_seen_and_total() {
    let (_, frames) = sign_request_frames();
    let mut decoder = decoder();
    assert_eq!(decoder.progress(), None);
    for (index, frame) in frames.iter().enumerate() {
        decoder.process(frame).unwrap();
        assert_eq!(
            decoder.progress(),
            Some(Progress {
                seen: index + 1,
                total: 5,
            })
        );
    }
}

#[test]
fn decoder_handles_two_messages_without_reset() {
    let encoder = frame_encoder();
    let request = sign_request();
    let response = xpubs_response(0x0000_000b);
    let request_frames = encoder.encode_request(&request).unwrap();
    let response_frames = encoder.encode_response(&response).unwrap();
    assert_eq!(request_frames.len(), 5);
    assert_eq!(response_frames.len(), 13);

    let mut decoder = decoder();
    assert_eq!(
        decode_all(&mut decoder, &request_frames),
        vec![Decoded::Request(request)]
    );
    assert_eq!(
        decode_all(&mut decoder, &response_frames),
        vec![Decoded::Response(response)]
    );
}
