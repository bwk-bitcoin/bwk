#![cfg(feature = "protocol")]

use bitcoin::{absolute, transaction, Psbt, Transaction};
use bwk_qr::{
    config::Config,
    decoder::{Decoded, Decoder},
    encoder::Encoder,
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

#[test]
fn protocol_request_round_trips_through_bbqr_frames() {
    let request = protocol::Request {
        id: id(),
        body: request::Body::Sign(request::Sign {
            descriptors: vec![request::Descriptor {
                alias: "main".to_string(),
                descriptor: Some(request::DescriptorBody::Bip380(
                    "wpkh([00000000/84h/1h/0h]xpub/0/*)".to_string(),
                )),
                proof: None,
            }],
            psbt: psbt(),
            want_kind: Some(protocol::SignResponseKind::Psbt),
        }),
    };
    let encoder = Encoder::new(Config {
        bbqr_part_bytes: 16,
        ..Config::default()
    })
    .unwrap();
    let mut decoder = Decoder::new(Config::default()).unwrap();
    let frames = encoder.encode_request(&request).unwrap();
    assert!(frames.len() > 1);

    let mut seen = Vec::new();
    for frame in frames.iter().rev() {
        seen.extend(decoder.process(frame).unwrap());
    }
    assert_eq!(
        decoder.progress().unwrap().seen,
        decoder.progress().unwrap().total
    );
    assert_eq!(seen, vec![Decoded::Request(request)]);
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
    let encoder = Encoder::new(Config::default()).unwrap();
    let mut decoder = Decoder::new(Config::default()).unwrap();
    let frames = encoder.encode_response(&response).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        decoder.process(&frames[0]).unwrap(),
        vec![Decoded::Response(response)]
    );
}
