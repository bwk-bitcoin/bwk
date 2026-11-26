#![cfg(feature = "bbqr")]

mod common;

use bwk_bbqr::Encoding;
use bwk_qr::{
    config::QrSize,
    decoder::{Decoded, Decoder},
    encoder::Encoder,
    image::Image,
};
use common::noise;

const ENCODINGS: [Encoding; 3] = [Encoding::Hex, Encoding::Base32, Encoding::Zlib];

// a small size forces a payload across several BBQR frames
fn frame_encoder() -> Encoder {
    Encoder::new(QrSize::S29)
}

fn payload() -> Vec<u8> {
    payload_of(100)
}

fn payload_of(len: usize) -> Vec<u8> {
    (0..=255u8).cycle().take(len).collect()
}

/// A payload that compresses: records that share most of their bytes.
fn records(count: u8) -> Vec<u8> {
    (0..count)
        .flat_map(|index| [b"record ".as_slice(), &[index], &[0xab; 24]].concat())
        .collect()
}

fn decode_raw(decoder: &mut Decoder, frames: &[Image]) -> Vec<Decoded> {
    frames
        .iter()
        .filter_map(|frame| decoder.process_raw(frame).unwrap())
        .collect()
}

#[test]
fn raw_payload_round_trips_through_bbqr_frames() {
    let frames = frame_encoder().encode_bbqr(&payload()).unwrap();
    assert!(
        frames.len() > 1,
        "expected several frames, got {}",
        frames.len()
    );

    let mut decoder = Decoder::new();
    assert_eq!(
        decode_raw(&mut decoder, &frames),
        vec![Decoded::Bytes(payload())]
    );
}

#[test]
fn raw_payload_is_only_returned_once_every_part_is_seen() {
    let frames = frame_encoder().encode_bbqr(&payload()).unwrap();
    let (last, first) = frames.split_last().unwrap();

    let mut decoder = Decoder::new();
    assert_eq!(decode_raw(&mut decoder, first), vec![]);
    let progress = decoder.progress().unwrap();
    assert_eq!(progress.seen(), first.len());
    assert_eq!(progress.total(), frames.len());
    assert_eq!(
        decoder.process_raw(last).unwrap(),
        Some(Decoded::Bytes(payload()))
    );
}

#[test]
fn every_encoding_round_trips_through_bbqr_frames() {
    let payloads = [vec![7], payload(), noise(300), records(40)];
    for encoding in ENCODINGS {
        let encoder = frame_encoder().with_bbqr_encoding(encoding);
        for payload in &payloads {
            let case = format!("{} bytes in {encoding:?}", payload.len());
            let frames = encoder.encode_bbqr(payload).unwrap();
            let mut decoder = Decoder::new();
            assert_eq!(
                decode_raw(&mut decoder, &frames),
                vec![Decoded::Bytes(payload.clone())],
                "{case}"
            );
            assert_eq!(decoder.progress().unwrap().total(), frames.len(), "{case}");
        }
    }
}

// in base32 a frame carries a quarter more than in hex, and zlib shrinks the payload
// first
#[test]
fn a_denser_encoding_takes_fewer_frames() {
    let frames = |encoding, payload: &[u8]| {
        let encoder = frame_encoder().with_bbqr_encoding(encoding);
        encoder.encode_bbqr(payload).unwrap().len()
    };
    let payload = records(40);
    let hex = frames(Encoding::Hex, &payload);
    let base32 = frames(Encoding::Base32, &payload);
    let zlib = frames(Encoding::Zlib, &payload);
    assert!(base32 < hex, "{base32} frames in base32, {hex} in hex");
    assert!(zlib < base32, "{zlib} frames in zlib, {base32} in base32");
}

#[test]
fn a_payload_is_compressed_unless_told_otherwise() {
    let payload = records(40);
    let zlib = frame_encoder().with_bbqr_encoding(Encoding::Zlib);
    assert_eq!(
        frame_encoder().encode_bbqr(&payload).unwrap(),
        zlib.encode_bbqr(&payload).unwrap()
    );
}

// a payload that compression does not shrink goes out in base32
#[test]
fn zlib_takes_the_frames_of_base32_for_noise() {
    let payload = noise(300);
    let zlib = frame_encoder().with_bbqr_encoding(Encoding::Zlib);
    let base32 = frame_encoder().with_bbqr_encoding(Encoding::Base32);
    assert_eq!(
        zlib.encode_bbqr(&payload).unwrap(),
        base32.encode_bbqr(&payload).unwrap()
    );
}

// parts that do not fill the encoder's size: the series renders smaller, and a frame
// with room left at a higher error correction level
#[test]
fn a_series_smaller_than_the_encoder_size_round_trips() {
    let encoder = Encoder::new(QrSize::S53).with_bbqr_encoding(Encoding::Hex);
    let full = encoder
        .encode_bbqr(&payload_of(QrSize::S53.bbqr_part_bytes(Encoding::Hex)))
        .unwrap()[0]
        .side();
    for len in [1, 40, 164, 500] {
        let frames = encoder.encode_bbqr(&payload_of(len)).unwrap();
        assert!(
            frames.iter().all(|frame| frame.side() < full),
            "{len} bytes"
        );

        let mut decoder = Decoder::new();
        assert_eq!(
            decode_raw(&mut decoder, &frames),
            vec![Decoded::Bytes(payload_of(len))],
            "{len} bytes"
        );
    }
}

#[test]
fn raw_decode_keeps_plain_codes_as_text() {
    let image = frame_encoder().encode_text("plain").unwrap();
    let mut decoder = Decoder::new();
    assert_eq!(
        decoder.process_raw(&image).unwrap(),
        Some(Decoded::Text("plain".to_string()))
    );
}

#[cfg(feature = "protocol")]
#[test]
fn protocol_payload_stays_undecoded_on_the_raw_path() {
    use bipqr::ll::{self as protocol, request, types::DerivationPath};

    let request = protocol::Request {
        id: protocol::RequestId([7; protocol::REQUEST_ID_LEN]),
        body: request::Body::GetKeys(request::GetKeys {
            keys: vec![request::KeyRequest {
                derivation_path: DerivationPath(vec![0x8000_0054, 0x8000_0001, 0x8000_0000]),
                kind: request::KeyKind::Public,
            }],
        }),
    };
    let message = protocol::encode_request(&request).unwrap();
    let frames = frame_encoder().encode_request(&request).unwrap();

    let mut decoder = Decoder::new();
    assert_eq!(
        decode_raw(&mut decoder, &frames),
        vec![Decoded::Bytes(message)]
    );
}
