#![cfg(feature = "bbqr")]

use bwk_qr::{
    config::Config,
    decoder::{Decoded, Decoder},
    encoder::Encoder,
    image::Image,
};

// small parts force a payload across several BBQR frames
fn frame_encoder() -> Encoder {
    Encoder::new(Config {
        bbqr_part_bytes: 16,
        ..Config::default()
    })
    .unwrap()
}

fn payload() -> Vec<u8> {
    (0..=255u8).cycle().take(100).collect()
}

fn decode_raw(decoder: &mut Decoder, frames: &[Image]) -> Vec<Decoded> {
    let mut decoded = Vec::new();
    for frame in frames {
        decoded.extend(decoder.process_raw(frame).unwrap());
    }
    decoded
}

#[test]
fn raw_payload_round_trips_through_bbqr_frames() {
    let frames = frame_encoder().encode_bytes(&payload()).unwrap();
    assert!(
        frames.len() > 1,
        "expected several frames, got {}",
        frames.len()
    );

    let mut decoder = Decoder::new(Config::default()).unwrap();
    assert_eq!(
        decode_raw(&mut decoder, &frames),
        vec![Decoded::Bytes(payload())]
    );
}

#[test]
fn raw_payload_is_only_returned_once_every_part_is_seen() {
    let frames = frame_encoder().encode_bytes(&payload()).unwrap();
    let (last, first) = frames.split_last().unwrap();

    let mut decoder = Decoder::new(Config::default()).unwrap();
    assert_eq!(decode_raw(&mut decoder, first), vec![]);
    let progress = decoder.progress().unwrap();
    assert_eq!(progress.seen, first.len());
    assert_eq!(progress.total, frames.len());
    assert_eq!(
        decoder.process_raw(last).unwrap(),
        vec![Decoded::Bytes(payload())]
    );
}

#[test]
fn raw_decode_keeps_plain_codes_as_text() {
    let image = frame_encoder().encode_text("plain").unwrap();
    let mut decoder = Decoder::new(Config::default()).unwrap();
    assert_eq!(
        decoder.process_raw(&image).unwrap(),
        vec![Decoded::Text("plain".to_string())]
    );
}

#[cfg(feature = "protocol")]
#[test]
fn protocol_payload_stays_undecoded_on_the_raw_path() {
    use bwk_qr::protocol::{self, request};

    let request = protocol::Request {
        id: protocol::RequestId([7; protocol::REQUEST_ID_LEN]),
        body: request::Body::GetSpDescriptor(request::GetSpDescriptor {}),
    };
    let message = protocol::encode_request(&request).unwrap();
    let frames = frame_encoder().encode_request(&request).unwrap();

    let mut decoder = Decoder::new(Config::default()).unwrap();
    assert_eq!(
        decode_raw(&mut decoder, &frames),
        vec![Decoded::Bytes(message)]
    );
}
