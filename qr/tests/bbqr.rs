#![cfg(feature = "bbqr")]

use bwk_qr::{
    config::Config,
    decoder::{Decoded, Decoder},
    encoder::Encoder,
    error::Error,
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
    use bwk_qr::protocol::ll::{self as protocol, request, types::DerivationPath};

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

    let mut decoder = Decoder::new(Config::default()).unwrap();
    assert_eq!(
        decode_raw(&mut decoder, &frames),
        vec![Decoded::Bytes(message)]
    );
}

fn frame_width(encoder: &Encoder) -> u32 {
    encoder.encode_bytes(&payload()).unwrap()[0].width
}

fn pinned(max_qr_version: u8, bbqr_part_bytes: usize) -> Result<Encoder, Error> {
    Encoder::new(Config {
        max_qr_version,
        bbqr_part_bytes,
        ..Config::default()
    })
}

#[test]
fn an_encoder_for_a_part_size_pins_the_smallest_version_a_full_part_fits() {
    for (part_bytes, version) in [(100, 7), (150, 9)] {
        let encoder = Encoder::for_part_bytes(part_bytes).unwrap();
        assert_eq!(
            frame_width(&encoder),
            frame_width(&pinned(version, part_bytes).unwrap())
        );
        assert!(matches!(
            pinned(version - 1, part_bytes),
            Err(Error::PartTooLarge { .. })
        ));
    }
}

#[test]
fn an_encoder_for_a_part_size_refuses_an_empty_part_or_one_no_version_holds() {
    assert!(matches!(
        Encoder::for_part_bytes(0),
        Err(Error::ZeroPartSize)
    ));
    assert!(matches!(
        Encoder::for_part_bytes(4096),
        Err(Error::PartTooLarge { version: 40, .. })
    ));
}
