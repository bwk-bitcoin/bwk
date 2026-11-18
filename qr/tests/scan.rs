#![cfg(all(feature = "gen", feature = "scan"))]

mod common;

use bwk_qr::{
    config::DecoderConfig,
    decoder::{Decoded, Decoder},
    error::Error,
    image::Image,
};

use common::{assert_round_trip, render, SP_ADDRESS};

const TAPROOT_ADDRESS: &str = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
const BIP21_URI: &str =
    "bitcoin:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh?amount=0.0125&label=Coffee";

#[test]
fn taproot_address_round_trips() {
    assert_round_trip(TAPROOT_ADDRESS);
}

#[test]
fn sp_address_round_trips() {
    assert_round_trip(SP_ADDRESS);
}

#[test]
fn mixed_case_text_round_trips() {
    assert_round_trip("Bwk QR Test 12345 aBcDeF");
}

#[test]
fn bip21_uri_round_trips() {
    assert_round_trip(BIP21_URI);
}

#[test]
fn inverted_frame_decodes_only_when_configured() {
    let rendered = render(TAPROOT_ADDRESS);
    let inverted = Image::from_frame(
        rendered.data().iter().map(|v| 255 - *v).collect(),
        rendered.side(),
        rendered.side(),
    )
    .unwrap();

    let mut permissive = Decoder::new();
    assert_eq!(
        permissive.process(&inverted).unwrap(),
        Some(Decoded::Text(TAPROOT_ADDRESS.to_string()))
    );

    let mut strict = Decoder::with_config(DecoderConfig {
        scan_inverted: false,
        ..DecoderConfig::default()
    });
    assert_eq!(strict.process(&inverted).unwrap(), None);
}

#[test]
fn frame_without_qr_decodes_to_nothing() {
    let mut decoder = Decoder::new();
    let gray = Image::from_frame(vec![128; 100 * 100], 100, 100).unwrap();
    assert_eq!(decoder.process(&gray).unwrap(), None);
}

const CAMERA_WIDTH: u32 = 1920;
const CAMERA_HEIGHT: u32 = 1080;

// A camera that only offers 1080p: the code drawn `scale` times larger on a white
// 1920 x 1080 frame, its left edge at `left` and centered vertically.
fn camera_frame(code: &Image, scale: u32, left: u32) -> Image {
    let (width, height) = (CAMERA_WIDTH, CAMERA_HEIGHT);
    let mut data = vec![255; (width * height) as usize];
    let top = (height - code.side() * scale) / 2;
    for y in 0..code.side() * scale {
        for x in 0..code.side() * scale {
            data[((top + y) * width + left + x) as usize] =
                code.data()[((y / scale) * code.side() + x / scale) as usize];
        }
    }
    Image::from_frame(data, width, height).unwrap()
}

fn centered_left(code: &Image, scale: u32) -> u32 {
    (CAMERA_WIDTH - code.side() * scale) / 2
}

#[test]
fn code_in_the_center_of_a_wide_frame_is_read() {
    const SCALE: u32 = 6;
    let code = render(TAPROOT_ADDRESS);
    let frame = camera_frame(&code, SCALE, centered_left(&code, SCALE));
    let mut decoder = Decoder::new();
    assert_eq!(
        decoder.process(&frame).unwrap(),
        Some(Decoded::Text(TAPROOT_ADDRESS.to_string()))
    );
}

#[test]
fn code_outside_the_centered_square_is_not_read() {
    const SCALE: u32 = 2;
    let code = render(TAPROOT_ADDRESS);
    let side = code.side() * SCALE;
    assert!(side <= (CAMERA_WIDTH - CAMERA_HEIGHT) / 2);
    let mut decoder = Decoder::new();
    assert_eq!(
        decoder
            .process(&camera_frame(&code, SCALE, centered_left(&code, SCALE)))
            .unwrap(),
        Some(Decoded::Text(TAPROOT_ADDRESS.to_string()))
    );
    for left in [0, CAMERA_WIDTH - side] {
        assert_eq!(
            decoder.process(&camera_frame(&code, SCALE, left)).unwrap(),
            None,
            "left: {left}"
        );
    }
}

#[test]
fn frame_whose_data_does_not_match_its_size_is_rejected() {
    let frame = render(TAPROOT_ADDRESS);
    let mut data = frame.data().to_vec();
    data.pop();
    assert_eq!(
        Image::from_frame(data, frame.side(), frame.side()),
        Err(Error::BadFrame)
    );
}
