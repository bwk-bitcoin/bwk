#![cfg(all(feature = "gen", feature = "scan"))]

use bwk_qr::{
    config::Config,
    decoder::{Decoded, Decoder},
    encoder::Encoder,
};

#[test]
fn plain_text_round_trips_through_rendered_qr() {
    let encoder = Encoder::new(Config::default()).unwrap();
    let mut decoder = Decoder::new(Config::default()).unwrap();
    let image = encoder
        .encode_text("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
        .unwrap();
    let decoded = decoder.process(&image).unwrap();
    assert_eq!(
        decoded,
        vec![Decoded::Text(
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string()
        )]
    );
}

#[test]
fn invalid_frame_length_is_rejected() {
    let mut decoder = Decoder::new(Config::default()).unwrap();
    let image = bwk_qr::image::Image {
        data: vec![0; 3],
        width: 2,
        height: 2,
    };
    assert!(decoder.process(&image).is_err());
}
