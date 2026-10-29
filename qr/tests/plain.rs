#![cfg(all(feature = "gen", feature = "scan"))]

mod common;

use bwk_qr::{config::Config, decoder::Decoder};

use common::{assert_round_trip, ADDRESS};

#[test]
fn plain_text_round_trips_through_rendered_qr() {
    assert_round_trip(ADDRESS);
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
