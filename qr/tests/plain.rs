#![cfg(all(feature = "gen", feature = "scan"))]

mod common;

use bwk_qr::{error::Error, image::Image};

use common::{assert_round_trip, ADDRESS};

#[test]
fn plain_text_round_trips_through_rendered_qr() {
    assert_round_trip(ADDRESS);
}

#[test]
fn invalid_frame_length_is_rejected() {
    assert_eq!(Image::from_frame(vec![0; 3], 2, 2), Err(Error::BadFrame));
}
