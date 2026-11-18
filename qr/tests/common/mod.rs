// Each integration binary includes this module and uses a different subset.
#![allow(dead_code)]

#[cfg(feature = "scan")]
use bwk_qr::decoder::{Decoded, Decoder};
use bwk_qr::{config::Config, encoder::Encoder, image::Image};

pub const ADDRESS: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
pub const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

pub fn render(text: &str) -> Image {
    let encoder = Encoder::new(Config::default()).unwrap();
    encoder.encode_text(text).unwrap()
}

#[cfg(feature = "scan")]
pub fn assert_round_trip(text: &str) {
    let mut decoder = Decoder::new(Config::default()).unwrap();
    let decoded = decoder.process(&render(text)).unwrap();
    assert_eq!(decoded, vec![Decoded::Text(text.to_string())]);
}
