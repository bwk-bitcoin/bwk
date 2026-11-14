#![cfg(feature = "gen")]

mod common;

use bwk_qr::{config::Config, encoder::Encoder, error::Error};

use common::{render, ADDRESS, SP_ADDRESS};

const DESCRIPTOR: &str = "tr([f00dbabe/86h/0h/0h]xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)#abcdefgh";

fn assert_render_size(text: &str, size: u32, pixels: usize) {
    let image = render(text);
    assert_eq!(image.width, size);
    assert_eq!(image.height, size);
    assert_eq!(image.data.len(), pixels);
}

#[test]
fn short_text_renders_version_one() {
    assert_render_size("bwk", 116, 13456);
}

#[test]
fn address_renders_version_three() {
    assert_render_size(ADDRESS, 148, 21904);
}

#[test]
fn descriptor_renders_version_seven() {
    assert_render_size(DESCRIPTOR, 212, 44944);
}

#[test]
fn sp_address_fits_default_version_cap() {
    assert_render_size(SP_ADDRESS, 196, 38416);
}

#[test]
fn empty_text_renders_version_one() {
    assert_render_size("", 116, 13456);
}

#[test]
fn version_cap_rejects_payload_that_does_not_fit() {
    let capped = Encoder::new(Config {
        max_qr_version: 3,
        // a full BBQR part still has to fit the capped version
        bbqr_part_bytes: 32,
        ..Config::default()
    })
    .unwrap();
    assert_eq!(capped.encode_text(SP_ADDRESS), Err(Error::TooLong));

    let default = Encoder::new(Config::default()).unwrap();
    assert!(default.encode_text(SP_ADDRESS).is_ok());
}
