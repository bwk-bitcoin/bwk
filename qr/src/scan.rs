use std::borrow::Cow;

use quircs::Quirc;

use crate::{
    error::Error,
    image::{box_shrink, shrink_factor, Image},
    threshold::local_threshold,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub text: String,
    pub bytes: Vec<u8>,
}

/// A frame above `max_pixels` is shrunk to fit before it is scanned, so the limit bounds
/// the work per frame rather than refusing a large camera frame.
pub fn scan(image: &Image, find_inverted: bool, max_pixels: usize) -> Result<Vec<Scanned>, Error> {
    if !image.validate_len() {
        return Err(Error::BadFrame);
    }
    let image = fit(image, max_pixels);
    if image.data.is_empty() {
        return Ok(Vec::new());
    }

    let mut decoded = read(image.width as usize, image.height as usize, &image.data);
    if find_inverted {
        let inverted = image.data.iter().map(|v| 255 - *v).collect::<Vec<_>>();
        for item in read(image.width as usize, image.height as usize, &inverted) {
            if !decoded.iter().any(|existing| existing.bytes == item.bytes) {
                decoded.push(item);
            }
        }
    }
    Ok(decoded)
}

/// `image` shrunk by the smallest integer factor that brings it within `max_pixels`.
fn fit(image: &Image, max_pixels: usize) -> Cow<'_, Image> {
    let factor = shrink_factor(image.width, image.height, max_pixels);
    if factor == 1 {
        return Cow::Borrowed(image);
    }
    Cow::Owned(Image {
        data: box_shrink(&image.data, image.width, image.height, 1, factor),
        width: image.width / factor,
        height: image.height / factor,
    })
}

/// The codes quirc reads in `data`, or when it reads none, the codes it reads in its
/// local threshold: a code whose dark modules sit above quirc's global threshold.
fn read(width: usize, height: usize, data: &[u8]) -> Vec<Scanned> {
    let decoded = scan_inner(width, height, data);
    if !decoded.is_empty() {
        return decoded;
    }
    scan_inner(width, height, &local_threshold(width, height, data))
}

// a camera frame routinely holds unreadable candidates, they must not sink the readable ones
fn scan_inner(width: usize, height: usize, data: &[u8]) -> Vec<Scanned> {
    let mut quirc = Quirc::default();
    let mut decoded = Vec::new();
    for code in quirc.identify(width, height, data) {
        let Ok(code) = code else { continue };
        let Ok(data) = code.decode() else { continue };
        decoded.push(Scanned {
            text: String::from_utf8_lossy(&data.payload).into_owned(),
            bytes: data.payload,
        });
    }
    decoded
}

#[cfg(test)]
mod tests {
    use crate::{
        image::Image,
        scan::{fit, read, scan_inner},
    };

    fn image(width: u32, height: u32) -> Image {
        Image {
            data: (0..width * height).map(|value| value as u8).collect(),
            width,
            height,
        }
    }

    #[test]
    fn a_frame_within_the_limit_is_scanned_as_is() {
        let frame = image(4, 2);
        assert_eq!(*fit(&frame, 8), frame);
    }

    #[test]
    fn a_frame_above_the_limit_is_averaged_by_the_smallest_factor_that_fits() {
        // 0 1 2 3 / 4 5 6 7 by 2: (0 + 1 + 4 + 5) / 4 and (2 + 3 + 6 + 7) / 4
        let small = image(4, 2);
        let fitted = fit(&small, 7);
        assert_eq!((fitted.width, fitted.height), (2, 1));
        assert_eq!(fitted.data, vec![2, 4]);
        let camera = image(1920, 1080);
        let fitted = fit(&camera, 1024 * 1024);
        assert_eq!((fitted.width, fitted.height), (960, 540));
    }

    /// `qr` drawn on a dim display in a dark room: the display at 110, its dark modules
    /// at 75, the room at 12. One global threshold splits the room from the display and
    /// leaves the whole code white.
    #[cfg(feature = "gen")]
    fn dim_display(qr: &Image, inverted: bool) -> Image {
        let (width, height) = (720, 540);
        let mut data = vec![12u8; (width * height) as usize];
        let (left, top) = ((width - qr.width) / 2, (height - qr.height) / 2);
        for y in top - 30..top + qr.height + 30 {
            data[(y * width + left - 30) as usize..(y * width + left + qr.width + 30) as usize]
                .fill(110);
        }
        for y in 0..qr.height {
            for x in 0..qr.width {
                if qr.data[(y * qr.width + x) as usize] < 128 {
                    data[((top + y) * width + left + x) as usize] = 75;
                }
            }
        }
        if inverted {
            data.iter_mut().for_each(|pixel| *pixel = 255 - *pixel);
        }
        Image {
            data,
            width,
            height,
        }
    }

    #[cfg(feature = "gen")]
    #[test]
    fn a_dim_code_quirc_misses_is_read_on_the_local_threshold() {
        use crate::{config::Config, encoder::Encoder};

        let code = Encoder::new(Config::default())
            .unwrap()
            .encode_text("dim display")
            .unwrap();
        let frame = dim_display(&code, false);
        let (width, height) = (frame.width as usize, frame.height as usize);
        assert!(
            scan_inner(width, height, &frame.data).is_empty(),
            "quirc alone reads the dim code"
        );
        let found = read(width, height, &frame.data);
        assert_eq!(
            found
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            ["dim display"]
        );
    }

    #[cfg(feature = "bbqr")]
    #[test]
    fn dim_bbqr_parts_join_in_either_polarity() {
        use crate::{
            config::Config,
            decoder::{Decoded, Decoder},
            encoder::Encoder,
        };

        let payload: Vec<u8> = (0..=255u8).cycle().take(400).collect();
        let parts = Encoder::for_part_bytes(150)
            .unwrap()
            .encode_bytes(&payload)
            .unwrap();
        assert!(parts.len() > 1);
        for inverted in [false, true] {
            let mut decoder = Decoder::new(Config::default()).unwrap();
            let mut joined = Vec::new();
            for part in &parts {
                joined.extend(decoder.process_raw(&dim_display(part, inverted)).unwrap());
            }
            assert_eq!(
                joined,
                vec![Decoded::Bytes(payload.clone())],
                "inverted: {inverted}"
            );
        }
    }
}
