use std::borrow::Cow;

use quircs::Quirc;

use crate::{
    image::{shrink_factor, Image},
    threshold::local_threshold,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub bytes: Vec<u8>,
}

/// The code quirc reads in `image`, then in its inverse when `find_inverted` and the
/// image holds none. The image is shrunk by [`shrink_factor`] unless `fine_scan`, so a
/// large camera frame is scanned at no less than [`SCAN_SIDE`](crate::image::SCAN_SIDE)
/// rather than at full size.
pub fn scan(image: &Image, find_inverted: bool, fine_scan: bool) -> Option<Scanned> {
    let image = fit(image, fine_scan);
    if image.data().is_empty() {
        return None;
    }
    let scanned = read(&image);
    if scanned.is_some() || !find_inverted {
        return scanned;
    }
    let inverted = Image::from_fn(image.side(), |x, y| 255 - image.pixel(x, y));
    read(&inverted)
}

/// `image` shrunk by [`shrink_factor`], or as is when `fine_scan`.
fn fit(image: &Image, fine_scan: bool) -> Cow<'_, Image> {
    let factor = shrink_factor(image.side());
    if fine_scan || factor == 1 {
        return Cow::Borrowed(image);
    }
    Cow::Owned(image.shrink(factor))
}

/// The code quirc reads in `image`, or when it reads none, the code it reads in its
/// local threshold: a code whose dark modules sit above quirc's global threshold.
fn read(image: &Image) -> Option<Scanned> {
    scan_inner(image).or_else(|| scan_inner(&local_threshold(image)))
}

// a camera frame routinely holds unreadable candidates, they must not sink a readable one
fn scan_inner(image: &Image) -> Option<Scanned> {
    let side = image.side() as usize;
    let mut quirc = Quirc::default();
    for code in quirc.identify(side, side, image.data()) {
        let Ok(code) = code else { continue };
        let Ok(data) = code.decode() else { continue };
        return Some(Scanned {
            bytes: data.payload,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::{image::Image, scan::fit};

    fn image(width: u32, height: u32) -> Image {
        Image::from_frame(
            (0..width * height).map(|value| value as u8).collect(),
            width,
            height,
        )
        .unwrap()
    }

    #[test]
    fn a_square_frame_below_the_scan_side_is_scanned_as_is() {
        let frame = image(2, 2);
        assert!(matches!(fit(&frame, false), Cow::Borrowed(_)));
        assert_eq!(*fit(&frame, false), frame);
    }

    #[test]
    fn a_wide_frame_is_cropped_to_its_centered_square() {
        // 0 1 2 3 / 4 5 6 7: columns 1 and 2
        let frame = image(4, 2);
        let fitted = fit(&frame, false);
        assert!(matches!(fitted, Cow::Borrowed(_)));
        assert_eq!(fitted.side(), 2);
        assert_eq!(fitted.data(), [1, 2, 5, 6]);
    }

    #[test]
    fn a_1080_frame_is_never_shrunk() {
        let camera = image(1920, 1080);
        assert!(matches!(fit(&camera, false), Cow::Borrowed(_)));
    }

    #[test]
    fn a_2160_frame_is_halved_unless_fine_scan() {
        let camera = image(3840, 2160);
        assert_eq!(fit(&camera, false).side(), 1080);
        assert!(matches!(fit(&camera, true), Cow::Borrowed(_)));
    }

    /// `qr` drawn on a dim display in a dark room: the display at 110, its dark modules
    /// at 75, the room at 12. One global threshold splits the room from the display and
    /// leaves the whole code white.
    #[cfg(feature = "gen")]
    fn dim_display(qr: &Image, inverted: bool) -> Image {
        let (width, height) = (720, 540);
        let mut data = vec![12u8; (width * height) as usize];
        let (left, top) = ((width - qr.side()) / 2, (height - qr.side()) / 2);
        for y in top - 30..top + qr.side() + 30 {
            data[(y * width + left - 30) as usize..(y * width + left + qr.side() + 30) as usize]
                .fill(110);
        }
        for y in 0..qr.side() {
            for x in 0..qr.side() {
                if qr.pixel(x, y) < 128 {
                    data[((top + y) * width + left + x) as usize] = 75;
                }
            }
        }
        if inverted {
            data.iter_mut().for_each(|pixel| *pixel = 255 - *pixel);
        }
        Image::from_frame(data, width, height).unwrap()
    }

    #[cfg(feature = "gen")]
    #[test]
    fn a_dim_code_quirc_misses_is_read_on_the_local_threshold() {
        use crate::{
            config::QrSize,
            encoder::Encoder,
            scan::{read, scan_inner, Scanned},
        };

        let code = Encoder::new(QrSize::S125)
            .encode_text("dim display")
            .unwrap();
        let frame = dim_display(&code, false);
        assert_eq!(scan_inner(&frame), None, "quirc alone reads the dim code");
        assert_eq!(
            read(&frame),
            Some(Scanned {
                bytes: b"dim display".to_vec()
            })
        );
    }

    #[cfg(feature = "bbqr")]
    #[test]
    fn dim_bbqr_parts_join_in_either_polarity() {
        use crate::{
            config::QrSize,
            decoder::{Decoded, Decoder},
            encoder::Encoder,
        };

        let payload: Vec<u8> = (0..=255u8).cycle().take(400).collect();
        let parts = Encoder::new(QrSize::S53).encode_bbqr(&payload).unwrap();
        assert!(parts.len() > 1);
        for inverted in [false, true] {
            let mut decoder = Decoder::new();
            let (last, first) = parts.split_last().unwrap();
            for part in first {
                assert_eq!(
                    decoder.process_raw(&dim_display(part, inverted)).unwrap(),
                    None,
                    "inverted: {inverted}"
                );
            }
            assert_eq!(
                decoder.process_raw(&dim_display(last, inverted)).unwrap(),
                Some(Decoded::Bytes(payload.clone())),
                "inverted: {inverted}"
            );
        }
    }
}
