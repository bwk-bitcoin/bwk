use std::borrow::Cow;

use quircs::Quirc;

use crate::{
    error::Error,
    image::{box_shrink, shrink_factor, Image},
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

    let mut decoded = scan_inner(image.width as usize, image.height as usize, &image.data);
    if find_inverted {
        let inverted = image.data.iter().map(|v| 255 - *v).collect::<Vec<_>>();
        for item in scan_inner(image.width as usize, image.height as usize, &inverted) {
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
    use crate::{image::Image, scan::fit};

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
}
