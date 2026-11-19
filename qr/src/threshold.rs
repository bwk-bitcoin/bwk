//! A local adaptive threshold, the fallback for a frame quirc reads nothing in.
//!
//! quirc thresholds a frame against one level. A screen photographed in a dark room can
//! have even its dark modules above that level, and the code then reads as all white.
//! Comparing each pixel to the mean of its own neighbourhood, as ZBar does, keeps the
//! modules apart wherever the code sits in the frame.

use crate::image::Image;

/// How much darker than its neighbourhood mean a pixel must be, in grey levels (0 to
/// 255), to turn black, so a flat area stays white rather than turning to noise.
const OFFSET: u64 = 3;
/// The neighbourhood is a square window an eighth of the image's side, within these
/// bounds, as ZBar's `qr_binarize` sizes it: large enough not to fit inside the dark core
/// of a version 1 finder pattern.
const WINDOW_DIVISOR: usize = 8;
const MIN_WINDOW: usize = 16;
const MAX_WINDOW: usize = 256;

/// `image` as black (0) and white (255): black where a pixel is more than [`OFFSET`] below
/// the mean of the square around it, the square clipped at the image's edges.
pub fn local_threshold(image: &Image) -> Image {
    let side = image.side() as usize;
    let radius = (side / WINDOW_DIVISOR).clamp(MIN_WINDOW, MAX_WINDOW) / 2;
    let sums = SummedArea::new(image);
    Image::from_fn(image.side(), |x, y| {
        let pixel = u64::from(image.pixel(x, y));
        let (x, y) = (x as usize, y as usize);
        let (top, bottom) = (y.saturating_sub(radius), (y + radius + 1).min(side));
        let (left, right) = (x.saturating_sub(radius), (x + radius + 1).min(side));
        let count = ((bottom - top) * (right - left)) as u64;
        let dark = (pixel + OFFSET) * count < sums.sum(left, top, right, bottom);
        if dark {
            0
        } else {
            255
        }
    })
}

/// Each entry is the sum of every pixel above and left of it, so the sum of any
/// rectangle costs four lookups.
struct SummedArea {
    stride: usize,
    sums: Vec<u64>,
}

impl SummedArea {
    fn new(image: &Image) -> Self {
        let side = image.side() as usize;
        let stride = side + 1;
        let mut sums = vec![0; stride * stride];
        for y in 0..side {
            let mut row = 0;
            for x in 0..side {
                row += u64::from(image.pixel(x as u32, y as u32));
                sums[(y + 1) * stride + x + 1] = sums[y * stride + x + 1] + row;
            }
        }
        Self { stride, sums }
    }

    /// The sum of the pixels in columns `left..right` of rows `top..bottom`.
    fn sum(&self, left: usize, top: usize, right: usize, bottom: usize) -> u64 {
        let at = |x: usize, y: usize| self.sums[y * self.stride + x];
        at(right, bottom) + at(left, top) - at(left, bottom) - at(right, top)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        image::Image,
        threshold::{local_threshold, SummedArea},
    };

    #[test]
    fn a_rectangle_sum_matches_adding_its_pixels() {
        // 5 x 5, pixel n is n
        let sums = SummedArea::new(&Image::from_fn(5, |x, y| (y * 5 + x) as u8));
        // rows 1..3, columns 2..5: 7 + 8 + 9 + 12 + 13 + 14
        assert_eq!(sums.sum(2, 1, 5, 3), 63);
        assert_eq!(sums.sum(0, 0, 5, 5), (0..25).sum::<u64>());
        assert_eq!(sums.sum(3, 2, 3, 4), 0);
    }

    #[test]
    fn a_flat_or_empty_image_stays_white() {
        for side in [0, 1, 2, 3, 40] {
            for level in [0, 3, 127, 255] {
                assert_eq!(
                    local_threshold(&Image::from_fn(side, |_, _| level)),
                    Image::from_fn(side, |_, _| 255),
                    "side {side} at {level}"
                );
            }
        }
    }

    #[test]
    fn a_pixel_turns_black_only_below_its_neighbourhood_mean_by_more_than_the_offset() {
        // one dim pixel in a 17 x 17 field at 100: the mean around it barely moves
        let field = |dim| Image::from_fn(17, move |x, y| if (x, y) == (8, 8) { dim } else { 100 });
        assert_eq!(local_threshold(&field(90)).pixel(8, 8), 0);
        assert_eq!(local_threshold(&field(98)).pixel(8, 8), 255);
    }
}
