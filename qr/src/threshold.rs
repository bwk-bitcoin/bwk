//! A local adaptive threshold, the fallback for a frame quirc reads nothing in.
//!
//! quirc thresholds a frame against one level. A screen photographed in a dark room can
//! have even its dark modules above that level, and the code then reads as all white.
//! Comparing each pixel to the mean of its own neighbourhood, as ZBar does, keeps the
//! modules apart wherever the code sits in the frame.

/// How much darker than its neighbourhood mean a pixel must be to turn black, so a
/// flat area stays white rather than turning to noise.
const OFFSET: u64 = 3;
/// The neighbourhood is about an eighth of the frame's shorter side, within these
/// bounds: wide enough that a finder pattern's dark core is not compared to itself.
const MIN_RADIUS: usize = 8;
const MAX_RADIUS: usize = 128;

/// `data`, `width` x `height` grey pixels, as black (0) and white (255): black where a
/// pixel is more than [`OFFSET`] below the mean of the square around it, the square
/// clipped at the frame's edges.
pub(crate) fn local_threshold(width: usize, height: usize, data: &[u8]) -> Vec<u8> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let radius = (width.min(height) / 16).clamp(MIN_RADIUS, MAX_RADIUS);
    let sums = SummedArea::new(width, height, data);
    let mut binary = Vec::with_capacity(data.len());
    for y in 0..height {
        let (top, bottom) = (y.saturating_sub(radius), (y + radius + 1).min(height));
        for x in 0..width {
            let (left, right) = (x.saturating_sub(radius), (x + radius + 1).min(width));
            let count = ((bottom - top) * (right - left)) as u64;
            let pixel = u64::from(data[y * width + x]);
            let dark = (pixel + OFFSET) * count < sums.sum(left, top, right, bottom);
            binary.push(if dark { 0 } else { 255 });
        }
    }
    binary
}

/// Each entry is the sum of every pixel above and left of it, so the sum of any
/// rectangle costs four lookups.
struct SummedArea {
    stride: usize,
    sums: Vec<u64>,
}

impl SummedArea {
    fn new(width: usize, height: usize, data: &[u8]) -> Self {
        let stride = width + 1;
        let mut sums = vec![0; stride * (height + 1)];
        for y in 0..height {
            let mut row = 0;
            for x in 0..width {
                row += u64::from(data[y * width + x]);
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
    use crate::threshold::{local_threshold, SummedArea};

    #[test]
    fn a_rectangle_sum_matches_adding_its_pixels() {
        let data: Vec<u8> = (0..20).collect();
        let sums = SummedArea::new(5, 4, &data);
        // rows 1..3, columns 2..5: 7 + 8 + 9 + 12 + 13 + 14
        assert_eq!(sums.sum(2, 1, 5, 3), 63);
        assert_eq!(sums.sum(0, 0, 5, 4), (0..20).sum::<u64>());
        assert_eq!(sums.sum(3, 2, 3, 4), 0);
    }

    #[test]
    fn a_flat_or_empty_frame_stays_white() {
        for (width, height) in [(0, 0), (0, 2), (2, 0), (1, 1), (3, 2), (40, 30)] {
            for level in [0, 3, 127, 255] {
                let data = vec![level; width * height];
                assert_eq!(
                    local_threshold(width, height, &data),
                    vec![255; width * height],
                    "{width}x{height} at {level}"
                );
            }
        }
    }

    #[test]
    fn a_pixel_turns_black_only_below_its_neighbourhood_mean_by_more_than_the_offset() {
        // one dim pixel in a 17 x 17 field at 100: the mean around it barely moves
        let mut data = vec![100; 17 * 17];
        data[8 * 17 + 8] = 90;
        assert_eq!(local_threshold(17, 17, &data)[8 * 17 + 8], 0);
        data[8 * 17 + 8] = 98;
        assert_eq!(local_threshold(17, 17, &data)[8 * 17 + 8], 255);
    }
}
