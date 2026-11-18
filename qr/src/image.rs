#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Image {
    pub fn validate_len(&self) -> bool {
        self.width
            .checked_mul(self.height)
            .and_then(|n| usize::try_from(n).ok())
            == Some(self.data.len())
    }
}

/// The smallest integer factor that brings `width` x `height` within `max_pixels`.
pub fn shrink_factor(width: u32, height: u32, max_pixels: usize) -> u32 {
    let (width, height) = (width as usize, height as usize);
    let mut factor = 1;
    while (width / factor) * (height / factor) > max_pixels {
        factor += 1;
    }
    factor as u32
}

/// `data`, `width` x `height` pixels of `channels` interleaved bytes, shrunk by `factor`
/// to `width / factor` x `height / factor`: each pixel the average of its factor x factor
/// block, channel by channel. No interpolation, so a module edge stays sharp.
///
/// Panics if `data` is shorter than `width * height * channels`.
pub fn box_shrink(data: &[u8], width: u32, height: u32, channels: usize, factor: u32) -> Vec<u8> {
    let (width, factor) = (width as usize, factor as usize);
    let (out_width, out_height) = (width / factor, height as usize / factor);
    let mut out = Vec::with_capacity(out_width * out_height * channels);
    for y in 0..out_height {
        for x in 0..out_width {
            for channel in 0..channels {
                let mut sum = 0;
                for row in y * factor..(y + 1) * factor {
                    let first = (row * width + x * factor) * channels + channel;
                    sum += (0..factor)
                        .map(|column| usize::from(data[first + column * channels]))
                        .sum::<usize>();
                }
                out.push((sum / (factor * factor)) as u8);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::image::{box_shrink, shrink_factor};

    #[test]
    fn the_factor_is_the_smallest_that_fits() {
        assert_eq!(shrink_factor(1280, 720, 1024 * 1024), 1);
        assert_eq!(shrink_factor(1920, 1080, 1024 * 1024), 2);
        assert_eq!(shrink_factor(4, 2, 2), 2);
    }

    #[test]
    fn each_channel_is_averaged_over_its_block() {
        // a 4 x 2 RGB frame whose pixel n is (n, 10 n, 255 - n)
        let data: Vec<u8> = (0..8u8).flat_map(|n| [n, 10 * n, 255 - n]).collect();
        // (0 + 1 + 4 + 5) / 4 = 2, then (2 + 3 + 6 + 7) / 4 = 4
        assert_eq!(box_shrink(&data, 4, 2, 3, 2), vec![2, 25, 252, 4, 45, 250]);
    }

    #[test]
    fn a_trailing_row_or_column_that_fills_no_block_is_dropped() {
        let data: Vec<u8> = (0..15).collect();
        // 5 x 3 grey by 2: the blocks at columns 0 and 2 of the first two rows,
        // (0 + 1 + 5 + 6) / 4 and (2 + 3 + 7 + 8) / 4
        assert_eq!(box_shrink(&data, 5, 3, 1, 2), vec![3, 5]);
    }
}
