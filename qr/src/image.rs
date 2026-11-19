use crate::error::Error;

/// An 8-bit greyscale square: one byte per pixel, 0 black to 255 white, row-major from the
/// top-left pixel with no padding between rows, so `data` is `side * side` bytes. A frame
/// of any shape goes in through [`Image::from_frame`], cropped to its centered square.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    data: Vec<u8>,
    side: u32,
}

impl Image {
    /// The centered square of a `width` x `height` greyscale frame: `data` holds one byte
    /// per pixel, laid out as an [`Image`]. See [`crop_center_square`].
    pub fn from_frame(data: Vec<u8>, width: u32, height: u32) -> Result<Self, Error> {
        if width
            .checked_mul(height)
            .and_then(|pixels| usize::try_from(pixels).ok())
            != Some(data.len())
        {
            return Err(Error::BadFrame);
        }
        let side = width.min(height);
        if width == height {
            return Ok(Self { data, side });
        }
        Ok(Self {
            data: crop_center_square(&data, width, height, 1),
            side,
        })
    }

    /// A `side` x `side` image whose pixel at column `x`, row `y` is `pixel(x, y)`.
    pub fn from_fn(side: u32, mut pixel: impl FnMut(u32, u32) -> u8) -> Self {
        let mut data = Vec::with_capacity(side as usize * side as usize);
        for y in 0..side {
            for x in 0..side {
                data.push(pixel(x, y));
            }
        }
        Self { data, side }
    }

    /// The grey value at column `x`, row `y`.
    pub fn pixel(&self, x: u32, y: u32) -> u8 {
        self.data[y as usize * self.side as usize + x as usize]
    }

    /// Shrunk by `factor` with [`box_shrink`].
    pub fn shrink(&self, factor: u32) -> Self {
        Self {
            data: box_shrink(&self.data, self.side, self.side, 1, factor),
            side: self.side / factor,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn side(&self) -> u32 {
        self.side
    }
}

/// The centered square of a `width` x `height` frame, `min(width, height)` pixels a side,
/// in the same layout. `channels` is the number of bytes per pixel: 1 for a greyscale
/// [`Image`], 3 for an RGB frame. `data` is row-major with no padding between rows, each
/// pixel's channel bytes next to each other. The square starts half the difference of
/// the sides in, rounded down, so when that difference is odd the extra column or row
/// dropped is after the square: a 5 x 2 frame keeps columns 1 and 2.
///
/// Panics if `data` is shorter than `width * height * channels`.
pub fn crop_center_square(data: &[u8], width: u32, height: u32, channels: usize) -> Vec<u8> {
    let side = width.min(height) as usize;
    let (width, height) = (width as usize, height as usize);
    let (left, top) = ((width - side) / 2, (height - side) / 2);
    let mut out = Vec::with_capacity(side * side * channels);
    for row in top..top + side {
        let first = (row * width + left) * channels;
        out.extend_from_slice(&data[first..first + side * channels]);
    }
    out
}

/// The side a frame is scanned at, at least, unless the frame itself is smaller. It maps
/// the common camera sides cleanly: 480, 720, 1080 and 1440 are scanned as is, 2160 at
/// 1080.
pub const SCAN_SIDE: u32 = 1080;

/// The largest integer factor that keeps `side` at or above [`SCAN_SIDE`], 1 for a side
/// below it.
pub fn shrink_factor(side: u32) -> u32 {
    (side / SCAN_SIDE).max(1)
}

/// A `width` x `height` frame shrunk by `factor` to `width / factor` x `height / factor`,
/// `data` and `channels` laid out as for [`crop_center_square`]. The frame is cut into
/// `factor` x `factor` blocks, each becoming one output pixel whose every channel is the
/// mean of that channel over the block: with RGB and a factor of 2, an output pixel's red
/// is the mean red of its 4 input pixels. No interpolation, so a module edge stays sharp.
///
/// Panics if `data` is shorter than `width * height * channels`.
pub fn box_shrink(data: &[u8], width: u32, height: u32, channels: usize, factor: u32) -> Vec<u8> {
    let (width, factor) = (width as usize, factor as usize);
    let (out_width, out_height) = (width / factor, height as usize / factor);
    let mut out = Vec::with_capacity(out_width * out_height * channels);
    let mut sums = vec![0usize; channels];
    for out_y in 0..out_height {
        for out_x in 0..out_width {
            sums.fill(0);
            for y in out_y * factor..(out_y + 1) * factor {
                for x in out_x * factor..(out_x + 1) * factor {
                    let start = (y * width + x) * channels;
                    let pixel = &data[start..start + channels];
                    for (channel, value) in pixel.iter().enumerate() {
                        sums[channel] += usize::from(*value);
                    }
                }
            }
            out.extend(sums.iter().map(|sum| (sum / (factor * factor)) as u8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::image::{box_shrink, crop_center_square, shrink_factor};

    #[test]
    fn a_landscape_frame_keeps_its_middle_columns() {
        // 4 x 2 grey, pixel n is n: columns 1 and 2
        let data: Vec<u8> = (0..8).collect();
        assert_eq!(crop_center_square(&data, 4, 2, 1), vec![1, 2, 5, 6]);
    }

    #[test]
    fn a_portrait_frame_keeps_its_middle_rows() {
        // 2 x 4 grey, pixel n is n: rows 1 and 2
        let data: Vec<u8> = (0..8).collect();
        assert_eq!(crop_center_square(&data, 2, 4, 1), vec![2, 3, 4, 5]);
    }

    #[test]
    fn an_odd_margin_leaves_the_extra_column_or_row_after_the_square() {
        let data: Vec<u8> = (0..10).collect();
        // 5 x 2: columns 1 and 2, columns 0, 3 and 4 dropped
        assert_eq!(crop_center_square(&data, 5, 2, 1), vec![1, 2, 6, 7]);
        // 2 x 5: rows 1 and 2
        assert_eq!(crop_center_square(&data, 2, 5, 1), vec![2, 3, 4, 5]);
    }

    #[test]
    fn a_square_frame_is_kept_whole() {
        let data: Vec<u8> = (0..27).collect();
        assert_eq!(crop_center_square(&data, 3, 3, 3), data);
    }

    #[test]
    fn each_channel_of_a_pixel_is_kept() {
        // 3 x 1 RGB, pixel n is (n, 10 n, 255 - n): the middle pixel
        let data: Vec<u8> = (0..3u8).flat_map(|n| [n, 10 * n, 255 - n]).collect();
        assert_eq!(crop_center_square(&data, 3, 1, 3), vec![1, 10, 254]);
    }

    #[test]
    fn the_factor_is_the_largest_that_keeps_the_scan_side() {
        for side in [480, 720, 1080, 1440, 2159] {
            assert_eq!(shrink_factor(side), 1, "side {side}");
        }
        assert_eq!(shrink_factor(2160), 2);
        assert_eq!(shrink_factor(3024), 2);
        assert_eq!(shrink_factor(3240), 3);
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
