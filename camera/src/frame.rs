use std::panic;

use bwk_qr::image::{box_shrink, crop_center_square, shrink_factor, Image};
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{FrameFormat, Resolution},
    FormatDecoder,
};

use crate::error::Error;

const RGB_CHANNELS: usize = 3;
/// Rec. 601 luma weights, in 256ths.
const LUMA_RED: u16 = 77;
const LUMA_GREEN: u16 = 150;
const LUMA_BLUE: u16 = 29;

/// An RGB888 square: three interleaved bytes per pixel, row-major from the top-left pixel
/// with no padding between rows, so `data` is `side * side * 3` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rgb {
    data: Vec<u8>,
    side: u32,
}

impl Rgb {
    /// The centered square of a captured frame in `format`, as RGB888.
    pub fn convert(
        format: FrameFormat,
        width: u32,
        height: u32,
        raw: &[u8],
    ) -> Result<Self, Error> {
        // mozjpeg reports a corrupt MJPEG frame by panicking
        let data = panic::catch_unwind(|| {
            RgbFormat::write_output(format, Resolution::new(width, height), raw)
        })
        .map_err(|_| unreadable())??;
        Self::from_frame(data, width, height)
    }

    /// The centered square of a `width` x `height` RGB888 frame without row padding.
    pub fn from_frame(data: Vec<u8>, width: u32, height: u32) -> Result<Self, Error> {
        let expected = u128::from(width) * u128::from(height) * RGB_CHANNELS as u128;
        if data.len() as u128 != expected {
            log::error!(
                "a {width}x{height} RGB888 frame holds {} bytes instead of {expected}",
                data.len()
            );
            return Err(unreadable());
        }
        let side = width.min(height);
        if width == height {
            return Ok(Self { data, side });
        }
        Ok(Self {
            data: crop_center_square(&data, width, height, RGB_CHANNELS),
            side,
        })
    }

    /// Shrunk by [`shrink_factor`], or as is when `fine_scan`.
    pub fn fit(self, fine_scan: bool) -> Self {
        let factor = shrink_factor(self.side);
        if fine_scan || factor == 1 {
            return self;
        }
        Self {
            data: box_shrink(&self.data, self.side, self.side, RGB_CHANNELS, factor),
            side: self.side / factor,
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn side(&self) -> u32 {
        self.side
    }

    /// One byte of Rec. 601 luma per pixel, what a QR decoder reads.
    pub fn grey(&self) -> Image {
        Image::from_fn(self.side, |x, y| {
            let start = (y as usize * self.side as usize + x as usize) * RGB_CHANNELS;
            let pixel = &self.data[start..start + RGB_CHANNELS];
            ((u16::from(pixel[0]) * LUMA_RED
                + u16::from(pixel[1]) * LUMA_GREEN
                + u16::from(pixel[2]) * LUMA_BLUE)
                >> 8) as u8
        })
    }
}

pub fn unreadable() -> Error {
    Error::Capture("the camera returned an unreadable frame".to_owned())
}

/// AVFoundation may pad each row of `width` x `height` RGB888 pixels: the padding is
/// dropped. None when `raw` is shorter than a row or not whole rows.
#[cfg(any(target_os = "macos", test))]
pub fn pack_rows(raw: Vec<u8>, width: u32, height: u32) -> Option<Vec<u8>> {
    let row = (width as usize).checked_mul(RGB_CHANNELS)?;
    let expected = row.checked_mul(height as usize)?;
    if raw.len() == expected {
        return Some(raw);
    }
    if height == 0 || raw.len() % height as usize != 0 {
        return None;
    }
    let stride = raw.len() / height as usize;
    if stride < row {
        return None;
    }
    let mut packed = Vec::with_capacity(expected);
    for padded in raw.chunks_exact(stride) {
        packed.extend_from_slice(&padded[..row]);
    }
    Some(packed)
}

#[cfg(test)]
mod tests {
    use nokhwa::utils::FrameFormat;

    use crate::{
        error::Error,
        frame::{pack_rows, unreadable, Rgb},
    };

    fn rgb(data: Vec<u8>, side: u32) -> Rgb {
        Rgb { data, side }
    }

    #[test]
    fn yuyv_converts_two_pixels_per_four_bytes() {
        // Y0 U Y1 V with no chroma: (Y - 16) * 298 / 256, rounded
        let raw = [16, 128, 235, 128, 235, 128, 16, 128];
        assert_eq!(
            Rgb::convert(FrameFormat::YUYV, 2, 2, &raw).unwrap(),
            rgb(vec![0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0], 2)
        );
    }

    #[test]
    fn nv12_shares_one_chroma_pair_over_a_two_by_two_block() {
        // the Y plane, then one U V pair
        let raw = [16, 128, 128, 235, 128, 128];
        assert_eq!(
            Rgb::convert(FrameFormat::NV12, 2, 2, &raw).unwrap(),
            rgb(
                vec![0, 0, 0, 130, 130, 130, 130, 130, 130, 255, 255, 255],
                2
            )
        );
    }

    #[test]
    fn grey_is_spread_over_the_three_channels() {
        assert_eq!(
            Rgb::convert(FrameFormat::GRAY, 2, 2, &[7, 9, 11, 13]).unwrap(),
            rgb(vec![7, 7, 7, 9, 9, 9, 11, 11, 11, 13, 13, 13], 2)
        );
    }

    #[test]
    fn raw_rgb_is_kept_and_raw_bgr_is_swapped() {
        assert_eq!(
            Rgb::convert(FrameFormat::RAWRGB, 1, 1, &[1, 2, 3]).unwrap(),
            rgb(vec![1, 2, 3], 1)
        );
        assert_eq!(
            Rgb::convert(FrameFormat::RAWBGR, 1, 1, &[1, 2, 3]).unwrap(),
            rgb(vec![3, 2, 1], 1)
        );
    }

    #[test]
    fn a_frame_of_the_wrong_length_is_refused() {
        assert_eq!(
            Rgb::convert(FrameFormat::RAWRGB, 2, 1, &[0; 5]),
            Err(unreadable())
        );
        assert_eq!(
            Rgb::convert(FrameFormat::GRAY, 2, 2, &[0; 3]),
            Err(unreadable())
        );
        assert!(matches!(
            Rgb::convert(FrameFormat::YUYV, 4, 1, &[0; 7]),
            Err(Error::Capture(_))
        ));
        assert!(matches!(
            Rgb::convert(FrameFormat::NV12, 2, 2, &[0; 5]),
            Err(Error::Capture(_))
        ));
    }

    #[cfg(feature = "mjpeg")]
    #[test]
    fn a_corrupt_mjpeg_frame_is_refused() {
        assert_eq!(
            Rgb::convert(FrameFormat::MJPEG, 1, 1, &[0; 16]),
            Err(unreadable())
        );
    }

    /// A raw RGB `width` x `height` frame whose pixel n is (n, 10 n, 255 - n), converted.
    fn numbered(width: u32, height: u32) -> Rgb {
        let raw: Vec<u8> = (0..(width * height) as u8)
            .flat_map(|n| [n, 10 * n, 255 - n])
            .collect();
        Rgb::convert(FrameFormat::RAWRGB, width, height, &raw).unwrap()
    }

    #[test]
    fn a_square_frame_is_kept_as_is_at_conversion() {
        let frame = numbered(2, 2);
        assert_eq!(
            frame,
            rgb(vec![0, 0, 255, 1, 10, 254, 2, 20, 253, 3, 30, 252], 2)
        );
    }

    #[test]
    fn a_wide_frame_is_cropped_to_its_centered_square_at_conversion() {
        // 4 x 2: pixels 1, 2, 5 and 6
        assert_eq!(
            numbered(4, 2),
            rgb(vec![1, 10, 254, 2, 20, 253, 5, 50, 250, 6, 60, 249], 2)
        );
    }

    #[test]
    fn a_tall_frame_is_cropped_to_its_centered_square_at_conversion() {
        // 1 x 3: pixel 1
        assert_eq!(numbered(1, 3), rgb(vec![1, 10, 254], 1));
    }

    #[test]
    fn a_frame_below_twice_the_scan_side_is_never_shrunk() {
        let frame = rgb(vec![7; 2159 * 2159 * 3], 2159);
        assert_eq!(frame.clone().fit(false), frame);
    }

    #[test]
    fn a_2160_frame_is_averaged_by_2_unless_fine_scan() {
        // each 2 x 2 block holds 0, 2, 2 and 0 on every channel: (0 + 2 + 2 + 0) / 4 = 1
        let data: Vec<u8> = (0..2160 * 2160)
            .flat_map(|n| {
                let value = ((n % 2160 + n / 2160) % 2 * 2) as u8;
                [value; 3]
            })
            .collect();
        let frame = rgb(data, 2160);
        assert_eq!(frame.clone().fit(true), frame);
        assert_eq!(frame.fit(false), rgb(vec![1; 1080 * 1080 * 3], 1080));
    }

    #[test]
    fn grey_weighs_green_most_and_blue_least() {
        let grey = rgb(vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255], 2).grey();
        assert_eq!(grey.data(), [76, 149, 28, 255]);
        assert_eq!(grey.side(), 2);
    }

    #[test]
    fn rows_without_padding_are_kept_as_is() {
        assert_eq!(
            pack_rows(vec![1, 2, 3, 4, 5, 6], 1, 2),
            Some(vec![1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn row_padding_is_dropped() {
        // a 1 x 2 frame whose rows are padded to 4 bytes
        assert_eq!(
            pack_rows(vec![1, 2, 3, 0, 4, 5, 6, 0], 1, 2),
            Some(vec![1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn a_buffer_that_is_not_whole_rows_is_refused() {
        assert_eq!(pack_rows(vec![0; 7], 1, 2), None);
        assert_eq!(pack_rows(vec![0; 4], 1, 2), None);
        assert_eq!(pack_rows(vec![0; 3], 1, 0), None);
    }
}
