use std::panic;

use bwk_qr::image::{box_shrink, shrink_factor, Image};
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{FrameFormat, Resolution},
    FormatDecoder,
};

use crate::Error;

const RGB_CHANNELS: usize = 3;

/// RGB888, three interleaved bytes per pixel, row-major.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rgb {
    pub data: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Rgb {
    /// A captured frame in `format`, as RGB888.
    pub(crate) fn convert(
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
        let rgb = Self {
            data,
            width,
            height,
        };
        if !rgb.validate_len() {
            return Err(unreadable());
        }
        Ok(rgb)
    }

    fn validate_len(&self) -> bool {
        (self.width as usize)
            .checked_mul(self.height as usize)
            .and_then(|pixels| pixels.checked_mul(RGB_CHANNELS))
            == Some(self.data.len())
    }

    /// Shrunk by the smallest integer factor that brings it within `max_pixels`.
    pub(crate) fn shrink(self, max_pixels: usize) -> Self {
        let factor = shrink_factor(self.width, self.height, max_pixels);
        if factor == 1 {
            return self;
        }
        Self {
            data: box_shrink(&self.data, self.width, self.height, RGB_CHANNELS, factor),
            width: self.width / factor,
            height: self.height / factor,
        }
    }

    /// One byte of Rec. 601 luma per pixel, what a QR decoder reads.
    pub fn grey(&self) -> Image {
        Image {
            data: self
                .data
                .chunks_exact(RGB_CHANNELS)
                .map(|pixel| {
                    ((u16::from(pixel[0]) * 77
                        + u16::from(pixel[1]) * 150
                        + u16::from(pixel[2]) * 29)
                        >> 8) as u8
                })
                .collect(),
            width: self.width,
            height: self.height,
        }
    }
}

/// A published frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub rgb: Rgb,
    /// Starts at 1 and grows by one per frame, so a reader that keeps the last one it
    /// read skips a frame it has seen.
    pub seq: u64,
}

pub(crate) fn unreadable() -> Error {
    Error::Capture("the camera returned an unreadable frame".to_owned())
}

/// AVFoundation may pad each row of `width` x `height` RGB888 pixels: the padding is
/// dropped. None when `raw` is shorter than a row or not whole rows.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn pack_rows(raw: Vec<u8>, width: u32, height: u32) -> Option<Vec<u8>> {
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
        frame::{pack_rows, unreadable, Rgb},
        Error,
    };

    fn rgb(data: Vec<u8>, width: u32, height: u32) -> Rgb {
        Rgb {
            data,
            width,
            height,
        }
    }

    #[test]
    fn yuyv_converts_two_pixels_per_four_bytes() {
        // Y0 U Y1 V with no chroma: (Y - 16) * 298 / 256, rounded
        let raw = [16, 128, 235, 128];
        assert_eq!(
            Rgb::convert(FrameFormat::YUYV, 2, 1, &raw).unwrap(),
            rgb(vec![0, 0, 0, 255, 255, 255], 2, 1)
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
                2,
                2
            )
        );
    }

    #[test]
    fn grey_is_spread_over_the_three_channels() {
        assert_eq!(
            Rgb::convert(FrameFormat::GRAY, 2, 1, &[7, 9]).unwrap(),
            rgb(vec![7, 7, 7, 9, 9, 9], 2, 1)
        );
    }

    #[test]
    fn raw_rgb_is_kept_and_raw_bgr_is_swapped() {
        assert_eq!(
            Rgb::convert(FrameFormat::RAWRGB, 1, 1, &[1, 2, 3]).unwrap(),
            rgb(vec![1, 2, 3], 1, 1)
        );
        assert_eq!(
            Rgb::convert(FrameFormat::RAWBGR, 1, 1, &[1, 2, 3]).unwrap(),
            rgb(vec![3, 2, 1], 1, 1)
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

    #[test]
    fn a_frame_within_the_limit_is_kept_as_is() {
        let frame = rgb((0..24).collect(), 4, 2);
        assert_eq!(frame.clone().shrink(8), frame);
    }

    #[test]
    fn a_frame_above_the_limit_is_averaged_by_the_smallest_factor_that_fits() {
        // pixel n of a 4 x 2 frame is (n, 10 n, 255 - n)
        let frame = rgb((0..8u8).flat_map(|n| [n, 10 * n, 255 - n]).collect(), 4, 2);
        assert_eq!(frame.shrink(7), rgb(vec![2, 25, 252, 4, 45, 250], 2, 1));
    }

    #[test]
    fn grey_weighs_green_most_and_blue_least() {
        let grey = rgb(vec![255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255], 2, 2).grey();
        assert_eq!(grey.data, vec![76, 149, 28, 255]);
        assert_eq!((grey.width, grey.height), (2, 2));
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
