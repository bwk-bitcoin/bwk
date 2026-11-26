#[cfg(feature = "bbqr")]
use bwk_bbqr::Encoding;

use crate::{config::QrSize, error::Error, gen, image::Image};

#[derive(Debug, Clone)]
pub struct Encoder {
    size: QrSize,
}

impl Encoder {
    /// Takes a [`QrSize`] or a [`QrDensity`](crate::config::QrDensity): the largest size
    /// of a plain text code and of a BBQR frame.
    pub fn new(size: impl Into<QrSize>) -> Self {
        Self { size: size.into() }
    }

    pub fn encode_text(&self, text: &str) -> Result<Image, Error> {
        gen::encode_text(text, self.size)
    }

    #[cfg(feature = "protocol")]
    pub fn encode_request(&self, request: &bipqr::ll::Request) -> Result<Vec<Image>, Error> {
        self.encode_bbqr(&bipqr::ll::encode_request(request)?)
    }

    #[cfg(feature = "protocol")]
    pub fn encode_response(&self, response: &bipqr::ll::Response) -> Result<Vec<Image>, Error> {
        self.encode_bbqr(&bipqr::ll::encode_response(response)?)
    }

    /// Splits any payload into BBQR generic-binary parts, one frame each: as few parts as
    /// the encoder's size allows, all of equal length but a last one that may be shorter.
    ///
    /// Every frame has the same size, the smallest that holds the longest part, so the
    /// series is smaller than the encoder's size when its parts do not fill it. A frame
    /// whose part leaves room at that size takes a higher error correction level, which
    /// frames of one series may then not share.
    #[cfg(feature = "bbqr")]
    pub fn encode_bbqr(&self, data: &[u8]) -> Result<Vec<Image>, Error> {
        let split = bwk_bbqr::split(data, Encoding::Hex, self.size.alphanumeric_chars())?;
        let size = self.size.smallest_for_bbqr_part(split.part_len());
        split
            .parts
            .iter()
            .map(|part| gen::encode_alphanumeric(part, size))
            .collect()
    }
}

#[cfg(all(test, feature = "bbqr"))]
mod tests {
    use bwk_bbqr::{Encoding, HEADER_LEN, MIN_PART_LEN};

    use crate::{
        config::{QrDensity, QrSize},
        encoder::Encoder,
        gen::{self, MODULE_SCALE, QUIET_ZONE},
        image::Image,
    };

    const SIZES: [(QrSize, usize); 4] = [
        (QrSize::S21, 8),
        (QrSize::S53, 163),
        (QrSize::S125, 1062),
        (QrSize::S177, 2144),
    ];

    fn width(size: QrSize) -> u32 {
        (size.modules() + 2 * QUIET_ZONE as u32) * MODULE_SCALE as u32
    }

    /// The one size every frame of `frames` is rendered at.
    fn series_size(frames: &[Image]) -> QrSize {
        let size = (1..=40)
            .filter_map(QrSize::from_version)
            .find(|size| width(*size) == frames[0].side())
            .unwrap();
        assert!(frames.iter().all(|frame| frame.side() == width(size)));
        size
    }

    fn part_fits(part_bytes: usize, size: impl Into<QrSize>) -> bool {
        let size = size.into();
        bwk_bbqr::split(
            &vec![0; part_bytes],
            Encoding::Hex,
            HEADER_LEN + 2 * part_bytes,
        )
        .is_ok_and(|split| gen::encode_alphanumeric(&split.parts[0], size).is_ok())
    }

    #[test]
    fn the_smallest_size_holds_the_smallest_bbqr_part() {
        assert_eq!(QrSize::S21.alphanumeric_chars(), MIN_PART_LEN);
    }

    #[test]
    fn a_part_fills_its_size() {
        for (size, bytes) in SIZES {
            assert_eq!(size.bbqr_part_bytes(), bytes, "{size:?}");
        }
    }

    #[test]
    fn every_size_fits_its_part_and_not_one_byte_more() {
        for version in 1..=40 {
            let size = QrSize::from_version(version).unwrap();
            assert_eq!(size.version(), version);
            let bytes = size.bbqr_part_bytes();
            assert!(part_fits(bytes, size), "{size:?}");
            assert!(!part_fits(bytes + 1, size), "{size:?}");
        }
        assert_eq!(QrSize::from_version(0), None);
        assert_eq!(QrSize::from_version(41), None);
    }

    // each level holds the bytes it carried per BBQR frame when it was a byte count, and
    // the next smaller size does not
    #[test]
    fn a_density_is_the_smallest_size_holding_its_former_part_bytes() {
        let densities = [
            (QrDensity::Lowest, QrSize::S29, QrSize::S33, 50, 53),
            (QrDensity::Low, QrSize::S41, QrSize::S45, 100, 108),
            (QrDensity::Medium, QrSize::S49, QrSize::S53, 150, 163),
            (QrDensity::High, QrSize::S57, QrSize::S61, 200, 230),
            (QrDensity::Highest, QrSize::S61, QrSize::S65, 250, 263),
        ];
        for (density, smaller, size, former, holds) in densities {
            assert_eq!(QrSize::from(density), size, "{density:?}");
            assert_eq!(smaller.version() + 1, size.version(), "{density:?}");
            assert_eq!(size.bbqr_part_bytes(), holds, "{density:?}");
            assert!(holds >= former, "{density:?}");
            assert!(smaller.bbqr_part_bytes() < former, "{density:?}");
        }
    }

    #[test]
    fn a_payload_splits_at_the_part_size_of_its_size() {
        for (size, bytes) in SIZES {
            let encoder = Encoder::new(size);
            assert_eq!(encoder.encode_bbqr(&vec![7; 2 * bytes]).unwrap().len(), 2);
            assert_eq!(
                encoder.encode_bbqr(&vec![7; 2 * bytes + 1]).unwrap().len(),
                3
            );
        }
    }

    #[test]
    fn parts_that_fill_the_size_render_at_it() {
        for (size, bytes) in SIZES {
            let frames = Encoder::new(size).encode_bbqr(&vec![7; 2 * bytes]).unwrap();
            assert_eq!(series_size(&frames), size);
        }
    }

    #[test]
    fn a_series_renders_at_the_smallest_size_holding_its_parts() {
        // the encoder's size, the payload bytes, then its frames and the size of each
        let cases = [
            (QrSize::S53, 1, 1, QrSize::S21),
            (QrSize::S53, 34, 1, QrSize::S29),
            (QrSize::S53, 35, 1, QrSize::S33),
            (QrSize::S53, 40, 1, QrSize::S33),
            (QrSize::S53, 163, 1, QrSize::S53),
            (QrSize::S53, 164, 2, QrSize::S41),
            (QrSize::S53, 326, 2, QrSize::S53),
            (QrSize::S53, 327, 3, QrSize::S49),
            (QrSize::S53, 500, 4, QrSize::S49),
            (QrSize::S53, 1000, 7, QrSize::S53),
            (QrSize::S53, 2000, 13, QrSize::S53),
            (QrSize::S33, 54, 2, QrSize::S29),
            (QrSize::S33, 107, 3, QrSize::S33),
            (QrSize::S65, 264, 2, QrSize::S49),
            (QrSize::S65, 527, 3, QrSize::S57),
            (QrSize::S65, 1000, 4, QrSize::S65),
            // 11 parts of 19 bytes and a last one of 8, that alone would fit S21
            (QrSize::S25, 217, 12, QrSize::S25),
        ];
        for (size, bytes, count, rendered) in cases {
            let frames = Encoder::new(size).encode_bbqr(&vec![7; bytes]).unwrap();
            assert_eq!(frames.len(), count, "{bytes} bytes at {size:?}");
            assert_eq!(series_size(&frames), rendered, "{bytes} bytes at {size:?}");
        }
    }

    #[test]
    fn every_frame_of_a_series_has_one_width_within_the_size() {
        for size in [QrSize::S21, QrSize::S33] {
            let encoder = Encoder::new(size);
            for bytes in 1..=3 * size.bbqr_part_bytes() + 1 {
                let frames = encoder.encode_bbqr(&vec![7; bytes]).unwrap();
                let rendered = series_size(&frames);
                assert!(rendered.version() <= size.version(), "{bytes} bytes");
            }
        }
    }
}
