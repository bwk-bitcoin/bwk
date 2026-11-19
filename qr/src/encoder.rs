use crate::{config::QrSize, error::Error, gen, image::Image};

#[derive(Debug, Clone)]
pub struct Encoder {
    size: QrSize,
}

impl Encoder {
    /// Takes a [`QrSize`] or a [`QrDensity`](crate::config::QrDensity): the largest size
    /// of a plain text code, and the size of every BBQR frame.
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

    /// Splits any payload into BBQR generic-binary parts, one frame each.
    #[cfg(feature = "bbqr")]
    pub fn encode_bbqr(&self, data: &[u8]) -> Result<Vec<Image>, Error> {
        let split = bwk_bbqr::split(data, self.size.bbqr_part_bytes())?;
        split
            .parts
            .iter()
            .map(|part| gen::encode_alphanumeric(part, self.size))
            .collect()
    }
}

#[cfg(all(test, feature = "bbqr"))]
mod tests {
    use crate::{
        config::{QrDensity, QrSize},
        encoder::Encoder,
        gen::{self, MODULE_SCALE, QUIET_ZONE},
    };

    const SIZES: [(QrSize, usize); 4] = [
        (QrSize::S21, 8),
        (QrSize::S53, 163),
        (QrSize::S125, 1062),
        (QrSize::S177, 2144),
    ];

    fn part_fits(part_bytes: usize, size: impl Into<QrSize>) -> bool {
        let size = size.into();
        bwk_bbqr::split(&vec![0; part_bytes], part_bytes)
            .is_ok_and(|split| gen::encode_alphanumeric(&split.parts[0], size).is_ok())
    }

    #[test]
    fn the_smallest_size_holds_the_smallest_bbqr_part() {
        assert_eq!(QrSize::S21.bbqr_part_bytes(), bwk_bbqr::MIN_PART_BYTES);
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
    fn every_bbqr_frame_has_the_width_of_its_size() {
        for (size, bytes) in SIZES {
            let width = (size.modules() + 2 * QUIET_ZONE as u32) * MODULE_SCALE as u32;
            let frames = Encoder::new(size)
                .encode_bbqr(&vec![7; 2 * bytes + 1])
                .unwrap();
            for frame in frames {
                assert_eq!(frame.side(), width, "{size:?}");
            }
        }
    }
}
