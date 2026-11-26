#[cfg(feature = "bbqr")]
use bwk_bbqr::{Encoding, Split};

use crate::{config::QrSize, error::Error, gen, image::Image};

#[derive(Debug, Clone)]
pub struct Encoder {
    size: QrSize,
    #[cfg(feature = "bbqr")]
    encoding: Encoding,
}

impl Encoder {
    /// Takes a [`QrSize`] or a [`QrDensity`](crate::config::QrDensity): the largest size
    /// of a plain text code and of a BBQR frame. BBQR parts are written in zlib unless
    /// [`Encoder::with_bbqr_encoding`] says otherwise.
    pub fn new(size: impl Into<QrSize>) -> Self {
        Self {
            size: size.into(),
            #[cfg(feature = "bbqr")]
            encoding: Encoding::Zlib,
        }
    }

    /// Writes the BBQR parts in `encoding` rather than in zlib, which compresses the
    /// payload first and writes one that does not shrink in base32: the fewest frames.
    /// Base32 as such skips the compression. Hex takes 10 chars per 5 bytes where base32
    /// takes 8, so a frame carries a fifth less, but it is the one encoding a reader
    /// that knows no other reads.
    #[cfg(feature = "bbqr")]
    pub fn with_bbqr_encoding(mut self, encoding: Encoding) -> Self {
        self.encoding = encoding;
        self
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

    /// Splits any payload into BBQR generic-binary parts, one frame each, in the encoder's
    /// encoding: as few parts as the encoder's size allows, all of equal length but a last
    /// one that may be shorter.
    ///
    /// Every frame has the same size, the smallest that holds the longest part, so the
    /// series is smaller than the encoder's size when its parts do not fill it. A frame
    /// whose part leaves room at that size takes a higher error correction level, which
    /// frames of one series may then not share.
    #[cfg(feature = "bbqr")]
    pub fn encode_bbqr(&self, data: &[u8]) -> Result<Vec<Image>, Error> {
        let split = self.split(data)?;
        let size = self.size.smallest_for_bbqr_part(split.part_len());
        split
            .parts
            .iter()
            .map(|part| gen::encode_alphanumeric(part, size))
            .collect()
    }

    /// The BBQR parts of `data`, none longer than a code of the encoder's size holds.
    #[cfg(feature = "bbqr")]
    fn split(&self, data: &[u8]) -> Result<Split, Error> {
        let max_part_len = self.size.alphanumeric_chars();
        Ok(bwk_bbqr::split(data, self.encoding, max_part_len)?)
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

    /// Sizes, each with the bytes a part carries in it in hex, then in base32.
    const SIZES: [(QrSize, usize, usize); 4] = [
        (QrSize::S21, 8, 10),
        (QrSize::S53, 163, 200),
        (QrSize::S125, 1062, 1325),
        (QrSize::S177, 2144, 2680),
    ];
    const ENCODINGS: [Encoding; 3] = [Encoding::Hex, Encoding::Base32, Encoding::Zlib];

    fn encoder(size: QrSize, encoding: Encoding) -> Encoder {
        Encoder::new(size).with_bbqr_encoding(encoding)
    }

    /// `SIZES` for `encoding`, hex or base32.
    fn sizes(encoding: Encoding) -> [(QrSize, usize); 4] {
        SIZES.map(|(size, hex, base32)| match encoding {
            Encoding::Hex => (size, hex),
            _ => (size, base32),
        })
    }

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

    /// Whether a part of `chars` chars renders at `size`.
    fn part_fits(chars: usize, size: QrSize) -> bool {
        gen::encode_alphanumeric(&"A".repeat(chars), size).is_ok()
    }

    // the encoder's size, the payload bytes, then its frames and the size of each
    fn assert_series(encoding: Encoding, cases: &[(QrSize, usize, usize, QrSize)]) {
        for (size, bytes, count, rendered) in cases {
            let case = format!("{bytes} bytes at {size:?} in {encoding:?}");
            let frames = encoder(*size, encoding)
                .encode_bbqr(&vec![7; *bytes])
                .unwrap();
            assert_eq!(frames.len(), *count, "{case}");
            assert_eq!(series_size(&frames), *rendered, "{case}");
        }
    }

    #[test]
    fn the_smallest_size_holds_the_smallest_bbqr_part() {
        assert_eq!(QrSize::S21.alphanumeric_chars(), MIN_PART_LEN);
    }

    #[test]
    fn a_part_fills_its_size() {
        for (size, hex, base32) in SIZES {
            assert_eq!(size.bbqr_part_bytes(Encoding::Hex), hex, "{size:?}");
            assert_eq!(size.bbqr_part_bytes(Encoding::Base32), base32, "{size:?}");
            assert_eq!(size.bbqr_part_bytes(Encoding::Zlib), base32, "{size:?}");
        }
    }

    #[test]
    fn every_size_fits_its_part_and_not_one_char_more() {
        for version in 1..=40 {
            let size = QrSize::from_version(version).unwrap();
            assert_eq!(size.version(), version);
            let chars = size.alphanumeric_chars();
            assert!(part_fits(chars, size), "{size:?}");
            assert!(!part_fits(chars + 1, size), "{size:?}");
            // a byte more in hex, or 5 more in base32, is a part too long for the size
            let hex = size.bbqr_part_bytes(Encoding::Hex);
            assert!(HEADER_LEN + 2 * hex <= chars, "{size:?}");
            assert!(HEADER_LEN + 2 * (hex + 1) > chars, "{size:?}");
            let base32 = size.bbqr_part_bytes(Encoding::Base32);
            assert!(HEADER_LEN + base32 / 5 * 8 <= chars, "{size:?}");
            assert!(HEADER_LEN + (base32 / 5 + 1) * 8 > chars, "{size:?}");
        }
        assert_eq!(QrSize::from_version(0), None);
        assert_eq!(QrSize::from_version(41), None);
    }

    // each level holds the bytes it carried per BBQR frame when it was a byte count of hex
    // parts, and the next smaller size does not
    #[test]
    fn a_density_is_the_smallest_size_holding_its_former_part_bytes() {
        let densities = [
            (QrDensity::Lowest, QrSize::S29, QrSize::S33, 50, 53, 65),
            (QrDensity::Low, QrSize::S41, QrSize::S45, 100, 108, 135),
            (QrDensity::Medium, QrSize::S49, QrSize::S53, 150, 163, 200),
            (QrDensity::High, QrSize::S57, QrSize::S61, 200, 230, 285),
            (QrDensity::Highest, QrSize::S61, QrSize::S65, 250, 263, 325),
        ];
        for (density, smaller, size, former, hex, base32) in densities {
            assert_eq!(QrSize::from(density), size, "{density:?}");
            assert_eq!(smaller.version() + 1, size.version(), "{density:?}");
            assert_eq!(size.bbqr_part_bytes(Encoding::Hex), hex, "{density:?}");
            assert_eq!(size.bbqr_part_bytes(Encoding::Base32), base32);
            assert!(hex >= former, "{density:?}");
            assert!(
                smaller.bbqr_part_bytes(Encoding::Hex) < former,
                "{density:?}"
            );
        }
    }

    #[test]
    fn a_payload_splits_at_the_part_size_of_its_size() {
        for encoding in [Encoding::Hex, Encoding::Base32] {
            for (size, bytes) in sizes(encoding) {
                let encoder = encoder(size, encoding);
                assert_eq!(encoder.encode_bbqr(&vec![7; 2 * bytes]).unwrap().len(), 2);
                assert_eq!(
                    encoder.encode_bbqr(&vec![7; 2 * bytes + 1]).unwrap().len(),
                    3
                );
            }
        }
    }

    #[test]
    fn parts_that_fill_the_size_render_at_it() {
        for encoding in [Encoding::Hex, Encoding::Base32] {
            for (size, bytes) in sizes(encoding) {
                let frames = encoder(size, encoding)
                    .encode_bbqr(&vec![7; 2 * bytes])
                    .unwrap();
                assert_eq!(series_size(&frames), size);
            }
        }
    }

    #[test]
    fn a_series_renders_at_the_smallest_size_holding_its_parts() {
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
        assert_series(Encoding::Hex, &cases);
    }

    #[test]
    fn a_base32_series_renders_at_the_smallest_size_holding_its_parts() {
        let cases = [
            (QrSize::S53, 1, 1, QrSize::S21),
            (QrSize::S53, 43, 1, QrSize::S29),
            (QrSize::S53, 44, 1, QrSize::S33),
            (QrSize::S53, 200, 1, QrSize::S53),
            // a sole part needs not end on 5 bytes, and holds 4 more
            (QrSize::S53, 204, 1, QrSize::S53),
            (QrSize::S53, 205, 2, QrSize::S41),
            (QrSize::S53, 400, 2, QrSize::S53),
            (QrSize::S53, 401, 3, QrSize::S45),
            (QrSize::S53, 500, 3, QrSize::S53),
            (QrSize::S53, 1000, 5, QrSize::S53),
            (QrSize::S33, 66, 1, QrSize::S33),
            (QrSize::S33, 67, 2, QrSize::S29),
            (QrSize::S33, 131, 3, QrSize::S33),
            (QrSize::S65, 330, 2, QrSize::S49),
            (QrSize::S65, 651, 3, QrSize::S57),
            (QrSize::S65, 1000, 4, QrSize::S61),
            // 10 parts of 20 bytes and a last one of 17
            (QrSize::S25, 217, 11, QrSize::S25),
        ];
        assert_series(Encoding::Base32, &cases);
    }

    #[test]
    fn every_frame_of_a_series_has_one_width_within_the_size() {
        for encoding in ENCODINGS {
            for size in [QrSize::S21, QrSize::S33] {
                let encoder = encoder(size, encoding);
                for bytes in 1..=3 * size.bbqr_part_bytes(encoding) + 1 {
                    let frames = encoder.encode_bbqr(&vec![7; bytes]).unwrap();
                    let rendered = series_size(&frames);
                    assert!(rendered.version() <= size.version(), "{bytes} bytes");
                }
            }
        }
    }

    // 7 frames in hex and 5 in base32
    #[test]
    fn a_payload_that_shrinks_takes_fewer_frames_in_zlib() {
        let encoder = encoder(QrSize::S53, Encoding::Zlib);
        let payload = vec![7; 1000];
        assert_eq!(encoder.split(&payload).unwrap().encoding, Encoding::Zlib);
        let frames = encoder.encode_bbqr(&payload).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(series_size(&frames), QrSize::S21);
    }

    #[test]
    fn a_payload_that_does_not_shrink_is_written_in_base32() {
        let payload = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let zlib = encoder(QrSize::S21, Encoding::Zlib);
        let base32 = encoder(QrSize::S21, Encoding::Base32);
        assert_eq!(zlib.split(&payload).unwrap().encoding, Encoding::Base32);
        assert_eq!(zlib.split(&payload), base32.split(&payload));
        assert_eq!(zlib.encode_bbqr(&payload).unwrap().len(), 2);
    }

    #[test]
    fn parts_are_compressed_unless_told_otherwise() {
        let split = Encoder::new(QrSize::S53).split(&[7; 100]).unwrap();
        assert_eq!(split.encoding, Encoding::Zlib);
        let hex = encoder(QrSize::S53, Encoding::Hex);
        assert_eq!(hex.split(&[7; 100]).unwrap().encoding, Encoding::Hex);
    }
}
