#[cfg(feature = "bbqr")]
use bwk_bbqr::Encoding;

/// The size of a QR code, named after its side in modules (the black and white squares):
/// a code of size `Sn` is n modules wide and n high. The QR spec (ISO 18004) calls this
/// the version, from 1 to 40, a code of version v being 17 + 4 * v modules wide, so
/// `S21` is version 1 and `S177` version 40.
///
/// A bigger code holds more data, but it has more modules to show and to read back: it
/// needs more pixels on screen to give each module enough of them, and more pixels in
/// the camera frame for each module to be told apart.
///
/// To pick one, divide the display's shorter side by the pixels each module gets, at
/// least 2 and better 3 or more, and take the largest size whose width plus 8 (the quiet
/// zone, 4 modules on each side) fits. Common choices:
/// - `S33` on a 128 pixel display, at 3 pixels per module;
/// - `S57` on a 240x135 signer screen, at 2 pixels per module;
/// - `S125` on a phone or a desktop window;
/// - `S177`, the most data per frame, on a large display.
///
/// [`QrDensity`] is the coarse alternative, five of these sizes for a UI setting.
///
/// The [`Encoder`](crate::encoder::Encoder) takes the size it is built with as a ceiling.
/// It renders a plain text code at the smallest size it fits. It cuts a BBQR payload into
/// as few parts as that ceiling allows, all of equal length, and renders every frame of
/// the series at one size, the smallest that holds such a part: the ceiling when the
/// parts fill it, a smaller size when they do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrSize {
    S21 = 1,
    S25,
    S29,
    S33,
    S37,
    S41,
    S45,
    S49,
    S53,
    S57,
    S61,
    S65,
    S69,
    S73,
    S77,
    S81,
    S85,
    S89,
    S93,
    S97,
    S101,
    S105,
    S109,
    S113,
    S117,
    S121,
    S125,
    S129,
    S133,
    S137,
    S141,
    S145,
    S149,
    S153,
    S157,
    S161,
    S165,
    S169,
    S173,
    S177,
}

impl QrSize {
    pub fn modules(self) -> u32 {
        17 + 4 * u32::from(self.version())
    }

    pub fn version(self) -> u8 {
        self as u8
    }

    /// The size of `version`, None outside 1 to 40.
    pub fn from_version(version: u8) -> Option<Self> {
        Some(match version {
            1 => Self::S21,
            2 => Self::S25,
            3 => Self::S29,
            4 => Self::S33,
            5 => Self::S37,
            6 => Self::S41,
            7 => Self::S45,
            8 => Self::S49,
            9 => Self::S53,
            10 => Self::S57,
            11 => Self::S61,
            12 => Self::S65,
            13 => Self::S69,
            14 => Self::S73,
            15 => Self::S77,
            16 => Self::S81,
            17 => Self::S85,
            18 => Self::S89,
            19 => Self::S93,
            20 => Self::S97,
            21 => Self::S101,
            22 => Self::S105,
            23 => Self::S109,
            24 => Self::S113,
            25 => Self::S117,
            26 => Self::S121,
            27 => Self::S125,
            28 => Self::S129,
            29 => Self::S133,
            30 => Self::S137,
            31 => Self::S141,
            32 => Self::S145,
            33 => Self::S149,
            34 => Self::S153,
            35 => Self::S157,
            36 => Self::S161,
            37 => Self::S165,
            38 => Self::S169,
            39 => Self::S173,
            40 => Self::S177,
            _ => return None,
        })
    }

    /// The chars a code of exactly this size holds in alphanumeric mode at error
    /// correction Low, the longest BBQR part it renders: the data codewords of the size
    /// (ISO 18004 Table 7), less the 4 bit mode indicator and the character count field,
    /// hold 2 characters per 11 bits and a last odd one in 6.
    #[cfg(feature = "bbqr")]
    pub(crate) fn alphanumeric_chars(self) -> usize {
        let count_bits = match self.version() {
            1..=9 => 9,
            10..=26 => 11,
            _ => 13,
        };
        let bits = DATA_CODEWORDS_ECC_LOW[usize::from(self.version()) - 1] * 8 - 4 - count_bits;
        2 * (bits / 11) + usize::from(bits % 11 >= 6)
    }

    /// The largest BBQR part, in bytes, whose part string fits a code of exactly this
    /// size: after the BBQR header, each byte takes two hex characters.
    #[cfg(feature = "bbqr")]
    pub fn bbqr_part_bytes(self) -> usize {
        Encoding::Hex.part_bytes(self.alphanumeric_chars())
    }

    /// The smallest size, up to this one, that holds a BBQR part of `part_len` chars, and
    /// this one when none does.
    #[cfg(feature = "bbqr")]
    pub(crate) fn smallest_for_bbqr_part(self, part_len: usize) -> Self {
        (1..self.version())
            .filter_map(Self::from_version)
            .find(|size| size.alphanumeric_chars() >= part_len)
            .unwrap_or(self)
    }
}

#[cfg(feature = "bbqr")]
const DATA_CODEWORDS_ECC_LOW: [usize; 40] = [
    19, 34, 55, 80, 108, 136, 156, 194, 232, 274, 324, 370, 428, 461, 523, 589, 647, 721, 795, 861,
    932, 1006, 1094, 1174, 1276, 1370, 1468, 1531, 1631, 1735, 1843, 1955, 2071, 2191, 2306, 2434,
    2566, 2702, 2812, 2956,
];

/// A coarse choice of [`QrSize`] for a UI setting, each level a QR size. A denser level
/// means fewer, bigger BBQR frames, that need a sharper camera to be read. Per BBQR
/// frame, a level holds at most:
/// - `Lowest`, `S33`: 53 bytes;
/// - `Low`, `S45`: 108 bytes;
/// - `Medium`, `S53`: 163 bytes;
/// - `High`, `S61`: 230 bytes;
/// - `Highest`, `S65`: 263 bytes.
///
/// A payload whose equal parts do not fill the level's size renders at a smaller one, see
/// [`QrSize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum QrDensity {
    Lowest,
    Low,
    Medium,
    High,
    Highest,
}

impl From<QrDensity> for QrSize {
    fn from(density: QrDensity) -> Self {
        match density {
            QrDensity::Lowest => QrSize::S33,
            QrDensity::Low => QrSize::S45,
            QrDensity::Medium => QrSize::S53,
            QrDensity::High => QrSize::S61,
            QrDensity::Highest => QrSize::S65,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderConfig {
    /// Scan at the frame's highest definition instead of the default, which shrinks a
    /// frame toward [`SCAN_SIDE`](crate::image::SCAN_SIDE).
    pub fine_scan: bool,
    /// Also scan each frame with its grey values flipped, to read a light-on-dark code.
    pub scan_inverted: bool,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            fine_scan: false,
            scan_inverted: true,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use crate::config::QrDensity;

    #[test]
    fn density_is_written_in_snake_case() {
        let json = serde_json::to_string(&QrDensity::Highest).unwrap();
        assert_eq!(json, "\"highest\"");
        assert_eq!(
            serde_json::from_str::<QrDensity>(&json).unwrap(),
            QrDensity::Highest
        );
    }
}
