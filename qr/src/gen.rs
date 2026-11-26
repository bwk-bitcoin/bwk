use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

use crate::{config::QrSize, error::Error, image::Image};

pub const QUIET_ZONE: i32 = 4;
pub const MODULE_SCALE: i32 = 4;

pub fn encode_text(data: &str, max_size: impl Into<QrSize>) -> Result<Image, Error> {
    let max_size = max_size.into();
    let segments = QrSegment::make_segments(data);
    QrCode::encode_segments_advanced(
        &segments,
        QrCodeEcc::Low,
        Version::MIN,
        Version::new(max_size.version()),
        None,
        true,
    )
    .map(qr_to_image)
    .map_err(|_| Error::TooLong)
}

#[cfg(feature = "bbqr")]
pub fn encode_alphanumeric(data: &str, size: impl Into<QrSize>) -> Result<Image, Error> {
    alphanumeric_code(data, size.into()).map(qr_to_image)
}

/// `data` in a code of exactly `size`, at the highest error correction level it fits
/// there: Low when it fills the size, a higher one when it leaves room. The level never
/// changes the size.
#[cfg(feature = "bbqr")]
fn alphanumeric_code(data: &str, size: QrSize) -> Result<QrCode, Error> {
    if !QrSegment::is_alphanumeric(data) {
        return Err(Error::PartNotAlphanumeric);
    }
    let version = Version::new(size.version());
    let segment = QrSegment::make_alphanumeric(data);
    QrCode::encode_segments_advanced(&[segment], QrCodeEcc::Low, version, version, None, true)
        .map_err(|_| Error::TooLong)
}

pub fn qr_to_image(qr: QrCode) -> Image {
    let size = (qr.size() + QUIET_ZONE * 2) * MODULE_SCALE;
    let module = |at: u32| at as i32 / MODULE_SCALE - QUIET_ZONE;
    Image::from_fn(size as u32, |x, y| {
        if qr.get_module(module(x), module(y)) {
            0
        } else {
            255
        }
    })
}

#[cfg(all(test, feature = "bbqr"))]
mod tests {
    use bwk_bbqr::{Encoding, HEADER_LEN};
    use qrcodegen::QrCodeEcc;

    use crate::{config::QrSize, gen::alphanumeric_code};

    #[test]
    fn a_part_takes_the_highest_error_correction_its_size_has_room_for() {
        let cases = [
            (1, QrSize::S21, QrCodeEcc::High),
            (40, QrSize::S33, QrCodeEcc::Medium),
            (53, QrSize::S33, QrCodeEcc::Low),
        ];
        for (bytes, size, level) in cases {
            let part_len = HEADER_LEN + 2 * bytes;
            let split = bwk_bbqr::split(&vec![7; bytes], Encoding::Hex, part_len).unwrap();
            let code = alphanumeric_code(&split.parts[0], size).unwrap();
            assert_eq!(code.version().value(), size.version(), "{bytes} bytes");
            assert_eq!(code.error_correction_level(), level, "{bytes} bytes");
        }
    }
}
