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
    if !QrSegment::is_alphanumeric(data) {
        return Err(Error::PartNotAlphanumeric);
    }
    let version = Version::new(size.into().version());
    let segment = QrSegment::make_alphanumeric(data);
    QrCode::encode_segments_advanced(&[segment], QrCodeEcc::Low, version, version, None, false)
        .map(qr_to_image)
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
