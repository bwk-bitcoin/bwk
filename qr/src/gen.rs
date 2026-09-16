use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

use crate::{error::Error, image::Image};

const QUIET_ZONE: i32 = 4;
const MODULE_SCALE: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectionLevel {
    Low,
    Medium,
    Quartile,
    High,
}

impl From<CorrectionLevel> for QrCodeEcc {
    fn from(level: CorrectionLevel) -> Self {
        match level {
            CorrectionLevel::Low => QrCodeEcc::Low,
            CorrectionLevel::Medium => QrCodeEcc::Medium,
            CorrectionLevel::Quartile => QrCodeEcc::Quartile,
            CorrectionLevel::High => QrCodeEcc::High,
        }
    }
}

pub fn encode_text(data: &str, level: CorrectionLevel, max_version: u8) -> Result<Image, Error> {
    let segments = QrSegment::make_segments(data);
    QrCode::encode_segments_advanced(
        &segments,
        level.into(),
        Version::MIN,
        Version::new(max_version),
        None,
        true,
    )
    .map(qr_to_image)
    .map_err(|_| Error::TooLong)
}

#[cfg(feature = "protocol")]
pub fn encode_alphanumeric(data: &str, version: u8) -> Result<Image, Error> {
    if !QrSegment::is_alphanumeric(data) {
        return Err(Error::PartNotAlphanumeric);
    }
    let version = Version::new(version);
    let segment = QrSegment::make_alphanumeric(data);
    QrCode::encode_segments_advanced(&[segment], QrCodeEcc::Low, version, version, None, false)
        .map(qr_to_image)
        .map_err(|_| Error::TooLong)
}

fn qr_to_image(qr: QrCode) -> Image {
    let qr_size = qr.size();
    let modules = qr_size + QUIET_ZONE * 2;
    let size = modules * MODULE_SCALE;
    let mut data = Vec::with_capacity((size * size) as usize);
    for y in -QUIET_ZONE..qr_size + QUIET_ZONE {
        for _ in 0..MODULE_SCALE {
            for x in -QUIET_ZONE..qr_size + QUIET_ZONE {
                let value = if qr.get_module(x, y) { 0 } else { 255 };
                for _ in 0..MODULE_SCALE {
                    data.push(value);
                }
            }
        }
    }
    Image {
        data,
        width: size as u32,
        height: size as u32,
    }
}
