use quircs::Quirc;

use crate::{error::Error, image::Image};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub text: String,
    pub bytes: Vec<u8>,
}

pub fn scan(image: &Image, find_inverted: bool, max_pixels: usize) -> Result<Vec<Scanned>, Error> {
    if !image.validate_len() || image.data.len() > max_pixels {
        return Err(Error::BadFrame);
    }

    let mut decoded = scan_inner(image.width as usize, image.height as usize, &image.data);
    if find_inverted {
        let inverted = image.data.iter().map(|v| 255 - *v).collect::<Vec<_>>();
        for item in scan_inner(image.width as usize, image.height as usize, &inverted) {
            if !decoded.iter().any(|existing| existing.bytes == item.bytes) {
                decoded.push(item);
            }
        }
    }
    Ok(decoded)
}

// a camera frame routinely holds unreadable candidates, they must not sink the readable ones
fn scan_inner(width: usize, height: usize, data: &[u8]) -> Vec<Scanned> {
    let mut quirc = Quirc::default();
    let mut decoded = Vec::new();
    for code in quirc.identify(width, height, data) {
        let Ok(code) = code else { continue };
        let Ok(data) = code.decode() else { continue };
        decoded.push(Scanned {
            text: String::from_utf8_lossy(&data.payload).into_owned(),
            bytes: data.payload,
        });
    }
    decoded
}
