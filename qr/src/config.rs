#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub max_qr_version: u8,
    /// Must fit `max_qr_version` once rendered as an alphanumeric BBQR part.
    pub bbqr_part_bytes: usize,
    pub max_image_pixels: usize,
    pub max_message_bytes: usize,
    pub scan_inverted: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_qr_version: 27,
            bbqr_part_bytes: 1024,
            max_image_pixels: 1024 * 1024,
            max_message_bytes: 512 * 1024,
            scan_inverted: true,
        }
    }
}
