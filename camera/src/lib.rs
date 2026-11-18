//! Camera capture for QR scanning.
//!
//! [`list`] offers the cameras that capture video, [`Camera::start`] streams one on a
//! capture thread that keeps only the latest frame. The tuning stays the caller's: the
//! minimum mode and the frame pixel limit come in [`Config`], how often frames are read
//! and decoded is up to the reader.

mod capture;
mod error;
mod frame;
#[cfg(target_os = "macos")]
mod macos;
mod mode;
#[cfg(not(target_os = "macos"))]
mod native;

pub use capture::{list, Camera, CameraInfo};
pub use error::Error;
pub use frame::{Frame, Rgb};
pub use nokhwa::utils::CameraFormat;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The smallest mode a camera is streamed at.
    pub min_width: u32,
    pub min_height: u32,
    pub min_fps: u32,
    /// A larger frame is shrunk to fit before it is published.
    pub max_pixels: usize,
}
