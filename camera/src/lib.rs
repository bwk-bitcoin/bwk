//! Camera capture for QR scanning.
//!
//! [`capture::list`] offers the cameras that capture video on a receiver, without
//! blocking the caller while macOS asks for the camera permission. Each comes with its
//! [`capture::CameraId`], the OS's own identifier for the device, so cameras added or
//! removed meanwhile never make it open another one. [`capture::Camera::start`] streams
//! one on a capture thread that keeps only the latest frame, cropped to its centered
//! square, and [`capture::Camera::frame`] moves it out, so each frame is read once. The
//! tuning stays the caller's: the minimum frame rate and the fine scan toggle come in
//! [`Config`], how often frames are read and decoded is up to the reader.

pub mod capture;
pub mod error;
pub mod frame;
#[cfg(target_os = "macos")]
mod macos;
pub mod mode;
#[cfg(not(target_os = "macos"))]
mod native;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub min_fps: u32,
    /// The frame rate a mode is chosen at when none reaches `min_fps`, if lower.
    pub fallback_fps: Option<u32>,
    /// Stream and publish at the camera's highest definition instead of the default, which
    /// sticks to `bwk_qr::image::SCAN_SIDE`.
    pub fine_scan: bool,
}
