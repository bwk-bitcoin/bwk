use nokhwa::{utils::CameraFormat, NokhwaError};

use crate::mode::describe;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no camera was found")]
    NoCamera,
    #[error("the camera is already in use")]
    Busy,
    #[error(
        "no camera mode meets the minimum resolution and frame rate, offered: {}",
        describe(offered)
    )]
    NoSuitableMode { offered: Vec<CameraFormat> },
    /// Refused, or not answered in time.
    #[error("camera permission refused")]
    PermissionDenied,
    #[error("camera capture failed: {0}")]
    Capture(String),
}

/// nokhwa reports every failure as text, so the kinds a caller acts on are told apart
/// by it.
impl From<NokhwaError> for Error {
    fn from(error: NokhwaError) -> Self {
        let text = error.to_string();
        let lowercase = text.to_ascii_lowercase();
        if lowercase.contains("permission") || lowercase.contains("denied") {
            Self::PermissionDenied
        } else if lowercase.contains("busy") || lowercase.contains("in use") {
            Self::Busy
        } else if lowercase.contains("not found") || lowercase.contains("no camera") {
            Self::NoCamera
        } else {
            Self::Capture(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use nokhwa::utils::{CameraFormat, FrameFormat};

    use crate::error::Error;

    #[test]
    fn no_suitable_mode_lists_the_modes_offered() {
        let error = Error::NoSuitableMode {
            offered: vec![
                CameraFormat::new_from(640, 480, FrameFormat::MJPEG, 30),
                CameraFormat::new_from(320, 240, FrameFormat::YUYV, 15),
            ],
        };
        assert_eq!(
            error.to_string(),
            "no camera mode meets the minimum resolution and frame rate, offered: \
             640x480@30 MJPEG, 320x240@15 YUYV"
        );
    }
}
