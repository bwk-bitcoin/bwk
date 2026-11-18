use nokhwa::{utils::CameraFormat, NokhwaError};

use crate::mode::describe;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("no camera was found")]
    NoCamera,
    #[error("the camera is already in use")]
    Busy,
    #[error(
        "no camera mode meets the minimum side and frame rate, offered: {}",
        describe(offered)
    )]
    NoSuitableMode { offered: Vec<CameraFormat> },
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
        } else if lowercase.contains("not found")
            || lowercase.contains("no camera")
            || lowercase.contains("no such file or directory")
            || lowercase.contains("no such device")
            || lowercase.contains("device is null")
        {
            Self::NoCamera
        } else {
            Self::Capture(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use nokhwa::{
        utils::{CameraFormat, FrameFormat},
        NokhwaError,
    };

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
            "no camera mode meets the minimum side and frame rate, offered: \
             640x480@30 MJPEG, 320x240@15 YUYV"
        );
    }

    #[test]
    fn a_missing_linux_device_is_no_camera() {
        for reason in [
            "No such file or directory (os error 2)",
            "No such device (os error 19)",
        ] {
            let error =
                NokhwaError::OpenDeviceError("0".to_string(), format!("V4L2 Error: {reason}"));
            assert_eq!(Error::from(error), Error::NoCamera, "{reason}");
        }
    }

    #[test]
    fn a_camera_gone_since_the_list_is_no_camera() {
        // what Media Foundation, then AVFoundation, report for an id no longer present
        for reason in ["Not Found", "Device is null"] {
            let error = NokhwaError::OpenDeviceError("id".to_string(), reason.to_string());
            assert_eq!(Error::from(error), Error::NoCamera, "{reason}");
        }
    }
}
