#[cfg(not(target_os = "windows"))]
use nokhwa::NokhwaError;
#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::E_ACCESSDENIED,
    Media::MediaFoundation::{
        MF_E_HW_MFT_FAILED_START_STREAMING, MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED,
        MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED,
    },
};

use crate::mode::{describe, Mode};

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
    NoSuitableMode { offered: Vec<Mode> },
    #[error("camera permission refused")]
    PermissionDenied,
    #[error("camera capture failed: {0}")]
    Capture(String),
}

/// nokhwa reports every failure as text, so the kinds a caller acts on are told apart
/// by it.
#[cfg(not(target_os = "windows"))]
impl From<NokhwaError> for Error {
    fn from(error: NokhwaError) -> Self {
        let text = error.to_string();
        let lowercase = text.to_ascii_lowercase();
        if lowercase.contains("permission") || lowercase.contains("denied") {
            Self::PermissionDenied
        } else if lowercase.contains("busy") || lowercase.contains("in use") {
            Self::Busy
        } else if lowercase.contains("no camera")
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

/// Access refused in the Windows privacy settings, a camera another app streams from, or
/// one unplugged while it streamed.
#[cfg(target_os = "windows")]
impl From<windows::core::Error> for Error {
    fn from(error: windows::core::Error) -> Self {
        match error.code() {
            E_ACCESSDENIED => Self::PermissionDenied,
            MF_E_HW_MFT_FAILED_START_STREAMING | MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED => {
                Self::Busy
            }
            MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED => Self::NoCamera,
            _ => Self::Capture(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    use nokhwa::NokhwaError;

    use crate::{
        error::Error,
        mode::{Format, Mode},
    };

    #[test]
    fn no_suitable_mode_lists_the_modes_offered() {
        let error = Error::NoSuitableMode {
            offered: vec![
                Mode {
                    width: 640,
                    height: 480,
                    frame_rate: 30,
                    format: Format::Mjpeg,
                },
                Mode {
                    width: 320,
                    height: 240,
                    frame_rate: 15,
                    format: Format::Yuyv,
                },
            ],
        };
        assert_eq!(
            error.to_string(),
            "no camera mode meets the minimum side and frame rate, offered: \
             640x480@30 MJPEG, 320x240@15 YUYV"
        );
    }

    #[cfg(not(target_os = "windows"))]
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn a_camera_gone_since_the_list_is_no_camera() {
        // what AVFoundation reports for an id no longer present
        let error = NokhwaError::OpenDeviceError("id".to_string(), "Device is null".to_string());
        assert_eq!(Error::from(error), Error::NoCamera);
    }
}
