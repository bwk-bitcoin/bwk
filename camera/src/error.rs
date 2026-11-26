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

#[cfg(not(target_os = "windows"))]
impl From<NokhwaError> for Error {
    fn from(error: NokhwaError) -> Self {
        Self::Capture(error.to_string())
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
}
