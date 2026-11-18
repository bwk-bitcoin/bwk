#[cfg(any(not(target_os = "macos"), test))]
use std::cmp::Reverse;

use nokhwa::utils::{CameraFormat, FrameFormat};

use crate::Config;

/// The formats a frame converts from without a JPEG decoder.
const RAW_FORMATS: [FrameFormat; 5] = [
    FrameFormat::YUYV,
    FrameFormat::NV12,
    FrameFormat::GRAY,
    FrameFormat::RAWRGB,
    FrameFormat::RAWBGR,
];

fn readable(format: FrameFormat) -> bool {
    RAW_FORMATS.contains(&format) || (cfg!(feature = "mjpeg") && format == FrameFormat::MJPEG)
}

pub(crate) fn qualifies(mode: &CameraFormat, config: &Config) -> bool {
    readable(mode.format())
        && mode.width() >= config.min_width
        && mode.height() >= config.min_height
        && mode.frame_rate() >= config.min_fps
}

/// Raw over MJPEG, then the lowest qualifying resolution, then the highest frame rate.
#[cfg(any(not(target_os = "macos"), test))]
pub(crate) fn choose_mode(offered: &[CameraFormat], config: &Config) -> Option<CameraFormat> {
    offered
        .iter()
        .copied()
        .filter(|mode| qualifies(mode, config))
        .min_by_key(|mode| {
            (
                mode.format() == FrameFormat::MJPEG,
                u64::from(mode.width()) * u64::from(mode.height()),
                Reverse(mode.frame_rate()),
            )
        })
}

/// `WxH@fps FORMAT`, comma separated.
pub(crate) fn describe(modes: &[CameraFormat]) -> String {
    modes
        .iter()
        .map(|mode| {
            format!(
                "{}x{}@{} {}",
                mode.width(),
                mode.height(),
                mode.frame_rate(),
                mode.format()
            )
        })
        .collect::<Vec<String>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use nokhwa::utils::{CameraFormat, FrameFormat};

    use crate::{
        mode::{choose_mode, describe},
        Config,
    };

    fn mode(width: u32, height: u32, fps: u32, format: FrameFormat) -> CameraFormat {
        CameraFormat::new_from(width, height, format, fps)
    }

    fn config() -> Config {
        Config {
            min_width: 1280,
            min_height: 720,
            min_fps: 10,
            max_pixels: 1024 * 1024,
        }
    }

    #[test]
    fn every_raw_format_qualifies() {
        for format in [
            FrameFormat::YUYV,
            FrameFormat::NV12,
            FrameFormat::GRAY,
            FrameFormat::RAWRGB,
            FrameFormat::RAWBGR,
        ] {
            let offered = [mode(1280, 720, 10, format)];
            assert_eq!(choose_mode(&offered, &config()), Some(offered[0]));
        }
    }

    #[test]
    fn raw_wins_over_mjpeg_even_at_a_higher_resolution() {
        let offered = [
            mode(1280, 720, 30, FrameFormat::MJPEG),
            mode(1920, 1080, 10, FrameFormat::YUYV),
        ];
        assert_eq!(
            choose_mode(&offered, &config()),
            Some(mode(1920, 1080, 10, FrameFormat::YUYV))
        );
    }

    #[test]
    fn the_lowest_qualifying_resolution_wins_then_the_highest_frame_rate() {
        let offered = [
            mode(1920, 1080, 30, FrameFormat::YUYV),
            mode(1280, 720, 10, FrameFormat::NV12),
            mode(1280, 720, 30, FrameFormat::YUYV),
            mode(640, 480, 30, FrameFormat::YUYV),
        ];
        assert_eq!(
            choose_mode(&offered, &config()),
            Some(mode(1280, 720, 30, FrameFormat::YUYV))
        );
    }

    #[test]
    fn a_mode_below_any_minimum_does_not_qualify() {
        let offered = [
            mode(1279, 720, 30, FrameFormat::YUYV),
            mode(1280, 719, 30, FrameFormat::YUYV),
            mode(1280, 720, 9, FrameFormat::YUYV),
        ];
        assert_eq!(choose_mode(&offered, &config()), None);
    }

    #[cfg(feature = "mjpeg")]
    #[test]
    fn mjpeg_is_the_fallback_when_no_raw_mode_qualifies() {
        let offered = [
            mode(1280, 720, 5, FrameFormat::YUYV),
            mode(1920, 1080, 30, FrameFormat::MJPEG),
            mode(1280, 720, 15, FrameFormat::MJPEG),
            mode(1280, 720, 30, FrameFormat::MJPEG),
        ];
        assert_eq!(
            choose_mode(&offered, &config()),
            Some(mode(1280, 720, 30, FrameFormat::MJPEG))
        );
    }

    #[cfg(not(feature = "mjpeg"))]
    #[test]
    fn mjpeg_never_qualifies_without_a_decoder() {
        let offered = [mode(1280, 720, 30, FrameFormat::MJPEG)];
        assert_eq!(choose_mode(&offered, &config()), None);
    }

    #[test]
    fn describe_lists_every_mode() {
        let offered = [
            mode(640, 480, 30, FrameFormat::MJPEG),
            mode(1280, 720, 10, FrameFormat::NV12),
        ];
        assert_eq!(describe(&offered), "640x480@30 MJPEG, 1280x720@10 NV12");
        assert_eq!(describe(&[]), "");
    }
}
