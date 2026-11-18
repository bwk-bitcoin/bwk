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

/// The minimum frame rates a mode is chosen at, in order: `min_fps`, then the fallback
/// when it is lower.
fn frame_rates(config: &Config) -> impl Iterator<Item = u32> {
    std::iter::once(config.min_fps).chain(config.fallback_fps.filter(|&fps| fps < config.min_fps))
}

fn qualifies(mode: &CameraFormat, config: &Config, min_fps: u32) -> bool {
    readable(mode.format())
        && mode.width() >= config.min_width
        && mode.height() >= config.min_height
        && mode.frame_rate() >= min_fps
}

/// The first minimum frame rate `mode` meets, None when it meets none.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn met_rate(mode: &CameraFormat, config: &Config) -> Option<u32> {
    frame_rates(config).find(|&min_fps| qualifies(mode, config, min_fps))
}

/// The mode streamed and the minimum frame rate it met: at `min_fps` first, then at the
/// fallback rate, each time raw over MJPEG, then the lowest qualifying resolution, then
/// the highest frame rate.
#[cfg(any(not(target_os = "macos"), test))]
pub(crate) fn choose_mode(
    offered: &[CameraFormat],
    config: &Config,
) -> Option<(CameraFormat, u32)> {
    frame_rates(config).find_map(|min_fps| {
        offered
            .iter()
            .copied()
            .filter(|mode| qualifies(mode, config, min_fps))
            .min_by_key(|mode| {
                (
                    mode.format() == FrameFormat::MJPEG,
                    u64::from(mode.width()) * u64::from(mode.height()),
                    Reverse(mode.frame_rate()),
                )
            })
            .map(|mode| (mode, min_fps))
    })
}

/// How the log tells a mode that met only the fallback rate: ` (fallback to N fps)`.
pub(crate) fn fallback_note(config: &Config, met: u32) -> String {
    if met < config.min_fps {
        format!(" (fallback to {met} fps)")
    } else {
        String::new()
    }
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
        mode::{choose_mode, describe, fallback_note, met_rate},
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
            fallback_fps: None,
            max_pixels: 1024 * 1024,
        }
    }

    /// 24 fps preferred, 10 when no mode reaches it.
    fn preferring_24() -> Config {
        Config {
            min_fps: 24,
            fallback_fps: Some(10),
            ..config()
        }
    }

    fn chosen(offered: &[CameraFormat], config: &Config) -> Option<CameraFormat> {
        choose_mode(offered, config).map(|(mode, _)| mode)
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
            assert_eq!(chosen(&offered, &config()), Some(offered[0]));
        }
    }

    #[test]
    fn raw_wins_over_mjpeg_even_at_a_higher_resolution() {
        let offered = [
            mode(1280, 720, 30, FrameFormat::MJPEG),
            mode(1920, 1080, 10, FrameFormat::YUYV),
        ];
        assert_eq!(
            chosen(&offered, &config()),
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
            chosen(&offered, &config()),
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
        assert_eq!(chosen(&offered, &config()), None);
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
            chosen(&offered, &config()),
            Some(mode(1280, 720, 30, FrameFormat::MJPEG))
        );
    }

    #[cfg(not(feature = "mjpeg"))]
    #[test]
    fn mjpeg_never_qualifies_without_a_decoder() {
        let offered = [mode(1280, 720, 30, FrameFormat::MJPEG)];
        assert_eq!(chosen(&offered, &config()), None);
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

    #[test]
    fn a_camera_with_a_mode_at_the_preferred_rate_gets_it() {
        let offered = [
            mode(1280, 720, 15, FrameFormat::YUYV),
            mode(1920, 1080, 30, FrameFormat::YUYV),
        ];
        // the preferred rate first, even at a higher resolution
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(1920, 1080, 30, FrameFormat::YUYV), 24))
        );
    }

    #[test]
    fn a_camera_with_only_slower_modes_falls_back() {
        let offered = [
            mode(1920, 1080, 15, FrameFormat::YUYV),
            mode(1280, 720, 15, FrameFormat::YUYV),
            mode(1280, 720, 5, FrameFormat::YUYV),
        ];
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(1280, 720, 15, FrameFormat::YUYV), 10))
        );
    }

    #[test]
    fn a_camera_below_the_fallback_rate_is_refused() {
        let offered = [
            mode(1280, 720, 9, FrameFormat::YUYV),
            mode(1920, 1080, 5, FrameFormat::YUYV),
        ];
        assert_eq!(choose_mode(&offered, &preferring_24()), None);
    }

    #[test]
    fn without_a_fallback_only_the_preferred_rate_is_tried() {
        let offered = [mode(1280, 720, 15, FrameFormat::YUYV)];
        let strict = Config {
            fallback_fps: None,
            ..preferring_24()
        };
        assert_eq!(choose_mode(&offered, &strict), None);
    }

    #[test]
    fn a_running_mode_meets_the_preferred_rate_or_the_fallback() {
        assert_eq!(
            met_rate(&mode(1280, 720, 30, FrameFormat::RAWRGB), &preferring_24()),
            Some(24)
        );
        assert_eq!(
            met_rate(&mode(1280, 720, 15, FrameFormat::RAWRGB), &preferring_24()),
            Some(10)
        );
        assert_eq!(
            met_rate(&mode(1280, 720, 5, FrameFormat::RAWRGB), &preferring_24()),
            None
        );
    }

    #[test]
    fn the_log_says_when_the_fallback_rate_was_met() {
        assert_eq!(fallback_note(&preferring_24(), 24), "");
        assert_eq!(fallback_note(&preferring_24(), 10), " (fallback to 10 fps)");
    }
}
