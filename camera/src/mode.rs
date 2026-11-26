#[cfg(any(not(target_os = "macos"), test))]
use std::cmp::Ordering;
use std::fmt;

#[cfg(any(not(target_os = "macos"), test))]
use bwk_qr::image::SCAN_SIDE;

use crate::Config;

/// A mode a camera captures in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub format: Format,
}

/// The pixel format of a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Yuyv,
    Nv12,
    I420,
    Gray,
    Rgb,
    Bgr,
    /// Four bytes per pixel, blue first, the fourth unused.
    Rgb32,
    Mjpeg,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}@{} {}",
            self.width, self.height, self.frame_rate, self.format
        )
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Yuyv => "YUYV",
            Self::Nv12 => "NV12",
            Self::I420 => "I420",
            Self::Gray => "GRAY",
            Self::Rgb => "RGB",
            Self::Bgr => "BGR",
            Self::Rgb32 => "RGB32",
            Self::Mjpeg => "MJPEG",
        })
    }
}

/// Every format but MJPEG converts without a JPEG decoder. Media Foundation decodes
/// MJPEG itself.
fn readable(format: Format) -> bool {
    format != Format::Mjpeg || cfg!(any(feature = "mjpeg", target_os = "windows"))
}

/// The minimum frame rates a mode is chosen at, in order: `min_fps`, then the fallback
/// when it is lower.
fn frame_rates(config: &Config) -> impl Iterator<Item = u32> {
    std::iter::once(config.min_fps).chain(config.fallback_fps.filter(|&fps| fps < config.min_fps))
}

/// The first minimum frame rate `mode` meets, None when it meets none or is unreadable.
pub fn met_rate(mode: &Mode, config: &Config) -> Option<u32> {
    if !readable(mode.format) {
        return None;
    }
    frame_rates(config).find(|&min_fps| mode.frame_rate >= min_fps)
}

/// The mode streamed and the minimum frame rate it met, among the readable modes that
/// meet one, preferring in order: a shorter side of at least [`SCAN_SIDE`], `min_fps`
/// over the fallback rate, the resolution (see [`by_resolution`]), raw over MJPEG, then
/// the highest frame rate.
#[cfg(any(not(target_os = "macos"), test))]
pub fn choose_mode(offered: &[Mode], config: &Config) -> Option<(Mode, u32)> {
    offered
        .iter()
        .filter_map(|mode| met_rate(mode, config).map(|met| (*mode, met)))
        .min_by(|(a, a_met), (b, b_met)| {
            reaches_scan_side(b)
                .cmp(&reaches_scan_side(a))
                .then(b_met.cmp(a_met))
                .then_with(|| by_resolution(a, b, config.fine_scan))
                .then((a.format == Format::Mjpeg).cmp(&(b.format == Format::Mjpeg)))
                .then(b.frame_rate.cmp(&a.frame_rate))
        })
}

#[cfg(any(not(target_os = "macos"), test))]
fn reaches_scan_side(mode: &Mode) -> bool {
    mode.width.min(mode.height) >= SCAN_SIDE
}

/// Between two modes on the same side of [`SCAN_SIDE`], `Less` when `a` is preferred: the
/// largest with `fine_scan`, else the smallest that reaches it or the largest below it,
/// by shorter side then area.
#[cfg(any(not(target_os = "macos"), test))]
fn by_resolution(a: &Mode, b: &Mode, fine_scan: bool) -> Ordering {
    let size = |mode: &Mode| {
        (
            mode.width.min(mode.height),
            u64::from(mode.width) * u64::from(mode.height),
        )
    };
    let smallest_first = size(a).cmp(&size(b));
    if fine_scan || !reaches_scan_side(a) {
        smallest_first.reverse()
    } else {
        smallest_first
    }
}

/// How the log tells a mode that met only the fallback rate: ` (fallback to N fps)`.
pub fn fallback_note(config: &Config, met: u32) -> String {
    if met < config.min_fps {
        format!(" (fallback to {met} fps)")
    } else {
        String::new()
    }
}

/// `WxH@fps FORMAT`, comma separated.
pub fn describe(modes: &[Mode]) -> String {
    modes
        .iter()
        .map(Mode::to_string)
        .collect::<Vec<String>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use crate::{
        mode::{choose_mode, describe, fallback_note, met_rate, Format, Mode},
        Config,
    };

    fn mode(width: u32, height: u32, frame_rate: u32, format: Format) -> Mode {
        Mode {
            width,
            height,
            frame_rate,
            format,
        }
    }

    fn config() -> Config {
        Config {
            min_fps: 10,
            fallback_fps: None,
            fine_scan: false,
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

    fn chosen(offered: &[Mode], config: &Config) -> Option<Mode> {
        choose_mode(offered, config).map(|(mode, _)| mode)
    }

    /// 480, 720, 1080, 1440 and 2160, the 1080 ones at two frame rates.
    fn every_side() -> [Mode; 6] {
        [
            mode(640, 480, 30, Format::Yuyv),
            mode(1280, 720, 30, Format::Yuyv),
            mode(1920, 1080, 15, Format::Yuyv),
            mode(1920, 1080, 30, Format::Yuyv),
            mode(2560, 1440, 30, Format::Yuyv),
            mode(3840, 2160, 30, Format::Yuyv),
        ]
    }

    #[test]
    fn every_raw_format_qualifies() {
        for format in [
            Format::Yuyv,
            Format::Nv12,
            Format::I420,
            Format::Gray,
            Format::Rgb,
            Format::Bgr,
            Format::Rgb32,
        ] {
            let offered = [mode(1280, 720, 10, format)];
            assert_eq!(chosen(&offered, &config()), Some(offered[0]));
        }
    }

    #[test]
    fn the_smallest_mode_reaching_the_scan_side_wins_then_the_highest_frame_rate() {
        assert_eq!(
            chosen(&every_side(), &config()),
            Some(mode(1920, 1080, 30, Format::Yuyv))
        );
    }

    #[test]
    fn fine_scan_takes_the_largest_mode() {
        let fine = Config {
            fine_scan: true,
            ..config()
        };
        assert_eq!(
            chosen(&every_side(), &fine),
            Some(mode(3840, 2160, 30, Format::Yuyv))
        );
    }

    #[test]
    fn below_the_scan_side_the_largest_mode_wins() {
        let offered = [
            mode(640, 480, 30, Format::Yuyv),
            mode(1280, 720, 30, Format::Yuyv),
            mode(800, 600, 30, Format::Yuyv),
        ];
        assert_eq!(chosen(&offered, &config()), Some(offered[1]));
    }

    #[test]
    fn raw_wins_over_mjpeg_at_the_same_resolution() {
        let offered = [
            mode(1920, 1080, 30, Format::Mjpeg),
            mode(1920, 1080, 10, Format::Yuyv),
        ];
        assert_eq!(chosen(&offered, &config()), Some(offered[1]));
    }

    #[cfg(any(feature = "mjpeg", target_os = "windows"))]
    #[test]
    fn mjpeg_reaching_the_scan_side_wins_over_raw_below_it() {
        let offered = [
            mode(1280, 720, 30, Format::Yuyv),
            mode(1920, 1080, 30, Format::Mjpeg),
        ];
        assert_eq!(chosen(&offered, &config()), Some(offered[1]));
    }

    #[test]
    fn a_mode_below_the_minimum_frame_rate_does_not_qualify() {
        let offered = [
            mode(1280, 720, 9, Format::Yuyv),
            mode(1920, 1080, 9, Format::Yuyv),
        ];
        assert_eq!(chosen(&offered, &config()), None);
    }

    #[test]
    fn a_mode_reaches_the_scan_side_by_its_shorter_side_in_either_orientation() {
        let offered = [
            mode(1920, 1079, 30, Format::Yuyv),
            mode(1080, 1920, 30, Format::Yuyv),
        ];
        assert_eq!(chosen(&offered, &config()), Some(offered[1]));
        let offered = [
            mode(640, 480, 30, Format::Yuyv),
            mode(720, 1280, 30, Format::Yuyv),
        ];
        assert_eq!(chosen(&offered, &config()), Some(offered[1]));
    }

    #[cfg(any(feature = "mjpeg", target_os = "windows"))]
    #[test]
    fn mjpeg_is_the_fallback_when_no_raw_mode_qualifies() {
        let offered = [
            mode(1280, 720, 5, Format::Yuyv),
            mode(1280, 720, 15, Format::Mjpeg),
            mode(1280, 720, 30, Format::Mjpeg),
        ];
        assert_eq!(
            chosen(&offered, &config()),
            Some(mode(1280, 720, 30, Format::Mjpeg))
        );
    }

    #[cfg(not(any(feature = "mjpeg", target_os = "windows")))]
    #[test]
    fn mjpeg_never_qualifies_without_a_decoder() {
        let offered = [mode(1280, 720, 30, Format::Mjpeg)];
        assert_eq!(chosen(&offered, &config()), None);
    }

    #[test]
    fn describe_lists_every_mode() {
        let offered = [
            mode(640, 480, 30, Format::Mjpeg),
            mode(1280, 720, 10, Format::Nv12),
        ];
        assert_eq!(describe(&offered), "640x480@30 MJPEG, 1280x720@10 NV12");
        assert_eq!(describe(&[]), "");
    }

    #[test]
    fn the_preferred_rate_wins_over_a_smaller_resolution() {
        let offered = [
            mode(1920, 1080, 15, Format::Yuyv),
            mode(2560, 1440, 30, Format::Yuyv),
        ];
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(2560, 1440, 30, Format::Yuyv), 24))
        );
    }

    #[test]
    fn reaching_the_scan_side_at_the_fallback_rate_wins_over_the_preferred_rate_below_it() {
        let offered = [
            mode(1280, 720, 30, Format::Yuyv),
            mode(1920, 1080, 15, Format::Yuyv),
        ];
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(1920, 1080, 15, Format::Yuyv), 10))
        );
    }

    #[test]
    fn a_camera_with_only_slower_modes_falls_back() {
        let offered = [
            mode(1280, 720, 15, Format::Yuyv),
            mode(1280, 720, 5, Format::Yuyv),
        ];
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(1280, 720, 15, Format::Yuyv), 10))
        );
    }

    #[test]
    fn a_mode_below_the_fallback_rate_is_never_chosen() {
        let offered = [
            mode(1280, 720, 9, Format::Yuyv),
            mode(1920, 1080, 5, Format::Yuyv),
        ];
        assert_eq!(choose_mode(&offered, &preferring_24()), None);
        let offered = [
            mode(3840, 2160, 5, Format::Yuyv),
            mode(640, 480, 15, Format::Yuyv),
        ];
        assert_eq!(
            choose_mode(&offered, &preferring_24()),
            Some((mode(640, 480, 15, Format::Yuyv), 10))
        );
    }

    #[test]
    fn without_a_fallback_only_the_preferred_rate_is_tried() {
        let offered = [mode(1280, 720, 15, Format::Yuyv)];
        let strict = Config {
            fallback_fps: None,
            ..preferring_24()
        };
        assert_eq!(choose_mode(&offered, &strict), None);
    }

    #[test]
    fn a_running_mode_meets_the_preferred_rate_or_the_fallback() {
        assert_eq!(
            met_rate(&mode(1280, 720, 30, Format::Rgb), &preferring_24()),
            Some(24)
        );
        assert_eq!(
            met_rate(&mode(1280, 720, 15, Format::Rgb), &preferring_24()),
            Some(10)
        );
        assert_eq!(
            met_rate(&mode(1280, 720, 5, Format::Rgb), &preferring_24()),
            None
        );
    }

    #[test]
    fn the_log_says_when_the_fallback_rate_was_met() {
        assert_eq!(fallback_note(&preferring_24(), 24), "");
        assert_eq!(fallback_note(&preferring_24(), 10), " (fallback to 10 fps)");
    }
}
