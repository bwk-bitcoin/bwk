//! Linux (V4L2) and Windows (Media Foundation), through nokhwa.

use std::sync::atomic::AtomicBool;

use nokhwa::{
    pixel_format::LumaFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};

use crate::{
    frame::Rgb,
    mode::{choose_mode, describe, fallback_note},
    Config, Error,
};

pub(crate) struct Stream {
    camera: Camera,
}

impl Stream {
    pub(crate) fn open(index: u32, config: &Config) -> Result<Self, Error> {
        // LumaFormat accepts every frame format, the mode choice narrows it down
        let mut camera = Camera::new(
            CameraIndex::Index(index),
            RequestedFormat::new::<LumaFormat>(RequestedFormatType::None),
        )?;
        let offered = camera.compatible_camera_formats()?;
        log::debug!("camera {index} offers {}", describe(&offered));
        let Some((chosen, met)) = choose_mode(&offered, config) else {
            return Err(Error::NoSuitableMode { offered });
        };
        log::info!(
            "camera {index} streams at {}{}",
            describe(&[chosen]),
            fallback_note(config, met)
        );
        camera.set_camera_requset(RequestedFormat::new::<LumaFormat>(
            RequestedFormatType::Exact(chosen),
        ))?;
        camera.open_stream()?;
        Ok(Self { camera })
    }

    /// Blocks until the next frame: a v4l2 read has no timeout.
    pub(crate) fn read(&mut self, _stop: &AtomicBool) -> Result<Option<Rgb>, Error> {
        let buffer = self.camera.frame()?;
        let resolution = buffer.resolution();
        Rgb::convert(
            buffer.source_frame_format(),
            resolution.width(),
            resolution.height(),
            buffer.buffer(),
        )
        .map(Some)
    }
}
