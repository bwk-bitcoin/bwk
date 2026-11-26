//! Linux (V4L2) and Windows (Media Foundation), through nokhwa.

use std::sync::atomic::{AtomicBool, Ordering};

use nokhwa::{
    pixel_format::LumaFormat,
    utils::{RequestedFormat, RequestedFormatType},
    Camera,
};

use crate::{
    capture::CameraId,
    error::Error,
    frame::Rgb,
    mode::{choose_mode, describe, fallback_note},
    Config,
};

pub struct Stream {
    id: CameraId,
    camera: Camera,
}

impl Stream {
    pub fn open(id: &CameraId, config: &Config) -> Result<Self, Error> {
        // LumaFormat accepts every frame format, the mode choice narrows it down
        let mut camera = Camera::new(
            id.index()?,
            RequestedFormat::new::<LumaFormat>(RequestedFormatType::None),
        )?;
        let offered = camera.compatible_camera_formats()?;
        log::debug!("camera {id} offers {}", describe(&offered));
        let Some((chosen, met)) = choose_mode(&offered, config) else {
            return Err(Error::NoSuitableMode { offered });
        };
        log::info!(
            "camera {id} streams at {}{}",
            describe(&[chosen]),
            fallback_note(config, met)
        );
        camera.set_camera_requset(RequestedFormat::new::<LumaFormat>(
            RequestedFormatType::Exact(chosen),
        ))?;
        camera.open_stream()?;
        Ok(Self {
            id: id.clone(),
            camera,
        })
    }

    /// Blocks until the next frame that decodes: a v4l2 read has no timeout. None once
    /// stopped.
    pub fn read(&mut self, stop: &AtomicBool) -> Result<Option<Rgb>, Error> {
        while !stop.load(Ordering::Acquire) {
            let buffer = self.camera.frame()?;
            let resolution = buffer.resolution();
            let converted = Rgb::convert(
                buffer.source_frame_format(),
                resolution.width(),
                resolution.height(),
                buffer.buffer(),
            )?;
            if converted.is_some() {
                return Ok(converted);
            }
            log::warn!(
                "camera {} sent a {resolution} MJPEG frame of {} bytes that does not decode, \
                 skipped",
                self.id,
                buffer.buffer().len()
            );
        }
        Ok(None)
    }
}
