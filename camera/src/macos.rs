//! macOS, through its own AVFoundation session.
//!
//! nokhwa configures the device format while constructing and opening a camera, and
//! some built-in Mac cameras refuse that exclusive configuration lock although they
//! capture fine. A session preset lets AVFoundation negotiate a processed mode without
//! locking the device.

use std::{
    ffi::CString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use flume::{Receiver, RecvTimeoutError, Sender};
use nokhwa::utils::{CameraFormat, FrameFormat};
use nokhwa_bindings_macos::{
    AVCaptureDevice, AVCaptureDeviceInput, AVCaptureSession, AVCaptureVideoCallback,
    AVCaptureVideoDataOutput,
};
use objc::{
    msg_send,
    runtime::{Object, BOOL, YES},
    sel, sel_impl,
};

use crate::{
    capture::CameraId,
    error::Error,
    frame::{pack_rows, unreadable, Rgb},
    mode::{fallback_note, met_rate},
    Config,
};

/// How long a read waits for a frame before it checks the stop flag again.
const FRAME_WAIT: Duration = Duration::from_millis(100);

#[link(name = "AVFoundation", kind = "framework")]
extern "C" {
    static AVCaptureSessionPreset3840x2160: *mut Object;
    static AVCaptureSessionPreset1920x1080: *mut Object;
    static AVCaptureSessionPreset1280x720: *mut Object;
}

type NativeFrame = (Vec<u8>, FrameFormat, Option<Duration>);

pub struct Stream {
    format: CameraFormat,
    session: AVCaptureSession,
    input: AVCaptureDeviceInput,
    output: AVCaptureVideoDataOutput,
    receiver: Receiver<NativeFrame>,
    // the callback reads the sender through a raw pointer, so both outlive the session
    _callback: AVCaptureVideoCallback,
    _sender: Arc<Sender<NativeFrame>>,
    _buffer_name: CString,
    _device: AVCaptureDevice,
}

impl Stream {
    pub fn open(id: &CameraId, config: &Config) -> Result<Self, Error> {
        let device = AVCaptureDevice::new(&id.index()?)?;
        let buffer_name = CString::new(format!("bwk-camera-{id}"))
            .map_err(|error| Error::Capture(error.to_string()))?;
        let (sender, receiver) = flume::unbounded();
        let sender = Arc::new(sender);
        let input = AVCaptureDeviceInput::new(&device)?;
        let session = AVCaptureSession::new();
        session.begin_configuration();
        session.add_input(&input)?;
        set_preset(&session, config.fine_scan)?;
        let callback = AVCaptureVideoCallback::new(&buffer_name, &sender)?;
        let output = AVCaptureVideoDataOutput::new();
        output.add_delegate(&callback)?;
        output.set_frame_format(FrameFormat::RAWRGB)?;
        session.add_output(&output)?;
        session.commit_configuration();
        session.start()?;
        let active = device.active_format()?;
        let stream = Self {
            format: CameraFormat::new(
                active.resolution(),
                FrameFormat::RAWRGB,
                active.frame_rate(),
            ),
            session,
            input,
            output,
            receiver,
            _callback: callback,
            _sender: sender,
            _buffer_name: buffer_name,
            _device: device,
        };
        // the preset decides the mode, so it is checked once it runs, against the
        // preferred frame rate then the fallback one
        let Some(met) = met_rate(&stream.format, config) else {
            return Err(Error::NoSuitableMode {
                offered: vec![stream.format],
            });
        };
        log::info!(
            "camera {id} streams at {}x{}@{}{}",
            stream.format.width(),
            stream.format.height(),
            stream.format.frame_rate(),
            fallback_note(config, met)
        );
        Ok(stream)
    }

    /// None once `stop` is set.
    pub fn read(&mut self, stop: &AtomicBool) -> Result<Option<Rgb>, Error> {
        let raw = loop {
            match self.receiver.recv_timeout(FRAME_WAIT) {
                Ok((raw, _, _)) => break raw,
                Err(RecvTimeoutError::Timeout) if stop.load(Ordering::Acquire) => return Ok(None),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Capture(
                        "the camera frame channel disconnected".to_owned(),
                    ))
                }
            }
        };
        // frames queued meanwhile are newer, only the last one is worth converting
        let raw = self
            .receiver
            .drain()
            .last()
            .map_or(raw, |(newer, _, _)| newer);
        let (width, height) = (self.format.width(), self.format.height());
        let data = pack_rows(raw, width, height).ok_or_else(unreadable)?;
        Rgb::from_frame(data, width, height).map(Some)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.session.remove_output(&self.output);
        self.session.remove_input(&self.input);
        self.session.stop();
    }
}

/// The first preset the session accepts: 1920x1080, then 1280x720 for a camera without a
/// 1080p mode, and with `fine_scan` 3840x2160 before both.
#[allow(unexpected_cfgs)]
fn set_preset(session: &AVCaptureSession, fine_scan: bool) -> Result<(), Error> {
    // SAFETY: AVFoundation exports these process-lifetime NSString constants.
    let presets = unsafe {
        [
            AVCaptureSessionPreset3840x2160,
            AVCaptureSessionPreset1920x1080,
            AVCaptureSessionPreset1280x720,
        ]
    };
    let presets = if fine_scan {
        &presets[..]
    } else {
        &presets[1..]
    };
    for &preset in presets {
        // SAFETY: `session.inner()` and `preset` are valid Objective-C objects for the
        // duration of these synchronous messages, and both selectors return the declared
        // Objective-C types.
        let supported: BOOL = unsafe { msg_send![session.inner(), canSetSessionPreset: preset] };
        if supported == YES {
            // SAFETY: the query above confirmed this session accepts the preset.
            let _: () = unsafe { msg_send![session.inner(), setSessionPreset: preset] };
            return Ok(());
        }
    }
    Err(Error::Capture(
        "the camera supports no 720p, 1080p or 2160p capture session".to_owned(),
    ))
}
