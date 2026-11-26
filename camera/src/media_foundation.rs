//! Windows, through its own Media Foundation source reader.
//!
//! nokhwa drops every mode whose frame rate is a fraction, `10000000/333333` for 30 fps
//! being what the UVC driver usually reports, and leaves some cameras with none. The
//! source reader converts the chosen mode to RGB32 itself, MJPEG included.

use std::{ptr, slice, sync::atomic::AtomicBool};

use windows::{
    core::{GUID, PWSTR},
    Win32::{
        Media::MediaFoundation::{
            IMFActivate, IMFAttributes, IMFMediaSource, IMFMediaType, IMFSample, IMFSourceReader,
            MFCreateAttributes, MFCreateMediaType, MFCreateSourceReaderFromMediaSource,
            MFEnumDeviceSources, MFGetStrideForBitmapInfoHeader, MFMediaType_Video, MFShutdown,
            MFStartup, MFVideoFormat_I420, MFVideoFormat_IYUV, MFVideoFormat_MJPG,
            MFVideoFormat_NV12, MFVideoFormat_RGB24, MFVideoFormat_RGB32, MFVideoFormat_YUY2,
            MFSTARTUP_NOSOCKET, MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, MF_MT_DEFAULT_STRIDE,
            MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE,
            MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED, MF_SOURCE_READERF_ENDOFSTREAM,
            MF_SOURCE_READERF_ERROR, MF_SOURCE_READER_ALL_STREAMS,
            MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, MF_SOURCE_READER_FIRST_VIDEO_STREAM,
            MF_VERSION,
        },
        System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
    },
};

use crate::{
    capture::CameraId,
    error::Error,
    frame::{rgb32_rows, unreadable, Rgb},
    mode::{choose_mode, describe, fallback_note, rounded_frame_rate, Format, Mode},
    Config,
};

const VIDEO_STREAM: u32 = MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32;

/// The native subtypes a mode is offered in.
const FORMATS: [(GUID, Format); 7] = [
    (MFVideoFormat_YUY2, Format::Yuyv),
    (MFVideoFormat_NV12, Format::Nv12),
    (MFVideoFormat_I420, Format::I420),
    (MFVideoFormat_IYUV, Format::I420),
    (MFVideoFormat_RGB24, Format::Bgr),
    (MFVideoFormat_RGB32, Format::Rgb32),
    (MFVideoFormat_MJPG, Format::Mjpeg),
];

pub struct Device {
    /// The device symbolic link.
    pub link: String,
    pub name: String,
}

/// The video capture devices, in the order Media Foundation lists them.
pub fn devices() -> Result<Vec<Device>, Error> {
    let _runtime = Runtime::start()?;
    activates()?
        .iter()
        .map(|activate| {
            Ok(Device {
                link: string(
                    activate,
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                )?,
                name: string(activate, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME)?,
            })
        })
        .collect()
}

pub struct Stream {
    reader: IMFSourceReader,
    source: IMFMediaSource,
    width: u32,
    height: u32,
    /// Negative when the rows are bottom-up.
    stride: i32,
    // dropped last: COM and Media Foundation outlive the objects above
    _runtime: Runtime,
}

impl Stream {
    pub fn open(id: &CameraId, config: &Config) -> Result<Self, Error> {
        let runtime = Runtime::start()?;
        let activate = activates()?
            .into_iter()
            .find(|activate| {
                string(
                    activate,
                    &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK,
                )
                .is_ok_and(|link| link == id.as_str())
            })
            .ok_or(Error::NoCamera)?;
        // SAFETY: every call below is a COM call on objects this thread created, with
        // COM and Media Foundation started by `runtime`.
        unsafe {
            let source: IMFMediaSource = activate.ActivateObject()?;
            let converting = attribute_store()?;
            converting.SetUINT32(&MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, 1)?;
            let reader =
                MFCreateSourceReaderFromMediaSource(&source, &converting).inspect_err(|_| {
                    let _ = source.Shutdown();
                })?;
            let mut stream = Self {
                reader,
                source,
                width: 0,
                height: 0,
                stride: 0,
                _runtime: runtime,
            };
            stream.set_mode(id, config)?;
            stream.read_output_type()?;
            Ok(stream)
        }
    }

    /// Blocks until the next frame, as a v4l2 read does.
    pub fn read(&mut self, _stop: &AtomicBool) -> Result<Option<Rgb>, Error> {
        loop {
            let mut flags = 0;
            let mut sample = None;
            // SAFETY: the reader is alive, the out pointers are valid locals.
            unsafe {
                self.reader.ReadSample(
                    VIDEO_STREAM,
                    0,
                    None,
                    Some(&mut flags),
                    None,
                    Some(&mut sample),
                )?;
            }
            let flags = flags as i32;
            if flags & MF_SOURCE_READERF_ERROR.0 != 0 {
                return Err(Error::Capture("the camera stream failed".to_owned()));
            }
            if flags & MF_SOURCE_READERF_ENDOFSTREAM.0 != 0 {
                return Err(Error::Capture("the camera stream ended".to_owned()));
            }
            if flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED.0 != 0 {
                self.read_output_type()?;
            }
            // a stream tick carries no sample
            if let Some(sample) = sample {
                return self.frame(&sample).map(Some);
            }
        }
    }

    /// Streams the chosen native mode, converted to RGB32 at the same size and rate.
    fn set_mode(&self, id: &CameraId, config: &Config) -> Result<(), Error> {
        let (offered, types) = self.native_modes()?;
        log::debug!("camera {id} offers {}", describe(&offered));
        let Some((chosen, met)) = choose_mode(&offered, config) else {
            return Err(Error::NoSuitableMode { offered });
        };
        log::info!(
            "camera {id} streams at {chosen}{}",
            fallback_note(config, met)
        );
        let position = offered.iter().position(|mode| *mode == chosen);
        let native = &types[position.expect("chosen among the offered modes")];
        // SAFETY: COM calls on the live reader and media types this thread created.
        unsafe {
            self.reader
                .SetStreamSelection(MF_SOURCE_READER_ALL_STREAMS.0 as u32, false)?;
            self.reader.SetStreamSelection(VIDEO_STREAM, true)?;
            self.reader
                .SetCurrentMediaType(VIDEO_STREAM, None, native)?;
            let output = MFCreateMediaType()?;
            output.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            output.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32)?;
            output.SetUINT64(&MF_MT_FRAME_SIZE, native.GetUINT64(&MF_MT_FRAME_SIZE)?)?;
            output.SetUINT64(&MF_MT_FRAME_RATE, native.GetUINT64(&MF_MT_FRAME_RATE)?)?;
            self.reader
                .SetCurrentMediaType(VIDEO_STREAM, None, &output)?;
        }
        Ok(())
    }

    /// The modes of the native types in a format of [`FORMATS`], with those types.
    fn native_modes(&self) -> Result<(Vec<Mode>, Vec<IMFMediaType>), Error> {
        let mut modes = Vec::new();
        let mut types = Vec::new();
        let mut index = 0;
        // SAFETY: COM calls on the live reader and the media types it returns. It answers
        // MF_E_NO_MORE_TYPES past the last type.
        while let Ok(native) = unsafe { self.reader.GetNativeMediaType(VIDEO_STREAM, index) } {
            index += 1;
            let (subtype, size, rate) = unsafe {
                (
                    native.GetGUID(&MF_MT_SUBTYPE)?,
                    native.GetUINT64(&MF_MT_FRAME_SIZE)?,
                    native.GetUINT64(&MF_MT_FRAME_RATE)?,
                )
            };
            let Some(&(_, format)) = FORMATS.iter().find(|(guid, _)| *guid == subtype) else {
                continue;
            };
            let (width, height) = split(size);
            let (numerator, denominator) = split(rate);
            let Some(frame_rate) = rounded_frame_rate(numerator, denominator) else {
                continue;
            };
            modes.push(Mode {
                width,
                height,
                frame_rate,
                format,
            });
            types.push(native);
        }
        Ok((modes, types))
    }

    fn read_output_type(&mut self) -> Result<(), Error> {
        // SAFETY: COM calls on the live reader and the media type it returns.
        unsafe {
            let current = self.reader.GetCurrentMediaType(VIDEO_STREAM)?;
            (self.width, self.height) = split(current.GetUINT64(&MF_MT_FRAME_SIZE)?);
            self.stride = match current.GetUINT32(&MF_MT_DEFAULT_STRIDE) {
                Ok(stride) => stride as i32,
                Err(_) => MFGetStrideForBitmapInfoHeader(MFVideoFormat_RGB32.data1, self.width)?,
            };
        }
        Ok(())
    }

    fn frame(&self, sample: &IMFSample) -> Result<Rgb, Error> {
        // SAFETY: the buffer stays locked while the slice over it is read, and Lock
        // gives its start and the length of its valid data.
        let data = unsafe {
            let buffer = sample.ConvertToContiguousBuffer()?;
            let mut start = ptr::null_mut();
            let mut length = 0;
            buffer.Lock(&mut start, None, Some(&mut length))?;
            let raw = slice::from_raw_parts(start, length as usize);
            let data = rgb32_rows(raw, self.width, self.height, self.stride);
            buffer.Unlock()?;
            data
        };
        Rgb::from_frame(data.ok_or_else(unreadable)?, self.width, self.height)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: shuts the source down once, before the runtime stops.
        let _ = unsafe { self.source.Shutdown() };
    }
}

/// COM and Media Foundation, started on the calling thread until dropped. Each runs on a
/// thread bwk-camera spawned, which nothing else initialized.
struct Runtime;

impl Runtime {
    fn start() -> Result<Self, Error> {
        // SAFETY: paired with the calls in Drop, on the same thread.
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
            if let Err(error) = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) {
                CoUninitialize();
                return Err(error.into());
            }
        }
        Ok(Self)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // SAFETY: `start` succeeded on this thread.
        unsafe {
            let _ = MFShutdown();
            CoUninitialize();
        }
    }
}

fn attribute_store() -> Result<IMFAttributes, Error> {
    let mut attributes = None;
    // SAFETY: MFCreateAttributes fills the out pointer when it succeeds.
    unsafe { MFCreateAttributes(&mut attributes, 1)? };
    attributes.ok_or_else(|| Error::Capture("no Media Foundation attribute store".to_owned()))
}

fn activates() -> Result<Vec<IMFActivate>, Error> {
    let mut array: *mut Option<IMFActivate> = ptr::null_mut();
    let mut count = 0;
    let video_capture = attribute_store()?;
    // SAFETY: MFEnumDeviceSources hands `count` activation objects in an array the caller
    // frees; each is moved out before the array is freed.
    unsafe {
        video_capture.SetGUID(
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
            &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
        )?;
        MFEnumDeviceSources(&video_capture, &mut array, &mut count)?;
        if array.is_null() {
            return Ok(Vec::new());
        }
        let activates = slice::from_raw_parts_mut(array, count as usize)
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        CoTaskMemFree(Some(array as *const _));
        Ok(activates)
    }
}

fn string(attributes: &IMFAttributes, key: &GUID) -> Result<String, Error> {
    let mut value = PWSTR::null();
    let mut length = 0;
    // SAFETY: GetAllocatedString hands a string the caller frees.
    unsafe {
        attributes.GetAllocatedString(key, &mut value, &mut length)?;
        let text = value.to_string();
        CoTaskMemFree(Some(value.0 as *const _));
        text.map_err(|error| Error::Capture(error.to_string()))
    }
}

/// A Media Foundation pair packed in a u64: width and height, or a frame rate fraction.
fn split(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}
