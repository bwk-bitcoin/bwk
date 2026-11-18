use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use nokhwa::utils::ApiBackend;

#[cfg(target_os = "macos")]
use crate::macos::Stream;
#[cfg(not(target_os = "macos"))]
use crate::native::Stream;
use crate::{
    frame::{Frame, Rgb},
    Config, Error,
};

/// Some platforms never answer when their permission service is unavailable.
const PERMISSION_TIMEOUT: Duration = Duration::from_secs(30);

/// The devices with a capture thread running. A second open of the same device fails,
/// and a stopped thread may still hold it, so this is process wide.
static RUNNING: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraInfo {
    pub index: u32,
    pub name: String,
}

/// The cameras that capture video, by index. Asks for the camera permission first,
/// which can block until the user answers.
pub fn list() -> Result<Vec<CameraInfo>, Error> {
    request_access()?;
    let mut cameras = Vec::new();
    for info in nokhwa::query(ApiBackend::Auto)? {
        let index = info.index().as_index()?;
        if !can_capture(index) {
            log::debug!(
                "camera {index} ({}) captures no video, skipped",
                info.human_name()
            );
            continue;
        }
        cameras.push(CameraInfo {
            index,
            name: info.human_name(),
        });
    }
    if cameras.is_empty() {
        return Err(Error::NoCamera);
    }
    // the backend lists them in no particular order
    cameras.sort_by_key(|camera| camera.index);
    Ok(cameras)
}

/// Only macOS asks; elsewhere it is granted at once.
fn request_access() -> Result<(), Error> {
    if nokhwa::nokhwa_check() {
        return Ok(());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    nokhwa::nokhwa_initialize(move |granted| {
        // the receiver is gone once the wait timed out, nobody is left to tell
        let _ = sender.try_send(granted);
    });
    match receiver.recv_timeout(PERMISSION_TIMEOUT) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(Error::PermissionDenied),
    }
}

/// V4L2 lists a UVC webcam twice: its capture node and a node that only streams
/// metadata. A node whose caps cannot be read is kept, so opening it reports why.
#[cfg(target_os = "linux")]
fn can_capture(index: u32) -> bool {
    match v4l::Device::new(index as usize).and_then(|device| device.query_caps()) {
        Ok(caps) => caps
            .capabilities
            .contains(v4l::capability::Flags::VIDEO_CAPTURE),
        Err(_) => true,
    }
}

#[cfg(not(target_os = "linux"))]
fn can_capture(_index: u32) -> bool {
    true
}

/// A camera streaming on its own thread. Dropping it stops the capture.
pub struct Camera {
    latest: Arc<Mutex<Latest>>,
    stop: Arc<AtomicBool>,
}

impl Camera {
    /// Only blocks to spawn the capture thread: the device opens inside it, and a
    /// failure there shows up later through [`Camera::failure`].
    pub fn start(index: u32, config: Config) -> Result<Self, Error> {
        if !nokhwa::nokhwa_check() {
            return Err(Error::PermissionDenied);
        }
        let lease = Lease::take(index).ok_or(Error::Busy)?;
        let latest = Arc::new(Mutex::new(Latest::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_latest = Arc::clone(&latest);
        let thread_stop = Arc::clone(&stop);
        // the thread is detached: a v4l2 read has no timeout, so it notices the stop
        // flag after its current frame and releases the device on its own
        thread::Builder::new()
            .name("bwk-camera".to_owned())
            .spawn(move || {
                let _lease = lease;
                if let Err(error) = capture(index, &config, &thread_latest, &thread_stop) {
                    log::warn!("camera {index} stopped: {error}");
                    thread_latest.lock().expect("poisoned").failure = Some(error);
                }
            })
            .map_err(|error| Error::Capture(error.to_string()))?;
        Ok(Self { latest, stop })
    }

    /// The latest frame, None until the first one is captured.
    pub fn frame(&self) -> Option<Frame> {
        self.latest.lock().expect("poisoned").frame.clone()
    }

    /// Why the capture stopped on its own, None while it runs.
    pub fn failure(&self) -> Option<Error> {
        self.latest.lock().expect("poisoned").failure.clone()
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn capture(
    index: u32,
    config: &Config,
    latest: &Mutex<Latest>,
    stop: &AtomicBool,
) -> Result<(), Error> {
    let mut stream = Stream::open(index, config)?;
    while !stop.load(Ordering::Acquire) {
        let Some(rgb) = stream.read(stop)? else {
            break;
        };
        let rgb = rgb.shrink(config.max_pixels);
        latest.lock().expect("poisoned").publish(rgb);
    }
    Ok(())
}

#[derive(Default)]
struct Latest {
    frame: Option<Frame>,
    failure: Option<Error>,
}

impl Latest {
    fn publish(&mut self, rgb: Rgb) {
        let seq = self.frame.as_ref().map_or(1, |frame| frame.seq + 1);
        self.frame = Some(Frame { rgb, seq });
    }
}

/// A device reserved in [`RUNNING`], released when dropped.
struct Lease(u32);

impl Lease {
    /// None while another lease holds `index`.
    fn take(index: u32) -> Option<Self> {
        let taken = RUNNING.lock().expect("poisoned").insert(index);
        taken.then(|| Self(index))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        RUNNING.lock().expect("poisoned").remove(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        capture::{Latest, Lease},
        frame::{Frame, Rgb},
    };

    fn rgb(value: u8) -> Rgb {
        Rgb {
            data: vec![value; 3],
            width: 1,
            height: 1,
        }
    }

    #[test]
    fn only_the_latest_frame_is_kept_and_its_seq_grows_by_one() {
        let mut latest = Latest::default();
        assert_eq!(latest.frame, None);
        latest.publish(rgb(1));
        assert_eq!(
            latest.frame,
            Some(Frame {
                rgb: rgb(1),
                seq: 1
            })
        );
        latest.publish(rgb(2));
        latest.publish(rgb(3));
        assert_eq!(
            latest.frame,
            Some(Frame {
                rgb: rgb(3),
                seq: 3
            })
        );
    }

    #[test]
    fn a_device_is_leased_once_until_released() {
        // an index no real device has, so no other test races for it
        let index = u32::MAX;
        let lease = Lease::take(index).unwrap();
        assert!(Lease::take(index).is_none());
        drop(lease);
        assert!(Lease::take(index).is_some());
    }
}
