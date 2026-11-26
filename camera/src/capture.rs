use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

#[cfg(not(target_os = "windows"))]
use nokhwa::utils::{ApiBackend, CameraIndex};

#[cfg(target_os = "macos")]
use crate::macos::Stream;
#[cfg(target_os = "windows")]
use crate::media_foundation::{self, Stream};
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use crate::native::Stream;
use crate::{error::Error, frame::Rgb, Config};

/// The devices with a capture thread running. A second open of the same device fails,
/// and a stopped thread may still hold it, so this is process wide.
static RUNNING: Mutex<BTreeSet<CameraId>> = Mutex::new(BTreeSet::new());

/// The node V4L2 opens a camera through, followed by its number.
#[cfg(target_os = "linux")]
const V4L2_NODE: &str = "/dev/video";

/// The OS's stable identifier for a camera while it stays connected: other cameras
/// being added or removed leave it unchanged. It is the device node on Linux
/// (`/dev/videoN`), the device symbolic link on Windows and the `AVCaptureDevice`
/// unique ID on macOS. On Linux a node freed by an unplugged camera can go to the next
/// one plugged, so a remembered id may then find another camera.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CameraId(String);

impl CameraId {
    /// To remember a user's choice: the camera is found again among those [`list`]
    /// returns by comparing it with their ids.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// nokhwa's V4L2 query gives the node number, not its path.
    #[cfg(target_os = "linux")]
    fn from_query(info: &nokhwa::utils::CameraInfo) -> Result<Self, Error> {
        Ok(Self(format!("{V4L2_NODE}{}", info.index().as_index()?)))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn from_query(info: &nokhwa::utils::CameraInfo) -> Result<Self, Error> {
        Ok(Self(info.misc()))
    }

    /// nokhwa's V4L2 backend opens a device by its node number only.
    #[cfg(target_os = "linux")]
    pub fn index(&self) -> Result<CameraIndex, Error> {
        self.0
            .strip_prefix(V4L2_NODE)
            .and_then(|number| number.parse().ok())
            .map(CameraIndex::Index)
            .ok_or(Error::NoCamera)
    }

    /// AVFoundation opens a device by its id, `NoCamera` once gone.
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn index(&self) -> Result<CameraIndex, Error> {
        Ok(CameraIndex::String(self.0.clone()))
    }
}

impl fmt::Display for CameraId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraInfo {
    pub id: CameraId,
    pub name: String,
}

/// The cameras that capture video, in the order the OS numbers them, sent once on the
/// returned receiver. It is a receiver because on macOS the list waits for the user to
/// answer the camera permission dialog, for as long as they take: the query runs on a
/// thread of its own, so this returns at once and is safe on a UI thread. Elsewhere
/// there is no dialog and the answer comes at once. Dropping the receiver discards it.
pub fn list() -> mpsc::Receiver<Result<Vec<CameraInfo>, Error>> {
    let (sender, receiver) = mpsc::channel();
    let sender_cloned = sender.clone();
    let spawned = thread::Builder::new()
        .name("bwk-camera-list".to_owned())
        .spawn(move || {
            let _ = sender_cloned.send(query());
        });
    if let Err(error) = spawned {
        let _ = sender.send(Err(Error::Capture(error.to_string())));
    }
    receiver
}

#[cfg(not(target_os = "windows"))]
fn query() -> Result<Vec<CameraInfo>, Error> {
    request_access()?;
    let mut cameras = Vec::new();
    let mut refused = Vec::new();
    for info in nokhwa::query(ApiBackend::Auto)? {
        let id = CameraId::from_query(&info)?;
        let listed = match probe(&id) {
            Node::Captures | Node::Unknown => &mut cameras,
            Node::Refused => &mut refused,
            Node::Other => continue,
        };
        let index = info.index().as_index()?;
        listed.push((
            index,
            CameraInfo {
                id,
                name: info.human_name(),
            },
        ));
    }
    let mut cameras = offered(cameras, refused);
    if cameras.is_empty() {
        return Err(Error::NoCamera);
    }
    // V4L2 lists the nodes in directory order, the node number orders them as the OS
    // list does elsewhere
    cameras.sort_by_key(|(index, _)| *index);
    Ok(cameras.into_iter().map(|(_, camera)| camera).collect())
}

/// Windows lists no camera while access is refused in its privacy settings, and fails
/// opening one with `PermissionDenied`.
#[cfg(target_os = "windows")]
fn query() -> Result<Vec<CameraInfo>, Error> {
    let cameras: Vec<CameraInfo> = media_foundation::devices()?
        .into_iter()
        .map(|device| CameraInfo {
            id: CameraId(device.link),
            name: device.name,
        })
        .collect();
    if cameras.is_empty() {
        return Err(Error::NoCamera);
    }
    Ok(cameras)
}

/// Only macOS asks, and blocks until the user answers; elsewhere it is granted at once.
#[cfg(not(target_os = "windows"))]
fn request_access() -> Result<(), Error> {
    if nokhwa::nokhwa_check() {
        return Ok(());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    nokhwa::nokhwa_initialize(move |granted| {
        let _ = sender.try_send(granted);
    });
    match receiver.recv() {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(Error::PermissionDenied),
    }
}

/// What a listed device turns out to be once probed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Node {
    Captures,
    /// The user may not open it.
    Refused,
    /// It streams something else than video.
    Other,
    /// Its caps cannot be read for another reason: it is kept, so opening it reports
    /// why.
    Unknown,
}

/// V4L2 lists a UVC webcam twice: its capture node and a node that only streams
/// metadata. It also lists nodes the user is refused: behind a MIPI camera relayed
/// through v4l2loopback sit the raw nodes of its image processing unit, which udev
/// keeps from the user.
#[cfg(target_os = "linux")]
fn probe(id: &CameraId) -> Node {
    match v4l::Device::with_path(id.as_str()).and_then(|device| device.query_caps()) {
        Ok(caps)
            if caps
                .capabilities
                .contains(v4l::capability::Flags::VIDEO_CAPTURE) =>
        {
            Node::Captures
        }
        Ok(_) => Node::Other,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Node::Refused,
        Err(_) => Node::Unknown,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn probe(_id: &CameraId) -> Node {
    Node::Captures
}

/// The devices the user is refused are offered only when no other is, so that starting
/// one says the permission is missing instead of no camera being found.
#[cfg_attr(target_os = "windows", allow(dead_code))]
fn offered<T>(cameras: Vec<T>, refused: Vec<T>) -> Vec<T> {
    if cameras.is_empty() {
        refused
    } else {
        cameras
    }
}

/// A camera streaming on its own thread. Dropping it stops the capture.
pub struct Camera {
    frame: LatestFrame,
    stop: Arc<AtomicBool>,
}

impl Camera {
    /// The device opens on the capture thread, so a failure there shows up later
    /// through [`Camera::failure`]. On macOS, [`list`] must have answered first: it asks
    /// for camera access, and until granted this is `PermissionDenied`. A camera gone
    /// since [`list`] fails with `NoCamera`, never opens another one.
    pub fn start(id: &CameraId, config: Config) -> Result<Self, Error> {
        if !access_granted() {
            return Err(Error::PermissionDenied);
        }
        let lease = Lease::take(id.clone()).ok_or(Error::Busy)?;
        let frame = LatestFrame::default();
        let stop = Arc::new(AtomicBool::new(false));
        let frame_cloned = frame.clone();
        let stop_cloned = stop.clone();
        // the thread is detached: a v4l2 read has no timeout, so it notices the stop
        // flag after its current frame and releases the device on its own
        thread::Builder::new()
            .name("bwk-camera".to_owned())
            .spawn(move || {
                let id = &lease.0;
                if let Err(error) = capture(id, &config, &frame_cloned, &stop_cloned) {
                    log::warn!("camera {id} stopped: {error}");
                    frame_cloned.record_failure(error);
                }
            })
            .map_err(|error| Error::Capture(error.to_string()))?;
        Ok(Self { frame, stop })
    }

    /// The latest frame, moved out: once returned it is None until a newer one is
    /// captured.
    pub fn frame(&self) -> Option<Rgb> {
        self.frame.take()
    }

    /// Like [`Camera::frame`], but waits up to `timeout` for a newer frame. Returns None
    /// at once once the capture failed.
    pub fn wait_frame(&self, timeout: Duration) -> Option<Rgb> {
        self.frame.wait(timeout)
    }

    /// Why the capture stopped on its own, None while it runs.
    pub fn failure(&self) -> Option<Error> {
        self.frame.failure()
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(not(target_os = "windows"))]
fn access_granted() -> bool {
    nokhwa::nokhwa_check()
}

/// A refusal shows when the camera opens.
#[cfg(target_os = "windows")]
fn access_granted() -> bool {
    true
}

fn capture(
    id: &CameraId,
    config: &Config,
    frame: &LatestFrame,
    stop: &AtomicBool,
) -> Result<(), Error> {
    let mut stream = Stream::open(id, config)?;
    while !stop.load(Ordering::Acquire) {
        let Some(rgb) = stream.read(stop)? else {
            break;
        };
        let rgb = rgb.fit(config.fine_scan);
        frame.publish(rgb);
    }
    Ok(())
}

/// What the capture thread hands the reader: a frame is taken out when read, so it is
/// read once, while the failure stays readable. A clone shares the same slot.
#[derive(Default, Clone)]
struct LatestFrame(Arc<Slot>);

#[derive(Default)]
struct Slot {
    latest: Mutex<Latest>,
    changed: Condvar,
}

#[derive(Default)]
struct Latest {
    frame: Option<Rgb>,
    failure: Option<Error>,
}

impl LatestFrame {
    fn publish(&self, rgb: Rgb) {
        self.0.latest.lock().expect("poisoned").frame = Some(rgb);
        self.0.changed.notify_all();
    }

    fn take(&self) -> Option<Rgb> {
        self.0.latest.lock().expect("poisoned").frame.take()
    }

    fn wait(&self, timeout: Duration) -> Option<Rgb> {
        let latest = self.0.latest.lock().expect("poisoned");
        let (mut latest, _) = self
            .0
            .changed
            .wait_timeout_while(latest, timeout, |latest| {
                latest.frame.is_none() && latest.failure.is_none()
            })
            .expect("poisoned");
        latest.frame.take()
    }

    fn record_failure(&self, error: Error) {
        self.0.latest.lock().expect("poisoned").failure = Some(error);
        self.0.changed.notify_all();
    }

    fn failure(&self) -> Option<Error> {
        self.0.latest.lock().expect("poisoned").failure.clone()
    }
}

/// A device reserved in [`RUNNING`], released when dropped.
struct Lease(CameraId);

impl Lease {
    /// None while another lease holds `id`.
    fn take(id: CameraId) -> Option<Self> {
        let taken = RUNNING.lock().expect("poisoned").insert(id.clone());
        taken.then(|| Self(id))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        RUNNING.lock().expect("poisoned").remove(&self.0);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use nokhwa::utils::CameraIndex;

    use std::time::Duration;

    use crate::{
        capture::{offered, CameraId, LatestFrame, Lease},
        error::Error,
        frame::Rgb,
    };

    fn rgb(value: u8) -> Rgb {
        Rgb::from_frame(vec![value; 3], 1, 1).unwrap()
    }

    #[test]
    fn a_frame_is_read_once() {
        let frame = LatestFrame::default();
        assert_eq!(frame.take(), None);
        frame.publish(rgb(1));
        assert_eq!(frame.take(), Some(rgb(1)));
        assert_eq!(frame.take(), None);
    }

    #[test]
    fn a_newer_frame_replaces_an_untaken_one() {
        let frame = LatestFrame::default();
        frame.publish(rgb(1));
        frame.publish(rgb(2));
        assert_eq!(frame.take(), Some(rgb(2)));
        assert_eq!(frame.take(), None);
    }

    #[test]
    fn a_waiting_reader_wakes_on_a_frame() {
        let frame = LatestFrame::default();
        let publisher = frame.clone();
        let thread = std::thread::spawn(move || publisher.publish(rgb(1)));
        assert_eq!(frame.wait(Duration::from_secs(10)), Some(rgb(1)));
        thread.join().unwrap();
        assert_eq!(frame.wait(Duration::from_millis(1)), None);
    }

    #[test]
    fn a_failure_ends_the_wait() {
        let frame = LatestFrame::default();
        frame.record_failure(Error::NoCamera);
        assert_eq!(frame.wait(Duration::from_secs(10)), None);
    }

    #[test]
    fn a_device_is_leased_once_until_released() {
        // an id no real device has, so no other test races for it
        let id = CameraId("bwk-camera-test".to_owned());
        let lease = Lease::take(id.clone()).unwrap();
        assert!(Lease::take(id.clone()).is_none());
        drop(lease);
        assert!(Lease::take(id).is_some());
    }

    #[test]
    fn a_refused_device_is_offered_only_when_no_other_is() {
        assert_eq!(offered(vec![32], vec![0, 1]), [32]);
        assert_eq!(offered(vec![], vec![0, 1]), [0, 1]);
        assert_eq!(offered::<u32>(vec![], vec![]), []);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_linux_id_opens_its_node_number() {
        let id = CameraId("/dev/video12".to_owned());
        assert_eq!(id.index(), Ok(CameraIndex::Index(12)));
        let id = CameraId("/dev/sda".to_owned());
        assert_eq!(id.index(), Err(Error::NoCamera));
    }
}
