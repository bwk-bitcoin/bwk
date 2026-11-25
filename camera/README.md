# bwk-camera

Camera capture for QR scanning on desktop: the built-in or USB cameras of Linux
(V4L2), Windows (Media Foundation) and macOS (AVFoundation), through `nokhwa`. Mobile
platforms (Android, iOS) are not targeted.

- `list()` offers the cameras that capture video and asks for the camera permission
  first where the platform has one (macOS). It returns a receiver at once and answers
  on it from a thread of its own, once the user answered the permission dialog on
  macOS, at once elsewhere, so it never blocks a UI thread. On Linux a node the user
  may not open is left out, as the raw nodes behind a MIPI camera relayed through
  v4l2loopback are, unless no other camera is found: starting one then fails with
  `PermissionDenied`.
- A camera is known by its `CameraId`, the OS's identifier for the device: its node on
  Linux (`/dev/videoN`), its symbolic link on Windows, its `AVCaptureDevice` unique ID
  on macOS. It stays the same while the camera is connected, whatever other cameras
  come and go, and `CameraId::as_str()` gives it to remember a user's choice, found
  again by comparing it with the ids `list()` returns. On Linux a node freed by an
  unplugged camera can go to the next one plugged.
- `Camera::start(&id, config)` streams one camera on a capture thread that keeps only
  the latest frame, and fails with `NoCamera` once that camera is gone.
  `Camera::frame()` moves that frame out, so it returns each frame once, then None
  until a newer one is captured. `Camera::wait_frame(timeout)` blocks until a newer
  frame or the capture failure, at most `timeout`. Dropping the `Camera` stops the capture.
- A frame is RGB888 (`Rgb`), square: the centered square of the captured frame,
  shrunk with an integer box average by `bwk_qr::image::shrink_factor` unless
  `Config::fine_scan`: a 1080 frame is kept whole, a 2160 one halved. It is what a
  `bwk-qr` decoder with the same `fine_scan` scans, so a preview of it shows exactly
  the area a code is read in. `Rgb::grey()` gives the luma that decoder reads.

Among the readable modes, raw formats (YUYV, NV12, GRAY, RGB, BGR) and MJPEG with the
`mjpeg` feature, the mode is chosen by, in order:

1. a shorter side of at least `bwk_qr::image::SCAN_SIDE` (1080); a mode below it only
   when none reaches it at an acceptable frame rate;
2. a frame rate meeting `min_fps` over one meeting only `fallback_fps`; a mode meeting
   neither is never chosen, and the log says when the fallback rate was met;
3. the resolution: the smallest that reaches `SCAN_SIDE`, or the largest below it,
   by shorter side then area; with `fine_scan`, the largest;
4. raw formats over MJPEG;
5. the highest frame rate.

When no mode meets a rate the camera fails with `NoSuitableMode`. On macOS the
session runs at AVFoundation's 1920x1080 preset, or 1280x720 when the camera has no
1080p mode, with `fine_scan` 3840x2160 first; its frame rate is checked against
`min_fps` then the fallback rate.

The tuning stays the caller's: the minimum frame rate and the fine scan toggle come
in the `Config`, how often frames are read and decoded is up to the reader.

The `capture` module holds `list`, `Camera`, `CameraId` and `CameraInfo`, the `frame`
module `Rgb`, the `error` module `Error`, and `Config` sits at the crate root.
`Error::NoSuitableMode` lists the modes offered as `nokhwa::utils::CameraFormat`, so a
caller that reads them depends on `nokhwa`.

Features:

- `mjpeg` (default) decodes MJPEG frames through `mozjpeg`, which needs a C toolchain.
  Without it an MJPEG mode never qualifies.
