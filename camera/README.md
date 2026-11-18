# bwk-camera

**Experimental. Do not use in production or with real coins. API will break.**

Camera capture for QR scanning: Linux (V4L2), Windows (Media Foundation) and macOS
(AVFoundation), through `nokhwa`.

- `list()` offers the cameras that capture video, by index, and asks for the camera
  permission first where the platform has one (macOS).
- `Camera::start(index, config)` streams one camera on a capture thread that keeps only
  the latest frame. `Camera::frame()` hands it back with a `seq` that grows by one per
  frame, so a reader skips a frame it has seen. Dropping the `Camera` stops the capture.
- A frame is RGB888 (`Frame::rgb`), shrunk with an integer box average to the pixel
  limit of the `Config`; `Rgb::grey()` gives the luma a `bwk-qr` decoder reads.

The mode is the lowest resolution that meets the minimum width, height and frame rate of
the `Config`, raw formats (YUYV, NV12, GRAY, RGB, BGR) over MJPEG. When no mode reaches
`min_fps`, the same choice runs again at `fallback_fps` if one is set, and the log says
so; only when that also finds nothing does the camera fail with `NoSuitableMode`. On
macOS the session runs at AVFoundation's 1280x720 preset, checked against the same
minimum, then the fallback rate.

The tuning stays the caller's: the minimum mode and the pixel limit come in the
`Config`, how often frames are read and decoded is up to the reader.

Features:

- `mjpeg` (default) decodes MJPEG frames through `mozjpeg`, which needs a C toolchain.
  Without it an MJPEG mode never qualifies.
