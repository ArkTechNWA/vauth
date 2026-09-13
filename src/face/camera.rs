//! Camera capture via nokhwa (V4L2 backend).

use anyhow::{Context, Result};
use dlib_face_recognition::ImageMatrix;
use image::{ImageBuffer, Rgb};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType, Resolution};
use nokhwa::Camera;

/// RGB image type matching what `ImageMatrix::from_image()` expects.
pub type RgbImage = ImageBuffer<Rgb<u8>, Vec<u8>>;

/// Camera configuration.
pub struct CameraConfig {
    pub index: u32,
    pub width: u32,
    pub height: u32,
}

impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            index: 0,
            width: 640,
            height: 480,
        }
    }
}

/// A live camera session capturing frames via V4L2.
pub struct CameraSession {
    camera: Camera,
}

impl CameraSession {
    /// Open a camera device and start the capture stream.
    pub fn open(config: &CameraConfig) -> Result<Self> {
        let index = CameraIndex::Index(config.index);
        let requested = RequestedFormat::new::<RgbFormat>(
            RequestedFormatType::Closest(
                nokhwa::utils::CameraFormat::new(
                    Resolution::new(config.width, config.height),
                    nokhwa::utils::FrameFormat::MJPEG,
                    30,
                ),
            ),
        );

        let mut camera = Camera::new(index, requested)
            .context("failed to open camera")?;

        camera.open_stream()
            .context("failed to start camera stream")?;

        Ok(Self { camera })
    }

    /// Capture a single frame as an RGB image.
    pub fn capture_rgb(&mut self) -> Result<RgbImage> {
        let frame = self.camera.frame()
            .context("failed to capture frame")?;
        let decoded = frame.decode_image::<RgbFormat>()
            .context("failed to decode frame to RGB")?;
        Ok(decoded)
    }

    /// Capture a single frame as a dlib `ImageMatrix`.
    pub fn capture_frame(&mut self) -> Result<ImageMatrix> {
        let rgb = self.capture_rgb()?;
        Ok(ImageMatrix::from_image(&rgb))
    }
}
