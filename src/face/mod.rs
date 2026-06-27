//! Native face recognition engine — replaces howdy dependency.
//!
//! Uses dlib (via dlib-face-recognition crate) for face detection and
//! 128-dimensional face encoding. Compatible with howdy's model format.

pub mod models;
pub mod camera;
pub mod overlay;

use dlib_face_recognition::{
    FaceDetector, FaceDetectorTrait,
    FaceEncoderNetwork, FaceEncoderTrait,
    LandmarkPredictor, LandmarkPredictorTrait,
    ImageMatrix,
};
use std::path::Path;

/// Result of a face verification attempt.
#[derive(Debug, Clone)]
pub enum VerifyResult {
    /// Face matched an enrolled model.
    Match {
        model_label: String,
        distance: f64,
    },
    /// Face detected but no match found.
    NoMatch {
        best_distance: f64,
    },
    /// No face detected in the frame.
    NoFace,
}

/// The face recognition engine. Holds loaded dlib models.
///
/// Expensive to construct (loads ~30MB of neural network weights).
/// Create once, reuse across verification attempts.
pub struct FaceEngine {
    detector: FaceDetector,
    predictor: LandmarkPredictor,
    encoder: FaceEncoderNetwork,
    threshold: f64,
}

impl FaceEngine {
    /// Load the face engine from dlib model files.
    ///
    /// `model_dir` must contain:
    /// - `shape_predictor_5_face_landmarks.dat`
    /// - `dlib_face_recognition_resnet_model_v1.dat`
    ///
    /// The FHOG face detector is built-in (no model file needed).
    pub fn new(model_dir: &Path, threshold: f64) -> anyhow::Result<Self> {
        let predictor_path = model_dir.join("shape_predictor_5_face_landmarks.dat");
        let encoder_path = model_dir.join("dlib_face_recognition_resnet_model_v1.dat");

        if !predictor_path.exists() {
            anyhow::bail!("Missing: {}", predictor_path.display());
        }
        if !encoder_path.exists() {
            anyhow::bail!("Missing: {}", encoder_path.display());
        }

        let detector = FaceDetector::default();
        let predictor = LandmarkPredictor::open(
            predictor_path.to_str().ok_or_else(|| anyhow::anyhow!("invalid path"))?,
        ).map_err(|_| anyhow::anyhow!("Failed to load landmark predictor"))?;
        let encoder = FaceEncoderNetwork::open(
            encoder_path.to_str().ok_or_else(|| anyhow::anyhow!("invalid path"))?,
        ).map_err(|_| anyhow::anyhow!("Failed to load face encoder network"))?;

        Ok(Self {
            detector,
            predictor,
            encoder,
            threshold,
        })
    }

    /// Detect faces in an image and compute 128-d encodings.
    pub fn encode(&self, image: &ImageMatrix) -> Vec<Vec<f64>> {
        let locations = self.detector.face_locations(image);
        if locations.is_empty() {
            return vec![];
        }

        let mut encodings = Vec::new();
        for rect in locations.iter() {
            let landmarks = self.predictor.face_landmarks(image, &rect);
            let face_encodings = self.encoder.get_face_encodings(image, &[landmarks], 0);
            for enc in face_encodings.iter() {
                let slice: &[f64] = enc.as_ref();
                encodings.push(slice.to_vec());
            }
        }
        encodings
    }

    /// Verify a frame against enrolled face models.
    pub fn verify_with_models(
        &self,
        image: &ImageMatrix,
        face_models: &[models::FaceModel],
    ) -> VerifyResult {
        let detected = self.encode(image);
        if detected.is_empty() {
            return VerifyResult::NoFace;
        }

        let mut best_distance = f64::MAX;
        let mut best_label = String::new();

        for det_enc in &detected {
            for model in face_models {
                for enrolled_enc in &model.data {
                    if enrolled_enc.len() != 128 {
                        continue;
                    }
                    let dist = euclidean_distance(det_enc, enrolled_enc);
                    if dist < best_distance {
                        best_distance = dist;
                        best_label = model.label.clone();
                    }
                }
            }
        }

        if best_distance <= self.threshold {
            VerifyResult::Match {
                model_label: best_label,
                distance: best_distance,
            }
        } else {
            VerifyResult::NoMatch { best_distance }
        }
    }
}

/// Euclidean distance between two 128-d face encodings.
fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

/// Default path to dlib model files (howdy's location).
pub fn default_model_dir() -> &'static Path {
    Path::new("/lib/security/howdy/dlib-data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_euclidean_distance_identical() {
        let a = vec![0.0; 128];
        assert!((euclidean_distance(&a, &a) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_euclidean_distance_known() {
        let a = vec![1.0; 128];
        let b = vec![0.0; 128];
        let expected = (128.0_f64).sqrt();
        assert!((euclidean_distance(&a, &b) - expected).abs() < 1e-10);
    }
}
