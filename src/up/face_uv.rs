//! Face-based user verification — opt-in, fail-safe.
//!
//! FaceVerifier bundles the face engine, liveness checker, and enrolled models
//! into a single struct that can be shared across verification attempts.
//! Face failures never block authentication — they fall through to PAM.

use crate::face::camera::CameraConfig;
use crate::face::liveness::{LivenessChecker, LivenessResult};
use crate::face::models::FaceModel;
use crate::face::{FaceEngine, VerifyResult};
use std::path::Path;
use std::time::Duration;

/// Bundled face verification state. Created once at startup, shared via Arc.
///
/// # Safety
/// The dlib types (FaceDetector, LandmarkPredictor, FaceEncoderNetwork) contain
/// C++ pointers behind UnsafeCell, so Rust doesn't auto-derive Send/Sync.
/// However, our usage is safe: FaceVerifier is created once at startup and
/// verify() is called inside spawn_blocking with no concurrent mutation.
/// The dlib models are read-only after loading.
pub struct FaceVerifier {
    engine: FaceEngine,
    liveness: LivenessChecker,
    models: Vec<FaceModel>,
    camera_config: CameraConfig,
    liveness_timeout: Duration,
}

// SAFETY: dlib models are read-only after construction. verify() creates
// its own CameraSession per call — no shared mutable state.
unsafe impl Send for FaceVerifier {}
unsafe impl Sync for FaceVerifier {}

impl FaceVerifier {
    /// Load all face verification resources.
    ///
    /// Returns Err if any required model or face data is missing — the daemon
    /// should start without face verification in that case.
    pub fn new(
        model_dir: &Path,
        username: &str,
        threshold: f64,
        liveness_timeout_secs: u64,
    ) -> anyhow::Result<Self> {
        let engine = FaceEngine::new(model_dir, threshold)?;
        let liveness = LivenessChecker::new(model_dir)?;

        let model_path = crate::face::models::model_path(username)?;
        let models = if model_path.exists() {
            crate::face::models::load_models(&model_path)?
        } else {
            // Try howdy models as fallback
            let howdy_path =
                std::path::PathBuf::from(format!("/lib/security/howdy/models/{username}.dat"));
            if howdy_path.exists() {
                crate::face::models::load_models(&howdy_path)?
            } else {
                anyhow::bail!(
                    "no face models found for '{username}' at {} or {}",
                    model_path.display(),
                    howdy_path.display()
                );
            }
        };

        if models.is_empty() {
            anyhow::bail!("face model file exists but contains no models");
        }

        tracing::info!(
            models = models.len(),
            encodings = models.iter().map(|m| m.data.len()).sum::<usize>(),
            username = username,
            "face verifier loaded"
        );

        Ok(Self {
            engine,
            liveness,
            models,
            camera_config: CameraConfig::default(),
            liveness_timeout: Duration::from_secs(liveness_timeout_secs),
        })
    }

    /// Run face verification: camera → liveness → identity.
    ///
    /// This is a blocking call (camera I/O + dlib inference).
    /// Call from `spawn_blocking`.
    ///
    /// Returns Ok(()) on successful verification, Err(reason) on any failure.
    pub fn verify(&self) -> Result<(), String> {
        let mut session = crate::face::camera::CameraSession::open(&self.camera_config)
            .map_err(|e| format!("camera: {e}"))?;

        let liveness_result = self
            .liveness
            .check(&mut session, self.liveness_timeout)
            .map_err(|e| format!("liveness error: {e}"))?;

        match &liveness_result {
            LivenessResult::Failed(failure) => {
                return Err(format!("liveness failed: {failure:?}"));
            }
            LivenessResult::Alive {
                blinks,
                mouth_events,
                ..
            } => {
                tracing::debug!(blinks, mouth_events, "liveness confirmed");
            }
        }

        let frame = session
            .capture_frame()
            .map_err(|e| format!("capture: {e}"))?;

        match self.engine.verify_with_models(&frame, &self.models) {
            VerifyResult::Match {
                model_label,
                distance,
            } => {
                tracing::info!(
                    model = model_label,
                    distance = format!("{distance:.4}"),
                    "face identity match"
                );
                Ok(())
            }
            VerifyResult::NoMatch { best_distance } => {
                Err(format!("no identity match (best distance: {best_distance:.4})"))
            }
            VerifyResult::NoFace => Err("no face in verification frame".into()),
        }
    }
}
