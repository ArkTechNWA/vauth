//! Liveness detection via EAR (Eye Aspect Ratio) and MAR (Mouth Aspect Ratio).
//!
//! Uses the 68-point dlib landmark model to detect blinks and mouth movement,
//! preventing photo-based spoofing attacks.

use anyhow::Result;
use dlib_face_recognition::{
    FaceDetector, FaceDetectorTrait,
    LandmarkPredictor, LandmarkPredictorTrait,
    Point,
};
use std::path::Path;
use std::time::{Duration, Instant};

use super::camera::CameraSession;

// 68-point landmark indices (0-indexed).
const RIGHT_EYE: [usize; 6] = [36, 37, 38, 39, 40, 41];
const LEFT_EYE: [usize; 6] = [42, 43, 44, 45, 46, 47];
// Inner mouth landmarks for MAR.
const INNER_MOUTH_TOP: [usize; 3] = [61, 62, 63];
const INNER_MOUTH_BOTTOM: [usize; 3] = [67, 66, 65];
const INNER_MOUTH_LEFT: usize = 60;
const INNER_MOUTH_RIGHT: usize = 64;

// Thresholds tuned for dlib's 68-point model.
const EAR_BLINK_THRESHOLD: f64 = 0.21;
const EAR_OPEN_THRESHOLD: f64 = 0.23;
const MAR_OPEN_THRESHOLD: f64 = 0.3;
const MAR_CLOSED_THRESHOLD: f64 = 0.15;

/// Result of a liveness check.
#[derive(Debug, Clone)]
pub enum LivenessResult {
    /// Face is live — detected real movement.
    Alive {
        blinks: u32,
        mouth_events: u32,
        frames_analyzed: u32,
    },
    /// Liveness check failed.
    Failed(LivenessFailure),
}

/// Why liveness failed.
#[derive(Debug, Clone)]
pub enum LivenessFailure {
    /// No face detected in any frame.
    NoFace,
    /// Face detected but no motion (possible photo).
    NoMotion { frames_analyzed: u32 },
    /// Ran out of time.
    Timeout { frames_analyzed: u32 },
}

/// Tracks EAR/MAR state transitions across frames.
struct MotionTracker {
    // Blink: eyes open → closed → open
    eyes_were_open: bool,
    eyes_closed: bool,
    blinks: u32,
    // Mouth: closed → open → closed
    mouth_was_closed: bool,
    mouth_opened: bool,
    mouth_events: u32,
}

impl MotionTracker {
    fn new() -> Self {
        Self {
            eyes_were_open: false,
            eyes_closed: false,
            blinks: 0,
            mouth_was_closed: false,
            mouth_opened: false,
            mouth_events: 0,
        }
    }

    fn update(&mut self, ear: f64, mar: f64) {
        // Track blinks: open → closed → open = 1 blink
        if ear > EAR_OPEN_THRESHOLD {
            if self.eyes_closed {
                self.blinks += 1;
                self.eyes_closed = false;
            }
            self.eyes_were_open = true;
        } else if ear < EAR_BLINK_THRESHOLD && self.eyes_were_open {
            self.eyes_closed = true;
        }

        // Track mouth: closed → open → closed = 1 event
        if mar < MAR_CLOSED_THRESHOLD {
            if self.mouth_opened {
                self.mouth_events += 1;
                self.mouth_opened = false;
            }
            self.mouth_was_closed = true;
        } else if mar > MAR_OPEN_THRESHOLD && self.mouth_was_closed {
            self.mouth_opened = true;
        }
    }

    fn is_alive(&self) -> bool {
        self.blinks >= 1 || self.mouth_events >= 1
    }
}

/// Liveness checker using 68-point dlib landmarks.
pub struct LivenessChecker {
    detector: FaceDetector,
    predictor: LandmarkPredictor,
}

impl LivenessChecker {
    /// Load the liveness checker with the 68-point landmark model.
    ///
    /// `model_dir` must contain `shape_predictor_68_face_landmarks.dat`.
    pub fn new(model_dir: &Path) -> Result<Self> {
        let predictor_path = model_dir.join("shape_predictor_68_face_landmarks.dat");
        if !predictor_path.exists() {
            anyhow::bail!(
                "Missing 68-point landmark model: {}\n\
                 Download from: http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2",
                predictor_path.display()
            );
        }

        let detector = FaceDetector::default();
        let predictor = LandmarkPredictor::open(
            predictor_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid path"))?,
        )
        .map_err(|_| anyhow::anyhow!("failed to load 68-point landmark predictor"))?;

        Ok(Self {
            detector,
            predictor,
        })
    }

    /// Run liveness detection over a camera session.
    ///
    /// Captures frames until a blink or mouth event is detected,
    /// or the timeout expires.
    pub fn check(
        &self,
        session: &mut CameraSession,
        timeout: Duration,
    ) -> Result<LivenessResult> {
        let deadline = Instant::now() + timeout;
        let mut tracker = MotionTracker::new();
        let mut frames = 0u32;
        let mut any_face = false;

        while Instant::now() < deadline {
            let image = match session.capture_frame() {
                Ok(img) => img,
                Err(_) => continue, // dropped frame, try again
            };
            frames += 1;

            let locations = self.detector.face_locations(&image);
            let Some(rect) = locations.first() else {
                continue;
            };
            any_face = true;

            let landmarks = self.predictor.face_landmarks(&image, rect);
            if landmarks.len() < 68 {
                continue;
            }

            let ear = avg_ear(&landmarks);
            let mar = mar(&landmarks);
            tracker.update(ear, mar);

            if tracker.is_alive() {
                return Ok(LivenessResult::Alive {
                    blinks: tracker.blinks,
                    mouth_events: tracker.mouth_events,
                    frames_analyzed: frames,
                });
            }
        }

        if !any_face {
            Ok(LivenessResult::Failed(LivenessFailure::NoFace))
        } else if !tracker.is_alive() {
            Ok(LivenessResult::Failed(LivenessFailure::NoMotion {
                frames_analyzed: frames,
            }))
        } else {
            Ok(LivenessResult::Failed(LivenessFailure::Timeout {
                frames_analyzed: frames,
            }))
        }
    }
}

/// Eye Aspect Ratio for one eye (6 landmarks).
///
/// ```text
///   p1 ---- p2
///  /          \
/// p0          p3
///  \          /
///   p5 ---- p4
///
/// EAR = (||p1-p5|| + ||p2-p4||) / (2 * ||p0-p3||)
/// ```
fn eye_ear(landmarks: &[Point], indices: &[usize; 6]) -> f64 {
    let p = |i: usize| -> (f64, f64) {
        let pt = &landmarks[indices[i]];
        (pt.x(), pt.y())
    };

    let dist = |a: (f64, f64), b: (f64, f64)| -> f64 {
        ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
    };

    let vertical_1 = dist(p(1), p(5));
    let vertical_2 = dist(p(2), p(4));
    let horizontal = dist(p(0), p(3));

    if horizontal < 1e-6 {
        return 0.0;
    }

    (vertical_1 + vertical_2) / (2.0 * horizontal)
}

/// Average EAR across both eyes.
fn avg_ear(landmarks: &[Point]) -> f64 {
    (eye_ear(landmarks, &RIGHT_EYE) + eye_ear(landmarks, &LEFT_EYE)) / 2.0
}

/// Mouth Aspect Ratio from inner mouth landmarks.
///
/// ```text
///       61  62  63
///  60                64
///       67  66  65
///
/// MAR = (||61-67|| + ||62-66|| + ||63-65||) / (3 * ||60-64||)
/// ```
fn mar(landmarks: &[Point]) -> f64 {
    let pt = |i: usize| -> (f64, f64) {
        let p = &landmarks[i];
        (p.x(), p.y())
    };

    let dist = |a: (f64, f64), b: (f64, f64)| -> f64 {
        ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
    };

    let v1 = dist(pt(INNER_MOUTH_TOP[0]), pt(INNER_MOUTH_BOTTOM[0]));
    let v2 = dist(pt(INNER_MOUTH_TOP[1]), pt(INNER_MOUTH_BOTTOM[1]));
    let v3 = dist(pt(INNER_MOUTH_TOP[2]), pt(INNER_MOUTH_BOTTOM[2]));
    let horizontal = dist(pt(INNER_MOUTH_LEFT), pt(INNER_MOUTH_RIGHT));

    if horizontal < 1e-6 {
        return 0.0;
    }

    (v1 + v2 + v3) / (3.0 * horizontal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_point(x: f64, y: f64) -> Point {
        Point::new(x, y)
    }

    /// Build a minimal 68-point landmark array with controllable eye/mouth geometry.
    fn make_landmarks(ear_ratio: f64, mar_ratio: f64) -> Vec<Point> {
        let mut pts = vec![make_point(0.0, 0.0); 68];

        // Right eye (indices 36-41): horizontal span = 20px
        // EAR = (v1 + v2) / (2 * h), so v = ear_ratio * h
        let h = 20.0;
        let v = ear_ratio * h;
        pts[36] = make_point(100.0, 100.0);        // p0 left corner
        pts[37] = make_point(105.0, 100.0 - v);     // p1 upper-left
        pts[38] = make_point(115.0, 100.0 - v);     // p2 upper-right
        pts[39] = make_point(120.0, 100.0);          // p3 right corner
        pts[40] = make_point(115.0, 100.0 + v);     // p4 lower-right
        pts[41] = make_point(105.0, 100.0 + v);     // p5 lower-left

        // Left eye — mirror
        pts[42] = make_point(140.0, 100.0);
        pts[43] = make_point(145.0, 100.0 - v);
        pts[44] = make_point(155.0, 100.0 - v);
        pts[45] = make_point(160.0, 100.0);
        pts[46] = make_point(155.0, 100.0 + v);
        pts[47] = make_point(145.0, 100.0 + v);

        // Inner mouth (indices 60-67): horizontal span = 30px
        // MAR = (v1+v2+v3) / (3*h), so each v = mar_ratio * h
        let mh = 30.0;
        let mv = mar_ratio * mh;
        pts[60] = make_point(110.0, 160.0);          // left corner
        pts[61] = make_point(115.0, 160.0 - mv);     // top-left
        pts[62] = make_point(125.0, 160.0 - mv);     // top-center
        pts[63] = make_point(135.0, 160.0 - mv);     // top-right
        pts[64] = make_point(140.0, 160.0);           // right corner
        pts[65] = make_point(135.0, 160.0 + mv);     // bottom-right
        pts[66] = make_point(125.0, 160.0 + mv);     // bottom-center
        pts[67] = make_point(115.0, 160.0 + mv);     // bottom-left

        pts
    }

    #[test]
    fn test_ear_open_eyes() {
        let pts = make_landmarks(0.3, 0.0);
        let ear = avg_ear(&pts);
        assert!(ear > EAR_OPEN_THRESHOLD, "EAR {ear} should indicate open eyes");
    }

    #[test]
    fn test_ear_closed_eyes() {
        let pts = make_landmarks(0.05, 0.0);
        let ear = avg_ear(&pts);
        assert!(ear < EAR_BLINK_THRESHOLD, "EAR {ear} should indicate closed eyes");
    }

    #[test]
    fn test_mar_closed_mouth() {
        let pts = make_landmarks(0.3, 0.05);
        let mar_val = mar(&pts);
        assert!(mar_val < MAR_CLOSED_THRESHOLD, "MAR {mar_val} should indicate closed mouth");
    }

    #[test]
    fn test_mar_open_mouth() {
        let pts = make_landmarks(0.3, 0.4);
        let mar_val = mar(&pts);
        assert!(mar_val > MAR_OPEN_THRESHOLD, "MAR {mar_val} should indicate open mouth");
    }

    #[test]
    fn test_blink_detection() {
        let mut tracker = MotionTracker::new();
        // Simulate: open → closed → open
        tracker.update(0.30, 0.1); // eyes open
        assert_eq!(tracker.blinks, 0);
        tracker.update(0.15, 0.1); // eyes closed
        assert_eq!(tracker.blinks, 0);
        tracker.update(0.30, 0.1); // eyes reopen → blink counted
        assert_eq!(tracker.blinks, 1);
        assert!(tracker.is_alive());
    }

    #[test]
    fn test_mouth_event_detection() {
        let mut tracker = MotionTracker::new();
        // Simulate: closed → open → closed
        tracker.update(0.30, 0.1); // mouth closed
        assert_eq!(tracker.mouth_events, 0);
        tracker.update(0.30, 0.4); // mouth open
        assert_eq!(tracker.mouth_events, 0);
        tracker.update(0.30, 0.1); // mouth closed → event counted
        assert_eq!(tracker.mouth_events, 1);
        assert!(tracker.is_alive());
    }

    #[test]
    fn test_no_motion_not_alive() {
        let mut tracker = MotionTracker::new();
        // All frames with steady open eyes, closed mouth
        for _ in 0..30 {
            tracker.update(0.30, 0.1);
        }
        assert_eq!(tracker.blinks, 0);
        assert_eq!(tracker.mouth_events, 0);
        assert!(!tracker.is_alive());
    }
}
