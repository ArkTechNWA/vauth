//! Live verification test with diagnostics.
//! Usage: cargo run --bin vauth_verify [-- --diag]

use std::time::{Duration, Instant};
use dlib_face_recognition::{
    FaceDetector, FaceDetectorTrait,
    LandmarkPredictor, LandmarkPredictorTrait,
    Point,
};
use vauth::face::{
    camera::{CameraConfig, CameraSession},
    liveness::{LivenessChecker, LivenessResult},
    models,
    FaceEngine, VerifyResult,
};

fn main() -> anyhow::Result<()> {
    let diag = std::env::args().any(|a| a == "--diag");
    let model_dir = vauth::face::default_model_dir();

    println!("[*] Loading face engine...");
    let engine = FaceEngine::new(model_dir, 0.6)?;

    // Load face models
    let username = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "meldrey".into());
    let howdy_model_path = std::path::PathBuf::from(format!(
        "/lib/security/howdy/models/{username}.dat"
    ));
    let face_models = models::load_models(&howdy_model_path)?;
    println!("[*] Loaded {} model(s) for '{username}'", face_models.len());

    let config = CameraConfig::default();
    let mut session = CameraSession::open(&config)?;
    println!("[*] Camera open");

    if diag {
        // Diagnostic mode: show EAR/MAR per frame + identity, no liveness gate
        println!("[*] DIAGNOSTIC MODE — showing EAR/MAR per frame for 8 seconds");
        println!("[*] Blink or open your mouth and watch the numbers change\n");

        let detector = FaceDetector::default();
        let predictor_path = model_dir.join("shape_predictor_68_face_landmarks.dat");
        let predictor = LandmarkPredictor::open(
            predictor_path.to_str().unwrap()
        ).map_err(|_| anyhow::anyhow!("failed to load 68-point model"))?;

        let deadline = Instant::now() + Duration::from_secs(8);
        let mut frame_count = 0u32;
        let start = Instant::now();

        while Instant::now() < deadline {
            let image = match session.capture_frame() {
                Ok(img) => img,
                Err(e) => {
                    println!("  [frame {}] capture error: {}", frame_count, e);
                    continue;
                }
            };
            frame_count += 1;

            let locations = detector.face_locations(&image);
            if locations.is_empty() {
                println!("  [frame {:3}] no face", frame_count);
                continue;
            }

            let rect = &locations[0];
            let landmarks = predictor.face_landmarks(&image, rect);
            if landmarks.len() < 68 {
                println!("  [frame {:3}] landmarks: {} (expected 68)", frame_count, landmarks.len());
                continue;
            }

            let ear = avg_ear(&landmarks);
            let mar = mar_value(&landmarks);

            let ear_status = if ear < 0.21 { "CLOSED" } else if ear > 0.25 { "open" } else { "partial" };
            let mar_status = if mar > 0.6 { "OPEN" } else if mar < 0.3 { "closed" } else { "partial" };

            println!("  [frame {:3}] EAR={:.3} ({:7})  MAR={:.3} ({:7})",
                frame_count, ear, ear_status, mar, mar_status);
        }

        let elapsed = start.elapsed().as_secs_f64();
        println!("\n[*] {} frames in {:.1}s = {:.1} fps", frame_count, elapsed, frame_count as f64 / elapsed);

        // One final identity check
        println!("[*] Running identity check...");
        let frame = session.capture_frame()?;
        let verify = engine.verify_with_models(&frame, &face_models);
        match &verify {
            VerifyResult::Match { model_label, distance } => {
                println!("[+] IDENTITY MATCH: '{}' (distance: {:.4})", model_label, distance);
            }
            VerifyResult::NoMatch { best_distance } => {
                println!("[-] NO MATCH: best distance {:.4}", best_distance);
            }
            VerifyResult::NoFace => {
                println!("[-] NO FACE in verification frame");
            }
        }
    } else {
        // Normal mode: liveness then identity
        println!("[*] Loading liveness checker...");
        let liveness = LivenessChecker::new(model_dir)?;
        println!("[*] Look at the camera — blink or open your mouth!");
        println!("[*] You have 8 seconds...\n");

        let liveness_result = liveness.check(&mut session, Duration::from_secs(8))?;
        match &liveness_result {
            LivenessResult::Alive { blinks, mouth_events, frames_analyzed } => {
                println!("[+] LIVENESS PASSED: {} blink(s), {} mouth event(s), {} frames",
                    blinks, mouth_events, frames_analyzed);
            }
            LivenessResult::Failed(failure) => {
                println!("[-] LIVENESS FAILED: {:?}", failure);
                return Ok(());
            }
        }

        println!("[*] Capturing frame for identity...");
        let frame = session.capture_frame()?;
        let verify = engine.verify_with_models(&frame, &face_models);
        match (&liveness_result, &verify) {
            (LivenessResult::Alive { .. }, VerifyResult::Match { model_label, distance }) => {
                println!("[+] IDENTITY MATCH: '{}' (distance: {:.4})", model_label, distance);
                println!("\n==> VERIFICATION PASSED");
            }
            _ => {
                println!("[-] Identity result: {:?}", verify);
                println!("\n==> VERIFICATION FAILED");
            }
        }
    }

    Ok(())
}

// EAR helpers (duplicated here for the diagnostic binary)
fn eye_ear(landmarks: &[Point], indices: &[usize; 6]) -> f64 {
    let p = |i: usize| (landmarks[indices[i]].x(), landmarks[indices[i]].y());
    let dist = |a: (f64, f64), b: (f64, f64)| ((a.0-b.0).powi(2) + (a.1-b.1).powi(2)).sqrt();
    let v1 = dist(p(1), p(5));
    let v2 = dist(p(2), p(4));
    let h = dist(p(0), p(3));
    if h < 1e-6 { return 0.0; }
    (v1 + v2) / (2.0 * h)
}

fn avg_ear(landmarks: &[Point]) -> f64 {
    const R: [usize; 6] = [36, 37, 38, 39, 40, 41];
    const L: [usize; 6] = [42, 43, 44, 45, 46, 47];
    (eye_ear(landmarks, &R) + eye_ear(landmarks, &L)) / 2.0
}

fn mar_value(landmarks: &[Point]) -> f64 {
    let pt = |i: usize| (landmarks[i].x(), landmarks[i].y());
    let dist = |a: (f64, f64), b: (f64, f64)| ((a.0-b.0).powi(2) + (a.1-b.1).powi(2)).sqrt();
    let v1 = dist(pt(61), pt(67));
    let v2 = dist(pt(62), pt(66));
    let v3 = dist(pt(63), pt(65));
    let h = dist(pt(60), pt(64));
    if h < 1e-6 { return 0.0; }
    (v1 + v2 + v3) / (3.0 * h)
}
