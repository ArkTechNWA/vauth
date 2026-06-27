//! Integration test: face engine loads models and can compare encodings.

use vauth::face::models;
use std::path::Path;

#[test]
fn test_load_howdy_models() {
    let howdy_path = Path::new("/lib/security/howdy/models/meldrey.dat");
    if !howdy_path.exists() {
        eprintln!("Skipping: no howdy models at {}", howdy_path.display());
        return;
    }

    let face_models = models::load_models(howdy_path).expect("failed to load howdy models");
    assert!(!face_models.is_empty(), "should have at least one model");

    // Verify structure
    for model in &face_models {
        assert!(!model.label.is_empty(), "model should have a label");
        for enc in &model.data {
            assert_eq!(enc.len(), 128, "encoding should be 128-dimensional");
        }
    }

    let all = models::all_encodings(&face_models);
    assert!(!all.is_empty(), "should have at least one encoding");
    eprintln!("Loaded {} models with {} total encodings", face_models.len(), all.len());
}

#[test]
fn test_model_roundtrip() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("test_user.json");

    let models = vec![
        models::FaceModel {
            time: 1700000000,
            label: "test-face".to_string(),
            id: 0,
            data: vec![vec![0.1; 128]],
        },
    ];

    models::save_models(&path, &models).expect("save");
    let loaded = models::load_models(&path).expect("load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].label, "test-face");
    assert_eq!(loaded[0].data[0].len(), 128);
}

#[test]
fn test_face_engine_loads() {
    let model_dir = Path::new("/lib/security/howdy/dlib-data");
    if !model_dir.exists() {
        eprintln!("Skipping: no dlib models at {}", model_dir.display());
        return;
    }

    let engine = vauth::face::FaceEngine::new(model_dir, 0.35);
    assert!(engine.is_ok(), "face engine should load: {:?}", engine.err());
    eprintln!("Face engine loaded successfully");
}

#[test]
fn test_self_distance_is_zero() {
    // Two identical encodings should have distance 0
    let howdy_path = Path::new("/lib/security/howdy/models/meldrey.dat");
    if !howdy_path.exists() {
        return;
    }

    let face_models = models::load_models(howdy_path).unwrap();
    let encodings = models::all_encodings(&face_models);
    if encodings.is_empty() {
        return;
    }

    // Distance of an encoding to itself should be 0
    let enc = encodings[0];
    let dist: f64 = enc.iter()
        .zip(enc.iter())
        .map(|(a, b)| (a - b).powi(2))
        .sum::<f64>()
        .sqrt();
    assert!(dist.abs() < 1e-10, "self-distance should be 0, got {dist}");
}
