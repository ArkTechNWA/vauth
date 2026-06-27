//! Face model storage — howdy-compatible JSON format.
//!
//! Each user has a JSON file containing an array of face models.
//! Each model holds one or more 128-dimensional dlib face encodings.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single enrolled face model (matches howdy's schema exactly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceModel {
    pub time: i64,
    pub label: String,
    pub id: u32,
    /// Each entry is a 128-element face encoding from dlib's ResNet.
    pub data: Vec<Vec<f64>>,
}

/// Load all face models for a user from their model file.
pub fn load_models(path: &Path) -> anyhow::Result<Vec<FaceModel>> {
    let content = std::fs::read_to_string(path)?;
    let models: Vec<FaceModel> = serde_json::from_str(&content)?;
    Ok(models)
}

/// Save face models to disk.
pub fn save_models(path: &Path, models: &[FaceModel]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(models)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Get the next available model ID from an existing set.
pub fn next_id(models: &[FaceModel]) -> u32 {
    models.iter().map(|m| m.id).max().map(|m| m + 1).unwrap_or(0)
}

/// Resolve the face models directory for vauth.
pub fn models_dir() -> anyhow::Result<PathBuf> {
    let data = crate::data_dir()?;
    Ok(data.join("face-models"))
}

/// Resolve the model file path for a given username.
pub fn model_path(username: &str) -> anyhow::Result<PathBuf> {
    Ok(models_dir()?.join(format!("{username}.json")))
}

/// Import howdy models for a user into vauth's model directory.
pub fn import_howdy(username: &str) -> anyhow::Result<usize> {
    let howdy_path = PathBuf::from(format!("/lib/security/howdy/models/{username}.dat"));
    if !howdy_path.exists() {
        anyhow::bail!("No howdy models found for user '{username}' at {}", howdy_path.display());
    }

    let models = load_models(&howdy_path)?;
    let count = models.len();

    let dest = model_path(username)?;
    if dest.exists() {
        // Merge: load existing, append new with re-numbered IDs
        let mut existing = load_models(&dest)?;
        let base_id = next_id(&existing);
        for (i, mut model) in models.into_iter().enumerate() {
            model.id = base_id + i as u32;
            model.label = format!("howdy-import: {}", model.label);
            existing.push(model);
        }
        save_models(&dest, &existing)?;
    } else {
        save_models(&dest, &models)?;
    }

    Ok(count)
}

/// Collect all 128-d encodings from a set of models into a flat list.
pub fn all_encodings(models: &[FaceModel]) -> Vec<&[f64]> {
    models
        .iter()
        .flat_map(|m| m.data.iter())
        .filter(|enc| enc.len() == 128)
        .map(|enc| enc.as_slice())
        .collect()
}
