use chrono::Utc;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event: &'static str,
    pub rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    pub uv_result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct AuditLog {
    file: Mutex<File>,
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    pub fn log(&self, event: AuditEvent) {
        let mut entry = event;
        if entry.timestamp.is_empty() {
            entry.timestamp = Utc::now().to_rfc3339();
        }
        match serde_json::to_string(&entry) {
            Ok(json) => {
                if let Ok(mut f) = self.file.lock() {
                    let _ = writeln!(f, "{json}");
                    let _ = f.flush();
                } else {
                    tracing::error!(path = %self.path.display(), "Audit log mutex poisoned");
                }
            }
            Err(e) => tracing::error!("Failed to serialize audit event: {e}"),
        }
    }

    pub fn log_make_credential(
        &self,
        rp_id: &str,
        user_name: Option<&str>,
        uv_ok: bool,
        credential_id: Option<&str>,
        error: Option<&str>,
    ) {
        self.log(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event: "makeCredential",
            rp_id: rp_id.to_string(),
            user_name: user_name.map(|s| s.to_string()),
            uv_result: if uv_ok { "pass" } else { "fail" },
            credential_id: credential_id.map(|s| s.to_string()),
            counter: None,
            error: error.map(|s| s.to_string()),
        });
    }

    pub fn log_get_assertion(
        &self,
        rp_id: &str,
        user_name: Option<&str>,
        uv_ok: bool,
        credential_id: Option<&str>,
        counter: Option<u64>,
        error: Option<&str>,
    ) {
        self.log(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event: "getAssertion",
            rp_id: rp_id.to_string(),
            user_name: user_name.map(|s| s.to_string()),
            uv_result: if uv_ok { "pass" } else { "fail" },
            credential_id: credential_id.map(|s| s.to_string()),
            counter,
            error: error.map(|s| s.to_string()),
        });
    }
}
