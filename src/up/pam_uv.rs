use super::lockout::LockoutTracker;
use super::prompt::UpPrompt;
use crate::ctap2::types::Ctap2Error;
use crate::ctaphid::packet::encode_response;
use crate::ctaphid::types::CMD_KEEPALIVE;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

/// Proof that user verification succeeded. Cannot be constructed
/// without going through the PAM gate.
pub struct UserPresenceProof {
    pub(crate) _private: (),
}

fn encode_keepalive(cid: u32, status: u8) -> [u8; 64] {
    encode_response(cid, CMD_KEEPALIVE, &[status])[0]
}

pub(crate) async fn require_user_verification(
    prompt: &UpPrompt,
    pam_service: &str,
    lockout: &Arc<LockoutTracker>,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cid: u32,
    cancel: &Arc<AtomicBool>,
) -> Result<UserPresenceProof, Ctap2Error> {
    if let Some(remaining) = lockout.check_locked() {
        tracing::warn!(remaining_secs = remaining.as_secs(), "UV locked out");
        return Err(Ctap2Error::PinAuthBlocked);
    }

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let tx_keepalive = outgoing_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    tx_keepalive.send(encode_keepalive(cid, 0x02)).await.ok();
                }
                _ = &mut stop_rx => break,
            }
        }
    });

    let service = pam_service.to_string();
    let desc = prompt.description.clone();

    let join = tokio::task::spawn_blocking(move || {
        pam_authenticate(&service, &desc)
    });

    let result = tokio::time::timeout(std::time::Duration::from_secs(60), join).await;

    let _ = stop_tx.send(());

    if cancel.load(Ordering::Relaxed) {
        return Err(Ctap2Error::KeepaliveCancel);
    }

    match result {
        Err(_) => {
            lockout.record_failure();
            Err(Ctap2Error::UserActionTimeout)
        }
        Ok(Err(_join_err)) => {
            lockout.record_failure();
            Err(Ctap2Error::OperationDenied)
        }
        Ok(Ok(Ok(()))) => {
            lockout.record_success();
            Ok(UserPresenceProof { _private: () })
        }
        Ok(Ok(Err(e))) => {
            lockout.record_failure();
            tracing::warn!("PAM authentication failed: {e}");
            Err(Ctap2Error::OperationDenied)
        }
    }
}

/// Get the real (non-root) username, even when running under sudo.
fn real_username() -> String {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return user;
        }
    }
    if let Ok(user) = std::env::var("LOGNAME") {
        if !user.is_empty() {
            return user;
        }
    }
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            return user;
        }
    }
    unsafe {
        let uid = libc::getuid();
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            return std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    "root".to_string()
}

/// PAM conversation handler that uses zenity for password prompts.
/// Biometric modules (howdy, fprintd) don't use the conversation —
/// they talk to hardware directly. When pam_unix asks for a password,
/// we pop a zenity dialog.
struct ZenityConversation {
    description: String,
}

impl pam_client2::ConversationHandler for ZenityConversation {
    fn prompt_echo_on(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, pam_client2::ErrorCode> {
        // Echo-on prompts (username etc) — return empty, we already set the user
        let _ = msg;
        std::ffi::CString::new("").map_err(|_| pam_client2::ErrorCode::BUF_ERR)
    }

    fn prompt_echo_off(&mut self, msg: &std::ffi::CStr) -> Result<std::ffi::CString, pam_client2::ErrorCode> {
        // Password prompt — use zenity
        let prompt_text = msg.to_string_lossy();
        tracing::info!(prompt = %prompt_text, "PAM requesting password, launching zenity");

        let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());

        let output = std::process::Command::new("zenity")
            .arg("--password")
            .arg("--title=vauth: Passkey Verification")
            .arg(&format!("--text={}", self.description))
            .env("DISPLAY", &display)
            .env("WAYLAND_DISPLAY",
                std::env::var("WAYLAND_DISPLAY").unwrap_or_default())
            .env("XDG_RUNTIME_DIR",
                std::env::var("XDG_RUNTIME_DIR")
                    .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() })))
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let pw = String::from_utf8_lossy(&out.stdout)
                    .trim_end_matches('\n')
                    .to_string();
                std::ffi::CString::new(pw).map_err(|_| pam_client2::ErrorCode::BUF_ERR)
            }
            Ok(out) => {
                tracing::warn!(status = ?out.status, "zenity cancelled or failed");
                Err(pam_client2::ErrorCode::CONV_ERR)
            }
            Err(e) => {
                tracing::error!("Failed to launch zenity: {e}");
                Err(pam_client2::ErrorCode::CONV_ERR)
            }
        }
    }

    fn text_info(&mut self, msg: &std::ffi::CStr) {
        tracing::info!(msg = %msg.to_string_lossy(), "PAM info");
    }

    fn error_msg(&mut self, msg: &std::ffi::CStr) {
        tracing::warn!(msg = %msg.to_string_lossy(), "PAM error");
    }
}

fn pam_authenticate(service: &str, description: &str) -> Result<(), String> {
    let user = real_username();
    tracing::info!(user = %user, service = %service, "Starting PAM authentication");

    let conv = ZenityConversation {
        description: description.to_string(),
    };

    let mut ctx = pam_client2::Context::new(service, Some(&user), conv)
        .map_err(|e| format!("PAM context for user '{user}': {e}"))?;

    match ctx.authenticate(pam_client2::Flag::NONE) {
        Ok(()) => {
            tracing::info!(user = %user, "PAM authentication succeeded");
            Ok(())
        }
        Err(e) => Err(format!("PAM auth for user '{user}': {e}")),
    }
}

impl UserPresenceProof {
    #[doc(hidden)]
    pub fn test_only() -> Self {
        Self { _private: () }
    }
}
