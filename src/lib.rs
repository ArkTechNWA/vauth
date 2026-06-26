pub mod audit;
pub mod config;
pub mod ctaphid;
pub mod diagnostics;
pub mod error;
pub mod hid;

pub(crate) mod ctap2;
pub mod store;
pub mod tpm;
pub mod up;

pub use up::UserPresenceProof;

/// Resolve the data directory using the real user's HOME, even under sudo.
pub fn data_dir() -> anyhow::Result<std::path::PathBuf> {
    // If running under sudo, use the real user's home
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            // Look up the user's home directory
            let pw = unsafe {
                let user_cstr = std::ffi::CString::new(sudo_user.as_str()).unwrap();
                libc::getpwnam(user_cstr.as_ptr())
            };
            if !pw.is_null() {
                let home_dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) }
                    .to_string_lossy()
                    .into_owned();
                Some(std::path::PathBuf::from(home_dir))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let data_dir = if let Some(home) = home {
        home.join(".local/share/fidorium")
    } else {
        directories::ProjectDirs::from("", "", "fidorium")
            .ok_or_else(|| anyhow::anyhow!("cannot determine XDG data dir"))?
            .data_dir()
            .to_path_buf()
    };

    Ok(data_dir)
}

pub async fn wipe(cfg: config::Config) -> anyhow::Result<()> {
    let nv_index = u32::from_str_radix(cfg.nv_index.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("invalid --nv-index: {e}"))?;

    let data_dir = data_dir()?;
    let creds_dir = data_dir.join("credentials");
    let mut count = 0usize;
    if creds_dir.exists() {
        for entry in std::fs::read_dir(&creds_dir)? {
            std::fs::remove_file(entry?.path())?;
            count += 1;
        }
    }
    println!("Deleted {count} credential(s) from {}", creds_dir.display());

    let tpm = tpm::TpmContext::new(&cfg.tpm_device)
        .map_err(|e| anyhow::anyhow!("Failed to initialize TPM: {e}"))?;
    let tpm2 = tpm.clone();
    tokio::task::spawn_blocking(move || {
        tpm2.with_ctx(|ctx, _| tpm::counter::delete_counter(ctx, nv_index))
    })
    .await??;
    println!("NV counter {nv_index:#010x} deleted (will be recreated on next start)");

    Ok(())
}

pub async fn run(cfg: config::Config) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let level = match cfg.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .init();

    tracing::info!("Starting fidorium");

    // Preflight checks
    diagnostics::check(&cfg)?;

    // Initialize audit log
    let audit_path = std::path::Path::new(&cfg.audit_log);
    let audit = std::sync::Arc::new(
        audit::AuditLog::open(audit_path)
            .map_err(|e| anyhow::anyhow!("Failed to open audit log {}: {e}", cfg.audit_log))?,
    );
    tracing::info!(path = %cfg.audit_log, "Audit log ready");

    // Initialize lockout tracker
    let lockout = std::sync::Arc::new(
        up::LockoutTracker::new(cfg.max_uv_failures, cfg.lockout_secs),
    );

    // Initialize UV cache (use-once, 10s TTL, source-bound)
    let uv_cache = std::sync::Arc::new(up::UvCache::new(10));

    // Compute data dir early (needed for lock fallback)
    let data_dir = data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    // Single-instance lock
    let lock_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| data_dir.clone());
    let lock_path = lock_dir.join("fidorium.lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    let mut lock = fd_lock::RwLock::new(lock_file);
    let _guard = lock.try_write().map_err(|_| {
        anyhow::anyhow!(
            "fidorium is already running (lock: {})",
            lock_path.display()
        )
    })?;

    let nv_index = u32::from_str_radix(cfg.nv_index.trim_start_matches("0x"), 16)
        .map_err(|e| anyhow::anyhow!("invalid --nv-index: {e}"))?;

    let tpm = tpm::TpmContext::new(&cfg.tpm_device)
        .map_err(|e| anyhow::anyhow!("Failed to initialize TPM: {e}"))?;
    tracing::info!("TPM context initialized");

    {
        let tpm2 = tpm.clone();
        tokio::task::spawn_blocking(move || {
            tpm2.with_ctx(|ctx, _| tpm::counter::ensure_counter(ctx, nv_index))
        })
        .await??;
    }
    tracing::info!(index = format!("{nv_index:#010x}"), "NV counter ready");

    let seal_blob_path = data_dir.join("seal_key.blob");
    let aes_key = load_or_create_seal_key(&tpm, &seal_blob_path).await?;
    tracing::info!("Seal key ready");

    let creds_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&creds_dir)?;
    let store = std::sync::Arc::new(std::sync::Mutex::new(
        store::CredentialStore::load(aes_key, creds_dir)
            .map_err(|e| anyhow::anyhow!("Failed to load credential store: {e}"))?,
    ));
    tracing::info!(
        count = store.lock().unwrap().credential_count(),
        "Credential store loaded"
    );

    let transport = hid::start_hid_transport()?;
    ctaphid::run_ctaphid_loop(
        transport.incoming_rx,
        transport.outgoing_tx,
        tpm,
        store,
        nv_index,
        cfg.pam_service,
        lockout,
        uv_cache,
        audit,
    )
    .await;
    match transport.task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(anyhow::anyhow!("HID transport error: {e}")),
        Err(e) => return Err(anyhow::anyhow!("HID transport panicked: {e}")),
    }
    Ok(())
}

async fn load_or_create_seal_key(
    tpm: &tpm::TpmContext,
    path: &std::path::Path,
) -> anyhow::Result<[u8; 32]> {
    if path.exists() {
        let blob = std::fs::read(path)?;
        if blob.len() < 4 {
            anyhow::bail!("seal_key.blob is truncated");
        }
        let private_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        if blob.len() < 4 + private_len {
            anyhow::bail!("seal_key.blob private section truncated");
        }
        let private_bytes = blob[4..4 + private_len].to_vec();
        let public_bytes = blob[4 + private_len..].to_vec();

        let tpm2 = tpm.clone();
        let key = tokio::task::spawn_blocking(move || {
            tpm2.with_ctx(|ctx, primary| {
                tpm::seal::unseal(ctx, primary, &private_bytes, &public_bytes)
            })
        })
        .await??;
        Ok(key)
    } else {
        let tpm2 = tpm.clone();
        let (private_bytes, public_bytes, key) =
            tokio::task::spawn_blocking(move || tpm2.with_ctx(tpm::seal::create_seal)).await??;

        let private_len = private_bytes.len() as u32;
        let mut blob = Vec::with_capacity(4 + private_bytes.len() + public_bytes.len());
        blob.extend_from_slice(&private_len.to_be_bytes());
        blob.extend_from_slice(&private_bytes);
        blob.extend_from_slice(&public_bytes);
        std::fs::write(path, &blob)?;
        Ok(key)
    }
}
