//! Privilege separation: drop from root to the real user after initialization,
//! retaining only the capabilities needed for runtime operation.

/// Drop privileges from root to the real user.
///
/// After calling this:
/// - UID/GID changed to the real user (SUDO_USER)
/// - All capabilities dropped except CAP_DAC_READ_SEARCH (for PAM/shadow)
/// - Existing file descriptors (uhid, TPM) remain valid
pub fn drop_privileges() -> anyhow::Result<()> {
    // Only drop if we're running as root
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        tracing::info!("Not running as root, skipping privilege drop");
        return Ok(());
    }

    let (target_uid, target_gid, username) = resolve_real_user()?;

    tracing::info!(
        user = %username,
        uid = target_uid,
        gid = target_gid,
        "Dropping privileges"
    );

    // 0. Preserve display-related env vars before dropping
    //    (needed for zenity password dialog and howdy camera access)
    let display = std::env::var("DISPLAY").ok();
    let wayland = std::env::var("WAYLAND_DISPLAY").ok();
    let xdg_runtime = format!("/run/user/{target_uid}");

    // 1. Set PR_SET_KEEPCAPS so capabilities survive the UID change
    let ret = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
    if ret != 0 {
        anyhow::bail!("prctl(PR_SET_KEEPCAPS) failed: {}", std::io::Error::last_os_error());
    }

    // 2. Set supplementary groups to the target user's groups, then set GID/UID
    set_user_groups(target_uid, target_gid)?;

    let ret = unsafe { libc::setgid(target_gid) };
    if ret != 0 {
        anyhow::bail!("setgid({target_gid}) failed: {}", std::io::Error::last_os_error());
    }

    let ret = unsafe { libc::setuid(target_uid) };
    if ret != 0 {
        anyhow::bail!("setuid({target_uid}) failed: {}", std::io::Error::last_os_error());
    }

    // 3. Verify we can't get root back
    if unsafe { libc::setuid(0) } == 0 {
        anyhow::bail!("SECURITY: setuid(0) succeeded after privilege drop!");
    }

    // 4. Set capabilities: keep only CAP_DAC_READ_SEARCH
    apply_capability_set()?;

    // 5. Clear PR_SET_KEEPCAPS
    unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };

    // Restore display env vars for the new user context
    // SAFETY: called before any threads are spawned (single-threaded init phase)
    unsafe {
        if let Some(d) = display {
            std::env::set_var("DISPLAY", d);
        }
        if let Some(w) = wayland {
            std::env::set_var("WAYLAND_DISPLAY", w);
        }
        std::env::set_var("XDG_RUNTIME_DIR", &xdg_runtime);
        std::env::set_var("HOME", format!("/home/{username}"));
    }

    tracing::info!(
        uid = unsafe { libc::getuid() },
        gid = unsafe { libc::getgid() },
        "Privileges dropped successfully"
    );

    Ok(())
}

fn resolve_real_user() -> anyhow::Result<(u32, u32, String)> {
    let username = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")
        .ok_or_else(|| anyhow::anyhow!(
            "Cannot determine real user. Run with sudo (SUDO_USER must be set)."
        ))?;

    let user_cstr = std::ffi::CString::new(username.as_str())
        .map_err(|_| anyhow::anyhow!("Invalid username"))?;

    let pw = unsafe { libc::getpwnam(user_cstr.as_ptr()) };
    if pw.is_null() {
        anyhow::bail!("User '{username}' not found in passwd database");
    }

    let uid = unsafe { (*pw).pw_uid };
    let gid = unsafe { (*pw).pw_gid };

    Ok((uid, gid, username))
}

fn set_user_groups(uid: u32, primary_gid: u32) -> anyhow::Result<()> {
    // Get the user's supplementary groups
    let username = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            anyhow::bail!("getpwuid({uid}) failed");
        }
        std::ffi::CStr::from_ptr((*pw).pw_name).to_owned()
    };

    let mut ngroups: libc::c_int = 32;
    let mut groups = vec![0 as libc::gid_t; ngroups as usize];

    let ret = unsafe {
        libc::getgrouplist(
            username.as_ptr(),
            primary_gid,
            groups.as_mut_ptr(),
            &mut ngroups,
        )
    };

    if ret < 0 {
        // Buffer too small, resize and retry
        groups.resize(ngroups as usize, 0);
        unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                primary_gid,
                groups.as_mut_ptr(),
                &mut ngroups,
            );
        }
    }
    groups.truncate(ngroups as usize);

    let ret = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
    if ret != 0 {
        tracing::warn!("setgroups failed: {}", std::io::Error::last_os_error());
    } else {
        tracing::debug!(count = groups.len(), "Supplementary groups set");
    }

    Ok(())
}

fn apply_capability_set() -> anyhow::Result<()> {
    use caps::{CapSet, Capability};

    // After setuid with KEEPCAPS:
    //   Permitted = all caps (preserved from root)
    //   Effective = empty (cleared by kernel)
    //
    // Order matters: raise what we need in effective FIRST (while it's
    // still in permitted), then drop everything else from permitted.

    // 1. Raise DAC_READ_SEARCH in effective (it's in permitted, so this works)
    caps::raise(None, CapSet::Effective, Capability::CAP_DAC_READ_SEARCH)
        .map_err(|e| anyhow::anyhow!("Failed to raise effective DAC_READ_SEARCH: {e}"))?;

    // 2. Drop every OTHER capability from permitted.
    //    Can't clear-then-raise (clearing drops permanently for non-root).
    let keep = Capability::CAP_DAC_READ_SEARCH;
    for cap in caps::all() {
        if cap != keep {
            let _ = caps::drop(None, CapSet::Permitted, cap);
        }
    }

    // 3. Clear inheritable set entirely
    caps::clear(None, CapSet::Inheritable)
        .map_err(|e| anyhow::anyhow!("Failed to clear inheritable caps: {e}"))?;

    tracing::debug!("Capabilities restricted to CAP_DAC_READ_SEARCH only");
    Ok(())
}
