use crate::config::Config;

pub fn check(cfg: &Config) -> anyhow::Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // Check 1: /dev/uhid writable
    match std::fs::OpenOptions::new().write(true).open("/dev/uhid") {
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "cannot open /dev/uhid: {e}\n  \
             → run as root or add a udev rule for uhid access"
        )),
    }

    // Check 2: TPM device readable
    match std::fs::OpenOptions::new().read(true).open(&cfg.tpm_device) {
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "cannot open {}: {e}\n  \
             → add yourself to the 'tss' group: sudo usermod -aG tss $USER",
            cfg.tpm_device
        )),
    }

    // Check 3: PAM service file exists
    let pam_path = format!("/etc/pam.d/{}", cfg.pam_service);
    if !std::path::Path::new(&pam_path).exists() {
        errors.push(format!(
            "PAM service file not found: {pam_path}\n  \
             → install it: sudo cp dist/pam.d/vauth /etc/pam.d/"
        ));
    }

    if errors.is_empty() {
        return Ok(());
    }

    for err in &errors {
        eprintln!("ERROR: {err}");
    }
    anyhow::bail!("{} preflight check(s) failed", errors.len());
}
