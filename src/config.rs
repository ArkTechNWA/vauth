pub const AAGUID: [u8; 16] = [
    0xf1, 0xd0, 0x6b, 0x4e, 0x3a, 0x17, 0x4c, 0x80, 0xb1, 0xd2, 0x9e, 0x3f, 0x00, 0x00, 0x00, 0x01,
];
pub const MAX_CHANNELS: usize = 8;
pub const CHANNEL_TIMEOUT_SECS: u64 = 30;

#[derive(clap::Parser, Debug, Clone)]
pub struct Config {
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[arg(long, default_value = "/dev/tpmrm0")]
    pub tpm_device: String,
    #[arg(long, default_value = "0x01800100")]
    pub nv_index: String,
    /// PAM service name for user verification (maps to /etc/pam.d/<name>).
    #[arg(long, default_value = "vauth")]
    pub pam_service: String,
    /// Path to the JSON-lines audit log file.
    #[arg(long, default_value = "/var/log/vauth/audit.jsonl")]
    pub audit_log: String,
    /// Maximum consecutive UV failures before lockout.
    #[arg(long, default_value = "5")]
    pub max_uv_failures: u32,
    /// Lockout duration in seconds after max failures.
    #[arg(long, default_value = "300")]
    pub lockout_secs: u64,
    /// Delete all stored credentials and reset the TPM NV counter, then exit.
    #[arg(long)]
    pub wipe: bool,
}
