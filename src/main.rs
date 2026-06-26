use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "vauth", about = "Virtual CTAP2 authenticator with TPM-bound keys")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    // Global flags (also used by `run`)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(long, default_value = "/dev/tpmrm0", global = true)]
    tpm_device: String,
    #[arg(long, default_value = "0x01800100", global = true)]
    nv_index: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the authenticator daemon (default if no subcommand given)
    Run {
        #[arg(long, default_value = "vauth")]
        pam_service: String,
        #[arg(long, default_value = "/var/log/vauth/audit.jsonl")]
        audit_log: String,
        #[arg(long, default_value = "5")]
        max_uv_failures: u32,
        #[arg(long, default_value = "300")]
        lockout_secs: u64,
    },
    /// List all stored credentials
    List,
    /// Show details of a specific credential
    Info {
        /// Credential ID (hex, prefix match ok)
        id: String,
    },
    /// Revoke (delete) a credential
    Revoke {
        /// Credential ID (hex, prefix match ok)
        id: String,
    },
    /// Delete all credentials and reset the TPM NV counter
    Wipe,
    /// Set up attestation CA and device certificate
    SetupAttestation,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let command = cli.command.unwrap_or(Command::Run {
        pam_service: "vauth".to_string(),
        audit_log: "/var/log/vauth/audit.jsonl".to_string(),
        max_uv_failures: 5,
        lockout_secs: 300,
    });

    match command {
        Command::Run {
            pam_service,
            audit_log,
            max_uv_failures,
            lockout_secs,
        } => {
            let cfg = vauth::config::Config {
                verbose: cli.verbose,
                tpm_device: cli.tpm_device,
                nv_index: cli.nv_index,
                pam_service,
                audit_log,
                max_uv_failures,
                lockout_secs,
                wipe: false,
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(vauth::run(cfg))
        }
        Command::Wipe => {
            let cfg = vauth::config::Config {
                verbose: cli.verbose,
                tpm_device: cli.tpm_device,
                nv_index: cli.nv_index,
                pam_service: String::new(),
                audit_log: String::new(),
                max_uv_failures: 5,
                lockout_secs: 300,
                wipe: true,
            };
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(vauth::wipe(cfg))
        }
        Command::SetupAttestation => cmd_setup_attestation(&cli.tpm_device),
        Command::List => cmd_list(&cli.tpm_device),
        Command::Info { id } => cmd_info(&cli.tpm_device, &id),
        Command::Revoke { id } => cmd_revoke(&cli.tpm_device, &id),
    }
}

fn open_store(tpm_device: &str) -> anyhow::Result<(vauth::store::CredentialStore, std::path::PathBuf)> {
    let tpm = vauth::tpm::TpmContext::new(tpm_device)
        .map_err(|e| anyhow::anyhow!("TPM: {e}"))?;

    let data_dir = vauth::data_dir()?;

    let seal_blob_path = data_dir.join("seal_key.blob");
    if !seal_blob_path.exists() {
        anyhow::bail!("No seal key found. Run the daemon first to initialize.");
    }

    let blob = std::fs::read(&seal_blob_path)?;
    if blob.len() < 4 {
        anyhow::bail!("seal_key.blob is truncated");
    }
    let private_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
    if blob.len() < 4 + private_len {
        anyhow::bail!("seal_key.blob private section truncated");
    }
    let private_bytes = blob[4..4 + private_len].to_vec();
    let public_bytes = blob[4 + private_len..].to_vec();

    let aes_key = tpm.with_ctx(|ctx, primary| {
        vauth::tpm::seal::unseal(ctx, primary, &private_bytes, &public_bytes)
    })?;

    let creds_dir = data_dir.join("credentials");
    let store = vauth::store::CredentialStore::load(aes_key, creds_dir)?;
    Ok((store, data_dir))
}

fn hex_id(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_timestamp(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn cmd_list(tpm_device: &str) -> anyhow::Result<()> {
    let (store, _) = open_store(tpm_device)?;
    let creds = store.all();

    if creds.is_empty() {
        println!("No credentials stored.");
        return Ok(());
    }

    println!("{:<12} {:<30} {:<20} {:<22} {:<5}",
        "ID", "Relying Party", "User", "Created", "Disc.");
    println!("{}", "-".repeat(91));

    for cred in &creds {
        let short_id = &hex_id(&cred.credential_id)[..12];
        let rp = cred.rp_name.as_deref()
            .unwrap_or(&cred.rp_id);
        let user = cred.user_display.as_deref()
            .or(cred.user_name.as_deref())
            .unwrap_or("(unknown)");
        let created = format_timestamp(cred.created_at);
        let disc = if cred.discoverable { "yes" } else { "no" };

        println!("{:<12} {:<30} {:<20} {:<22} {:<5}",
            short_id,
            &rp[..rp.len().min(29)],
            &user[..user.len().min(19)],
            created,
            disc);
    }

    println!("\n{} credential(s) total.", creds.len());
    Ok(())
}

fn find_by_prefix<'a>(
    store: &'a vauth::store::CredentialStore,
    prefix: &str,
) -> anyhow::Result<&'a vauth::store::credential::CredentialRecord> {
    let prefix_lower = prefix.to_lowercase();
    let matches: Vec<_> = store.all().into_iter()
        .filter(|c| hex_id(&c.credential_id).starts_with(&prefix_lower))
        .collect();

    match matches.len() {
        0 => anyhow::bail!("No credential matching '{prefix}'"),
        1 => Ok(matches[0]),
        n => {
            eprintln!("{n} credentials match '{prefix}':");
            for c in &matches {
                eprintln!("  {}", hex_id(&c.credential_id));
            }
            anyhow::bail!("Ambiguous prefix, be more specific");
        }
    }
}

fn cmd_info(tpm_device: &str, id: &str) -> anyhow::Result<()> {
    let (store, _) = open_store(tpm_device)?;
    let cred = find_by_prefix(&store, id)?;

    println!("Credential ID:  {}", hex_id(&cred.credential_id));
    println!("RP ID:          {}", cred.rp_id);
    if let Some(name) = &cred.rp_name {
        println!("RP Name:        {name}");
    }
    if let Some(name) = &cred.user_name {
        println!("User Name:      {name}");
    }
    if let Some(display) = &cred.user_display {
        println!("User Display:   {display}");
    }
    println!("User ID:        {}", hex_id(&cred.user_id));
    println!("Created:        {}", format_timestamp(cred.created_at));
    println!("Discoverable:   {}", if cred.discoverable { "yes" } else { "no" });
    println!("Public Key X:   {}", hex_id(&cred.public_key_x));
    println!("Public Key Y:   {}", hex_id(&cred.public_key_y));

    Ok(())
}

fn cmd_revoke(tpm_device: &str, id: &str) -> anyhow::Result<()> {
    let (mut store, _) = open_store(tpm_device)?;
    let cred = find_by_prefix(&store, id)?;
    let full_id = cred.credential_id.clone();
    let rp_id = cred.rp_id.clone();
    let user = cred.user_name.clone().or(cred.user_display.clone())
        .unwrap_or_else(|| "(unknown)".to_string());
    let hex = hex_id(&full_id);

    println!("Revoking credential:");
    println!("  ID:   {hex}");
    println!("  RP:   {rp_id}");
    println!("  User: {user}");

    store.remove(&full_id)?;
    println!("\nCredential revoked.");
    Ok(())
}

fn cmd_setup_attestation(tpm_device: &str) -> anyhow::Result<()> {
    let data_dir = vauth::data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    if vauth::attestation_ca::is_initialized(&data_dir) {
        println!("Attestation already initialized.");
        println!("To regenerate, delete the files in {}:", data_dir.display());
        println!("  attestation_ca.pem, attestation_ca.key.pem");
        println!("  attestation_device.pem, attestation_device.key.pem");
        return Ok(());
    }

    println!("Setting up attestation CA and device certificate...");
    vauth::attestation_ca::setup(&data_dir, &vauth::config::AAGUID)?;
    println!("\nAttestation ready. The CA cert can be imported into Authentik");
    println!("to enforce \"only vauth\" credentials.");
    println!("\nCopy the CA cert for Authentik:");
    println!("  {}/attestation_ca.pem", data_dir.display());
    Ok(())
}
