use std::path::{Path, PathBuf};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType,
    Issuer, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};

const CA_CERT_FILE: &str = "attestation_ca.pem";
const CA_KEY_FILE: &str = "attestation_ca.key.pem";
const DEVICE_CERT_FILE: &str = "attestation_device.pem";
const DEVICE_KEY_FILE: &str = "attestation_device.key.pem";

/// Check if attestation is initialized.
pub fn is_initialized(data_dir: &Path) -> bool {
    data_dir.join(CA_CERT_FILE).exists()
        && data_dir.join(DEVICE_CERT_FILE).exists()
        && data_dir.join(DEVICE_KEY_FILE).exists()
}

/// Generate the full attestation chain: CA root + device cert + device key.
pub fn setup(data_dir: &Path, aaguid: &[u8; 16]) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir)?;

    // 1. Generate CA
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "vauth Attestation Root CA");
        dn.push(DnType::OrganizationName, "vauth");
        dn
    };

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let ca_cert_path = data_dir.join(CA_CERT_FILE);
    let ca_key_path = data_dir.join(CA_KEY_FILE);
    std::fs::write(&ca_cert_path, ca_cert.pem())?;
    std::fs::write(&ca_key_path, ca_key.serialize_pem())?;
    set_mode_600(&ca_key_path);

    println!("  CA cert:    {}", ca_cert_path.display());
    println!("  CA key:     {}", ca_key_path.display());

    // 2. Generate device attestation key + cert signed by CA
    let device_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut dev_params = CertificateParams::default();
    dev_params.is_ca = IsCa::NoCa;
    dev_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    dev_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "vauth Attestation Key");
        dn.push(DnType::OrganizationName, "vauth");
        let aaguid_hex: String = aaguid.iter().map(|b| format!("{b:02x}")).collect();
        dn.push(DnType::OrganizationalUnitName, format!("AAGUID:{aaguid_hex}"));
        dn
    };

    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);
    let device_cert = dev_params.signed_by(&device_key, &ca_issuer)?;

    let dev_cert_path = data_dir.join(DEVICE_CERT_FILE);
    let dev_key_path = data_dir.join(DEVICE_KEY_FILE);
    std::fs::write(&dev_cert_path, device_cert.pem())?;
    std::fs::write(&dev_key_path, device_key.serialize_pem())?;
    set_mode_600(&dev_key_path);

    println!("  Device cert: {}", dev_cert_path.display());
    println!("  Device key:  {}", dev_key_path.display());

    Ok(())
}

/// Runtime attestation state: device cert (DER) + signing key.
pub struct AttestationState {
    pub device_cert_der: Vec<u8>,
    pub ca_cert_der: Vec<u8>,
    signing_key: p256::ecdsa::SigningKey,
}

impl AttestationState {
    /// Sign data with the attestation key. Returns DER-encoded ECDSA signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use p256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.signing_key.sign(data);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Load attestation materials for runtime use.
pub fn load(data_dir: &Path) -> anyhow::Result<Option<AttestationState>> {
    if !is_initialized(data_dir) {
        return Ok(None);
    }

    let dev_cert_pem = std::fs::read_to_string(data_dir.join(DEVICE_CERT_FILE))?;
    let ca_cert_pem = std::fs::read_to_string(data_dir.join(CA_CERT_FILE))?;
    let dev_key_pem = std::fs::read_to_string(data_dir.join(DEVICE_KEY_FILE))?;

    let device_cert_der = pem_to_der(&dev_cert_pem)?;
    let ca_cert_der = pem_to_der(&ca_cert_pem)?;

    // Parse PEM private key into p256 SigningKey
    use p256::pkcs8::DecodePrivateKey;
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(&dev_key_pem)
        .map_err(|e| anyhow::anyhow!("Failed to load attestation key: {e}"))?;

    Ok(Some(AttestationState {
        device_cert_der,
        ca_cert_der,
        signing_key,
    }))
}

fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let b64: String = pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| anyhow::anyhow!("PEM decode: {e}"))
}

#[allow(unused_variables)]
fn set_mode_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}
