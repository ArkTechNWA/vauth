use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use super::attestation::build_attestation_object;
use super::authenticator_data::{build_make_cred_auth_data, encode_der_ecdsa};
use super::types::{Ctap2Error, MakeCredentialRequest};
use crate::audit::AuditLog;
use crate::store::{CredentialRecord, CredentialStore};
use crate::tpm::{self, TpmContext};
use crate::up::LockoutTracker;
use crate::attestation_ca::AttestationState;
use crate::up::UvCache;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_make_credential(
    req: MakeCredentialRequest,
    tpm: &TpmContext,
    store: &Arc<Mutex<CredentialStore>>,
    _nv_index: u32,
    pam_service: &str,
    lockout: &Arc<LockoutTracker>,
    uv_cache: &Arc<UvCache>,
    attestation: Option<&Arc<AttestationState>>,
    audit: &Arc<AuditLog>,
    cid: u32,
    outgoing_tx: &mpsc::Sender<[u8; 64]>,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<u8>, Ctap2Error> {
    // 1. Validate algorithm
    if !req.alg_ok {
        return Err(Ctap2Error::UnsupportedAlgorithm);
    }

    // 2. Compute rp_id_hash and check excludeList
    let rp_id_hash: [u8; 32] = Sha256::digest(req.rp_id.as_bytes()).into();
    {
        let guard = store.lock().unwrap();
        for exc_id in &req.exclude_list {
            if let Some(cred) = guard.get_by_id(exc_id)
                && cred.rp_id_hash == rp_id_hash.as_slice()
            {
                return Err(Ctap2Error::CredentialExcluded);
            }
        }
    }

    // 3. User verification — check cache first, then PAM
    let proof = if uv_cache.consume(cid, &req.rp_id) {
        audit.log_make_credential(
            &req.rp_id, req.user_name.as_deref(), true, None, None,
        );
        crate::up::UserPresenceProof::test_only()
    } else {
        let prompt = crate::up::make_credential_prompt(
            &req.rp_id,
            req.rp_name.as_deref(),
            req.user_display.as_deref(),
            req.user_name.as_deref(),
        );
        match crate::up::require_user_verification(
            &prompt, pam_service, lockout, outgoing_tx, cid, cancel,
        ).await {
            Ok(p) => {
                audit.log_make_credential(
                    &req.rp_id, req.user_name.as_deref(), true, None, None,
                );
                uv_cache.store(cid, &req.rp_id);
                p
            }
            Err(e) => {
                audit.log_make_credential(
                    &req.rp_id, req.user_name.as_deref(), false, None,
                    Some(&format!("{e}")),
                );
                return Err(e);
            }
        }
    };
    tracing::info!(cid = format!("{cid:#010x}"), "User verification confirmed");

    // 4. Generate credential ID
    let cred_id: [u8; 32] = rand::thread_rng().r#gen();

    // 5. TPM operations
    let tpm2 = tpm.clone();
    let rp_id_hash2 = rp_id_hash;
    let cred_id2 = cred_id;
    let cdh2 = req.client_data_hash.clone();

    let (priv_bytes, pub_bytes, x, y, auth_data, raw_sig) =
        tokio::task::spawn_blocking(move || {
            tpm2.with_ctx(|ctx, primary| {
                let (priv_bytes, pub_bytes) = tpm::keys::create_child_key(ctx, primary)?;
                let (x, y) = tpm::keys::ecc_public_coords(&pub_bytes)?;
                let auth_data = build_make_cred_auth_data(&rp_id_hash2, &cred_id2, &x, &y);
                let mut to_sign = auth_data.clone();
                to_sign.extend_from_slice(&cdh2);
                let handle = tpm::keys::load_key(ctx, primary, &priv_bytes, &pub_bytes)?;
                let raw_sig = tpm::keys::sign(ctx, handle, &to_sign, &proof)?;
                tpm::keys::flush(ctx, handle)?;
                Ok((priv_bytes, pub_bytes, x, y, auth_data, raw_sig))
            })
        })
        .await
        .map_err(|e| Ctap2Error::Tpm(tpm::TpmError::Other(e.to_string())))??;

    let der_sig = encode_der_ecdsa(&raw_sig);

    // 6. Store credential
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cred_id_hex: String = cred_id.iter().map(|b| format!("{b:02x}")).collect();

    let record = CredentialRecord {
        version: 1,
        credential_id: cred_id.to_vec(),
        rp_id: req.rp_id.clone(),
        rp_id_hash: rp_id_hash.to_vec(),
        rp_name: req.rp_name,
        user_id: req.user_id,
        user_name: req.user_name.clone(),
        user_display: req.user_display,
        public_key_x: x.to_vec(),
        public_key_y: y.to_vec(),
        key_private: priv_bytes,
        key_public: pub_bytes,
        created_at,
        discoverable: req.resident_key,
    };

    store.lock().unwrap().add(record)?;

    audit.log_make_credential(
        &req.rp_id, req.user_name.as_deref(), true,
        Some(&cred_id_hex), None,
    );
    tracing::info!(cred_id = cred_id_hex, "Credential stored");

    // 7. Build attestation object
    let (att_sig, x5c) = if let Some(att) = attestation {
        // Full packed attestation: sign with the attestation key, include cert chain
        let mut to_sign_att = auth_data.clone();
        to_sign_att.extend_from_slice(&req.client_data_hash);
        let att_sig_der = att.sign(&to_sign_att)
            .map_err(|e| Ctap2Error::Cbor(format!("attestation sign: {e}")))?;
        let certs = vec![att.device_cert_der.clone(), att.ca_cert_der.clone()];
        (att_sig_der, Some(certs))
    } else {
        // Self-attestation: use the credential key's signature (already computed)
        (der_sig.clone(), None)
    };
    let response_cbor = build_attestation_object(&auth_data, &att_sig, x5c.as_ref().map(|v| v.as_slice()))?;

    // 8. Return 0x00 + CBOR
    let mut response = vec![0x00u8];
    response.extend_from_slice(&response_cbor);
    Ok(response)
}
