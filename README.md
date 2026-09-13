# vauth

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ArkTechNWA/vauth/badge)](https://scorecard.dev/viewer/?uri=github.com/ArkTechNWA/vauth)


A virtual CTAP2 authenticator for Linux with TPM 2.0-bound keys, biometric user verification, and enterprise attestation.

vauth creates a virtual FIDO2 security key via Linux uhid. Browsers see it as a hardware authenticator — register and sign in with passkeys using your face or a password, backed by keys that never leave your TPM.

## Features

- **TPM 2.0-bound keys** — private keys generated inside and never exported from the TPM
- **Native face recognition** — dlib-based face detection and 128-d encoding, compatible with howdy models
- **Liveness detection** — EAR (eye blink) and MAR (mouth movement) via 68-point landmarks, prevents photo spoofing
- **Camera capture** — V4L2 via nokhwa at ~27 fps (release build)
- **Packed attestation** — self-signed CA with x5c certificate chain for enterprise enforcement
- **Privilege separation** — drops from root to real user after init, retains only `CAP_DAC_READ_SEARCH`
- **Audit logging** — single JSONL file, every operation logged with RP, user, result, counter
- **UV caching** — (CID, RP ID)-bound, use-once, 10s TTL — no double-prompts, no attack window
- **Lockout** — configurable failure threshold and cooldown
- **Credential management** — `list`, `info`, `revoke`, `wipe` subcommands
- **Monotonic counter** — TPM NV counter for clone detection

## Requirements

- Linux with kernel uhid support
- TPM 2.0 (`/dev/tpmrm0`)
- Rust 1.91+
- `libpam` (PAM development headers)
- `tpm2-tss` (TPM2 Software Stack)
- V4L2-compatible webcam

### dlib models

The face engine requires dlib model files. If you have [howdy](https://github.com/boltgolt/howdy) installed, the models are already at `/lib/security/howdy/dlib-data/`.

Required models:
- `shape_predictor_5_face_landmarks.dat` — face alignment for encoding
- `dlib_face_recognition_resnet_model_v1.dat` — 128-d face encoding
- `shape_predictor_68_face_landmarks.dat` — liveness detection (EAR/MAR)

To download the 68-point model (required for liveness):
```bash
wget http://dlib.net/files/shape_predictor_68_face_landmarks.dat.bz2
bunzip2 shape_predictor_68_face_landmarks.dat.bz2
sudo mv shape_predictor_68_face_landmarks.dat /lib/security/howdy/dlib-data/
```

### Optional

- [howdy](https://github.com/boltgolt/howdy) — provides dlib models and enrolled face data
- `zenity` — GUI password dialog fallback

## Building

```bash
cargo build --release
```

The binary is at `target/release/vauth`.

## Setup

### 1. Udev rule (uhid access)

```bash
sudo cp dist/udev/99-vauth.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger /dev/uhid
```

Ensure your user is in the `input` group:
```bash
sudo usermod -aG input $USER
```

### 2. PAM service

```bash
sudo cp dist/pam.d/vauth /etc/pam.d/
```

Edit `/etc/pam.d/vauth` to match your system. The default config tries howdy (face), then falls back to password:

```
auth    sufficient    pam_python.so /lib/security/howdy/pam.py
auth    required      pam_unix.so nullok
```

### 3. Attestation (optional)

Generate a self-signed attestation CA and device certificate:

```bash
sudo vauth setup-attestation
```

The CA cert can be imported into your identity provider (e.g., Authentik) to enforce "only vauth" credentials. The cert is at:
```
~/.local/share/fidorium/attestation_ca.pem
```

### 4. Systemd service (optional)

```bash
sudo cp dist/systemd/vauth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vauth
```

## Usage

### Run the daemon

```bash
sudo vauth run -vv --audit-log /var/log/vauth/audit.jsonl
```

The daemon starts as root (for TPM + uhid), then drops to your user. Open a browser, navigate to a WebAuthn-enabled site, and register a passkey.

### Test face verification

The `vauth_verify` binary tests the face recognition and liveness pipeline:

```bash
# Full liveness + identity verification
./target/release/vauth_verify

# Diagnostic mode — shows EAR/MAR per frame + identity
./target/release/vauth_verify --diag
```

### Manage credentials

```bash
sudo vauth list                    # List all stored credentials
sudo vauth info <id-prefix>        # Show credential details
sudo vauth revoke <id-prefix>      # Delete a credential
sudo vauth wipe                    # Delete everything + reset TPM counter
```

Credential IDs support prefix matching — `vauth info 8d94` matches `8d945861f3a4...`.

### CLI reference

```
vauth [OPTIONS] [COMMAND]

Commands:
  run                  Start the authenticator daemon (default)
  list                 List all stored credentials
  info <ID>            Show details of a specific credential
  revoke <ID>          Revoke (delete) a credential
  wipe                 Delete all credentials and reset TPM NV counter
  setup-attestation    Generate attestation CA and device certificate

Options:
  -v, --verbose        Increase log verbosity (use -vv for debug)
  --tpm-device <PATH>  TPM device [default: /dev/tpmrm0]
  --nv-index <HEX>     TPM NV counter index [default: 0x01800100]
```

### Run-specific options

```
vauth run [OPTIONS]

Options:
  --pam-service <NAME>       PAM service name [default: vauth]
  --audit-log <PATH>         Audit log path [default: /var/log/vauth/audit.jsonl]
  --max-uv-failures <N>      Failures before lockout [default: 5]
  --lockout-secs <N>         Lockout duration [default: 300]
```

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed analysis of what vauth does and does not defend against.

Key points:
- Private keys never leave the TPM
- Every signing operation requires fresh user verification
- Liveness detection prevents static image bypass (blink or mouth movement required)
- The daemon runs as an unprivileged user after initialization
- A compromised local OS can bypass all protections — no software authenticator can prevent this

## Architecture

```
Browser (WebAuthn JS API)
    │ HID reports via /dev/uhid
    ▼
vauth daemon (unprivileged after init)
    ├── CTAPHID framing + dispatch
    ├── CTAP2 protocol (makeCredential, getAssertion, getInfo)
    ├── Face verification pipeline
    │   ├── Camera capture (V4L2 via nokhwa, ~27 fps)
    │   ├── Liveness detection (68-point landmarks → EAR/MAR)
    │   └── Identity verification (5-point landmarks → 128-d encoding)
    ├── PAM fallback (password via zenity dialog)
    ├── UV cache (CID+RP bound, use-once, TTL)
    ├── Attestation signing (device cert + CA chain)
    ├── Audit logger (JSONL)
    └── TPM 2.0 (key generation, signing, NV counter, sealing)
```

## Credits

vauth is a fork of [fidorium](https://github.com/edg-l/fidorium) by Edgar Luque, which provided the foundational CTAP2/CTAPHID/TPM implementation. Licensed under MIT/Apache-2.0.

## License

MIT OR Apache-2.0

## TODO

- [ ] AUR PKGBUILD
- [ ] Install script
- [ ] GTK4 verification overlay UI (Milestone 3)
- [ ] Cross-browser testing (Chromium)
- [ ] FIDO Alliance conformance test vectors
- [ ] Hybrid transport / caBLE (QR code auth from other devices)
- [ ] Encrypted credential sync (portable passkey support)
- [ ] Platform authenticator integration (emerging Linux credential-provider APIs)
- [ ] seccomp filter (restrict syscalls post-init)
- [ ] TPM policy sessions (bind UV cryptographically to signing, not just type-level gate)
