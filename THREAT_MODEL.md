# vauth Threat Model

## What This Is

vauth is a virtual CTAP2 authenticator — a software-based FIDO2 security key that uses a TPM 2.0 for key storage and PAM for user verification. It creates a virtual HID device via Linux uhid that browsers (Firefox, Chromium) recognize as a hardware authenticator.

## What vauth Defends Against

### Remote attackers without local code execution
WebAuthn's origin binding prevents phishing by design. Credentials are bound to the RP ID (domain). A credential created for `example.com` cannot be used on `evil.com`. vauth inherits this from the CTAP2 protocol.

### Credential theft from the relying party's database
RPs only store public keys. The private keys never leave the TPM. A database breach at the RP yields nothing usable.

### Unauthorized signing without user presence
Every `makeCredential` and `getAssertion` requires fresh user verification via PAM — face recognition (howdy) or password. The UV cache is (CID, RP ID)-bound, use-once, and expires after 10 seconds. There is no persistent "unlocked" state.

### Lockout after repeated failures
After 5 consecutive UV failures (configurable), the authenticator locks out for 5 minutes. This mitigates brute-force attempts against the biometric or password gate.

## What vauth Partially Defends Against

### Local malware reading key material (TPM-dependent)
Private keys are generated inside and never exported from the TPM 2.0. The key material does not exist in process memory. An attacker with local code execution cannot extract the private key from the TPM.

However, the credential metadata (RP ID, user info, public key coordinates) is stored on disk encrypted with a TPM-sealed AES key. An attacker with root access could unseal this key via the TPM and read the metadata — but not the signing keys.

### Attestation forgery
With the attestation CA configured, RPs can verify that credentials were created by a vauth instance controlled by the CA operator. An attacker would need the attestation private key (stored on disk with mode 0600) to forge attestation statements. The CA key can be moved offline after initial setup.

## What vauth Does NOT Defend Against

### A fully compromised local OS / root attacker
An attacker with persistent root access can:
- Patch the vauth binary to bypass the UV gate
- Drive the PAM conversation programmatically
- Attach a debugger to the running process
- Replace the PAM service file to accept all authentication

No software authenticator can defend against this. This is the fundamental trade-off of moving keys off a hardware secure element. **State this plainly to anyone evaluating vauth for deployment.**

### UV bypass via PAM manipulation
The UV gate is a PAM conversation. The PAM service file (`/etc/pam.d/vauth`) controls which modules run. An attacker who can modify this file can weaken or remove the verification requirement. The file should be owned by root with restrictive permissions.

### Biometric spoofing
The face recognition backend (howdy) uses a standard RGB webcam with the `face_recognition` library (dlib). It does **not** perform liveness detection. A sufficiently high-quality photograph or video of the enrolled user may bypass face verification. This is a known limitation of howdy and is documented in its own threat model.

For higher assurance, use an IR depth camera or treat face recognition as one factor alongside a password.

### TPM reset attacks
If an attacker gains physical access to the machine, they may be able to reset the TPM, clearing the NV counter and sealed keys. This would destroy existing credentials (denial of service) but not enable forgery.

### Side-channel attacks on the TPM
Software-based TPM interactions may be vulnerable to timing or power analysis attacks in specialized threat environments. This is outside vauth's scope.

## Privilege Model

vauth starts as root to initialize the TPM context and uhid device, then drops to the real user (via `SUDO_USER`) before processing any CTAP2 messages. After the drop:

- **UID/GID**: real user (not root)
- **Capabilities**: only `CAP_DAC_READ_SEARCH` (for PAM shadow access)
- **Supplementary groups**: preserved (including `input` for uhid)
- **Root re-escalation**: explicitly verified impossible after drop

The CTAP2 message parser, which processes untrusted input from the browser, runs entirely as an unprivileged user. A vulnerability in CBOR parsing cannot directly escalate to root or TPM abuse.

## Audit Trail

Every `makeCredential` and `getAssertion` operation is logged to a single JSONL file with:
- Timestamp, event type, RP ID, username
- UV result (pass/fail), credential ID, signature counter
- Error description on failure

Key material and biometric data are never logged.

## Signature Counter

vauth maintains a monotonic signature counter in the TPM NV RAM, incremented on every `getAssertion`. RPs use this for clone detection — if the counter ever goes backwards, the credential may have been duplicated. Since the counter is in TPM NV storage, it survives process restarts and persists across reboots.
