# Virtual CTAP2 Authenticator — Phase 2: Next-Level Engineering Brief

Companion to `virtual-authenticator-brief.md`. Phase 1 = "it works." Phase 2 = "it is trustworthy, maintainable, and not a security liability." This document assumes Phase 1's build sequence is complete (Firefox enumerates the daemon, a full enroll + login against Authentik succeeds).

---

## 1. The Central Security Problem You Just Created
A software authenticator moves the private key off a hardware secure element and into a userspace process on a general-purpose OS. This is the entire risk surface. Everything below exists to compensate for that move.

- The `UV` (user-verified) bit is **self-asserted**. Your daemon claims a human was verified; nothing above it can check. If the daemon is compromised, the attacker inherits the ability to assert UV and sign at will.
- The private key, while in process memory, is exfiltratable by anything with `ptrace`, root, or a memory-read primitive.
- The biometric gate is only as strong as the weakest path to the signing function. If an attacker can call `getAssertion` while bypassing the gate, the biometric is theater.

**Design principle:** the signing key must be unusable without a live, fresh verification event, and verification must be *bound* to the signing operation — not a separate "unlock then sign whenever" flow.

---

## 2. Key Storage Hardening (resolve the Phase 1 fork, then harden)
- **TPM-bound keys (recommended for single-machine):** generate/seal the private key inside the TPM 2.0 (`tpm2-pytss`, `libtpms`, or kernel TPM resource manager). The key never exists in plaintext in process memory; signing is delegated to the TPM. Bind unsealing to PCR state if you want boot-integrity gating.
- **Encrypted keystore (portable path):** key wrapped with a KEK derived from the user-verification event (e.g., biometric-released secret via systemd / PAM, or a passphrase through Argon2id). Key only decrypted transiently per-operation, zeroized after.
- **Resident vs. non-resident credentials:** resident (discoverable) keys enable usernameless passkey UX but mean the key material/metadata lives on-device and must be encrypted at rest. Non-resident wraps the key into the credential ID handed to the RP — lighter, but no usernameless login.
- **Memory hygiene:** `mlock` key buffers to prevent swap; explicit zeroization; avoid language GC retaining copies (a concern in Go/Python — prefer a small C/Rust core for the crypto path, or use locked byte buffers).

---

## 3. Binding Verification to Signing (the part most prototypes get wrong)
- Treat each `getAssertion` as requiring a **fresh** UV event with a short validity window (seconds), not a cached session.
- The UV backend should release a per-operation secret (e.g., decrypt the key or authorize a TPM policy session) rather than flip a boolean. A boolean is trivially patched; a cryptographic dependency is not.
- For TPM: use a **policy session** where successful verification satisfies the policy that authorizes the signing key's use. Verification failure = TPM refuses to sign. This makes the gate structural, not advisory.

---

## 4. Biometric Backend Integrity
The pluggable UV gate from Phase 1 was a stub/PIN. Production needs real anti-spoofing and a sane policy engine.

- **Face:** liveness/anti-spoofing is mandatory or it's defeated by a photo. Consider `howdy` (existing Linux face-auth via PAM) as a backend rather than rolling your own — it already integrates with PAM and has had its spoofing weaknesses documented, so you inherit a known threat profile instead of an unknown one.
- **Fingerprint:** `fprintd` over D-Bus is the standard Linux path; integrate rather than touching the reader directly.
- **Voice:** weakest modality for anti-spoofing; treat as a second factor, not primary.
- **PAM as the unifying layer:** rather than integrating each modality yourself, make the UV gate a **PAM conversation**. Then face/fingerprint/PIN are PAM modules, the policy (which/how many) is PAM config, and you get a battle-tested stack. This is the single highest-leverage architecture decision in Phase 2.
- **Policy engine:** define UV policy explicitly — required modalities, fallback order, lockout after N failures, rate limiting. Lockout/throttling is a CTAP2 expectation (real keys lock after consecutive PIN failures); mirror it.

---

## 5. Attestation, Trust, and Authentik Policy
- Phase 1 used `none` attestation. For an enterprise posture, decide whether Authentik should *enforce* attestation. Self-built authenticators can't produce a vendor-rooted packed attestation, so either:
  - keep `none`/self and accept that Authentik can't cryptographically distinguish your authenticator from any other software one, OR
  - mint your own attestation CA, embed a cert in the daemon, and configure Authentik to trust that root — giving you fleet-level "only our authenticator" enforcement.
- The attestation CA path is what makes this "enterprise": you can now assert *this credential came from a daemon we built and control*, and revoke at the CA level.
- Configure Authentik's WebAuthn stage: `user_verification = required` (force the UV bit), set allowed attestation, and decide on resident-key requirement to match your credential design.

---

## 6. Productionization / Operational Layer
- **Daemon lifecycle:** systemd user service, socket activation, clean restart without orphaning the uhid device. Handle the device teardown on crash so Firefox doesn't see a zombie key.
- **Privilege separation:** split into a privileged broker (owns uhid, TPM access) and an unprivileged front-end. The crypto/key path runs with the minimum capabilities; drop the rest. seccomp filter on the signing process.
- **IPC security:** if multi-process, authenticate the IPC channel (peer-cred check on the unix socket) so a random local process can't request signatures.
- **Logging/audit:** structured audit log of every make/getAssertion — RP ID, timestamp, UV result, credential used. This is your forensic trail and an enterprise/compliance requirement. Never log key material or raw biometric data.
- **Multi-RP / credential management:** a CLI or small UI to list, name, and revoke enrolled credentials across RPs (Authentik and any others). Users need to see what exists and kill it.
- **Counter handling:** implement the signature counter correctly (monotonic per credential) — RPs use it for clone detection. A software authenticator that resets counters looks like a cloned/attacked key and may get rejected.

---

## 7. Threat Model (write this down explicitly before shipping)
State, in the repo, what this does and does NOT defend against:
- **Defends:** remote attacker without local code execution; phishing (WebAuthn origin binding handles this for free); credential theft from Authentik's DB (only public keys there).
- **Partially defends (depends on TPM):** local malware reading the key — mitigated only if TPM-bound; a file keystore is vulnerable to root.
- **Does NOT defend:** a fully compromised local OS / root attacker who can patch the daemon or drive the UV gate. No software authenticator can. State this plainly.
- **Biometric-specific:** spoofing of the chosen modality; document the liveness assumptions.

This honesty is itself an enterprise deliverable — security reviews ask exactly this.

---

## 8. Testing & Conformance
- **FIDO conformance tooling:** run against the FIDO Alliance conformance test vectors / `libfido2`'s `fido2-*` tools to validate CTAP2 message handling beyond "Firefox accepted it once."
- **Cross-browser:** validate against Chromium's WebAuthn too — it's stricter than Firefox on some CTAP2 responses and surfaces bugs Firefox tolerates.
- **Negative tests:** wrong RP ID rejected, UV-failure refuses to sign, counter regression detected, malformed CBOR handled without crashing.
- **CI:** automated enroll+assert against a disposable Authentik instance (containerized) on every commit.

---

## 9. Roadmap Beyond Authentik
- **Hybrid transport / caBLE:** let the daemon act as a passkey provider for *other* devices via the FIDO hybrid (QR/BLE) flow — turns this machine into an authenticator for your phone-initiated logins.
- **Sync / backup:** if portable, design encrypted credential sync (this is what makes it a true "passkey" in the consumer sense). Threat-model the sync channel separately.
- **Standard provider integration:** on Linux, track the emerging platform authenticator/credential-provider interfaces so the daemon can register as a first-class system passkey provider rather than only a virtual HID key.

---

## Priority Order for Phase 2
1. PAM-based UV gate (Section 4) — highest leverage, replaces bespoke biometric code with a trusted stack.
2. TPM-bound keys + verification-bound signing (Sections 2–3) — closes the core key-theft and UV-bypass risks.
3. Attestation CA (Section 5) — unlocks real enterprise enforcement in Authentik.
4. Privilege separation + audit logging (Section 6) — operational trust.
5. Conformance + negative testing (Section 8) — correctness you can't eyeball.
6. Explicit threat model doc (Section 7) — gates any security review.
