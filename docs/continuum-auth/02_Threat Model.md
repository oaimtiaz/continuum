# Continuum Auth — Threat Model

> **Status:** Draft  
> **Scope:** Authentication, secure channels, and pairing/enrollment.  
> **Out of scope (v0.1):** Authorization/roles, multi-user tenancy, and protection against a fully compromised host (e.g. root).

This is a minimal threat model intended to keep the authentication and IPC design grounded,
while remaining quick to iterate on during v0.1 development.

---

## Assets

The system aims to protect the following assets:

- **Daemon control surface:** the ability to connect to and issue commands to the daemon.
- **Interactive session I/O:** PTY input/output may contain secrets.
- **Long-term identity keys:** client and daemon private keys.
- **Trust stores:** `known_hosts` (client-side) and `authorized_keys` (daemon-side).
- **Enrollment tokens:** short-lived secrets used during pairing.
- **Task execution parameters:** command, environment, working directory, and PTY settings.

---

## Adversaries

The system is designed to defend against:

- **Remote network attackers**
  - MITM, replay, spoofing, or traffic manipulation.
- **Unauthorized remote clients**
  - Attempt to connect without being enrolled.
- **Local unprivileged attackers (daemon host)**
  - Can run arbitrary processes.
  - May attempt to connect to Unix sockets or observe process metadata.
- **Lost or compromised client devices**
  - Attacker gains access to a valid client identity key.

---

## Trust Boundaries

Security decisions occur at the following boundaries:

1. **Client ↔ Daemon (network boundary)**
   - Hostile network assumptions.
   - Must authenticate both parties and resist MITM.

2. **Daemon ↔ Shim (local IPC boundary)**
   - Same host, but other local processes may be untrusted.
   - Must prevent socket spoofing and unauthorized shim impersonation.

3. **On-disk state**
   - Identity keys and trust stores must be protected from accidental exposure.

---

## Primary Risks

The primary risks considered in v0.1 are:

- **Unauthorized client access**
  - A client must not connect unless explicitly enrolled.
- **Enrollment token misuse**
  - Token theft, replay, or brute-force attempts.
- **Local IPC impersonation**
  - A local process attempts to impersonate a shim or connect to the daemon IPC socket.
- **Information leakage via process metadata**
  - Secrets exposed via argv, logs, or weak file permissions.
- **Trust store tampering**
  - Modification of `known_hosts` or `authorized_keys`.

---

## Mitigations

### Client ↔ Daemon
- **TLS 1.3 with mutual authentication (mTLS)**
  - Provides encryption, integrity, and mutual identity verification.
- **Explicit client allowlist (`authorized_keys`)**
  - Unknown clients are rejected before any gRPC requests are served.
- **Server identity pinning (`known_hosts`)**
  - Prevents silent daemon impersonation.

### Enrollment
- **Operator-initiated enrollment mode**
  - Enrollment is only possible while explicitly enabled.
- **Signed enrollment tokens with embedded fingerprint**
  - Token contains server fingerprint, eliminating TOFU vulnerability.
  - Signature binds all fields (random, fingerprint, expiry) together.
  - Domain separation prefix prevents cross-protocol attacks.
- **Short-lived, single-use enrollment tokens**
  - Prevent replay and opportunistic enrollment.
- **No auto-registration**
  - Clients cannot enroll themselves without operator involvement.
- **Pinned fingerprint verification during enrollment**
  - Client verifies server identity during TLS handshake using embedded fingerprint.
  - No TOFU prompt that could be exploited by MITM.

### Daemon ↔ Shim IPC
- **Separate shim process**
  - Provides fault isolation from daemon crashes.
- **Unix domain socket with restricted permissions**
  - Socket placed in a private directory owned by the daemon.
- **OS peer credential verification**
  - Daemon verifies uid/gid/pid of connecting shim where supported.
- **Per-launch association**
  - Shim is spawned by the daemon and connects back immediately.
- **Structured IPC**
  - Command, environment, and execution parameters are sent over IPC,
    not via process argv.
- **Optional defense-in-depth**
  - Noise XX may be used to encrypt IPC traffic and bind identities.

---

## Security Invariants

The following invariants must always hold:

- Authentication occurs before any daemon-managed operation.
- There is no plaintext or unauthenticated fallback path.
- Clients cannot self-enroll.
- Identity mismatches are hard failures.
- Enrollment tokens are time-limited and single-use.
- Secrets (private keys, enrollment tokens, PTY data) are never logged.

---

## Security Hardening (v0.1.1)

The following security hardening measures were implemented:

### Critical (C1-C3)
- **C1: Server-side token signature verification**
  - Enrollment tokens are now cryptographically verified server-side.
  - Prevents forged token attacks where an attacker guesses token hashes.
- **C2: Certificate-public key binding verification**
  - Server verifies the client certificate contains the claimed public key.
  - Uses constant-time comparison to prevent timing attacks.
- **C3: Admin API authentication**
  - `list_authorized_clients` and `revoke_client` now require mTLS authentication.

### High (H1-H6)
- **H1: TLS signature verification**
  - TLS handshake signatures are now properly verified using ring crypto.
  - Previously returned unconditional success after fingerprint check.
- **H3: Atomic token consumption**
  - Uses single atomic UPDATE with WHERE conditions instead of SELECT-then-UPDATE.
  - Prevents race conditions in concurrent token use.
- **H4: Key material zeroization**
  - Private key material uses `Zeroizing<Vec<u8>>` for secure memory erasure.
- **H5: Generic error messages**
  - Token validation errors return generic messages to prevent oracle attacks.
- **H6: Explicit OsRng usage**
  - Token entropy uses `OsRng` directly instead of `ThreadRng`.

---
## Residual Risks (Fine for v0.1)

- **Compromised client key**
  - An attacker can authenticate until the key is removed or rotated.
- **Local same-user attacker**
  - Mitigated but not fully prevented without stronger sandboxing.

---

## Test Implications

At minimum, v0.1 testing should verify:

- Unauthorized clients are rejected.
- Daemon identity mismatches are rejected.
- Enrollment tokens cannot be replayed.
- IPC connections fail when peer credentials are invalid.
- No secrets appear in argv or logs.
- No plaintext communication paths exist.
