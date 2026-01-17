# Continuum Auth — Flows

> **Status:** Implemented (v0.1)
> **Scope:** Authentication only (no authorization/roles in v0.1)

This document summarizes the *end-to-end flows* for Continuum authentication and pairing, at a level intended to stay stable even as implementation details change.

---

## Components and connections

- **Client**: CLI or automation on a user device
- **Daemon**: long-running service on a host device
- **Shim**: local helper on the daemon host for process spawning and PTY management

Connections:

- **Client ↔ Daemon**: gRPC over TLS 1.3 with mutual authentication (mTLS)
- **Daemon ↔ Shim**: Unix domain socket with file permission restrictions (0600 socket, 0700 directory)

---

## Flow 0 — First run (daemon initialization)

**Goal:** Establish a stable daemon identity and start listening securely.

1. Daemon loads or generates its long-term identity.
2. Daemon starts the gRPC server with **TLS 1.3** and **client authentication required**.
3. Daemon exposes its identity fingerprint for out-of-band verification (e.g., logs / a `show-key` command).

**Outcome:** The daemon has a stable identity that clients can pin.

---

## Flow 1 — Pairing / client enrollment (operator-initiated)

**Goal:** Add a new client identity to the daemon allowlist.

### Security Note: InitiateEnrollment

The `InitiateEnrollment` RPC is intentionally unauthenticated. This is a design
decision to allow operators to generate enrollment tokens from any authorized
context (including scripts, CI/CD, admin panels).

**Mitigations:**
- Rate limiting prevents token flooding (configurable, default 2 req/sec burst 10)
- Tokens are short-lived (configurable, default 5 minutes)
- Token generation is logged for audit
- Tokens are single-use and cryptographically bound to the server

An attacker who can call `InitiateEnrollment` can generate valid tokens, but
cannot use them to enroll without access to a valid client private key and
the ability to complete the mTLS handshake.

---

1. Daemon placed into **enrollment mode** (first iteration: RPC?)
2. Daemon generates a **signed enrollment token** containing:
   - 32 bytes of random entropy (for single-use identification)
   - daemon's fingerprint (SHA-256 of public key)
   - expiration timestamp
   - Ed25519 signature over all fields with domain separation
3. Token is displayed (chunked base64 or QR code) — must not be returned over the network.
4. Client generates or loads its long-term identity.
5. User provides the enrollment token to the client (scan/paste).
6. Client extracts the daemon fingerprint from the token.
7. Client connects to the daemon using **pinned fingerprint verification** (not TOFU).
8. Client presents:
   - enrollment token
   - client public identity (or fingerprint)
9. Daemon validates the token (signature, expiration, single-use) and records the client identity in the allowlist (`authorized_keys`).
10. Client stores the daemon fingerprint in its local trust store.
11. Enrollment mode exits automatically after success or timeout.

**Outcome:** The client is now eligible to authenticate on future connections, and has a pinned server identity.

---

## Flow 2 — Normal connect (post-enrollment connections)

**Goal:** Establish an authenticated, encrypted gRPC session.

1. Client opens a connection to the daemon and performs **TLS 1.3 mTLS** handshake.
2. Client verifies daemon identity (shared during enrollment)
   - If pinned in `known_hosts`, it must match.
   - If mismatch, hard fail.
3. Daemon verifies client identity:
   - Extract client identity from the TLS session.
   - Check presence in `authorized_keys`.
   - If absent, reject (no RPC served).
4. If both sides accept, gRPC requests proceed over the authenticated channel.

**Outcome:** All client operations for v0.1 occur over this authenticated gRPC session.

---

## Flow 3 — Local IPC connect (daemon ↔ shim)

**Goal:** Ensure shim control and PTY operations are protected from local spoofing.

1. The daemon spawns the shim process and provides a Unix socket address to connect to.
2. The shim initiates a connection to the daemon over the Unix domain socket.
3. Socket permissions (0600) and directory permissions (0700) restrict access.
4. The daemon issues shim commands over the socket.

**Outcome:** Local process control relies on Unix file permissions for security.

---

### IPC execution parameters (daemon ↔ shim)

Sensitive execution parameters (command, environment, working directory, PTY settings) are sent over the daemon↔shim IPC channel rather than passed via shim process arguments.

Rationale: process argv may be observable to other local processes on some systems.

---

## Authentication Failure Cases

- **Daemon identity mismatch (client side):** connection rejected; user must resolve by re-pairing or deliberate pin update.
- **Client not allowlisted (daemon side):** connection rejected; operator must enroll/allowlist the client.
- **Enrollment token invalid/expired/used:** enrollment rejected; operator must restart enrollment mode to generate a new token.
- **IPC permission check fails (v0.1):** daemon refuses shim connection due to socket permission mismatch.

---

### Enrollment token properties

During enrollment mode the daemon generates a **signed enrollment token** with the following properties:

**Wire format (137 bytes total):**
- 1 byte: version (currently 1)
- 32 bytes: random entropy
- 32 bytes: server fingerprint (SHA-256 of public key)
- 8 bytes: expiration timestamp (Unix seconds, big-endian)
- 64 bytes: Ed25519 signature

**Security properties:**
- **Domain separation:** Signature uses `CONTINUUM-ENROLL-v1:` prefix to prevent cross-protocol attacks
- **Fingerprint binding:** Server identity is cryptographically bound to the token
- **Expiration:** Tokens expire after 1-60 minutes (configurable)
- **Single-use:** A token may only be used once; replay must fail
- **Never persisted:** Tokens are in-memory only and never logged

**Transport:** Base64-encoded, typically displayed as chunked string for readability.

**Pairing UX:** The embedded fingerprint eliminates the need for TOFU — the client verifies the server during the TLS handshake before any data is exchanged.

