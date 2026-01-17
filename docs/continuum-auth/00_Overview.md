# Continuum Authentication Overview

> **Status:** Implemented (v0.1)
> **Scope:** Authentication only

*Note*: Authorization is not in scope for this initial version. It will likely be implemented in a future version, but for now, the assumption is that all connections to a particular daemon have the same permissions across the entire daemon. 

---

## Purpose and Scope

`continuum-auth` defines how Continuum components establish **secure, authenticated connections** and verify **peer identity**.

This documentation describes:
- how identities are created and verified
- how trust is established and persisted
- how connections are authenticated on every use

---

## Goals

The authentication system is designed to provide:

- Mutual authentication between clients and the daemon
- Strong cryptographic identities based on public keys
- Encrypted transport on all communication paths
- Explicit trust decisions (no implicit trust)
- Resistance to man-in-the-middle attacks
- Fail-closed behavior with no plaintext fallback

---

## System Components and Boundaries

Continuum consists of the following components:

- **Client (CLI or automation)** — connects remotely to issue commands
- **Daemon** — long-running server managing tasks and sessions
- **Shim** — local helper responsible for spawning processes and managing PTYs

Authentication is enforced across two trust boundaries:

1. **Remote boundary:** Client ↔ Daemon (untrusted network)
2. **Local boundary:** Daemon ↔ Shim (same host, privilege boundary)

---

## Transport Strategy

Different transports are used based on the boundary being crossed.

### Client ↔ Daemon

- **Transport:** gRPC over TLS 1.3
- **Authentication:** Mutual TLS (mTLS)
- **Rationale:** Native integration with HTTP/2 and gRPC tooling

TLS provides:
- encryption and integrity
- server identity verification
- client identity verification

### Daemon ↔ Shim

- **Transport:** Unix domain sockets
- **Security:** File permission restrictions (socket 0600, directory 0700)
- **Rationale:** Lightweight, no certificate infrastructure, appropriate for local IPC

The daemon spawns shim processes and communicates via Unix sockets in a private directory. Security relies on Unix file permissions to prevent unauthorized local processes from connecting.

---

## Identity Model

Each principal (client, daemon, shim) has a long-term cryptographic identity
represented by a public/private keypair.

- The **public key** uniquely identifies the principal
- The **private key** never leaves the local machine
- A stable **fingerprint** (SHA-256 hash of the public key) is used for comparison and storage

Identities are:
- long-lived
- explicitly trusted

---

## Trust Model

### Server trust (client side)

Clients verify the daemon identity using the **enrollment token**. The token embeds the server's fingerprint, eliminating the need for Trust-On-First-Use (TOFU).

- During enrollment, the client extracts the server fingerprint from the enrollment token
- The client verifies the server's TLS certificate against this embedded fingerprint during the handshake
- After successful enrollment, the server identity is stored in a local trust store (`known_hosts`)
- Subsequent connections verify against the stored identity
- If a previously known identity changes, the connection is rejected

This approach is more secure than TOFU because the server identity is cryptographically bound to the enrollment token, preventing man-in-the-middle attacks during first connection.

### Client trust (daemon side)

The daemon maintains an explicit **client allowlist** (`authorized_keys`).

- Only clients whose identity is present in the allowlist may connect
- Unknown clients are rejected during authentication
- A client is added via enrollment (token-based or same-machine proof)

There is no automatic or implicit client registration.

---

## Authentication Flow

Authentication proceeds in clearly defined stages.

### Phase 0: Daemon initialization

1. The daemon generates or loads its long-term identity.
2. The daemon exposes its identity fingerprint for external verification.
3. The daemon starts the gRPC server with TLS and client authentication required.

---

### Phase 1: Client enrollment (explicit, operator-initiated)

Before a client can connect, it must be explicitly enrolled.

1. The daemon should be manually placed into **enrollment mode** using a local or
   otherwise privileged action.
2. The daemon generates a **signed enrollment token** containing:
   - random entropy (for single-use identification)
   - the daemon's fingerprint (SHA-256 of public key)
   - expiration timestamp
   - cryptographic signature binding all fields together
3. The token is displayed (e.g. as a chunked base64 string or QR code).
4. While enrollment mode is active:
   - the client generates or loads its long-term identity,
   - the user provides the enrollment token to the client,
   - the client extracts the server fingerprint from the token,
   - the client connects to the daemon using pinned fingerprint verification,
   - the client presents the token and its public identity.
5. The daemon validates the token signature and expiration, then records the
   client identity in the client allowlist.
6. The client stores the daemon fingerprint in its local trust store.
7. Enrollment mode exits automatically after success or timeout.

> Enrollment is a deliberate, operator-controlled process.
> Clients cannot self-enroll or trigger enrollment mode.
---

### Phase 2: Client → daemon connection (every connection)

On every connection attempt:

1. The client and daemon perform a TLS 1.3 handshake with mutual authentication.
2. The client verifies the daemon identity against its local trust store.
3. The daemon verifies the client identity:
   - extract client fingerprint from the TLS session
   - check presence in the client allowlist.
4. If verification fails on either side, the connection is rejected.
5. If verification succeeds, a secure, authenticated session is established.

All subsequent RPCs occur over this authenticated channel.

---

## Local IPC (Daemon ↔ Shim)

For internal communication on the same host:

1. The daemon spawns the shim process with a socket path argument.
2. The shim connects to the Unix domain socket.
3. Socket permissions (0600) and directory permissions (0700) restrict access.
4. The socket is used for task lifecycle events and PTY I/O.

This prevents unauthorized local processes from connecting to the daemon's IPC.

---

## Security Invariants

The following invariants must always hold:

- All connections are authenticated before any action occurs
- All communication is encrypted
- Trust decisions are explicit and persistent
- Identity mismatches are hard errors
- There is no plaintext or unauthenticated fallback path

---

## Cryptographic Identities

Continuum identifies principals (client and daemon) by long-term public keys.

- **Identity key type:** Ed25519
- **Fingerprint:** `SHA-256(public_key_bytes)` encoded as base64 with `SHA256:` prefix
- **Canonical public key encoding:** base64 of raw public key bytes

These values define how identities are displayed, compared, and persisted in trust stores.


---

