# Continuum Auth — Persistence

> **Status:** Draft  
> **Scope:** Persistence of authentication-related state only.

This document describes what authentication state is persisted by Continuum,
where it is stored, and the invariants around its protection.

---

## Goals

Persistence exists to provide:

- Stable cryptographic identity across restarts
- Stable trust decisions (what has been trusted before)
- Clear recovery and reset semantics
- Minimal, auditable on-disk state

---

## What Is Persisted

### Daemon identity
- Long-term private key
- Derived public key and fingerprint

Used to:
- authenticate the daemon to clients
- detect daemon identity changes

### Client identities (daemon-side)
- Client public keys or fingerprints
- Metadata (optional): comment, creation time

Used to:
- determine whether a client is allowed to authenticate

### Server trust (client-side)
- Mapping of daemon address → daemon identity
- Used for server pinning (`known_hosts` semantics)

### Enrollment history (limited)
- Successful enrollment events may be recorded for audit/logging
- Enrollment *tokens themselves are not persisted*

---

## What Is *Not* Persisted 

- Enrollment tokens (in-memory only)
- Session state
- Authorization roles or permissions
- Per-task or per-session secrets
- Shim execution state

---

## Storage Backend

Continuum uses **SQLite** as its persistence backend.

Reasons:
- Single-user, single-daemon model
- ACID semantics
- Easy backup, inspection, and recovery
- No additional service dependency

---

## Database Contents (High Level)

The database logically contains:

- **identity**
  - daemon private key (encrypted-at-rest optional, future)
  - daemon public key / fingerprint

- **trusted_servers** (client-side)
  - daemon address
  - daemon fingerprint
  - first-seen / pinned timestamp

- **authorized_clients** (daemon-side)
  - client fingerprint or public key
  - added timestamp
  - optional comment

---

## Permissions and Hardening

- Configuration directory must be owned by the daemon user.
- Directory permissions:
  - Unix: `0700`
  - Windows: current-user-only ACL
- SQLite database file:
  - Unix: `0600`
- The daemon warns if unsafe configuration is detected
	- Or should it refuse to start? Maybe require an override flag

---

## Enrollment State

- Enrollment mode state is **in-memory only**.
- Enrollment tokens:
  - generated with high entropy
  - single-use
  - time-limited
  - never written to disk
  - never logged

Restarting the daemon exits enrollment mode.

---

## Key Rotation and Recovery

- **Daemon key change**
  - Clients will see a daemon identity mismatch
  - Requires deliberate re-pinning or re-enrollment

- **Client key change**
  - New key must be re-enrolled
  - Old key must be removed from allowlist

- **Reset**
  - Deleting the database resets all trust decisions
  - Clients must re-pair
  - Daemon identity may be regenerated

---

## Non-goals (v0.1)

- Multiple profiles per daemon
- Encrypted-at-rest key storage
- Shared or networked databases
- Migration tooling beyond basic SQLite schema upgrades
