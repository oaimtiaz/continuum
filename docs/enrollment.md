# Enrolling a New Device

## Overview

Before you can run tasks on a Continuum daemon, your device must be enrolled. This is a one-time setup that establishes trust between your device and the daemon.

## Local Enrollment (Same Machine)

If you're running the CLI on the same machine as the daemon, use local enrollment (no token required):

```bash
continuum enroll --local
```

This works by reading a shared secret from the filesystem that only local processes can access.

### How It Works

1. The daemon writes trust files to `$XDG_RUNTIME_DIR/continuum/`:
    - `server-fingerprint` — the daemon's identity
    - `local-trust-token` — a 32-byte secret
2. The CLI reads these files and sends a proof (SHA256 of the token) to the daemon
3. The daemon verifies the proof and approves enrollment

### Requirements

Local enrollment requires `$XDG_RUNTIME_DIR` to be set:

-   **Linux**: Usually set automatically by systemd to `/run/user/$UID`
-   **macOS**: Not set by default—see [Troubleshooting](#troubleshooting)

---

## Token-Based Enrollment (Remote)

For remote enrollment or when local enrollment isn't available:

### 1. Get an Enrollment Token

Ask your administrator for an enrollment token. They will:

-   Generate a token on the machine running the daemon
-   Share it with you (via Slack, email, in person, etc.)

Tokens look like: `AQAA-xxxx-xxxx-xxxx-...`

**Note:** Tokens expire after 5 minutes, so use them promptly.

### 2. Enroll Your Device

Run the enroll command with the token you received:

```bash
continuum enroll -t AQAA-xxxx-xxxx-xxxx-...
```

You can add a label to identify your device:

```bash
continuum enroll -t AQAA-xxxx-xxxx-xxxx-... --label "my-laptop"
```

Enrollment is automatic once you provide a valid token.

---

## Verify Enrollment

Check that your device is enrolled:

```bash
continuum status
```

You should see: `Client is authorized`

## Troubleshooting

### Local Enrollment Issues

**"No secure runtime directory available. Set $XDG_RUNTIME_DIR."**

The daemon and CLI need a secure directory for local trust files. On macOS, set it up:

```bash
# Add to your shell profile (~/.zshrc or ~/.bashrc)
export XDG_RUNTIME_DIR="${TMPDIR:-/tmp}/runtime-$(id -u)"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
```

Then restart your terminal and the daemon.

**"Server fingerprint not found. Is the daemon running locally?"**

The daemon hasn't written its fingerprint file yet. Ensure:

1. The daemon is running
2. `$XDG_RUNTIME_DIR` is set for both daemon and CLI
3. Check that `$XDG_RUNTIME_DIR/continuum/server-fingerprint` exists

**"Local trust proof not available."**

The CLI can't read the trust token. Check:

1. The daemon is running on the same machine
2. Both processes use the same `$XDG_RUNTIME_DIR`
3. File permissions allow your user to read `$XDG_RUNTIME_DIR/continuum/local-trust-token`

### Token-Based Enrollment Issues

**"Token expired"** — Tokens are only valid for 5 minutes. Ask your administrator for a new token.

**"Enrollment rejected"** — The token may have already been used (tokens are single-use). Request a new token.

**"Invalid enrollment token format"** — Check that you copied the entire token, including the `AQAA-` prefix.

### General Issues

**"Not enrolled"** — Run `continuum enroll --local` or `continuum enroll -t <token>` first.

**"Connection refused"** — Make sure the daemon is running. For remote connections, check the address with `--daemon <address>`.

## For Administrators

### Generating Tokens

To enroll a new device, generate a token on the daemon host:

```bash
continuum-daemon token generate --label "alice-laptop"
```

The token will be displayed locally. Share it with the user through a secure out-of-band channel (not over the network the CLI will connect through).

Options:

-   `--label <name>` - Label to identify who/what is enrolling
-   `--validity <duration>` - How long the token is valid (default: 5m, max: 1h)

### Managing Enrolled Clients

List all enrolled clients:

```bash
continuum clients list
```

Revoke a client's access:

```bash
continuum clients revoke SHA256:xxxx...
```

### Security Notes

-   **Token = Authorization**: A valid enrollment token is sufficient for authorization. No additional approval is needed.
-   Tokens are cryptographically signed and single-use
-   Tokens contain the server's identity, preventing man-in-the-middle attacks
-   Same-machine detection is logged for auditing but does not affect authorization
-   Remote enrollment requires out-of-band token sharing for security
