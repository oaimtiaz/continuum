# Enrolling a New Device

## Overview

Before you can run tasks on a Continuum daemon, your device must be enrolled. This is a one-time setup that establishes trust between your device and the daemon.

## Steps

### 1. Get an Enrollment Token

Ask your administrator for an enrollment token. They will:

- Generate a token on the machine running the daemon
- Share it with you (via Slack, email, in person, etc.)

Tokens look like: `AQAA-xxxx-xxxx-xxxx-...`

**Note:** Tokens expire after 5 minutes, so use them promptly.

### 2. Enroll Your Device

Run the enroll command with the token you received:

```bash
continuum enroll AQAA-xxxx-xxxx-xxxx-...
```

You can add a label to identify your device:

```bash
continuum enroll AQAA-xxxx-xxxx-xxxx-... --label "my-laptop"
```

Enrollment is automatic once you provide a valid token.

### 3. Verify Enrollment

Check that your device is enrolled:

```bash
continuum status
```

You should see: `Client is authorized`

## Troubleshooting

**"Token expired"** - Tokens are only valid for 5 minutes. Ask your administrator for a new token.

**"Enrollment rejected"** - The token may have already been used (tokens are single-use). Request a new token.

**"Not enrolled"** - Run `continuum enroll <token>` with a valid token first.

**"Connection refused"** - Make sure the daemon is running and you have the correct address. Check with `--daemon <address>` if needed.

## For Administrators

### Generating Tokens

To enroll a new device, generate a token on the daemon host:

```bash
continuum-daemon token generate --label "alice-laptop"
```

The token will be displayed locally. Share it with the user through a secure out-of-band channel (not over the network the CLI will connect through).

Options:

- `--label <name>` - Label to identify who/what is enrolling
- `--validity <duration>` - How long the token is valid (default: 5m, max: 1h)

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

- **Token = Authorization**: A valid enrollment token is sufficient for authorization. No additional approval is needed.
- Tokens are cryptographically signed and single-use
- Tokens contain the server's identity, preventing man-in-the-middle attacks
- Same-machine detection is logged for auditing but does not affect authorization
- Remote enrollment requires out-of-band token sharing for security
