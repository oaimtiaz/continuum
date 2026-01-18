# Continuum

**Local-first runtime that keeps work alive across devices.**

Continuum lets long-running, interactive tasks continue on your home or office machine while you observe, intervene, and resume them from anywhere—without moving your work to the cloud.

## The Problem

Tasks die when you close your laptop, lose a terminal, or walk away. You have to babysit sessions, set up SSH tunnels, or re-run work from scratch.

## The Solution

Continuum makes long-running work survivable. Start work on one machine, check progress from your phone, approve prompts, and resume exactly where you left off, without needing to hover over your device.

## Key Features

-   **Durable tasks** — Work continues even when you disconnect
-   **Multi-device access** — Monitor and interact from laptop, phone, or tablet
-   **Interactive prompts** — Respond to password prompts and confirmations remotely
-   **PTY support** — Full terminal output with colors and control codes
-   **Audit trail** — Complete history of who did what and when
-   **Local-first** — Your data stays on your machines, not in the cloud

## Quick Start

### Build

```bash
# Build all crates (debug)
cargo build

# Build release binaries
cargo build --release
```

### Run the Daemon

The daemon runs on your host machine and manages task execution:

```bash
# Start the daemon (foreground, with logging)
RUST_LOG=info ./target/release/continuum-daemon

# Or run in background
./target/release/continuum-daemon &
```

The daemon listens on two ports:

-   **Port 50051**: Enrollment service (server-auth TLS only)
-   **Port 50052**: Main API (mTLS required)

### Enroll a Client

Before using the CLI, you need to enroll your device. See [Enrollment Guide](docs/enrollment.md) for details.

**Quick start (same machine):**

```bash
# Same-machine auto-enrollment (simplest)
./target/release/continuum enroll --local

# Or with a token (for remote enrollment)
./target/release/continuum-daemon token generate --label "my-laptop"
./target/release/continuum enroll -t AQAA-xxxx-xxxx-...
```

### Use the CLI

```bash
# Run a task
./target/release/continuum run -- echo "hello world"

# Run a long-running task
./target/release/continuum run -- ./my-script.sh

# List tasks
./target/release/continuum ls

# Show task details
./target/release/continuum show <task-id>

# Attach to task output (stream live)
./target/release/continuum attach <task-id>

# Attach interactively (forward your input to the task)
./target/release/continuum attach -i <task-id>

# Send input to a running task
./target/release/continuum send <task-id> "user input here"

# Cancel a task (SIGTERM)
./target/release/continuum cancel <task-id>

# Force kill a task (SIGKILL)
./target/release/continuum cancel --force <task-id>
```

### CLI Reference

```
continuum [OPTIONS] <COMMAND>

Commands:
  enroll   Enroll this client with the daemon
  status   Check enrollment status
  clients  Manage authorized clients
  run      Run a new task
  ls       List tasks
  show     Show task details
  attach   Attach to task output
  send     Send input to a task
  cancel   Cancel a running task

Global Options:
  --daemon <ADDR>   Daemon address [default: http://127.0.0.1:50052]
  --json            Output JSON instead of human-readable text
  -v, --verbose     Verbose output
```

#### `enroll` - Enroll with Daemon

```bash
continuum enroll <TOKEN> [--label <NAME>]
```

#### `status` - Check Enrollment Status

```bash
continuum status
```

#### `clients` - Manage Authorized Clients (Admin)

```bash
continuum clients list           # List enrolled clients
continuum clients revoke <FP>    # Revoke by fingerprint
```

#### `run` - Start a Task

```bash
continuum run [OPTIONS] -- <COMMAND>...

Options:
  -i, --interactive    Attach immediately after starting
  --name <NAME>        Task name (defaults to command name)
  --cwd <PATH>         Working directory
  --env <KEY=VALUE>    Environment variable (can be repeated)
```

#### `ls` - List Tasks

```bash
continuum ls [OPTIONS]

Options:
  --status <STATUS>    Filter by status (queued, running, completed, failed, canceled)
  --recent <N>         Show last N tasks [default: 20]
  --all                Show all tasks
```

#### `attach` - Stream Task Output

```bash
continuum attach [OPTIONS] <TASK_ID>

Options:
  -i, --interactive    Forward stdin to task
  --no-follow          Print history and exit (don't stream)
```

#### `send` - Send Input to Task

```bash
continuum send [OPTIONS] <TASK_ID> [DATA]

Options:
  --file <PATH>        Send contents of file
  --ctrl-c             Send interrupt signal
  --raw                Don't append newline to data
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Network                            │
│                                                                 │
│   ┌──────────┐     ┌───────────────────┐     ┌──────────────┐   │
│   │  Phone   │────▶│                   │◀────│   Laptop     │   │
│   │  (view)  │     │  continuum-daemon │     │   (admin)    │   │
│   └──────────┘     │                   │     └──────────────┘   │
│                    │  Running on your  │                        │
│                    │  home/office      │                        │
│                    │  machine          │                        │
│                    └────────┬──────────┘                        │
│                             │                                   │
│                      ┌──────▼──────┐                            │
│                      │    Tasks    │                            │
│                      │  (durable)  │                            │
│                      └─────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

This is a Rust workspace with eight crates:

```
continuum/
├── continuum-core/       # Pure domain types (IO-free)
├── continuum-auth/       # Pure authentication library (IO-free)
├── continuum-proto/      # gRPC protobuf definitions
├── continuum-shim-proto/ # Shim↔Daemon IPC protocol
├── continuum-pty/        # PTY spawn/read/write/signal
├── continuum-shim/       # Per-task process manager
├── continuum-daemon/     # gRPC server, task supervisor
└── continuum-cli/        # Command-line interface
```

### `continuum-core`

Pure domain types and business logic. Intentionally IO-free:

-   No filesystem, network, or database operations
-   All types are plain Rust structs/enums with serde serialization
-   Stable API with semantic versioning

**Key types:**

-   `Task` — A durable command with lifecycle state machine
-   `TaskStatus` — Queued → Running → Completed/Failed/Canceled
-   `AttentionState` — Overlay indicating if a task needs user input
-   `Device`, `DeviceRole` — Multi-device identity and authorization
-   `AuditEvent` — Security and compliance logging

### `continuum-auth`

Pure authentication library. Also IO-free, all persistence is injected via traits:

-   Ed25519 keypairs with secure memory handling
-   Signed enrollment tokens (no TOFU)
-   mTLS certificate verification
-   Server trust and client allowlist abstractions

### `continuum-daemon`

The service that runs on your host machine:

-   Dual-port gRPC server (enrollment on 50051, main API on 50052)
-   mTLS authentication for all API calls
-   Executes tasks via shim processes with PTY sessions
-   Streams output to connected clients
-   Detects when tasks need input (attention state)
-   SQLite persistence for tasks and auth state

### `continuum-cli`

Command-line interface for interacting with the daemon:

-   Device enrollment (local or token-based)
-   Start, stop, and monitor tasks
-   Send input to running tasks (including interactive `~.` detach)
-   Stream live output
-   Client management (list, revoke)

## Task Lifecycle

```
     ┌─────────────────────────────────────────────────────────────────┐
     │                                                                 │
     │  ┌─────────┐    ┌─────────┐    ┌───────────────┐                │
     │  │ Queued  │───▶│ Running │───▶│  Completed    │                │
     │  └─────────┘    └────┬────┘    └───────────────┘                │
     │       │              │                                          │
     │       │              │         ┌───────────────┐                │
     │       │              └────────▶│    Failed     │                │
     │       │              │         └───────────────┘                │
     │       │              │                                          │
     │       │              │         ┌───────────────┐                │
     │       └──────────────┴────────▶│   Canceled    │                │
     │                                └───────────────┘                │
     │                                                                 │
     └─────────────────────────────────────────────────────────────────┘
```

Tasks use an event-sourced state machine. Each state transition is recorded as an event, providing a complete audit trail and enabling replay.

## Design Principles

1. **Local-first** — Data never leaves your machines unless you want it to
2. **Work survives interruption** — Tasks are durable, not tied to sessions
3. **Multi-device by design** — Access from anywhere on your network
4. **Audit everything** — Full history for security and debugging
5. **IO-free core** — Business logic is pure and testable

## Status

Early development. Core functionality works:

-   Task execution with full PTY support (colors, control codes)
-   Live output streaming and input forwarding
-   Attention detection (password prompts, stalls)
-   Client enrollment with signed tokens (no TOFU)
-   mTLS for secure connections
-   SQLite persistence for tasks and auth
-   Same-machine trust (local auto-enrollment)
-   Graceful shutdown with task cancellation

Not yet implemented:

-   Multi-device sync
-   Mobile/web clients

## Contributors

-   Omar Imtiaz (@oaimtiaz)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
