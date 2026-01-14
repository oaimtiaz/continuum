# Continuum

**Local-first runtime that keeps work alive across devices.**

Continuum lets long-running, interactive tasks continue on your home or office machine while you observe, intervene, and resume them from anywhere—without moving your work to the cloud.

## The Problem

Tasks die when you close your laptop, lose a terminal, or walk away. You have to babysit sessions, set up SSH tunnels, or re-run work from scratch.

## The Solution

Continuum makes long-running work survivable. Start work on one machine, check progress from your phone, approve prompts, and resume exactly where you left off—without SSH gymnastics or babysitting sessions.

**Mental model:** *"My work lives on a machine, not in a session."*

## Key Features

- **Durable tasks** — Work continues even when you disconnect
- **Multi-device access** — Monitor and interact from laptop, phone, or tablet
- **Interactive prompts** — Respond to password prompts and confirmations remotely
- **PTY support** — Full terminal output with colors and control codes
- **Audit trail** — Complete history of who did what and when
- **Local-first** — Your data stays on your machines, not in the cloud

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Network                            │
│                                                                 │
│   ┌──────────┐     ┌──────────────────┐     ┌──────────────┐   │
│   │  Phone   │────▶│                  │◀────│   Laptop     │   │
│   │  (view)  │     │  continuum-daemon │     │   (admin)    │   │
│   └──────────┘     │                  │     └──────────────┘   │
│                    │  Running on your │                        │
│                    │  home/office     │                        │
│                    │  machine         │                        │
│                    └────────┬─────────┘                        │
│                             │                                  │
│                      ┌──────▼──────┐                           │
│                      │    Tasks    │                           │
│                      │  (durable)  │                           │
│                      └─────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

This is a Rust workspace with four crates:

```
continuum/
├── continuum-core/      # Pure domain types (IO-free)
├── continuum-proto/     # Protobuf types for IPC
├── continuum-daemon/    # Service running on host machine
└── continuum-cli/       # Command-line interface
```

### `continuum-core`

Pure domain types and business logic. Intentionally IO-free:
- No filesystem, network, or database operations
- All types are plain Rust structs/enums with serde serialization
- Stable API with semantic versioning

**Key types:**
- `Task` — A durable command with lifecycle state machine
- `TaskStatus` — Queued → Running → Completed/Failed/Canceled
- `AttentionState` — Overlay indicating if a task needs user input
- `Device`, `DeviceRole` — Multi-device identity and authorization
- `AuditEvent` — Security and compliance logging

### `continuum-proto`

Protocol buffer definitions for client-daemon communication. Generated from `proto/continuum.proto`.

### `continuum-daemon`

The service that runs on your host machine:
- Executes tasks in PTY sessions
- Streams output to connected clients
- Detects when tasks need input
- Persists task state across restarts

### `continuum-cli`

Command-line interface for interacting with the daemon:
- Start, stop, and monitor tasks
- Send input to running tasks
- Manage device authorization

## Building

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Build release
cargo build --release
```

## Design Principles

1. **Local-first** — Data never leaves your machines unless you want it to
2. **Work survives interruption** — Tasks are durable, not tied to sessions
3. **Multi-device by design** — Access from anywhere on your network
4. **Audit everything** — Full history for security and debugging
5. **IO-free core** — Business logic is pure and testable

## Task Lifecycle

```
     ┌─────────────────────────────────────────────────────┐
     │                                                     │
     │  ┌─────────┐    ┌─────────┐    ┌───────────────┐   │
     │  │ Queued  │───▶│ Running │───▶│  Completed    │   │
     │  └─────────┘    └────┬────┘    └───────────────┘   │
     │       │              │                              │
     │       │              │         ┌───────────────┐   │
     │       │              └────────▶│    Failed     │   │
     │       │              │         └───────────────┘   │
     │       │              │                              │
     │       │              │         ┌───────────────┐   │
     │       └──────────────┴────────▶│   Canceled    │   │
     │                                └───────────────┘   │
     │                                                     │
     └─────────────────────────────────────────────────────┘
```

Tasks use an event-sourced state machine. Each state transition is recorded as an event, providing a complete audit trail and enabling replay.

## Device Roles

| Role | Permissions |
|------|-------------|
| **Viewer** | Observe tasks and output (read-only) |
| **Interactor** | Send input to running tasks |
| **Admin** | Full control: create tasks, manage devices |

## Status

Early development. Core types are implemented; daemon and CLI are scaffolded.

## License

[TBD]
