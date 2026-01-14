//! # Continuum Core
//!
//! Pure domain types and business logic for the Continuum distributed task
//! execution system.
//!
//! ## Design Principles
//!
//! This crate is intentionally **IO-free**:
//! - No filesystem operations
//! - No network calls
//! - No database interactions
//! - No OS-specific APIs
//!
//! All types are plain Rust structs/enums with serde serialization. The actual
//! IO (process execution, IPC, persistence) lives in `continuum-daemon`.
//!
//! ## Stability
//!
//! This crate follows semantic versioning. The public API includes:
//! - All types exported from this module
//! - Their serde serialization format (JSON field names, enum representations)
//!
//! Breaking changes to serialization format will bump the major version.
//!
//! ## Modules
//!
//! - [`identity`] - Device identification and authorization
//! - [`task`] - Task execution and I/O types
//! - [`audit`] - Audit logging for security and compliance

pub mod audit;
pub mod identity;
pub mod task;

// Re-export commonly used types at crate root for convenience.
// Users can write `use continuum_core::Task` instead of `use continuum_core::task::Task`.

pub use audit::{AuditAction, AuditEvent, AuditTarget};
pub use identity::{AuthzDecision, DeviceDisplayName, DeviceId, DeviceRole};
pub use task::{CreatedVia, Input, OutputChunk, Stream, Task, TaskId, TaskStatus};
