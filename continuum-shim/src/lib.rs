//! Continuum shim library - bridges a single PTY child to a parent process.
//!
//! Each shim instance:
//! - Owns one PTY child process
//! - Streams output to the parent via Unix socket IPC
//! - Receives stdin, signals, and resize from the parent
//! - Exits when the child exits

pub mod args;
#[cfg(feature = "attention")]
pub mod attention;
pub mod child;
pub mod io;
pub mod ipc;
pub mod run;
pub mod util;

pub use args::Args;
pub use run::run;
