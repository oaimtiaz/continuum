//! IPC communication with daemon.

pub mod client;
pub mod unix;

pub use client::IpcClient;
