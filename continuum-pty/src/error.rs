//! PTY error types.

use std::io;

/// Errors that can occur during PTY operations.
#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    /// PTY allocation failed (openpty).
    #[error("PTY allocation failed: {0}")]
    Allocation(#[source] io::Error),

    /// fork() failed.
    #[error("fork failed: {0}")]
    Fork(#[source] io::Error),

    /// setsid() failed.
    #[error("setsid failed: {0}")]
    Setsid(#[source] io::Error),

    /// TIOCSCTTY ioctl failed.
    #[error("failed to set controlling terminal: {0}")]
    SetControllingTerminal(#[source] io::Error),

    /// dup2() failed.
    #[error("dup2 failed: {0}")]
    Dup(#[source] io::Error),

    /// execvp() failed.
    #[error("exec failed: {0}")]
    Exec(#[source] io::Error),

    /// chdir() failed.
    #[error("chdir failed: {0}")]
    Chdir(#[source] io::Error),

    /// TIOCSWINSZ ioctl failed.
    #[error("resize failed: {0}")]
    Resize(#[source] io::Error),

    /// kill() failed.
    #[error("signal failed: {0}")]
    Signal(#[source] io::Error),

    /// waitpid() failed.
    #[error("waitpid failed: {0}")]
    Wait(#[source] io::Error),

    /// Invalid path (contains null bytes).
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// Invalid argument string (contains null bytes).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
