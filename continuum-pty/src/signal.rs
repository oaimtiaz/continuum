//! Signal handling for PTY processes.

use std::io;

use crate::error::PtyError;
use crate::types::{Pid, ProcessGroupId};

/// Signals that can be sent to processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Interrupt (Ctrl+C).
    Int,
    /// Terminate.
    Term,
    /// Kill (cannot be caught).
    Kill,
    /// Hangup.
    Hup,
    /// Window size change.
    Winch,
    /// Custom signal number.
    Custom(i32),
}

impl Signal {
    /// Convert to libc signal number.
    pub fn to_libc(self) -> libc::c_int {
        match self {
            Signal::Int => libc::SIGINT,
            Signal::Term => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
            Signal::Hup => libc::SIGHUP,
            Signal::Winch => libc::SIGWINCH,
            Signal::Custom(n) => n,
        }
    }
}

/// Send a signal to a specific process.
pub fn signal_pid(pid: Pid, sig: Signal) -> Result<(), PtyError> {
    let ret = unsafe { libc::kill(pid.0, sig.to_libc()) };
    if ret != 0 {
        return Err(PtyError::Signal(io::Error::last_os_error()));
    }
    Ok(())
}

/// Send a signal to a process group.
///
/// This sends the signal to all processes in the group, which is useful
/// for terminal job control (e.g., sending SIGINT to the foreground job).
pub fn signal_pgid(pgid: ProcessGroupId, sig: Signal) -> Result<(), PtyError> {
    // Negative pid means send to process group
    let ret = unsafe { libc::kill(-pgid.0, sig.to_libc()) };
    if ret != 0 {
        return Err(PtyError::Signal(io::Error::last_os_error()));
    }
    Ok(())
}
