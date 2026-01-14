//! Process exit status handling.

use std::io;

use crate::error::PtyError;
use crate::types::Pid;

/// Exit status of a terminated process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Process exited normally with this code.
    Code(i32),
    /// Process was killed by a signal.
    Signaled(i32),
}

impl ExitStatus {
    /// Returns true if the process exited successfully (code 0).
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Code(0))
    }

    /// Returns the exit code if the process exited normally.
    pub fn code(&self) -> Option<i32> {
        match self {
            ExitStatus::Code(c) => Some(*c),
            ExitStatus::Signaled(_) => None,
        }
    }

    /// Returns the signal number if the process was killed by a signal.
    pub fn signal(&self) -> Option<i32> {
        match self {
            ExitStatus::Code(_) => None,
            ExitStatus::Signaled(s) => Some(*s),
        }
    }
}

/// Decode a raw waitpid status into ExitStatus.
fn decode_status(status: libc::c_int) -> ExitStatus {
    if libc::WIFEXITED(status) {
        ExitStatus::Code(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        ExitStatus::Signaled(libc::WTERMSIG(status))
    } else {
        // Stopped or continued - treat as still running, shouldn't happen with WNOHANG
        ExitStatus::Code(-1)
    }
}

/// Non-blocking check for child exit status.
///
/// Returns:
/// - `Ok(None)` if the child is still running
/// - `Ok(Some(status))` if the child has exited
/// - `Err` if waitpid failed
pub fn try_wait(pid: Pid) -> Result<Option<ExitStatus>, PtyError> {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid.0, &mut status, libc::WNOHANG) };

    if result == 0 {
        // Child still running
        Ok(None)
    } else if result > 0 {
        // Child exited
        Ok(Some(decode_status(status)))
    } else {
        // Error (result == -1)
        Err(PtyError::Wait(io::Error::last_os_error()))
    }
}

/// Blocking wait for child exit status.
///
/// Blocks until the child exits.
pub fn wait(pid: Pid) -> Result<ExitStatus, PtyError> {
    let mut status: libc::c_int = 0;
    let result = unsafe { libc::waitpid(pid.0, &mut status, 0) };

    if result > 0 {
        Ok(decode_status(status))
    } else {
        Err(PtyError::Wait(io::Error::last_os_error()))
    }
}
