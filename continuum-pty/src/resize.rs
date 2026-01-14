//! PTY window resize handling.

use std::os::fd::AsRawFd;

use crate::error::PtyError;
use crate::platform;
use crate::signal::{signal_pgid, Signal};
use crate::types::{ProcessGroupId, PtyMaster, Winsz};

/// Resize a PTY and optionally notify the process group with SIGWINCH.
///
/// # Arguments
/// * `master` - The PTY master fd
/// * `winsz` - The new window size
/// * `notify` - If Some, send SIGWINCH to this process group after resize
pub fn resize(
    master: &PtyMaster,
    winsz: Winsz,
    notify: Option<ProcessGroupId>,
) -> Result<(), PtyError> {
    // Set the new window size via ioctl
    platform::set_window_size(master.as_raw_fd(), winsz)?;

    // Optionally notify the process group
    if let Some(pgid) = notify {
        signal_pgid(pgid, Signal::Winch)?;
    }

    Ok(())
}
