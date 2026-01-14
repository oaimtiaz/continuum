//! Linux PTY implementation (stub).

use std::os::fd::RawFd;

use crate::error::PtyError;
use crate::types::{PtyMaster, PtySlave, Winsz};

/// Allocate a PTY pair (master, slave) with initial window size.
pub(crate) fn open_pty_pair(_winsz: Winsz) -> Result<(PtyMaster, PtySlave), PtyError> {
    unimplemented!("Linux PTY support not yet implemented")
}

/// Set window size on a PTY fd using TIOCSWINSZ.
pub(crate) fn set_window_size(_fd: RawFd, _winsz: Winsz) -> Result<(), PtyError> {
    unimplemented!("Linux PTY support not yet implemented")
}

/// Set the controlling terminal for the current process.
pub(crate) fn set_controlling_terminal(_fd: RawFd) -> Result<(), PtyError> {
    unimplemented!("Linux PTY support not yet implemented")
}
