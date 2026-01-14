//! macOS PTY implementation using openpty().

use std::io;
use std::os::fd::RawFd;

use crate::error::PtyError;
use crate::types::{PtyMaster, PtySlave, Winsz};

// TIOCSCTTY is not in libc for macOS, define it ourselves.
// From sys/ttycom.h: #define TIOCSCTTY _IO('t', 97)
const TIOCSCTTY: libc::c_ulong = 0x20007461;

unsafe extern "C" {
    unsafe fn openpty(
        amaster: *mut libc::c_int,
        aslave: *mut libc::c_int,
        name: *mut libc::c_char,
        termp: *const libc::termios,
        winp: *const libc::winsize,
    ) -> libc::c_int;
}

/// Allocate a PTY pair (master, slave) with initial window size.
pub(crate) fn open_pty_pair(winsz: Winsz) -> Result<(PtyMaster, PtySlave), PtyError> {
    let mut master_fd: libc::c_int = -1;
    let mut slave_fd: libc::c_int = -1;
    let ws = winsz.to_libc();

    let ret = unsafe {
        openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            &ws,
        )
    };

    if ret != 0 {
        return Err(PtyError::Allocation(io::Error::last_os_error()));
    }

    // Safety: openpty succeeded, so these are valid owned fds
    let master = unsafe { PtyMaster::from_raw_fd(master_fd) };
    let slave = unsafe { PtySlave::from_raw_fd(slave_fd) };

    Ok((master, slave))
}

/// Set window size on a PTY fd using TIOCSWINSZ.
pub(crate) fn set_window_size(fd: RawFd, winsz: Winsz) -> Result<(), PtyError> {
    let ws = winsz.to_libc();
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret != 0 {
        return Err(PtyError::Resize(io::Error::last_os_error()));
    }
    Ok(())
}

/// Set the controlling terminal for the current process.
/// Must be called after setsid() in the child.
pub(crate) fn set_controlling_terminal(fd: RawFd) -> Result<(), PtyError> {
    let ret = unsafe { libc::ioctl(fd, TIOCSCTTY, 0 as libc::c_int) };
    if ret != 0 {
        return Err(PtyError::SetControllingTerminal(io::Error::last_os_error()));
    }
    Ok(())
}
