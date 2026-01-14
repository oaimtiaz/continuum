//! Core types for PTY handling.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// Process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub i32);

impl Pid {
    /// Create a new Pid.
    pub fn new(pid: i32) -> Self {
        Self(pid)
    }

    /// Get the raw pid value.
    pub fn as_raw(&self) -> i32 {
        self.0
    }
}

/// Process group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGroupId(pub i32);

impl ProcessGroupId {
    /// Create a new ProcessGroupId.
    pub fn new(pgid: i32) -> Self {
        Self(pgid)
    }

    /// Get the raw pgid value.
    pub fn as_raw(&self) -> i32 {
        self.0
    }
}

/// Terminal window size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Winsz {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsz {
    /// Create a new window size with rows and columns.
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            rows,
            cols,
            xpixel: 0,
            ypixel: 0,
        }
    }

    /// Convert to libc winsize struct.
    pub(crate) fn to_libc(self) -> libc::winsize {
        libc::winsize {
            ws_row: self.rows,
            ws_col: self.cols,
            ws_xpixel: self.xpixel,
            ws_ypixel: self.ypixel,
        }
    }
}

impl Default for Winsz {
    fn default() -> Self {
        Self::new(24, 80)
    }
}

/// The PTY master end owned by the parent (shim/daemon).
pub struct PtyMaster(OwnedFd);

impl PtyMaster {
    /// Create from a raw file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid, open file descriptor that the caller owns.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self(OwnedFd::from_raw_fd(fd))
    }

    /// Get a reference to the underlying OwnedFd.
    pub fn as_fd(&self) -> &OwnedFd {
        &self.0
    }

    /// Get a mutable reference to the underlying OwnedFd.
    pub fn as_mut_fd(&mut self) -> &mut OwnedFd {
        &mut self.0
    }
}

impl AsRawFd for PtyMaster {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for PtyMaster {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// The PTY slave end used for the child's controlling terminal.
pub struct PtySlave(OwnedFd);

impl PtySlave {
    /// Create from a raw file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid, open file descriptor that the caller owns.
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self(OwnedFd::from_raw_fd(fd))
    }
}

impl AsRawFd for PtySlave {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for PtySlave {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// A spawned child attached to a PTY slave.
pub struct PtyChild {
    /// The child's process ID.
    pub pid: Pid,
    /// The child's process group ID.
    pub pgid: ProcessGroupId,
    /// The master end of the PTY.
    pub master: PtyMaster,
}
