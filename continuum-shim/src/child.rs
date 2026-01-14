//! Child process management using continuum-pty.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::AsRawFd;

use continuum_pty::{
    resize, signal_pid, signal_pgid, spawn_pty, try_wait, wait,
    ExitStatus, Pid, ProcessGroupId, PtyChild, PtyError, Signal, SpawnSpec, Winsz,
};

use crate::args::Args;

/// Wrapper around PtyChild with helper methods.
pub struct Child {
    inner: PtyChild,
}

impl Child {
    /// Spawn a child process from command-line arguments.
    pub fn spawn(args: &Args) -> Result<Self, PtyError> {
        let program = args.cmd.first().ok_or_else(|| {
            PtyError::InvalidArgument("no command specified".to_string())
        })?;

        // Build CString args
        let c_args: Vec<CString> = args
            .cmd
            .iter()
            .filter_map(|s| CString::new(s.as_bytes()).ok())
            .collect();

        // Build environment
        let env: BTreeMap<String, String> = args.parse_env().into_iter().collect();

        // Canonicalize cwd
        let cwd = args.cwd.canonicalize().unwrap_or_else(|_| args.cwd.clone());

        let spec = SpawnSpec::new(program.as_bytes())?
            .args(c_args)
            .cwd(cwd)
            .env(env)
            .winsz(Winsz::new(args.rows, args.cols));

        let child = spawn_pty(spec)?;

        tracing::info!(
            pid = child.pid.as_raw(),
            pgid = child.pgid.as_raw(),
            "child process spawned"
        );

        Ok(Self { inner: child })
    }

    /// Get the child's PID.
    pub fn pid(&self) -> Pid {
        self.inner.pid
    }

    /// Get the child's process group ID.
    pub fn pgid(&self) -> ProcessGroupId {
        self.inner.pgid
    }

    /// Get the raw file descriptor for the PTY master.
    pub fn master_fd(&self) -> i32 {
        self.inner.master.as_raw_fd()
    }

    /// Resize the PTY and optionally notify the process group.
    #[allow(dead_code)]
    pub fn resize(&self, rows: u16, cols: u16, notify: bool) -> Result<(), PtyError> {
        let notify_pgid = if notify { Some(self.inner.pgid) } else { None };
        resize(&self.inner.master, Winsz::new(rows, cols), notify_pgid)
    }

    /// Send a signal to the child process.
    #[allow(dead_code)]
    pub fn signal(&self, sig: Signal) -> Result<(), PtyError> {
        signal_pid(self.inner.pid, sig)
    }

    /// Send a signal to the child's process group.
    #[allow(dead_code)]
    pub fn signal_group(&self, sig: Signal) -> Result<(), PtyError> {
        signal_pgid(self.inner.pgid, sig)
    }

    /// Non-blocking check for exit status.
    pub fn try_wait(&self) -> Result<Option<ExitStatus>, PtyError> {
        try_wait(self.inner.pid)
    }

    /// Blocking wait for exit status.
    #[allow(dead_code)]
    pub fn wait(&self) -> Result<ExitStatus, PtyError> {
        wait(self.inner.pid)
    }
}
