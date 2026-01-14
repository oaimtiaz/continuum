//! PTY child process spawning.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use crate::error::PtyError;
use crate::platform;
use crate::types::{Pid, ProcessGroupId, PtyChild, Winsz};

/// Specification for spawning a PTY child process.
pub struct SpawnSpec {
    /// Program to execute (must be a valid path or command name).
    pub program: CString,
    /// Arguments to pass (argv[0] should typically be the program name).
    pub args: Vec<CString>,
    /// Working directory for the child.
    pub cwd: PathBuf,
    /// Environment variables for the child.
    pub env: BTreeMap<String, String>,
    /// Initial window size.
    pub winsz: Winsz,
}

impl SpawnSpec {
    /// Create a new SpawnSpec with the given program.
    pub fn new(program: impl Into<Vec<u8>>) -> Result<Self, PtyError> {
        let program =
            CString::new(program).map_err(|e| PtyError::InvalidArgument(e.to_string()))?;
        Ok(Self {
            program,
            args: Vec::new(),
            cwd: PathBuf::from("/"),
            env: BTreeMap::new(),
            winsz: Winsz::default(),
        })
    }

    /// Set the arguments (including argv[0]).
    pub fn args(mut self, args: Vec<CString>) -> Self {
        self.args = args;
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    /// Set environment variables.
    pub fn env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// Set the initial window size.
    pub fn winsz(mut self, winsz: Winsz) -> Self {
        self.winsz = winsz;
        self
    }
}

/// Spawn a child process attached to a PTY.
///
/// This function:
/// 1. Allocates a PTY pair (master/slave)
/// 2. Forks the process
/// 3. In the child: sets up the PTY as controlling terminal and execs
/// 4. In the parent: returns the PtyChild with master fd
pub fn spawn_pty(spec: SpawnSpec) -> Result<PtyChild, PtyError> {
    // Allocate PTY pair
    let (master, slave) = platform::open_pty_pair(spec.winsz)?;

    // Convert cwd to CString
    let cwd_cstr = CString::new(spec.cwd.to_string_lossy().as_bytes())
        .map_err(|e| PtyError::InvalidPath(e.to_string()))?;

    // Build environment as array of "KEY=VALUE\0" CStrings
    let env_cstrings: Vec<CString> = spec
        .env
        .iter()
        .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect();

    // Build argv - if empty, use program as argv[0]
    let argv: Vec<&CStr> = if spec.args.is_empty() {
        vec![spec.program.as_c_str()]
    } else {
        spec.args.iter().map(|s| s.as_c_str()).collect()
    };

    // Fork
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        return Err(PtyError::Fork(io::Error::last_os_error()));
    }

    if pid == 0 {
        // === CHILD PROCESS ===
        // This code runs in the child after fork.
        // Errors here should exit the child, not return.

        // Close master fd in child (we only need slave)
        drop(master);

        // Create new session (become session leader)
        if unsafe { libc::setsid() } < 0 {
            unsafe { libc::_exit(1) };
        }

        // Set controlling terminal
        if platform::set_controlling_terminal(slave.as_raw_fd()).is_err() {
            unsafe { libc::_exit(1) };
        }

        // Duplicate slave fd to stdin/stdout/stderr
        let slave_fd = slave.as_raw_fd();
        if unsafe { libc::dup2(slave_fd, libc::STDIN_FILENO) } < 0 {
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::dup2(slave_fd, libc::STDOUT_FILENO) } < 0 {
            unsafe { libc::_exit(1) };
        }
        if unsafe { libc::dup2(slave_fd, libc::STDERR_FILENO) } < 0 {
            unsafe { libc::_exit(1) };
        }

        // Close original slave fd if it's not one of stdin/stdout/stderr
        if slave_fd > libc::STDERR_FILENO {
            drop(slave);
        }

        // Change directory
        if unsafe { libc::chdir(cwd_cstr.as_ptr()) } < 0 {
            unsafe { libc::_exit(1) };
        }

        // Build null-terminated argv array
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        // Set custom environment variables if any
        for env_cstr in &env_cstrings {
            // setenv is safer than putenv as it copies the string
            let bytes = env_cstr.as_bytes();
            if let Some(eq_pos) = bytes.iter().position(|&b| b == b'=') {
                let key = &bytes[..eq_pos];
                let val = &bytes[eq_pos + 1..];
                if let (Ok(key_cstr), Ok(val_cstr)) = (CString::new(key), CString::new(val)) {
                    unsafe {
                        libc::setenv(key_cstr.as_ptr(), val_cstr.as_ptr(), 1);
                    }
                }
            }
        }

        // Exec (uses PATH if program doesn't contain /)
        unsafe { libc::execvp(spec.program.as_ptr(), argv_ptrs.as_ptr()) };

        // If exec returns, it failed
        unsafe { libc::_exit(127) };
    }

    // === PARENT PROCESS ===
    // Close slave fd in parent
    drop(slave);

    Ok(PtyChild {
        pid: Pid::new(pid),
        pgid: ProcessGroupId::new(pid), // Child becomes its own process group leader
        master,
    })
}
