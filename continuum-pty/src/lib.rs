//! PTY handling for Continuum.
//!
//! This crate provides low-level PTY (pseudo-terminal) operations for Unix systems.
//! It encapsulates all PTY + spawn + signal + resize syscalls in a clean, safe API.
//!
//! # Example
//!
//! ```no_run
//! use continuum_pty::{spawn_pty, SpawnSpec, Winsz, try_wait, signal_pid, Signal};
//!
//! // Spawn a shell
//! let spec = SpawnSpec::new("/bin/sh")
//!     .unwrap()
//!     .winsz(Winsz::new(24, 80));
//!
//! let mut child = spawn_pty(spec).unwrap();
//!
//! // Check if child has exited
//! if let Some(status) = try_wait(child.pid).unwrap() {
//!     println!("Child exited with: {:?}", status);
//! }
//!
//! // Send SIGTERM to terminate
//! signal_pid(child.pid, Signal::Term).unwrap();
//! ```

mod error;
mod platform;
mod resize;
mod signal;
mod spawn;
mod types;
mod wait;

// Re-export public API
pub use error::PtyError;
pub use resize::resize;
pub use signal::{signal_pgid, signal_pid, Signal};
pub use spawn::{spawn_pty, SpawnSpec};
pub use types::{Pid, ProcessGroupId, PtyChild, PtyMaster, PtySlave, Winsz};
pub use wait::{try_wait, wait, ExitStatus};

/// Allocate a PTY pair (master, slave) with initial window size.
///
/// This is useful if you want to do custom spawn wiring.
/// For most cases, use [`spawn_pty`] instead.
pub fn open_pty(winsz: Winsz) -> Result<(PtyMaster, PtySlave), PtyError> {
    platform::open_pty_pair(winsz)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_winsz_new() {
        let ws = Winsz::new(25, 80);
        assert_eq!(ws.rows, 25);
        assert_eq!(ws.cols, 80);
        assert_eq!(ws.xpixel, 0);
        assert_eq!(ws.ypixel, 0);
    }

    #[test]
    fn test_winsz_default() {
        let ws = Winsz::default();
        assert_eq!(ws.rows, 24);
        assert_eq!(ws.cols, 80);
    }

    #[test]
    fn test_signal_to_libc() {
        assert_eq!(Signal::Int.to_libc(), libc::SIGINT);
        assert_eq!(Signal::Term.to_libc(), libc::SIGTERM);
        assert_eq!(Signal::Kill.to_libc(), libc::SIGKILL);
        assert_eq!(Signal::Hup.to_libc(), libc::SIGHUP);
        assert_eq!(Signal::Winch.to_libc(), libc::SIGWINCH);
        assert_eq!(Signal::Custom(42).to_libc(), 42);
    }

    #[test]
    fn test_exit_status_code() {
        let status = ExitStatus::Code(0);
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
        assert_eq!(status.signal(), None);

        let status = ExitStatus::Code(1);
        assert!(!status.success());
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn test_exit_status_signaled() {
        let status = ExitStatus::Signaled(libc::SIGTERM);
        assert!(!status.success());
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn test_open_pty() {
        let result = open_pty(Winsz::new(24, 80));
        assert!(result.is_ok());
        let (master, slave) = result.unwrap();
        assert!(master.as_raw_fd() >= 0);
        assert!(slave.as_raw_fd() >= 0);
    }

    #[test]
    fn test_spawn_echo() {
        let spec = SpawnSpec::new("/bin/echo")
            .unwrap()
            .args(vec![
                CString::new("echo").unwrap(),
                CString::new("hello").unwrap(),
            ])
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Wait for child to exit
        let status = wait(child.pid).unwrap();
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_spawn_false() {
        let spec = SpawnSpec::new("/usr/bin/false")
            .unwrap()
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        let status = wait(child.pid).unwrap();
        assert!(!status.success());
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn test_spawn_true() {
        let spec = SpawnSpec::new("/usr/bin/true")
            .unwrap()
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        let status = wait(child.pid).unwrap();
        assert!(status.success());
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_try_wait_running() {
        // Spawn a process that sleeps
        let spec = SpawnSpec::new("/bin/sleep")
            .unwrap()
            .args(vec![
                CString::new("sleep").unwrap(),
                CString::new("10").unwrap(),
            ])
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Should still be running
        let result = try_wait(child.pid).unwrap();
        assert!(result.is_none());

        // Kill it
        signal_pid(child.pid, Signal::Kill).unwrap();

        // Wait for it to die
        let status = wait(child.pid).unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn test_resize() {
        let spec = SpawnSpec::new("/bin/cat")
            .unwrap()
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Resize without SIGWINCH notification (avoids race conditions in tests)
        let result = resize(&child.master, Winsz::new(48, 120), None);
        assert!(result.is_ok(), "resize failed: {:?}", result.err());

        // Clean up
        signal_pid(child.pid, Signal::Kill).unwrap();
        let _ = wait(child.pid);
    }

    #[test]
    fn test_signal_term() {
        let spec = SpawnSpec::new("/bin/cat")
            .unwrap()
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Send SIGTERM
        signal_pid(child.pid, Signal::Term).unwrap();

        // Wait for exit
        let status = wait(child.pid).unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn test_env_passing() {
        use std::collections::BTreeMap;

        let mut env = BTreeMap::new();
        env.insert("TEST_VAR".to_string(), "test_value".to_string());

        let spec = SpawnSpec::new("/usr/bin/env")
            .unwrap()
            .env(env)
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Read output from master until child exits
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];

        // Set non-blocking mode for reading
        unsafe {
            let flags = libc::fcntl(child.master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(child.master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let fd = child.master.as_raw_fd();

        // Read until child exits
        loop {
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n > 0 {
                output.extend_from_slice(&buf[..n as usize]);
            }

            // Check if child has exited
            if let Ok(Some(_)) = try_wait(child.pid) {
                // Read any remaining output
                loop {
                    let n = unsafe {
                        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if n <= 0 {
                        break;
                    }
                    output.extend_from_slice(&buf[..n as usize]);
                }
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        let output_str = String::from_utf8_lossy(&output);
        assert!(
            output_str.contains("TEST_VAR=test_value"),
            "Expected TEST_VAR=test_value in output, got: {}",
            output_str
        );
    }

    #[test]
    fn test_cwd() {
        let spec = SpawnSpec::new("/bin/pwd")
            .unwrap()
            .cwd("/tmp")
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Read output until child exits
        let mut output = Vec::new();
        let mut buf = [0u8; 1024];

        unsafe {
            let flags = libc::fcntl(child.master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(child.master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let fd = child.master.as_raw_fd();

        loop {
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n > 0 {
                output.extend_from_slice(&buf[..n as usize]);
            }

            if let Ok(Some(_)) = try_wait(child.pid) {
                loop {
                    let n = unsafe {
                        libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                    };
                    if n <= 0 {
                        break;
                    }
                    output.extend_from_slice(&buf[..n as usize]);
                }
                break;
            }

            thread::sleep(Duration::from_millis(10));
        }

        let output_str = String::from_utf8_lossy(&output);
        // On macOS, /tmp is a symlink to /private/tmp
        assert!(
            output_str.contains("/tmp") || output_str.contains("/private/tmp"),
            "Expected /tmp in output, got: {}",
            output_str
        );
    }

    #[test]
    fn test_spawn_nonexistent() {
        let spec = SpawnSpec::new("/nonexistent/path/to/program")
            .unwrap()
            .winsz(Winsz::new(24, 80));

        let child = spawn_pty(spec).unwrap();

        // Child should exit with code 127 (command not found)
        let status = wait(child.pid).unwrap();
        assert_eq!(status.code(), Some(127));
    }

    #[test]
    fn test_pid_accessors() {
        let pid = Pid::new(1234);
        assert_eq!(pid.as_raw(), 1234);
        assert_eq!(pid.0, 1234);
    }

    #[test]
    fn test_pgid_accessors() {
        let pgid = ProcessGroupId::new(5678);
        assert_eq!(pgid.as_raw(), 5678);
        assert_eq!(pgid.0, 5678);
    }

    #[test]
    fn test_spawn_spec_builder() {
        use std::collections::BTreeMap;

        let mut env = BTreeMap::new();
        env.insert("FOO".to_string(), "bar".to_string());

        let spec = SpawnSpec::new("/bin/sh")
            .unwrap()
            .args(vec![CString::new("sh").unwrap(), CString::new("-c").unwrap()])
            .cwd("/tmp")
            .env(env.clone())
            .winsz(Winsz::new(30, 100));

        assert_eq!(spec.program, CString::new("/bin/sh").unwrap());
        assert_eq!(spec.args.len(), 2);
        assert_eq!(spec.cwd, std::path::PathBuf::from("/tmp"));
        assert_eq!(spec.env, env);
        assert_eq!(spec.winsz.rows, 30);
        assert_eq!(spec.winsz.cols, 100);
    }
}
