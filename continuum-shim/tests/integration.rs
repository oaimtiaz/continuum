//! Integration tests for continuum-shim.
//!
//! These tests verify the actual PTY spawning and IPC flow.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use prost::Message;

// Re-export proto types
use continuum_shim_proto::{DaemonToShim, ShimToDaemon, Shutdown, daemon_to_shim, shim_to_daemon};

/// Counter for unique socket paths.
static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Read a length-delimited frame (blocking).
fn read_frame(stream: &mut UnixStream) -> std::io::Result<Bytes> {
    use std::io::Read;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    Ok(Bytes::from(buf))
}

/// Write a length-delimited frame (blocking).
fn write_frame(stream: &mut UnixStream, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

/// A mock daemon for testing.
struct MockDaemon {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl MockDaemon {
    fn new() -> std::io::Result<Self> {
        let counter = SOCKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        let socket_path = std::env::temp_dir().join(format!(
            "continuum-test-{}-{}.sock",
            std::process::id(),
            counter
        ));

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(false)?;

        Ok(Self {
            listener,
            socket_path,
        })
    }

    fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    fn accept(&self) -> std::io::Result<UnixStream> {
        let (stream, _) = self.listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(stream)
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Spawn the shim as a subprocess.
fn spawn_shim(
    socket_path: &PathBuf,
    task_id: &str,
    cmd: &[&str],
) -> std::io::Result<std::process::Child> {
    let shim_binary = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("continuum-shim");

    let mut args = vec![
        "--task-id".to_string(),
        task_id.to_string(),
        "--connect".to_string(),
        socket_path.to_string_lossy().to_string(),
        "--".to_string(),
    ];
    args.extend(cmd.iter().map(|s| s.to_string()));

    std::process::Command::new(shim_binary)
        .args(&args)
        .spawn()
}

#[test]
fn test_shim_sends_started_message() {
    let daemon = MockDaemon::new().expect("failed to create mock daemon");

    // Spawn shim in background
    let socket_path = daemon.socket_path().clone();
    let shim_handle = thread::spawn(move || {
        spawn_shim(&socket_path, "test-started", &["echo", "hello"])
    });

    // Accept connection and read Started message
    let mut stream = daemon.accept().expect("failed to accept connection");

    let frame = read_frame(&mut stream).expect("failed to read frame");
    let msg = ShimToDaemon::decode(frame).expect("failed to decode message");

    match msg.msg {
        Some(shim_to_daemon::Msg::Started(started)) => {
            assert!(started.pid > 0, "pid should be positive");
            assert!(started.pgid > 0, "pgid should be positive");
        }
        other => panic!("expected Started message, got {:?}", other),
    }

    // Send shutdown to clean up
    let shutdown_msg = DaemonToShim {
        msg: Some(daemon_to_shim::Msg::Shutdown(Shutdown {})),
    };
    let _ = write_frame(&mut stream, &shutdown_msg.encode_to_vec());

    // Wait for shim to exit
    let mut child = shim_handle.join().unwrap().unwrap();
    let _ = child.wait();
}

#[test]
fn test_shim_sends_output() {
    let daemon = MockDaemon::new().expect("failed to create mock daemon");

    let socket_path = daemon.socket_path().clone();
    let shim_handle = thread::spawn(move || {
        spawn_shim(&socket_path, "test-output", &["echo", "hello world"])
    });

    let mut stream = daemon.accept().expect("failed to accept connection");

    // Read Started
    let frame = read_frame(&mut stream).expect("failed to read Started");
    let msg = ShimToDaemon::decode(frame).expect("decode Started");
    assert!(matches!(msg.msg, Some(shim_to_daemon::Msg::Started(_))));

    // Read Output (may come in multiple chunks)
    let mut output_data = Vec::new();
    loop {
        match read_frame(&mut stream) {
            Ok(frame) => {
                let msg = ShimToDaemon::decode(frame).expect("decode message");
                match msg.msg {
                    Some(shim_to_daemon::Msg::Output(output)) => {
                        output_data.extend_from_slice(&output.data);
                    }
                    Some(shim_to_daemon::Msg::Exited(_)) => break,
                    _ => {}
                }
            }
            Err(_) => break,
        }
    }

    let output_str = String::from_utf8_lossy(&output_data);
    assert!(
        output_str.contains("hello world"),
        "output should contain 'hello world', got: {:?}",
        output_str
    );

    let mut child = shim_handle.join().unwrap().unwrap();
    let _ = child.wait();
}

#[test]
fn test_shim_sends_exited_on_completion() {
    let daemon = MockDaemon::new().expect("failed to create mock daemon");

    let socket_path = daemon.socket_path().clone();
    let shim_handle = thread::spawn(move || {
        spawn_shim(&socket_path, "test-exit", &["true"]) // exits with 0
    });

    let mut stream = daemon.accept().expect("failed to accept connection");

    // Read messages until we get Exited
    let mut got_exited = false;
    let mut exit_code = None;

    for _ in 0..20 {
        match read_frame(&mut stream) {
            Ok(frame) => {
                let msg = ShimToDaemon::decode(frame).expect("decode message");
                if let Some(shim_to_daemon::Msg::Exited(exited)) = msg.msg {
                    got_exited = true;
                    if let Some(continuum_shim_proto::exited::Status::Code(code)) = exited.status {
                        exit_code = Some(code);
                    }
                    break;
                }
            }
            Err(_) => break,
        }
    }

    assert!(got_exited, "should receive Exited message");
    assert_eq!(exit_code, Some(0), "exit code should be 0");

    let mut child = shim_handle.join().unwrap().unwrap();
    let _ = child.wait();
}

#[test]
fn test_shim_sends_exited_with_nonzero_code() {
    let daemon = MockDaemon::new().expect("failed to create mock daemon");

    let socket_path = daemon.socket_path().clone();
    let shim_handle = thread::spawn(move || {
        spawn_shim(&socket_path, "test-exit-code", &["false"]) // exits with 1
    });

    let mut stream = daemon.accept().expect("failed to accept connection");

    let mut exit_code = None;

    for _ in 0..20 {
        match read_frame(&mut stream) {
            Ok(frame) => {
                let msg = ShimToDaemon::decode(frame).expect("decode message");
                if let Some(shim_to_daemon::Msg::Exited(exited)) = msg.msg {
                    if let Some(continuum_shim_proto::exited::Status::Code(code)) = exited.status {
                        exit_code = Some(code);
                    }
                    break;
                }
            }
            Err(_) => break,
        }
    }

    assert_eq!(exit_code, Some(1), "exit code should be 1");

    let mut child = shim_handle.join().unwrap().unwrap();
    let _ = child.wait();
}

#[test]
fn test_shim_receives_stdin() {
    let daemon = MockDaemon::new().expect("failed to create mock daemon");

    let socket_path = daemon.socket_path().clone();
    let shim_handle = thread::spawn(move || {
        // Use sh -c to read one line and echo it back, then exit naturally
        spawn_shim(
            &socket_path,
            "test-stdin",
            &["sh", "-c", "read line && echo \"GOT: $line\""],
        )
    });

    let mut stream = daemon.accept().expect("failed to accept connection");

    // Read Started
    let frame = read_frame(&mut stream).expect("failed to read Started");
    let _ = ShimToDaemon::decode(frame).expect("decode Started");

    // Send stdin
    let stdin_msg = DaemonToShim {
        msg: Some(daemon_to_shim::Msg::Stdin(continuum_shim_proto::Stdin {
            data: b"test input\n".to_vec(),
        })),
    };
    write_frame(&mut stream, &stdin_msg.encode_to_vec()).expect("send stdin");

    // Read output until we get Exited (process should exit naturally after echoing)
    let mut output_data = Vec::new();
    for _ in 0..20 {
        match read_frame(&mut stream) {
            Ok(frame) => {
                let msg = ShimToDaemon::decode(frame).expect("decode message");
                match msg.msg {
                    Some(shim_to_daemon::Msg::Output(output)) => {
                        output_data.extend_from_slice(&output.data);
                    }
                    Some(shim_to_daemon::Msg::Exited(_)) => break,
                    _ => {}
                }
            }
            Err(_) => break,
        }
    }

    let output_str = String::from_utf8_lossy(&output_data);
    assert!(
        output_str.contains("GOT: test input"),
        "output should contain 'GOT: test input', got: {:?}",
        output_str
    );

    let mut child = shim_handle.join().unwrap().unwrap();
    let _ = child.wait();
}
