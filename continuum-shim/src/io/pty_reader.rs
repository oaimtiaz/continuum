//! Async PTY read loop.

use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

/// Output chunk from the PTY.
pub struct PtyOutput {
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub timestamp: Instant,
}

/// Run the PTY read loop, sending output to the channel.
///
/// Returns when the PTY is closed or an error occurs.
pub async fn run_pty_reader(
    fd: RawFd,
    output_tx: mpsc::Sender<PtyOutput>,
    attention_tx: mpsc::Sender<(Vec<u8>, Instant)>,
) -> std::io::Result<()> {
    // Set non-blocking mode (required by AsyncFd)
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Wrap the raw fd in AsyncFd for async I/O
    let async_fd = AsyncFd::new(fd)?;

    let mut buf = vec![0u8; 4096];

    loop {
        // Wait for the fd to be readable
        let mut guard = async_fd.readable().await?;

        match guard.try_io(|inner| {
            let fd = inner.as_raw_fd();
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => {
                // EOF - PTY closed
                break;
            }
            Ok(Ok(n)) => {
                let timestamp = Instant::now();
                let data = buf[..n].to_vec();

                // Send to attention detector
                let _ = attention_tx.try_send((data.clone(), timestamp));

                // Send to IPC
                if output_tx.send(PtyOutput { data, timestamp }).await.is_err() {
                    break;
                }
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Spurious wakeup, continue
                continue;
            }
            Ok(Err(e)) => {
                tracing::error!("PTY read error: {}", e);
                return Err(e);
            }
            Err(_would_block) => {
                // Not ready, will be retried
                continue;
            }
        }
    }

    Ok(())
}
