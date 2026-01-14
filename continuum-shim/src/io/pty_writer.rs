//! PTY write handling.

use std::os::fd::RawFd;
use std::time::Instant;
use tokio::sync::mpsc;

/// Write data to the PTY master.
///
/// This is a blocking write wrapped for use from async context.
pub fn write_to_pty(fd: RawFd, data: &[u8]) -> std::io::Result<usize> {
    let n = unsafe {
        libc::write(fd, data.as_ptr() as *const libc::c_void, data.len())
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Run the PTY write loop, receiving stdin from the channel.
pub async fn run_pty_writer(
    fd: RawFd,
    mut stdin_rx: mpsc::Receiver<Vec<u8>>,
    input_notify_tx: mpsc::Sender<Instant>,
) -> std::io::Result<()> {
    while let Some(data) = stdin_rx.recv().await {
        // Write to PTY (blocking, but should be fast)
        let result = tokio::task::spawn_blocking({
            let data = data.clone();
            move || write_to_pty(fd, &data)
        })
        .await
        .map_err(std::io::Error::other)?;

        match result {
            Ok(_n) => {
                // Notify attention detector that input was sent
                let _ = input_notify_tx.try_send(Instant::now());
            }
            Err(e) => {
                tracing::error!("PTY write error: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}
