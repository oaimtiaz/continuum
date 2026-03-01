//! Main orchestration loop.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use continuum_pty::{ExitStatus, Signal};
use continuum_shim_proto::daemon_to_shim;
use tokio::sync::mpsc;

use crate::args::Args;
use crate::child::Child;
use crate::io::pty_reader::{run_pty_reader, PtyOutput};
use crate::io::pty_writer::run_pty_writer;
use crate::ipc::{unix, IpcClient};

#[cfg(feature = "attention")]
use std::time::Instant;

#[cfg(feature = "attention")]
use crate::attention::{AttentionConfig, AttentionDetector};

/// Get current timestamp in milliseconds since epoch.
fn timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Run the shim.
///
/// Returns the exit code to use.
pub async fn run(args: Args) -> Result<i32> {
    // Connect to daemon
    let stream = unix::connect(&args.connect)
        .await
        .context("failed to connect to daemon")?;

    let client = Arc::new(IpcClient::new(stream));

    // Spawn child process
    let child = Child::spawn(&args).context("failed to spawn child")?;
    let pid = child.pid().as_raw();
    let pgid = child.pgid().as_raw();
    let master_fd = child.master_fd();

    // Send Started message
    client.send_started(pid, pgid).await?;

    // Create channels
    let (output_tx, mut output_rx) = mpsc::channel::<PtyOutput>(256);
    // attention_rx is only consumed when the attention feature is enabled;
    // the PTY reader still sends on attention_tx unconditionally (try_send, fire-and-forget).
    #[allow(unused_variables, unused_mut)]
    let (attention_tx, mut attention_rx) = mpsc::channel::<(Vec<u8>, std::time::Instant)>(256);
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    #[allow(unused_variables, unused_mut)]
    let (input_notify_tx, mut input_notify_rx) = mpsc::channel::<std::time::Instant>(64);

    // Spawn PTY reader task
    let reader_handle =
        tokio::spawn(async move { run_pty_reader(master_fd, output_tx, attention_tx).await });

    // Spawn PTY writer task
    let writer_handle =
        tokio::spawn(async move { run_pty_writer(master_fd, stdin_rx, input_notify_tx).await });

    // IPC message sending task
    let client_send = client.clone();
    let send_handle = tokio::spawn(async move {
        while let Some(output) = output_rx.recv().await {
            let ts = timestamp_ms();
            if let Err(e) = client_send.send_output(ts, output.data).await {
                tracing::error!("failed to send output: {}", e);
                break;
            }
        }
    });

    // IPC receive task
    let client_recv = client.clone();
    let stdin_tx_clone = stdin_tx.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            match client_recv.recv().await {
                Ok(Some(msg)) => {
                    if let Some(inner) = msg.msg {
                        match inner {
                            daemon_to_shim::Msg::Stdin(stdin) => {
                                if let Err(e) = stdin_tx_clone.send(stdin.data).await {
                                    tracing::error!("failed to queue stdin: {}", e);
                                }
                            }
                            daemon_to_shim::Msg::Signal(sig) => {
                                let signal = match sig.signum {
                                    2 => Signal::Int,
                                    15 => Signal::Term,
                                    9 => Signal::Kill,
                                    1 => Signal::Hup,
                                    _ => Signal::Custom(sig.signum),
                                };
                                if let Err(e) =
                                    continuum_pty::signal_pid(continuum_pty::Pid::new(pid), signal)
                                {
                                    tracing::error!("failed to send signal: {}", e);
                                }
                            }
                            daemon_to_shim::Msg::Resize(resize) => {
                                let rows = resize.rows as u16;
                                let cols = resize.cols as u16;
                                if rows > 0 && cols > 0 {
                                    let ws = libc::winsize {
                                        ws_row: rows,
                                        ws_col: cols,
                                        ws_xpixel: 0,
                                        ws_ypixel: 0,
                                    };
                                    let ret = unsafe {
                                        libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws)
                                    };
                                    if ret != 0 {
                                        tracing::warn!("resize ioctl failed: {}", std::io::Error::last_os_error());
                                    }
                                    unsafe { libc::kill(-pgid, libc::SIGWINCH); }
                                }
                            }
                            daemon_to_shim::Msg::Shutdown(_) => {
                                tracing::info!("shutdown requested by daemon");
                                break;
                            }
                            daemon_to_shim::Msg::AttentionResponse(resp) => {
                                tracing::debug!(
                                    attention_id = %resp.attention_id,
                                    "forwarding attention response to stdin"
                                );
                                if let Err(e) = stdin_tx_clone.send(resp.payload).await {
                                    tracing::warn!("failed to forward attention response to stdin: {e}");
                                }
                            }
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!("IPC connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("IPC receive error: {}", e);
                    break;
                }
            }
        }
    });

    // Main loop: wait for child exit
    #[cfg(feature = "attention")]
    let exit_status = {
        let mut detector = AttentionDetector::new(AttentionConfig::default());
        let mut attention_ticker = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = attention_ticker.tick() => {
                    while let Ok((data, ts)) = attention_rx.try_recv() {
                        detector.on_output(&data, ts);
                    }
                    while let Ok(ts) = input_notify_rx.try_recv() {
                        detector.on_input_sent(ts);
                    }
                    if let Some(event) = detector.tick(Instant::now()) {
                        let ts = timestamp_ms();
                        if let Err(e) = client.send_attention(event.kind, ts, event.context).await {
                            tracing::error!("failed to send attention: {}", e);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    match child.try_wait() {
                        Ok(Some(status)) => break status,
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::error!("waitpid error: {}", e);
                            break ExitStatus::Code(1);
                        }
                    }
                }
            }
        }
    };

    #[cfg(not(feature = "attention"))]
    let exit_status = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!("waitpid error: {}", e);
                break ExitStatus::Code(1);
            }
        }
    };

    // Send Exited message
    match exit_status {
        ExitStatus::Code(code) => {
            tracing::info!(code, "child exited with code");
            client.send_exited_code(code).await?;
        }
        ExitStatus::Signaled(sig) => {
            tracing::info!(signal = sig, "child killed by signal");
            client.send_exited_signal(sig).await?;
        }
    }

    // Clean up tasks
    recv_handle.abort();
    send_handle.abort();
    reader_handle.abort();
    writer_handle.abort();

    // Return exit code
    Ok(match exit_status {
        ExitStatus::Code(code) => code,
        ExitStatus::Signaled(sig) => 128 + sig,
    })
}
