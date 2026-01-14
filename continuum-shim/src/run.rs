//! Main orchestration loop.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use continuum_pty::{ExitStatus, Signal};
use continuum_shim_proto::daemon_to_shim;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::args::Args;
use crate::attention::{AttentionConfig, AttentionDetector};
use crate::child::Child;
use crate::io::pty_reader::{run_pty_reader, PtyOutput};
use crate::io::pty_writer::run_pty_writer;
use crate::ipc::{unix, IpcClient};

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
    let (attention_tx, mut attention_rx) = mpsc::channel::<(Vec<u8>, Instant)>(256);
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    let (input_notify_tx, mut input_notify_rx) = mpsc::channel::<Instant>(64);

    // Spawn PTY reader task
    let reader_handle =
        tokio::spawn(async move { run_pty_reader(master_fd, output_tx, attention_tx).await });

    // Spawn PTY writer task
    let writer_handle =
        tokio::spawn(async move { run_pty_writer(master_fd, stdin_rx, input_notify_tx).await });

    // Attention detector
    let mut detector = AttentionDetector::new(AttentionConfig::default());
    let mut attention_ticker = interval(Duration::from_millis(100));

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
                                tracing::debug!(
                                    "resize requested: {}x{}",
                                    resize.rows,
                                    resize.cols
                                );
                            }
                            daemon_to_shim::Msg::Shutdown(_) => {
                                tracing::info!("shutdown requested by daemon");
                                break;
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

    // Main loop: wait for child exit while processing attention
    let exit_status = loop {
        tokio::select! {
            // Check attention detector
            _ = attention_ticker.tick() => {
                // Process any pending attention data
                while let Ok((data, ts)) = attention_rx.try_recv() {
                    detector.on_output(&data, ts);
                }

                // Process input notifications
                while let Ok(ts) = input_notify_rx.try_recv() {
                    detector.on_input_sent(ts);
                }

                // Check for attention events
                if let Some(event) = detector.tick(Instant::now()) {
                    let ts = timestamp_ms();
                    if let Err(e) = client.send_attention(event.kind, ts, event.context).await {
                        tracing::error!("failed to send attention: {}", e);
                    }
                }
            }

            // Check for child exit (non-blocking)
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
