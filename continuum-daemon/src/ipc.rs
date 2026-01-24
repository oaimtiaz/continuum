//! IPC handler for shim connections.
//!
//! Each task gets a Unix socket connection from its shim process.
//! This module handles framing, message routing, and bidirectional communication.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use continuum_core::task::{AttentionState, Stream, TaskEvent, TaskEventKind, TaskId};
use continuum_shim_proto::{shim_to_daemon, AttentionKind, DaemonToShim, ShimToDaemon};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::store::{OutputChunk, TaskStore};

/// Maximum frame size (16 MB).
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Read a length-delimited frame from an async reader.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Bytes> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes", len),
        ));
    }

    let mut buf = BytesMut::with_capacity(len);
    buf.resize(len, 0);
    reader.read_exact(&mut buf).await?;

    Ok(buf.freeze())
}

/// Write a length-delimited frame to an async writer.
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame too large: {} bytes", data.len()),
        ));
    }

    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;

    Ok(())
}

/// Handle a shim connection for a task.
///
/// This spawns two tasks:
/// - Read loop: receives ShimToDaemon messages and updates the store
/// - Write loop: sends DaemonToShim messages from the channel
pub async fn handle_shim_connection(task_id: TaskId, stream: UnixStream, store: Arc<TaskStore>) {
    let (mut read_half, mut write_half) = stream.into_split();

    // Create channel for daemon -> shim messages
    let (tx, mut rx) = mpsc::channel::<DaemonToShim>(32);

    // Register the sender with the store
    store.set_shim_sender(&task_id, tx).await;

    let task_id_read = task_id.clone();
    let store_read = store.clone();

    // Read loop: ShimToDaemon -> TaskStore
    let read_handle = tokio::spawn(async move {
        loop {
            match read_frame(&mut read_half).await {
                Ok(frame) => match ShimToDaemon::decode(frame) {
                    Ok(msg) => {
                        if let Err(e) = process_shim_message(&task_id_read, msg, &store_read).await
                        {
                            tracing::error!(task = %task_id_read.0, error = %e, "Failed to process shim message");
                        }
                    }
                    Err(e) => {
                        tracing::error!(task = %task_id_read.0, error = %e, "Failed to decode shim message");
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::debug!(task = %task_id_read.0, "Shim connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!(task = %task_id_read.0, error = %e, "Error reading from shim");
                    break;
                }
            }
        }
    });

    // Write loop: channel -> DaemonToShim
    let task_id_write = task_id.clone();
    let write_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            tracing::debug!(task = %task_id_write.0, "Writing message to shim");
            let encoded = msg.encode_to_vec();
            if let Err(e) = write_frame(&mut write_half, &encoded).await {
                // Broken pipe is expected during shutdown (shim may have exited)
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    tracing::debug!(task = %task_id_write.0, "Shim connection closed");
                } else {
                    tracing::error!(task = %task_id_write.0, error = %e, "Error writing to shim");
                }
                break;
            }
            tracing::debug!(task = %task_id_write.0, bytes = encoded.len(), "Wrote to shim");
        }
        tracing::debug!(task = %task_id_write.0, "Write loop ended");
    });

    // Wait for both tasks to complete
    let _ = tokio::join!(read_handle, write_handle);

    // Clear the shim sender since connection is closed
    store.clear_shim_sender(&task_id).await;
    tracing::info!(task = %task_id.0, "Shim connection handler finished");
}

/// Process a message from the shim and update the store accordingly.
async fn process_shim_message(
    task_id: &TaskId,
    msg: ShimToDaemon,
    store: &TaskStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match msg.msg {
        Some(shim_to_daemon::Msg::Started(started)) => {
            tracing::info!(
                task = %task_id.0,
                pid = started.pid,
                pgid = started.pgid,
                "Task started"
            );

            let event = TaskEvent::new(TaskEventKind::Started {
                pid: Some(started.pid as u32),
            });
            store.apply_event(task_id, event).await?;
        }

        Some(shim_to_daemon::Msg::Output(output)) => {
            tracing::trace!(
                task = %task_id.0,
                bytes = output.data.len(),
                "Output received"
            );

            let chunk = OutputChunk {
                stream: Stream::Pty,
                data: output.data,
                timestamp_ms: output.timestamp_ms,
            };
            store.append_output(task_id, chunk).await;
        }

        Some(shim_to_daemon::Msg::Attention(attention)) => {
            let kind =
                AttentionKind::try_from(attention.kind).unwrap_or(AttentionKind::Unspecified);

            tracing::info!(
                task = %task_id.0,
                kind = ?kind,
                context = ?attention.context,
                "Attention signal"
            );

            // Convert optional context to Vec for AttentionState
            let reasons: Vec<String> = attention.context.clone().into_iter().collect();

            // Map shim attention kinds to core AttentionState
            let (state, should_notify, urgent) = match kind {
                AttentionKind::Unspecified => (AttentionState::None, false, false),
                AttentionKind::MaybeNeedsInput => (
                    AttentionState::NeedsInput {
                        confidence: 0.5,
                        reasons: reasons.clone(),
                    },
                    false, // Low confidence, don't spam notifications
                    false,
                ),
                AttentionKind::NeedsInput => (
                    AttentionState::NeedsInput {
                        confidence: 0.9,
                        reasons: reasons.clone(),
                    },
                    true, // High confidence, notify
                    false,
                ),
                AttentionKind::Stalled => (
                    AttentionState::PossiblyStuck {
                        idle_seconds: 30, // Placeholder, shim could provide this
                    },
                    true,
                    false,
                ),
                AttentionKind::Error => (
                    AttentionState::NeedsInput {
                        confidence: 1.0,
                        reasons: vec!["Error detected".to_string()],
                    },
                    true,
                    true, // Errors are urgent
                ),
            };

            let event = TaskEvent::new(TaskEventKind::AttentionChanged { state });
            store.apply_event(task_id, event).await?;

            // Forward to relay for push notification (if connected and warranted)
            if should_notify {
                if let Some(relay_handle) = store.relay_handle().await {
                    let message = attention.context.clone().unwrap_or_else(|| {
                        format!("Task {} needs attention", task_id.0)
                    });

                    // Use task_id as session_id for attention tracking
                    if let Err(e) = relay_handle
                        .request_attention(&task_id.0.to_string(), &message, urgent)
                        .await
                    {
                        tracing::warn!(
                            task = %task_id.0,
                            error = %e,
                            "Failed to send attention request to relay"
                        );
                    } else {
                        tracing::debug!(
                            task = %task_id.0,
                            urgent = urgent,
                            "Forwarded attention to relay"
                        );
                    }
                }
            }
        }

        Some(shim_to_daemon::Msg::Exited(exited)) => {
            // Core Exited event only takes exit_code: i32
            // For signals, we use Unix convention: 128 + signal number
            let exit_code = match exited.status {
                Some(continuum_shim_proto::exited::Status::Code(code)) => {
                    tracing::info!(task = %task_id.0, exit_code = code, "Task exited");
                    code
                }
                Some(continuum_shim_proto::exited::Status::Signal(sig)) => {
                    tracing::info!(task = %task_id.0, signal = sig, "Task killed by signal");
                    128 + sig // Unix convention for signal exits
                }
                None => {
                    tracing::warn!(task = %task_id.0, "Task exited with unknown status");
                    -1 // Unknown exit
                }
            };

            let event = TaskEvent::new(TaskEventKind::Exited { exit_code });
            store.apply_event(task_id, event).await?;
        }

        None => {
            tracing::warn!(task = %task_id.0, "Received empty message from shim");
        }
    }

    Ok(())
}
