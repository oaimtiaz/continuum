//! Type conversions between core types and protobuf types.
//!
//! Due to Rust's orphan rules, we can't implement From traits between
//! types from different crates. Instead, we provide conversion functions.

use continuum_core::task::{Stream as CoreStream, Task, TaskStatus as CoreStatus};
use continuum_proto::{
    OutputChunk as ProtoOutputChunk, Stream as ProtoStream, TaskStatus as ProtoStatus,
    TaskView,
};

use crate::store::OutputChunk;

/// Convert a Task to TaskView for gRPC responses.
pub fn task_to_view(task: &Task) -> TaskView {
    TaskView {
        id: task.id.0.to_string(),
        name: task.name.clone(),
        cmd: task.cmd.clone(),
        cwd: task.cwd.to_string_lossy().to_string(),
        status: status_to_proto(task.status).into(),
        created_at_ms: task.created_at.timestamp_millis(),
        started_at_ms: task.started_at.map(|t| t.timestamp_millis()),
        ended_at_ms: task.ended_at.map(|t| t.timestamp_millis()),
        exit_code: task.exit_code,
        failure_reason: task.failure_reason.clone(),
        needs_input: task.needs_input(),
    }
}

/// Convert core TaskStatus to proto TaskStatus.
pub fn status_to_proto(status: CoreStatus) -> ProtoStatus {
    match status {
        CoreStatus::Queued => ProtoStatus::Queued,
        CoreStatus::Running => ProtoStatus::Running,
        CoreStatus::Completed => ProtoStatus::Completed,
        CoreStatus::Failed => ProtoStatus::Failed,
        CoreStatus::Canceled => ProtoStatus::Canceled,
    }
}

/// Convert core Stream to proto Stream.
pub fn stream_to_proto(stream: CoreStream) -> ProtoStream {
    match stream {
        CoreStream::Pty => ProtoStream::Pty,
        CoreStream::Stdout => ProtoStream::Stdout,
        CoreStream::Stderr => ProtoStream::Stderr,
    }
}

/// Convert OutputChunk to proto OutputChunk.
pub fn output_chunk_to_proto(chunk: &OutputChunk) -> ProtoOutputChunk {
    ProtoOutputChunk {
        stream: stream_to_proto(chunk.stream).into(),
        data: chunk.data.clone(),
        timestamp_ms: chunk.timestamp_ms,
    }
}
