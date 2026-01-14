//! Task execution types and state machine.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::identity::DeviceId;

// ============================================================================
// Core Types
// ============================================================================

/// Unique identifier for a task.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(pub Uuid);

impl TaskId {
    pub fn new(id: impl Into<Uuid>) -> Self {
        Self(id.into())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

/// Lifecycle status of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task is queued but not yet started.
    Queued,
    /// Task is currently running.
    Running,
    /// Task completed successfully (exit code 0).
    Completed,
    /// Task failed (non-zero exit or failed to start).
    Failed,
    /// Task was canceled by user or system.
    Canceled,
}

impl TaskStatus {
    /// Returns true if the task is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }

    /// Returns true if the task is currently active (running).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running)
    }
}

/// How the task was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatedVia {
    /// Created via command-line interface.
    Cli,
    /// Created via mobile application.
    Mobile,
    /// Created via web interface.
    Web,
}

/// Output stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// Pseudo-terminal output (combined stdout/stderr with control codes).
    Pty,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

// ============================================================================
// Attention State (Derived/Overlay)
// ============================================================================

/// Attention state indicating whether a running task needs user attention.
///
/// This is an overlay on top of `TaskStatus::Running`, NOT a lifecycle state.
/// A task can be `Running` with `AttentionState::NeedsInput` — for UX purposes
/// this might display as "Waiting", but the underlying status remains `Running`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AttentionState {
    /// Task is running normally, no attention needed.
    None,
    /// Task is waiting for user input.
    NeedsInput {
        /// Confidence level (0.0 - 1.0) that input is needed.
        confidence: f64,
        /// Reasons why input appears to be needed.
        reasons: Vec<String>,
    },
    /// Task may be stuck or idle.
    PossiblyStuck {
        /// How long since last output.
        idle_seconds: u64,
    },
}

impl Default for AttentionState {
    fn default() -> Self {
        Self::None
    }
}

// ============================================================================
// Process Metrics
// ============================================================================

/// Sampled process metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProcessMetrics {
    /// CPU usage percentage (0.0 - 100.0+).
    pub cpu_percent: Option<f64>,
    /// Resident set size in bytes.
    pub rss_bytes: Option<u64>,
    /// When these metrics were sampled.
    pub sampled_at: Option<DateTime<Utc>>,
}

// ============================================================================
// Task Events
// ============================================================================

/// Unique identifier for an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(pub Uuid);

impl EventId {
    /// Create a new random event ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an event ID from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Who initiated an action (device or system).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Actor {
    Device { id: DeviceId },
    System,
}

impl Actor {
    pub fn device(id: DeviceId) -> Self {
        Self::Device { id }
    }

    pub fn system() -> Self {
        Self::System
    }
}

/// A task event with unique ID and timestamp.
///
/// Each event is uniquely identified and timestamped for audit and replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskEvent {
    /// Unique identifier for this event.
    pub id: EventId,
    /// When this event occurred.
    pub ts: DateTime<Utc>,
    /// The event payload.
    #[serde(flatten)]
    pub kind: TaskEventKind,
}

impl TaskEvent {
    /// Create a new event with auto-generated ID and current timestamp.
    pub fn new(kind: TaskEventKind) -> Self {
        Self {
            id: EventId::new(),
            ts: Utc::now(),
            kind,
        }
    }

    /// Create a new event with a specific timestamp.
    pub fn with_ts(kind: TaskEventKind, ts: DateTime<Utc>) -> Self {
        Self {
            id: EventId::new(),
            ts,
            kind,
        }
    }

    /// Returns true if this is a lifecycle event that changes TaskStatus.
    pub fn is_lifecycle(&self) -> bool {
        self.kind.is_lifecycle()
    }
}

/// The kind/payload of a task event.
///
/// Lifecycle events change `TaskStatus`. Interaction events update derived fields
/// but do NOT change the lifecycle status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskEventKind {
    // ── Lifecycle Events (change TaskStatus) ──────────────────────────────
    /// Task execution has started.
    /// Transition: Queued → Running
    Started {
        /// Process ID if available.
        pid: Option<u32>,
    },

    /// Task process exited.
    /// Transition: Running → Completed (if exit_code == 0) or Failed (otherwise)
    Exited { exit_code: i32 },

    /// Task was canceled.
    /// Transition: Queued|Running → Canceled
    Canceled { actor: Actor },

    /// Task failed to start (e.g., command not found, permission denied).
    /// Transition: Queued → Failed
    FailedToStart { reason: String },

    // ── Interaction Events (do NOT change TaskStatus) ─────────────────────
    /// Output was appended to a stream.
    OutputAppended {
        stream: Stream,
        /// Length in bytes (actual data stored elsewhere).
        data_len: usize,
    },

    /// Input was sent to the task.
    InputSent {
        /// Length in bytes.
        data_len: usize,
        sent_by: DeviceId,
    },

    /// Process metrics were sampled.
    MetricsSampled {
        cpu_percent: Option<f64>,
        rss_bytes: Option<u64>,
    },

    /// Attention state changed (detected by daemon heuristics).
    AttentionChanged { state: AttentionState },
}

impl TaskEventKind {
    /// Returns true if this is a lifecycle event that changes TaskStatus.
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self,
            Self::Started { .. }
                | Self::Exited { .. }
                | Self::Canceled { .. }
                | Self::FailedToStart { .. }
        )
    }
}

// ============================================================================
// Transition Errors
// ============================================================================

/// Error when a state transition is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTransition {
    pub from: TaskStatus,
    pub event: &'static str,
    pub reason: String,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid transition: cannot apply '{}' to task in state '{:?}': {}",
            self.event, self.from, self.reason
        )
    }
}

impl std::error::Error for InvalidTransition {}

// ============================================================================
// Task
// ============================================================================

/// A task representing a command to be executed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    // ── Identity ──────────────────────────────────────────────────────────
    /// Unique identifier for this task.
    pub id: TaskId,

    /// Human-readable name for the task.
    pub name: String,

    // ── Specification ─────────────────────────────────────────────────────
    /// Command to execute (program and arguments).
    pub cmd: Vec<String>,

    /// Working directory for command execution.
    pub cwd: PathBuf,

    /// Environment variables for the command.
    pub env: BTreeMap<String, String>,

    // ── Lifecycle ─────────────────────────────────────────────────────────
    /// Current lifecycle status.
    pub status: TaskStatus,

    /// When the task was created.
    pub created_at: DateTime<Utc>,

    /// When the task started executing.
    pub started_at: Option<DateTime<Utc>>,

    /// When the task finished (completed, failed, or canceled).
    pub ended_at: Option<DateTime<Utc>>,

    /// Process ID (if running or finished).
    pub pid: Option<u32>,

    /// Exit code (if exited).
    pub exit_code: Option<i32>,

    /// Failure reason (if FailedToStart).
    pub failure_reason: Option<String>,

    // ── Provenance ────────────────────────────────────────────────────────
    /// Device that created this task.
    pub created_by: DeviceId,

    /// How the task was created.
    pub created_via: CreatedVia,

    // ── Derived/Observability State ───────────────────────────────────────
    /// Last time output was received.
    pub last_output_at: Option<DateTime<Utc>>,

    /// Last time input was sent.
    pub last_input_at: Option<DateTime<Utc>>,

    /// Total output bytes received.
    pub output_bytes: u64,

    /// Total input bytes sent.
    pub input_bytes: u64,

    /// Current attention state (overlay on Running).
    pub attention: AttentionState,

    /// Latest process metrics.
    pub metrics: ProcessMetrics,
}

impl Task {
    /// Create a new task in Queued status.
    pub fn new(
        id: TaskId,
        name: String,
        cmd: Vec<String>,
        cwd: PathBuf,
        env: BTreeMap<String, String>,
        created_by: DeviceId,
        created_via: CreatedVia,
    ) -> Self {
        Self {
            id,
            name,
            cmd,
            cwd,
            env,
            status: TaskStatus::Queued,
            created_at: Utc::now(),
            started_at: None,
            ended_at: None,
            pid: None,
            exit_code: None,
            failure_reason: None,
            created_by,
            created_via,
            last_output_at: None,
            last_input_at: None,
            output_bytes: 0,
            input_bytes: 0,
            attention: AttentionState::None,
            metrics: ProcessMetrics::default(),
        }
    }

    /// Apply an event to this task, updating state accordingly.
    ///
    /// Returns `Ok(())` if the event was applied successfully, or an error
    /// if the transition is invalid for the current state.
    pub fn apply(&mut self, event: &TaskEvent) -> Result<(), InvalidTransition> {
        let ts = event.ts;

        match &event.kind {
            // ── Lifecycle Events ──────────────────────────────────────────
            TaskEventKind::Started { pid } => {
                if self.status != TaskStatus::Queued {
                    return Err(InvalidTransition {
                        from: self.status,
                        event: "Started",
                        reason: "task must be Queued to start".into(),
                    });
                }
                self.status = TaskStatus::Running;
                self.started_at = Some(ts);
                self.pid = *pid;
            }

            TaskEventKind::Exited { exit_code } => {
                if self.status != TaskStatus::Running {
                    return Err(InvalidTransition {
                        from: self.status,
                        event: "Exited",
                        reason: "task must be Running to exit".into(),
                    });
                }
                self.status = if *exit_code == 0 {
                    TaskStatus::Completed
                } else {
                    TaskStatus::Failed
                };
                self.ended_at = Some(ts);
                self.exit_code = Some(*exit_code);
                self.attention = AttentionState::None;
            }

            TaskEventKind::Canceled { .. } => {
                if self.status.is_terminal() {
                    return Err(InvalidTransition {
                        from: self.status,
                        event: "Canceled",
                        reason: "cannot cancel a task that has already ended".into(),
                    });
                }
                self.status = TaskStatus::Canceled;
                self.ended_at = Some(ts);
                self.attention = AttentionState::None;
            }

            TaskEventKind::FailedToStart { reason } => {
                if self.status != TaskStatus::Queued {
                    return Err(InvalidTransition {
                        from: self.status,
                        event: "FailedToStart",
                        reason: "task must be Queued to fail to start".into(),
                    });
                }
                self.status = TaskStatus::Failed;
                self.ended_at = Some(ts);
                self.failure_reason = Some(reason.clone());
            }

            // ── Interaction Events (no status change) ─────────────────────
            TaskEventKind::OutputAppended { data_len, .. } => {
                self.last_output_at = Some(ts);
                self.output_bytes = self.output_bytes.saturating_add(*data_len as u64);
            }

            TaskEventKind::InputSent { data_len, .. } => {
                self.last_input_at = Some(ts);
                self.input_bytes = self.input_bytes.saturating_add(*data_len as u64);
            }

            TaskEventKind::MetricsSampled {
                cpu_percent,
                rss_bytes,
            } => {
                self.metrics = ProcessMetrics {
                    cpu_percent: *cpu_percent,
                    rss_bytes: *rss_bytes,
                    sampled_at: Some(ts),
                };
            }

            TaskEventKind::AttentionChanged { state } => {
                self.attention = state.clone();
            }
        }

        Ok(())
    }

    /// Returns the effective display status, considering attention state.
    ///
    /// For UX purposes: if status is Running and attention is NeedsInput,
    /// this returns a "waiting" indicator.
    pub fn display_status(&self) -> &'static str {
        match (&self.status, &self.attention) {
            (TaskStatus::Running, AttentionState::NeedsInput { .. }) => "waiting",
            (TaskStatus::Queued, _) => "queued",
            (TaskStatus::Running, _) => "running",
            (TaskStatus::Completed, _) => "completed",
            (TaskStatus::Failed, _) => "failed",
            (TaskStatus::Canceled, _) => "canceled",
        }
    }

    /// Returns true if the task appears to need user input.
    pub fn needs_input(&self) -> bool {
        matches!(self.attention, AttentionState::NeedsInput { .. })
    }
}

// ============================================================================
// Output and Input Types
// ============================================================================

/// A chunk of output from a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputChunk {
    /// Task this output belongs to.
    pub task_id: TaskId,

    /// Which stream produced this output.
    pub stream: Stream,

    /// When this output was captured.
    pub ts: DateTime<Utc>,

    /// Raw output data (base64 encoded in JSON).
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub data: Vec<u8>,
}

/// Input sent to a running task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// Task to receive this input.
    pub task_id: TaskId,

    /// When this input was sent.
    pub ts: DateTime<Utc>,

    /// Raw input data (base64 encoded in JSON).
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub data: Vec<u8>,

    /// Device that sent this input.
    pub sent_by: DeviceId,
}

fn serialize_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task() -> Task {
        Task::new(
            TaskId::new(Uuid::new_v4()),
            "Test task".to_string(),
            vec!["echo".to_string(), "hello".to_string()],
            PathBuf::from("/tmp"),
            BTreeMap::new(),
            DeviceId::new("device-1"),
            CreatedVia::Cli,
        )
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Helper to create a TaskEvent with a specific kind and timestamp.
    fn event(kind: TaskEventKind, timestamp: DateTime<Utc>) -> TaskEvent {
        TaskEvent::with_ts(kind, timestamp)
    }

    // ── Lifecycle Transitions ─────────────────────────────────────────────

    #[test]
    fn queued_to_running() {
        let mut task = make_task();
        assert_eq!(task.status, TaskStatus::Queued);

        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Running);
        assert_eq!(task.pid, Some(1234));
        assert_eq!(task.started_at, Some(ts("2024-01-15T10:00:00Z")));
    }

    #[test]
    fn running_to_completed() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::Exited { exit_code: 0 },
            ts("2024-01-15T10:01:00Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.exit_code, Some(0));
        assert_eq!(task.ended_at, Some(ts("2024-01-15T10:01:00Z")));
    }

    #[test]
    fn running_to_failed() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::Exited { exit_code: 1 },
            ts("2024-01-15T10:01:00Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.exit_code, Some(1));
    }

    #[test]
    fn queued_to_canceled() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Canceled {
                actor: Actor::device(DeviceId::new("user-1")),
            },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Canceled);
        assert_eq!(task.ended_at, Some(ts("2024-01-15T10:00:00Z")));
    }

    #[test]
    fn running_to_canceled() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::Canceled {
                actor: Actor::system(),
            },
            ts("2024-01-15T10:00:30Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Canceled);
    }

    #[test]
    fn queued_to_failed_to_start() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::FailedToStart {
                reason: "command not found".to_string(),
            },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.failure_reason, Some("command not found".to_string()));
        assert_eq!(task.ended_at, Some(ts("2024-01-15T10:00:00Z")));
    }

    // ── Invalid Transitions ───────────────────────────────────────────────

    #[test]
    fn cannot_start_running_task() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        let result = task.apply(&event(
            TaskEventKind::Started { pid: Some(5678) },
            ts("2024-01-15T10:00:01Z"),
        ));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.from, TaskStatus::Running);
        assert_eq!(err.event, "Started");
    }

    #[test]
    fn cannot_exit_queued_task() {
        let mut task = make_task();
        let result = task.apply(&event(
            TaskEventKind::Exited { exit_code: 0 },
            ts("2024-01-15T10:00:00Z"),
        ));

        assert!(result.is_err());
    }

    #[test]
    fn cannot_cancel_completed_task() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();
        task.apply(&event(
            TaskEventKind::Exited { exit_code: 0 },
            ts("2024-01-15T10:01:00Z"),
        ))
        .unwrap();

        let result = task.apply(&event(
            TaskEventKind::Canceled {
                actor: Actor::system(),
            },
            ts("2024-01-15T10:02:00Z"),
        ));

        assert!(result.is_err());
    }

    // ── Interaction Events ────────────────────────────────────────────────

    #[test]
    fn output_appended_updates_counters() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::OutputAppended {
                stream: Stream::Stdout,
                data_len: 100,
            },
            ts("2024-01-15T10:00:01Z"),
        ))
        .unwrap();

        assert_eq!(task.output_bytes, 100);
        assert_eq!(task.last_output_at, Some(ts("2024-01-15T10:00:01Z")));

        task.apply(&event(
            TaskEventKind::OutputAppended {
                stream: Stream::Stderr,
                data_len: 50,
            },
            ts("2024-01-15T10:00:02Z"),
        ))
        .unwrap();

        assert_eq!(task.output_bytes, 150);
        assert_eq!(task.last_output_at, Some(ts("2024-01-15T10:00:02Z")));
    }

    #[test]
    fn input_sent_updates_counters() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::InputSent {
                data_len: 10,
                sent_by: DeviceId::new("device-2"),
            },
            ts("2024-01-15T10:00:05Z"),
        ))
        .unwrap();

        assert_eq!(task.input_bytes, 10);
        assert_eq!(task.last_input_at, Some(ts("2024-01-15T10:00:05Z")));
    }

    #[test]
    fn attention_changed_updates_state() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::AttentionChanged {
                state: AttentionState::NeedsInput {
                    confidence: 0.9,
                    reasons: vec!["password prompt detected".to_string()],
                },
            },
            ts("2024-01-15T10:00:10Z"),
        ))
        .unwrap();

        assert!(task.needs_input());
        assert_eq!(task.display_status(), "waiting");

        // Clear attention
        task.apply(&event(
            TaskEventKind::AttentionChanged {
                state: AttentionState::None,
            },
            ts("2024-01-15T10:00:15Z"),
        ))
        .unwrap();

        assert!(!task.needs_input());
        assert_eq!(task.display_status(), "running");
    }

    #[test]
    fn metrics_sampled_updates_state() {
        let mut task = make_task();
        task.apply(&event(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();

        task.apply(&event(
            TaskEventKind::MetricsSampled {
                cpu_percent: Some(25.5),
                rss_bytes: Some(1024 * 1024 * 100),
            },
            ts("2024-01-15T10:00:05Z"),
        ))
        .unwrap();

        assert_eq!(task.metrics.cpu_percent, Some(25.5));
        assert_eq!(task.metrics.rss_bytes, Some(104_857_600));
    }

    // ── Display Status ────────────────────────────────────────────────────

    #[test]
    fn display_status_reflects_attention() {
        let mut task = make_task();
        assert_eq!(task.display_status(), "queued");

        task.apply(&event(
            TaskEventKind::Started { pid: Some(1) },
            ts("2024-01-15T10:00:00Z"),
        ))
        .unwrap();
        assert_eq!(task.display_status(), "running");

        task.attention = AttentionState::NeedsInput {
            confidence: 0.8,
            reasons: vec![],
        };
        assert_eq!(task.display_status(), "waiting");
    }

    // ── Serialization ─────────────────────────────────────────────────────

    #[test]
    fn task_status_snake_case() {
        assert_eq!(
            serde_json::to_string(&TaskStatus::Queued).unwrap(),
            r#""queued""#
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Running).unwrap(),
            r#""running""#
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Completed).unwrap(),
            r#""completed""#
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Failed).unwrap(),
            r#""failed""#
        );
        assert_eq!(
            serde_json::to_string(&TaskStatus::Canceled).unwrap(),
            r#""canceled""#
        );
    }

    #[test]
    fn event_id_is_unique() {
        let id1 = EventId::new();
        let id2 = EventId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn task_event_has_unique_id_and_timestamp() {
        let e1 = TaskEvent::new(TaskEventKind::Started { pid: Some(1) });
        let e2 = TaskEvent::new(TaskEventKind::Started { pid: Some(1) });

        // Each event has a unique ID
        assert_ne!(e1.id, e2.id);
        // Both have timestamps
        assert!(e1.ts <= Utc::now());
        assert!(e2.ts <= Utc::now());
    }

    #[test]
    fn task_event_kind_roundtrip() {
        let kinds = vec![
            TaskEventKind::Started { pid: Some(1234) },
            TaskEventKind::Exited { exit_code: 0 },
            TaskEventKind::Canceled {
                actor: Actor::device(DeviceId::new("user-1")),
            },
            TaskEventKind::FailedToStart {
                reason: "not found".to_string(),
            },
            TaskEventKind::OutputAppended {
                stream: Stream::Stdout,
                data_len: 100,
            },
            TaskEventKind::InputSent {
                data_len: 10,
                sent_by: DeviceId::new("device-1"),
            },
        ];

        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: TaskEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn task_event_roundtrip() {
        let event = TaskEvent::with_ts(
            TaskEventKind::Started { pid: Some(1234) },
            ts("2024-01-15T10:00:00Z"),
        );

        let json = serde_json::to_string(&event).unwrap();
        let parsed: TaskEvent = serde_json::from_str(&json).unwrap();

        // ID and ts are preserved exactly
        assert_eq!(parsed.id, event.id);
        assert_eq!(parsed.ts, event.ts);
        assert_eq!(parsed.kind, event.kind);
    }

    #[test]
    fn attention_state_roundtrip() {
        let states = vec![
            AttentionState::None,
            AttentionState::NeedsInput {
                confidence: 0.95,
                reasons: vec!["prompt".to_string()],
            },
            AttentionState::PossiblyStuck { idle_seconds: 300 },
        ];

        for state in states {
            let json = serde_json::to_string(&state).unwrap();
            let parsed: AttentionState = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn task_id_roundtrip() {
        let id = TaskId::new(Uuid::new_v4());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_uuid()));
        let parsed: TaskId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn output_chunk_roundtrip() {
        let chunk = OutputChunk {
            task_id: TaskId::new(Uuid::new_v4()),
            stream: Stream::Stdout,
            ts: ts("2024-01-15T10:30:05Z"),
            data: b"Hello, world!\n".to_vec(),
        };

        let json = serde_json::to_string(&chunk).unwrap();
        let parsed: OutputChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, chunk);
    }

    #[test]
    fn input_roundtrip() {
        let input = Input {
            task_id: TaskId::new(Uuid::new_v4()),
            ts: ts("2024-01-15T10:31:00Z"),
            data: b"yes\n".to_vec(),
            sent_by: DeviceId::new("device-iphone"),
        };

        let json = serde_json::to_string(&input).unwrap();
        let parsed: Input = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, input);
    }
}
