//! Audit logging types for security and compliance.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::DeviceId;
use crate::task::TaskId;

/// Action being audited.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Task lifecycle
    /// Task was created.
    TaskCreated,
    /// Task execution started.
    TaskStarted,
    /// Task completed (success or failure).
    TaskCompleted,
    /// Task was canceled.
    TaskCanceled,

    // Task interaction
    /// Input was sent to a task.
    InputSent,
    /// Output was received from a task.
    OutputReceived,

    // Device management
    /// Device connected to the network.
    DeviceConnected,
    /// Device disconnected from the network.
    DeviceDisconnected,
    /// Device was registered/paired.
    DeviceRegistered,
    /// Device was removed/unpaired.
    DeviceRemoved,
    /// Device role was changed.
    DeviceRoleChanged,

    // Authorization
    /// Authorization check was performed.
    AuthzChecked,
    /// Authorization was denied.
    AuthzDenied,
}

/// Target of an audit action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "id")]
pub enum AuditTarget {
    /// Action targeted a task.
    Task(TaskId),
    /// Action targeted a device.
    Device(DeviceId),
}

/// An audit event recording an action in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub ts: DateTime<Utc>,

    /// Device that performed the action (None for system-initiated).
    pub actor: Option<DeviceId>,

    /// What action was performed.
    pub action: AuditAction,

    /// What the action targeted.
    pub target: AuditTarget,

    /// Additional contextual information.
    /// Using BTreeMap for deterministic serialization order.
    pub metadata: BTreeMap<String, String>,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    pub fn new(actor: Option<DeviceId>, action: AuditAction, target: AuditTarget) -> Self {
        Self {
            ts: Utc::now(),
            actor,
            action,
            target,
            metadata: BTreeMap::new(),
        }
    }

    /// Create a new audit event with specific timestamp.
    pub fn with_timestamp(
        ts: DateTime<Utc>,
        actor: Option<DeviceId>,
        action: AuditAction,
        target: AuditTarget,
    ) -> Self {
        Self {
            ts,
            actor,
            action,
            target,
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata to the event (builder pattern).
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn audit_action_snake_case() {
        assert_eq!(
            serde_json::to_string(&AuditAction::TaskCreated).unwrap(),
            r#""task_created""#
        );
        assert_eq!(
            serde_json::to_string(&AuditAction::DeviceConnected).unwrap(),
            r#""device_connected""#
        );
        assert_eq!(
            serde_json::to_string(&AuditAction::AuthzDenied).unwrap(),
            r#""authz_denied""#
        );
    }

    #[test]
    fn audit_action_roundtrip() {
        let actions = [
            AuditAction::TaskCreated,
            AuditAction::TaskStarted,
            AuditAction::TaskCompleted,
            AuditAction::TaskCanceled,
            AuditAction::InputSent,
            AuditAction::OutputReceived,
            AuditAction::DeviceConnected,
            AuditAction::DeviceDisconnected,
            AuditAction::DeviceRegistered,
            AuditAction::DeviceRemoved,
            AuditAction::DeviceRoleChanged,
            AuditAction::AuthzChecked,
            AuditAction::AuthzDenied,
        ];

        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: AuditAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }

    #[test]
    fn audit_target_task_roundtrip() {
        let target = AuditTarget::Task(TaskId::new(Uuid::new_v4()));
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(json, r#"{"type":"task","id":"task-123"}"#);
        let parsed: AuditTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn audit_target_device_roundtrip() {
        let target = AuditTarget::Device(DeviceId::new("device-456"));
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(json, r#"{"type":"device","id":"device-456"}"#);
        let parsed: AuditTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, target);
    }

    #[test]
    fn audit_event_roundtrip() {
        let event = AuditEvent::with_timestamp(
            DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            Some(DeviceId::new("device-macbook")),
            AuditAction::TaskCreated,
            AuditTarget::Task(TaskId::new(Uuid::new_v4())),
        )
        .with_metadata("reason", "user request")
        .with_metadata("priority", "high");

        let json = serde_json::to_string_pretty(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);

        // Verify metadata ordering is deterministic (BTreeMap: priority < reason)
        let json_lines: Vec<&str> = json.lines().collect();
        let priority_pos = json_lines.iter().position(|l| l.contains("priority"));
        let reason_pos = json_lines.iter().position(|l| l.contains("reason"));
        assert!(
            priority_pos < reason_pos,
            "BTreeMap should order alphabetically"
        );
    }

    #[test]
    fn audit_event_system_actor() {
        let event = AuditEvent::with_timestamp(
            DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None, // System-initiated
            AuditAction::TaskCompleted,
            AuditTarget::Task(TaskId::new(Uuid::new_v4())),
        );

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""actor":null"#));
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.actor, None);
    }
}
