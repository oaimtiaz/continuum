//! Identity and authorization types for device management.

use serde::{Deserialize, Serialize};

/// Unique identifier for a device in the Continuum network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Human-readable display name for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceDisplayName(pub String);

impl DeviceDisplayName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Role determining a device's permissions in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    /// Can only observe tasks and output (read-only).
    Viewer,
    /// Can interact with running tasks (send input).
    Interactor,
    /// Full control: create tasks, manage devices.
    #[serde(rename = "admin")]
    Admin,
}

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthzDecision {
    /// Action is permitted.
    Allow,
    /// Action is denied with explanation.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
    },
}

impl AuthzDecision {
    /// Create an Allow decision.
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Create a Deny decision with the given reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    /// Returns true if this is an Allow decision.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub display_name: DeviceDisplayName,
    pub role: DeviceRole,
}

impl Device {
    pub fn new(id: DeviceId, display_name: DeviceDisplayName, role: DeviceRole) -> Self {
        Self {
            id,
            display_name,
            role,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_roundtrip() {
        let id = DeviceId::new("device-123");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#""device-123""#);
        let parsed: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn device_display_name_roundtrip() {
        let name = DeviceDisplayName::new("My MacBook Pro");
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, r#""My MacBook Pro""#);
        let parsed: DeviceDisplayName = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, name);
    }

    #[test]
    fn device_role_snake_case() {
        assert_eq!(
            serde_json::to_string(&DeviceRole::Viewer).unwrap(),
            r#""viewer""#
        );
        assert_eq!(
            serde_json::to_string(&DeviceRole::Interactor).unwrap(),
            r#""interactor""#
        );
        assert_eq!(
            serde_json::to_string(&DeviceRole::Admin).unwrap(),
            r#""admin""#
        );
    }

    #[test]
    fn device_role_roundtrip() {
        for role in [
            DeviceRole::Viewer,
            DeviceRole::Interactor,
            DeviceRole::Admin,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let parsed: DeviceRole = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn authz_decision_allow_roundtrip() {
        let decision = AuthzDecision::allow();
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(json, r#"{"decision":"allow"}"#);
        let parsed: AuthzDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn authz_decision_deny_roundtrip() {
        let decision = AuthzDecision::deny("insufficient permissions");
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(
            json,
            r#"{"decision":"deny","reason":"insufficient permissions"}"#
        );
        let parsed: AuthzDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }
}
