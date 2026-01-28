//! Data models for the mobile client.
//!
//! These types are exposed to Swift/Kotlin via UniFFI and match
//! the dashboard API response shapes.

use serde::Deserialize;

/// A connected host (daemon).
#[derive(Debug, Clone, uniffi::Record)]
pub struct Host {
    /// Unique fingerprint identifier (e.g., "SHA256:abc123...")
    pub fingerprint: String,
    /// User-assigned label (e.g., "MacBook Pro")
    pub label: Option<String>,
    /// System hostname
    pub hostname: Option<String>,
    /// Current connection status
    pub status: HostStatus,
    /// ISO 8601 timestamp of last activity
    pub last_seen_at: String,
}

/// Host connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HostStatus {
    /// Host is connected and responsive
    Online,
    /// Host is disconnected
    Offline,
}

/// Current user status with hosts and pending attention.
#[derive(Debug, Clone, uniffi::Record)]
pub struct UserStatus {
    /// User's display name
    pub user_name: String,
    /// User's avatar URL (from Auth0)
    pub avatar_url: Option<String>,
    /// List of enrolled hosts
    pub hosts: Vec<Host>,
    /// Pending attention requests
    pub pending_attention: Vec<AttentionSummary>,
}

/// Summary of an attention request (for list display).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AttentionSummary {
    /// Unique identifier
    pub id: String,
    /// Host label or fingerprint
    pub host_label: String,
    /// Task name if available
    pub task_name: Option<String>,
    /// Brief message
    pub message: String,
    /// ISO 8601 timestamp
    pub created_at: String,
    /// Whether this needs immediate attention
    pub urgent: bool,
}

/// Full attention request details (for detail screen).
#[derive(Debug, Clone, uniffi::Record)]
pub struct AttentionDetail {
    /// Unique identifier
    pub id: String,
    /// Associated task ID
    pub task_id: String,
    /// Host information
    pub host: Host,
    /// Task name if available
    pub task_name: Option<String>,
    /// Structured prompt for response
    pub prompt: AttentionPrompt,
    /// Recent terminal output for context (last N lines)
    pub output_context: Vec<String>,
    /// Current status
    pub status: AttentionStatus,
    /// ISO 8601 timestamp
    pub created_at: String,
}

/// Structured prompt types.
///
/// MVP includes Binary and TextInput. Others can be added when needed.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum AttentionPrompt {
    /// Yes/No, y/n, Continue? style prompts
    Binary {
        /// The question being asked
        message: String,
        /// Label for affirmative button (e.g., "Yes", "Continue")
        affirm_label: String,
        /// Value to send for affirmative (e.g., "y", "yes")
        affirm_value: String,
        /// Label for negative button (e.g., "No", "Cancel")
        deny_label: String,
        /// Value to send for negative (e.g., "n", "no")
        deny_value: String,
        /// Whether affirmative is the default (for UI hints)
        default_is_affirm: bool,
    },
    /// Free-form text input
    TextInput {
        /// The prompt message
        message: String,
        /// Placeholder text for input field
        placeholder: Option<String>,
        /// Default value to pre-fill
        default_value: Option<String>,
    },
    /// Fallback when prompt type is unknown or missing
    Unknown {
        /// Raw message to display
        message: String,
    },
}

/// Status of an attention request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AttentionStatus {
    /// Waiting for user response
    Pending,
    /// User has responded
    Resolved,
    /// Request timed out
    Expired,
}

// ============================================================================
// API Response Types (serde deserialization)
// These match the dashboard API response shapes exactly.
// ============================================================================

/// Response from GET /api/mobile/status
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusResponse {
    pub hosts: Vec<HostResponse>,
    pub pending_attention: Vec<AttentionSummaryResponse>,
}

/// Host in status response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostResponse {
    pub fingerprint: String,
    pub label: String,
    pub hostname: Option<String>,
    pub status: String,
    pub last_seen_at: String,
}

impl From<HostResponse> for Host {
    fn from(r: HostResponse) -> Self {
        Host {
            fingerprint: r.fingerprint,
            label: Some(r.label),
            hostname: r.hostname,
            status: if r.status == "online" {
                HostStatus::Online
            } else {
                HostStatus::Offline
            },
            last_seen_at: r.last_seen_at,
        }
    }
}

/// Attention summary in status response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttentionSummaryResponse {
    pub id: String,
    pub host_label: String,
    pub task_name: Option<String>,
    pub message: String,
    pub created_at: String,
    pub urgent: bool,
}

impl From<AttentionSummaryResponse> for AttentionSummary {
    fn from(r: AttentionSummaryResponse) -> Self {
        AttentionSummary {
            id: r.id,
            host_label: r.host_label,
            task_name: r.task_name,
            message: r.message,
            created_at: r.created_at,
            urgent: r.urgent,
        }
    }
}

/// Response from GET /api/mobile/attention/{id}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Some fields reserved for future use
pub(crate) struct AttentionDetailResponse {
    pub id: String,
    pub host_fingerprint: String,
    pub host_label: String,
    pub task_name: Option<String>,
    pub message: String,
    pub prompt: PromptResponse,
    pub output_context: Vec<String>,
    pub created_at: String,
    pub urgent: bool,
}

/// Prompt configuration in attention detail
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[allow(dead_code)] // Choice variant reserved for future use
pub(crate) enum PromptResponse {
    #[serde(rename = "binary")]
    Binary {
        #[serde(rename = "affirmLabel")]
        affirm_label: String,
        #[serde(rename = "affirmValue")]
        affirm_value: String,
        #[serde(rename = "denyLabel")]
        deny_label: String,
        #[serde(rename = "denyValue")]
        deny_value: String,
        #[serde(rename = "defaultIsAffirm")]
        default_is_affirm: bool,
    },
    #[serde(rename = "text")]
    Text {
        placeholder: Option<String>,
    },
    #[serde(rename = "choice")]
    Choice {
        options: Vec<ChoiceOption>,
    },
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Reserved for future choice prompt support
pub(crate) struct ChoiceOption {
    pub label: String,
    pub value: String,
}

impl From<PromptResponse> for AttentionPrompt {
    fn from(r: PromptResponse) -> Self {
        match r {
            PromptResponse::Binary {
                affirm_label,
                affirm_value,
                deny_label,
                deny_value,
                default_is_affirm,
            } => AttentionPrompt::Binary {
                message: String::new(), // Message is separate in our type
                affirm_label,
                affirm_value,
                deny_label,
                deny_value,
                default_is_affirm,
            },
            PromptResponse::Text { placeholder } => AttentionPrompt::TextInput {
                message: String::new(),
                placeholder,
                default_value: None,
            },
            PromptResponse::Choice { .. } => AttentionPrompt::Unknown {
                message: "Choice prompts not yet supported".to_string(),
            },
        }
    }
}
