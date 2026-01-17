//! Shared utility functions.

use chrono::{TimeZone, Utc};

/// Format a Unix timestamp (seconds) as a human-readable string.
pub fn format_timestamp_secs(secs: i64) -> String {
    Utc.timestamp_opt(secs, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

/// Format a Unix timestamp (milliseconds) as a human-readable string.
pub fn format_timestamp_millis(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}
