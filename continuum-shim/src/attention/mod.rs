//! Attention detection for prompts and stalls.

pub mod detector;
pub mod patterns;
pub mod strip_ansi;

pub use detector::{AttentionConfig, AttentionDetector};
