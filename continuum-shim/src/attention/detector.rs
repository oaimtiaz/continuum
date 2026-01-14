//! Attention state machine and detector.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use continuum_shim_proto::AttentionKind;

use super::patterns::PromptMatcher;
use super::strip_ansi::strip_ansi_bytes;

/// Attention detection configuration.
#[derive(Clone, Debug)]
pub struct AttentionConfig {
    /// Time after last output before emitting MaybeNeedsInput.
    pub maybe_after: Duration,
    /// Time after last output before emitting Stalled.
    pub stalled_after: Duration,
    /// Minimum interval between attention emissions.
    pub emit_min_interval: Duration,
    /// Maximum bytes to keep in rolling buffer.
    pub max_buffer_bytes: usize,
}

impl Default for AttentionConfig {
    fn default() -> Self {
        Self {
            maybe_after: Duration::from_millis(500),
            stalled_after: Duration::from_secs(5),
            emit_min_interval: Duration::from_secs(1),
            max_buffer_bytes: 4096,
        }
    }
}

/// An attention event to report to the daemon.
#[derive(Debug, Clone)]
pub struct AttentionEvent {
    pub kind: AttentionKind,
    pub context: Option<String>,
}

/// Attention detector state machine.
pub struct AttentionDetector {
    /// Rolling buffer of recent output.
    buffer: VecDeque<u8>,
    /// Timestamp of last output.
    last_output_at: Option<Instant>,
    /// Timestamp of last input sent.
    last_input_at: Option<Instant>,
    /// Timestamp of last attention emission.
    last_emit_at: Option<Instant>,
    /// Current attention state.
    current_state: Option<AttentionKind>,
    /// Configuration.
    config: AttentionConfig,
    /// Prompt pattern matcher.
    matcher: PromptMatcher,
}

impl AttentionDetector {
    /// Create a new attention detector.
    pub fn new(config: AttentionConfig) -> Self {
        Self {
            buffer: VecDeque::with_capacity(config.max_buffer_bytes),
            last_output_at: None,
            last_input_at: None,
            last_emit_at: None,
            current_state: None,
            config,
            matcher: PromptMatcher::new(),
        }
    }

    /// Process new output from the PTY.
    pub fn on_output(&mut self, data: &[u8], ts: Instant) {
        self.last_output_at = Some(ts);

        // Add to rolling buffer, evicting old data if needed
        for &byte in data {
            if self.buffer.len() >= self.config.max_buffer_bytes {
                self.buffer.pop_front();
            }
            self.buffer.push_back(byte);
        }

        // Check for immediate prompt detection
        let text = strip_ansi_bytes(data);

        if let Some(_context) = self.matcher.match_high_confidence(&text) {
            self.current_state = Some(AttentionKind::NeedsInput);
            // Will emit on next tick if interval allows
        }
    }

    /// Notify that input was sent to the PTY.
    pub fn on_input_sent(&mut self, ts: Instant) {
        self.last_input_at = Some(ts);
        // Clear any pending attention state
        self.current_state = None;
        self.buffer.clear();
    }

    /// Tick the detector and potentially emit an attention event.
    pub fn tick(&mut self, now: Instant) -> Option<AttentionEvent> {
        // Check emit interval
        if let Some(last_emit) = self.last_emit_at {
            if now.duration_since(last_emit) < self.config.emit_min_interval {
                return None;
            }
        }

        // If we have a pending state, emit it
        if let Some(kind) = self.current_state.take() {
            self.last_emit_at = Some(now);
            let context = self.get_buffer_context();
            return Some(AttentionEvent { kind, context });
        }

        // Check for time-based conditions
        let last_output = self.last_output_at?;

        // Don't trigger if we recently sent input
        if let Some(last_input) = self.last_input_at {
            if last_input > last_output {
                return None;
            }
        }

        let elapsed = now.duration_since(last_output);

        if elapsed >= self.config.stalled_after {
            self.last_emit_at = Some(now);
            return Some(AttentionEvent {
                kind: AttentionKind::Stalled,
                context: self.get_buffer_context(),
            });
        }

        if elapsed >= self.config.maybe_after {
            // Check for low-confidence prompts
            let text = self.get_buffer_text();
            if let Some(context) = self.matcher.match_low_confidence(&text) {
                self.last_emit_at = Some(now);
                return Some(AttentionEvent {
                    kind: AttentionKind::MaybeNeedsInput,
                    context: Some(context),
                });
            }
        }

        None
    }

    /// Get the last N characters from the buffer as context.
    fn get_buffer_context(&self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let text = self.get_buffer_text();
        // Return last 100 chars
        let start = text.len().saturating_sub(100);
        Some(text[start..].to_string())
    }

    /// Get the buffer as text (ANSI-stripped).
    fn get_buffer_text(&self) -> String {
        let bytes: Vec<u8> = self.buffer.iter().copied().collect();
        strip_ansi_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_prompt_detection() {
        let config = AttentionConfig::default();
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"Password: ", now);

        // Should detect on next tick
        let event = detector.tick(now + Duration::from_millis(10));
        assert!(event.is_some());
        assert_eq!(event.unwrap().kind, AttentionKind::NeedsInput);
    }

    #[test]
    fn test_stall_detection() {
        let config = AttentionConfig {
            stalled_after: Duration::from_millis(100),
            ..Default::default()
        };
        let mut detector = AttentionDetector::new(config);

        let start = Instant::now();
        detector.on_output(b"working...", start);

        // Not enough time passed
        assert!(detector.tick(start + Duration::from_millis(50)).is_none());

        // Enough time passed
        let event = detector.tick(start + Duration::from_millis(150));
        assert!(event.is_some());
        assert_eq!(event.unwrap().kind, AttentionKind::Stalled);
    }

    #[test]
    fn test_input_clears_state() {
        let config = AttentionConfig::default();
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"Password: ", now);
        detector.on_input_sent(now + Duration::from_millis(5));

        // Should not emit after input
        assert!(detector.tick(now + Duration::from_secs(10)).is_none());
    }

    #[test]
    fn test_emit_interval_enforcement() {
        let config = AttentionConfig {
            emit_min_interval: Duration::from_secs(2),
            stalled_after: Duration::from_millis(100),
            ..Default::default()
        };
        let mut detector = AttentionDetector::new(config);

        let start = Instant::now();
        detector.on_output(b"working...", start);

        // First tick should emit stalled
        let event = detector.tick(start + Duration::from_millis(150));
        assert!(event.is_some());
        assert_eq!(event.unwrap().kind, AttentionKind::Stalled);

        // New output
        detector.on_output(b"still working...", start + Duration::from_millis(200));

        // Second tick too soon after first emit - should not emit
        assert!(detector.tick(start + Duration::from_millis(500)).is_none());

        // After emit interval, should emit again
        let event = detector.tick(start + Duration::from_secs(3));
        assert!(event.is_some());
    }

    #[test]
    fn test_buffer_overflow_handling() {
        let config = AttentionConfig {
            max_buffer_bytes: 100,
            ..Default::default()
        };
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();

        // Add more than max_buffer_bytes
        detector.on_output(&[b'x'; 150], now);

        // Buffer should be capped at max size
        // We can verify by checking the context length is reasonable
        let context = detector.get_buffer_context();
        assert!(context.is_some());
        // Context should be at most 100 chars (buffer size)
        assert!(context.unwrap().len() <= 100);
    }

    #[test]
    fn test_yes_no_prompt_detection() {
        let config = AttentionConfig::default();
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"Continue? [y/n]: ", now);

        let event = detector.tick(now + Duration::from_millis(10));
        assert!(event.is_some());
        assert_eq!(event.unwrap().kind, AttentionKind::NeedsInput);
    }

    #[test]
    fn test_sudo_prompt_detection() {
        let config = AttentionConfig::default();
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"[sudo] password for user: ", now);

        let event = detector.tick(now + Duration::from_millis(10));
        assert!(event.is_some());
        assert_eq!(event.unwrap().kind, AttentionKind::NeedsInput);
    }

    #[test]
    fn test_no_false_positive_on_normal_output() {
        let config = AttentionConfig {
            maybe_after: Duration::from_millis(100),
            ..Default::default()
        };
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"Compiling project...\nBuilding module 1\n", now);

        // Immediate tick should not emit
        assert!(detector.tick(now + Duration::from_millis(10)).is_none());

        // Even after maybe_after, normal output shouldn't trigger low-confidence
        // because it doesn't match prompt patterns
        let event = detector.tick(now + Duration::from_millis(150));
        assert!(event.is_none());
    }

    #[test]
    fn test_context_extraction() {
        let config = AttentionConfig::default();
        let mut detector = AttentionDetector::new(config);

        let now = Instant::now();
        detector.on_output(b"Enter your password: ", now);

        let event = detector.tick(now + Duration::from_millis(10));
        assert!(event.is_some());

        let event = event.unwrap();
        assert!(event.context.is_some());
        let context = event.context.unwrap();
        assert!(context.contains("password"));
    }
}
