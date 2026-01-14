//! Prompt pattern matching.

use regex::Regex;

/// Pattern matchers for detecting prompts that need input.
pub struct PromptMatcher {
    /// High confidence patterns (passwords, y/n prompts).
    high_confidence: Vec<Regex>,
    /// Low confidence patterns (shell prompts, trailing colons).
    low_confidence: Vec<Regex>,
}

impl PromptMatcher {
    /// Create a new prompt matcher with default patterns.
    pub fn new() -> Self {
        Self {
            high_confidence: vec![
                // Password prompts
                Regex::new(r"(?i)password\s*:").unwrap(),
                Regex::new(r"(?i)passphrase\s*:").unwrap(),
                Regex::new(r"(?i)enter passphrase").unwrap(),
                // Yes/no prompts
                Regex::new(r"\[y/n\]").unwrap(),
                Regex::new(r"\[Y/n\]").unwrap(),
                Regex::new(r"\[yes/no\]").unwrap(),
                Regex::new(r"\(yes/no\)").unwrap(),
                // Sudo prompt
                Regex::new(r"(?i)\[sudo\]").unwrap(),
                // SSH key confirmation
                Regex::new(r"Are you sure you want to continue").unwrap(),
            ],
            low_confidence: vec![
                // Shell prompts at end of line
                Regex::new(r"[$#>]\s*$").unwrap(),
                // Generic trailing colon (often a prompt)
                Regex::new(r":\s*$").unwrap(),
                // "Press any key" style prompts
                Regex::new(r"(?i)press (any key|enter|return)").unwrap(),
                // Confirmation prompts
                Regex::new(r"(?i)continue\?").unwrap(),
            ],
        }
    }

    /// Check if text matches a high-confidence prompt pattern.
    ///
    /// Returns the matched pattern context if found.
    pub fn match_high_confidence(&self, text: &str) -> Option<String> {
        for pattern in &self.high_confidence {
            if let Some(m) = pattern.find(text) {
                // Return context around the match
                let start = m.start().saturating_sub(20);
                let end = (m.end() + 20).min(text.len());
                return Some(text[start..end].to_string());
            }
        }
        None
    }

    /// Check if text matches a low-confidence prompt pattern.
    ///
    /// Returns the matched pattern context if found.
    pub fn match_low_confidence(&self, text: &str) -> Option<String> {
        for pattern in &self.low_confidence {
            if let Some(m) = pattern.find(text) {
                let start = m.start().saturating_sub(20);
                let end = (m.end() + 20).min(text.len());
                return Some(text[start..end].to_string());
            }
        }
        None
    }
}

impl Default for PromptMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_high_confidence("Password: ").is_some());
        assert!(matcher
            .match_high_confidence("Enter passphrase: ")
            .is_some());
    }

    #[test]
    fn test_yes_no_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_high_confidence("Continue? [y/n]").is_some());
        assert!(matcher
            .match_high_confidence("Overwrite (yes/no)?")
            .is_some());
    }

    #[test]
    fn test_shell_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_low_confidence("user@host:~$ ").is_some());
        assert!(matcher.match_low_confidence("root# ").is_some());
    }

    #[test]
    fn test_no_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_high_confidence("regular output").is_none());
    }

    #[test]
    fn test_sudo_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher
            .match_high_confidence("[sudo] password for user: ")
            .is_some());
    }

    #[test]
    fn test_ssh_confirmation() {
        let matcher = PromptMatcher::new();
        let text = "Are you sure you want to continue connecting (yes/no)?";
        assert!(matcher.match_high_confidence(text).is_some());
    }

    #[test]
    fn test_gpg_passphrase() {
        let matcher = PromptMatcher::new();
        assert!(matcher
            .match_high_confidence("Enter passphrase for key: ")
            .is_some());
    }

    #[test]
    fn test_press_enter() {
        let matcher = PromptMatcher::new();
        assert!(matcher
            .match_low_confidence("Press Enter to continue...")
            .is_some());
        assert!(matcher
            .match_low_confidence("Press any key to exit")
            .is_some());
    }

    #[test]
    fn test_continue_prompt() {
        let matcher = PromptMatcher::new();
        assert!(matcher
            .match_low_confidence("Do you want to continue?")
            .is_some());
    }

    #[test]
    fn test_trailing_colon() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_low_confidence("Enter your name: ").is_some());
        assert!(matcher.match_low_confidence("Username:").is_some());
    }

    #[test]
    fn test_context_extraction_bounds() {
        let matcher = PromptMatcher::new();
        // Test that context extraction doesn't panic on short strings
        let result = matcher.match_high_confidence("Password:");
        assert!(result.is_some());

        // Test with match at the very end
        let result = matcher.match_low_confidence("$");
        assert!(result.is_some());
    }

    #[test]
    fn test_case_insensitive_password() {
        let matcher = PromptMatcher::new();
        assert!(matcher.match_high_confidence("PASSWORD:").is_some());
        assert!(matcher.match_high_confidence("PaSsWoRd:").is_some());
        assert!(matcher.match_high_confidence("password:").is_some());
    }

    #[test]
    fn test_embedded_in_output() {
        let matcher = PromptMatcher::new();
        // Password prompt can appear in longer output
        let text = "Connecting to server...\nPassword: ";
        assert!(matcher.match_high_confidence(text).is_some());
    }
}
