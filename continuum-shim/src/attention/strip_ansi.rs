//! Best-effort ANSI escape sequence removal.

use regex::Regex;
use std::sync::OnceLock;

static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();

fn ansi_regex() -> &'static Regex {
    ANSI_REGEX.get_or_init(|| {
        // Matches most ANSI escape sequences:
        // - CSI sequences: \x1b[...
        // - OSC sequences: \x1b]...
        // - Simple escapes: \x1b followed by single char
        Regex::new(r"\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07]*\x07|[a-zA-Z])").unwrap()
    })
}

/// Strip ANSI escape sequences from text.
///
/// This is best-effort and may not catch all sequences.
pub fn strip_ansi(text: &str) -> String {
    ansi_regex().replace_all(text, "").to_string()
}

/// Strip ANSI from bytes, treating invalid UTF-8 as empty.
pub fn strip_ansi_bytes(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    strip_ansi(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_colors() {
        let input = "\x1b[31mred\x1b[0m text";
        assert_eq!(strip_ansi(input), "red text");
    }

    #[test]
    fn test_strip_cursor() {
        let input = "\x1b[2J\x1b[Hclear screen";
        assert_eq!(strip_ansi(input), "clear screen");
    }

    #[test]
    fn test_no_ansi() {
        let input = "plain text";
        assert_eq!(strip_ansi(input), "plain text");
    }

    #[test]
    fn test_strip_bold_and_underline() {
        let input = "\x1b[1mbold\x1b[0m and \x1b[4munderline\x1b[0m";
        assert_eq!(strip_ansi(input), "bold and underline");
    }

    #[test]
    fn test_strip_256_color() {
        // 256-color foreground: \x1b[38;5;<n>m
        let input = "\x1b[38;5;196mred\x1b[0m";
        assert_eq!(strip_ansi(input), "red");
    }

    #[test]
    fn test_strip_rgb_color() {
        // RGB color: \x1b[38;2;<r>;<g>;<b>m
        let input = "\x1b[38;2;255;0;0mred\x1b[0m";
        assert_eq!(strip_ansi(input), "red");
    }

    #[test]
    fn test_strip_osc_title() {
        // OSC sequence for setting window title
        let input = "\x1b]0;My Title\x07normal text";
        assert_eq!(strip_ansi(input), "normal text");
    }

    #[test]
    fn test_strip_cursor_movement() {
        // Various cursor movement sequences
        let input = "\x1b[5A\x1b[10Bhello\x1b[C\x1b[D";
        assert_eq!(strip_ansi(input), "hello");
    }

    #[test]
    fn test_strip_erase_sequences() {
        // Erase line and screen
        let input = "\x1b[Ktext\x1b[2J";
        assert_eq!(strip_ansi(input), "text");
    }

    #[test]
    fn test_multiple_sequences() {
        let input = "\x1b[32m\x1b[1mGreen Bold\x1b[0m Normal";
        assert_eq!(strip_ansi(input), "Green Bold Normal");
    }

    #[test]
    fn test_bytes_with_valid_utf8() {
        let input = b"\x1b[31mhello\x1b[0m";
        assert_eq!(strip_ansi_bytes(input), "hello");
    }

    #[test]
    fn test_bytes_with_invalid_utf8() {
        // Invalid UTF-8 should be replaced with replacement character
        let mut input = vec![0x1b, b'[', b'3', b'1', b'm'];
        input.push(0xFF); // Invalid UTF-8 byte
        input.extend_from_slice(b"\x1b[0m");

        let result = strip_ansi_bytes(&input);
        // Should contain the replacement character
        assert!(result.contains('\u{FFFD}'));
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(strip_ansi(""), "");
        assert_eq!(strip_ansi_bytes(b""), "");
    }

    #[test]
    fn test_only_ansi() {
        let input = "\x1b[31m\x1b[0m";
        assert_eq!(strip_ansi(input), "");
    }
}
