//! Steganography detection and extraction.
//!
//! This module provides functionality to detect and extract hidden information
//! using various steganography techniques:
//! - Zero-width character extraction (ZWSP, ZWNJ, ZWJ, etc.)
//! - Text pattern analysis for hidden data
//! - Basic image LSB analysis (when image feature is enabled)

use crate::storage::INVISIBLE_CHARS;

/// Zero-width characters commonly used for text steganography.
pub const ZERO_WIDTH_CHARS: [char; 6] = [
    '\u{200B}', // Zero Width Space (ZWSP)
    '\u{200C}', // Zero Width Non-Joiner (ZWNJ)
    '\u{200D}', // Zero Width Joiner (ZWJ)
    '\u{200E}', // Left-to-Right Mark (LRM)
    '\u{200F}', // Right-to-Left Mark (RLM)
    '\u{FEFF}', // Zero Width No-Break Space (BOM)
];

/// Extract zero-width characters from text.
///
/// Returns a vector of found zero-width characters in order of appearance.
pub fn extract_zero_width_chars(text: &str) -> Vec<char> {
    text.chars()
        .filter(|c| ZERO_WIDTH_CHARS.contains(c))
        .collect()
}

/// Decode hidden binary data from zero-width characters.
///
/// Uses the following encoding:
/// - ZWSP (U+200B) = 0
/// - ZWNJ (U+200C) = 1
/// - Other zero-width chars are ignored
///
/// Returns the decoded bytes if successful.
pub fn decode_zero_width_binary(text: &str) -> Option<Vec<u8>> {
    let bits: Vec<bool> = text
        .chars()
        .filter_map(|c| match c {
            '\u{200B}' => Some(false), // ZWSP = 0
            '\u{200C}' => Some(true),  // ZWNJ = 1
            _ => None,
        })
        .collect();

    if bits.is_empty() {
        return None;
    }

    // Convert bits to bytes (8 bits per byte, pad with zeros if needed)
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte: u8 = 0;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }

    // Remove trailing null bytes (padding)
    while bytes.last() == Some(&0) {
        bytes.pop();
    }

    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

/// Check if text contains steganographic content (zero-width characters).
pub fn contains_steganography(text: &str) -> bool {
    text.chars().any(|c| ZERO_WIDTH_CHARS.contains(&c))
}

/// Count the number of zero-width characters in text.
pub fn count_zero_width_chars(text: &str) -> usize {
    text.chars()
        .filter(|c| ZERO_WIDTH_CHARS.contains(c))
        .count()
}

/// Result of steganography analysis.
#[derive(Debug, Clone)]
pub struct SteganographyResult {
    /// Whether steganographic content was detected.
    pub detected: bool,
    /// Type of steganography detected.
    pub technique: SteganographyType,
    /// Extracted hidden data (if any).
    pub hidden_data: Option<Vec<u8>>,
    /// Text with steganographic content removed.
    pub cleaned_text: String,
}

/// Types of steganography techniques.
#[derive(Debug, Clone, PartialEq)]
pub enum SteganographyType {
    /// No steganography detected.
    None,
    /// Zero-width character encoding.
    ZeroWidthChars,
    /// Text pattern encoding (e.g., whitespace patterns).
    WhitespacePattern,
    /// Unknown technique.
    Unknown,
}

/// Analyze text for steganographic content.
pub fn analyze(text: &str) -> SteganographyResult {
    let zero_width_count = count_zero_width_chars(text);

    if zero_width_count == 0 {
        return SteganographyResult {
            detected: false,
            technique: SteganographyType::None,
            hidden_data: None,
            cleaned_text: text.to_string(),
        };
    }

    // Try to decode zero-width binary encoding
    let hidden_data = decode_zero_width_binary(text);

    // Remove zero-width characters to get clean text
    let cleaned_text: String = text
        .chars()
        .filter(|c| !ZERO_WIDTH_CHARS.contains(c))
        .collect();

    SteganographyResult {
        detected: true,
        technique: SteganographyType::ZeroWidthChars,
        hidden_data,
        cleaned_text,
    }
}

/// Remove all zero-width and invisible characters from text.
pub fn remove_invisible_chars(text: &str) -> String {
    text.chars()
        .filter(|c| !INVISIBLE_CHARS.contains(c))
        .collect()
}

/// Extract all invisible characters from text with their positions.
pub fn extract_invisible_with_positions(text: &str) -> Vec<(usize, char)> {
    text.char_indices()
        .filter(|(_, c)| INVISIBLE_CHARS.contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_zero_width_chars() {
        let text = "hello\u{200B}world\u{200C}";
        let chars = extract_zero_width_chars(text);
        assert_eq!(chars.len(), 2);
        assert_eq!(chars[0], '\u{200B}');
        assert_eq!(chars[1], '\u{200C}');
    }

    #[test]
    fn test_extract_zero_width_chars_empty() {
        let text = "hello world";
        let chars = extract_zero_width_chars(text);
        assert!(chars.is_empty());
    }

    #[test]
    fn test_decode_zero_width_binary() {
        // Encode "Hi" using zero-width chars
        // 'H' = 0x48 = 01001000
        // 'i' = 0x69 = 01101001
        let mut encoded = String::new();
        let bits = [0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1];
        for bit in bits {
            encoded.push(if bit == 0 { '\u{200B}' } else { '\u{200C}' });
        }

        let decoded = decode_zero_width_binary(&encoded);
        assert!(decoded.is_some());
        let bytes = decoded.unwrap();
        assert_eq!(bytes, b"Hi");
    }

    #[test]
    fn test_decode_zero_width_binary_empty() {
        let text = "hello world";
        let decoded = decode_zero_width_binary(text);
        assert!(decoded.is_none());
    }

    #[test]
    fn test_contains_steganography() {
        assert!(contains_steganography("hello\u{200B}world"));
        assert!(!contains_steganography("hello world"));
    }

    #[test]
    fn test_count_zero_width_chars() {
        assert_eq!(count_zero_width_chars("hello\u{200B}\u{200C}world"), 2);
        assert_eq!(count_zero_width_chars("hello world"), 0);
    }

    #[test]
    fn test_analyze_with_steganography() {
        let text = "hello\u{200B}\u{200C}world";
        let result = analyze(text);
        assert!(result.detected);
        assert_eq!(result.technique, SteganographyType::ZeroWidthChars);
        assert_eq!(result.cleaned_text, "helloworld");
    }

    #[test]
    fn test_analyze_without_steganography() {
        let text = "hello world";
        let result = analyze(text);
        assert!(!result.detected);
        assert_eq!(result.technique, SteganographyType::None);
        assert_eq!(result.cleaned_text, "hello world");
    }

    #[test]
    fn test_remove_invisible_chars() {
        let text = "hello\u{200B}\u{200C}world";
        let cleaned = remove_invisible_chars(text);
        assert_eq!(cleaned, "helloworld");
    }

    #[test]
    fn test_extract_invisible_with_positions() {
        let text = "he\u{200B}l\u{200C}lo";
        let positions = extract_invisible_with_positions(text);
        assert_eq!(positions.len(), 2);
        // char_indices() returns byte positions
        // 'h' = byte 0, 'e' = byte 1, '\u{200B}' = byte 2 (3 bytes in UTF-8)
        // 'l' = byte 5, '\u{200C}' = byte 6 (3 bytes in UTF-8)
        assert_eq!(positions[0].0, 2);
        assert_eq!(positions[0].1, '\u{200B}');
        assert_eq!(positions[1].0, 6);
        assert_eq!(positions[1].1, '\u{200C}');
    }
}
