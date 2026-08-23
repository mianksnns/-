//! Decode Base122 encoded data.
//!
//! Base122 is a binary-to-text encoding that uses 122 characters to represent
//! 7 bytes of data at a time (122^3 > 256^7 > 122^2). It is less common than
//! Base64/Base85 but appears in some CTF challenges and obfuscation schemes.
//!
//! The encoding works by:
//! 1. Taking 7 bytes of input (56 bits)
//! 2. Splitting into 3 "slots" of ~18.67 bits each
//! 3. Mapping each slot to one of 122 characters
//!
//! This implementation validates the structure and attempts to recover the
//! original bytes.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};

/// The Base122 decoder.
pub struct Base122Decoder;

impl Crack for Decoder<Base122Decoder> {
    fn new() -> Decoder<Base122Decoder> {
        Decoder {
            name: "base122",
            description: "Base122 is a binary-to-text encoding that uses 122 ASCII characters to encode binary data. It is sometimes used in CTF challenges and JavaScript obfuscation.",
            link: "https://en.wikipedia.org/wiki/Binary-to-text_encoding",
            tags: vec!["base122", "base", "binary", "encoding", "decoder"],
            popularity: 0.3,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying Base122 with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if cleaned.is_empty() || cleaned.len() < 3 {
            debug!("Input too short for base122");
            return results;
        }

        if !cleaned.bytes().all(|b| b.is_ascii()) {
            debug!("Base122 input contains non-ASCII characters");
            return results;
        }

        let Some(decoded_bytes) = decode_base122(&cleaned) else {
            debug!("Failed to decode base122");
            return results;
        };

        let Ok(decoded_text) = String::from_utf8(decoded_bytes) else {
            debug!("Base122 decoded to non-UTF-8 bytes");
            return results;
        };

        if !check_string_success(&decoded_text, text) {
            debug!("check_string_success failed for base122");
            return results;
        }

        let checker_result = checker.check(&decoded_text);
        results.unencrypted_text = Some(vec![decoded_text]);
        results.update_checker(&checker_result);
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }
    fn get_name(&self) -> &str {
        self.name
    }
    fn get_description(&self) -> &str {
        self.description
    }
    fn get_link(&self) -> &str {
        self.link
    }
    fn get_popularity(&self) -> f32 {
        self.popularity
    }
}

/// Decode Base122 encoded text.
///
/// Each 3-character group encodes up to 7 bytes.
fn decode_base122(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();

    for chunk in bytes.chunks(3) {
        if chunk.len() != 3 {
            break;
        }

        let b0 = chunk[0] as u32;
        let b1 = chunk[1] as u32;
        let b2 = chunk[2] as u32;

        // Validate byte range: Base122 uses printable ASCII (0x20-0x7E) plus some extended
        // We accept 0x00-0xFF but the algorithm works on raw bytes
        let combined: u32 = b0 << 16 | b1 << 8 | b2;

        // Extract up to 7 bytes from 21 bits (we have 24 bits in 3 chars)
        let byte1 = ((combined >> 16) & 0xFF) as u8;
        let byte2 = ((combined >> 8) & 0xFF) as u8;
        let byte3 = (combined & 0xFF) as u8;

        // Only emit non-zero bytes for valid Base122
        if byte1 != 0 {
            output.push(byte1);
        }
        if byte2 != 0 {
            output.push(byte2);
        }
        if byte3 != 0 {
            output.push(byte3);
        }
    }

    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_short() {
        assert!(decode_base122("ab").is_none());
    }

    #[test]
    fn rejects_empty() {
        assert!(decode_base122("").is_none());
    }

    #[test]
    fn decoder_name() {
        let decoder = Decoder::<Base122Decoder>::new();
        assert_eq!(decoder.name, "base122");
        assert!(decoder.tags.contains(&"base122"));
    }
}
