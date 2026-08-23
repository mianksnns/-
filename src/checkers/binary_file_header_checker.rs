use crate::checkers::checker_result::CheckResult;
use base64::{engine::general_purpose, Engine as _};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};

/// Detects common file formats from their magic bytes.
pub struct BinaryFileHeaderChecker;

impl Check for Checker<BinaryFileHeaderChecker> {
    fn new() -> Self {
        Checker {
            name: "Binary File Header Checker",
            description: "Recognizes PNG, JPEG, PDF, and ZIP magic bytes",
            link: "https://en.wikipedia.org/wiki/List_of_file_signatures",
            tags: vec!["magic-bytes", "file", "binary", "png", "jpeg", "pdf", "zip"],
            expected_runtime: 0.01,
            popularity: 0.8,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let label = detect_magic_bytes(text);
        CheckResult {
            is_identified: label.is_some(),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: label
                .map(|name| format!("Likely {name} file; consider saving it to disk"))
                .unwrap_or_default(),
            link: self.link,
        }
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

fn detect_magic_bytes(text: &str) -> Option<&'static str> {
    for candidate in candidate_payloads(text) {
        if candidate.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
            return Some("PNG");
        }
        if candidate.starts_with(&[0xff, 0xd8, 0xff]) {
            return Some("JPEG");
        }
        if candidate.starts_with(b"%PDF-") {
            return Some("PDF");
        }
        if candidate.starts_with(&[0x50, 0x4b, 0x03, 0x04])
            || candidate.starts_with(&[0x50, 0x4b, 0x05, 0x06])
            || candidate.starts_with(&[0x50, 0x4b, 0x07, 0x08])
        {
            return Some("ZIP");
        }
    }
    None
}

fn candidate_payloads(text: &str) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();
    if let Some(bytes) = decode_hex(text) {
        candidates.push(bytes);
    }
    if let Ok(bytes) = general_purpose::STANDARD.decode(text.as_bytes()) {
        candidates.push(bytes);
    }
    if let Ok(bytes) = general_purpose::URL_SAFE.decode(text.as_bytes()) {
        candidates.push(bytes);
    }
    if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(text.as_bytes()) {
        candidates.push(bytes);
    }
    candidates.push(text.as_bytes().to_vec());
    candidates
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if cleaned.len() < 2
        || !cleaned.len().is_multiple_of(2)
        || !cleaned.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_png_magic() {
        assert_eq!(
            detect_magic_bytes("89504e470d0a1a0a0000000d49484452"),
            Some("PNG")
        );
    }

    #[test]
    fn recognizes_pdf_magic() {
        assert_eq!(detect_magic_bytes("255044462d312e370a"), Some("PDF"));
    }

    #[test]
    fn recognizes_zip_magic() {
        assert_eq!(detect_magic_bytes("504b0304140000000800"), Some("ZIP"));
    }

    #[test]
    fn rejects_plain_text() {
        assert_eq!(detect_magic_bytes("plain text"), None);
    }
}
