//! Detect weak crypto patterns commonly found in CTF tasks.

use base64::{engine::general_purpose, Engine as _};
use log::{debug, trace};
use std::collections::HashSet;

use crate::checkers::CheckerTypes;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

/// Detects common weak crypto scenarios and returns hint text.
pub struct CtfWeakCryptoDecoder;

impl Crack for Decoder<CtfWeakCryptoDecoder> {
    fn new() -> Decoder<CtfWeakCryptoDecoder> {
        Decoder {
            name: "ctf-weak-crypto",
            description: "Detects common weak crypto patterns used in CTF tasks, including ECB mode reuse, padding-oracle style errors, and weak RSA parameter exposure.",
            link: "https://en.wikipedia.org/wiki/Cryptanalysis",
            tags: vec!["crypto", "ctf", "hints", "decoder"],
            popularity: 0.75,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying CtfWeakCryptoDecoder with text {:?}", text);
        let mut result = CrackResult::new(self, text.to_string());

        let mut hints = Vec::new();
        for candidate in candidate_payloads(text) {
            if let Some(hint) = detect_block_cipher_hint(&candidate) {
                hints.push(hint);
            }
        }
        if let Some(hint) = detect_padding_oracle_hint(text) {
            hints.push(hint);
        }
        if let Some(hint) = detect_rsa_hint(text) {
            hints.push(hint);
        }

        hints.sort();
        hints.dedup();
        if hints.is_empty() {
            debug!("No weak-crypto hint matched");
            return result;
        }

        let summary = hints.join(" ");
        let checker_result = checker.check(&summary);
        result.unencrypted_text = Some(vec![summary]);
        if checker_result.is_identified {
            result.update_checker(&checker_result);
        }
        result.success = true;
        result
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
    if !is_mostly_printable(text.as_bytes()) {
        candidates.push(text.as_bytes().to_vec());
    }

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

fn detect_block_cipher_hint(bytes: &[u8]) -> Option<String> {
    let aes_repeats = repeated_block_count(bytes, 16);
    let des_repeats = repeated_block_count(bytes, 8);

    if aes_repeats == 0 && des_repeats == 0 {
        return None;
    }

    let mut parts = Vec::new();
    if aes_repeats > 0 {
        parts.push(format!(
            "AES-style ECB hint: repeated 16-byte blocks detected ({} duplicates).",
            aes_repeats
        ));
    }
    if des_repeats > 0 {
        parts.push(format!(
            "DES/3DES-style ECB hint: repeated 8-byte blocks detected ({} duplicates).",
            des_repeats
        ));
    }
    Some(parts.join(" "))
}

fn repeated_block_count(bytes: &[u8], block_size: usize) -> usize {
    if bytes.len() < block_size * 2 {
        return 0;
    }

    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut duplicates = 0usize;
    for block in bytes.chunks_exact(block_size) {
        if !seen.insert(block) {
            duplicates += 1;
        }
    }
    duplicates
}

fn detect_padding_oracle_hint(text: &str) -> Option<String> {
    let lowered = text.to_ascii_lowercase();
    let markers = [
        "padding oracle",
        "invalid padding",
        "bad padding",
        "padding check failed",
    ];
    if markers.iter().any(|marker| lowered.contains(marker)) {
        Some("Padding-oracle hint: the text mentions a padding validation failure.".to_string())
    } else {
        None
    }
}

fn detect_rsa_hint(text: &str) -> Option<String> {
    let lowered = text.to_ascii_lowercase();
    let mut hints = Vec::new();

    if lowered.contains("e=3") || lowered.contains("e = 3") || lowered.contains("public exponent 3")
    {
        hints.push("RSA hint: small public exponent e=3 detected.");
    }
    if lowered.contains("p=")
        || lowered.contains("q=")
        || lowered.contains("private exponent")
        || lowered.contains("factor")
    {
        hints.push("RSA hint: private factors or private-key material are exposed.");
    }
    if lowered.contains("n=") && lowered.contains("e=") {
        hints.push("RSA hint: modulus and exponent are exposed; check for common-modulus or weak-parameter attacks.");
    }

    if hints.is_empty() {
        None
    } else {
        Some(hints.join(" "))
    }
}

fn is_mostly_printable(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    printable * 2 >= bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::Crack;
    use crate::decoders::interface::Decoder;

    fn get_athena_checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    #[test]
    fn detects_aes_ecb_blocks() {
        let decoder = Decoder::<CtfWeakCryptoDecoder>::new();
        let ciphertext = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let result = decoder.crack(ciphertext, &get_athena_checker());
        let hint = result.unencrypted_text.expect("expected hint");
        assert!(result.success);
        assert!(hint[0].contains("ECB"));
    }

    #[test]
    fn detects_padding_oracle_hint() {
        let decoder = Decoder::<CtfWeakCryptoDecoder>::new();
        let result = decoder.crack("server returned invalid padding", &get_athena_checker());
        let hint = result.unencrypted_text.expect("expected hint");
        assert!(hint[0].contains("Padding-oracle"));
    }

    #[test]
    fn detects_rsa_hint() {
        let decoder = Decoder::<CtfWeakCryptoDecoder>::new();
        let result = decoder.crack("n=3233 e=3", &get_athena_checker());
        let hint = result.unencrypted_text.expect("expected hint");
        assert!(hint[0].contains("RSA hint"));
    }

    #[test]
    fn rejects_plain_text() {
        let decoder = Decoder::<CtfWeakCryptoDecoder>::new();
        let result = decoder.crack("ordinary text", &get_athena_checker());
        assert!(!result.success);
    }
}
