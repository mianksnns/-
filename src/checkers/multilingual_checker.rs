use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};

/// Detects common non-English plaintext languages.
pub struct MultilingualChecker;

impl Check for Checker<MultilingualChecker> {
    fn new() -> Self {
        Checker {
            name: "Multilingual Checker",
            description: "Recognizes common Chinese, Japanese, Korean, French, German, Spanish, and Russian plaintext",
            link: "https://en.wikipedia.org/wiki/Language_identification",
            tags: vec!["multilingual", "language", "nlp"],
            expected_runtime: 0.02,
            popularity: 0.8,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let label = detect_language(text);
        CheckResult {
            is_identified: label.is_some(),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: label
                .map(|name| format!("Likely {name} plaintext"))
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

fn detect_language(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    if !is_text_like(trimmed) {
        return None;
    }

    if count_chars_in_ranges(trimmed, &[(0x3040, 0x309f), (0x30a0, 0x30ff)]) >= 2 {
        return Some("Japanese");
    }
    if count_chars_in_ranges(trimmed, &[(0x4e00, 0x9fff)]) >= 2 {
        return Some("Chinese");
    }
    if count_chars_in_ranges(trimmed, &[(0xac00, 0xd7af), (0x1100, 0x11ff)]) >= 2 {
        return Some("Korean");
    }
    if count_chars_in_ranges(trimmed, &[(0x0400, 0x04ff)]) >= 3 {
        return Some("Russian");
    }

    let tokens = tokenize_words(trimmed);
    if looks_french(&tokens, trimmed) {
        return Some("French");
    }
    if looks_german(&tokens, trimmed) {
        return Some("German");
    }
    if looks_spanish(&tokens, trimmed) {
        return Some("Spanish");
    }

    None
}

fn is_text_like(text: &str) -> bool {
    let total = text.chars().count();
    if total == 0 {
        return false;
    }

    let non_control = text.chars().filter(|c| !c.is_control()).count();
    non_control * 2 >= total
}

fn count_chars_in_ranges(text: &str, ranges: &[(u32, u32)]) -> usize {
    text.chars()
        .filter(|c| {
            let code = *c as u32;
            ranges
                .iter()
                .any(|(start, end)| code >= *start && code <= *end)
        })
        .count()
}

fn looks_french(tokens: &[String], text: &str) -> bool {
    text.contains('é')
        || text.contains('à')
        || text.contains('è')
        || text.contains('ç')
        || count_token_hits(tokens, &["le", "la", "de", "des", "est", "pour", "avec"]) >= 2
}

fn looks_german(tokens: &[String], text: &str) -> bool {
    text.contains('ä')
        || text.contains('ö')
        || text.contains('ü')
        || text.contains('ß')
        || count_token_hits(tokens, &["der", "die", "das", "und", "nicht", "ist"]) >= 2
}

fn looks_spanish(tokens: &[String], text: &str) -> bool {
    text.contains('ñ')
        || text.contains('á')
        || text.contains('é')
        || text.contains('í')
        || text.contains('ó')
        || text.contains('ú')
        || count_token_hits(
            tokens,
            &["el", "la", "los", "las", "que", "para", "una", "es"],
        ) >= 2
}

fn tokenize_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphabetic())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_lowercase())
        .collect()
}

fn count_token_hits(tokens: &[String], needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| tokens.iter().any(|token| token == *needle))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_chinese() {
        assert_eq!(detect_language("这是一个中文句子"), Some("Chinese"));
    }

    #[test]
    fn recognizes_japanese() {
        assert_eq!(detect_language("これは日本語です"), Some("Japanese"));
    }

    #[test]
    fn recognizes_korean() {
        assert_eq!(detect_language("이것은 한국어 문장입니다"), Some("Korean"));
    }

    #[test]
    fn recognizes_russian() {
        assert_eq!(detect_language("это русский текст"), Some("Russian"));
    }

    #[test]
    fn recognizes_french() {
        assert_eq!(
            detect_language("c'est une phrase avec le café"),
            Some("French")
        );
    }

    #[test]
    fn recognizes_german() {
        assert_eq!(
            detect_language("das ist ein deutscher satz"),
            Some("German")
        );
    }

    #[test]
    fn recognizes_spanish() {
        assert_eq!(
            detect_language("esta es una frase en español"),
            Some("Spanish")
        );
    }

    #[test]
    fn rejects_plain_text() {
        assert_eq!(detect_language("this is just regular english"), None);
    }
}
