//! # Result Ranker Module
//!
//! Provides confidence scoring and ranking for decoded plaintext results.
//! Results are scored based on checker reliability, path quality, and string quality.

use crate::searchers::helper_functions::calculate_string_quality;
use crate::storage::wait_athena_storage::PlaintextResult;
use crate::DecoderResult;

/// Confidence score between 0.0 and 1.0
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Confidence(pub f32);

impl Confidence {
    pub fn as_percent(&self) -> u8 {
        (self.0 * 100.0).min(100.0) as u8
    }
}

/// Ranked result with confidence score
#[derive(Debug, Clone)]
pub struct RankedResult {
    pub plaintext: PlaintextResult,
    pub confidence: Confidence,
    pub path_length: usize,
}

/// Calculate confidence score for a decoded result
///
/// The confidence is a weighted combination of:
/// - Checker confidence (40%): How reliable is the checker that identified this
/// - Path quality (30%): Shorter decode paths are more likely correct
/// - String quality (30%): Quality of the decoded string itself
pub fn calculate_confidence(checker_name: &str, path_length: usize, text: &str) -> Confidence {
    let checker_confidence = get_checker_confidence(checker_name);
    let path_quality = calculate_path_quality(path_length);
    let string_quality = calculate_string_quality(text);

    let score = checker_confidence * 0.4 + path_quality * 0.3 + string_quality * 0.3;
    Confidence(score.clamp(0.0, 1.0))
}

/// Get the inherent confidence weight for each checker type
fn get_checker_confidence(checker_name: &str) -> f32 {
    match checker_name {
        "Structured Data Checker" => 0.95,
        "English Checker" => 0.90,
        "Programming Language Checker" => 0.88,
        "Multilingual Checker" => 0.85,
        "Binary File Header Checker" => 0.92,
        "Regex Checker" => 0.80,
        "Wordlist Checker" => 0.75,
        "Password Checker" => 0.70,
        "LemmeKnow Checker" => 0.65,
        _ => 0.50,
    }
}

/// Calculate path quality: shorter paths are more likely correct
fn calculate_path_quality(path_length: usize) -> f32 {
    1.0 / (1.0 + path_length as f32 * 0.15)
}

/// Rank results by confidence, highest first
pub fn rank_results(mut results: Vec<RankedResult>) -> Vec<RankedResult> {
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Deduplicate results by plaintext text
pub fn deduplicate_results(results: Vec<RankedResult>) -> Vec<RankedResult> {
    let mut seen = std::collections::HashSet::new();
    results
        .into_iter()
        .filter(|r| seen.insert(r.plaintext.text.clone()))
        .collect()
}

/// Convert DecoderResult to RankedResult
pub fn decoder_result_to_ranked(
    result: &DecoderResult,
    checker_name: &str,
) -> Option<RankedResult> {
    let text = result.text.first()?;
    let confidence = calculate_confidence(checker_name, result.path.len(), text);
    Some(RankedResult {
        plaintext: PlaintextResult {
            text: text.clone(),
            description: format!(
                "Decoded at depth {} via {}",
                result.path.len(),
                result.path.last().map(|r| r.decoder).unwrap_or("unknown")
            ),
            checker_name: checker_name.to_string(),
            decoder_name: result
                .path
                .iter()
                .map(|r| r.decoder)
                .collect::<Vec<_>>()
                .join(" → "),
        },
        confidence,
        path_length: result.path.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_range() {
        let conf = calculate_confidence("English Checker", 1, "Hello World");
        assert!(conf.0 >= 0.0 && conf.0 <= 1.0);
        assert!(conf.as_percent() <= 100);
    }

    #[test]
    fn test_checker_confidence_ordering() {
        let structured = get_checker_confidence("Structured Data Checker");
        let english = get_checker_confidence("English Checker");
        let unknown = get_checker_confidence("Unknown Checker");

        assert!(structured > english);
        assert!(english > unknown);
    }

    #[test]
    fn test_path_quality_decreases_with_length() {
        let short = calculate_path_quality(1);
        let medium = calculate_path_quality(3);
        let long = calculate_path_quality(10);

        assert!(short > medium);
        assert!(medium > long);
        assert!(short <= 1.0);
    }

    #[test]
    fn test_rank_results_sorts_by_confidence() {
        let results = vec![
            RankedResult {
                plaintext: PlaintextResult {
                    text: "low".to_string(),
                    description: "test".to_string(),
                    checker_name: "Unknown".to_string(),
                    decoder_name: "Base64".to_string(),
                },
                confidence: Confidence(0.3),
                path_length: 5,
            },
            RankedResult {
                plaintext: PlaintextResult {
                    text: "high".to_string(),
                    description: "test".to_string(),
                    checker_name: "English Checker".to_string(),
                    decoder_name: "Base64".to_string(),
                },
                confidence: Confidence(0.9),
                path_length: 1,
            },
            RankedResult {
                plaintext: PlaintextResult {
                    text: "medium".to_string(),
                    description: "test".to_string(),
                    checker_name: "English Checker".to_string(),
                    decoder_name: "Hex".to_string(),
                },
                confidence: Confidence(0.6),
                path_length: 2,
            },
        ];

        let ranked = rank_results(results);
        assert_eq!(ranked[0].plaintext.text, "high");
        assert_eq!(ranked[1].plaintext.text, "medium");
        assert_eq!(ranked[2].plaintext.text, "low");
    }

    #[test]
    fn test_deduplicate_results() {
        let results = vec![
            RankedResult {
                plaintext: PlaintextResult {
                    text: "duplicate".to_string(),
                    description: "test".to_string(),
                    checker_name: "English Checker".to_string(),
                    decoder_name: "Base64".to_string(),
                },
                confidence: Confidence(0.8),
                path_length: 1,
            },
            RankedResult {
                plaintext: PlaintextResult {
                    text: "duplicate".to_string(),
                    description: "test".to_string(),
                    checker_name: "English Checker".to_string(),
                    decoder_name: "Hex".to_string(),
                },
                confidence: Confidence(0.7),
                path_length: 1,
            },
            RankedResult {
                plaintext: PlaintextResult {
                    text: "unique".to_string(),
                    description: "test".to_string(),
                    checker_name: "English Checker".to_string(),
                    decoder_name: "Base64".to_string(),
                },
                confidence: Confidence(0.6),
                path_length: 2,
            },
        ];

        let deduped = deduplicate_results(results);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].plaintext.text, "duplicate");
        assert_eq!(deduped[1].plaintext.text, "unique");
    }
}
