use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};
use crate::{checkers::checker_result::CheckResult, config::get_config};
use log::trace;
use regex::Regex;

/// The Regex Checker checks if the text matches a known Regex pattern.
/// This is the struct for it.
pub struct RegexChecker;

impl Check for Checker<RegexChecker> {
    fn new() -> Self {
        Checker {
            name: "Regex Checker",
            description: "Uses Regex to check for regex matches, useful for finding cribs.",
            link: "https://github.com/rust-lang/regex",
            tags: vec!["crib", "regex"],
            expected_runtime: 0.01,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        trace!("Checking {} with regex", text);
        let config = get_config();
        let regex_to_parse = config.regex.clone();

        let Some(pattern) = regex_to_parse else {
            return CheckResult {
                is_identified: false,
                text: text.to_string(),
                checker_name: self.name,
                checker_description: self.description,
                description: "No regex pattern provided".to_string(),
                link: self.link,
            };
        };

        // Limit pattern complexity to prevent ReDoS
        if pattern.len() > 1000 {
            return CheckResult {
                is_identified: false,
                text: text.to_string(),
                checker_name: self.name,
                checker_description: self.description,
                description: "Regex pattern too complex (ReDoS protection)".to_string(),
                link: self.link,
            };
        }

        let re = match Regex::new(&pattern) {
            Ok(re) => re,
            Err(e) => {
                return CheckResult {
                    is_identified: false,
                    text: text.to_string(),
                    checker_name: self.name,
                    checker_description: self.description,
                    description: format!("Invalid regex: {}", e),
                    link: self.link,
                };
            }
        };

        // Use timeout guard for ReDoS protection
        let timeout = crate::security::TimeoutGuard::new(crate::security::MAX_REGEX_EXECUTION_MS);
        let mut plaintext_found = false;
        let printed_name = format!("Regex matched: {re}");

        // For simple patterns, just check directly
        // For complex patterns with quantifiers, we'd need async timeout
        let regex_check_result = re.is_match(text);

        if timeout.is_expired() {
            return CheckResult {
                is_identified: false,
                text: text.to_string(),
                checker_name: self.name,
                checker_description: self.description,
                description: "Regex execution timed out (ReDoS protection)".to_string(),
                link: self.link,
            };
        }

        if regex_check_result {
            plaintext_found = true;
        }

        CheckResult {
            is_identified: plaintext_found,
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: printed_name,
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
