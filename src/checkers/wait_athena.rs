/// WaitAthena checker is a variant of Athena that collects all plaintexts found during the search.
/// While Athena exits immediately when a plaintext is found, WaitAthena continues checking and
/// stores all plaintexts it finds until the timer expires.
/// Unlike Athena, WaitAthena does not use the human checker and automatically accepts all potential plaintexts.
use crate::{checkers::checker_result::CheckResult, config::get_config};
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;
use log::trace;

use crate::storage::wait_athena_storage;

use super::{
    binary_file_header_checker::BinaryFileHeaderChecker,
    checker_type::{Check, Checker},
    english::EnglishChecker,
    enhanced::{EnhancedDetector, HeuristicDetector},
    lemmeknow_checker::LemmeKnow,
    multilingual_checker::MultilingualChecker,
    password::PasswordChecker,
    programming_language_checker::ProgrammingLanguageChecker,
    regex_checker::RegexChecker,
    wordlist::WordlistChecker,
};

/// WaitAthena checker runs all other checkers and stores results for later display
/// This is identical to Athena but instead of returning immediately, it stores results
/// and continues checking until the timer expires
pub struct WaitAthena;

impl Check for Checker<WaitAthena> {
    fn new() -> Self {
        Checker {
            name: "WaitAthena Checker",
            description: "Runs all available checkers and stores results until timer expires",
            link: "",
            tags: vec!["wait_athena", "all"],
            expected_runtime: 1.0,
            popularity: 1.0,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium, // Default to Medium sensitivity
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let config = get_config();

        // If regex is specified, only run the regex checker
        // operates exactly the same as athena
        if config.regex.is_some() {
            trace!("running regex");
            let regex_checker = Checker::<RegexChecker>::new().with_sensitivity(self.sensitivity);
            let regex_result = regex_checker.check(text);
            if regex_result.is_identified {
                let mut check_res = CheckResult::new(&regex_checker);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = regex_result.text;
                check_res.description = regex_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    regex_checker.name.to_string(),
                    "RegexChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }
        } else {
            // Run wordlist checker first if a wordlist is provided
            if config.wordlist.is_some() {
                trace!("running wordlist checker");
                let wordlist_checker =
                    Checker::<WordlistChecker>::new().with_sensitivity(self.sensitivity);
                let wordlist_result = wordlist_checker.check(text);
                if wordlist_result.is_identified {
                    let mut check_res = CheckResult::new(&wordlist_checker);
                    check_res.is_identified = true; // No human checker involvement
                    check_res.text = wordlist_result.text;
                    check_res.description = wordlist_result.description;

                    // Store the result instead of returning immediately
                    wait_athena_storage::add_plaintext_result(
                        check_res.text.clone(),
                        check_res.description.clone(),
                        wordlist_checker.name.to_string(),
                        "WordlistChecker".to_string(),
                    );

                    // Continue checking by returning the result
                    return check_res;
                }
            }

            // In Ciphey if the user uses the regex checker all the other checkers turn off
            // This is because they are looking for one specific bit of information so will not want the other checkers
            let lemmeknow = Checker::<LemmeKnow>::new().with_sensitivity(self.sensitivity);
            let lemmeknow_result = lemmeknow.check(text);
            if lemmeknow_result.is_identified {
                let mut check_res = CheckResult::new(&lemmeknow);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = lemmeknow_result.text;
                check_res.description = lemmeknow_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    lemmeknow.name.to_string(),
                    "LemmeKnow".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let password = Checker::<PasswordChecker>::new().with_sensitivity(self.sensitivity);
            let password_result = password.check(text);
            if password_result.is_identified {
                let mut check_res = CheckResult::new(&password);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = password_result.text;
                check_res.description = password_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    password.name.to_string(),
                    "PasswordChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let programming =
                Checker::<ProgrammingLanguageChecker>::new().with_sensitivity(self.sensitivity);
            let programming_result = programming.check(text);
            if programming_result.is_identified {
                let mut check_res = CheckResult::new(&programming);
                check_res.is_identified = true;
                check_res.text = programming_result.text;
                check_res.description = programming_result.description;

                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    programming.name.to_string(),
                    "ProgrammingLanguageChecker".to_string(),
                );

                return check_res;
            }

            let binary_file_header =
                Checker::<BinaryFileHeaderChecker>::new().with_sensitivity(self.sensitivity);
            let binary_file_header_result = binary_file_header.check(text);
            if binary_file_header_result.is_identified {
                let mut check_res = CheckResult::new(&binary_file_header);
                check_res.is_identified = true;
                check_res.text = binary_file_header_result.text;
                check_res.description = binary_file_header_result.description;

                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    binary_file_header.name.to_string(),
                    "BinaryFileHeaderChecker".to_string(),
                );

                return check_res;
            }

            let multilingual =
                Checker::<MultilingualChecker>::new().with_sensitivity(self.sensitivity);
            let multilingual_result = multilingual.check(text);
            if multilingual_result.is_identified {
                let mut check_res = CheckResult::new(&multilingual);
                check_res.is_identified = true;
                check_res.text = multilingual_result.text;
                check_res.description = multilingual_result.description;

                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    multilingual.name.to_string(),
                    "MultilingualChecker".to_string(),
                );

                return check_res;
            }

            let english = Checker::<EnglishChecker>::new().with_sensitivity(self.sensitivity);
            let english_result = english.check(text);
            if english_result.is_identified {
                let mut check_res = CheckResult::new(&english);
                check_res.is_identified = true; // No human checker involvement
                check_res.text = english_result.text;
                check_res.description = english_result.description;

                // Store the result instead of returning immediately
                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    english.name.to_string(),
                    "EnglishChecker".to_string(),
                );

                // Continue checking by returning the result
                return check_res;
            }

            let structured_data =
                Checker::<crate::checkers::structured_data::StructuredDataChecker>::new()
                    .with_sensitivity(self.sensitivity);
            let structured_result = structured_data.check(text);
            if structured_result.is_identified {
                let mut check_res = CheckResult::new(&structured_data);
                check_res.is_identified = true;
                check_res.text = structured_result.text;
                check_res.description = structured_result.description;

                wait_athena_storage::add_plaintext_result(
                    check_res.text.clone(),
                    check_res.description.clone(),
                    structured_data.name.to_string(),
                    "StructuredDataChecker".to_string(),
                );

                return check_res;
            }

            if config.enhanced_detection {
                let detector = HeuristicDetector::new(config.enhanced_config.clone());
                let score = detector.detect(text);
                if score >= config.enhanced_config.threshold {
                    let mut check_res = CheckResult::new(self);
                    check_res.is_identified = true;
                    check_res.text = text.to_string();
                    check_res.description = format!("Enhanced detector score: {:.3}", score);

                    wait_athena_storage::add_plaintext_result(
                        check_res.text.clone(),
                        check_res.description.clone(),
                        "WaitAthena".to_string(),
                        "EnhancedDetector".to_string(),
                    );

                    return check_res;
                }
            }
        }

        CheckResult::new(self)
    }

    fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    fn get_sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gibberish_or_not::Sensitivity;

    #[test]
    fn test_check_english_sentence() {
        let checker = Checker::<WaitAthena>::new();
        assert!(checker.check("test valid english sentence").is_identified);
    }

    #[test]
    fn test_check_dictionary_word() {
        let checker = Checker::<WaitAthena>::new();
        assert!(checker.check("exuberant").is_identified);
    }

    #[test]
    fn test_default_sensitivity_is_medium() {
        let checker = Checker::<WaitAthena>::new();
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Medium));
    }

    #[test]
    fn test_with_sensitivity_changes_sensitivity() {
        let checker = Checker::<WaitAthena>::new().with_sensitivity(Sensitivity::Low);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::Low));

        let checker = Checker::<WaitAthena>::new().with_sensitivity(Sensitivity::High);
        assert!(matches!(checker.get_sensitivity(), Sensitivity::High));
    }
}
