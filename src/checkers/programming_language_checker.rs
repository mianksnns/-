use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};

/// Detects common code snippets in Python, JavaScript, and C.
pub struct ProgrammingLanguageChecker;

impl Check for Checker<ProgrammingLanguageChecker> {
    fn new() -> Self {
        Checker {
            name: "Programming Language Checker",
            description: "Recognizes valid code snippets in Python, JavaScript, and C",
            link: "https://en.wikipedia.org/wiki/Source_code",
            tags: vec!["code", "source", "python", "javascript", "c"],
            expected_runtime: 0.02,
            popularity: 0.8,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let label = detect_programming_language(text);
        CheckResult {
            is_identified: label.is_some(),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: label
                .map(|name| format!("Likely {name} code"))
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

fn detect_programming_language(text: &str) -> Option<&'static str> {
    let normalized = normalize(text);
    if looks_like_python(&normalized) {
        return Some("Python");
    }
    if looks_like_javascript(&normalized) {
        return Some("JavaScript");
    }
    if looks_like_c(&normalized) {
        return Some("C");
    }
    None
}

fn normalize(text: &str) -> String {
    text.replace("```", "")
}

fn looks_like_python(text: &str) -> bool {
    let markers = [
        "def ",
        "class ",
        "import ",
        "from ",
        "if __name__ == \"__main__\":",
        "self.",
        "print(",
        "async def ",
        "except ",
        "elif ",
        "pass",
        "return ",
    ];
    score_markers(text, &markers) >= 2
}

fn looks_like_javascript(text: &str) -> bool {
    let markers = [
        "function ",
        "const ",
        "let ",
        "var ",
        "=>",
        "console.log",
        "export default",
        "import ",
        "document.",
        "window.",
    ];
    score_markers(text, &markers) >= 2
}

fn looks_like_c(text: &str) -> bool {
    let markers = [
        "#include",
        "int main",
        "printf(",
        "scanf(",
        "return 0;",
        "stdio.h",
        "stdlib.h",
    ];
    score_markers(text, &markers) >= 2
}

fn score_markers(text: &str, markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|marker| text.contains(*marker))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_python() {
        let code = "def greet(name):\n    print(name)";
        assert_eq!(detect_programming_language(code), Some("Python"));
    }

    #[test]
    fn recognizes_javascript() {
        let code = "const greet = name => console.log(name);";
        assert_eq!(detect_programming_language(code), Some("JavaScript"));
    }

    #[test]
    fn recognizes_c() {
        let code = "#include <stdio.h>\nint main() { printf(\"hi\"); return 0; }";
        assert_eq!(detect_programming_language(code), Some("C"));
    }

    #[test]
    fn rejects_plain_text() {
        assert_eq!(detect_programming_language("this is just plain text"), None);
    }
}
