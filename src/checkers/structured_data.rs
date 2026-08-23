use crate::checkers::checker_result::CheckResult;
use gibberish_or_not::Sensitivity;
use lemmeknow::Identifier;

use super::checker_type::{Check, Checker};

/// Detects common structured data formats in decoded text.
pub struct StructuredDataChecker;

impl Check for Checker<StructuredDataChecker> {
    fn new() -> Self {
        Checker {
            name: "Structured Data Checker",
            description: "Recognizes valid JSON, XML, YAML, TOML, and CSV text",
            link: "https://www.json.org/",
            tags: vec!["structured", "json", "xml", "yaml", "toml", "csv"],
            expected_runtime: 0.01,
            popularity: 0.9,
            lemmeknow_config: Identifier::default(),
            sensitivity: Sensitivity::Medium,
            enhanced_detector: None,
            _phantom: std::marker::PhantomData,
        }
    }

    fn check(&self, text: &str) -> CheckResult {
        let format = detect_format(text);
        CheckResult {
            is_identified: format.is_some(),
            text: text.to_string(),
            checker_name: self.name,
            checker_description: self.description,
            description: format
                .map(|name| format!("Valid {name} structured data"))
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

/// Detect the most specific supported structured-data format.
fn detect_format(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if value.is_object() || value.is_array() {
            return Some("JSON");
        }
    }

    if is_xml_document(trimmed) {
        return Some("XML");
    }

    if let Ok(value) = toml::from_str::<toml::Value>(trimmed) {
        if value.is_table() {
            return Some("TOML");
        }
    }

    if is_csv_document(trimmed) {
        return Some("CSV");
    }

    if is_yaml_document(trimmed) {
        return Some("YAML");
    }

    None
}

/// Check whether text contains balanced XML-like elements.
fn is_xml_document(text: &str) -> bool {
    if !text.starts_with('<') || !text.ends_with('>') {
        return false;
    }

    let mut stack: Vec<&str> = Vec::new();
    let mut saw_element = false;
    let mut cursor = 0;
    while let Some(start) = text[cursor..].find('<') {
        let start = cursor + start;
        let Some(relative_end) = text[start..].find('>') else {
            return false;
        };
        let end = start + relative_end;
        let tag = text[start + 1..end].trim();
        cursor = end + 1;

        if tag.is_empty() || tag.starts_with('!') || tag.starts_with('?') {
            continue;
        }
        saw_element = true;
        if let Some(name) = tag.strip_prefix('/') {
            if stack.pop() != Some(name.trim()) {
                return false;
            }
        } else if !tag.ends_with('/') {
            let name = tag.split_whitespace().next().unwrap_or_default();
            if name.is_empty() || name.contains('=') {
                return false;
            }
            stack.push(name);
        }
    }

    saw_element && stack.is_empty()
}

/// Check whether all non-empty CSV rows have the same field count.
fn is_csv_document(text: &str) -> bool {
    let mut rows = text.lines().filter(|line| !line.trim().is_empty());
    let Some(first) = rows.next() else {
        return false;
    };
    let width = csv_width(first);
    if width < 2 {
        return false;
    }
    let mut row_count = 1;
    for row in rows {
        if csv_width(row) != width {
            return false;
        }
        row_count += 1;
    }
    row_count >= 2
}

/// Count CSV fields while handling quoted commas and escaped quotes.
fn csv_width(row: &str) -> usize {
    let mut fields = 1;
    let mut quoted = false;
    let mut chars = row.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields += 1,
            _ => {}
        }
    }
    if quoted {
        0
    } else {
        fields
    }
}

/// Check for a conservative YAML mapping or sequence shape.
fn is_yaml_document(text: &str) -> bool {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() < 2 {
        return false;
    }

    let structured_lines = lines
        .iter()
        .filter(|line| {
            line.starts_with('-')
                || line
                    .split_once(':')
                    .is_some_and(|(key, _)| !key.trim().is_empty())
        })
        .count();
    structured_lines == lines.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_json() {
        assert_eq!(detect_format(r#"{"name":"alice","age":3}"#), Some("JSON"));
    }

    #[test]
    fn recognizes_xml() {
        assert_eq!(
            detect_format("<root><item>hello</item></root>"),
            Some("XML")
        );
    }

    #[test]
    fn recognizes_toml() {
        assert_eq!(detect_format("name = \"alice\"\nage = 3"), Some("TOML"));
    }

    #[test]
    fn recognizes_csv() {
        assert_eq!(detect_format("name,age\nalice,3"), Some("CSV"));
    }

    #[test]
    fn recognizes_yaml() {
        assert_eq!(detect_format("name: alice\nage: 3"), Some("YAML"));
    }

    #[test]
    fn rejects_plain_text() {
        assert!(
            !Checker::<StructuredDataChecker>::new()
                .check("this is ordinary text")
                .is_identified
        );
    }

    #[test]
    fn rejects_base64_like_text() {
        assert_eq!(detect_format("IOgtHeA2JY4rHeA="), None);
    }
}
