//! WASM (WebAssembly) compatibility module.
//!
//! This module provides a JavaScript-friendly API for using ciphey in
//! web browsers via WebAssembly. It exposes a simplified interface
//! for decoding operations.
//!
//! # Example (JavaScript)
//! ```javascript
//! import init, { decode } from './ciphey_wasm.js';
//!
//! async function main() {
//!     await init();
//!     const result = decode("SGVsbG8gV29ybGQ=");
//!     console.log(result.text);
//!     console.log(result.path);
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::config::{get_config, set_global_config, Config};
use crate::perform_cracking;

/// Decode result returned to JavaScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmDecodeResult {
    /// Whether decoding was successful.
    pub success: bool,
    /// Decoded plaintext (if successful).
    pub text: Option<String>,
    /// Decode path as a list of decoder names.
    pub path: Vec<String>,
    /// Confidence percentage (0-100).
    pub confidence: u8,
    /// Error message (if failed).
    pub error: Option<String>,
}

impl WasmDecodeResult {
    fn from_decoder_result(result: &crate::DecoderResult) -> Self {
        let path: Vec<String> = result.path.iter().map(|c| c.decoder.to_string()).collect();

        // Calculate confidence based on path length and checker
        let confidence = if result.path.is_empty() {
            100
        } else {
            // Longer paths get lower confidence
            let path_penalty = (result.path.len() as u8).saturating_mul(5);
            95_u8.saturating_sub(path_penalty)
        };

        WasmDecodeResult {
            success: true,
            text: Some(result.text[0].clone()),
            path,
            confidence,
            error: None,
        }
    }

    fn failure(error: String) -> Self {
        WasmDecodeResult {
            success: false,
            text: None,
            path: vec![],
            confidence: 0,
            error: Some(error),
        }
    }
}

/// Configuration for WASM decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConfig {
    /// Timeout in seconds.
    pub timeout: u32,
    /// Whether to enable human checker (should be false for WASM).
    pub human_checker: bool,
    /// Optional regex pattern.
    pub regex: Option<String>,
}

impl Default for WasmConfig {
    fn default() -> Self {
        WasmConfig {
            timeout: 10,
            human_checker: false,
            regex: None,
        }
    }
}

/// Initialize the WASM module with default configuration.
///
/// This should be called once before any decode operations.
pub fn init_wasm() {
    let config = Config::default();
    set_global_config(config);
}

/// Initialize the WASM module with custom configuration.
pub fn init_wasm_with_config(wasm_config: WasmConfig) {
    let mut config = Config::default();
    config.timeout = wasm_config.timeout;
    config.human_checker_on = wasm_config.human_checker;
    config.regex = wasm_config.regex;
    config.api_mode = true;
    set_global_config(config);
}

/// Decode the given input text.
///
/// This is the main entry point for WASM decoding.
///
/// # Arguments
/// * `input` - The encoded text to decode.
///
/// # Returns
/// A `WasmDecodeResult` containing the decoded text or error information.
pub fn decode(input: &str) -> WasmDecodeResult {
    let config = get_config();

    // Validate input size
    if let Err(e) = crate::security::validate_input_size(input) {
        return WasmDecodeResult::failure(e.to_string());
    }

    let result = perform_cracking(input, config.clone());

    match result {
        Some(result) => WasmDecodeResult::from_decoder_result(&result),
        None => WasmDecodeResult::failure(
            "Failed to decode the input text. It may not be a recognized encoding format."
                .to_string(),
        ),
    }
}

/// Decode with a custom timeout.
///
/// # Arguments
/// * `input` - The encoded text to decode.
/// * `timeout_seconds` - Custom timeout in seconds.
///
/// # Returns
/// A `WasmDecodeResult` containing the decoded text or error information.
pub fn decode_with_timeout(input: &str, timeout_seconds: u32) -> WasmDecodeResult {
    let mut config = get_config().clone();
    config.timeout = timeout_seconds;
    config.api_mode = true;

    // Validate input size
    if let Err(e) = crate::security::validate_input_size(input) {
        return WasmDecodeResult::failure(e.to_string());
    }

    let result = perform_cracking(input, config);

    match result {
        Some(result) => WasmDecodeResult::from_decoder_result(&result),
        None => WasmDecodeResult::failure(
            "Failed to decode the input text within the specified timeout.".to_string(),
        ),
    }
}

/// Get information about the library.
///
/// Returns version and capability information for the WASM module.
pub fn get_info() -> WasmInfo {
    WasmInfo {
        version: env!("CARGO_PKG_VERSION"),
        name: "ciphey-wasm",
        description: "Automatic decoding tool for web browsers",
        supported_features: vec![
            "base64".to_string(),
            "hex".to_string(),
            "caesar".to_string(),
            "url".to_string(),
            "rot13".to_string(),
            "binary".to_string(),
            "morse".to_string(),
        ],
    }
}

/// Information about the WASM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmInfo {
    /// Library version.
    pub version: &'static str,
    /// Module name.
    pub name: &'static str,
    /// Description.
    pub description: &'static str,
    /// List of supported features.
    pub supported_features: Vec<String>,
}

/// Batch decode multiple inputs.
///
/// # Arguments
/// * `inputs` - List of encoded texts to decode.
///
/// # Returns
/// A list of decode results, one for each input.
pub fn batch_decode(inputs: &[String]) -> Vec<WasmDecodeResult> {
    inputs.iter().map(|input| decode(input)).collect()
}

/// Check if the input is likely plaintext.
///
/// Returns true if the input appears to be plaintext already.
pub fn is_plaintext(input: &str) -> bool {
    use crate::checkers::athena::Athena;
    use crate::checkers::checker_type::{Check, Checker};
    use crate::checkers::CheckerTypes;

    let checker = Checker::<Athena>::new();
    let checker_types = CheckerTypes::CheckAthena(checker);
    let result = checker_types.check(input);
    result.is_identified
}

/// WASM-specific exports for JavaScript interop.
///
/// These functions use `wasm_bindgen` when compiled for WASM target.
#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Decode function exported to JavaScript.
    #[wasm_bindgen]
    pub fn wasm_decode(input: &str) -> JsValue {
        let result = decode(input);
        serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
    }

    /// Initialize the WASM module.
    #[wasm_bindgen]
    pub fn wasm_init() {
        init_wasm();
    }

    /// Get library info as JSON.
    #[wasm_bindgen]
    pub fn wasm_get_info() -> JsValue {
        let info = get_info();
        serde_wasm_bindgen::to_value(&info).unwrap_or(JsValue::NULL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64() {
        let result = decode("SGVsbG8gV29ybGQ=");
        assert!(result.success);
        assert_eq!(result.text.as_deref(), Some("Hello World"));
    }

    #[test]
    fn test_decode_failure() {
        let result = decode("");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_wasm_config_default() {
        let config = WasmConfig::default();
        assert_eq!(config.timeout, 10);
        assert!(!config.human_checker);
    }

    #[test]
    fn test_wasm_decode_result_success() {
        let result = WasmDecodeResult {
            success: true,
            text: Some("Hello".to_string()),
            path: vec!["Base64".to_string()],
            confidence: 90,
            error: None,
        };
        assert!(result.success);
        assert_eq!(result.confidence, 90);
    }

    #[test]
    fn test_wasm_decode_result_failure() {
        let result = WasmDecodeResult::failure("test error".to_string());
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("test error"));
    }

    #[test]
    fn test_get_info() {
        let info = get_info();
        assert_eq!(info.name, "ciphey-wasm");
        assert!(!info.supported_features.is_empty());
    }

    #[test]
    fn test_batch_decode() {
        let inputs = vec!["SGVsbG8=".to_string(), "aGVsbG8=".to_string()];
        let results = batch_decode(&inputs);
        assert_eq!(results.len(), 2);
        assert!(results[0].success);
        assert!(results[1].success);
    }

    #[test]
    fn test_decode_with_timeout() {
        let result = decode_with_timeout("SGVsbG8=", 5);
        assert!(result.success);
    }

    #[test]
    fn test_init_wasm() {
        init_wasm();
        // Should not panic
    }

    #[test]
    fn test_init_wasm_with_config() {
        let config = WasmConfig {
            timeout: 15,
            human_checker: false,
            regex: None,
        };
        init_wasm_with_config(config);
        // Should not panic
    }
}
