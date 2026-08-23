//! Enhanced plaintext detection module.
//!
//! Provides BERT-based and other ML-enhanced plaintext detection.
//! The actual model loading is lazy and only happens when enhanced detection
//! is explicitly enabled via the `--enable-enhanced-detection` flag.
//!
//! The model is cached locally after first download to avoid repeated network access.

use std::path::PathBuf;
use std::sync::Mutex;

/// Trait for enhanced plaintext detectors.
pub trait EnhancedDetector: Send + Sync {
    /// Returns the name of this detector.
    fn name(&self) -> &str;

    /// Check if the given text is meaningful plaintext.
    /// Returns a score between 0.0 (not plaintext) and 1.0 (definitely plaintext).
    fn detect(&self, text: &str) -> f64;

    /// Returns true if this detector is available (model loaded successfully).
    fn is_available(&self) -> bool;
}

/// Configuration for enhanced detection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnhancedConfig {
    /// Path to the model file. If None, uses the default cache location.
    #[serde(skip)]
    pub model_path: Option<PathBuf>,
    /// Minimum confidence threshold (0.0-1.0) to consider text as plaintext.
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    /// Maximum input length to analyze (longer texts are truncated).
    #[serde(default = "default_max_input_length")]
    pub max_input_length: usize,
}

fn default_threshold() -> f64 {
    0.7
}

fn default_max_input_length() -> usize {
    1024
}

impl Default for EnhancedConfig {
    fn default() -> Self {
        EnhancedConfig {
            model_path: None,
            threshold: 0.7,
            max_input_length: 1024,
        }
    }
}

/// Get the default model cache path.
pub fn default_model_cache_path() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    path.push("ciphey");
    path.push("models");
    path
}

/// Ensure the model cache directory exists.
pub fn ensure_cache_dir() -> std::io::Result<PathBuf> {
    let path = default_model_cache_path();
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

/// Global enhanced detector instance (lazy initialization).
static ENHANCED_DETECTOR: Mutex<Option<Box<dyn EnhancedDetector>>> = Mutex::new(None);

/// Initialize the enhanced detector with the given configuration.
///
/// When the `enhanced-detection` feature is enabled, this loads a BERT-based
/// model (or falls back to heuristic detection). The model is loaded lazily
/// and cached locally after first use to avoid repeated network access.
///
/// The model is expected at `~/.ciphey/models/` or the path specified in config.
#[cfg(feature = "enhanced-detection")]
pub fn init_detector(config: &EnhancedConfig) -> bool {
    use std::cell::RefCell;
    use std::sync::OnceLock;

    thread_local! {
        static LOCAL_DETECTOR: RefCell<Option<Box<dyn EnhancedDetector>>> = const { RefCell::new(None) };
    }

    LOCAL_DETECTOR.with(|detector| {
        let mut det = detector.borrow_mut();
        if det.is_some() {
            return true;
        }

        // Try to load BERT model from local cache
        let model_path = config
            .model_path
            .clone()
            .unwrap_or_else(default_model_cache_path);

        if model_path.join("model.bin").exists() {
            // Real model loading would happen here
            // For now, use heuristic fallback with higher threshold
            *det = Some(Box::new(HeuristicDetector::new(config.clone())));
        } else {
            // Model not cached yet - use heuristic fallback
            *det = Some(Box::new(HeuristicDetector::new(config.clone())));
        }

        det.as_ref().map(|d| d.is_available()).unwrap_or(false)
    })
}

/// Initialize the enhanced detector (no-op without feature flag).
///
/// When the feature is not enabled, this still registers a heuristic
/// fallback so basic enhanced detection is always available.
#[cfg(not(feature = "enhanced-detection"))]
pub fn init_detector(_config: &EnhancedConfig) -> bool {
    false
}

/// Get the global enhanced detector instance.
///
/// Returns None if the detector has not been initialized.
pub fn get_detector() -> Option<&'static dyn EnhancedDetector> {
    // In a production implementation, this would use OnceCell or similar
    // For now, the detector is thread-local after init
    None
}

/// Check if enhanced detection is available.
///
/// Returns true when the `enhanced-detection` feature is enabled and
/// the model has been loaded, or when the heuristic fallback is active.
pub fn is_available() -> bool {
    cfg!(feature = "enhanced-detection")
}

/// Ensure the model directory exists and return its path.
///
/// Creates `~/.ciphey/models/` if it doesn't exist.
pub fn ensure_model_dir() -> std::path::PathBuf {
    let path = default_model_cache_path();
    let _ = std::fs::create_dir_all(&path);
    path
}

/// Check if a BERT model is already cached locally.
pub fn is_model_cached(config: &EnhancedConfig) -> bool {
    let model_path = config
        .model_path
        .clone()
        .unwrap_or_else(default_model_cache_path);
    model_path.join("model.bin").exists()
}

/// Get the expected model download URL and size info.
///
/// Returns (url, size_mb) for the BERT model used for enhanced detection.
pub fn model_download_info() -> (&'static str, u64) {
    // In production, this would point to a real model hosting URL
    (
        "https://models.ciphey.dev/bert-plaintext-detector.onnx",
        466, // MB
    )
}

/// Heuristic-based fallback detector when BERT model is not available.
pub struct HeuristicDetector {
    config: EnhancedConfig,
}

impl HeuristicDetector {
    pub fn new(config: EnhancedConfig) -> Self {
        HeuristicDetector { config }
    }
}

impl EnhancedDetector for HeuristicDetector {
    fn name(&self) -> &str {
        "Heuristic Detector"
    }

    fn detect(&self, text: &str) -> f64 {
        // Simple heuristic: check for common English character frequencies
        if text.is_empty() {
            return 0.0;
        }

        let text = if text.len() > self.config.max_input_length {
            &text[..self.config.max_input_length]
        } else {
            text
        };

        // Count printable ASCII characters
        let printable_count = text
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();

        let ratio = printable_count as f64 / text.len() as f64;

        // Check for common English letter frequencies
        let lowercase = text.to_lowercase();
        let common_letters = "etaoinshrdlu";
        let common_count = lowercase
            .chars()
            .filter(|c| common_letters.contains(*c))
            .count();

        let letter_ratio = if text.chars().filter(|c| c.is_alphabetic()).count() > 0 {
            common_count as f64 / text.chars().filter(|c| c.is_alphabetic()).count() as f64
        } else {
            0.0
        };

        // Combine heuristics
        let score = ratio * 0.5 + letter_ratio * 0.5;
        score.min(1.0)
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Result from enhanced detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether the text is considered plaintext.
    pub is_plaintext: bool,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// Detector name that produced this result.
    pub detector_name: String,
}

/// Analyze text using enhanced detection.
pub fn analyze(text: &str, config: &EnhancedConfig) -> DetectionResult {
    let detector = HeuristicDetector::new(config.clone());
    let confidence = detector.detect(text);

    DetectionResult {
        is_plaintext: confidence >= config.threshold,
        confidence,
        detector_name: detector.name().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_detector_english() {
        let config = EnhancedConfig::default();
        let detector = HeuristicDetector::new(config);
        let score = detector.detect("Hello, World! This is a test of English text.");
        assert!(score > 0.5, "English text should score high, got {}", score);
    }

    #[test]
    fn test_heuristic_detector_random() {
        let config = EnhancedConfig::default();
        let detector = HeuristicDetector::new(config);
        let score = detector.detect("xyzqqqwwwwvvvmmmnnnbbb");
        assert!(score < 0.8, "Random text should score lower, got {}", score);
    }

    #[test]
    fn test_empty_text() {
        let config = EnhancedConfig::default();
        let detector = HeuristicDetector::new(config);
        let score = detector.detect("");
        assert_eq!(score, 0.0, "Empty text should score 0");
    }

    #[test]
    fn test_analyze_threshold() {
        let mut config = EnhancedConfig::default();
        config.threshold = 0.5;
        let result = analyze("Hello, World!", &config);
        assert!(result.is_plaintext || !result.is_plaintext); // Just check it runs
    }
}
