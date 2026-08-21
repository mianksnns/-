//! Python bindings for ciphey.
//!
//! Exposes the library's core [`crate::perform_cracking`] function to Python
//! directly, replacing the fragile subprocess+ANSI-parsing approach in
//! `ciphey_api.py`.
//!
//! Build with: `cargo build --release --features python`
//! The resulting module is `target/release/libciphey.so`.

use crate::config::Config;
use crate::perform_cracking;
use log::debug;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// The result of a decoding attempt, exposed to Python.
#[pyclass]
#[derive(Debug, Clone)]
struct CipheyResult {
    /// True if the input was successfully decoded.
    #[pyo3(get)]
    success: bool,
    /// The decoded plaintext, if any.
    #[pyo3(get)]
    plaintext: Option<String>,
    /// The decoders used, in order, e.g. ["Base64", "Hex"].
    #[pyo3(get)]
    path: Vec<String>,
    /// The keys used by each decoder, when applicable.
    #[pyo3(get)]
    keys: Vec<Option<String>>,
}

/// Decode text using ciphey.
///
/// Args:
///     text (str): The encoded/encrypted text to decode.
///     timeout (int, optional): Timeout in seconds. Defaults to 2.
///     top_results (bool, optional): Collect all plaintexts until timeout.
///
/// Returns:
///     CipheyResult: The decoding result.
#[pyfunction]
#[pyo3(signature = (text, timeout=None, top_results=None))]
fn crack(text: &str, timeout: Option<u32>, top_results: Option<bool>) -> PyResult<CipheyResult> {
    let mut config = Config::default();
    if let Some(t) = timeout {
        config.timeout = t;
    }
    if let Some(t) = top_results {
        config.top_results = t;
    }
    // The library is not interactive; always disable the human checker.
    config.human_checker_on = false;
    config.api_mode = true;

    debug!("calling perform_cracking from Python with text {:?}", text);
    let result = perform_cracking(text, config);
    let Some(result) = result else {
        return Ok(CipheyResult {
            success: false,
            plaintext: None,
            path: Vec::new(),
            keys: Vec::new(),
        });
    };

    let path = result
        .path
        .iter()
        .map(|cr| cr.decoder.to_string())
        .collect();
    let keys = result.path.iter().map(|cr| cr.key.clone()).collect();
    let plaintext = result.text.first().cloned();

    Ok(CipheyResult {
        success: plaintext.is_some(),
        plaintext,
        path,
        keys,
    })
}

/// A helper to raise a typed error if no text is provided.
#[pyfunction]
#[pyo3(signature = (text))]
fn is_plaintext(text: &str) -> PyResult<bool> {
    if text.is_empty() {
        return Err(PyValueError::new_err("text must not be empty"));
    }
    let mut config = Config::default();
    config.human_checker_on = false;
    config.api_mode = true;
    Ok(perform_cracking(text, config).is_some())
}

/// The ciphey Python module.
#[pymodule]
fn ciphey(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(crack, m)?)?;
    m.add_function(wrap_pyfunction!(is_plaintext, m)?)?;
    m.add_class::<CipheyResult>()?;
    Ok(())
}
