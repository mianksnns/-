//! # Streaming / Incremental Processing Module
//!
//! Handles large inputs by splitting them into overlapping chunks,
//! processing each chunk independently, and merging results.
//!
//! ## Use Cases
//!
//! - Large files that shouldn't be loaded entirely into memory
//! - Network streams or piped input
//! - Timeout-bounded processing where partial results are valuable

use crate::searchers::search_for_plaintext;
use crate::DecoderResult;
use log::{debug, trace};

/// Default chunk size in characters
pub const DEFAULT_CHUNK_SIZE: usize = 1024;

/// Default overlap between chunks in characters
pub const DEFAULT_OVERLAP_SIZE: usize = 100;

/// Configuration for streaming processing
#[derive(Debug, Clone)]
pub struct StreamConfig {
    pub chunk_size: usize,
    pub overlap_size: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        StreamConfig {
            chunk_size: DEFAULT_CHUNK_SIZE,
            overlap_size: DEFAULT_OVERLAP_SIZE,
        }
    }
}

/// Split input into overlapping chunks
///
/// Returns a vector of (chunk_text, is_last) tuples.
/// The overlap ensures that patterns spanning chunk boundaries are not missed.
pub fn split_into_chunks(input: &str, config: &StreamConfig) -> Vec<(String, bool)> {
    let mut chunks = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let total_len = chars.len();

    if total_len <= config.chunk_size {
        chunks.push((input.to_string(), true));
        return chunks;
    }

    let mut offset = 0;
    loop {
        let end = (offset + config.chunk_size).min(total_len);
        let chunk: String = chars[offset..end].iter().collect();
        let is_last = end >= total_len;

        chunks.push((chunk, is_last));

        if is_last {
            break;
        }

        offset += config.chunk_size - config.overlap_size;
        if offset >= total_len {
            break;
        }
    }

    chunks
}

/// Process input in streaming fashion
///
/// Returns the first successful result found across all chunks.
/// If no chunk produces a result, returns None.
pub fn process_streaming(input: &str, config: StreamConfig) -> Option<DecoderResult> {
    let chunks = split_into_chunks(input, &config);
    debug!(
        "Streaming: split input into {} chunks (chunk_size={}, overlap={})",
        chunks.len(),
        config.chunk_size,
        config.overlap_size
    );

    for (i, (chunk, is_last)) in chunks.iter().enumerate() {
        trace!("Processing chunk {}/{}", i + 1, chunks.len());

        if let Some(result) = search_for_plaintext(chunk.clone()) {
            debug!("Streaming: found result in chunk {}", i + 1);
            return Some(result);
        }

        if *is_last {
            break;
        }
    }

    debug!("Streaming: no result found in any chunk");
    None
}

/// Process input in streaming fashion, collecting all chunk results
///
/// Returns results from all chunks that produced successful decodes.
pub fn process_streaming_collect_all(input: &str, config: StreamConfig) -> Vec<DecoderResult> {
    let chunks = split_into_chunks(input, &config);
    let mut results = Vec::new();

    for (i, (chunk, is_last)) in chunks.iter().enumerate() {
        trace!("Processing chunk {}/{}", i + 1, chunks.len());

        if let Some(result) = search_for_plaintext(chunk.clone()) {
            results.push(result);
        }

        if *is_last {
            break;
        }
    }

    results
}

/// Check if input should use streaming based on size
pub fn should_use_stream(input_len: usize, chunk_size: Option<usize>) -> bool {
    match chunk_size {
        Some(size) => input_len > size,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_small_input() {
        let config = StreamConfig::default();
        let chunks = split_into_chunks("Hello World", &config);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, "Hello World");
        assert!(chunks[0].1);
    }

    #[test]
    fn test_split_large_input() {
        let config = StreamConfig {
            chunk_size: 10,
            overlap_size: 2,
        };
        let input = "abcdefghijklmnopqrstuvwxyz";
        let chunks = split_into_chunks(input, &config);

        assert!(chunks.len() > 1);
        assert_eq!(chunks[0].0, "abcdefghij");
        assert_eq!(chunks[1].0, "ijklmnopqr");
        assert!(chunks.last().unwrap().1);
    }

    #[test]
    fn test_split_with_overlap() {
        let config = StreamConfig {
            chunk_size: 5,
            overlap_size: 2,
        };
        let input = "12345678901234567890";
        let chunks = split_into_chunks(input, &config);

        assert_eq!(chunks[0].0, "12345");
        assert_eq!(chunks[1].0, "45678");
        assert_eq!(chunks[2].0, "78901");
        assert_eq!(chunks[3].0, "01234");
        assert_eq!(chunks[4].0, "34567");
        assert_eq!(chunks[5].0, "67890");
        assert!(chunks.last().unwrap().1);
    }

    #[test]
    fn test_should_use_stream() {
        assert!(should_use_stream(2048, Some(1024)));
        assert!(!should_use_stream(512, Some(1024)));
        assert!(!should_use_stream(2048, None));
    }

    #[test]
    fn test_process_streaming_empty() {
        let config = StreamConfig::default();
        let result = process_streaming("", config);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_streaming_base64_chunk() {
        let config = StreamConfig {
            chunk_size: 1024,
            overlap_size: 100,
        };
        let result = process_streaming("SGVsbG8gV29ybGQ=", config);
        assert!(result.is_some());
        if let Some(decoder_result) = result {
            assert_eq!(decoder_result.text[0], "Hello World");
        }
    }
}
