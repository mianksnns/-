//! Security and resource limit protections.
//!
//! This module provides DoS protection, input validation, and resource limits
//! to prevent malicious or accidental resource exhaustion.

/// Maximum allowed input size in bytes (10 MB).
pub const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum depth for search algorithms.
pub const MAX_SEARCH_DEPTH: u32 = 100;

/// Maximum number of search nodes to explore.
pub const MAX_SEARCH_NODES: usize = 1_000_000;

/// Maximum decompression ratio (compressed size * ratio = max decompressed size).
pub const MAX_DECOMPRESSION_RATIO: usize = 2000;

/// Maximum compressed input size in bytes (64 MB).
pub const MAX_COMPRESSED_INPUT_SIZE: usize = 64 * 1024 * 1024;

/// Maximum regex execution time in milliseconds.
pub const MAX_REGEX_EXECUTION_MS: u64 = 5000;

/// Maximum brainfuck execution steps.
pub const MAX_BRAINFUCK_STEPS: usize = 1_000_000;

/// Maximum brainfuck execution time in milliseconds.
pub const MAX_BRAINFUCK_EXECUTION_MS: u64 = 10_000;

/// Maximum number of results to collect.
pub const MAX_RESULTS: usize = 1000;

/// Validates input size and returns an error if it exceeds limits.
pub fn validate_input_size(input: &str) -> Result<(), ResourceLimitError> {
    let size = input.len();
    if size > MAX_INPUT_SIZE {
        Err(ResourceLimitError::InputTooLarge {
            size,
            max_size: MAX_INPUT_SIZE,
        })
    } else {
        Ok(())
    }
}

/// Resource limit errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceLimitError {
    /// Input exceeds maximum allowed size.
    InputTooLarge {
        /// Actual input size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max_size: usize,
    },
    /// Search exceeded maximum depth.
    SearchDepthExceeded {
        /// Current depth.
        depth: u32,
        /// Maximum allowed depth.
        max_depth: u32,
    },
    /// Search exceeded maximum number of nodes.
    SearchNodesExceeded {
        /// Current node count.
        nodes: usize,
        /// Maximum allowed nodes.
        max_nodes: usize,
    },
    /// Decompression ratio exceeded limit (possible zip bomb).
    DecompressionRatioExceeded {
        /// Actual ratio.
        ratio: usize,
        /// Maximum allowed ratio.
        max_ratio: usize,
    },
    /// Regex execution timed out.
    RegexTimeout {
        /// Execution time in milliseconds.
        elapsed_ms: u64,
        /// Maximum allowed time in milliseconds.
        max_ms: u64,
    },
    /// Brainfuck execution timed out.
    BrainfuckTimeout {
        /// Execution time in milliseconds.
        elapsed_ms: u64,
        /// Maximum allowed time in milliseconds.
        max_ms: u64,
    },
}

impl std::fmt::Display for ResourceLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceLimitError::InputTooLarge { size, max_size } => {
                write!(
                    f,
                    "Input too large: {} bytes (max: {} bytes)",
                    size, max_size
                )
            }
            ResourceLimitError::SearchDepthExceeded { depth, max_depth } => {
                write!(f, "Search depth exceeded: {} (max: {})", depth, max_depth)
            }
            ResourceLimitError::SearchNodesExceeded { nodes, max_nodes } => {
                write!(f, "Search nodes exceeded: {} (max: {})", nodes, max_nodes)
            }
            ResourceLimitError::DecompressionRatioExceeded { ratio, max_ratio } => {
                write!(
                    f,
                    "Decompression ratio exceeded: {}x (max: {}x) - possible zip bomb",
                    ratio, max_ratio
                )
            }
            ResourceLimitError::RegexTimeout { elapsed_ms, max_ms } => {
                write!(
                    f,
                    "Regex execution timed out: {}ms (max: {}ms)",
                    elapsed_ms, max_ms
                )
            }
            ResourceLimitError::BrainfuckTimeout { elapsed_ms, max_ms } => {
                write!(
                    f,
                    "Brainfuck execution timed out: {}ms (max: {}ms)",
                    elapsed_ms, max_ms
                )
            }
        }
    }
}

impl std::error::Error for ResourceLimitError {}

/// Resource tracker for monitoring search progress.
#[derive(Debug)]
pub struct ResourceTracker {
    /// Current search depth.
    pub current_depth: u32,
    /// Number of nodes explored.
    pub nodes_explored: usize,
    /// Start time for timeout tracking.
    pub start_time: std::time::Instant,
    /// Maximum allowed depth.
    pub max_depth: u32,
    /// Maximum allowed nodes.
    pub max_nodes: usize,
    /// Maximum allowed execution time in milliseconds.
    pub max_execution_ms: u64,
}

impl ResourceTracker {
    /// Create a new resource tracker with default limits.
    pub fn new() -> Self {
        ResourceTracker {
            current_depth: 0,
            nodes_explored: 0,
            start_time: std::time::Instant::now(),
            max_depth: MAX_SEARCH_DEPTH,
            max_nodes: MAX_SEARCH_NODES,
            max_execution_ms: 30_000, // 30 seconds default
        }
    }

    /// Create a new resource tracker with custom limits.
    pub fn with_limits(max_depth: u32, max_nodes: usize, max_execution_ms: u64) -> Self {
        ResourceTracker {
            current_depth: 0,
            nodes_explored: 0,
            start_time: std::time::Instant::now(),
            max_depth,
            max_nodes,
            max_execution_ms,
        }
    }

    /// Record that a node has been explored.
    pub fn record_node(&mut self) {
        self.nodes_explored += 1;
    }

    /// Update the current depth.
    pub fn update_depth(&mut self, depth: u32) {
        self.current_depth = depth;
    }

    /// Check if the search should stop due to resource limits.
    pub fn should_stop(&self) -> Option<ResourceLimitError> {
        if self.current_depth > self.max_depth {
            Some(ResourceLimitError::SearchDepthExceeded {
                depth: self.current_depth,
                max_depth: self.max_depth,
            })
        } else if self.nodes_explored > self.max_nodes {
            Some(ResourceLimitError::SearchNodesExceeded {
                nodes: self.nodes_explored,
                max_nodes: self.max_nodes,
            })
        } else {
            let elapsed = self.start_time.elapsed().as_millis() as u64;
            if elapsed > self.max_execution_ms {
                Some(ResourceLimitError::RegexTimeout {
                    elapsed_ms: elapsed,
                    max_ms: self.max_execution_ms,
                })
            } else {
                None
            }
        }
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

impl Default for ResourceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Timeout guard for measuring execution time.
pub struct TimeoutGuard {
    start: std::time::Instant,
    limit_ms: u64,
}

impl TimeoutGuard {
    /// Create a new timeout guard.
    pub fn new(limit_ms: u64) -> Self {
        TimeoutGuard {
            start: std::time::Instant::now(),
            limit_ms,
        }
    }

    /// Check if the time limit has been exceeded.
    pub fn is_expired(&self) -> bool {
        self.start.elapsed().as_millis() as u64 > self.limit_ms
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_input_size_ok() {
        let input = "small input";
        assert!(validate_input_size(input).is_ok());
    }

    #[test]
    fn test_validate_input_size_too_large() {
        let input = "x".repeat(MAX_INPUT_SIZE + 1);
        let result = validate_input_size(&input);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ResourceLimitError::InputTooLarge {
                size: MAX_INPUT_SIZE + 1,
                max_size: MAX_INPUT_SIZE,
            }
        );
    }

    #[test]
    fn test_resource_tracker_default() {
        let tracker = ResourceTracker::new();
        assert_eq!(tracker.current_depth, 0);
        assert_eq!(tracker.nodes_explored, 0);
        assert!(tracker.should_stop().is_none());
    }

    #[test]
    fn test_resource_tracker_depth_limit() {
        let mut tracker = ResourceTracker::with_limits(10, 1000, 30000);
        tracker.update_depth(11);
        let result = tracker.should_stop();
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            ResourceLimitError::SearchDepthExceeded {
                depth: 11,
                max_depth: 10,
            }
        );
    }

    #[test]
    fn test_resource_tracker_node_limit() {
        let mut tracker = ResourceTracker::with_limits(100, 10, 30000);
        for _ in 0..11 {
            tracker.record_node();
        }
        let result = tracker.should_stop();
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            ResourceLimitError::SearchNodesExceeded {
                nodes: 11,
                max_nodes: 10,
            }
        );
    }

    #[test]
    fn test_timeout_guard() {
        let guard = TimeoutGuard::new(10000);
        assert!(!guard.is_expired());
    }

    #[test]
    fn test_display_errors() {
        let err = ResourceLimitError::InputTooLarge {
            size: 100,
            max_size: 50,
        };
        assert!(err.to_string().contains("Input too large"));

        let err = ResourceLimitError::DecompressionRatioExceeded {
            ratio: 5000,
            max_ratio: 2000,
        };
        assert!(err.to_string().contains("zip bomb"));
    }
}
