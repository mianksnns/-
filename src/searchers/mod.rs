//! The search algorithm decides what encryptions to do next
//! And also runs the decryption modules
//! Click here to find out more:
//! https://broadleaf-angora-7db.notion.site/Search-Nodes-Edges-What-should-they-look-like-b74c43ca7ac341a1a5cfdbeb84a7eef0

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use crossbeam::channel::bounded;
use serde::{Deserialize, Serialize};

use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::filtration_system::{filter_and_get_decoders, MyResults};
use crate::{timer, DecoderResult};
/// This module provides access to the A* search algorithm
/// which uses a heuristic to prioritize decoders.
mod astar;
/// Beam search implementation for faster but less exhaustive decoding.
mod beam_search;
/// This module provides access to the breadth first search
/// which searches for the plaintext.
mod bfs;
/// This module contains helper functions used by the A* search algorithm.
mod helper_functions;
/// Result ranking and confidence scoring for decoded results.
pub mod result_ranker;
/// Streaming/chunked processing for large inputs.
mod streaming;

/// Available search strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStrategy {
    /// A* search (default, best-first with heuristic).
    AStar,
    /// Beam search (limited width, faster but less exhaustive).
    BeamSearch,
}

impl Default for SearchStrategy {
    fn default() -> Self {
        SearchStrategy::AStar
    }
}

impl std::str::FromStr for SearchStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "astar" | "a*" => Ok(SearchStrategy::AStar),
            "beam" | "beam_search" | "beamsearch" => Ok(SearchStrategy::BeamSearch),
            _ => Err(format!("Unknown search strategy: {}", s)),
        }
    }
}

/*pub struct Tree <'a> {
    // Wrap in a box because
    // https://doc.rust-lang.org/error-index.html#E0072
    parent: &'a Box<Option<Tree<'a>>>,
    value: String
}*/

/// Performs the search algorithm.
///
/// When we perform the decryptions, we will get a vector of Some<String>
/// We need to loop through these and determine:
/// 1. Did we reach our exit condition?
/// 2. If not, create new nodes out of them and add them to the queue.
///
///    We can return an Option? An Enum? And then match on that
///    So if we return CrackSuccess we return
///    Else if we return an array, we add it to the children and go again.
pub fn search_for_plaintext(input: String) -> Option<DecoderResult> {
    let config = get_config();

    if streaming::should_use_stream(input.len(), config.stream_chunk_size) {
        let stream_config = streaming::StreamConfig {
            chunk_size: config.stream_chunk_size.unwrap_or(streaming::DEFAULT_CHUNK_SIZE),
            overlap_size: streaming::DEFAULT_OVERLAP_SIZE,
        };
        return streaming::process_streaming(&input, stream_config);
    }

    let timeout = config.timeout;
    let timer = timer::start(timeout);

    let (result_sender, result_recv) = bounded::<Option<DecoderResult>>(1);
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();

    let handle = match config.search_strategy {
        SearchStrategy::BeamSearch => {
            thread::spawn(move || beam_search::beam_search(input, result_sender, s))
        }
        SearchStrategy::AStar => thread::spawn(move || astar::astar(input, result_sender, s)),
    };

    let top_results_mode = config.top_results;
    let mut first_result = None;

    loop {
        if let Ok(res) = result_recv.try_recv() {
            log::info!("Found potential plaintext result");
            log::trace!("Result details: {:?}", res);

            if top_results_mode {
                if first_result.is_none() {
                    first_result = res;
                }
            } else {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                handle.join().unwrap();
                return res;
            }
        }

        if timer.try_recv().is_ok() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            log::info!("Search timer expired");
            handle.join().unwrap();

            if top_results_mode {
                return first_result;
            }

            return None;
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Performs the decodings by getting all of the decoders
/// and calling `.run` which in turn loops through them and calls
/// `.crack()`.
#[allow(dead_code)]
fn perform_decoding(text: &DecoderResult) -> MyResults {
    let decoders = filter_and_get_decoders(text);
    let athena_checker = Checker::<Athena>::new();
    let checker = CheckerTypes::CheckAthena(athena_checker);
    decoders.run(&text.text[0], checker)
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://github.com/bee-san/ciphey/pull/14/files#diff-b8829c7e292562666c7fa5934de7b478c4a5de46d92e42c46215ac4d9ff89db2R37
    // Only used for tests!
    fn exit_condition(input: &str) -> bool {
        // use Athena Checker from checkers module
        // call check(input)
        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        checker.check(input).is_identified
    }

    #[test]
    fn exit_condition_succeeds() {
        let result = exit_condition("https://www.google.com");
        assert!(result);
    }
    #[test]
    fn exit_condition_fails() {
        let result = exit_condition("vjkrerkdnxhrfjekfdjexk");
        assert!(!result);
    }

    #[test]
    fn perform_decoding_succeeds() {
        let dc = DecoderResult::_new("aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbQ==");
        let result = perform_decoding(&dc);
        assert!(
            result
                ._break_value()
                .expect("expected successful value, none found")
                .success
        );
        //TODO assert that the plaintext is correct by looping over the vector
    }
    #[test]
    fn perform_decoding_succeeds_empty_string() {
        // Some decoders like base64 return even when the string is empty.
        let dc = DecoderResult::_new("");
        let result = perform_decoding(&dc);
        assert!(result._break_value().is_none());
    }
}
