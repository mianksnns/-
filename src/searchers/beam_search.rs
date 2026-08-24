//! # Beam Search Implementation for Decoding
//!
//! An alternative to A* search that limits the number of nodes at each level
//! to a fixed beam width. This trades completeness for speed and memory efficiency.
//!
//! ## Algorithm Overview
//!
//! 1. Start with the initial input text
//! 2. At each level:
//!    - Expand all nodes from the current beam
//!    - Score all expanded nodes using the same heuristic as A*
//!    - Keep only the top-W nodes (beam width)
//! 3. Continue until a plaintext is found or the search space is exhausted

use crate::cli_pretty_printing;
use crate::cli_pretty_printing::decoded_how_many_times;
use crate::filtration_system::{get_all_decoders, get_decoder_tagged_decoders, MyResults};
use crossbeam::channel::Sender;
use dashmap::DashSet;
use log::{debug, trace};
use rayon::prelude::*;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AtomicOrdering};
use std::sync::Arc;

use crate::checkers::athena::Athena;
use crate::checkers::checker_type::{Check, Checker};
use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::searchers::helper_functions::{calculate_string_worth, generate_heuristic};
use crate::storage::wait_athena_storage;
use crate::DecoderResult;

/// Maximum depth for search
const MAX_DEPTH: u32 = 100;

/// Default beam width if not configured
const DEFAULT_BEAM_WIDTH: usize = 5;

/// Number of nodes to process in parallel
const PARALLEL_BATCH_SIZE: usize = 10;

/// Beam search node with priority based on f = g + h
#[derive(Debug, Clone)]
struct BeamNode {
    state: DecoderResult,
    cost: u32,
    total_cost: f32,
    next_decoder_name: Option<String>,
}

impl Ord for BeamNode {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .total_cost
            .partial_cmp(&self.total_cost)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for BeamNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for BeamNode {
    fn eq(&self, other: &Self) -> bool {
        self.total_cost == other.total_cost
    }
}

impl Eq for BeamNode {}

/// Expand a single node and return new nodes
fn expand_node(
    node: &BeamNode,
    seen_strings: &DashSet<String, ahash::RandomState>,
    stop: &Arc<AtomicBool>,
) -> Vec<BeamNode> {
    let mut new_nodes = Vec::new();

    if stop.load(AtomicOrdering::Relaxed) {
        return new_nodes;
    }

    let mut decoders = if let Some(decoder_name) = &node.next_decoder_name {
        trace!("Using specific decoder: {}", decoder_name);
        crate::filtration_system::get_decoder_by_name(decoder_name)
    } else {
        get_decoder_tagged_decoders(&node.state)
    };

    if let Some(last_decoder) = node.state.path.last() {
        if last_decoder.checker_description.contains("reciprocal") {
            let excluded_name = &last_decoder.decoder;
            decoders
                .components
                .retain(|d| d.get_name() != *excluded_name);
        }
    }

    if !decoders.components.is_empty() {
        if stop.load(AtomicOrdering::Relaxed) {
            return new_nodes;
        }

        let athena_checker = Checker::<Athena>::new();
        let checker = CheckerTypes::CheckAthena(athena_checker);
        let decoder_results = decoders.run(&node.state.text[0], checker);

        match decoder_results {
            MyResults::Break(res) => {
                if res.success {
                    let mut decoders_used = node.state.path.clone();
                    let text = res.unencrypted_text.clone().unwrap_or_default();
                    decoders_used.push(res.clone());

                    let result_node = BeamNode {
                        state: DecoderResult {
                            text: text.clone(),
                            path: decoders_used,
                        },
                        cost: node.cost + 1,
                        total_cost: -1000.0,
                        next_decoder_name: Some("__RESULT__".to_string()),
                    };
                    new_nodes.push(result_node);
                }
            }
            MyResults::Continue(results) => {
                for r in results {
                    if stop.load(AtomicOrdering::Relaxed) {
                        break;
                    }

                    let mut decoders_used = node.state.path.clone();
                    let text = r.unencrypted_text.clone().unwrap_or_default();

                    if text.is_empty() || !calculate_string_worth(&text[0]) {
                        continue;
                    }

                    let text_hash = text[0].clone();
                    if !seen_strings.insert(text_hash) {
                        continue;
                    }

                    decoders_used.push(r.clone());
                    let cost = node.cost + 1;
                    let heuristic = generate_heuristic(&text[0], &decoders_used, &None);
                    let total_cost = cost as f32 + heuristic;

                    new_nodes.push(BeamNode {
                        state: DecoderResult {
                            text,
                            path: decoders_used,
                        },
                        cost,
                        total_cost,
                        next_decoder_name: Some(r.decoder.to_string()),
                    });
                }
            }
        }
    }

    if new_nodes.is_empty() {
        let all_decoders = get_all_decoders();

        for decoder in all_decoders.components {
            if stop.load(AtomicOrdering::Relaxed) {
                break;
            }

            if let Some(last_decoder) = node.state.path.last() {
                if last_decoder.decoder == decoder.get_name() {
                    continue;
                }
                if last_decoder.checker_description.contains("reciprocal")
                    && last_decoder.decoder == decoder.get_name()
                {
                    continue;
                }
            }

            let athena_checker = Checker::<Athena>::new();
            let checker = CheckerTypes::CheckAthena(athena_checker);
            let result = decoder.crack(&node.state.text[0], &checker);

            if let Some(decoded_text) = &result.unencrypted_text {
                if let Some(first_text) = decoded_text.first() {
                    if first_text.is_empty() {
                        continue;
                    }

                    let text_hash = first_text.clone();
                    if !seen_strings.insert(text_hash) {
                        continue;
                    }

                    let mut decoders_used = node.state.path.clone();
                    decoders_used.push(result.clone());

                    let cost = node.cost + 1;
                    let heuristic = generate_heuristic(first_text, &decoders_used, &None);
                    let total_cost = cost as f32 + heuristic;

                    new_nodes.push(BeamNode {
                        state: DecoderResult {
                            text: decoded_text.clone(),
                            path: decoders_used,
                        },
                        cost,
                        total_cost,
                        next_decoder_name: Some(decoder.get_name().to_string()),
                    });
                }
            }
        }
    }

    new_nodes
}

/// Prune nodes to keep only the top `beam_width` nodes
fn prune_to_beam_width(nodes: Vec<BeamNode>, beam_width: usize) -> Vec<BeamNode> {
    if nodes.len() <= beam_width {
        return nodes;
    }

    let mut heap = BinaryHeap::from(nodes);
    let mut pruned = Vec::with_capacity(beam_width);
    for _ in 0..beam_width {
        if let Some(node) = heap.pop() {
            pruned.push(node);
        }
    }
    pruned
}

/// Beam search implementation
pub fn beam_search(
    input: String,
    result_sender: Sender<Option<DecoderResult>>,
    stop: Arc<AtomicBool>,
) {
    let config = get_config();
    let beam_width = config.beam_width.unwrap_or(DEFAULT_BEAM_WIDTH);

    let initial = DecoderResult {
        text: vec![input],
        path: vec![],
    };

    let seen_strings = DashSet::with_hasher(ahash::RandomState::new());
    let seen_results: DashSet<String, ahash::RandomState> =
        DashSet::with_hasher(ahash::RandomState::new());

    let initial_total_cost = generate_heuristic(&initial.text[0], &initial.path, &None);

    let mut current_beam: Vec<BeamNode> = vec![BeamNode {
        state: initial,
        cost: 0,
        total_cost: initial_total_cost,
        next_decoder_name: None,
    }];

    let curr_depth = Arc::new(AtomicU32::new(1));

    while !current_beam.is_empty() && !stop.load(AtomicOrdering::Relaxed) {
        let depth = curr_depth.load(AtomicOrdering::Relaxed);
        trace!(
            "Beam search depth: {}, beam size: {}",
            depth,
            current_beam.len()
        );

        let batch_size = std::cmp::min(PARALLEL_BATCH_SIZE, current_beam.len());
        let batch: Vec<BeamNode> = current_beam.drain(..batch_size).collect();

        let new_nodes: Vec<BeamNode> = batch
            .par_iter()
            .flat_map(|node| expand_node(node, &seen_strings, &stop))
            .collect();

        for node in &new_nodes {
            if let Some(decoder_name) = &node.next_decoder_name {
                if decoder_name == "__RESULT__" {
                    if let Some(text) = node.state.text.first() {
                        let result_hash = text.clone();
                        if !seen_results.insert(result_hash) {
                            continue;
                        }
                    }

                    decoded_how_many_times(depth);

                    cli_pretty_printing::success(&format!(
                        "beam_search.rs - Sending successful result with {} decoders",
                        node.state.path.len()
                    ));

                    if config.top_results {
                        if let Some(plaintext) = node.state.text.first() {
                            let decoder_name = node
                                .state
                                .path
                                .last()
                                .map(|d| d.decoder)
                                .unwrap_or("Unknown");
                            let checker_name = node
                                .state
                                .path
                                .last()
                                .map(|d| d.checker_name)
                                .unwrap_or("Unknown");

                            if !checker_name.is_empty() && checker_name != "Unknown" {
                                wait_athena_storage::add_plaintext_result(
                                    plaintext.clone(),
                                    format!("Decoded at depth {}", depth),
                                    checker_name.to_string(),
                                    decoder_name.to_string(),
                                );
                            }
                        }
                    }

                    result_sender
                        .send(Some(node.state.clone()))
                        .expect("Should successfully send the result");

                    if !config.top_results {
                        stop.store(true, AtomicOrdering::Relaxed);
                        return;
                    }
                }
            }
        }

        let non_result_nodes: Vec<BeamNode> = new_nodes
            .into_iter()
            .filter(|node| {
                node.next_decoder_name
                    .as_ref()
                    .map(|n| n != "__RESULT__")
                    .unwrap_or(true)
            })
            .collect();

        current_beam.extend(non_result_nodes);
        current_beam = prune_to_beam_width(current_beam, beam_width);

        curr_depth.fetch_add(1, AtomicOrdering::Relaxed);

        if depth >= MAX_DEPTH {
            debug!("Beam search reached maximum depth");
            break;
        }
    }

    if !stop.load(AtomicOrdering::Relaxed) {
        result_sender
            .send(None)
            .expect("Should successfully send the result");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::channel::bounded;

    #[test]
    fn test_beam_search_empty_input() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));

        beam_search("".to_string(), sender, stop);

        let result = receiver.recv().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_beam_search_base64() {
        let (sender, receiver) = bounded::<Option<DecoderResult>>(1);
        let stop = Arc::new(AtomicBool::new(false));

        let input = "SGVsbG8gV29ybGQ=".to_string();
        let stop_clone = stop.clone();

        std::thread::spawn(move || {
            beam_search(input, sender, stop_clone);
        });

        let result = receiver.recv().unwrap();
        assert!(result.is_some());
        if let Some(decoder_result) = result {
            assert!(!decoder_result.path.is_empty());
        }
    }

    #[test]
    fn test_prune_to_beam_width() {
        let nodes: Vec<BeamNode> = (0..10)
            .map(|i| BeamNode {
                state: DecoderResult {
                    text: vec![format!("text_{}", i)],
                    path: vec![],
                },
                cost: i as u32,
                total_cost: i as f32,
                next_decoder_name: None,
            })
            .collect();

        let pruned = prune_to_beam_width(nodes, 3);
        assert_eq!(pruned.len(), 3);

        assert!((pruned[0].total_cost - 0.0).abs() < f32::EPSILON);
        assert!((pruned[1].total_cost - 1.0).abs() < f32::EPSILON);
        assert!((pruned[2].total_cost - 2.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_prune_smaller_than_beam() {
        let nodes: Vec<BeamNode> = (0..3)
            .map(|i| BeamNode {
                state: DecoderResult {
                    text: vec![format!("text_{}", i)],
                    path: vec![],
                },
                cost: i as u32,
                total_cost: i as f32,
                next_decoder_name: None,
            })
            .collect();

        let pruned = prune_to_beam_width(nodes, 5);
        assert_eq!(pruned.len(), 3);
    }
}
