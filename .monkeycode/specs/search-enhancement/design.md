# Search Enhancement Design

## Overview

This design document covers improvements to ciphey's search algorithm and result presentation:

1. **Top-N Results Output** (Task 24) - Display multiple candidate results with confidence scores
2. **Beam Search** (Task 25) - Alternative search strategy for faster results
3. **Incremental Streaming** (Task 26) - Process large inputs in chunks

## Current State Analysis

### A* Search (`src/searchers/astar.rs`)
- Uses f = g + h scoring where g is depth and h is heuristic
- Heuristic includes: decoder popularity, depth penalty, string quality, cipher identification
- Supports `top_results` mode via WaitAthena storage but lacks result ranking/display

### Result Storage (`src/storage/wait_athena_storage.rs`)
- Stores PlaintextResult structs with text, description, checker_name, decoder_name
- No confidence scoring or sorting mechanism

### CLI Output (`src/cli/mod.rs`, `src/cli_pretty_printing.rs`)
- Results are printed as found
- No aggregated result display

## Design Decisions

### Task 24: Top-N Results Output

**Confidence Score Calculation:**
```
confidence = (checker_confidence * 0.4) + (path_quality * 0.3) + (string_quality * 0.3)
```
Where:
- `checker_confidence`: Based on checker type (English=0.9, Structured=0.95, Code=0.85, Multilingual=0.8)
- `path_quality`: 1.0 / (1.0 + path_length * 0.1) - shorter paths are more likely correct
- `string_quality`: From existing `calculate_string_quality` function

**Output Format:**
```
=== Top N Results ===
1. [95% confidence] "Hello World" (via Base64 → English Checker)
2. [72% confidence] "Hello World" (via Hex → Base64 → English Checker)
3. [45% confidence] "..." (via Base32 → English Checker)
```

### Task 25: Beam Search

**Implementation Strategy:**
- Beam width W (configurable, default=5)
- At each level, keep only top-W nodes by f-score
- Process nodes in parallel like A*
- Same heuristic function as A*
- Trades completeness for speed

**Key Differences from A*:**
- Fixed-width beam vs open-ended priority queue
- Aggressive pruning at each level
- Better for timeout-bounded scenarios

### Task 26: Incremental Streaming

**Implementation Strategy:**
- Split input into overlapping chunks (default 1024 chars, 100 char overlap)
- Process each chunk independently
- Merge results by detecting chunk boundaries
- Useful for large files or streaming inputs

**Chunk Processing:**
```
[----chunk1----]
          [----chunk2----]
                    [----chunk3----]
```

## Architecture

```
searchers/
├── astar.rs          # Existing A* implementation
├── beam_search.rs    # NEW: Beam search implementation
├── bfs.rs            # Existing BFS implementation
├── helper_functions.rs # Shared heuristic functions
├── streaming.rs      # NEW: Streaming/chunked processing
└── mod.rs            # Search dispatcher (add beam_search option)
```

## Configuration Changes

Add to `Config`:
```rust
pub search_strategy: SearchStrategy,  # AStar, BeamSearch(pub beam_width)
pub max_results: usize,               # Number of top results to display
pub stream_chunk_size: Option<usize>,  # None = no streaming
```

## Testing Strategy

1. Unit tests for confidence calculation
2. Unit tests for beam search pruning
3. Integration tests comparing A* vs Beam Search results
4. Tests for streaming chunk processing
