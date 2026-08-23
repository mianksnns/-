# Search Enhancement Task List

## Status Legend
- [x] Completed
- [ ] In Progress
- [ ] Not Started

---

## Task 24: Top-N Results Output

### 24.1: Implement Confidence Score Calculation
- [ ] Create `src/searchers/result_ranker.rs` module
- [ ] Implement `calculate_confidence` function
- [ ] Integrate with checker types and path quality

### 24.2: Enhance Result Storage
- [ ] Add confidence field to `PlaintextResult`
- [ ] Implement result sorting by confidence
- [ ] Add deduplication logic

### 2.4.3: Update CLI Output
- [ ] Add `--max-results` CLI argument
- [ ] Implement formatted result display
- [ ] Support both normal and JSON output modes

### 24.4: Tests
- [ ] Unit tests for confidence calculation
- [ ] Integration tests for result ranking
- [ ] CLI output formatting tests

---

## Task 25: Beam Search

### 25.1: Implement Beam Search Module
- [ ] Create `src/searchers/beam_search.rs`
- [ ] Implement beam node structure
- [ ] Implement beam width limiting

### 25.2: Implement Beam Search Algorithm
- [ ] Node expansion with beam constraint
- [ ] Parallel processing within beam
- [ ] Result collection and return

### 25.3: Integrate with Search Dispatcher
- [ ] Add `SearchStrategy` enum to config
- [ ] Update `search_for_plaintext` to dispatch to beam search
- [ ] Add `--search-strategy` CLI argument

### 25.4: Tests
- [ ] Unit tests for beam pruning
- [ ] Comparison tests: A* vs Beam Search
- [ ] Edge cases: beam_width=1, beam_width=unlimited

---

## Task 26: Incremental Streaming

### 26.1: Implement Streaming Module
- [ ] Create `src/searchers/streaming.rs`
- [ ] Implement chunk generator with overlap
- [ ] Implement chunk result merger

### 26.2: Integrate with Search Pipeline
- [ ] Add streaming config options
- [ ] Update search entry point to use streaming when configured
- [ ] Handle chunk boundary edge cases

### 26.3: Tests
- [ ] Unit tests for chunk generation
- [ ] Integration tests for full streaming pipeline
- [ ] Edge cases: empty chunks, overlap handling

---

## Cross-cutting Concerns

### Config Updates
- [ ] Add `SearchStrategy` enum
- [ ] Add `max_results` field
- [ ] Add `stream_chunk_size` field
- [ ] Update Default implementation

### CLI Updates
- [ ] Add `--max-results` argument
- [ ] Add `--search-strategy` argument
- [ ] Add `--stream-chunk-size` argument
- [ ] Update help text

### Documentation
- [ ] Update README with new options
- [ ] Add examples for beam search and streaming
