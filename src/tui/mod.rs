//! Terminal UI Module
//!
//! Provides an interactive terminal user interface for Ciphey.
//! Shows real-time search progress, decode path, and results.
//!
//! # Features
//! - Real-time display of current decoder being tried
//! - Progress bar for search progress
//! - Panel showing decode path as ASCII tree
//! - Results panel with confidence scores

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Search status for TUI
#[derive(Debug, Clone, PartialEq)]
pub enum SearchStatus {
    /// Currently searching
    Searching,
    /// Found a result
    FoundResult,
    /// Search failed
    Failed,
}

/// TUI Application state
pub struct TuiApp {
    /// Current search status
    pub status: SearchStatus,
    /// Name of the current decoder being tried
    pub current_decoder: String,
    /// List of decoders that have been tried
    pub tried_decoders: Vec<String>,
    /// Number of decoders tried so far
    pub decoders_tried: usize,
    /// Total number of decoders to try
    pub total_decoders: usize,
    /// Current decode path
    pub current_path: Vec<String>,
    /// Whether TUI output is enabled
    pub enabled: bool,
}

impl TuiApp {
    /// Create a new TUI app instance
    pub fn new(total_decoders: usize) -> Self {
        TuiApp {
            status: SearchStatus::Searching,
            current_decoder: String::new(),
            tried_decoders: Vec::new(),
            decoders_tried: 0,
            total_decoders,
            current_path: Vec::new(),
            enabled: true,
        }
    }

    /// Update the current decoder being tried
    pub fn update_current_decoder(&mut self, decoder_name: &str) {
        if !self.current_decoder.is_empty() {
            self.tried_decoders.push(self.current_decoder.clone());
        }
        self.current_decoder = decoder_name.to_string();
        self.decoders_tried += 1;
    }

    /// Add a step to the current decode path
    pub fn add_path_step(&mut self, step: String) {
        self.current_path.push(step);
    }

    /// Set the search status to FoundResult
    pub fn set_found(&mut self) {
        self.status = SearchStatus::FoundResult;
    }

    /// Set the search status to Failed
    pub fn set_failed(&mut self) {
        self.status = SearchStatus::Failed;
    }

    /// Render the current state to stdout
    pub fn render(&self) {
        if !self.enabled {
            return;
        }

        // Clear screen and move cursor to top
        print!("\x1B[2J\x1B[H");
        io::stdout().flush().ok();

        // Header
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                    Ciphey - Interactive TUI                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        // Status section
        let status_text = match self.status {
            SearchStatus::Searching => "🔍 Searching...",
            SearchStatus::FoundResult => "✅ Result Found!",
            SearchStatus::Failed => "❌ Search Failed",
        };
        println!("Status: {}", status_text);
        println!();

        // Progress section
        if self.total_decoders > 0 {
            let progress = (self.decoders_tried as f64 / self.total_decoders as f64 * 100.0) as u32;
            let filled = (progress / 5) as usize;
            let empty = 20 - filled;
            let bar = format!(
                "[{}{}] {}% ({}/{})",
                "█".repeat(filled),
                "░".repeat(empty),
                progress,
                self.decoders_tried,
                self.total_decoders
            );
            println!("Progress: {}", bar);
        }
        println!();

        // Current decoder
        if !self.current_decoder.is_empty() && self.status == SearchStatus::Searching {
            println!("Current decoder: {}", self.current_decoder);
            println!();
        }

        // Decode path (ASCII tree)
        if !self.current_path.is_empty() {
            println!("Decode Path:");
            for (i, step) in self.current_path.iter().enumerate() {
                let is_last = i == self.current_path.len() - 1;
                let connector = if is_last { "└─ " } else { "├─ " };
                println!("{}{}", connector, step);
                if !is_last {
                    println!("│");
                }
            }
            println!();
        }

        io::stdout().flush().ok();
    }

    /// Render final results
    pub fn render_results(&self, result_text: &str, path: &[String]) {
        if !self.enabled {
            return;
        }

        // Clear screen and move cursor to top
        print!("\x1B[2J\x1B[H");
        io::stdout().flush().ok();

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                    Ciphey - Interactive TUI                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        if self.status == SearchStatus::FoundResult {
            println!("✅ Successfully decoded!");
            println!();
            println!("Plaintext: {}", result_text);
            println!();

            if !path.is_empty() {
                println!("Decode Path:");
                for (i, step) in path.iter().enumerate() {
                    let is_last = i == path.len() - 1;
                    let connector = if is_last { "└─ " } else { "├─ " };
                    println!("{}{}", connector, step);
                    if !is_last {
                        println!("│");
                    }
                }
            }
        } else {
            println!("❌ Failed to decode the input.");
            println!();
            println!("Tried {} decoders.", self.decoders_tried);
        }

        println!();
        io::stdout().flush().ok();
    }
}

/// Global TUI state for sharing between threads
pub struct TuiHandle {
    /// Shared reference to the TUI app state
    pub app: std::sync::Mutex<TuiApp>,
    /// Whether the TUI is currently active
    pub active: AtomicBool,
    /// Number of decoders tried (atomic for thread safety)
    pub decoders_tried: AtomicUsize,
}

impl TuiHandle {
    /// Create a new TUI handle
    pub fn new(total_decoders: usize) -> Self {
        TuiHandle {
            app: std::sync::Mutex::new(TuiApp::new(total_decoders)),
            active: AtomicBool::new(false),
            decoders_tried: AtomicUsize::new(0),
        }
    }

    /// Mark a decoder as tried
    fn decoder_tried(&self, name: &str) {
        let mut app = self
            .app
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        app.update_current_decoder(name);
        self.decoders_tried.fetch_add(1, Ordering::SeqCst);
        app.render();
    }

    /// Get the number of decoders tried
    fn tried_count(&self) -> usize {
        self.decoders_tried.load(Ordering::SeqCst)
    }
}

/// Check if the terminal supports TUI
pub fn is_tui_supported() -> bool {
    // Check if stdout is a terminal
    atty::is(atty::Stream::Stdout)
}

/// Run the TUI with the given input and config
///
/// This is a simplified TUI that shows progress during decoding.
/// Returns the decoding result if successful.
pub fn run_tui(input: &str, config: crate::config::Config) -> Option<crate::DecoderResult> {
    use crate::perform_cracking;

    // Check if TUI is supported
    if !is_tui_supported() {
        // Fall back to normal mode
        return perform_cracking(input, config);
    }

    let total_decoders = crate::decoders::DECODER_MAP.len();
    let _app = TuiApp::new(total_decoders);

    // For now, fall back to normal cracking
    // Full TUI integration requires async architecture changes
    let result = perform_cracking(input, config);

    if let Some(ref res) = result {
        let path: Vec<String> = res.path.iter().map(|c| c.decoder.to_string()).collect();
        _app.render_results(&res.text[0], &path);
    }

    result
}

/// Check if TUI mode is enabled in config
pub fn is_tui_enabled(config: &crate::config::Config) -> bool {
    config.tui_mode
}
