// First-run configuration module
mod first_run;
pub use first_run::run_first_time_setup;

use std::io::{self, BufRead};
use std::{fs::File, io::Read};

use crate::cli_pretty_printing;
use crate::cli_pretty_printing::panic_failure_both_input_and_fail_provided;
use crate::config::{get_config_file_into_struct, load_wordlist, Config};
/// This doc string acts as a help message when the uses run '--help' in CLI mode
/// as do all doc strings on fields
use clap::Parser;
use log::trace;

/// The struct for Clap CLI arguments
#[derive(Parser)]
#[command(author = "Bee <bee@skerritt.blog>", about, long_about = None)]
pub struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[arg(short, long)]
    text: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Turn off human checker, perfect for APIs where you don't want input from humans
    #[arg(short, long)]
    disable_human_checker: bool,

    /// Set timeout, if it is not decrypted after this time, it will return an error.
    /// Default is 5 seconds.
    // If we want to call it `timeout`, the short argument contends with the one for Text `ciphey -t`.
    // I propose we just call it `cracking_timeout`.
    #[arg(short, long)]
    cracking_timeout: Option<u32>,
    /// Run in API mode, this will return the results instead of printing them.
    /// Default is false
    #[arg(short, long)]
    api_mode: Option<bool>,
    /// Output machine-readable JSON on stdout. Ideal for programmatic use.
    /// Implies no ANSI colours and suppresses human-interactive prompts.
    #[arg(long)]
    json: bool,
    /// Opens a file for decoding
    /// Use instead of `--text`
    #[arg(short, long)]
    file: Option<String>,
    /// If you have a crib (you know a piece of information in the plaintext)
    /// Or you want to create a custom regex to check against, you can use the Regex checker below.
    /// This turns off other checkers (English, LemmeKnow)
    #[arg(short, long)]
    regex: Option<String>,
    /// Path to a wordlist file containing newline-separated words
    /// The checker will match input against these words exactly
    /// Takes precedence over config file if both specify a wordlist
    #[arg(
        long,
        help = "Path to a wordlist file with newline-separated words for exact matching"
    )]
    wordlist: Option<String>,
    /// Show all potential plaintexts found instead of exiting after the first one
    /// Automatically disables the human checker
    #[arg(long)]
    top_results: bool,
    /// Enables enhanced plaintext detection with BERT model.
    #[arg(long)]
    enable_enhanced_detection: bool,
    /// Search strategy to use: "astar" (default) or "beam".
    #[arg(long)]
    search_strategy: Option<String>,
    /// Beam width for beam search. Higher values explore more paths but use more memory.
    #[arg(long)]
    beam_width: Option<usize>,
    /// Maximum number of results to display in top-results mode.
    #[arg(long)]
    max_results: Option<usize>,
    /// Enable streaming processing with specified chunk size (in characters).
    #[arg(long)]
    stream_chunk_size: Option<usize>,
    /// Read input from standard input (pipe or interactive).
    /// Useful for piping output from other commands.
    #[arg(long)]
    stdin: bool,
    /// Batch mode: process multiple ciphertexts (one per line).
    /// With --file, reads each line of the file as a separate ciphertext.
    /// With --stdin, reads each line from stdin as a separate ciphertext.
    #[arg(long)]
    batch: bool,
    /// Path to write batch output results.
    /// If not specified, results are printed to stdout.
    #[arg(long)]
    output: Option<String>,
    /// Cache management operations: clear, stats, list
    /// Use --cache clear to clear all cache entries
    /// Use --cache stats to show cache statistics
    /// Use --cache list [N] to list recent N entries (default: 10)
    #[arg(long, value_name = "OP")]
    cache: Option<String>,
    /// Number of entries to show with --cache list
    #[arg(long, default_value = "10")]
    cache_limit: i64,
    /// Generate shell completion script for the specified shell
    /// Supported shells: bash, zsh, fish, powershell, elvish
    #[arg(long, value_name = "SHELL")]
    generate_completion: Option<String>,
    /// Enable interactive TUI mode for real-time decoding progress
    #[arg(long)]
    tui: bool,
}

/// Input source enumeration for CLI
#[derive(Debug, Clone)]
pub enum InputSource {
    /// Single text input
    Text(String),
    /// File path input
    File(String),
    /// Read from stdin
    Stdin,
    /// Batch mode (multiple ciphertexts)
    Batch(Vec<String>),
}

/// Parse CLI Arguments turns a Clap Opts struct, seen above
/// Into a library Struct for use within the program
/// The library struct can be found in the [config](../config) folder.
/// # Panics
/// This function can panic when it gets both a file and text input at the same time.
pub fn parse_cli_args() -> (InputSource, Config) {
    let mut opts: Opts = Opts::parse();
    let min_log_level = match opts.verbose {
        0 => "Warn",
        1 => "Info",
        2 => "Debug",
        _ => "Trace",
    };
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, min_log_level),
    );

    let input_source = parse_input_source(&mut opts);

    trace!("Program was called with CLI 😉");
    trace!("Parsed the arguments");

    let config = cli_args_into_config_struct(opts, input_source.clone());
    (input_source, config)
}

/// Parse input source from CLI options
fn parse_input_source(opts: &mut Opts) -> InputSource {
    if opts.stdin && opts.batch {
        // Batch mode from stdin
        let lines = read_stdin_lines();
        InputSource::Batch(lines)
    } else if opts.stdin {
        // Single stdin input
        InputSource::Stdin
    } else if opts.file.is_some() && opts.batch {
        // Batch mode from file
        let file_path = opts.file.take().unwrap();
        let lines = read_file_lines(&file_path);
        InputSource::Batch(lines)
    } else {
        match (opts.file.take(), opts.text.take()) {
            (Some(_), Some(_)) => {
                panic_failure_both_input_and_fail_provided();
                unreachable!("panic helper should terminate the process");
            }
            (Some(file), None) => InputSource::File(file),
            (None, Some(text)) => InputSource::Text(text),
            (None, None) => {
                // Default to stdin if no input provided
                InputSource::Stdin
            }
        }
    }
}

/// Read all lines from stdin
fn read_stdin_lines() -> Vec<String> {
    let stdin = io::stdin();
    stdin
        .lock()
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// Read all lines from a file (for batch mode)
fn read_file_lines(file_path: &str) -> Vec<String> {
    let mut file = File::open(file_path).unwrap_or_else(|err| {
        eprintln!("Error: Cannot open file '{}': {}", file_path, err);
        std::process::exit(1);
    });

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap_or_else(|err| {
        eprintln!("Error: Cannot read file '{}': {}", file_path, err);
        std::process::exit(1);
    });

    contents
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// Read stdin content as a single string
pub fn read_stdin() -> String {
    let mut contents = String::new();
    io::stdin()
        .read_to_string(&mut contents)
        .unwrap_or_else(|err| {
            eprintln!("Error reading from stdin: {}", err);
            std::process::exit(1);
        });
    contents.trim_end_matches(['\n', '\r']).to_owned()
}

/// Handle cache management commands
///
/// Returns true if a cache command was handled (and the program should exit),
/// false if no cache command was specified.
pub fn handle_cache_command(cache_op: &str, cache_limit: i64) -> bool {
    use crate::storage::database;

    match cache_op {
        "clear" => {
            match database::clear_cache() {
                Ok(count) => println!("Cleared {} cache entries.", count),
                Err(e) => eprintln!("Error clearing cache: {}", e),
            }
            // Also clear human rejections
            match database::clear_human_rejections() {
                Ok(count) => println!("Cleared {} human rejection entries.", count),
                Err(e) => eprintln!("Error clearing human rejections: {}", e),
            }
        }
        "stats" => {
            match database::get_cache_stats() {
                Ok(stats) => {
                    println!("=== Cache Statistics ===");
                    println!("Total entries: {}", stats.total_entries);
                    println!("Successful: {}", stats.successful_entries);
                    println!("Failed: {}", stats.failed_entries);
                    println!("Avg execution time: {:.2} ms", stats.avg_execution_time_ms);
                    if let Some(oldest) = &stats.oldest_entry {
                        println!("Oldest entry: {}", oldest);
                    }
                    if let Some(newest) = &stats.newest_entry {
                        println!("Newest entry: {}", newest);
                    }
                }
                Err(e) => eprintln!("Error getting cache stats: {}", e),
            }
        }
        "list" => {
            let limit = if cache_limit > 0 { cache_limit as usize } else { 10 };
            match database::list_cache_entries(limit) {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No cache entries found.");
                    } else {
                        println!("=== Recent {} Cache Entries ===", entries.len());
                        for (i, entry) in entries.iter().enumerate() {
                            println!(
                                "\n[{}] Encoded: {}...",
                                i + 1,
                                if entry.encoded_text.len() > 40 {
                                    &entry.encoded_text[..40]
                                } else {
                                    &entry.encoded_text
                                }
                            );
                            println!("    Decoded: {}", entry.decoded_text);
                            println!("    Path: {}", entry.path.join(" → "));
                            println!(
                                "    Status: {}",
                                if entry.successful {
                                    "Success"
                                } else {
                                    "Failed"
                                }
                            );
                            println!("    Time: {} ms", entry.execution_time_ms);
                            println!("    Date: {}", entry.timestamp);
                        }
                    }
                }
                Err(e) => eprintln!("Error listing cache entries: {}", e),
            }
        }
        _ => {
            eprintln!("Unknown cache operation: '{}'. Use 'clear', 'stats', or 'list'.", cache_op);
        }
    }
    true
}

/// Handle shell completion generation
///
/// Generates a shell completion script for the specified shell and prints it to stdout.
/// Supported shells: bash, zsh, fish, powershell, elvish
pub fn handle_generate_completion(shell: &str) {
    use clap::CommandFactory;

    let shell = shell.to_lowercase();
    let mut cmd = Opts::command();

    match shell.as_str() {
        "bash" => {
            let mut buf = Vec::new();
            clap_complete::generate(clap_complete::Shell::Bash, &mut cmd, "ciphey", &mut buf);
            println!("{}", String::from_utf8_lossy(&buf));
        }
        "zsh" => {
            let mut buf = Vec::new();
            clap_complete::generate(clap_complete::Shell::Zsh, &mut cmd, "ciphey", &mut buf);
            println!("{}", String::from_utf8_lossy(&buf));
        }
        "fish" => {
            let mut buf = Vec::new();
            clap_complete::generate(clap_complete::Shell::Fish, &mut cmd, "ciphey", &mut buf);
            println!("{}", String::from_utf8_lossy(&buf));
        }
        "powershell" => {
            let mut buf = Vec::new();
            clap_complete::generate(
                clap_complete::Shell::PowerShell,
                &mut cmd,
                "ciphey",
                &mut buf,
            );
            println!("{}", String::from_utf8_lossy(&buf));
        }
        "elvish" => {
            let mut buf = Vec::new();
            clap_complete::generate(clap_complete::Shell::Elvish, &mut cmd, "ciphey", &mut buf);
            println!("{}", String::from_utf8_lossy(&buf));
        }
        _ => {
            eprintln!("Unsupported shell: '{}'. Supported shells: bash, zsh, fish, powershell, elvish", shell);
            std::process::exit(1);
        }
    }
}

/// When the CLI is called with `-f` to open a file
/// this function opens it
pub fn read_and_parse_file(file_path: String) -> String {
    let mut file = File::open(&file_path).unwrap_or_else(|err| {
        eprintln!("Error: Cannot open file '{}': {}", file_path, err);
        std::process::exit(1);
    });

    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap_or_else(|err| {
        eprintln!("Error: Cannot read file '{}': {}", file_path, err);
        std::process::exit(1);
    });
    // We can just put the file into the `Opts.text` and the program will work as normal
    // On Unix systems a line is defined as "\n{text}\n"
    // https://stackoverflow.com/a/729795
    // Which means if a user creates a file on Unix, it'll have a new line appended.
    // This is probably not what they wanted to decode (it is not what I wanted) so we are removing them
    contents.trim_end_matches(['\n', '\r']).to_owned()
}

/// Turns our CLI arguments into a config stuct
fn cli_args_into_config_struct(opts: Opts, _input: InputSource) -> Config {
    // Get configuration from file first
    let mut config = get_config_file_into_struct();

    // Update config with CLI arguments when they're explicitly set
    config.verbose = opts.verbose;
    config.human_checker_on = !opts.disable_human_checker;

    if let Some(timeout) = opts.cracking_timeout {
        config.timeout = timeout;
    }

    if let Some(api_mode) = opts.api_mode {
        config.api_mode = api_mode;
    }

    if opts.json {
        config.json_output = true;
        // JSON output must be free of human interaction and colour
        config.human_checker_on = false;
        config.api_mode = true;
    }

    if let Some(regex) = opts.regex {
        config.regex = Some(regex);
    }

    // Handle wordlist if provided via CLI (takes precedence over config file)
    if let Some(wordlist_path) = opts.wordlist {
        config.wordlist_path = Some(wordlist_path.clone());

        // Load the wordlist here in the CLI layer
        match load_wordlist(&wordlist_path) {
            Ok(wordlist) => {
                config.wordlist = Some(wordlist);
            }
            Err(e) => {
                // Critical error - exit if wordlist is specified but can't be loaded
                eprintln!("Can't load wordlist at '{}': {}", wordlist_path, e);
                std::process::exit(1);
            }
        }
    }

    // Set top_results mode if the flag is present
    config.top_results = opts.top_results;

    // If top_results is enabled, automatically disable the human checker
    if config.top_results {
        config.human_checker_on = false;
    }

    // Handle enhanced detection if enabled via CLI
    if opts.enable_enhanced_detection {
        config.enhanced_detection = true;
        eprintln!(
            "{}",
            cli_pretty_printing::statement("Enhanced detection enabled.", None)
        );
    }

    // Handle search strategy
    if let Some(strategy_str) = opts.search_strategy {
        match strategy_str.parse::<crate::searchers::SearchStrategy>() {
            Ok(strategy) => {
                config.search_strategy = strategy;
            }
            Err(e) => {
                eprintln!("{}", cli_pretty_printing::warning(&e));
            }
        }
    }

    // Handle beam width
    if let Some(width) = opts.beam_width {
        config.beam_width = Some(width);
    }

    // Handle max results
    if let Some(max) = opts.max_results {
        config.max_results = Some(max);
    }

    // Handle streaming chunk size
    if let Some(chunk_size) = opts.stream_chunk_size {
        config.stream_chunk_size = Some(chunk_size);
    }

    // Handle batch mode
    if opts.batch {
        config.batch_mode = true;
        config.human_checker_on = false;
    }

    // Handle cache commands
    if let Some(cache_op) = opts.cache {
        config.cache_op = Some(cache_op);
    }
    config.cache_limit = opts.cache_limit;

    // Handle shell completion generation
    config.generate_completion = opts.generate_completion;

    // Handle TUI mode
    config.tui_mode = opts.tui;

    config
}
