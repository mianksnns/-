/// import general checker
use lemmeknow::Identifier;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::io::{Read, Write};
use std::path::Path;

use crate::searchers::SearchStrategy;

/// Library input is the default API input
/// The CLI turns its arguments into a LibraryInput struct
/// The Config object is a default configuration object
/// For the entire program
/// It's access using a variable like configuration
/// ```rust
/// use ciphey::config::get_config;
/// let config = get_config();
/// assert_eq!(config.verbose, 0);
/// ```
#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// A level of verbosity to determine.
    /// How much we print in logs.
    pub verbose: u8,
    /// The lemmeknow config to use
    #[serde(skip)]
    pub lemmeknow_config: Identifier,
    /// lemmeknow_config serialization fields
    #[serde(default)]
    pub lemmeknow_min_rarity: f32,
    /// Maximum rarity threshold for lemmeknow detection
    #[serde(default)]
    pub lemmeknow_max_rarity: f32,
    /// List of lemmeknow tags to include in detection
    #[serde(default)]
    pub lemmeknow_tags: Vec<String>,
    /// List of lemmeknow tags to exclude from detection
    #[serde(default)]
    pub lemmeknow_exclude_tags: Vec<String>,
    /// Whether to use boundaryless mode in lemmeknow detection
    #[serde(default)]
    pub lemmeknow_boundaryless: bool,
    /// Should the human checker be on?
    /// This asks yes/no for plaintext. Turn off for API
    pub human_checker_on: bool,
    /// The timeout threshold before ciphey quits
    /// This is in seconds
    pub timeout: u32,
    /// Whether to collect all plaintexts until timeout expires
    /// instead of exiting after finding the first valid plaintext
    pub top_results: bool,
    /// Is the program being run in API mode?
    /// This is used to determine if we should print to stdout
    /// Or return the values
    pub api_mode: bool,
    /// Should the program output machine-readable JSON?
    /// When enabled, all CLI output is replaced by a single JSON document
    /// on stdout, making the output stable for programmatic consumers.
    pub json_output: bool,
    /// Regex enables the user to search for a specific regex or crib
    pub regex: Option<String>,
    /// Path to the wordlist file. Will be overridden by CLI argument if provided.
    pub wordlist_path: Option<String>,
    /// Wordlist data structure (loaded from file). CLI takes precedence if both config and CLI specify a wordlist.
    #[serde(skip)]
    pub wordlist: Option<HashSet<String>>,
    /// Colourscheme hashmap
    pub colourscheme: HashMap<String, String>,
    /// Enables enhanced plaintext detection using a BERT model.
    pub enhanced_detection: bool,
    /// Path to the enhanced detection model. If None, will use the default path.
    pub model_path: Option<String>,
    /// Search strategy to use for decoding.
    pub search_strategy: SearchStrategy,
    /// Beam width for beam search. None uses the default (5).
    pub beam_width: Option<usize>,
    /// Maximum number of top results to display. None means use default (10).
    pub max_results: Option<usize>,
    /// Chunk size for streaming processing. None disables streaming.
    pub stream_chunk_size: Option<usize>,
    /// Whether batch mode is enabled (process multiple inputs at once).
    pub batch_mode: bool,
    /// Cache management operation (clear, stats, list). None means no cache operation.
    #[serde(skip)]
    pub cache_op: Option<String>,
    /// Number of entries to show with cache list command.
    #[serde(skip)]
    pub cache_limit: i64,
    /// Shell to generate completion script for. None means no completion generation.
    #[serde(skip)]
    pub generate_completion: Option<String>,
    /// Whether TUI mode is enabled.
    #[serde(default)]
    pub tui_mode: bool,
    /// Enhanced detection configuration.
    #[serde(default)]
    pub enhanced_config: crate::checkers::enhanced::EnhancedConfig,
}

impl Clone for Config {
    fn clone(&self) -> Self {
        Config {
            verbose: self.verbose,
            lemmeknow_config: make_identifier_from_config(self),
            lemmeknow_min_rarity: self.lemmeknow_min_rarity,
            lemmeknow_max_rarity: self.lemmeknow_max_rarity,
            lemmeknow_tags: self.lemmeknow_tags.clone(),
            lemmeknow_exclude_tags: self.lemmeknow_exclude_tags.clone(),
            lemmeknow_boundaryless: self.lemmeknow_boundaryless,
            human_checker_on: self.human_checker_on,
            timeout: self.timeout,
            top_results: self.top_results,
            api_mode: self.api_mode,
            json_output: self.json_output,
            regex: self.regex.clone(),
            wordlist_path: self.wordlist_path.clone(),
            wordlist: self.wordlist.clone(),
            colourscheme: self.colourscheme.clone(),
            enhanced_detection: self.enhanced_detection,
            model_path: self.model_path.clone(),
            search_strategy: self.search_strategy,
            beam_width: self.beam_width,
            max_results: self.max_results,
            stream_chunk_size: self.stream_chunk_size,
            batch_mode: self.batch_mode,
            cache_op: self.cache_op.clone(),
            cache_limit: self.cache_limit,
            generate_completion: self.generate_completion.clone(),
            tui_mode: self.tui_mode,
            enhanced_config: self.enhanced_config.clone(),
        }
    }
}

/// Cell for storing global Config
static CONFIG: OnceCell<Config> = OnceCell::new();

/// To initialize global config with custom values
pub fn set_global_config(config: Config) {
    CONFIG.set(config).ok(); // ok() used to make compiler happy about using Result
}

/// Get the global config.
/// This will return default config if the config wasn't already initialized
pub fn get_config() -> &'static Config {
    CONFIG.get_or_init(Config::default)
}

/// Creates a default lemmeknow config
const LEMMEKNOW_DEFAULT_CONFIG: Identifier = Identifier {
    min_rarity: 0.0_f32,
    max_rarity: 0.0_f32,
    tags: vec![],
    exclude_tags: vec![],
    file_support: false,
    boundaryless: false,
};

/// Convert Config fields into an Identifier
fn make_identifier_from_config(config: &Config) -> Identifier {
    Identifier {
        min_rarity: config.lemmeknow_min_rarity,
        max_rarity: config.lemmeknow_max_rarity,
        tags: config.lemmeknow_tags.clone(),
        exclude_tags: config.lemmeknow_exclude_tags.clone(),
        file_support: false, // Always false as per LEMMEKNOW_DEFAULT_CONFIG
        boundaryless: config.lemmeknow_boundaryless,
    }
}

/// Update Config's Identifier field from its serialization fields
fn update_identifier_in_config(config: &mut Config) {
    config.lemmeknow_config = make_identifier_from_config(config);
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Config {
            verbose: 0,
            lemmeknow_config: LEMMEKNOW_DEFAULT_CONFIG,
            lemmeknow_min_rarity: 0.0_f32,
            lemmeknow_max_rarity: 0.0_f32,
            lemmeknow_tags: vec![],
            lemmeknow_exclude_tags: vec![],
            lemmeknow_boundaryless: false,
            human_checker_on: false,
            timeout: 5,
            top_results: false,
            api_mode: false,
            json_output: false,
            regex: None,
            wordlist_path: None,
            wordlist: None,
            enhanced_detection: false,
            model_path: None,
            search_strategy: SearchStrategy::AStar,
            beam_width: None,
            max_results: Some(10),
            stream_chunk_size: None,
            batch_mode: false,
            cache_op: None,
            cache_limit: 10,
            generate_completion: None,
            tui_mode: false,
            enhanced_config: crate::checkers::enhanced::EnhancedConfig::default(),
            colourscheme: HashMap::new(),
        };

        // Set default colors
        config
            .colourscheme
            .insert(String::from("informational"), String::from("255,215,0")); // Gold yellow
        config
            .colourscheme
            .insert(String::from("warning"), String::from("255,0,0")); // Red
        config
            .colourscheme
            .insert(String::from("success"), String::from("0,255,0")); // Green
        config
            .colourscheme
            .insert(String::from("error"), String::from("255,0,0")); // Red

        config
            .colourscheme
            .insert(String::from("question"), String::from("255,215,0")); // Gold yellow (same as informational)
        config
    }
}

/// Get the path to the ciphey config file
///
/// # Panics
///
/// This function will panic if:
/// - The home directory cannot be found
/// - The ciphey directory cannot be created
pub fn get_config_file_path() -> std::path::PathBuf {
    let mut path = dirs::home_dir().expect("Could not find home directory");
    path.push(".ciphey");
    fs::create_dir_all(&path).expect("Could not create ciphey directory");
    path.push("config.toml");
    path
}

/// Create a default config file at the specified path
///
/// # Errors
///
/// This function returns an error if the config file cannot be created, serialized, or written.
///
/// # Panics
///
/// This function will panic if the config file path cannot be determined
/// (see `get_config_file_path`).
pub fn create_default_config_file() -> std::io::Result<()> {
    let config = Config::default();
    let toml_string = toml::to_string_pretty(&config)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let path = get_config_file_path();
    let mut file = File::create(path)?;
    file.write_all(toml_string.as_bytes())?;
    Ok(())
}

/// Read and parse the config file
fn read_config_file() -> std::io::Result<String> {
    let path = get_config_file_path();
    let mut file = File::open(&path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Parse a TOML string into a Config struct, handling unknown keys
fn parse_toml_with_unknown_keys(contents: &str) -> Config {
    // First parse into a generic Value to check for unknown keys
    let parsed_value: toml::Value = toml::from_str(contents).expect("Could not parse config file");

    // Check for unknown keys at the root level
    if let toml::Value::Table(table) = &parsed_value {
        let known_keys = [
            "verbose",
            "lemmeknow_min_rarity",
            "enhanced_detection",
            "model_path",
            "lemmeknow_max_rarity",
            "lemmeknow_tags",
            "lemmeknow_exclude_tags",
            "lemmeknow_boundaryless",
            "human_checker_on",
            "timeout",
            "top_results",
            "api_mode",
            "json_output",
            "regex",
            "wordlist_path",
            "question",
            "colourscheme",
            "search_strategy",
            "beam_width",
            "max_results",
            "stream_chunk_size",
        ];
        for key in table.keys() {
            if !known_keys.contains(&key.as_str()) {
                crate::cli_pretty_printing::warning_unknown_config_key(key);
            }
        }
    }

    // Parse into Config struct
    let mut config: Config = toml::from_str(contents).expect("Could not parse config file");
    update_identifier_in_config(&mut config);
    config
}

/// Loads a wordlist from a file into a HashSet for efficient lookups.
///
/// # Arguments
/// * `path` - Path to the wordlist file
///
/// # Returns
/// * `Ok(HashSet<String>)` - The loaded wordlist as a HashSet for O(1) lookups
/// * `Err(io::Error)` - If the file cannot be opened or read
///
/// # Errors
/// This function will return an error if:
/// * The file does not exist
/// * The file cannot be opened due to permissions
/// * The file contains invalid UTF-8 characters
pub fn load_wordlist<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wordlist path must point to a regular file",
        ));
    }

    let reader = BufReader::new(file);
    let mut wordlist = HashSet::new();

    for line in reader.lines() {
        let word = line.map_err(|err| {
            if err.kind() == io::ErrorKind::InvalidData {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wordlist file contains invalid UTF-8",
                )
            } else {
                err
            }
        })?;
        let trimmed = word.trim().to_string();
        if !trimmed.is_empty() {
            wordlist.insert(trimmed);
        }
    }

    Ok(wordlist)
}

/// Get configuration from file or create default if it doesn't exist
pub fn get_config_file_into_struct() -> Config {
    let path = get_config_file_path();

    if !path.exists() {
        // First run - get user preferences
        let first_run_config = crate::cli::run_first_time_setup();
        let colourscheme = first_run_config
            .iter()
            .filter(|(k, _)| !k.starts_with("wordlist") && *k != "timeout")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut config = Config {
            colourscheme,
            ..Config::default()
        };

        // Set timeout if present
        if let Some(timeout) = first_run_config.get("timeout") {
            config.timeout = timeout.parse().unwrap_or(5);
        }

        // Extract wordlist path if present
        if let Some(wordlist_path) = first_run_config.get("wordlist_path") {
            config.wordlist_path = Some(wordlist_path.clone());

            // Load the wordlist
            match load_wordlist(wordlist_path) {
                Ok(wordlist) => {
                    config.wordlist = Some(wordlist);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Could not load wordlist at '{}': {}",
                        wordlist_path, e
                    );
                    // Don't exit - just continue without the wordlist
                }
            }
        }

        // Save the config to file
        save_config_to_file(&config, &path);
        config
    } else {
        // Existing config - read and parse it
        match read_config_file() {
            Ok(contents) => {
                let mut config = parse_toml_with_unknown_keys(&contents);

                // If wordlist is specified in config file, set it in the config struct
                if let Some(wordlist_path) = &config.wordlist_path {
                    // Load the wordlist here in the config layer
                    match load_wordlist(wordlist_path) {
                        Ok(wordlist) => {
                            config.wordlist = Some(wordlist);
                        }
                        Err(_e) => {
                            // Critical error - exit if config specifies wordlist but can't load it
                            eprintln!("Can't load wordlist at '{}'. Either fix or remove wordlist from config file at '{}'", 
                                wordlist_path, path.display());
                            std::process::exit(1);
                        }
                    }
                }

                config
            }
            Err(e) => {
                eprintln!("Error reading config file: {}. Using defaults.", e);
                Config::default()
            }
        }
    }
}

/// Save a Config struct to a file
fn save_config_to_file(config: &Config, path: &std::path::Path) {
    let toml_string = toml::to_string_pretty(config).expect("Could not serialize config");
    let mut file = File::create(path).expect("Could not create config file");
    file.write_all(toml_string.as_bytes())
        .expect("Could not write to config file");
}
