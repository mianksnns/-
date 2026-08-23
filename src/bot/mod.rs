//! Bot integration module for Discord and Telegram.
//!
//! This module provides a framework for running ciphey as a bot
//! on various messaging platforms. It handles command parsing,
//! rate limiting, and result formatting.
//!
//! # Supported Platforms
//! - Discord (via `discord` feature flag)
//! - Telegram (via `telegram` feature flag)
//! - Generic bot framework (always available)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Bot configuration.
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Bot name.
    pub name: String,
    /// Command prefix (e.g., "$" for Discord, "/" for Telegram).
    pub command_prefix: String,
    /// Default timeout for decode operations (seconds).
    pub default_timeout: u32,
    /// Maximum input length.
    pub max_input_length: usize,
    /// Rate limit: maximum requests per user per window.
    pub rate_limit_requests: u32,
    /// Rate limit window duration.
    pub rate_limit_window: Duration,
    /// Whether to show decode path in results.
    pub show_path: bool,
}

impl Default for BotConfig {
    fn default() -> Self {
        BotConfig {
            name: "ciphey".to_string(),
            command_prefix: "$".to_string(),
            default_timeout: 10,
            max_input_length: 10000,
            rate_limit_requests: 5,
            rate_limit_window: Duration::from_secs(60),
            show_path: true,
        }
    }
}

/// A bot command request.
#[derive(Debug, Clone)]
pub struct BotCommand {
    /// Command name.
    pub name: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// User ID who sent the command.
    pub user_id: String,
    /// Channel/chat ID.
    pub channel_id: String,
    /// Timestamp when the command was received.
    pub timestamp: Instant,
}

/// Response from a bot command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotResponse {
    /// Whether the command was successful.
    pub success: bool,
    /// Response message.
    pub message: String,
    /// Optional embed data for rich formatting.
    pub embed: Option<BotEmbed>,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

/// Rich embed data for bot responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotEmbed {
    /// Embed title.
    pub title: String,
    /// Embed description.
    pub description: String,
    /// Embed color (hex).
    pub color: u32,
    /// Embed fields.
    pub fields: Vec<BotEmbedField>,
}

/// A field in a bot embed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotEmbedField {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Whether the field should be displayed inline.
    pub inline: bool,
}

impl BotResponse {
    /// Create a success response.
    pub fn success(message: String, processing_time_ms: u64) -> Self {
        BotResponse {
            success: true,
            message,
            embed: None,
            processing_time_ms,
        }
    }

    /// Create a success response with an embed.
    pub fn success_with_embed(message: String, embed: BotEmbed, processing_time_ms: u64) -> Self {
        BotResponse {
            success: true,
            message,
            embed: Some(embed),
            processing_time_ms,
        }
    }

    /// Create an error response.
    pub fn error(message: String) -> Self {
        BotResponse {
            success: false,
            message,
            embed: None,
            processing_time_ms: 0,
        }
    }
}

/// Rate limiter for bot commands.
#[derive(Debug)]
pub struct RateLimiter {
    /// User ID -> (request count, window start).
    requests: HashMap<String, (u32, Instant)>,
    /// Maximum requests per window.
    max_requests: u32,
    /// Window duration.
    window: Duration,
    /// Total requests processed.
    total_requests: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        RateLimiter {
            requests: HashMap::new(),
            max_requests,
            window,
            total_requests: AtomicU64::new(0),
        }
    }

    /// Check if a user is allowed to make a request.
    pub fn is_allowed(&mut self, user_id: &str) -> bool {
        let now = Instant::now();

        // Clean up expired entries
        self.requests
            .retain(|_, (_, start)| now.duration_since(*start) < self.window);

        match self.requests.get_mut(user_id) {
            Some((count, start)) => {
                if now.duration_since(*start) >= self.window {
                    // Window expired, reset
                    *count = 1;
                    *start = now;
                    true
                } else if *count < self.max_requests {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                self.requests.insert(user_id.to_string(), (1, now));
                true
            }
        }
    }

    /// Get the remaining requests for a user.
    pub fn remaining(&self, user_id: &str) -> u32 {
        let now = Instant::now();

        match self.requests.get(user_id) {
            Some((count, start)) => {
                if now.duration_since(*start) >= self.window {
                    self.max_requests
                } else {
                    self.max_requests.saturating_sub(*count)
                }
            }
            None => self.max_requests,
        }
    }

    /// Get total requests processed.
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::SeqCst)
    }

    /// Record a request (for stats).
    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::SeqCst);
    }
}

/// Bot state shared across handlers.
#[derive(Debug)]
pub struct BotState {
    /// Bot configuration.
    pub config: BotConfig,
    /// Rate limiter.
    pub rate_limiter: RateLimiter,
    /// Start time.
    pub start_time: Instant,
}

impl BotState {
    /// Create a new bot state.
    pub fn new(config: BotConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit_requests, config.rate_limit_window);
        BotState {
            config,
            rate_limiter,
            start_time: Instant::now(),
        }
    }

    /// Handle a decode command.
    pub fn handle_decode(&mut self, command: &BotCommand) -> BotResponse {
        // Check rate limit
        if !self.rate_limiter.is_allowed(&command.user_id) {
            return BotResponse::error(format!(
                "Rate limit exceeded. Try again in {} seconds.",
                self.config.rate_limit_window.as_secs()
            ));
        }

        self.rate_limiter.record_request();

        // Combine args into input
        let input = command.args.join(" ");

        if input.is_empty() {
            return BotResponse::error(
                "Please provide text to decode. Usage: `$ciphey <text>`".to_string(),
            );
        }

        if input.len() > self.config.max_input_length {
            return BotResponse::error(format!(
                "Input too long. Maximum length is {} characters.",
                self.config.max_input_length
            ));
        }

        // Perform decoding
        let start = Instant::now();
        let timeout = self.config.default_timeout;

        use crate::config::Config;
        use crate::perform_cracking;

        let mut config = Config::default();
        config.timeout = timeout;
        config.api_mode = true;
        config.human_checker_on = false;

        let result = perform_cracking(&input, config);
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Some(decoded) => {
                let path: Vec<String> =
                    decoded.path.iter().map(|c| c.decoder.to_string()).collect();

                if self.config.show_path && !path.is_empty() {
                    let embed = BotEmbed {
                        title: "Decoded Successfully".to_string(),
                        description: format!("```\n{}\n```", decoded.text[0]),
                        color: 0x00ff00,
                        fields: vec![
                            BotEmbedField {
                                name: "Decoder Path".to_string(),
                                value: path.join(" → "),
                                inline: false,
                            },
                            BotEmbedField {
                                name: "Processing Time".to_string(),
                                value: format!("{}ms", elapsed),
                                inline: true,
                            },
                        ],
                    };
                    BotResponse::success_with_embed("Decoded!".to_string(), embed, elapsed)
                } else {
                    BotResponse::success(
                        format!("```\n{}\n```", decoded.text[0]),
                        elapsed,
                    )
                }
            }
            None => BotResponse::error(
                format!(
                    "Failed to decode the input within {} seconds. The text may not be a recognized encoding format.",
                    timeout
                ),
            ),
        }
    }

    /// Handle a help command.
    pub fn handle_help(&self) -> BotResponse {
        let embed = BotEmbed {
            title: "Ciphey Bot Help".to_string(),
            description: "Automatic decoding bot. I can detect and decode various encodings."
                .to_string(),
            color: 0x3498db,
            fields: vec![
                BotEmbedField {
                    name: "Decode".to_string(),
                    value: format!(
                        "`{}ciphey <text>` - Decode the given text",
                        self.config.command_prefix
                    ),
                    inline: false,
                },
                BotEmbedField {
                    name: "Help".to_string(),
                    value: format!(
                        "`{}help` - Show this help message",
                        self.config.command_prefix
                    ),
                    inline: false,
                },
                BotEmbedField {
                    name: "Info".to_string(),
                    value: format!(
                        "`{}info` - Show bot information",
                        self.config.command_prefix
                    ),
                    inline: false,
                },
            ],
        };

        BotResponse::success_with_embed("Help".to_string(), embed, 0)
    }

    /// Handle an info command.
    pub fn handle_info(&self) -> BotResponse {
        let uptime = self.start_time.elapsed();
        let embed = BotEmbed {
            title: "Ciphey Bot Info".to_string(),
            description: "Automatic decoding tool".to_string(),
            color: 0x9b59b6,
            fields: vec![
                BotEmbedField {
                    name: "Version".to_string(),
                    value: env!("CARGO_PKG_VERSION").to_string(),
                    inline: true,
                },
                BotEmbedField {
                    name: "Uptime".to_string(),
                    value: format!("{}s", uptime.as_secs()),
                    inline: true,
                },
                BotEmbedField {
                    name: "Total Requests".to_string(),
                    value: self.rate_limiter.total_requests().to_string(),
                    inline: true,
                },
            ],
        };

        BotResponse::success_with_embed("Info".to_string(), embed, 0)
    }
}

/// Parse a bot command from a message.
pub fn parse_command(prefix: &str, message: &str) -> Option<BotCommand> {
    if !message.starts_with(prefix) {
        return None;
    }

    let content = &message[prefix.len()..];
    let parts: Vec<&str> = content.trim().split_whitespace().collect();

    if parts.is_empty() {
        return None;
    }

    Some(BotCommand {
        name: parts[0].to_lowercase(),
        args: parts[1..].iter().map(|s| s.to_string()).collect(),
        user_id: String::new(),
        channel_id: String::new(),
        timestamp: Instant::now(),
    })
}

/// Discord-specific bot implementation.
#[cfg(feature = "discord")]
pub mod discord {
    use super::*;

    /// Discord bot configuration.
    #[derive(Debug, Clone)]
    pub struct DiscordConfig {
        /// Bot token.
        pub token: String,
        /// Base bot configuration.
        pub bot_config: BotConfig,
    }

    impl Default for DiscordConfig {
        fn default() -> Self {
            DiscordConfig {
                token: String::new(),
                bot_config: BotConfig {
                    command_prefix: "$".to_string(),
                    ..Default::default()
                },
            }
        }
    }
}

/// Telegram-specific bot implementation.
#[cfg(feature = "telegram")]
pub mod telegram {
    use super::*;

    /// Telegram bot configuration.
    #[derive(Debug, Clone)]
    pub struct TelegramConfig {
        /// Bot token.
        pub token: String,
        /// Base bot configuration.
        pub bot_config: BotConfig,
    }

    impl Default for TelegramConfig {
        fn default() -> Self {
            TelegramConfig {
                token: String::new(),
                bot_config: BotConfig {
                    command_prefix: "/".to_string(),
                    ..Default::default()
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_config_default() {
        let config = BotConfig::default();
        assert_eq!(config.name, "ciphey");
        assert_eq!(config.command_prefix, "$");
        assert_eq!(config.default_timeout, 10);
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(limiter.is_allowed("user1"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(limiter.is_allowed("user1"));
        }
        assert!(!limiter.is_allowed("user1"));
    }

    #[test]
    fn test_rate_limiter_allows_different_users() {
        let mut limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.is_allowed("user1"));
        assert!(!limiter.is_allowed("user1"));
        assert!(limiter.is_allowed("user2"));
    }

    #[test]
    fn test_rate_limiter_remaining() {
        let mut limiter = RateLimiter::new(5, Duration::from_secs(60));
        assert_eq!(limiter.remaining("user1"), 5);
        limiter.is_allowed("user1");
        assert_eq!(limiter.remaining("user1"), 4);
    }

    #[test]
    fn test_parse_command_valid() {
        let cmd = parse_command("$", "$ciphey SGVsbG8=");
        assert!(cmd.is_some());
        let cmd = cmd.unwrap();
        assert_eq!(cmd.name, "ciphey");
        assert_eq!(cmd.args, vec!["SGVsbG8="]);
    }

    #[test]
    fn test_parse_command_no_prefix() {
        let cmd = parse_command("$", "ciphey SGVsbG8=");
        assert!(cmd.is_none());
    }

    #[test]
    fn test_parse_command_empty() {
        let cmd = parse_command("$", "$");
        assert!(cmd.is_none());
    }

    #[test]
    fn test_bot_response_success() {
        let resp = BotResponse::success("test".to_string(), 100);
        assert!(resp.success);
        assert_eq!(resp.message, "test");
        assert_eq!(resp.processing_time_ms, 100);
    }

    #[test]
    fn test_bot_response_error() {
        let resp = BotResponse::error("test error".to_string());
        assert!(!resp.success);
        assert_eq!(resp.message, "test error");
    }

    #[test]
    fn test_bot_state_new() {
        let config = BotConfig::default();
        let state = BotState::new(config);
        assert_eq!(state.rate_limiter.total_requests(), 0);
    }

    #[test]
    fn test_bot_state_handle_help() {
        let config = BotConfig::default();
        let state = BotState::new(config);
        let response = state.handle_help();
        assert!(response.success);
        assert!(response.embed.is_some());
    }

    #[test]
    fn test_bot_state_handle_info() {
        let config = BotConfig::default();
        let state = BotState::new(config);
        let response = state.handle_info();
        assert!(response.success);
        assert!(response.embed.is_some());
    }

    #[test]
    fn test_bot_state_handle_decode_empty() {
        let config = BotConfig::default();
        let mut state = BotState::new(config);
        let command = BotCommand {
            name: "ciphey".to_string(),
            args: vec![],
            user_id: "user1".to_string(),
            channel_id: "channel1".to_string(),
            timestamp: Instant::now(),
        };
        let response = state.handle_decode(&command);
        assert!(!response.success);
    }

    #[test]
    fn test_bot_state_rate_limit() {
        let config = BotConfig {
            rate_limit_requests: 2,
            ..Default::default()
        };
        let mut state = BotState::new(config);
        let command = BotCommand {
            name: "ciphey".to_string(),
            args: vec!["test".to_string()],
            user_id: "user1".to_string(),
            channel_id: "channel1".to_string(),
            timestamp: Instant::now(),
        };

        // First two requests should succeed
        let _ = state.handle_decode(&command);
        let _ = state.handle_decode(&command);
        // Third should be rate limited
        let response = state.handle_decode(&command);
        assert!(!response.success);
        assert!(response.message.contains("Rate limit"));
    }
}
