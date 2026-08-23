use ciphey::cli::{
    handle_cache_command, handle_generate_completion, parse_cli_args, read_stdin, InputSource,
};
use ciphey::cli_pretty_printing::{
    json_decode_failure, json_decode_success, program_exiting_successful_decoding, success,
};
use ciphey::perform_cracking;

fn main() {
    // Turn CLI arguments into a library object
    let (input_source, config) = parse_cli_args();

    // Handle cache commands before normal processing
    if let Some(ref cache_op) = config.cache_op {
        handle_cache_command(cache_op, config.cache_limit);
        return;
    }

    // Handle shell completion generation before normal processing
    if let Some(ref shell) = config.generate_completion {
        handle_generate_completion(shell);
        return;
    }

    match input_source {
        InputSource::Batch(inputs) => {
            run_batch(inputs, config);
        }
        _ => {
            let text = resolve_input(input_source);

            // Use TUI mode if enabled
            let result = if config.tui_mode {
                ciphey::tui::run_tui(&text, config.clone())
            } else {
                perform_cracking(&text, config.clone())
            };

            if config.json_output {
                match result {
                    Some(res) => json_decode_success(&res),
                    None => json_decode_failure(),
                }
                return;
            }
            match result {
                Some(result) => {
                    program_exiting_successful_decoding(result);
                }
                None => ciphey::cli_pretty_printing::failed_to_decode(),
            }
        }
    }
}

/// Resolve input source to a single string
fn resolve_input(input: InputSource) -> String {
    match input {
        InputSource::Text(text) => text,
        InputSource::File(path) => ciphey::cli::read_and_parse_file(path),
        InputSource::Stdin => read_stdin(),
        InputSource::Batch(_) => unreachable!("Batch handled separately"),
    }
}

/// Run batch processing on multiple inputs
fn run_batch(inputs: Vec<String>, config: ciphey::config::Config) {
    use ciphey::cli_pretty_printing::statement;

    let total = inputs.len();
    println!(
        "{}",
        statement(
            &format!("Processing {} ciphertext(s) in batch mode...", total),
            Some("informational")
        )
    );

    let mut results = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        if !config.api_mode && !config.json_output {
            eprintln!(
                "  [{}/{}] Decoding: {}...",
                i + 1,
                total,
                if input.len() > 50 {
                    format!("{}...", &input[..50])
                } else {
                    input.clone()
                }
            );
        }
        let result = perform_cracking(input, config.clone());
        results.push((input.clone(), result));
    }

    if config.json_output {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(input, result)| match result {
                Some(res) => {
                    let plaintext = res.text.first().cloned().unwrap_or_default();
                    let path: Vec<String> =
                        res.path.iter().map(|c| c.decoder.to_string()).collect();
                    serde_json::json!({
                        "input": input,
                        "success": true,
                        "plaintext": plaintext,
                        "path": path,
                    })
                }
                None => serde_json::json!({
                    "input": input,
                    "success": false,
                    "error": "Failed to decode",
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json_results).unwrap_or_default()
        );
    } else {
        for (i, (input, result)) in results.iter().enumerate() {
            match result {
                Some(res) => {
                    let plaintext = res.text.first().cloned().unwrap_or_default();
                    let path: Vec<String> =
                        res.path.iter().map(|c| c.decoder.to_string()).collect();
                    println!(
                        "\n[{}] Input: {}",
                        i + 1,
                        if input.len() > 50 {
                            format!("{}...", &input[..50])
                        } else {
                            input.clone()
                        }
                    );
                    println!("    Plaintext: {}", plaintext);
                    println!("    Path: {}", path.join(" → "));
                }
                None => {
                    println!("\n[{}] Input: {}", i + 1, input);
                    println!("    Result: Failed to decode");
                }
            }
        }
    }
}
