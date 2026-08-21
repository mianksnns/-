use ciphey::cli::parse_cli_args;
use ciphey::cli_pretty_printing::{
    json_decode_failure, json_decode_success, program_exiting_successful_decoding, success,
};
use ciphey::perform_cracking;

fn main() {
    // Turn CLI arguments into a library object
    let (text, config) = parse_cli_args();
    let result = perform_cracking(&text, config.clone());
    if config.json_output {
        match result {
            Some(res) => json_decode_success(&res),
            None => json_decode_failure(),
        }
        return;
    }
    success(&format!(
        "DEBUG: main.rs - Result from perform_cracking: {:?}",
        result.is_some()
    ));
    match result {
        // TODO: As result have array of CrackResult used,
        // we can print in better way with more info
        Some(result) => {
            success(&format!(
                "DEBUG: main.rs - Got successful result with {} decoders in path",
                result.path.len()
            ));
            program_exiting_successful_decoding(result);
        }
        None => {
            success("DEBUG: main.rs - Got None result, calling failed_to_decode");
            ciphey::cli_pretty_printing::failed_to_decode()
        }
    }
}
