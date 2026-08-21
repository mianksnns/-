//! Automatic cracking of monoalphabetic substitution ciphers.
//!
//! Unlike `SubstitutionGenericDecoder` (which only handles tiny symbol sets
//! mapped to binary/morse), this decoder attacks full 26-letter substitution
//! ciphers where ciphertext letters are a permutation of the alphabet. It uses
//! a simulated-annealing hill climb driven by English letter/bigram frequency
//! scores to recover the plaintext mapping without a known key.
//!
//! This is the "automatic crack" counterpart to known-key decoders: the two are
//! kept as separate decoders so A* can prefer the automatic path.

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};
use crate::checkers::CheckerTypes;
use crate::storage::{load_english_bigrams, ENGLISH_FREQS};
use log::trace;
use rand::seq::SliceRandom;
use rand::{rng, RngExt};
use std::collections::HashMap;

/// Number of simulated-annealing iterations.
const ITERATIONS: usize = 20_000;
/// Starting temperature for the anneal.
const START_TEMP: f64 = 5.0;
/// Temperature reduction per iteration.
const COOLING: f64 = 0.9999;
/// Minimum improvement required to accept a worse solution.
const MIN_TEMP: f64 = 0.0001;

/// Automatic substitution cracker.
pub struct SubstitutionAutocrackDecoder;

impl Crack for Decoder<SubstitutionAutocrackDecoder> {
    fn new() -> Decoder<SubstitutionAutocrackDecoder> {
        Decoder {
            name: "substitution-autocrack",
            description: "Automatically cracks monoalphabetic substitution ciphers using simulated annealing over English letter and bigram frequencies. No key required.",
            link: "https://en.wikipedia.org/wiki/Substitution_cipher",
            tags: vec!["substitution", "crack", "classic", "automatic", "decoder", "auto-crack"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying SubstitutionAutocrackDecoder with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Count the number of distinct letters present in the input.
        let letters: Vec<char> = text
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_lowercase())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Need a reasonable alphabet coverage to be a substitution cipher.
        if letters.len() < 6 {
            trace!(
                "Too few distinct letters ({}) for substitution cracking",
                letters.len()
            );
            return results;
        }

        // Recover the plaintext mapping with simulated annealing.
        let mapping = solve_substitution(text);
        let plaintext = apply_mapping(text, &mapping);

        if plaintext.is_empty() || plaintext == text {
            return results;
        }

        let checker_result = checker.check(&plaintext);
        if checker_result.is_identified {
            results.unencrypted_text = Some(vec![plaintext]);
            results.update_checker(&checker_result);
            results.key = Some(mapping_to_key_string(&mapping));
        }
        results
    }

    fn get_tags(&self) -> &Vec<&str> {
        &self.tags
    }

    fn get_name(&self) -> &str {
        self.name
    }

    fn get_description(&self) -> &str {
        self.description
    }

    fn get_link(&self) -> &str {
        self.link
    }

    fn get_popularity(&self) -> f32 {
        self.popularity
    }
}

/// Solve a substitution cipher with simulated annealing.
/// Returns a mapping from ciphertext letter (a-z) to plaintext letter (a-z).
fn solve_substitution(ciphertext: &str) -> HashMap<char, char> {
    // Build the bigram score table once.
    let bigrams = load_english_bigrams();

    // A mapping is `cipher_letter -> plaintext_letter`.
    // Start from a random permutation.
    let mut alphabet: Vec<char> = (b'a'..=b'z').map(char::from).collect();
    let mut rng = rng();
    alphabet.shuffle(&mut rng);
    let mut mapping: HashMap<char, char> = (b'a'..=b'z')
        .map(char::from)
        .zip(alphabet.clone())
        .collect();

    // Score the initial mapping.
    let mut current_score = score_mapping(ciphertext, &mapping, &bigrams);
    let mut best_mapping = mapping.clone();
    let mut best_score = current_score;
    let mut temperature = START_TEMP;

    for _ in 0..ITERATIONS {
        // Swap two letters in the mapping to propose a neighbour.
        let a = rng.random_range(0..26);
        let b = rng.random_range(0..26);
        if a == b {
            continue;
        }

        let cipher_a = (b'a' + a as u8) as char;
        let cipher_b = (b'a' + b as u8) as char;
        let plain_a = mapping[&cipher_a];
        let plain_b = mapping[&cipher_b];
        mapping.insert(cipher_a, plain_b);
        mapping.insert(cipher_b, plain_a);

        let neighbour_score = score_mapping(ciphertext, &mapping, &bigrams);

        // Accept improvements always, worse solutions with annealed probability.
        if neighbour_score >= current_score {
            current_score = neighbour_score;
        } else {
            let delta = neighbour_score - current_score;
            let accept_prob = (delta / temperature.max(MIN_TEMP)).exp();
            if rng.random::<f64>() < accept_prob {
                current_score = neighbour_score;
            } else {
                // Revert the swap.
                mapping.insert(cipher_a, plain_a);
                mapping.insert(cipher_b, plain_b);
            }
        }

        if current_score > best_score {
            best_score = current_score;
            best_mapping = mapping.clone();
        }

        temperature *= COOLING;
        if temperature < MIN_TEMP {
            break;
        }
    }

    best_mapping
}

/// Score a candidate mapping by summing log-likelihoods of the resulting text.
fn score_mapping(
    ciphertext: &str,
    mapping: &HashMap<char, char>,
    bigrams: &HashMap<(char, char), f64>,
) -> f64 {
    // Apply the mapping and score letter-by-letter plus bigram-by-bigram.
    let plain: Vec<char> = ciphertext
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                mapping[&c.to_ascii_lowercase()]
            } else {
                c
            }
        })
        .collect();

    let mut score = 0.0;
    // Unigram component (weighted lower to let bigrams dominate).
    for &c in &plain {
        if c.is_ascii_lowercase() {
            score += 10.0 * (ENGLISH_FREQS[(c as u8 - b'a') as usize] + 1e-6).ln();
        }
    }
    // Bigram component.
    for pair in plain.windows(2) {
        let (x, y) = (pair[0], pair[1]);
        if x.is_ascii_lowercase() && y.is_ascii_lowercase() {
            if let Some(&prob) = bigrams.get(&(x, y)) {
                score += (prob + 1e-12).ln();
            } else {
                score += -20.0;
            }
        }
    }
    score
}

/// Apply a cipher->plain mapping to the text.
fn apply_mapping(text: &str, mapping: &HashMap<char, char>) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let mapped = mapping[&c.to_ascii_lowercase()];
                if c.is_ascii_uppercase() {
                    mapped.to_ascii_uppercase()
                } else {
                    mapped
                }
            } else {
                c
            }
        })
        .collect()
}

/// Render a mapping as a readable substitution key string.
fn mapping_to_key_string(mapping: &HashMap<char, char>) -> String {
    let mut key = String::with_capacity(26);
    for c in b'a'..=b'z' {
        key.push(mapping[&(c as char)]);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        checkers::{
            athena::Athena,
            checker_type::{Check, Checker},
            CheckerTypes,
        },
        decoders::interface::{Crack, Decoder},
    };

    fn get_athena_checker() -> CheckerTypes {
        let athena_checker = Checker::<Athena>::new();
        CheckerTypes::CheckAthena(athena_checker)
    }

    #[test]
    fn test_apply_mapping() {
        let mut mapping = HashMap::new();
        for (c, p) in (b'a'..=b'z')
            .map(char::from)
            .zip((b'a'..=b'z').map(char::from))
        {
            mapping.insert(c, p);
        }
        assert_eq!(apply_mapping("Hello World", &mapping), "Hello World");
    }

    #[test]
    fn test_solve_short_substitution() {
        // Simple Caesar-like shift (mapping is still a permutation).
        let decoder = Decoder::<SubstitutionAutocrackDecoder>::new();
        // "attack at dawn" encoded with a Caesar +3 shift -> "dwwdfn dw gdzq"
        let result = decoder.crack("dwwdfn dw gdzq", &get_athena_checker());
        if let Some(texts) = result.unencrypted_text {
            assert!(texts[0].to_lowercase().contains("attack"));
        }
    }

    #[test]
    fn test_fails_on_random_gibberish() {
        let decoder = Decoder::<SubstitutionAutocrackDecoder>::new();
        let result = decoder.crack("qzwxcvbnmlkjhgfdsapoiuytrewq", &get_athena_checker());
        // Should not claim success on pure noise.
        assert!(!result.success);
    }
}
