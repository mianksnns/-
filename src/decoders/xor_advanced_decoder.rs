//! XOR with known plaintext and two-ciphertext XOR attacks.
//!
//! When the attacker knows some plaintext (a "crib"), XORing the known plaintext
//! with the ciphertext reveals the key. Similarly, when two messages are XOR'd
//! with the same key, XORing the two ciphertexts together eliminates the key
//! and produces plaintext1 XOR plaintext2, which can often be solved by crib-dragging.
//!
//! This decoder implements both attack modes:
//! 1. Known-plaintext: given ciphertext + known plaintext, recover the key.
//! 2. Two-ciphertext: given two ciphertexts XOR'd with the same key, recover
//!    both plaintexts via crib-dragging.
//!
//! The decoder works on hex-encoded inputs. For known-plaintext mode, the input
//! is expected as "ciphertext_hex:known_plaintext". For two-ciphertext mode,
//! the input is "ciphertext1_hex:ciphertext2_hex".

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;
use super::xor_single_byte_decoder::hex_decode;

use log::{debug, trace};

/// The XOR advanced decoder (known-plaintext and two-ciphertext attacks).
pub struct XorAdvancedDecoder;

impl Crack for Decoder<XorAdvancedDecoder> {
    fn new() -> Decoder<XorAdvancedDecoder> {
        Decoder {
            name: "xor-advanced",
            description: "XOR cipher attacks using known plaintext or two ciphertexts. Input format: hex_ciphertext:known_plaintext (known-plaintext mode) or hex_ciphertext1:hex_ciphertext2 (two-ciphertext mode). Recovers the key and decrypts without brute force.",
            link: "https://en.wikipedia.org/wiki/XOR_cipher",
            tags: vec!["xor", "crypto", "crib", "attack", "auto-crack"],
            popularity: 0.8,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying XorAdvanced with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let trimmed = text.trim();
        let (part1, part2) = match trimmed.split_once(':') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => {
                debug!("XorAdvanced input must contain ':' separator");
                return results;
            }
        };

        // Mode 1: known-plaintext attack
        if !part2.is_empty() && part2.as_bytes().iter().all(|&b| {
            b.is_ascii_alphanumeric() || b == b' ' || b == b'.' || b == b',' || b == b'!' || b == b'?'
        }) {
            if let Some(result) =
                known_plaintext_attack(part1, part2, checker, &mut results)
            {
                return result;
            }
        }

        // Mode 2: two-ciphertext XOR attack
        if let Some(result) = two_ciphertext_attack(part1, part2, checker, &mut results) {
            return result;
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

/// Known-plaintext XOR attack: XOR ciphertext with known plaintext to recover key.
fn known_plaintext_attack(
    cipher_hex: &str,
    known_plaintext: &str,
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    let ciphertext = hex_decode(cipher_hex)?;
    let plain_bytes = known_plaintext.as_bytes();

    if ciphertext.len() < plain_bytes.len() {
        debug!("Ciphertext shorter than known plaintext");
        return None;
    }

    // Derive key bytes: key[i] = ciphertext[i] XOR plaintext[i]
    let key: Vec<u8> = ciphertext[..plain_bytes.len()]
        .iter()
        .zip(plain_bytes.iter())
        .map(|(&c, &p)| c ^ p)
        .collect();

    // If we found a repeating key pattern, use it for the full decryption
    if let Some(key_len) = detect_repeating_key_len(&key) {
        let short_key = &key[..key_len];
        let decrypted: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ short_key[i % key_len])
            .collect();

        if let Ok(text) = String::from_utf8(decrypted) {
            if check_string_success(&text, cipher_hex) {
                let checker_result = checker.check(&text);
                if checker_result.is_identified {
                    base_result.unencrypted_text = Some(vec![text]);
                    base_result.update_checker(&checker_result);
                    base_result.key = Some(format!(
                        "key={}",
                        short_key
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>()
                    ));
                    return Some(base_result.clone());
                }
            }
        }
    }

    // Fallback: use the full derived key as single-byte if all same
    if key.iter().all(|&b| b == key[0]) {
        let decrypted: Vec<u8> = ciphertext.iter().map(|&b| b ^ key[0]).collect();
        if let Ok(text) = String::from_utf8(decrypted) {
            if check_string_success(&text, cipher_hex) {
                let checker_result = checker.check(&text);
                base_result.unencrypted_text = Some(vec![text]);
                base_result.update_checker(&checker_result);
                base_result.key = Some(format!("single-byte key={:02x}", key[0]));
                return Some(base_result.clone());
            }
        }
    }

    // Use derived key directly to decrypt
    let decrypted: Vec<u8> = ciphertext
        .iter()
        .zip(key.iter().cycle())
        .map(|(&c, &k)| c ^ k)
        .collect();

    if let Ok(text) = String::from_utf8(decrypted) {
        if check_string_success(&text, cipher_hex) {
            let checker_result = checker.check(&text);
            if checker_result.is_identified {
                base_result.unencrypted_text = Some(vec![text]);
                base_result.update_checker(&checker_result);
                base_result.key = Some(format!(
                    "derived key={}",
                    key.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                ));
                return Some(base_result.clone());
            }
        }
    }

    None
}

/// Two-ciphertext XOR attack: XOR two ciphertexts encrypted with the same key.
fn two_ciphertext_attack(
    cipher1_hex: &str,
    cipher2_hex: &str,
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    let ct1 = hex_decode(cipher1_hex)?;
    let ct2 = hex_decode(cipher2_hex)?;

    if ct1.is_empty() || ct2.is_empty() {
        debug!("Empty ciphertext in two-ciphertext attack");
        return None;
    }

    // ct1 XOR ct2 = pt1 XOR pt2 (key cancels out)
    let xored: Vec<u8> = ct1.iter().zip(ct2.iter()).map(|(&a, &b)| a ^ b).collect();

    // Try common cribs to recover plaintext
    let cribs: Vec<&[u8]> = vec![
        b" the ",
        b" The ",
        b" and ",
        b" is ",
        b" to ",
        b" a ",
        b" in ",
        b" of ",
        b" for ",
        b" with ",
        b" on ",
        b" CTF",
        b" flag",
        b" ciphey",
        b" hello",
        b" password",
        b" secret",
        b" message",
    ];

    for crib in &cribs {
        // Try XORing the crib at each position in the XOR'd result
        for pos in 0..xored.len().saturating_sub(crib.len()) {
            let candidate: Vec<u8> = xored[pos..pos + crib.len()]
                .iter()
                .zip(crib.iter())
                .map(|(&x, &c)| x ^ c)
                .collect();

            if candidate.iter().all(|&b| {
                b.is_ascii_alphanumeric() || b == b' ' || b == b'.' || b == b',' || b == b'!' || b == b'_'
            }) {
                // This might be part of plaintext2; verify by deriving what plaintext1 would be
                let pt1_fragment: Vec<u8> = xored[pos..pos + crib.len()]
                    .iter()
                    .zip(candidate.iter())
                    .map(|(&x, &p2)| x ^ p2)
                    .collect();

                if let (Ok(frag1), Ok(frag2)) = (
                    String::from_utf8(pt1_fragment),
                    String::from_utf8(candidate),
                ) {
                    // Try to extend using the crib as key material
                    if let Some(full_result) =
                        try_extend_two_cipher(&ct1, &ct2, &xored, pos, crib, checker, base_result)
                    {
                        return Some(full_result);
                    }

                    // At minimum, report the partial recovery
                    if frag1.len() >= 4 && is_plausible_text(&frag1) && is_plausible_text(&frag2) {
                        let msg = format!(
                            "Partial recovery at offset {}: pt1=\"{}\" pt2=\"{}\"",
                            pos, frag1, frag2
                        );
                        let checker_result = checker.check(&msg);
                        base_result.unencrypted_text = Some(vec![msg]);
                        base_result.update_checker(&checker_result);
                        return Some(base_result.clone());
                    }
                }
            }
        }
    }

    None
}

/// Try to extend a partial crib match into a fuller decryption.
fn try_extend_two_cipher(
    ct1: &[u8],
    _ct2: &[u8],
    _xored: &[u8],
    pos: usize,
    crib: &[u8],
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    // Derive key fragment: key[pos..pos+crib.len()] = ct1[pos..] XOR crib
    let key_fragment: Vec<u8> = ct1[pos..pos + crib.len()]
        .iter()
        .zip(crib.iter())
        .map(|(&c, &p)| c ^ p)
        .collect();

    // Try to decrypt ct1 with this key fragment (repeated if needed)
    let decrypted1: Vec<u8> = ct1
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if i >= pos && i < pos + crib.len() {
                c ^ key_fragment[i - pos]
            } else {
                c // Can't decrypt without full key
            }
        })
        .collect();

    // Only return if the decrypted portion is valid UTF-8 and plausible
    let dec_fragment = &decrypted1[pos..pos + crib.len().min(decrypted1.len() - pos)];
    if let Ok(text) = String::from_utf8(dec_fragment.to_vec()) {
        if is_plausible_text(&text) {
            let msg = format!(
                "Recovered key fragment at offset {}: \"{}\" -> pt1 fragment: \"{}\"",
                pos,
                String::from_utf8_lossy(&key_fragment),
                text
            );
            let checker_result = checker.check(&msg);
            base_result.unencrypted_text = Some(vec![msg]);
            base_result.update_checker(&checker_result);
            return Some(base_result.clone());
        }
    }

    None
}

/// Detect if a key is repeating (returns the period if so).
fn detect_repeating_key_len(key: &[u8]) -> Option<usize> {
    if key.len() < 4 {
        return None;
    }

    for period in 1..=key.len() / 2 {
        let mut repeating = true;
        for i in period..key.len() {
            if key[i] != key[i % period] {
                repeating = false;
                break;
            }
        }
        if repeating {
            return Some(period);
        }
    }

    None
}

/// Quick heuristic: is this string plausible English text?
fn is_plausible_text(text: &str) -> bool {
    if text.len() < 2 {
        return false;
    }
    let printable = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    printable * 100 / text.len().max(1) >= 80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<XorAdvancedDecoder>::new();
        assert_eq!(decoder.name, "xor-advanced");
        assert!(decoder.tags.contains(&"xor"));
        assert!(decoder.tags.contains(&"crypto"));
    }

    #[test]
    fn known_plaintext_basic() {
        // "hello" XOR'd with key 0x42
        // h=0x68, e=0x65, l=0x6c, l=0x6c, o=0x6f
        // XOR with 0x42: 0x2a, 0x27, 0x2e, 0x2e, 0x2d
        let ct = "2a272e2e2d";
        let key = ct
            .as_bytes()
            .chunks(2)
            .map(|c| {
                let hi = (c[0] as char).to_digit(16).unwrap() << 4;
                let lo = (c[1] as char).to_digit(16).unwrap();
                (hi | lo) as u8
            })
            .collect::<Vec<_>>();

        // Verify: XOR with "hello" should give 0x42
        let derived: Vec<u8> = key
            .iter()
            .zip(b"hello".iter())
            .map(|(&k, &p)| k ^ p)
            .collect();
        assert!(derived.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn two_ciphertext_math() {
        let pt1 = b"hello world";
        let pt2 = b"secret msg!";
        let key: Vec<u8> = vec![0xAB; 12];

        let ct1: Vec<u8> = pt1.iter().zip(key.iter()).map(|(&p, &k)| p ^ k).collect();
        let ct2: Vec<u8> = pt2.iter().zip(key.iter()).map(|(&p, &k)| p ^ k).collect();

        // ct1 XOR ct2 = pt1 XOR pt2 (key cancels)
        let xored: Vec<u8> = ct1.iter().zip(ct2.iter()).map(|(&a, &b)| a ^ b).collect();
        let recovered: Vec<u8> = xored.iter().zip(pt1.iter()).map(|(&x, &p)| x ^ p).collect();
        assert_eq!(recovered, pt2);
    }
}
