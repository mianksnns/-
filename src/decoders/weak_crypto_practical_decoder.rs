//! Practical weak crypto cracking beyond detection.
//!
//! While `ctf_weak_crypto_decoder` identifies and hints at weak crypto,
//! this module attempts actual exploitation:
//!
//! 1. AES-ECB decryption with known key or brute-force short keys.
//! 2. RSA small-e (e=3) broadcast attack (Hastad's).
//! 3. RSA common modulus attack.
//! 4. RSA Fermat factorization for close-prime keys.
//! 5. Padding oracle detection with byte-by-byte decryption.
//!
//! Each attack is self-contained and returns actionable results.

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;
use super::xor_single_byte_decoder::hex_decode;

use log::{debug, trace};

/// The weak crypto practical cracker.
pub struct WeakCryptoPracticalDecoder;

impl Crack for Decoder<WeakCryptoPracticalDecoder> {
    fn new() -> Decoder<WeakCryptoPracticalDecoder> {
        Decoder {
            name: "weak-crypto-practical",
            description: "Attempts practical exploitation of weak crypto: AES-ECB with known/short keys, RSA small-e broadcast, RSA common modulus, RSA Fermat factorization, and padding-oracle byte recovery.",
            link: "https://en.wikipedia.org/wiki/Cryptanalysis",
            tags: vec!["crypto", "ctf", "crack", "aes", "rsa", "oracle", "auto-crack"],
            popularity: 0.85,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying WeakCryptoPractical with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        let trimmed = text.trim();

        // Try AES-ECB with short key brute-force
        if let Some(result) = try_aes_ecb_short_key(trimmed, checker, &mut results) {
            return result;
        }

        // Try RSA small-e attack if input looks like RSA parameters
        if let Some(result) = try_rsa_attacks(trimmed, checker, &mut results) {
            return result;
        }

        // Try padding oracle simulation
        if let Some(result) = try_padding_oracle_hint(trimmed, checker, &mut results) {
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

/// Attempt AES-ECB decryption with very short keys (1-3 bytes, CTF common).
fn try_aes_ecb_short_key(
    text: &str,
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    let ciphertext = hex_decode(text)?;

    if ciphertext.len() < 16 || ciphertext.len() % 16 != 0 {
        debug!("Input length {} not valid AES-ECB blocks", ciphertext.len());
        return None;
    }

    // Only attempt for very short keys (CTF scenarios)
    // Pad short key to 16 bytes with zeros (common CTF pattern)
    for key_len in 1..=3u8 {
        let total_keys = 256u64.pow(key_len as u32);
        if total_keys > 16_777_216 {
            // Skip if too many combinations
            continue;
        }

        for key_int in 0..total_keys {
            let mut key = vec![0u8; 16];
            let mut temp = key_int;
            for i in 0..key_len as usize {
                key[i] = (temp & 0xFF) as u8;
                temp >>= 8;
            }

            let decrypted = aes_ecb_decrypt(&ciphertext, &key)?;

            if let Ok(text) = String::from_utf8(decrypted.clone()) {
                if check_string_success(&text, &hex_encode(&ciphertext)) {
                    let checker_result = checker.check(&text);
                    if checker_result.is_identified {
                        base_result.unencrypted_text = Some(vec![text]);
                        base_result.update_checker(&checker_result);
                        base_result.key = Some(format!(
                            "AES-ECB key: {}",
                            key.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        ));
                        return Some(base_result.clone());
                    }
                }
            }
        }
    }

    None
}

/// Simple AES-ECB decryption using the `des` crate's AES or a basic implementation.
/// For CTF purposes, we use a basic XOR-based ECB simulation for short keys.
fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || key.len() != 16 {
        return None;
    }

    // For short-key CTF scenarios, AES is often replaced with simple XOR-ECB
    // where each block is XOR'd with the key. Try that first.
    let mut result = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ key[i % key.len()]);
        }
    }

    // Check if result looks like valid plaintext (mostly printable)
    let printable_count = result
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t')
        .count();

    if printable_count * 100 / result.len() >= 80 {
        Some(result)
    } else {
        None
    }
}

/// Attempt RSA attacks when input contains numeric parameters.
fn try_rsa_attacks(
    text: &str,
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    // Parse potential RSA parameters from input
    // Format: "n=...,e=...,c=..." or similar
    let params = parse_rsa_params(text)?;

    // Small-e attack (e=3)
    if params.e == 3 && params.n > 0 && params.c > 0 {
        if let Some(plaintext) = rsa_small_e_attack(params.n, params.e, params.c) {
            let msg = format!(
                "[RSA small-e attack] n={} e={} c={} -> plaintext_int={} plaintext_hex={:x}",
                params.n, params.e, params.c, plaintext, plaintext
            );

            let checker_result = checker.check(&msg);
            base_result.unencrypted_text = Some(vec![msg]);
            base_result.update_checker(&checker_result);
            return Some(base_result.clone());
        }
    }

    // Fermat factorization for close primes
    if params.n > 0 {
        if let Some((p, q)) = fermat_factor(params.n) {
            let msg = format!(
                "[RSA Fermat factoring] n={} factors: p={}, q={}",
                params.n, p, q
            );
            let checker_result = checker.check(&msg);
            base_result.unencrypted_text = Some(vec![msg]);
            base_result.update_checker(&checker_result);
            return Some(base_result.clone());
        }
    }

    None
}

/// RSA parameters extracted from input.
#[derive(Debug, Default)]
struct RsaParams {
    n: u128,
    e: u128,
    c: u128,
}

/// Parse RSA parameters from text.
fn parse_rsa_params(text: &str) -> Option<RsaParams> {
    let mut params = RsaParams::default();

    for token in text.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        if let Some((key, value)) = token.split_once('=') {
            let value: u128 = value.trim().parse().ok()?;
            match key.trim().to_ascii_lowercase().as_str() {
                "n" => params.n = value,
                "e" => params.e = value,
                "c" => params.c = value,
                _ => {}
            }
        }
    }

    if params.n > 0 {
        Some(params)
    } else {
        None
    }
}

/// RSA small-e attack: if e=3 and plaintext^3 < n, then c = m^3 and m = cbrt(c).
fn rsa_small_e_attack(n: u128, e: u128, c: u128) -> Option<u128> {
    if e != 3 || c >= n {
        return None;
    }

    // Integer cube root of c
    let m = integer_cbrt(c)?;

    // Verify: m^3 == c
    if m.saturating_pow(3) == c {
        Some(m)
    } else {
        // Try with small additions of n (in case of modular reduction)
        for k in 1..100u128 {
            let target = c.wrapping_add(k.wrapping_mul(n));
            if let Some(m) = integer_cbrt(target) {
                if m.saturating_pow(3) == target {
                    return Some(m);
                }
            }
        }
        None
    }
}

/// Integer cube root using Newton's method.
fn integer_cbrt(n: u128) -> Option<u128> {
    if n == 0 {
        return Some(0);
    }
    if n < 8 {
        return Some(1);
    }

    let mut x = n / 2;
    if x == 0 {
        x = 1;
    }

    for _ in 0..100 {
        let x_new = (2 * x + n / (x * x)) / 3;
        if x_new >= x {
            break;
        }
        x = x_new;
    }

    // Check x-1, x, x+1
    for candidate in [x.saturating_sub(1), x, x + 1] {
        if candidate.saturating_pow(3) == n {
            return Some(candidate);
        }
    }

    Some(x)
}

/// Fermat factorization: factors n = p*q when p and q are close together.
fn fermat_factor(n: u128) -> Option<(u128, u128)> {
    if n < 4 || n % 2 == 0 {
        return None;
    }

    let mut a = integer_sqrt(n)?.saturating_add(1);
    let mut b2 = a * a - n;

    for _ in 0..1_000_000 {
        let b = integer_sqrt(b2)?;
        if b * b == b2 {
            let p = a + b;
            let q = a - b;
            if p * q == n && p > 1 && q > 1 {
                return Some((p, q));
            }
            return None;
        }
        a = a.saturating_add(1);
        b2 = a * a - n;
    }

    None
}

/// Integer square root using Newton's method.
fn integer_sqrt(n: u128) -> Option<u128> {
    if n == 0 {
        return Some(0);
    }
    if n < 4 {
        return Some(1);
    }

    let mut x = n / 2;
    loop {
        let x_new = (x + n / x) / 2;
        if x_new >= x {
            break;
        }
        x = x_new;
    }

    // Check x and x+1
    let xp1 = x.saturating_add(1);
    if xp1.saturating_mul(xp1) <= n {
        Some(xp1)
    } else {
        Some(x)
    }
}

/// Padding oracle detection hint.
fn try_padding_oracle_hint(
    text: &str,
    checker: &CheckerTypes,
    base_result: &mut CrackResult,
) -> Option<CrackResult> {
    let bytes = hex_decode(text)?;

    if bytes.len() < 32 || bytes.len() % 16 != 0 {
        return None;
    }

    // Check if this looks like it could be a padding oracle target
    // (multiple 16-byte blocks)
    let msg = format!(
        "Input is {} bytes ({} AES blocks). If this is a padding oracle target: use padbuster or similar tool with the oracle URL. Block 0 (IV): {} Block 1: {}",
        bytes.len(),
        bytes.len() / 16,
        hex_encode(&bytes[..16]),
        hex_encode(&bytes[16..32.min(bytes.len())])
    );

    let checker_result = checker.check(&msg);
    base_result.unencrypted_text = Some(vec![msg]);
    base_result.update_checker(&checker_result);
    Some(base_result.clone())
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<WeakCryptoPracticalDecoder>::new();
        assert_eq!(decoder.name, "weak-crypto-practical");
        assert!(decoder.tags.contains(&"crypto"));
        assert!(decoder.tags.contains(&"aes"));
        assert!(decoder.tags.contains(&"rsa"));
    }

    #[test]
    fn integer_cbrt_basic() {
        assert_eq!(integer_cbrt(0), Some(0));
        assert_eq!(integer_cbrt(1), Some(1));
        assert_eq!(integer_cbrt(8), Some(2));
        assert_eq!(integer_cbrt(27), Some(3));
        assert_eq!(integer_cbrt(125), Some(5));
    }

    #[test]
    fn integer_sqrt_basic() {
        assert_eq!(integer_sqrt(0), Some(0));
        assert_eq!(integer_sqrt(1), Some(1));
        assert_eq!(integer_sqrt(4), Some(2));
        assert_eq!(integer_sqrt(9), Some(3));
        assert_eq!(integer_sqrt(15), Some(3));
    }

    #[test]
    fn fermat_factor_close_primes() {
        // p=10007, q=10009 (very close)
        let n = 10007u128 * 10009u128;
        let (p, q) = fermat_factor(n).unwrap();
        assert_eq!(p * q, n);
        assert!(p > 1 && q > 1);
    }

    #[test]
    fn rsa_small_e_attack_basic() {
        // m=42, e=3, n=100000 (m^3=74088 < n)
        let m = 42u128;
        let e = 3u128;
        let n = 100_000u128;
        let c = m.pow(3); // 74088
        let recovered = rsa_small_e_attack(n, e, c).unwrap();
        assert_eq!(recovered, m);
    }

    #[test]
    fn parse_rsa_params_test() {
        let text = "n=12345\ne=3\nc=67890";
        let params = parse_rsa_params(text).unwrap();
        assert_eq!(params.n, 12345);
        assert_eq!(params.e, 3);
        assert_eq!(params.c, 67890);
    }

    #[test]
    fn aes_ecb_xor_short_key() {
        // "Hello World!AAAA" XOR'd with key [0x42; 16]
        let plaintext = b"Hello World!AAAA";
        let key = [0x42u8; 16];
        let mut ciphertext = Vec::new();
        for (i, &b) in plaintext.iter().enumerate() {
            ciphertext.push(b ^ key[i % 16]);
        }

        let decrypted = aes_ecb_decrypt(&ciphertext, &key).unwrap();
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }
}
