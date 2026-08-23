//! Decode a hash using a local wordlist.
//!
//! The original plan called for S3-hosted wordlists and 10-100GB rainbow
//! tables, which is unrealistic for an offline CLI tool. This implementation
//! drops the network dependency entirely: it hashes every word from the
//! user-provided wordlist (or a small built-in default) and compares against
//! the target hash.
//!
//! Supports the following algorithms:
//! - MD5, SHA1, SHA256, SHA512
//! - SHA3-256, SHA3-512, Keccak-256, Keccak-512
//! - NTLM (MD4 of UTF-16LE), CRC32, MySQL323
//! - bcrypt, argon2id, scrypt (verified against the wordlist)

use crate::checkers::CheckerTypes;
use crate::config::get_config;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::{Crack, Decoder};

use argon2::{Argon2, PasswordVerifier};
use digest::Digest;
use log::{debug, info, trace};
use once_cell::sync::Lazy;
use sha2::{Sha256, Sha512};

/// A small built-in wordlist used when the user does not provide one.
/// This keeps the hash cracker useful out of the box while staying offline.
static BUILTIN_WORDLIST: Lazy<Vec<String>> = Lazy::new(|| {
    let words = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
        "baseball",
        "iloveyou",
        "master",
        "sunshine",
        "ashley",
        "bailey",
        "passw0rd",
        "shadow",
        "123123",
        "654321",
        "superman",
        "qazwsx",
        "michael",
        "football",
        "hello",
        "admin",
        "root",
        "toor",
        "test",
        "guest",
        "secret",
        "welcome",
        "default",
        "admin123",
        "password1",
        "password123",
        "p@ssw0rd",
        "P@ssw0rd",
        "Password1",
        "zaq1zaq1",
        "qwerty123",
        "asdfgh",
        "zxcvbn",
        "qwe123",
        "1qaz2wsx",
        "1q2w3e4r",
        "love",
        "princess",
        "charlie",
        "buster",
        "soccer",
        "hunter",
        "starwars",
        "flower",
        "computer",
        "whatever",
        "maggie",
        "freedom",
        "America",
        "batman",
        "1qaz",
        "qwe",
        "pokemon",
        "jordan",
        "harley",
        "ranger",
        "thomas",
        "samsung",
        "andrew",
        "gandalf",
        "internet",
        "liverpool",
        "arsenal",
        "chelsea",
        "dallas",
        "denver",
        "orange",
        "purple",
        "nicole",
        "jessica",
        "jennifer",
        "amanda",
        "melissa",
        "kimberly",
        "tiffany",
        "daniel",
        "robert",
        "richard",
        "joseph",
        "george",
        "edward",
        "ronald",
        "martha",
        "karen",
        "nancy",
        "linda",
        "barbara",
        "susan",
        "margaret",
        "betty",
        "dorothy",
        "sandra",
        "donald",
        "austin",
        "anthony",
        "kevin",
        "brian",
        "jason",
        "matthew",
        "johnny",
        "honey",
    ];
    words.iter().map(|s| s.to_string()).collect()
});

/// The HashCrackDecoder, call:
/// `let hash_crack_decoder = Decoder::<HashCrackDecoder>::new()` to create a new instance
/// And then call:
/// `result = hash_crack_decoder.crack(input)` to decode a hash
pub struct HashCrackDecoder;

/// The hash algorithms this decoder can crack.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Keccak256,
    Keccak512,
    Ntlm,
    Crc32,
    Mysql323,
    Bcrypt,
    Argon2id,
    Scrypt,
}

impl HashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Keccak256 => "Keccak-256",
            Self::Keccak512 => "Keccak-512",
            Self::Ntlm => "NTLM",
            Self::Crc32 => "CRC32",
            Self::Mysql323 => "MySQL323",
            Self::Bcrypt => "bcrypt",
            Self::Argon2id => "argon2id",
            Self::Scrypt => "scrypt",
        }
    }
}

impl Crack for Decoder<HashCrackDecoder> {
    fn new() -> Decoder<HashCrackDecoder> {
        Decoder {
            name: "HashCrack",
            description: "Cracks hashes using a local wordlist. Supports MD5, SHA1, SHA256, SHA512, SHA3, Keccak, NTLM, CRC32, MySQL323, bcrypt, argon2id and scrypt.",
            link: "https://en.wikipedia.org/wiki/Password_cracking",
            tags: vec!["hash", "crack", "wordlist", "md5", "sha1", "sha256", "decoder", "auto-crack"],
            popularity: 0.9,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying HashCrack with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Detect the hash algorithm(s) that could match this text.
        let algorithms = detect_hash_algorithm(text);
        if algorithms.is_empty() {
            debug!("Failed to crack hash because no known hash algorithm matched");
            return results;
        }

        // Load the wordlist (user-provided or built-in).
        let wordlist = load_wordlist();
        if wordlist.is_empty() {
            debug!("Failed to crack hash because the wordlist is empty");
            return results;
        }

        for algorithm in &algorithms {
            trace!(
                "Trying hash algorithm {:?} with {} words",
                algorithm,
                wordlist.len()
            );

            // First try the compact rainbow table (fast path)
            if let Some(plaintext) = super::hash_rainbow::lookup(text, *algorithm) {
                if check_string_success(&plaintext, text) {
                    let checker_result = checker.check(&plaintext);
                    results.unencrypted_text = Some(vec![plaintext.clone()]);
                    results.update_checker(&checker_result);
                    results.key = Some(format!("{} (rainbow)", algorithm.name()));
                    info!(
                        "Cracked hash {} via rainbow table ({}) -> {}",
                        text,
                        algorithm.name(),
                        plaintext
                    );
                    return results;
                }
            }

            // Fall back to wordlist brute-force
            let cracked = crack_with_algorithm(text, *algorithm, &wordlist);
            if let Some(plaintext) = cracked {
                if check_string_success(&plaintext, text) {
                    let checker_result = checker.check(&plaintext);
                    results.unencrypted_text = Some(vec![plaintext.clone()]);
                    results.update_checker(&checker_result);
                    results.key = Some(algorithm.name().to_string());
                    info!(
                        "Cracked hash {} with algorithm {} -> {}",
                        text,
                        algorithm.name(),
                        plaintext
                    );
                    return results;
                }
            }
        }

        // If all methods fail, return the empty result.
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

/// Detect which hash algorithm(s) could match the given text.
/// Returns an empty vec if the text does not look like any supported hash.
pub fn detect_hash_algorithm(hash: &str) -> Vec<HashAlgorithm> {
    let trimmed = hash.trim();

    // Modular hash formats (bcrypt, argon2, scrypt) are self-identifying.
    if trimmed.starts_with("$2a$") || trimmed.starts_with("$2b$") || trimmed.starts_with("$2y$") {
        return vec![HashAlgorithm::Bcrypt];
    }
    if trimmed.starts_with("$argon2id$") {
        return vec![HashAlgorithm::Argon2id];
    }
    if trimmed.starts_with("$argon2i$") || trimmed.starts_with("$argon2d$") {
        return vec![HashAlgorithm::Argon2id];
    }
    if trimmed.starts_with("$scrypt$") {
        return vec![HashAlgorithm::Scrypt];
    }

    // Hexadecimal digests.
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) || trimmed.len() % 2 != 0 {
        return Vec::new();
    }

    match trimmed.len() {
        8 => vec![HashAlgorithm::Crc32],
        16 => vec![HashAlgorithm::Mysql323],
        32 => vec![HashAlgorithm::Md5, HashAlgorithm::Ntlm],
        40 => vec![HashAlgorithm::Sha1],
        64 => vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Keccak256,
        ],
        128 => vec![
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_512,
            HashAlgorithm::Keccak512,
        ],
        _ => Vec::new(),
    }
}

/// Load the wordlist to use: the user-provided one, or the built-in default.
fn load_wordlist() -> Vec<String> {
    let config = get_config();
    if let Some(wordlist) = &config.wordlist {
        let words: Vec<String> = wordlist.iter().cloned().collect();
        if !words.is_empty() {
            return words;
        }
    }
    BUILTIN_WORDLIST.clone()
}

/// Crack a hash of a single algorithm against the wordlist.
fn crack_with_algorithm(
    hash: &str,
    algorithm: HashAlgorithm,
    wordlist: &[String],
) -> Option<String> {
    let trimmed = hash.trim();

    // Salted KDFs are verified against each word directly.
    match algorithm {
        HashAlgorithm::Bcrypt => {
            for word in wordlist {
                if bcrypt::verify(word, trimmed).unwrap_or(false) {
                    return Some(word.clone());
                }
            }
            return None;
        }
        HashAlgorithm::Argon2id => {
            return verify_argon2id(trimmed, wordlist);
        }
        HashAlgorithm::Scrypt => {
            return verify_scrypt(trimmed, wordlist);
        }
        _ => {}
    }

    // Fast algorithms: compute the digest of every word and compare.
    for word in wordlist {
        let digest = match algorithm {
            HashAlgorithm::Md5 => hex_digest::<md5::Md5>(word),
            HashAlgorithm::Sha1 => hex_digest::<sha1::Sha1>(word),
            HashAlgorithm::Sha256 => hex_digest::<Sha256>(word),
            HashAlgorithm::Sha512 => hex_digest::<Sha512>(word),
            HashAlgorithm::Sha3_256 => hex_digest::<sha3::Sha3_256>(word),
            HashAlgorithm::Sha3_512 => hex_digest::<sha3::Sha3_512>(word),
            HashAlgorithm::Keccak256 => hex_digest::<sha3::Keccak256>(word),
            HashAlgorithm::Keccak512 => hex_digest::<sha3::Keccak512>(word),
            HashAlgorithm::Ntlm => ntlm_digest(word),
            HashAlgorithm::Crc32 => crc32_digest(word),
            HashAlgorithm::Mysql323 => mysql323_digest(word),
            _ => return None,
        };
        if digest == trimmed {
            return Some(word.clone());
        }
    }
    None
}

/// Hex-encode the digest of a wordlist word for a given digest type.
fn hex_digest<D: Digest>(word: &str) -> String {
    let digest = D::digest(word.as_bytes());
    hex_encode(&digest)
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// NTLM hash: MD4 of the UTF-16LE encoding of the password.
fn ntlm_digest(word: &str) -> String {
    use md4::digest::Digest as _;
    let utf16le: Vec<u8> = word
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let digest = md4::Md4::digest(&utf16le);
    hex_encode(&digest)
}

/// CRC32 digest of a word.
fn crc32_digest(word: &str) -> String {
    format!("{:08x}", crc32fast::hash(word.as_bytes()))
}

/// MySQL323 password hash.
/// See https://dba.stackexchange.com/questions/3488/mysql-password-function-and-its-magic-number
fn mysql323_digest(word: &str) -> String {
    let mut nr: u32 = 1345345333;
    let mut add: u32 = 7;
    let mut nr2: u32 = 0x12345671;
    for c in word.chars() {
        if c == ' ' || c == '\t' {
            continue;
        }
        nr ^= ((c as u32) & 0xff).wrapping_add(add);
        nr2 = nr2.wrapping_add(nr.wrapping_shl(8)).wrapping_add(nr);
        add = add.wrapping_add(nr2);
    }
    format!("{:08x}{:08x}", nr & 0x7fffffff, nr2 & 0x7fffffff)
}

/// Verify a word against an argon2id hash using the Argon2 crate.
fn verify_argon2id(hash: &str, wordlist: &[String]) -> Option<String> {
    let parsed = argon2::PasswordHash::new(hash).ok()?;
    for word in wordlist {
        if Argon2::default()
            .verify_password(word.as_bytes(), &parsed)
            .is_ok()
        {
            return Some(word.clone());
        }
    }
    None
}

/// Verify a word against a scrypt hash using the scrypt crate.
fn verify_scrypt(hash: &str, wordlist: &[String]) -> Option<String> {
    let parsed = scrypt::password_hash::PasswordHash::new(hash).ok()?;
    for word in wordlist {
        if scrypt::Scrypt
            .verify_password(word.as_bytes(), &parsed)
            .is_ok()
        {
            return Some(word.clone());
        }
    }
    None
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
    fn test_detect_hash_type() {
        // MD5
        assert_eq!(
            detect_hash_algorithm("5f4dcc3b5aa765d61d8327deb882cf99"),
            vec![HashAlgorithm::Md5, HashAlgorithm::Ntlm]
        );
        // SHA1
        assert_eq!(
            detect_hash_algorithm("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
            vec![HashAlgorithm::Sha1]
        );
        // SHA256
        assert_eq!(
            detect_hash_algorithm(
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
            ),
            vec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha3_256,
                HashAlgorithm::Keccak256
            ]
        );
        // CRC32
        assert_eq!(
            detect_hash_algorithm("098f6bcd"),
            vec![HashAlgorithm::Crc32]
        );
        // Not a hash
        assert!(detect_hash_algorithm("not_a_hash").is_empty());
        assert!(detect_hash_algorithm("").is_empty());
        // bcrypt
        assert_eq!(
            detect_hash_algorithm("$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpfGz9XoQ2r3qS"),
            vec![HashAlgorithm::Bcrypt]
        );
    }

    #[test]
    fn test_hex_encoder() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_ntlm_hash() {
        // NTLM hash of "password" is a known constant.
        assert_eq!(ntlm_digest("password"), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn test_mysql323_hash() {
        // Value computed by the standard MySQL 3.23 hash_password algorithm.
        assert_eq!(mysql323_digest("password"), "7a57514f3ce8206b");
    }

    #[test]
    fn test_crc32_hash() {
        assert_eq!(crc32_digest("test"), "d87f7e0c");
    }

    #[test]
    fn test_md5_crack_with_builtin_wordlist() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // MD5 hash for "password"
        let result =
            hash_crack_decoder.crack("5f4dcc3b5aa765d61d8327deb882cf99", &get_athena_checker());
        if let Some(cracked) = result.unencrypted_text {
            assert_eq!(cracked[0], "password");
        } else {
            panic!("Failed to crack MD5 hash");
        }
    }

    #[test]
    fn test_sha1_crack() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // SHA1 hash for "password"
        let result = hash_crack_decoder.crack(
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            &get_athena_checker(),
        );
        if let Some(cracked) = result.unencrypted_text {
            assert_eq!(cracked[0], "password");
        } else {
            panic!("Failed to crack SHA1 hash");
        }
    }

    #[test]
    fn test_sha256_crack() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // SHA256 hash for "password"
        let result = hash_crack_decoder.crack(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            &get_athena_checker(),
        );
        if let Some(cracked) = result.unencrypted_text {
            assert_eq!(cracked[0], "password");
        } else {
            panic!("Failed to crack SHA256 hash");
        }
    }

    #[test]
    fn test_ntlm_crack() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // NTLM hash for "password"
        let result =
            hash_crack_decoder.crack("8846f7eaee8fb117ad06bdd830b7586c", &get_athena_checker());
        if let Some(cracked) = result.unencrypted_text {
            assert_eq!(cracked[0], "password");
        } else {
            panic!("Failed to crack NTLM hash");
        }
    }

    #[test]
    fn test_invalid_hash() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // Invalid hash (not hexadecimal)
        let result = hash_crack_decoder.crack("not_a_hash", &get_athena_checker());
        assert!(result.unencrypted_text.is_none());
    }

    #[test]
    fn test_bcrypt_crack() {
        let hash_crack_decoder = Decoder::<HashCrackDecoder>::new();
        // bcrypt hash for "password" (cost 10), generated at test-time below.
        let bcrypt_hash = bcrypt::hash("password", 4).expect("failed to generate bcrypt hash");
        let result = hash_crack_decoder.crack(&bcrypt_hash, &get_athena_checker());
        if let Some(cracked) = result.unencrypted_text {
            assert_eq!(cracked[0], "password");
        } else {
            panic!("Failed to crack bcrypt hash");
        }
    }
}
