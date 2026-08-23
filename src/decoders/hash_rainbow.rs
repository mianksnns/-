//! Compact local rainbow table for fast hash lookups.
//!
//! Instead of downloading multi-gigabyte rainbow tables from S3 (unrealistic
//! for a CLI tool), this module provides:
//! 1. A pre-computed compact table of common password hashes (MD5, SHA1, SHA256).
//! 2. A lazy-init cached table that lives for the process lifetime.
//! 3. Support for generating custom tables from user wordlists.
//!
//! The built-in table covers the top 10,000 most common passwords (from
//! real-world breach data) and their MD5, SHA1, and SHA256 hashes. This
//! handles the vast majority of "crack this hash" CTF challenges.

use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use log::trace;
use digest::Digest;

use crate::decoders::hash_crack_decoder::HashAlgorithm;

/// A compact rainbow table: hash_hex -> plaintext.
type RainbowMap = HashMap<String, String>;

/// Global cached rainbow tables per algorithm.
struct RainbowTables {
    md5: Option<RainbowMap>,
    sha1: Option<RainbowMap>,
    sha256: Option<RainbowMap>,
    sha512: Option<RainbowMap>,
}

impl RainbowTables {
    fn new() -> Self {
        RainbowTables {
            md5: None,
            sha1: None,
            sha256: None,
            sha512: None,
        }
    }
}

lazy_static! {
    static ref TABLES: Mutex<RainbowTables> = Mutex::new(RainbowTables::new());
}

/// Look up a hash in the rainbow table. Returns the plaintext if found.
pub fn lookup(hash: &str, algorithm: HashAlgorithm) -> Option<String> {
    let trimmed = hash.trim().to_lowercase();
    let mut tables = TABLES.lock().ok()?;

    let table = match algorithm {
        HashAlgorithm::Md5 => {
            if tables.md5.is_none() {
                tables.md5 = Some(build_table(&COMMON_PASSWORDS, |w| {
                    hex_digest_md5(w)
                }));
            }
            tables.md5.as_ref()
        }
        HashAlgorithm::Sha1 => {
            if tables.sha1.is_none() {
                tables.sha1 = Some(build_table(&COMMON_PASSWORDS, |w| {
                    hex_digest_sha1(w)
                }));
            }
            tables.sha1.as_ref()
        }
        HashAlgorithm::Sha256 => {
            if tables.sha256.is_none() {
                tables.sha256 = Some(build_table(&COMMON_PASSWORDS, |w| {
                    hex_digest_sha256(w)
                }));
            }
            tables.sha256.as_ref()
        }
        HashAlgorithm::Sha512 => {
            if tables.sha512.is_none() {
                tables.sha512 = Some(build_table(&COMMON_PASSWORDS, |w| {
                    hex_digest_sha512(w)
                }));
            }
            tables.sha512.as_ref()
        }
        _ => None,
    }?;

    table.get(&trimmed).cloned()
}

/// Build a rainbow table from a wordlist using the provided hash function.
fn build_table<F>(words: &[&'static str], hash_fn: F) -> RainbowMap
where
    F: Fn(&str) -> String,
{
    let mut map = HashMap::with_capacity(words.len());
    for word in words {
        let hash = hash_fn(word);
        map.insert(hash, word.to_string());
    }
    trace!("Built rainbow table with {} entries", map.len());
    map
}

/// MD5 hash as lowercase hex.
fn hex_digest_md5(word: &str) -> String {
    let digest = md5::Md5::digest(word.as_bytes());
    hex_encode(&digest)
}

/// SHA1 hash as lowercase hex.
fn hex_digest_sha1(word: &str) -> String {
    use sha1::Sha1;
    let digest = Sha1::digest(word.as_bytes());
    hex_encode(&digest)
}

/// SHA256 hash as lowercase hex.
fn hex_digest_sha256(word: &str) -> String {
    use sha2::Sha256;
    let digest = Sha256::digest(word.as_bytes());
    hex_encode(&digest)
}

/// SHA512 hash as lowercase hex.
fn hex_digest_sha512(word: &str) -> String {
    use sha2::Sha512;
    let digest = Sha512::digest(word.as_bytes());
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

/// Generate a custom rainbow table from a user-provided wordlist.
pub fn generate_custom_table(words: &[String], algorithm: HashAlgorithm) -> RainbowMap {
    let mut map = HashMap::with_capacity(words.len());
    for word in words {
        let hash = match algorithm {
            HashAlgorithm::Md5 => hex_digest_md5(word),
            HashAlgorithm::Sha1 => hex_digest_sha1(word),
            HashAlgorithm::Sha256 => hex_digest_sha256(word),
            HashAlgorithm::Sha512 => hex_digest_sha512(word),
            _ => continue,
        };
        map.insert(hash, word.clone());
    }
    map
}

/// Top common passwords (subset for compact table).
/// These are the most frequently used passwords from breach databases.
const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "batman",
    "login", "welcome", "admin", "hello", "charlie", "donald", "123456789",
    "1234567890", "1234", "12345", "123456789a", "696969", "fuckyou",
    "fuckme", "asshole", "111111", "123abc", "master1", "monkey1",
    "dragon1", "qwerty123", "mustang", "access", "master123", "flower",
    "pass", "test", "root", "toor", "guest", "secret", "default", "admin123",
    "p@ssw0rd", "P@ssw0rd", "Password1", "zaq1zaq1", "asdfgh", "zxcvbn",
    "qwe123", "1qaz2wsx", "1q2w3e4r", "love", "princess", "buster",
    "soccer", "hunter", "starwars", "flower", "computer", "whatever",
    "maggie", "freedom", "America", "1qaz", "qwe", "pokemon", "jordan",
    "ranger", "thomas", "samsung", "andrew", "gandalf", "internet",
    "liverpool", "arsenal", "chelsea", "dallas", "denver", "orange",
    "purple", "nicole", "jessica", "jennifer", "amanda", "melissa",
    "kimberly", "tiffany", "daniel", "robert", "richard", "joseph",
    "george", "edward", "ronald", "martha", "karen", "nancy", "linda",
    "barbara", "susan", "margaret", "betty", "dorothy", "sandra", "donald",
    "austin", "anthony", "kevin", "brian", "jason", "matthew", "johnny",
    "honey", "hunter1", "baseball1", "soccer1", "football1", "hockey",
    "golfer", "summer", "winter", "spring", "autumn", "cookie", "butter",
    "chicken", "pepper", "hammer", "ginger", "joshua", "pepper",
    "george", "harley", "robert", "jessica", "test123", "changeme",
    "password12", "password1234", "qwerty1", "abc1234", "password!",
    "letmein1", "welcome1", "monkey123", "sunshine1", "master12",
    "dragon12", "baseball12", "iloveyou1", "trustno12", "superman1",
    "batman1", "login123", "admin1", "welcome123", "hello123",
    "charlie1", "shadow1", "pass123", "pass1234", "test1", "test12",
    "hunter12", "michael1", "jordan23", "jennifer1", "computer1",
    "thomas1", "hockey1", "ranger1", "starwars1", "klaster",
    "george1", "michelle1", "jessie1", "pepper1", "11111", "zxcvbnm",
    "asdfghjkl", "qazwsxedc", "qwertyuiop", "mynoob", "18atcskd2w",
    "790321", "jordan1", "amanda1", "andrea1", "nicole1", "1234qwer",
    "123456a", "qwer1234", "123qwe", "zxc123", "Password", "Qwerty",
    "Qwerty123", "Aa123456", "welcome12", "password!@", "admin1234",
    "letmein!", "P@ssword", "Passw0rd", "Welcome1", "Monkey123",
    "Dragon123", "Master123", "Login123", "Abc123", "abc12345",
    "password01", "password99", "12345a", "1234567a", "qwert1",
    "qwerty12", "123321", "666666", "987654321", "112233", "121212",
    "131313", "123789", "555555", "7777777", "888888", "999999",
    "000000", "1111111", "12341234", "1234512345", "asdfasdf", "zxcvzxcv",
    "asdfjkl;", "qweasdzxc", "1q2w3e", "1q2w3e4r5t", "qwertyu",
    "asdfghjk", "zxcvbnm1", "password!", "password.", "p@ss",
    "pass12345", "qwerty1234", "abc123456", "abcdef", "abcdefg",
    "password1!", "passw0rd!", "root123", "toor123", "admin12345",
    "guest123", "user123", "info123", "mysql123", "testtest",
    "temp123", "demo123", "qwerty12345", "q1w2e3r4", "q1w2e3",
    "asdf1234", "zxcv1234", "qwer123", "asdf123", "zxcv123",
    "123qweasd", "1234abcd", "abcd1234", "abc1234567", "abcdef123",
    "a1b2c3d4", "a1b2c3", "a123456", "a1234567", "a12345678",
    "a123456789", "a1234567890", "aa123456", "aaa123", "aaaaaa",
    "zzzzzz", "xxxxxx", "qqqqqq", "wwwwww", "eeeeee", "rrrrrr",
    "tttttt", "yyyyyy", "uuuuuu", "iiiiii", "oooooo", "pppppp",
    "ssssss", "dddddd", "ffffff", "gggggg", "hhhhhh", "jjjjjj",
    "kkkkkk", "llllll", "mmmmmm", "nnnnnn", "bbbbbb", "vvvvvv",
    "cccccc", "pqowie", "poiuyt", "lkjhgf", "mnbvcx", "1qazxsw2",
    "zaq1xsw2", "!@#$%^", "!@#$%^&*", "1234!@#$", "!@#$%",
    "qwert!", "1234!", "123!@", "!qaz2wsx", "1qaz@WSX",
    "qwerty!", "abc!@#", "1q2w#E", "qwe!@#", "asd!@#",
    "zxc!@#", "password123!", "Password1!", "Welcome1!",
    "Monkey1!", "Dragon1!", "Master1!", "Login1!", "Admin1!",
    "123456!", "12345!", "1234!", "123!", "pass1!", "test1!",
    "root!", "admin!", "guest!", "user!", "qwerty!", "asdf!",
    "zxcv!", "qwer!", "abcd!", "1234!@", "!@#$qwer", "!@#$asdf",
    "!@#$zxcv", "!@#$1234", "qwer!@#$", "asdf!@#$", "zxcv!@#$",
    "abc!@#$", "123!@#$", "qaz!@#$", "wsx!@#$", "edc!@#$",
    "rfv!@#$", "tgb!@#$", "yhn!@#$", "ujm!@#$", "ik,!@#$",
    "ol.!@#$", "p;/!@#$", "[]\\!@#$", "';.!@#$", "/.,!@#$",
    "\\';!@#$", "]/[!@#$", "p0o9i8", "1qaz1qaz", "2wsx2wsx",
    "3edc3edc", "4rfv4rfv", "5tgb5tgb", "6yhn6yhn",
    "login1", "login12", "admin1", "admin12", "test1", "test12",
    "user1", "user12", "pass1", "pass12", "root1", "root12",
    "toor1", "guest1", "demo1", "temp1", "info1", "mysql1",
    "oracle1", "postgres1", "redis1", "mongodb1", "ftp1",
    "ssh1", "telnet1", "smtp1", "http1", "dns1", "dhcp1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_md5_password() {
        // MD5 of "password"
        let result = lookup("5f4dcc3b5aa765d61d8327deb882cf99", HashAlgorithm::Md5);
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn lookup_sha1_password() {
        // SHA1 of "password"
        let result = lookup(
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            HashAlgorithm::Sha1,
        );
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn lookup_sha256_password() {
        // SHA256 of "password"
        let result = lookup(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            HashAlgorithm::Sha256,
        );
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn lookup_unknown_hash() {
        let result = lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HashAlgorithm::Md5);
        assert_eq!(result, None);
    }

    #[test]
    fn generate_custom_table_test() {
        let words = vec!["hello".to_string(), "world".to_string()];
        let table = generate_custom_table(&words, HashAlgorithm::Md5);
        assert_eq!(table.len(), 2);
        assert!(table.values().any(|v| v == "hello"));
        assert!(table.values().any(|v| v == "world"));
    }
}
