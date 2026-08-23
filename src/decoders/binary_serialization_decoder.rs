//! Detect and normalize compact binary serialization formats.

use base64::{engine::general_purpose, Engine as _};
use log::{debug, trace};
use serde_json::Value;
use std::convert::TryFrom;

use crate::checkers::CheckerTypes;
use crate::decoders::bencode_decoder::BencodeDecoder;
use crate::decoders::interface::{check_string_success, Crack, Decoder};

use super::crack_results::CrackResult;

/// Detects Bencode, MessagePack, CBOR, and Protobuf-like payloads.
///
/// ```
/// use ciphey::checkers::{athena::Athena, checker_type::{Check, Checker}, CheckerTypes};
/// use ciphey::decoders::binary_serialization_decoder::BinarySerializationDecoder;
/// use ciphey::decoders::interface::{Crack, Decoder};
///
/// let decoder = Decoder::<BinarySerializationDecoder>::new();
/// let checker = CheckerTypes::CheckAthena(Checker::<Athena>::new());
/// let result = decoder.crack("d3:msg11:hello worlde", &checker);
/// assert!(result.unencrypted_text.is_some());
/// ```
pub struct BinarySerializationDecoder;

impl Crack for Decoder<BinarySerializationDecoder> {
    fn new() -> Decoder<BinarySerializationDecoder> {
        Decoder {
            name: "binary-serialization",
            description: "Detects compact binary serialization formats such as Bencode, MessagePack, CBOR, and Protobuf. MessagePack and CBOR are transcoded to JSON when possible, while Protobuf is reported as a wire-format hint unless a schema is available.",
            link: "https://en.wikipedia.org/wiki/Serialization",
            tags: vec!["serialization", "binary", "msgpack", "cbor", "protobuf", "bencode", "decoder"],
            popularity: 0.65,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying BinarySerializationDecoder with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        if let Some(result) = try_bencode(text, checker) {
            return result;
        }

        for candidate in candidate_byte_payloads(text) {
            if let Some(decoded) = decode_cbor_candidate(&candidate) {
                return finalize_json_candidate(self, text, checker, "CBOR", decoded);
            }

            if let Some(decoded) = decode_msgpack_candidate(&candidate) {
                return finalize_json_candidate(self, text, checker, "MessagePack", decoded);
            }

            if let Some(summary) = decode_protobuf_candidate(&candidate) {
                let checker_result = checker.check(&summary);
                if checker_result.is_identified {
                    results.unencrypted_text = Some(vec![summary]);
                    results.update_checker(&checker_result);
                } else {
                    results.unencrypted_text = Some(vec![summary]);
                    results.description =
                        "Detected Protobuf wire format. A .proto schema or descriptor set is needed to recover field names.";
                }
                results.success = true;
                return results;
            }
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

fn try_bencode(text: &str, checker: &CheckerTypes) -> Option<CrackResult> {
    let decoder = Decoder::<BencodeDecoder>::new();
    let mut result = decoder.crack(text, checker);
    if result.unencrypted_text.is_some() {
        result.success = true;
        Some(result)
    } else {
        None
    }
}

fn finalize_json_candidate(
    decoder: &Decoder<BinarySerializationDecoder>,
    original_text: &str,
    checker: &CheckerTypes,
    format_name: &str,
    decoded: Value,
) -> CrackResult {
    let mut result = CrackResult::new(decoder, original_text.to_string());
    let rendered = match serde_json::to_string(&decoded) {
        Ok(json) => json,
        Err(_) => return result,
    };

    if !check_string_success(&rendered, original_text) {
        debug!("{} candidate did not change the input", format_name);
        return result;
    }

    let checker_result = checker.check(&rendered);
    if checker_result.is_identified {
        result.unencrypted_text = Some(vec![rendered]);
        result.update_checker(&checker_result);
        result.description = match format_name {
            "CBOR" => "Detected CBOR payload and transcode it into JSON when possible.",
            "MessagePack" => {
                "Detected MessagePack payload and transcode it into JSON when possible."
            }
            _ => decoder.description,
        };
        result.success = true;
    } else {
        result.unencrypted_text = Some(vec![rendered]);
        result.description = match format_name {
            "CBOR" => "Detected CBOR payload and transcode it into JSON when possible.",
            "MessagePack" => {
                "Detected MessagePack payload and transcode it into JSON when possible."
            }
            _ => decoder.description,
        };
        result.success = true;
    }
    result
}

fn candidate_byte_payloads(text: &str) -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();

    if let Some(bytes) = decode_hex(text) {
        candidates.push(bytes);
    }

    if let Ok(bytes) = general_purpose::STANDARD.decode(text.as_bytes()) {
        candidates.push(bytes);
    }

    if let Ok(bytes) = general_purpose::URL_SAFE.decode(text.as_bytes()) {
        candidates.push(bytes);
    }

    if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(text.as_bytes()) {
        candidates.push(bytes);
    }

    if !is_mostly_printable(text.as_bytes()) {
        candidates.push(text.as_bytes().to_vec());
    }

    candidates
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.len() < 2
        || trimmed.len() % 2 != 0
        || !trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return None;
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    for pair in trimmed.as_bytes().chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_cbor_candidate(bytes: &[u8]) -> Option<Value> {
    serde_cbor::from_slice::<Value>(bytes).ok()
}

fn decode_msgpack_candidate(bytes: &[u8]) -> Option<Value> {
    rmp_serde::from_slice::<Value>(bytes).ok()
}

fn decode_protobuf_candidate(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }

    let mut idx = 0usize;
    let mut field_count = 0usize;
    let mut length_delimited = 0usize;

    while idx < bytes.len() {
        let (key, next) = read_varint(bytes, idx)?;
        idx = next;

        let field_number = key >> 3;
        let wire_type = (key & 0x7) as u8;
        if field_number == 0 {
            return None;
        }

        match wire_type {
            0 => {
                let (_, next) = read_varint(bytes, idx)?;
                idx = next;
            }
            1 => {
                idx = idx.checked_add(8)?;
            }
            2 => {
                let (len, next) = read_varint(bytes, idx)?;
                idx = next;
                let len = usize::try_from(len).ok()?;
                idx = idx.checked_add(len)?;
                length_delimited += 1;
            }
            5 => {
                idx = idx.checked_add(4)?;
            }
            _ => return None,
        }

        field_count += 1;
    }

    if field_count == 0 || is_mostly_printable(bytes) {
        return None;
    }

    Some(format!(
        "Likely Protobuf wire format with {field_count} field(s). A .proto schema or descriptor set is needed to recover field names. Length-delimited fields: {length_delimited}."
    ))
}

fn read_varint(bytes: &[u8], mut idx: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    loop {
        let byte = *bytes.get(idx)?;
        value |= u64::from(byte & 0x7f) << shift;
        idx += 1;
        if byte & 0x80 == 0 {
            return Some((value, idx));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn is_mostly_printable(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    printable * 2 >= bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::{
        athena::Athena,
        checker_type::{Check, Checker},
        CheckerTypes,
    };
    use crate::decoders::interface::Crack;
    use crate::decoders::interface::Decoder;
    use base64::engine::general_purpose;

    fn get_athena_checker() -> CheckerTypes {
        CheckerTypes::CheckAthena(Checker::<Athena>::new())
    }

    #[test]
    fn recognizes_bencode() {
        let decoder = Decoder::<BinarySerializationDecoder>::new();
        let result = decoder
            .crack("d3:msg11:hello worlde", &get_athena_checker())
            .unencrypted_text
            .expect("expected bencode result");
        assert!(result[0].contains("hello world"));
    }

    #[test]
    fn recognizes_messagepack() {
        let payload = serde_json::json!({"name": "alice", "age": 3});
        let bytes = rmp_serde::to_vec(&payload).expect("msgpack encode");
        let input = general_purpose::STANDARD.encode(bytes);

        let decoder = Decoder::<BinarySerializationDecoder>::new();
        let result = decoder
            .crack(&input, &get_athena_checker())
            .unencrypted_text
            .expect("expected msgpack result");
        assert!(result[0].contains("alice"));
        assert!(result[0].contains("age"));
    }

    #[test]
    fn recognizes_cbor() {
        let payload = serde_json::json!({"lang": "rust", "level": 10});
        let bytes = serde_cbor::to_vec(&payload).expect("cbor encode");
        let input = general_purpose::STANDARD.encode(bytes);

        let decoder = Decoder::<BinarySerializationDecoder>::new();
        let result = decoder
            .crack(&input, &get_athena_checker())
            .unencrypted_text
            .expect("expected cbor result");
        assert!(result[0].contains("rust"));
        assert!(result[0].contains("level"));
    }

    #[test]
    fn recognizes_protobuf() {
        let bytes = vec![0x08, 0x96, 0x01, 0x12, 0x03, b'a', b'b', b'c'];
        let input = general_purpose::STANDARD.encode(bytes);

        let decoder = Decoder::<BinarySerializationDecoder>::new();
        let result = decoder.crack(&input, &get_athena_checker());
        assert!(result.success);
        assert!(result.unencrypted_text.is_some());
    }

    #[test]
    fn rejects_plain_text() {
        let decoder = Decoder::<BinarySerializationDecoder>::new();
        let result = decoder.crack("ordinary text", &get_athena_checker());
        assert!(!result.success);
    }
}
