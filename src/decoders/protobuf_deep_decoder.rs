//! Deep Protobuf decoder with field recovery.
//!
//! Protobuf (Protocol Buffers) is a binary serialization format that uses
//! tag-value pairs with wire types. This decoder goes beyond simple detection:
//! it attempts to parse the wire format and recover field numbers, wire types,
//! and human-readable values without requiring a .proto schema.
//!
//! Supported wire types:
//! - 0: Varint (int32, int64, uint32, uint64, sint32, sint64, bool, enum)
//! - 1: 64-bit (fixed64, sfixed64, double)
//! - 2: Length-delimited (string, bytes, embedded messages, packed repeated)
//! - 5: 32-bit (fixed32, sfixed32, float)

use crate::checkers::CheckerTypes;
use crate::decoders::interface::check_string_success;

use super::crack_results::CrackResult;
use super::interface::Crack;
use super::interface::Decoder;

use log::{debug, trace};

/// The Protobuf deep decoder.
pub struct ProtobufDeepDecoder;

/// Protobuf wire types.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum WireType {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
}

impl WireType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Varint),
            1 => Some(Self::Fixed64),
            2 => Some(Self::LengthDelimited),
            5 => Some(Self::Fixed32),
            _ => None,
        }
    }
}

/// A parsed protobuf field.
#[derive(Debug)]
struct ProtobufField {
    field_number: u32,
    wire_type: WireType,
    value: FieldValue,
}

/// The value of a protobuf field.
#[derive(Debug)]
#[allow(dead_code)]
enum FieldValue {
    Varint(u64),
    Fixed64(u64),
    LengthDelimited(Vec<u8>),
    Fixed32(u32),
    Float(f32),
    Double(f64),
}

impl Crack for Decoder<ProtobufDeepDecoder> {
    fn new() -> Decoder<ProtobufDeepDecoder> {
        Decoder {
            name: "protobuf-deep",
            description: "Deep Protobuf decoder that parses the wire format to recover field numbers, wire types, and values without requiring a .proto schema. Attempts to decode embedded messages and display numeric values in multiple formats.",
            link: "https://protobuf.dev/programming-guides/encoding/",
            tags: vec!["protobuf", "binary", "serialization", "wire-format", "decoder"],
            popularity: 0.6,
            phantom: std::marker::PhantomData,
        }
    }

    fn crack(&self, text: &str, checker: &CheckerTypes) -> CrackResult {
        trace!("Trying ProtobufDeep with text {:?}", text);
        let mut results = CrackResult::new(self, text.to_string());

        // Try hex decode first
        let bytes = if let Some(b) = super::xor_single_byte_decoder::hex_decode(text) {
            b
        } else if text.bytes().all(|b| b.is_ascii()) {
            text.as_bytes().to_vec()
        } else {
            debug!("ProtobufDeep input is not hex or ASCII");
            return results;
        };

        if bytes.len() < 2 {
            debug!("Input too short for protobuf");
            return results;
        }

        let fields = match parse_protobuf(&bytes) {
            Some(f) if !f.is_empty() => f,
            _ => {
                debug!("Failed to parse protobuf structure");
                return results;
            }
        };

        let rendered = render_protobuf(&fields);

        if !check_string_success(&rendered, text) {
            debug!("check_string_success failed for protobuf-deep");
            return results;
        }

        let checker_result = checker.check(&rendered);
        results.unencrypted_text = Some(vec![rendered]);
        results.update_checker(&checker_result);
        results.key = Some(format!("{} fields parsed", fields.len()));
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

/// Parse protobuf wire format into fields.
fn parse_protobuf(bytes: &[u8]) -> Option<Vec<ProtobufField>> {
    let mut fields = Vec::new();
    let mut pos = 0;

    while pos < bytes.len() {
        // Read tag: (field_number << 3) | wire_type
        let (tag, new_pos) = read_varint(bytes, pos)?;
        pos = new_pos;

        let wire_type_num = tag & 0x07;
        let field_number = tag >> 3;

        if field_number == 0 || field_number > 10000 {
            debug!("Invalid field number: {}", field_number);
            break;
        }

        let wire_type = WireType::from_u32(wire_type_num.try_into().ok()?)?;

        let (value, new_pos) = read_field_value(bytes, pos, &wire_type)?;
        pos = new_pos;

        fields.push(ProtobufField {
            field_number: field_number.try_into().ok()?,
            wire_type,
            value,
        });
    }

    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

/// Read a varint from the byte slice, returning (value, new_position).
fn read_varint(bytes: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;

    loop {
        if pos >= bytes.len() {
            return None;
        }
        let byte = bytes[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return None;
        }
    }

    Some((result, pos))
}

/// Read a field value based on wire type.
fn read_field_value(
    bytes: &[u8],
    pos: usize,
    wire_type: &WireType,
) -> Option<(FieldValue, usize)> {
    match wire_type {
        WireType::Varint => {
            let (value, new_pos) = read_varint(bytes, pos)?;
            Some((FieldValue::Varint(value), new_pos))
        }
        WireType::Fixed64 => {
            if pos + 8 > bytes.len() {
                return None;
            }
            let mut val: u64 = 0;
            for i in 0..8 {
                val |= (bytes[pos + i] as u64) << (i * 8);
            }
            // Store as Double (more commonly used for 64-bit wire type)
            Some((FieldValue::Double(f64::from_bits(val)), pos + 8))
        }
        WireType::LengthDelimited => {
            let (length, new_pos) = read_varint(bytes, pos)?;
            let length = length as usize;
            if new_pos + length > bytes.len() {
                return None;
            }
            let data = bytes[new_pos..new_pos + length].to_vec();
            Some((FieldValue::LengthDelimited(data), new_pos + length))
        }
        WireType::Fixed32 => {
            if pos + 4 > bytes.len() {
                return None;
            }
            let mut val: u32 = 0;
            for i in 0..4 {
                val |= (bytes[pos + i] as u32) << (i * 8);
            }
            // Store as Float (more commonly used for 32-bit wire type)
            Some((FieldValue::Float(f32::from_bits(val)), pos + 4))
        }
    }
}

/// Render parsed protobuf fields to a human-readable string.
fn render_protobuf(fields: &[ProtobufField]) -> String {
    let mut output = String::new();
    output.push_str("Protobuf decoded:\n");

    for field in fields {
        let wire_type_name = match field.wire_type {
            WireType::Varint => "varint",
            WireType::Fixed64 => "64-bit",
            WireType::LengthDelimited => "length-delimited",
            WireType::Fixed32 => "32-bit",
        };

        output.push_str(&format!(
            "  field {} ({}): ",
            field.field_number, wire_type_name
        ));

        match &field.value {
            FieldValue::Varint(v) => {
                output.push_str(&format!("{} (0x{:x})", v, v));
                // Try to interpret as sint32 (zigzag encoding)
                let sint = (*v as i64 >> 1) ^ -((*v as i64) & 1);
                if sint != *v as i64 && sint.abs() < 1_000_000 {
                    output.push_str(&format!(" [sint: {}]", sint));
                }
            }
            FieldValue::Fixed64(v) => {
                output.push_str(&format!("0x{:016x}", v));
            }
            FieldValue::Fixed32(v) => {
                output.push_str(&format!("0x{:08x}", v));
            }
            FieldValue::LengthDelimited(data) => {
                // Try UTF-8 string
                if let Ok(s) = String::from_utf8(data.clone()) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                        output.push_str(&format!("\"{}\"", s));
                    } else {
                        output.push_str(&format!("({} bytes): {}", data.len(), s));
                    }
                } else {
                    // Try parsing as embedded message
                    if let Some(nested) = parse_protobuf(data) {
                        output.push_str(&format!("embedded message ({} fields):\n", nested.len()));
                        for nf in &nested {
                            output.push_str(&format!(
                                "    field {}: {:?}\n",
                                nf.field_number, nf.value
                            ));
                        }
                    } else {
                        output.push_str(&format!(
                            "<{} bytes: {}>",
                            data.len(),
                            hex_preview(data, 32)
                        ));
                    }
                }
            }
            FieldValue::Float(f) => {
                output.push_str(&format!("{:.6}", f));
            }
            FieldValue::Double(d) => {
                output.push_str(&format!("{:.10}", d));
            }
        }
        output.push('\n');
    }

    output
}

/// Create a hex preview of binary data.
fn hex_preview(data: &[u8], max_len: usize) -> String {
    let preview = if data.len() > max_len {
        &data[..max_len]
    } else {
        data
    };
    preview
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_metadata() {
        let decoder = Decoder::<ProtobufDeepDecoder>::new();
        assert_eq!(decoder.name, "protobuf-deep");
        assert!(decoder.tags.contains(&"protobuf"));
    }

    #[test]
    fn parse_simple_varint() {
        // field 1, wire type 0 (varint), value 150
        // Tag: (1 << 3) | 0 = 0x08
        // Varint 150: 0x96 0x01
        let bytes = vec![0x08, 0x96, 0x01];
        let fields = parse_protobuf(&bytes).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_number, 1);
        match &fields[0].value {
            FieldValue::Varint(v) => assert_eq!(*v, 150),
            _ => panic!("Expected varint, got {:?}", fields[0].value),
        }
    }

    #[test]
    fn parse_string_field() {
        // field 2, wire type 2 (length-delimited), "hello"
        // Tag: (2 << 3) | 2 = 0x12
        // Length: 5
        // Data: "hello"
        let bytes = vec![0x12, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let fields = parse_protobuf(&bytes).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_number, 2);
        match &fields[0].value {
            FieldValue::LengthDelimited(data) => {
                assert_eq!(String::from_utf8(data.clone()).unwrap(), "hello");
            }
            _ => panic!("Expected length-delimited"),
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_protobuf(&[]).is_none());
    }

    #[test]
    fn rejects_invalid_wire_type() {
        // Wire type 3 is reserved
        let bytes = vec![0x1b]; // (1 << 3) | 3 = 0x1b
        assert!(parse_protobuf(&bytes).is_none());
    }
}
