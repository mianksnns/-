//! This module contains all the code for decoders
//! Think of a decoder as a decryption method that doesn't require a key
//! The `interface.rs` defines what each decoder looks like.
//! Once you have made a decoder you need to add it to the filtration system's
//! mod.rs file
//! you will also need to make it a public module in this file.

/// The a1z26_decoder module decodes A1Z26
pub mod a1z26_decoder;
/// The atbash_decoder module decodes atbash
pub mod atbash_decoder;
/// The base32_decoder module decodes base32
pub mod base32_decoder;
/// The base58_bitcoin_decoder module decodes base58 bitcoin
pub mod base58_bitcoin_decoder;
/// The base58_monero_decoder module decodes base58 monero
pub mod base58_monero_decoder;
/// The binary_decoder module decodes binary
pub mod binary_decoder;
/// The hexadecimal_decoder module decodes hexadecimal
pub mod hexadecimal_decoder;

/// The base58_ripple_decoder module decodes base58 ripple
pub mod base58_ripple_decoder;

/// The base58_flickr decoder module decodes base58 flickr
pub mod base58_flickr_decoder;

/// The base64_decoder module decodes base64
/// It is public as we use it in some tests.
pub mod base64_decoder;
/// The base65536 module decodes base65536
pub mod base65536_decoder;
/// The base91_decoder module decodes base91
pub mod base91_decoder;
/// The citrix_ctx1_decoder module decodes citrix ctx1
pub mod citrix_ctx1_decoder;
/// The crack_results module defines the CrackResult
/// Each and every decoder return same CrackResult
pub mod crack_results;
/// The url_decoder module decodes url
pub mod url_decoder;

/// The interface module defines the interface for decoders
/// Each and every decoder has the same struct & traits
pub mod interface;

/// The reverse_decoder module decodes reverse text
/// Stac -> Cats
/// It is public as we use it in some tests.
pub mod reverse_decoder;

/// The morse_code module decodes morse code
/// It is public as we use it in some tests.
pub mod morse_code;

/// For the caesar cipher decoder
pub mod caesar_decoder;

/// For the railfence cipher decoder
pub mod railfence_decoder;
/// For the rot47 decoder
pub mod rot47_decoder;

/// For the z85 cipher decoder
pub mod z85_decoder;

/// For the braille decoder
pub mod braille_decoder;

/// The substitution_generic_decoder module handles generic substitution ciphers
pub mod substitution_generic_decoder;

/// The hash_crack_decoder module cracks hashes using a local wordlist
pub mod hash_crack_decoder;

/// The substitution_autocrack_decoder module automatically cracks substitution ciphers
pub mod substitution_autocrack_decoder;

/// A brainfuck interpreter
pub mod brainfuck_interpreter;

/// The vigenere_decoder module decodes Vigenère cipher text
pub mod vigenere_decoder;

/// The xor_single_byte_decoder module brute-forces single-byte XOR ciphers
pub mod xor_single_byte_decoder;

/// The xor_repeating_decoder module cracks repeating-key XOR ciphers
pub mod xor_repeating_decoder;

/// The compression_decoder module detects and decompresses compressed data
pub mod compression_decoder;

/// The base62_decoder module decodes base62
pub mod base62_decoder;

/// The base36_decoder module decodes base36
pub mod base36_decoder;

/// The base45_decoder module decodes base45
pub mod base45_decoder;

/// The base85_decoder module decodes base85 (Ascii85)
pub mod base85_decoder;

/// The base32hex_decoder module decodes base32hex
pub mod base32hex_decoder;

/// The bencode_decoder module decodes Bencode data
pub mod bencode_decoder;
/// The binary_serialization_decoder module detects compact binary serialization formats
pub mod binary_serialization_decoder;

/// The bech32_decoder module decodes Bech32 strings
pub mod bech32_decoder;

/// The base64url_decoder module decodes base64url
pub mod base64url_decoder;

/// The html_entities_decoder module decodes HTML/XML entities
pub mod html_entities_decoder;

/// The jwt_decoder module decodes JWT tokens
pub mod jwt_decoder;

/// The unicode_escape_decoder module decodes unicode escape sequences
pub mod unicode_escape_decoder;

/// The punycode_decoder module decodes punycode labels
pub mod punycode_decoder;

/// The uuencode_decoder module decodes uuencode text
pub mod uuencode_decoder;

/// The xxencode_decoder module decodes xxencode text
pub mod xxencode_decoder;

/// The affine_decoder module decodes affine ciphers
pub mod affine_decoder;

/// The beaufort_decoder module decodes beaufort ciphers
pub mod beaufort_decoder;

/// The autokey_decoder module decodes autokey ciphers
pub mod autokey_decoder;

/// The gronsfeld_decoder module decodes gronsfeld ciphers
pub mod gronsfeld_decoder;

/// The porta_decoder module decodes porta ciphers
pub mod porta_decoder;

/// The nihilist_decoder module decodes nihilist ciphers
pub mod nihilist_decoder;

/// The polybius_decoder module decodes Polybius square ciphers
pub mod polybius_decoder;

/// The bifid_decoder module decodes Bifid ciphers
pub mod bifid_decoder;

/// The trifid_decoder module decodes Trifid ciphers
pub mod trifid_decoder;

/// The hill_decoder module decodes Hill ciphers
pub mod hill_decoder;

/// The playfair_decoder module decodes Playfair ciphers
pub mod playfair_decoder;

/// The four_square_decoder module decodes Four-square ciphers
pub mod four_square_decoder;

/// The two_square_decoder module decodes Two-square ciphers
pub mod two_square_decoder;

/// The adfgvx_decoder module decodes ADFGVX ciphers
pub mod adfgvx_decoder;

/// The chaocipher_decoder module decodes Chaocipher messages
pub mod chaocipher_decoder;

/// The enigma_decoder module decodes Enigma machine messages
pub mod enigma_decoder;

/// The straddling_checkerboard_decoder module decodes straddling checkerboard ciphers
pub mod straddling_checkerboard_decoder;

/// The bacon_decoder module decodes Bacon's ciphers
pub mod bacon_decoder;

/// The leet_decoder module decodes leetspeak
pub mod leet_decoder;

/// The nato_decoder module decodes NATO phonetic alphabet messages
pub mod nato_decoder;

/// The pigpen_decoder module decodes Pigpen ciphers
pub mod pigpen_decoder;

/// The tap_code_decoder module decodes Tap code messages
pub mod tap_code_decoder;

use atbash_decoder::AtbashDecoder;
use base32_decoder::Base32Decoder;
use base58_bitcoin_decoder::Base58BitcoinDecoder;
use base58_flickr_decoder::Base58FlickrDecoder;
use base58_monero_decoder::Base58MoneroDecoder;
use base58_ripple_decoder::Base58RippleDecoder;
use binary_decoder::BinaryDecoder;
use hexadecimal_decoder::HexadecimalDecoder;
use interface::{Crack, Decoder};

use a1z26_decoder::A1Z26Decoder;
use base64_decoder::Base64Decoder;
use base65536_decoder::Base65536Decoder;
use base91_decoder::Base91Decoder;
use braille_decoder::BrailleDecoder;
use caesar_decoder::CaesarDecoder;
use citrix_ctx1_decoder::CitrixCTX1Decoder;
use morse_code::MorseCodeDecoder;
use railfence_decoder::RailfenceDecoder;
use reverse_decoder::ReverseDecoder;
use rot47_decoder::ROT47Decoder;
use substitution_generic_decoder::SubstitutionGenericDecoder;
use url_decoder::URLDecoder;
use vigenere_decoder::VigenereDecoder;
use z85_decoder::Z85Decoder;

use base32hex_decoder::Base32HexDecoder;
use base36_decoder::Base36Decoder;
use base45_decoder::Base45Decoder;
use base62_decoder::Base62Decoder;
use base64url_decoder::Base64UrlDecoder;
use base85_decoder::Base85Decoder;
use bech32_decoder::Bech32Decoder;
use bencode_decoder::BencodeDecoder;
use binary_serialization_decoder::BinarySerializationDecoder;
use brainfuck_interpreter::BrainfuckInterpreter;
use compression_decoder::CompressionDecoder;
use hash_crack_decoder::HashCrackDecoder;
use html_entities_decoder::HtmlEntitiesDecoder;
use jwt_decoder::JwtDecoder;
use punycode_decoder::PunycodeDecoder;
use substitution_autocrack_decoder::SubstitutionAutocrackDecoder;
use unicode_escape_decoder::UnicodeEscapeDecoder;
use uuencode_decoder::UuencodeDecoder;
use xor_repeating_decoder::XorRepeatingDecoder;
use xor_single_byte_decoder::XorSingleByteDecoder;
use xxencode_decoder::XxencodeDecoder;

use affine_decoder::AffineDecoder;
use autokey_decoder::AutokeyDecoder;
use beaufort_decoder::BeaufortDecoder;
use gronsfeld_decoder::GronsfeldDecoder;
use nihilist_decoder::NihilistDecoder;
use porta_decoder::PortaDecoder;

use adfgvx_decoder::AdfgvxDecoder;
use bacon_decoder::BaconDecoder;
use bifid_decoder::BifidDecoder;
use chaocipher_decoder::ChaocipherDecoder;
use enigma_decoder::EnigmaDecoder;
use four_square_decoder::FourSquareDecoder;
use hill_decoder::HillDecoder;
use leet_decoder::LeetDecoder;
use nato_decoder::NatoDecoder;
use pigpen_decoder::PigpenDecoder;
use playfair_decoder::PlayfairDecoder;
use polybius_decoder::PolybiusDecoder;
use straddling_checkerboard_decoder::StraddlingCheckerboardDecoder;
use tap_code_decoder::TapCodeDecoder;
use trifid_decoder::TrifidDecoder;
use two_square_decoder::TwoSquareDecoder;

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Enum for annotating Decoder types, specifically for retrieving decoders from
/// DECODER_MAP
pub enum DecoderType {
    /// default decoder
    DefaultDecoder(interface::DefaultDecoder),
    /// a1z26 decoder
    A1z26Decoder(a1z26_decoder::A1Z26Decoder),
    /// atbash decoder
    AtbashDecoder(atbash_decoder::AtbashDecoder),
    /// base32 decoder
    Base32Decoder(base32_decoder::Base32Decoder),
    /// base58 bitcoin decoder
    Base58BitcoinDecoder(base58_bitcoin_decoder::Base58BitcoinDecoder),
    /// base58 monero decoder
    Base58MoneroDecoder(base58_monero_decoder::Base58MoneroDecoder),
    /// binary decoder
    BinaryDecoder(binary_decoder::BinaryDecoder),
    /// hexadecimal decoder
    HexadecimalDecoder(hexadecimal_decoder::HexadecimalDecoder),
    /// base58 ripple decoder
    Base58RippleDecoder(base58_ripple_decoder::Base58RippleDecoder),
    /// base58 flickr decoder
    Base58FlickrDecoder(base58_flickr_decoder::Base58FlickrDecoder),
    /// base64 decoder
    Base64Decoder(base64_decoder::Base64Decoder),
    /// base65536 decoder
    Base65536Decoder(base65536_decoder::Base65536Decoder),
    /// base91 decoder
    Base91Decoder(base91_decoder::Base91Decoder),
    /// citrix ctx1 decoder
    CitrixCtx1Decoder(citrix_ctx1_decoder::CitrixCTX1Decoder),
    /// url decoder
    UrlDecoder(url_decoder::URLDecoder),
    /// reverse decoder
    ReverseDecoder(reverse_decoder::ReverseDecoder),
    /// morse decoder
    MorseCode(morse_code::MorseCodeDecoder),
    /// caesar decoder
    CaesarDecoder(caesar_decoder::CaesarDecoder),
    /// railfence decoder
    RailfenceDecoder(railfence_decoder::RailfenceDecoder),
    /// rot47 decoder
    Rot47Decoder(rot47_decoder::ROT47Decoder),
    /// z85 decoder
    Z85Decoder(z85_decoder::Z85Decoder),
    /// braille decoder
    BrailleDecoder(braille_decoder::BrailleDecoder),
    /// substitution decoder
    SubstitutionGenericDecoder(substitution_generic_decoder::SubstitutionGenericDecoder),
    /// hash crack decoder
    HashCrackDecoder(hash_crack_decoder::HashCrackDecoder),
    /// substitution autocrack decoder
    SubstitutionAutocrackDecoder(substitution_autocrack_decoder::SubstitutionAutocrackDecoder),
    /// brainfuck interpreter
    BrainfuckInterpreter(brainfuck_interpreter::BrainfuckInterpreter),
    /// vigenere decoder
    VigenereDecoder(vigenere_decoder::VigenereDecoder),
    /// xor single byte decoder
    XorSingleByteDecoder(xor_single_byte_decoder::XorSingleByteDecoder),
    /// xor repeating decoder
    XorRepeatingDecoder(xor_repeating_decoder::XorRepeatingDecoder),
    /// compression decoder
    CompressionDecoder(compression_decoder::CompressionDecoder),
    /// base62 decoder
    Base62Decoder(base62_decoder::Base62Decoder),
    /// base36 decoder
    Base36Decoder(base36_decoder::Base36Decoder),
    /// base45 decoder
    Base45Decoder(base45_decoder::Base45Decoder),
    /// base85 decoder
    Base85Decoder(base85_decoder::Base85Decoder),
    /// base32hex decoder
    Base32HexDecoder(base32hex_decoder::Base32HexDecoder),
    /// bencode decoder
    BencodeDecoder(bencode_decoder::BencodeDecoder),
    /// binary serialization decoder
    BinarySerializationDecoder(binary_serialization_decoder::BinarySerializationDecoder),
    /// bech32 decoder
    Bech32Decoder(bech32_decoder::Bech32Decoder),
    /// base64url decoder
    Base64UrlDecoder(base64url_decoder::Base64UrlDecoder),
    /// html entities decoder
    HtmlEntitiesDecoder(html_entities_decoder::HtmlEntitiesDecoder),
    /// jwt decoder
    JwtDecoder(jwt_decoder::JwtDecoder),
    /// unicode escape decoder
    UnicodeEscapeDecoder(unicode_escape_decoder::UnicodeEscapeDecoder),
    /// punycode decoder
    PunycodeDecoder(punycode_decoder::PunycodeDecoder),
    /// uuencode decoder
    UuencodeDecoder(uuencode_decoder::UuencodeDecoder),
    /// xxencode decoder
    XxencodeDecoder(xxencode_decoder::XxencodeDecoder),
    /// affine decoder
    AffineDecoder(affine_decoder::AffineDecoder),
    /// beaufort decoder
    BeaufortDecoder(beaufort_decoder::BeaufortDecoder),
    /// autokey decoder
    AutokeyDecoder(autokey_decoder::AutokeyDecoder),
    /// gronsfeld decoder
    GronsfeldDecoder(gronsfeld_decoder::GronsfeldDecoder),
    /// porta decoder
    PortaDecoder(porta_decoder::PortaDecoder),
    /// nihilist decoder
    NihilistDecoder(nihilist_decoder::NihilistDecoder),
    /// polybius decoder
    PolybiusDecoder(polybius_decoder::PolybiusDecoder),
    /// bifid decoder
    BifidDecoder(bifid_decoder::BifidDecoder),
    /// trifid decoder
    TrifidDecoder(trifid_decoder::TrifidDecoder),
    /// hill decoder
    HillDecoder(hill_decoder::HillDecoder),
    /// playfair decoder
    PlayfairDecoder(playfair_decoder::PlayfairDecoder),
    /// four-square decoder
    FourSquareDecoder(four_square_decoder::FourSquareDecoder),
    /// two-square decoder
    TwoSquareDecoder(two_square_decoder::TwoSquareDecoder),
    /// adfgvx decoder
    AdfgvxDecoder(adfgvx_decoder::AdfgvxDecoder),
    /// chaocipher decoder
    ChaocipherDecoder(chaocipher_decoder::ChaocipherDecoder),
    /// enigma decoder
    EnigmaDecoder(enigma_decoder::EnigmaDecoder),
    /// straddling checkerboard decoder
    StraddlingCheckerboardDecoder(straddling_checkerboard_decoder::StraddlingCheckerboardDecoder),
    /// bacon decoder
    BaconDecoder(bacon_decoder::BaconDecoder),
    /// leet decoder
    LeetDecoder(leet_decoder::LeetDecoder),
    /// nato decoder
    NatoDecoder(nato_decoder::NatoDecoder),
    /// pigpen decoder
    PigpenDecoder(pigpen_decoder::PigpenDecoder),
    /// tap code decoder
    TapCodeDecoder(tap_code_decoder::TapCodeDecoder),
}

/// Wrapper struct to hold Decoders for DECODER_MAP
pub struct DecoderBox {
    /// Wrapper box to hold Decoders for DECODER_MAP
    value: Box<dyn Crack + Sync + Send>,
}

impl DecoderBox {
    /// Constructor for DecoderBox. Takes in a Decoder and stores it as the
    /// internal value
    fn new<T: 'static + Crack + Sync + Send>(value: T) -> Self {
        Self {
            value: Box::new(value),
        }
    }

    /// Getter method for DecoderBox to return the internal Box
    pub fn get<T: 'static>(&self) -> &(dyn Crack + Sync + Send) {
        self.value.as_ref()
    }
}

/// Global hashmap for translating strings to Decoders
pub static DECODER_MAP: Lazy<HashMap<&str, DecoderBox>> = Lazy::new(|| {
    HashMap::from([
        (
            "Default decoder",
            DecoderBox::new(Decoder::<interface::DefaultDecoder>::new()),
        ),
        (
            "Vigenere",
            DecoderBox::new(Decoder::<VigenereDecoder>::new()),
        ),
        ("Binary", DecoderBox::new(Decoder::<BinaryDecoder>::new())),
        (
            "Hexadecimal",
            DecoderBox::new(Decoder::<HexadecimalDecoder>::new()),
        ),
        (
            "Base58 Bitcoin",
            DecoderBox::new(Decoder::<Base58BitcoinDecoder>::new()),
        ),
        (
            "Base58 Monero",
            DecoderBox::new(Decoder::<Base58MoneroDecoder>::new()),
        ),
        (
            "Base58 Ripple",
            DecoderBox::new(Decoder::<Base58RippleDecoder>::new()),
        ),
        (
            "Base58 Flickr",
            DecoderBox::new(Decoder::<Base58FlickrDecoder>::new()),
        ),
        ("Base64", DecoderBox::new(Decoder::<Base64Decoder>::new())),
        ("Base91", DecoderBox::new(Decoder::<Base91Decoder>::new())),
        (
            "Base65536",
            DecoderBox::new(Decoder::<Base65536Decoder>::new()),
        ),
        (
            "Citrix Ctx1",
            DecoderBox::new(Decoder::<CitrixCTX1Decoder>::new()),
        ),
        ("URL", DecoderBox::new(Decoder::<URLDecoder>::new())),
        ("Base32", DecoderBox::new(Decoder::<Base32Decoder>::new())),
        ("Reverse", DecoderBox::new(Decoder::<ReverseDecoder>::new())),
        (
            "Morse Code",
            DecoderBox::new(Decoder::<MorseCodeDecoder>::new()),
        ),
        ("atbash", DecoderBox::new(Decoder::<AtbashDecoder>::new())),
        ("caesar", DecoderBox::new(Decoder::<CaesarDecoder>::new())),
        (
            "railfence",
            DecoderBox::new(Decoder::<RailfenceDecoder>::new()),
        ),
        ("rot47", DecoderBox::new(Decoder::<ROT47Decoder>::new())),
        ("Z85", DecoderBox::new(Decoder::<Z85Decoder>::new())),
        ("a1z26", DecoderBox::new(Decoder::<A1Z26Decoder>::new())),
        ("Braille", DecoderBox::new(Decoder::<BrailleDecoder>::new())),
        (
            "simplesubstitution",
            DecoderBox::new(Decoder::<SubstitutionGenericDecoder>::new()),
        ),
        (
            "HashCrack",
            DecoderBox::new(Decoder::<HashCrackDecoder>::new()),
        ),
        (
            "substitution-autocrack",
            DecoderBox::new(Decoder::<SubstitutionAutocrackDecoder>::new()),
        ),
        (
            "Brainfuck",
            DecoderBox::new(Decoder::<BrainfuckInterpreter>::new()),
        ),
        (
            "xor-single-byte",
            DecoderBox::new(Decoder::<XorSingleByteDecoder>::new()),
        ),
        (
            "xor-repeating",
            DecoderBox::new(Decoder::<XorRepeatingDecoder>::new()),
        ),
        (
            "compression",
            DecoderBox::new(Decoder::<CompressionDecoder>::new()),
        ),
        ("Base36", DecoderBox::new(Decoder::<Base36Decoder>::new())),
        ("Base45", DecoderBox::new(Decoder::<Base45Decoder>::new())),
        ("Base62", DecoderBox::new(Decoder::<Base62Decoder>::new())),
        ("Base85", DecoderBox::new(Decoder::<Base85Decoder>::new())),
        (
            "Base32hex",
            DecoderBox::new(Decoder::<Base32HexDecoder>::new()),
        ),
        ("Bencode", DecoderBox::new(Decoder::<BencodeDecoder>::new())),
        (
            "Binary Serialization",
            DecoderBox::new(Decoder::<BinarySerializationDecoder>::new()),
        ),
        ("Bech32", DecoderBox::new(Decoder::<Bech32Decoder>::new())),
        (
            "Base64url",
            DecoderBox::new(Decoder::<Base64UrlDecoder>::new()),
        ),
        (
            "HTML entities",
            DecoderBox::new(Decoder::<HtmlEntitiesDecoder>::new()),
        ),
        ("JWT", DecoderBox::new(Decoder::<JwtDecoder>::new())),
        (
            "Unicode escape",
            DecoderBox::new(Decoder::<UnicodeEscapeDecoder>::new()),
        ),
        (
            "Punycode",
            DecoderBox::new(Decoder::<PunycodeDecoder>::new()),
        ),
        (
            "UUencode",
            DecoderBox::new(Decoder::<UuencodeDecoder>::new()),
        ),
        (
            "XXencode",
            DecoderBox::new(Decoder::<XxencodeDecoder>::new()),
        ),
        ("Affine", DecoderBox::new(Decoder::<AffineDecoder>::new())),
        (
            "Beaufort",
            DecoderBox::new(Decoder::<BeaufortDecoder>::new()),
        ),
        ("Autokey", DecoderBox::new(Decoder::<AutokeyDecoder>::new())),
        (
            "Gronsfeld",
            DecoderBox::new(Decoder::<GronsfeldDecoder>::new()),
        ),
        ("Porta", DecoderBox::new(Decoder::<PortaDecoder>::new())),
        (
            "Nihilist",
            DecoderBox::new(Decoder::<NihilistDecoder>::new()),
        ),
        (
            "Polybius",
            DecoderBox::new(Decoder::<PolybiusDecoder>::new()),
        ),
        ("Bifid", DecoderBox::new(Decoder::<BifidDecoder>::new())),
        ("Trifid", DecoderBox::new(Decoder::<TrifidDecoder>::new())),
        ("Hill", DecoderBox::new(Decoder::<HillDecoder>::new())),
        (
            "Playfair",
            DecoderBox::new(Decoder::<PlayfairDecoder>::new()),
        ),
        (
            "Four-square",
            DecoderBox::new(Decoder::<FourSquareDecoder>::new()),
        ),
        (
            "Two-square",
            DecoderBox::new(Decoder::<TwoSquareDecoder>::new()),
        ),
        ("ADFGVX", DecoderBox::new(Decoder::<AdfgvxDecoder>::new())),
        (
            "Chaocipher",
            DecoderBox::new(Decoder::<ChaocipherDecoder>::new()),
        ),
        ("Enigma", DecoderBox::new(Decoder::<EnigmaDecoder>::new())),
        (
            "Straddling checkerboard",
            DecoderBox::new(Decoder::<StraddlingCheckerboardDecoder>::new()),
        ),
        (
            "Bacon's cipher",
            DecoderBox::new(Decoder::<BaconDecoder>::new()),
        ),
        ("Leet", DecoderBox::new(Decoder::<LeetDecoder>::new())),
        (
            "NATO phonetic",
            DecoderBox::new(Decoder::<NatoDecoder>::new()),
        ),
        ("Pigpen", DecoderBox::new(Decoder::<PigpenDecoder>::new())),
        (
            "Tap code",
            DecoderBox::new(Decoder::<TapCodeDecoder>::new()),
        ),
    ])
});
