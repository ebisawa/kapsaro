// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/codec base64 modules.

use secretenv::support::codec::base64_public::{
    decode_base64_standard, decode_base64url_nopad, encode_base64_standard,
    encode_base64_standard_nopad, encode_base64url_nopad,
};
use secretenv::support::codec::base64_secret::{
    decode_base64url_nopad_secret_32, decode_base64url_nopad_secret_64,
    encode_base64url_nopad_secret_32, encode_base64url_nopad_secret_64,
};
use secretenv::support::secret::SecretArray;

#[test]
fn test_encode_base64url_nopad_roundtrip() {
    let data = b"hello world";
    let encoded = encode_base64url_nopad(data);
    let decoded = decode_base64url_nopad(&encoded, "test").unwrap();

    assert_eq!(encoded, "aGVsbG8gd29ybGQ");
    assert_eq!(decoded, data);
}

#[test]
fn test_encode_base64_standard_roundtrip() {
    let data = b"hello world";
    let encoded = encode_base64_standard(data);
    let decoded = decode_base64_standard(&encoded, "test").unwrap();

    assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
    assert_eq!(decoded, data);
}

#[test]
fn test_encode_base64_standard_nopad_matches_known_value() {
    let encoded = encode_base64_standard_nopad(b"hello world");

    assert_eq!(encoded, "aGVsbG8gd29ybGQ");
}

#[test]
fn test_decode_base64url_nopad_rejects_padding() {
    let error = decode_base64url_nopad("aGVsbG8=", "test").unwrap_err();

    assert!(error.to_string().contains("padding"));
}

#[test]
fn test_decode_base64url_nopad_rejects_non_zero_tail_bits_len_two() {
    let error = decode_base64url_nopad("AB", "test").unwrap_err();

    assert!(error.to_string().contains("tail bits"));
}

#[test]
fn test_decode_base64url_nopad_rejects_non_zero_tail_bits_len_three() {
    let error = decode_base64url_nopad("AAB", "test").unwrap_err();

    assert!(error.to_string().contains("tail bits"));
}

#[test]
fn test_decode_base64url_nopad_accepts_canonical_tail_bits() {
    assert_eq!(decode_base64url_nopad("AA", "test").unwrap(), vec![0]);
    assert_eq!(decode_base64url_nopad("AAA", "test").unwrap(), vec![0, 0]);
}

#[test]
fn test_decode_base64url_nopad_rejects_non_canonical_fixed_length_values() {
    let mut signature = encode_base64url_nopad(&[0u8; 64]);
    signature.replace_range(85..86, "B");
    let signature_error = decode_base64url_nopad(&signature, "signature").unwrap_err();

    let mut salt = encode_base64url_nopad(&[0u8; 32]);
    salt.replace_range(42..43, "B");
    let salt_error = decode_base64url_nopad(&salt, "salt").unwrap_err();

    assert!(signature_error.to_string().contains("tail bits"));
    assert!(salt_error.to_string().contains("tail bits"));
}

#[test]
fn test_decode_base64_standard_rejects_invalid_character() {
    let error = decode_base64_standard("aGVsbG8*", "test").unwrap_err();

    assert!(error.to_string().contains("invalid"));
}

#[test]
fn test_decode_base64_standard_rejects_non_zero_tail_bits() {
    let error = decode_base64_standard("AB==", "test").unwrap_err();

    assert!(error.to_string().contains("tail bits"));
    assert_eq!(decode_base64_standard("AA==", "test").unwrap(), vec![0]);
}

#[test]
fn test_encode_base64url_nopad_secret_32_matches_public_encoding() {
    let secret = SecretArray::new((0u8..32).collect::<Vec<_>>().try_into().unwrap());
    let encoded = encode_base64url_nopad_secret_32(&secret);

    assert_eq!(
        encoded.as_str(),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    );
}

#[test]
fn test_encode_base64url_nopad_secret_64_matches_public_encoding() {
    let secret = SecretArray::new((0u8..64).collect::<Vec<_>>().try_into().unwrap());
    let encoded = encode_base64url_nopad_secret_64(&secret);

    assert_eq!(
        encoded.as_str(),
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"
    );
}

#[test]
fn test_decode_base64url_nopad_secret_32_roundtrip() {
    let decoded =
        decode_base64url_nopad_secret_32("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "secret")
            .unwrap();

    assert_eq!(
        decoded.expose_secret(),
        (0u8..32).collect::<Vec<_>>().as_slice()
    );
}

#[test]
fn test_decode_base64url_nopad_secret_64_roundtrip() {
    let decoded = decode_base64url_nopad_secret_64(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw",
        "secret",
    )
    .unwrap();

    assert_eq!(
        decoded.expose_secret(),
        (0u8..64).collect::<Vec<_>>().as_slice()
    );
}

#[test]
fn test_decode_base64url_nopad_secret_32_wrong_length_error() {
    let error = decode_base64url_nopad_secret_32("AAECAwQFBgc", "secret").unwrap_err();

    assert!(error.to_string().contains("length"));
}
