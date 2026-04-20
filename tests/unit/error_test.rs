// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::crypto::CryptoError;
use secretenv::Error;

#[test]
fn test_user_message_schema_returns_fixed_string() {
    let error = Error::Schema {
        message: r#"{"key":"value"} is not valid under any of the schemas"#.to_string(),
        source: None,
    };
    assert_eq!(error.user_message(), "Schema validation failed");
}

#[test]
fn test_user_message_crypto_returns_message_field() {
    let error = Error::crypto("Cannot find public key in workspace");
    assert_eq!(error.user_message(), "Cannot find public key in workspace");
}

#[test]
fn test_user_message_crypto_with_source_returns_context_only() {
    let error = Error::crypto_with_source(
        "PublicKey self-signature verification failed",
        std::io::Error::other("inner error"),
    );
    assert_eq!(
        error.user_message(),
        "PublicKey self-signature verification failed"
    );
}

#[test]
fn test_user_message_not_found() {
    let error = Error::not_found("member file missing");
    assert_eq!(error.user_message(), "member file missing");
}

#[test]
fn test_user_message_invalid_argument() {
    let error = Error::invalid_argument("Member handle mismatch");
    assert_eq!(error.user_message(), "Member handle mismatch");
}

#[test]
fn test_from_crypto_error_preserves_source() {
    let crypto_err = CryptoError::operation_failed_with_source(
        "decryption failed",
        std::io::Error::other("inner"),
    );
    let error = Error::from(crypto_err);
    assert_eq!(error.user_message(), "decryption failed");
    match &error {
        Error::Crypto { source, .. } => assert!(source.is_some()),
        _ => panic!("expected Crypto variant"),
    }
}

#[test]
fn test_from_crypto_error_uses_message_field() {
    let crypto_err = CryptoError::operation_failed("XChaCha20-Poly1305 decryption failed");
    let error = Error::from(crypto_err);
    assert_eq!(error.user_message(), "XChaCha20-Poly1305 decryption failed");
}
