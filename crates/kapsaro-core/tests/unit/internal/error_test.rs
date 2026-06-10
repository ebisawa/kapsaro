// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::CryptoError;
use kapsaro_core::{Error, ErrorKind};

#[test]
fn test_user_message_schema_returns_message_field() {
    let error = Error::build_schema_error(
        "Invalid kapsaro document\nReason: signature.signer_pub is missing".to_string(),
    );
    assert_eq!(
        error.format_user_message(),
        "Invalid kapsaro document\nReason: signature.signer_pub is missing"
    );
}

#[test]
fn test_user_message_crypto_returns_message_field() {
    let error = Error::build_crypto_error("Cannot find public key in workspace");
    assert_eq!(
        error.format_user_message(),
        "Cannot find public key in workspace"
    );
}

#[test]
fn test_user_message_crypto_with_source_returns_context_only() {
    let error = Error::build_crypto_error_with_source(
        "PublicKey self-signature verification failed",
        std::io::Error::other("inner error"),
    );
    assert_eq!(
        error.format_user_message(),
        "PublicKey self-signature verification failed"
    );
}

#[test]
fn test_user_message_not_found() {
    let error = Error::build_not_found_error("member file missing");
    assert_eq!(error.format_user_message(), "member file missing");
}

#[test]
fn test_user_message_invalid_argument() {
    let error = Error::build_invalid_argument_error("Member handle mismatch");
    assert_eq!(error.format_user_message(), "Member handle mismatch");
}

#[test]
fn test_from_crypto_error_preserves_source() {
    let crypto_err = CryptoError::build_operation_failed_error_with_source(
        "decryption failed",
        std::io::Error::other("inner"),
    );
    let error = Error::from(crypto_err);
    assert_eq!(error.format_user_message(), "decryption failed");
    assert_eq!(error.kind(), ErrorKind::Crypto);
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn test_from_crypto_error_uses_message_field() {
    let crypto_err =
        CryptoError::build_operation_failed_error("XChaCha20-Poly1305 decryption failed");
    let error = Error::from(crypto_err);
    assert_eq!(
        error.format_user_message(),
        "XChaCha20-Poly1305 decryption failed"
    );
}
