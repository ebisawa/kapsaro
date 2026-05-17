// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Display / From coverage for src/error.rs.
//!
//! Complements error_test.rs (format_user_message coverage) with table-driven
//! Display output checks and From conversion checks.

use secretenv_core::cli_api::test_support::helpers::codec::base64_public::decode_base64_standard;
use secretenv_core::cli_api::test_support::primitives::CryptoError;
use secretenv_core::cli_api::test_support::storage::ssh::SshError;
use secretenv_core::cli_api::test_support::wire::FormatError;
use secretenv_core::{Error, ErrorKind};
use std::error::Error as StdError;

// --------------------------------------------------------------------
// Display output for each Error variant
// --------------------------------------------------------------------

#[test]
fn test_display_schema_variant() {
    let err = Error::build_schema_error(
        "Invalid secretenv document\nReason: signature.signer_pub is missing".to_string(),
    );
    let text = format!("{}", err);
    assert!(text.contains("Invalid secretenv document"));
    assert!(text.contains("signature.signer_pub is missing"));
    assert!(!text.contains("Schema validation error"));
}

#[test]
fn test_display_crypto_variant() {
    let err = Error::build_crypto_error("HPKE decap failed");
    let text = format!("{}", err);
    assert!(text.contains("Cryptographic error:"));
    assert!(text.contains("HPKE decap failed"));
}

#[test]
fn test_display_ssh_variant() {
    let err = Error::build_ssh_error_with_source(
        "agent unavailable",
        std::io::Error::other("ENOENT: /tmp/ssh-agent.sock"),
    );
    let text = format!("{}", err);
    assert!(text.contains("SSH error:"));
    assert!(text.contains("agent unavailable"));
}

#[test]
fn test_display_verify_variant_has_rule_and_message() {
    let err = Error::build_verification_error("E_SIGNATURE_INVALID", "signature check failed");
    let text = format!("{}", err);
    assert!(text.contains("Verification failed"));
    assert!(text.contains("E_SIGNATURE_INVALID"));
    assert!(text.contains("signature check failed"));
}

#[test]
fn test_display_io_variant() {
    let err = Error::build_io_error("read failure");
    let text = format!("{}", err);
    assert!(text.contains("I/O error:"));
    assert!(text.contains("read failure"));
}

#[test]
fn test_display_parse_variant() {
    let err = Error::build_parse_error("unexpected token");
    let text = format!("{}", err);
    assert!(text.contains("Parse error:"));
    assert!(text.contains("unexpected token"));
}

#[test]
fn test_display_config_variant() {
    let err = Error::build_config_error("missing secretenv.toml");
    let text = format!("{}", err);
    assert!(text.contains("Configuration error:"));
    assert!(text.contains("missing secretenv.toml"));
}

#[test]
fn test_display_not_found_variant() {
    let err = Error::build_not_found_error("member alice not registered");
    let text = format!("{}", err);
    assert!(text.contains("Not found:"));
    assert!(text.contains("member alice not registered"));
}

#[test]
fn test_display_invalid_argument_variant() {
    let err = Error::build_invalid_argument_error("--recipient must be non-empty");
    let text = format!("{}", err);
    assert!(text.contains("Invalid argument:"));
    assert!(text.contains("--recipient must be non-empty"));
}

#[test]
fn test_display_invalid_operation_variant() {
    let err = Error::build_invalid_operation_error("cannot sign with public key");
    let text = format!("{}", err);
    assert!(text.contains("Invalid operation:"));
    assert!(text.contains("cannot sign with public key"));
}

// --------------------------------------------------------------------
// From conversions
// --------------------------------------------------------------------

#[test]
fn test_from_io_error_wraps_source() {
    let io_err = std::io::Error::other("disk full");
    let err: Error = io_err.into();
    assert_eq!(err.kind(), ErrorKind::Io);
    assert!(err.format_user_message().contains("disk full"));
    assert!(StdError::source(&err).is_some(), "source must be preserved");
}

#[test]
fn test_from_serde_json_error_wraps_as_parse() {
    let json_err = serde_json::from_str::<serde_json::Value>("{ not valid").unwrap_err();
    let err: Error = json_err.into();
    assert_eq!(err.kind(), ErrorKind::Parse);
    assert!(err.format_user_message().contains("JSON error:"));
    assert!(StdError::source(&err).is_some());
}

#[test]
fn test_base64_decode_reports_parse_error() {
    let err = decode_base64_standard("!!!not-base64!!!", "field").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Parse);
    assert!(
        err.format_user_message().contains("field"),
        "got: {}",
        err.format_user_message()
    );
    assert!(StdError::source(&err).is_none());
}

#[test]
fn test_from_crypto_error_invalid_key_maps_to_error_crypto() {
    let src = CryptoError::build_invalid_key_error("bad length");
    let err: Error = src.into();
    assert_eq!(err.kind(), ErrorKind::Crypto);
    assert_eq!(err.format_user_message(), "bad length");
    assert!(StdError::source(&err).is_none());
}

#[test]
fn test_from_crypto_error_operation_failed_preserves_source() {
    let src = CryptoError::build_operation_failed_error_with_source(
        "AEAD seal failed",
        std::io::Error::other("inner"),
    );
    let err: Error = src.into();
    assert_eq!(err.kind(), ErrorKind::Crypto);
    assert_eq!(err.format_user_message(), "AEAD seal failed");
    assert!(StdError::source(&err).is_some());
}

#[test]
fn test_from_crypto_error_key_derivation_failed_maps_to_error_crypto() {
    let src = CryptoError::build_key_derivation_error("hkdf mismatch");
    let err: Error = src.into();
    assert_eq!(err.kind(), ErrorKind::Crypto);
    assert_eq!(err.format_user_message(), "hkdf mismatch");
    assert!(StdError::source(&err).is_none());
}

#[test]
fn test_from_ssh_error_maps_to_error_ssh() {
    let src = SshError::build_operation_failed_error("ssh-agent not running");
    let err: Error = src.into();
    assert_eq!(err.kind(), ErrorKind::Ssh);
    assert_eq!(err.format_user_message(), "ssh-agent not running");
    assert!(StdError::source(&err).is_none());
}

#[test]
fn test_from_format_error_loses_source() {
    // Current contract: FormatError -> Error::Parse discards the nested source
    // and keeps only the rendered message.
    let src = FormatError::build_parse_error("unexpected EOF");
    let err: Error = src.into();
    assert_eq!(err.kind(), ErrorKind::Parse);
    assert!(err.format_user_message().contains("unexpected EOF"));
    assert!(
        StdError::source(&err).is_none(),
        "FormatError source must not propagate"
    );
}

#[test]
fn test_from_hkdf_invalid_length_maps_to_crypto() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, b"ikm");
    // Requesting an oversized output (> 255 * HashLen) triggers InvalidLength.
    let mut out = vec![0u8; 255 * 32 + 1];
    let invalid = hk.expand(b"info", &mut out).unwrap_err();
    let err: Error = invalid.into();
    assert_eq!(err.kind(), ErrorKind::Crypto);
    assert!(err.format_user_message().contains("HKDF"));
    assert!(StdError::source(&err).is_none());
}

#[test]
fn test_io_error_source_is_exposed_via_std_error_trait() {
    let err = Error::build_io_error_with_source("wrap", std::io::Error::other("underlying"));
    // `std::error::Error::source` should return the wrapped io::Error.
    let src = StdError::source(&err).expect("source must be present");
    assert!(src.to_string().contains("underlying"));
}
