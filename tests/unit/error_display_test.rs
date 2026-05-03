// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Display / From coverage for src/error.rs.
//!
//! Complements error_test.rs (format_user_message coverage) with table-driven
//! Display output checks and From conversion checks.

use secretenv::crypto::CryptoError;
use secretenv::format::FormatError;
use secretenv::io::ssh::SshError;
use secretenv::support::codec::base64_public::decode_base64_standard;
use secretenv::Error;
use std::error::Error as StdError;

// --------------------------------------------------------------------
// Display output for each Error variant
// --------------------------------------------------------------------

#[test]
fn test_display_schema_variant() {
    let err = Error::Schema {
        message: "Invalid secretenv document\nReason: signature.signer_pub is missing".to_string(),
        source: None,
    };
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
    match err {
        Error::Io { message, source } => {
            assert!(message.contains("disk full"));
            assert!(source.is_some(), "source must be preserved");
        }
        other => panic!("expected Error::Io, got {:?}", other),
    }
}

#[test]
fn test_from_serde_json_error_wraps_as_parse() {
    let json_err = serde_json::from_str::<serde_json::Value>("{ not valid").unwrap_err();
    let err: Error = json_err.into();
    match err {
        Error::Parse { message, source } => {
            assert!(message.contains("JSON error:"));
            assert!(source.is_some());
        }
        other => panic!("expected Error::Parse, got {:?}", other),
    }
}

#[test]
fn test_base64_decode_reports_parse_error() {
    let err = decode_base64_standard("!!!not-base64!!!", "field").unwrap_err();
    match err {
        Error::Parse { message, source } => {
            assert!(message.contains("field"), "got: {message}");
            assert!(source.is_none());
        }
        other => panic!("expected Error::Parse, got {:?}", other),
    }
}

#[test]
fn test_from_crypto_error_invalid_key_maps_to_error_crypto() {
    let src = CryptoError::build_invalid_key_error("bad length");
    let err: Error = src.into();
    match err {
        Error::Crypto { message, source } => {
            assert_eq!(message, "bad length");
            assert!(source.is_none());
        }
        other => panic!("expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_from_crypto_error_operation_failed_preserves_source() {
    let src = CryptoError::build_operation_failed_error_with_source(
        "AEAD seal failed",
        std::io::Error::other("inner"),
    );
    let err: Error = src.into();
    match err {
        Error::Crypto { message, source } => {
            assert_eq!(message, "AEAD seal failed");
            assert!(source.is_some());
        }
        other => panic!("expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_from_crypto_error_key_derivation_failed_maps_to_error_crypto() {
    let src = CryptoError::build_key_derivation_error("hkdf mismatch");
    let err: Error = src.into();
    match err {
        Error::Crypto { message, source } => {
            assert_eq!(message, "hkdf mismatch");
            assert!(source.is_none());
        }
        other => panic!("expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_from_ssh_error_maps_to_error_ssh() {
    let src = SshError::build_operation_failed_error("ssh-agent not running");
    let err: Error = src.into();
    match err {
        Error::Ssh { message, source } => {
            assert_eq!(message, "ssh-agent not running");
            assert!(source.is_none());
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_from_format_error_loses_source() {
    // Current contract: FormatError -> Error::Parse discards the nested source
    // and keeps only the rendered message.
    let src = FormatError::build_parse_error("unexpected EOF");
    let err: Error = src.into();
    match err {
        Error::Parse { message, source } => {
            assert!(message.contains("unexpected EOF"));
            assert!(source.is_none(), "FormatError source must not propagate");
        }
        other => panic!("expected Error::Parse, got {:?}", other),
    }
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
    match err {
        Error::Crypto { message, source } => {
            assert!(message.contains("HKDF"));
            assert!(source.is_none());
        }
        other => panic!("expected Error::Crypto, got {:?}", other),
    }
}

#[test]
fn test_io_error_source_is_exposed_via_std_error_trait() {
    let err = Error::build_io_error_with_source("wrap", std::io::Error::other("underlying"));
    // `std::error::Error::source` should return the wrapped io::Error.
    let src = StdError::source(&err).expect("source must be present");
    assert!(src.to_string().contains("underlying"));
}
