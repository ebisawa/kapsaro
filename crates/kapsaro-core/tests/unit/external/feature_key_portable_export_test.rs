// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::cli_api::test_support::domain::private_key::{PrivateKey, PrivateKeyPlaintext};
use kapsaro_core::cli_api::test_support::helpers::codec::base64_public::decode_base64url_nopad;
use kapsaro_core::cli_api::test_support::helpers::secret::SecretString;
use kapsaro_core::cli_api::test_support::operations::key::material::{
    build_private_key_plaintext, generate_keypairs,
};
use kapsaro_core::cli_api::test_support::operations::key::portable_export::{
    build_password_strength_warning, export_private_key_portable, ExportPasswordPolicy,
    PortableExportOptions,
};
use kapsaro_core::cli_api::test_support::operations::key::protection::password_encryption::decrypt_private_key_with_password;

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let keypairs = generate_keypairs().unwrap();
    build_private_key_plaintext(
        &keypairs.kem_sk,
        &keypairs.kem_pk,
        &keypairs.sig_sk,
        &keypairs.sig_pk,
    )
}

fn secret(value: &str) -> SecretString {
    SecretString::new(value.to_string())
}

#[test]
fn test_export_produces_valid_base64url() {
    let plaintext = build_test_plaintext();
    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("strong-password-42-xx"),
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    )
    .expect("export should succeed");

    // No padding characters
    assert!(!result.as_str().contains('='), "should not contain padding");
    // No standard base64 characters
    assert!(!result.as_str().contains('+'), "should not contain '+'");
    assert!(!result.as_str().contains('/'), "should not contain '/'");
    // Only valid base64url characters
    assert!(
        result
            .as_str()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "should only contain base64url characters"
    );
    // Should be non-empty
    assert!(!result.as_str().is_empty(), "should not be empty");

    let debug = format!("{result:?}");
    assert!(debug.contains("REDACTED"), "got: {debug}");
    assert!(!debug.contains(result.as_str()), "got: {debug}");
}

#[test]
fn test_export_roundtrip() {
    let plaintext = build_test_plaintext();
    let password = secret("strong-password-42-xx");

    let exported = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &password,
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    )
    .expect("export should succeed");

    // Decode base64url
    let json_bytes = decode_base64url_nopad(exported.as_str(), "portable export")
        .expect("should be valid base64url");

    // Deserialize to PrivateKey
    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).expect("should be valid JSON");

    // Decrypt with password
    let decrypted = decrypt_private_key_with_password(&private_key, &password, false)
        .expect("decryption should succeed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_export_preserves_metadata() {
    let plaintext = build_test_plaintext();
    let member_handle = "bob@example.com";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let created_at = "2026-03-01T12:00:00Z";
    let expires_at = "2027-03-01T12:00:00Z";

    let exported = export_private_key_portable(
        &plaintext,
        member_handle,
        kid,
        created_at,
        expires_at,
        &secret("strong-password-42-xx"),
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    )
    .expect("export should succeed");

    let json_bytes = decode_base64url_nopad(exported.as_str(), "portable export")
        .expect("should be valid base64url");
    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).expect("should be valid JSON");

    assert_eq!(private_key.protected.subject_handle, member_handle);
    assert_eq!(private_key.protected.kid, kid);
    assert_eq!(private_key.protected.created_at, created_at);
    assert_eq!(private_key.protected.expires_at, expires_at);
}

#[test]
fn test_export_password_too_short_fails() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("short"),
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    );

    assert!(
        result.is_err(),
        "password shorter than 20 bytes should fail"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("password") || err.contains("Password"),
        "error should mention password: {}",
        err
    );
}

#[test]
fn test_export_password_19_bytes_fails_by_default() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("1234567890123456789"),
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    );

    assert!(result.is_err(), "19-byte password should fail by default");
}

#[test]
fn test_export_password_20_bytes_succeeds_by_default() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("12345678901234567890"),
        PortableExportOptions::new(ExportPasswordPolicy::Recommended, false),
    );

    assert!(result.is_ok(), "20-byte password should succeed by default");
}

#[test]
fn test_export_password_8_bytes_succeeds_when_weak_passwords_are_allowed() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("12345678"),
        PortableExportOptions::new(ExportPasswordPolicy::AllowWeak, false),
    );

    assert!(
        result.is_ok(),
        "8-byte password should succeed when explicitly allowed"
    );
}

#[test]
fn test_export_password_7_utf8_bytes_fails_even_when_weak_passwords_are_allowed() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("あいa"),
        PortableExportOptions::new(ExportPasswordPolicy::AllowWeak, false),
    );

    assert!(result.is_err(), "7 UTF-8 bytes should fail");
}

#[test]
fn test_export_password_9_utf8_bytes_succeeds_when_weak_passwords_are_allowed() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        &secret("あいう"),
        PortableExportOptions::new(ExportPasswordPolicy::AllowWeak, false),
    );

    assert!(
        result.is_ok(),
        "9 UTF-8 bytes should succeed when explicitly allowed"
    );
}

#[test]
fn test_password_strength_warning_uses_utf8_byte_length() {
    assert!(build_password_strength_warning("1234567").is_none());
    assert!(build_password_strength_warning("12345678").is_some());
    assert!(build_password_strength_warning("あいう").is_some());
    assert!(build_password_strength_warning("12345678901234567890").is_none());
}
