// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for inspect formatting (file.rs, kv.rs) and verify report builders.
//!
//! Tests inspect output sections for file-enc and kv-enc formats,
//! and verify report construction via the public verify_*_document_report API.

use crate::keygen_helpers::build_verified_recipient_key;
use crate::test_utils::{setup_member_key_context, setup_test_keystore, EnvGuard};
use crate::test_utils::{
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE, DAVE_MEMBER_HANDLE,
};
use kapsaro_core::cli_api::test_support::domain::verification::VerifyingKeySource;
use kapsaro_core::cli_api::test_support::operations::context::crypto::SigningContext;
use kapsaro_core::cli_api::test_support::operations::encrypt::encrypt_file_content;
use kapsaro_core::cli_api::test_support::operations::inspect::{build_inspect_view, InspectOutput};
use kapsaro_core::cli_api::test_support::operations::kv::encrypt::encrypt_kv_document;
use kapsaro_core::cli_api::test_support::operations::verify::file::verify_file_document_report;
use kapsaro_core::cli_api::test_support::operations::verify::kv::signature::verify_kv_document_report;
use kapsaro_core::cli_api::test_support::storage::keystore::storage::{list_kids, load_public_key};
use kapsaro_core::cli_api::test_support::wire::content::EncContent;
use kapsaro_core::cli_api::test_support::wire::schema::document::parse_kv_signature_token;
use kapsaro_core::cli_api::test_support::wire::token::TokenCodec;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

fn inspect_contains(output: &InspectOutput, needle: &str) -> bool {
    output.sections.iter().any(|section| {
        section.title.contains(needle) || section.lines.iter().any(|line| line.contains(needle))
    })
}

fn build_signing_context(
    temp_dir: &TempDir,
    member_handle: &str,
) -> (
    kapsaro_core::cli_api::test_support::operations::context::crypto::CryptoContext,
    kapsaro_core::cli_api::test_support::domain::public_key::PublicKey,
) {
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, member_handle)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let key_ctx = setup_member_key_context(temp_dir, member_handle, Some(&kid));
    let public_key = load_public_key(&keystore_root, member_handle, &kid).unwrap();
    (key_ctx, public_key)
}

fn encrypt_kv_fixture(temp_dir: &TempDir, member_handle: &str, key: &str, value: &str) -> String {
    let (key_ctx, public_key) = build_signing_context(temp_dir, member_handle);
    let mut kv = HashMap::new();
    kv.insert(key.to_string(), value.to_string());
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: key_ctx.kid(),
        signer_pub: public_key.clone(),
        debug: false,
    };
    encrypt_kv_document(
        &kv,
        &[build_verified_recipient_key(public_key)],
        &signing,
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

fn encrypt_file_fixture(temp_dir: &TempDir, member_handle: &str, content: &[u8]) -> String {
    let (key_ctx, public_key) = build_signing_context(temp_dir, member_handle);
    let signing = SigningContext {
        signing_key: key_ctx.signing_key(),
        signer_kid: key_ctx.kid(),
        signer_pub: public_key.clone(),
        debug: false,
    };
    encrypt_file_content(
        content,
        &[member_handle.to_string()],
        &[build_verified_recipient_key(public_key)],
        &signing,
    )
    .unwrap()
}

/// Helper: create a kv-enc encrypted file and return its content as String.
fn build_kv_enc_content(member_handle: &str) -> (tempfile::TempDir, String) {
    let _guard = EnvGuard::new(&["KAPSARO_PRIVATE_KEY", "KAPSARO_KEY_PASSWORD"]);
    let temp_dir = setup_test_keystore(member_handle);
    let content = encrypt_kv_fixture(
        &temp_dir,
        member_handle,
        "DATABASE_URL",
        "postgres://localhost",
    );
    (temp_dir, content)
}

/// Helper: create a file-enc encrypted file and return its content as String.
fn build_file_enc_content(member_handle: &str) -> (tempfile::TempDir, String) {
    let _guard = EnvGuard::new(&["KAPSARO_PRIVATE_KEY", "KAPSARO_KEY_PASSWORD"]);
    let temp_dir = setup_test_keystore(member_handle);
    let content = encrypt_file_fixture(&temp_dir, member_handle, b"super secret content");
    (temp_dir, content)
}

// ============================================================================
// file-enc inspect output tests
// ============================================================================

#[test]
fn test_inspect_file_enc_header_contains_sid_and_timestamps() {
    let (_temp_dir, content) = build_file_enc_content(ALICE_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    let header = output
        .sections
        .iter()
        .find(|s| s.title == "Header")
        .expect("Should have Header section");
    assert!(
        header.lines.iter().any(|l| l.contains("SID:")),
        "Header should contain SID. Lines: {:?}",
        header.lines
    );
    assert!(
        header.lines.iter().any(|l| l.contains("Created:")),
        "Header should contain Created. Lines: {:?}",
        header.lines
    );
    assert!(
        header.lines.iter().any(|l| l.contains("Updated:")),
        "Header should contain Updated. Lines: {:?}",
        header.lines
    );
    assert!(
        !header.lines.iter().any(|l| l.contains("Format:")),
        "Header should NOT contain Format. Lines: {:?}",
        header.lines
    );
}

#[test]
fn test_inspect_file_enc_wrap_data_contains_recipients() {
    let (_temp_dir, content) = build_file_enc_content(BOB_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    let wrap_section = output
        .sections
        .iter()
        .find(|s| s.title.starts_with("Wrap Data"))
        .expect("Should have Wrap Data section");
    assert!(
        wrap_section.lines.iter().any(|l| l.contains("Recipients")),
        "Wrap Data should contain Recipients. Lines: {:?}",
        wrap_section.lines
    );
    assert!(
        !output.sections.iter().any(|s| s.title == "Recipients"),
        "Should NOT have a separate Recipients section"
    );
}

#[test]
fn test_inspect_file_enc_payload_contains_sid() {
    let (_temp_dir, content) = build_file_enc_content(ALICE_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    let payload = output
        .sections
        .iter()
        .find(|s| s.title == "Payload")
        .expect("Should have Payload section");
    assert!(
        payload.lines.iter().any(|l| l.contains("SID:")),
        "Payload should contain SID. Lines: {:?}",
        payload.lines
    );
}

#[test]
fn test_inspect_file_enc_shows_signature() {
    let (_temp_dir, content) = build_file_enc_content(CAROL_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    assert!(
        inspect_contains(&output, "Signature"),
        "file-enc inspect output should contain 'Signature:' section. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "Algorithm:"),
        "file-enc inspect output should contain algorithm info. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "Kid:"),
        "file-enc inspect output should contain kid info. Output: {output:?}",
    );

    assert!(
        inspect_contains(&output, "Attestation:"),
        "file-enc inspect output should include attestation method. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "Attest Key:"),
        "file-enc inspect output should include attestation pubkey. Output: {output:?}",
    );
}

// ============================================================================
// kv-enc inspect output tests
// ============================================================================

#[test]
fn test_inspect_kv_enc_shows_header() {
    let (_temp_dir, content) = build_kv_enc_content(ALICE_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    assert!(
        output.sections.iter().any(|s| s.title == "Header"),
        "kv-enc inspect output should contain 'Header' section. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "SID:"),
        "kv-enc inspect output should contain SID in Header section. Output: {output:?}",
    );
    // Version section should not exist
    assert!(
        !output.sections.iter().any(|s| s.title == "Version"),
        "kv-enc inspect output should NOT have Version section. Output: {output:?}",
    );
}

#[test]
fn test_inspect_kv_enc_shows_entries() {
    let (_temp_dir, content) = build_kv_enc_content(BOB_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    assert!(
        inspect_contains(&output, "Entries"),
        "kv-enc inspect output should contain 'Entries' section. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "DATABASE_URL"),
        "kv-enc inspect output should list the entry key. Output: {output:?}",
    );
}

#[test]
fn test_inspect_kv_enc_shows_wrap_data() {
    let (_temp_dir, content) = build_kv_enc_content(CAROL_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    assert!(
        output
            .sections
            .iter()
            .any(|s| s.title.starts_with("Wrap Data")),
        "kv-enc inspect output should contain 'Wrap Data' section. Output: {output:?}",
    );
}

#[test]
fn test_inspect_kv_enc_shows_header_aead_not_entry_k() {
    let (_temp_dir, content) = build_kv_enc_content(ALICE_MEMBER_HANDLE);

    let encrypted = EncContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    let entries = output
        .sections
        .iter()
        .find(|s| s.title.starts_with("Entries"))
        .expect("Should have Entries section");
    assert!(
        !entries.lines.iter().any(|l| l.contains("K:")),
        "Entries should not contain K field. Lines: {:?}",
        entries.lines
    );
    let header = output
        .sections
        .iter()
        .find(|s| s.title == "Header")
        .expect("Should have Header section");
    assert!(
        header.lines.iter().any(|l| l.contains("AEAD:")),
        "Header should contain AEAD field. Lines: {:?}",
        header.lines
    );
}

// ============================================================================
// verify report builder tests (tested indirectly via public API)
// ============================================================================

#[test]
fn test_build_error_report() {
    let (_temp_dir, content) = build_kv_enc_content(ALICE_MEMBER_HANDLE);

    // Corrupt the signature kid to trigger a "Cannot find public key" error
    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines = Vec::new();
    for line in &lines {
        if line.starts_with(":SIG ") {
            new_lines.push(":SIG eyJhbGciOiJlZGRzYS1lZDI1NTE5Iiwia2lkIjoiMDFOT05FWElTVEVOVEtFWV9JRCIsInNpZyI6Ii4uLiJ9");
        } else {
            new_lines.push(line);
        }
    }
    let corrupted_content = new_lines.join("\n") + "\n";

    let report = verify_kv_document_report(&corrupted_content, false);

    assert!(!report.verified, "Error report should have verified=false");
    assert!(
        report.signer_handle.is_none(),
        "Error report should have no signer_handle"
    );
    assert!(
        report.source.is_none(),
        "Error report should have no source"
    );
    assert!(
        !report.message.is_empty(),
        "Error report should have a non-empty message"
    );
}

#[test]
fn test_build_success_report() {
    let (_temp_dir, content) = build_file_enc_content(DAVE_MEMBER_HANDLE);

    let file_enc_doc: kapsaro_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&content).unwrap();

    let report = verify_file_document_report(&file_enc_doc, false);

    assert!(report.verified, "Success report should have verified=true");
    assert_eq!(
        report.signer_handle,
        Some(DAVE_MEMBER_HANDLE.to_string()),
        "Success report should contain the signer member_handle"
    );
    assert!(
        matches!(report.source, Some(VerifyingKeySource::SignerPubEmbedded)),
        "Success report source should be SignerPubEmbedded (signer_pub is embedded in signature)"
    );
    assert_eq!(
        report.message, "OK",
        "Success report message should be 'OK'"
    );
}

// ============================================================================
// Tests merged from inspect_verify_test.rs
// ============================================================================

#[test]
fn test_inspect_kv_enc_with_verification() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_HANDLE);
    let encrypted_content = encrypt_kv_fixture(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        "DATABASE_URL",
        "postgres://localhost",
    );

    // Inspect with verification
    let encrypted = EncContent::detect(encrypted_content.clone()).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();
    let signature_report = verify_kv_document_report(&encrypted_content, false);

    // Check that verification result is included
    assert!(
        signature_report.verified,
        "signature report should indicate verification success"
    );
    assert!(
        signature_report.signer_handle.as_deref() == Some(ALICE_MEMBER_HANDLE),
        "signature report should include signer member_handle"
    );
    assert!(
        inspect_contains(&output, "Attestation:"),
        "Output should include embedded signer attestation method. Output: {output:?}",
    );
    assert!(
        inspect_contains(&output, "Attest Key:"),
        "Output should include embedded signer attestation pubkey. Output: {output:?}",
    );
}

#[test]
fn test_inspect_kv_enc_with_verification_failure_no_keystore() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_HANDLE);
    let test_dir = temp_dir.path();

    // Read encrypted content and corrupt the signature
    let mut kv_content = encrypt_kv_fixture(&temp_dir, ALICE_MEMBER_HANDLE, "KEY", "value");
    let lines: Vec<&str> = kv_content.lines().collect();
    // Replace the SIG line with an invalid signature
    let original_signature_line = lines
        .iter()
        .find(|line| line.starts_with(":SIG "))
        .expect("SIG line should exist");
    let mut invalid_signature =
        parse_kv_signature_token(original_signature_line.trim_start_matches(":SIG ")).unwrap();
    invalid_signature.sig =
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
            .to_string();
    let invalid_signature_token =
        TokenCodec::encode(TokenCodec::JsonJcs, &invalid_signature).unwrap();
    let mut new_lines = Vec::new();
    for line in &lines {
        if line.starts_with(":SIG ") {
            new_lines.push(format!(":SIG {}", invalid_signature_token));
        } else {
            new_lines.push((*line).to_string());
        }
    }
    kv_content = new_lines.join("\n") + "\n";

    // Create a new keystore without the key (empty keystore)
    let empty_keystore = test_dir.join("empty_keys");
    fs::create_dir_all(&empty_keystore).unwrap();

    // Inspect with verification (keystore doesn't have the key).
    // With graceful degradation, inspect succeeds and shows FAILED verification status.
    let encrypted = EncContent::detect(kv_content.clone()).unwrap();
    let result = build_inspect_view(&encrypted);

    assert!(
        result.is_ok(),
        "Inspect should succeed even when keystore does not contain the signing key"
    );
    let output = result.unwrap();
    let signature_report = verify_kv_document_report(&kv_content, false);
    assert!(
        !signature_report.verified,
        "Output should show FAILED verification status: {output:?}",
    );
}

#[test]
fn test_verify_kv_document_report() {
    let temp_dir = setup_test_keystore(BOB_MEMBER_HANDLE);
    let encrypted_content = encrypt_kv_fixture(&temp_dir, BOB_MEMBER_HANDLE, "KEY", "value");

    // Verify signature
    let report = verify_kv_document_report(&encrypted_content, false);

    assert!(report.verified, "Signature should be verified");
    assert_eq!(report.signer_handle, Some(BOB_MEMBER_HANDLE.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}

#[test]
fn test_verify_file_document_report() {
    let temp_dir = setup_test_keystore(CAROL_MEMBER_HANDLE);
    let encrypted_content = encrypt_file_fixture(&temp_dir, CAROL_MEMBER_HANDLE, b"test content");
    let file_enc_doc: kapsaro_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_content).unwrap();

    // Verify signature
    let report = verify_file_document_report(&file_enc_doc, false);

    assert!(report.verified, "Signature should be verified");
    assert_eq!(report.signer_handle, Some(CAROL_MEMBER_HANDLE.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}

#[test]
fn test_verify_kv_document_report_failure_wrong_key() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_HANDLE);

    // Read encrypted content and change the signature kid to a non-existent one
    let mut kv_content = encrypt_kv_fixture(&temp_dir, ALICE_MEMBER_HANDLE, "KEY", "value");
    let lines: Vec<&str> = kv_content.lines().collect();
    let mut new_lines = Vec::new();
    let original_signature_line = lines
        .iter()
        .find(|line| line.starts_with(":SIG "))
        .expect("SIG line should exist");
    let mut wrong_kid_signature =
        parse_kv_signature_token(original_signature_line.trim_start_matches(":SIG ")).unwrap();
    wrong_kid_signature.kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GG".to_string();
    let wrong_kid_signature_token =
        TokenCodec::encode(TokenCodec::JsonJcs, &wrong_kid_signature).unwrap();
    for line in &lines {
        if line.starts_with(":SIG ") {
            // Replace with signature that references a non-existent kid
            new_lines.push(format!(":SIG {}", wrong_kid_signature_token));
        } else {
            new_lines.push((*line).to_string());
        }
    }
    kv_content = new_lines.join("\n") + "\n";

    let report = verify_kv_document_report(&kv_content, false);

    assert!(!report.verified, "Signature should not be verified");
    assert!(report.signer_handle.is_none());
    assert!(report.source.is_none());
    assert!(
        report.message.contains("kid mismatch"),
        "Expected kid mismatch error, got: {}",
        report.message
    );
}

#[test]
fn test_verify_kv_document_report_with_embedded_signer_pub() {
    let temp_dir = setup_test_keystore(DAVE_MEMBER_HANDLE);
    let encrypted_content = encrypt_kv_fixture(&temp_dir, DAVE_MEMBER_HANDLE, "KEY", "value");

    // Verify signature with embedded signer_pub
    let report = verify_kv_document_report(&encrypted_content, false);

    // Should succeed even with embedded signer_pub
    assert!(
        report.verified,
        "Signature should be verified with embedded signer_pub. Message: {}, Source: {:?}",
        report.message, report.source
    );
    assert_eq!(report.signer_handle, Some(DAVE_MEMBER_HANDLE.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}
