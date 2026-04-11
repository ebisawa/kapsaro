// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for inspect formatting (file.rs, kv.rs) and verify report builders.
//!
//! Tests inspect output sections for file-enc and kv-enc formats,
//! and verify report construction via the public verify_*_document_report API.

use crate::test_utils::{setup_test_keystore, EnvGuard};
use crate::test_utils::{ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID};
use secretenv::feature::inspect::{build_inspect_view, InspectOutput};
use secretenv::feature::verify::file::verify_file_document_report;
use secretenv::feature::verify::kv::signature::verify_kv_document_report;
use secretenv::format::content::EncryptedContent;
use secretenv::format::token::TokenCodec;
use secretenv::model::signature::Signature;
use secretenv::model::verification::VerifyingKeySource;
use std::fs;

fn inspect_contains(output: &InspectOutput, needle: &str) -> bool {
    output.sections.iter().any(|section| {
        section.title.contains(needle) || section.lines.iter().any(|line| line.contains(needle))
    })
}

/// Create a minimal workspace structure in `workspace_dir` and copy the given
/// member's public key from `keystore_root` into `members/active/`.
fn setup_workspace_with_member(
    keystore_root: &std::path::Path,
    workspace_dir: &std::path::Path,
    member_id: &str,
) {
    let members_dir = workspace_dir.join("members/active");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.join("secrets")).unwrap();

    let keystore_member_files = fs::read_dir(keystore_root.join(member_id)).unwrap();
    for entry in keystore_member_files {
        let entry = entry.unwrap();
        if !entry.path().is_dir() {
            continue;
        }
        let pub_file = entry.path().join("public.json");
        if pub_file.exists() {
            let pub_content = fs::read_to_string(&pub_file).unwrap();
            let member_file = members_dir.join(format!("{}.json", member_id));
            fs::write(&member_file, pub_content).unwrap();
            break;
        }
    }
}

/// Build CommonOptions for a test using the given workspace dir and temp_dir for SSH key.
fn build_common_opts(
    test_dir: &std::path::Path,
    workspace_dir: &std::path::Path,
) -> secretenv::cli::options::CommonOptions {
    use secretenv::cli::options::CommonOptions;
    let ssh_key_path = test_dir.join(".ssh").join("test_ed25519");
    CommonOptions {
        home: Some(test_dir.to_path_buf()),
        workspace: Some(workspace_dir.to_path_buf()),
        identity: Some(ssh_key_path),
        ssh_agent: false,
        ssh_keygen: true,
        json: false,
        quiet: false,
        verbose: false,
    }
}

/// Helper: create a kv-enc encrypted file and return its content as String.
fn create_kv_enc_content(member_id: &str) -> (tempfile::TempDir, String) {
    let _guard = EnvGuard::new(&["SECRETENV_PRIVATE_KEY", "SECRETENV_KEY_PASSWORD"]);
    let temp_dir = setup_test_keystore(member_id);
    let test_dir = temp_dir.path().to_path_buf();
    let keystore_root = test_dir.join("keys");
    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, member_id);

    use secretenv::cli::set;
    let common_opts = build_common_opts(&test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(member_id.to_string()),
        name: None,
        key: "DATABASE_URL".to_string(),
        value: Some("postgres://localhost".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    let content = fs::read_to_string(&encrypted_path).unwrap();
    (temp_dir, content)
}

/// Helper: create a file-enc encrypted file and return its content as String.
fn create_file_enc_content(member_id: &str) -> (tempfile::TempDir, String) {
    let _guard = EnvGuard::new(&["SECRETENV_PRIVATE_KEY", "SECRETENV_KEY_PASSWORD"]);
    let temp_dir = setup_test_keystore(member_id);
    let test_dir = temp_dir.path().to_path_buf();
    let keystore_root = test_dir.join("keys");
    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, member_id);

    let input_path = workspace_dir.join("secret.txt");
    fs::write(&input_path, b"super secret content").unwrap();

    use secretenv::cli::encrypt;
    let common_opts = build_common_opts(&test_dir, &workspace_dir);
    let encrypted_path = test_dir.join("secret.json");

    let encrypt_args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(member_id.to_string()),
        input: input_path,
        out: Some(encrypted_path.clone()),
    };
    encrypt::run(encrypt_args).unwrap();

    let content = fs::read_to_string(&encrypted_path).unwrap();
    (temp_dir, content)
}

// ============================================================================
// file-enc inspect output tests
// ============================================================================

#[test]
fn test_inspect_file_enc_header_contains_sid_and_timestamps() {
    let (_temp_dir, content) = create_file_enc_content(ALICE_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_file_enc_content(BOB_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_file_enc_content(ALICE_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_file_enc_content(CAROL_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_kv_enc_content(ALICE_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_kv_enc_content(BOB_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
    let (_temp_dir, content) = create_kv_enc_content(CAROL_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
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
fn test_inspect_kv_enc_entries_contain_k_field() {
    let (_temp_dir, content) = create_kv_enc_content(ALICE_MEMBER_ID);

    let encrypted = EncryptedContent::detect(content).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();

    let entries = output
        .sections
        .iter()
        .find(|s| s.title.starts_with("Entries"))
        .expect("Should have Entries section");
    assert!(
        entries.lines.iter().any(|l| l.contains("K:")),
        "Entries should contain K field. Lines: {:?}",
        entries.lines
    );
}

// ============================================================================
// verify report builder tests (tested indirectly via public API)
// ============================================================================

#[test]
fn test_build_error_report() {
    let (_temp_dir, content) = create_kv_enc_content(ALICE_MEMBER_ID);

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
        report.signer_member_id.is_none(),
        "Error report should have no signer_member_id"
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
    let (_temp_dir, content) = create_file_enc_content(DAVE_MEMBER_ID);

    let file_enc_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&content).unwrap();

    let report = verify_file_document_report(&file_enc_doc, false);

    assert!(report.verified, "Success report should have verified=true");
    assert_eq!(
        report.signer_member_id,
        Some(DAVE_MEMBER_ID.to_string()),
        "Success report should contain the signer member_id"
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
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, ALICE_MEMBER_ID);

    // Create kv-enc file via set command
    use secretenv::cli::set;
    let common_opts = build_common_opts(test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        name: None,
        key: "DATABASE_URL".to_string(),
        value: Some("postgres://localhost".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    // Read encrypted content
    let encrypted_content = fs::read_to_string(&encrypted_path).unwrap();

    // Inspect with verification
    let encrypted = EncryptedContent::detect(encrypted_content.clone()).unwrap();
    let output = build_inspect_view(&encrypted).unwrap();
    let signature_report = verify_kv_document_report(&encrypted_content, false);

    // Check that verification result is included
    assert!(
        signature_report.verified,
        "signature report should indicate verification success"
    );
    assert!(
        signature_report.signer_member_id.as_deref() == Some(ALICE_MEMBER_ID),
        "signature report should include signer member_id"
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
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, ALICE_MEMBER_ID);

    // Create kv-enc file via set command
    use secretenv::cli::set;
    let common_opts = build_common_opts(test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        name: None,
        key: "KEY".to_string(),
        value: Some("value".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    // Read encrypted content and corrupt the signature
    let mut kv_content = fs::read_to_string(&encrypted_path).unwrap();
    // Replace the SIG line with an invalid signature
    let invalid_signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: None,
        sig:
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                .to_string(),
    };
    let invalid_signature_token =
        TokenCodec::encode(TokenCodec::JsonJcs, &invalid_signature).unwrap();
    let lines: Vec<&str> = kv_content.lines().collect();
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
    let encrypted = EncryptedContent::detect(kv_content.clone()).unwrap();
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
    let temp_dir = setup_test_keystore(BOB_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, BOB_MEMBER_ID);

    // Create kv-enc file via set command
    use secretenv::cli::set;
    let common_opts = build_common_opts(test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(BOB_MEMBER_ID.to_string()),
        name: None,
        key: "KEY".to_string(),
        value: Some("value".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    let encrypted_content = fs::read_to_string(&encrypted_path).unwrap();

    // Verify signature
    let report = verify_kv_document_report(&encrypted_content, false);

    assert!(report.verified, "Signature should be verified");
    assert_eq!(report.signer_member_id, Some(BOB_MEMBER_ID.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}

#[test]
fn test_verify_file_document_report() {
    let temp_dir = setup_test_keystore(CAROL_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, CAROL_MEMBER_ID);

    // Create and encrypt a binary file using encrypt command
    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"test content").unwrap();

    use secretenv::cli::encrypt;
    let common_opts = build_common_opts(test_dir, &workspace_dir);

    let encrypted_path = test_dir.join("test.json");
    let encrypt_args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(CAROL_MEMBER_ID.to_string()),
        input: input_path,
        out: Some(encrypted_path.clone()),
    };
    encrypt::run(encrypt_args).unwrap();

    let encrypted_content = fs::read_to_string(&encrypted_path).unwrap();
    let file_enc_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_content).unwrap();

    // Verify signature
    let report = verify_file_document_report(&file_enc_doc, false);

    assert!(report.verified, "Signature should be verified");
    assert_eq!(report.signer_member_id, Some(CAROL_MEMBER_ID.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}

#[test]
fn test_verify_kv_document_report_failure_wrong_key() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, ALICE_MEMBER_ID);

    // Create kv-enc file via set command
    use secretenv::cli::set;
    let common_opts = build_common_opts(test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        name: None,
        key: "KEY".to_string(),
        value: Some("value".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    // Read encrypted content and change the signature kid to a non-existent one
    let mut kv_content = fs::read_to_string(&encrypted_path).unwrap();
    let lines: Vec<&str> = kv_content.lines().collect();
    let mut new_lines = Vec::new();
    let wrong_kid_signature = Signature {
        alg: "eddsa-ed25519".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GG".to_string(),
        signer_pub: None,
        sig:
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                .to_string(),
    };
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
    assert!(report.signer_member_id.is_none());
    assert!(report.source.is_none());
    assert!(
        report.message.contains("signer_pub is missing"),
        "Expected E_SIGNER_PUB_MISSING error, got: {}",
        report.message
    );
}

#[test]
fn test_verify_kv_document_report_with_embedded_signer_pub() {
    let temp_dir = setup_test_keystore(DAVE_MEMBER_ID);
    let test_dir = temp_dir.path();
    let keystore_root = test_dir.join("keys");

    let workspace_dir = test_dir.join("workspace");
    fs::create_dir_all(&workspace_dir).unwrap();
    setup_workspace_with_member(&keystore_root, &workspace_dir, DAVE_MEMBER_ID);

    // Create and encrypt a kv file
    use secretenv::cli::set;
    let common_opts = build_common_opts(test_dir, &workspace_dir);
    let encrypted_path = workspace_dir.join("secrets").join("default.kvenc");

    let set_args = set::SetArgs {
        common: common_opts,
        member_id: Some(DAVE_MEMBER_ID.to_string()),
        name: None,
        key: "KEY".to_string(),
        value: Some("value".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    let encrypted_content = fs::read_to_string(&encrypted_path).unwrap();

    // Verify signature with embedded signer_pub
    let report = verify_kv_document_report(&encrypted_content, false);

    // Should succeed even with embedded signer_pub
    assert!(
        report.verified,
        "Signature should be verified with embedded signer_pub. Message: {}, Source: {:?}",
        report.message, report.source
    );
    assert_eq!(report.signer_member_id, Some(DAVE_MEMBER_ID.to_string()));
    assert!(matches!(
        report.source,
        Some(VerifyingKeySource::SignerPubEmbedded)
    ));
    assert_eq!(report.message, "OK");
}
