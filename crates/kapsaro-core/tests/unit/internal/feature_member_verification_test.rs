// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::io::verify_online::{VerificationStatus, VerifiedGithubIdentity};
use crate::test_utils::{setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE};
use crate::Error;
use serde_json::Value;

fn dummy_github() -> VerifiedGithubIdentity {
    VerifiedGithubIdentity::new(1, "alice-gh".to_string(), "SHA256:abc".to_string(), 42)
}

fn tampered_active_member_public_key(
    tamper: impl FnOnce(&mut Value),
) -> crate::model::public_key::PublicKey {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let member_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    let mut value: Value =
        serde_json::from_str(&std::fs::read_to_string(member_file).unwrap()).unwrap();
    tamper(&mut value);
    serde_json::from_value(value).unwrap()
}

#[test]
fn test_verify_member_public_key_file_rejects_tampered_attestation_signature() {
    let public_key = tampered_active_member_public_key(|value| {
        value["protected"]["attestation"]["sig"] = Value::String("broken".to_string());
    });

    let error = verify_member_public_key_file(
        &public_key,
        Some(ALICE_MEMBER_HANDLE),
        "members/active/alice@example.com.json",
    )
    .unwrap_err();

    assert!(
        error
            .format_user_message()
            .contains("does not match derived kid"),
        "unexpected error: {}",
        error.format_user_message()
    );
}

#[test]
fn test_append_verification_warnings_keeps_original_message_without_warnings() {
    let result = VerificationResult::failed("alice", "offline failed".to_string(), None, true);

    let updated = append_verification_warnings(result, &[]);

    assert_eq!(updated.message, "offline failed");
}

#[test]
fn test_append_verification_warnings_appends_joined_warning_suffix() {
    let result = VerificationResult::verified("alice", "verified".to_string(), dummy_github());
    let warnings = vec!["warning one".to_string(), "warning two".to_string()];

    let updated = append_verification_warnings(result, &warnings);

    assert_eq!(updated.message, "verified [warning one; warning two]");
}

#[test]
fn test_build_offline_verification_failure_preserves_claim_flag_and_prefix() {
    let result = build_offline_verification_failure(
        "alice",
        Error::build_invalid_argument_error("broken attestation".to_string()),
        true,
    );

    assert_eq!(result.member_handle, "alice");
    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(
        result.message,
        "Offline verification failed: broken attestation"
    );
    assert!(result.github_claim_present);
}
