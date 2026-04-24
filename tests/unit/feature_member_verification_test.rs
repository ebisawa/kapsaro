// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::Error;

fn dummy_github() -> VerifiedGithubIdentity {
    VerifiedGithubIdentity::new(1, "alice-gh".to_string(), "SHA256:abc".to_string(), 42)
}

#[test]
fn test_build_verification_result_groups_all_verified() {
    let results = vec![VerificationResult::verified(
        "alice",
        "SSH key verified on GitHub (id=1, login=alice-gh)".to_string(),
        dummy_github(),
    )];
    let (verified, failed, not_configured) = build_verification_result_groups(&results);
    assert_eq!(verified.len(), 1);
    assert!(failed.is_empty());
    assert!(not_configured.is_empty());
}

#[test]
fn test_build_verification_result_groups_mixed() {
    let results = vec![
        VerificationResult::verified("alice", "OK".to_string(), dummy_github()),
        VerificationResult::failed("bob", "SSH key not found".to_string(), None, true),
        VerificationResult::not_configured("carol", "No binding_claims", None, false),
    ];
    let (verified, failed, not_configured) = build_verification_result_groups(&results);
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].member_id, "alice");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].member_id, "bob");
    assert_eq!(not_configured.len(), 1);
    assert_eq!(not_configured[0].member_id, "carol");
}

#[test]
fn test_build_verification_result_groups_empty() {
    let results: Vec<VerificationResult> = vec![];
    let (verified, failed, not_configured) = build_verification_result_groups(&results);
    assert!(verified.is_empty());
    assert!(failed.is_empty());
    assert!(not_configured.is_empty());
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
        Error::InvalidArgument {
            message: "broken attestation".to_string(),
        },
        true,
    );

    assert_eq!(result.member_id, "alice");
    assert_eq!(result.status, VerificationStatus::Failed);
    assert_eq!(
        result.message,
        "Offline verification failed: broken attestation"
    );
    assert!(result.github_claim_present);
}
