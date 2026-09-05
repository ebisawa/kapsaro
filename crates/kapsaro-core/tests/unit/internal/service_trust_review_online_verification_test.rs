// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};
use crate::service::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};

fn candidate(configured: bool) -> TrustApprovalCandidate {
    TrustApprovalCandidate::for_test(
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        configured,
    )
}

fn verified_candidate(candidate: &TrustApprovalCandidate) -> TrustApprovalCandidate {
    let evidence = crate::service::online::VerifiedGitHubEvidence::for_test(
        candidate.service_candidate(),
        42,
        "alice",
        "SHA256:test",
        100,
    );
    TrustApprovalCandidateBuilder::from_known_key_candidate(candidate.service_candidate())
        .with_verified_service_evidence(evidence)
        .with_online_verification_context(true, Some("verified".to_string()))
        .build()
}

fn failed_candidate(candidate: &TrustApprovalCandidate, message: &str) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::from_known_key_candidate(candidate.service_candidate())
        .with_online_verification_context(true, Some(message.to_string()))
        .build()
}

#[test]
fn test_review_candidate_for_confirmation_skips_unconfigured_binding() {
    let candidate = candidate(false);
    let mut called = false;

    let reviewed = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        &mut |_candidate| {
            called = true;
            Ok(candidate.clone())
        },
    )
    .unwrap();

    assert_eq!(reviewed, candidate);
    assert!(!called);
}

#[test]
fn test_review_candidate_for_confirmation_accepts_verified_result() {
    let candidate = candidate(true);

    let reviewed = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        &mut |candidate| Ok(verified_candidate(candidate)),
    )
    .unwrap();

    assert_eq!(reviewed.github_id(), Some(42));
    assert_eq!(reviewed.github_login(), Some("alice"));
    assert!(reviewed.is_github_verified());
}

#[test]
fn test_review_candidate_for_confirmation_allows_non_member_failed_online_result() {
    let candidate = candidate(true);

    let reviewed = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::NonMemberAcceptance,
        &mut |candidate| Ok(failed_candidate(candidate, "not found")),
    )
    .unwrap();

    assert_eq!(reviewed.online_verification_message(), Some("not found"));
    assert!(!reviewed.is_github_verified());
}

#[test]
fn test_review_candidate_for_confirmation_allows_non_member_verifier_error() {
    let candidate = candidate(true);

    let reviewed = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::NonMemberAcceptance,
        &mut |_candidate| {
            Err(crate::Error::build_verification_error(
                "V-GITHUB-API".to_string(),
                "GitHub API unavailable".to_string(),
            ))
        },
    )
    .unwrap();

    assert!(reviewed.online_verification_attempted());
    assert_eq!(
        reviewed.online_verification_message(),
        Some("GitHub API unavailable")
    );
    assert!(!reviewed.is_github_verified());
}

#[test]
fn test_review_candidate_for_confirmation_requires_online_verification_for_known_key() {
    let candidate = candidate(true);

    let error = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        &mut |candidate| Ok(failed_candidate(candidate, "not found")),
    )
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_ONLINE_VERIFY_REQUIRED"));
    assert!(
        error.format_user_message().contains("not found"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[test]
fn test_review_candidate_for_confirmation_propagates_known_key_verifier_error() {
    let candidate = candidate(true);

    let error = review_candidate_for_confirmation(
        &candidate,
        InteractiveTrustReviewKind::KnownKeyApproval,
        &mut |_candidate| {
            Err(crate::Error::build_verification_error(
                "V-GITHUB-API".to_string(),
                "GitHub API unavailable".to_string(),
            ))
        },
    )
    .unwrap_err();

    assert_eq!(error.rule(), Some("V-GITHUB-API"));
}

#[test]
fn test_verify_trust_candidate_online_skips_unconfigured_binding_without_public_key() {
    let candidate = candidate(false);

    let reviewed = verify_trust_candidate_online(&candidate).unwrap();

    assert_eq!(reviewed, candidate);
}

#[test]
fn test_verify_trust_candidate_online_skips_already_verified_candidate_without_public_key() {
    let candidate = verified_candidate(&candidate(true));

    let reviewed = verify_trust_candidate_online(&candidate).unwrap();

    assert_eq!(reviewed, candidate);
}
