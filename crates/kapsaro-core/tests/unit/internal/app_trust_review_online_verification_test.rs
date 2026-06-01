// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    review_candidate_for_confirmation, verify_trust_candidate_online, InteractiveTrustReviewKind,
};
use crate::app::trust::{TrustApprovalCandidate, TrustApprovalCandidateBuilder};
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::public_key::{
    Attestation, BindingClaims, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};

const TEST_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

fn candidate(configured: bool) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::new("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
        .with_github_binding_configured(configured)
        .build()
}

fn verified_candidate(candidate: &TrustApprovalCandidate) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::new(candidate.member_handle.as_str(), candidate.kid.as_str())
        .with_github_binding_configured(candidate.github_binding_configured)
        .with_verified_github(Some(VerifiedGithubIdentity::new(
            42,
            "alice".to_string(),
            "SHA256:test".to_string(),
            100,
        )))
        .with_online_verification_context(true, Some("verified".to_string()))
        .build()
}

fn failed_candidate(candidate: &TrustApprovalCandidate, message: &str) -> TrustApprovalCandidate {
    TrustApprovalCandidateBuilder::new(candidate.member_handle.as_str(), candidate.kid.as_str())
        .with_github_binding_configured(candidate.github_binding_configured)
        .with_online_verification_context(true, Some(message.to_string()))
        .build()
}

fn public_key_for_member(member_handle: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "kapsaro:format:public-key@1".to_string(),
            subject_handle: member_handle.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                },
            },
            attestation: Attestation {
                method: "ssh".to_string(),
                pub_: TEST_SSH_PUBKEY.to_string(),
                sig: "signature".to_string(),
            },
            binding_claims: Some(BindingClaims {
                github_account: None,
            }),
            expires_at: "2099-12-31T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "sig".to_string(),
    }
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

    assert_eq!(reviewed.github_id, Some(42));
    assert_eq!(reviewed.github_login, Some("alice".to_string()));
    assert!(reviewed.verified_github.is_some());
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

    assert_eq!(
        reviewed.online_verification_message,
        Some("not found".to_string())
    );
    assert!(reviewed.verified_github.is_none());
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
    assert_eq!(
        error.verification_rule(),
        Some("E_TRUST_ONLINE_VERIFY_REQUIRED")
    );
    assert!(
        error.format_user_message().contains("not found"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[test]
fn test_verify_trust_candidate_online_missing_public_key_error() {
    let candidate = candidate(true);

    let error = verify_trust_candidate_online(&candidate, false).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(
        error.verification_rule(),
        Some("E_TRUST_REVIEW_SOURCE_MISSING")
    );
    assert!(
        error
            .format_user_message()
            .contains("Missing public key required for online verification"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[test]
fn test_verify_trust_candidate_online_skips_unconfigured_binding_without_public_key() {
    let candidate = candidate(false);

    let reviewed = verify_trust_candidate_online(&candidate, false).unwrap();

    assert_eq!(reviewed, candidate);
}

#[test]
fn test_verify_trust_candidate_online_skips_already_verified_candidate_without_public_key() {
    let candidate = verified_candidate(&candidate(true));

    let reviewed = verify_trust_candidate_online(&candidate, false).unwrap();

    assert_eq!(reviewed, candidate);
}

#[cfg(not(feature = "online"))]
#[test]
fn test_verify_trust_candidate_online_requires_online_feature() {
    let candidate =
        TrustApprovalCandidateBuilder::new("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
            .with_github_binding_configured(true)
            .with_public_key(Some(public_key_for_member("alice@example.com")))
            .build();

    let error = verify_trust_candidate_online(&candidate, false).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Config);
    assert!(error
        .format_user_message()
        .contains("requires the 'online' feature"));
}

#[cfg(feature = "online")]
#[test]
fn test_verify_trust_candidate_online_rejects_member_handle_mismatch() {
    let candidate =
        TrustApprovalCandidateBuilder::new("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
            .with_github_binding_configured(true)
            .with_public_key(Some(public_key_for_member("bob@example.com")))
            .build();

    let error = verify_trust_candidate_online(&candidate, false).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(
        error.verification_rule(),
        Some("E_TRUST_ONLINE_VERIFY_MISMATCH")
    );
    assert!(
        error
            .format_user_message()
            .contains("did not match candidate 'alice@example.com'"),
        "unexpected: {}",
        error.format_user_message()
    );
}

#[cfg(feature = "online")]
#[test]
fn test_verify_trust_candidate_online_applies_failed_result_context() {
    let candidate =
        TrustApprovalCandidateBuilder::new("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
            .with_github_binding_configured(true)
            .with_public_key(Some(public_key_for_member("alice@example.com")))
            .build();

    let reviewed = verify_trust_candidate_online(&candidate, false).unwrap();

    assert!(reviewed.online_verification_attempted);
    assert!(reviewed.online_verification_message.is_some());
    assert!(reviewed.verified_github.is_none());
}
