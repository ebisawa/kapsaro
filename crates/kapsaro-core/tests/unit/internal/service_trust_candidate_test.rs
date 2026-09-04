// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::service::online::VerifiedGitHubEvidence;
use crate::service::trust::KnownKeyReviewCandidate;

use super::TrustApprovalCandidateBuilder;

const MEMBER_HANDLE: &str = "bob@example.com";
const KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const ATTESTOR_PUB: &str = "ssh-ed25519 AAAA test";

fn service_candidate() -> KnownKeyReviewCandidate {
    KnownKeyReviewCandidate::for_test(MEMBER_HANDLE, KID, ATTESTOR_PUB)
}

#[test]
fn test_trust_approval_candidate_projects_verified_service_identity() {
    let candidate =
        TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate()).build();

    assert_eq!(candidate.member_handle().as_str(), MEMBER_HANDLE);
    assert_eq!(candidate.kid().as_str(), KID);
    assert_eq!(candidate.attestor_pub(), ATTESTOR_PUB);
    assert_eq!(candidate.github_id(), None);
    assert_eq!(candidate.github_login(), None);
    assert!(!candidate.is_github_verified());
    assert!(!candidate.online_verification_attempted());
    assert_eq!(candidate.online_verification_message(), None);
    assert!(candidate.requires_out_of_band_verification);
}

#[test]
fn test_trust_approval_candidate_projects_opaque_verified_github_evidence() {
    let service_candidate = service_candidate();
    let evidence = VerifiedGitHubEvidence::for_test(
        &service_candidate,
        100,
        "current-login",
        "SHA256:verified",
        9,
    );
    let candidate = TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate)
        .with_verified_service_evidence(evidence)
        .with_online_verification_context(true, Some("verified".to_string()))
        .build();

    assert_eq!(candidate.fingerprint(), Some("SHA256:verified"));
    assert_eq!(candidate.github_id(), Some(100));
    assert_eq!(candidate.github_login(), Some("current-login"));
    assert!(candidate.is_github_verified());
    assert!(candidate.online_verification_attempted());
    assert_eq!(candidate.online_verification_message(), Some("verified"));
}

#[test]
fn test_failed_online_verification_retains_service_identity() {
    let verification = VerificationResult {
        member_handle: MEMBER_HANDLE.to_string(),
        status: VerificationStatus::Failed,
        message: "not found".to_string(),
        fingerprint: None,
        matched_key_id: None,
        github_claim_present: true,
        verified_github: None,
    };
    let candidate = TrustApprovalCandidateBuilder::from_known_key_candidate(&service_candidate())
        .with_verification_result(&verification)
        .build();

    assert_eq!(candidate.member_handle().as_str(), MEMBER_HANDLE);
    assert_eq!(candidate.kid().as_str(), KID);
    assert!(!candidate.is_github_verified());
    assert!(candidate.online_verification_attempted());
    assert_eq!(candidate.online_verification_message(), Some("not found"));
}
